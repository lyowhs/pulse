package bench

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/wiresocket"
)

func runCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Self-contained in-process throughput benchmark",
		Long: `Starts an echo server and client in-process, then measures round-trip
throughput for each combination of --size and --mtu.  No second terminal needed.`,
		RunE: runBench,
	}
	cmd.Flags().Duration("duration", 5*time.Second, "how long to run each sub-benchmark")
	cmd.Flags().IntSlice("mtu", []int{1472}, "UDP payload MTU(s) to sweep (comma-separated or repeated)")
	cmd.Flags().IntSlice("size", []int{1024, 64 * 1024, 512 * 1024}, "payload size(s) in bytes to sweep")
	cmd.Flags().Duration("coalesce", 200*time.Microsecond, "coalesce interval; 0 disables")
	cmd.Flags().Bool("reliable", true, "use reliable delivery (default: on; set --reliable=false to disable)")
	cmd.Flags().Int64("rate-limit", 0, "outgoing byte rate limit in bytes/s (0 = unlimited; acts as CC ceiling when --cc is set)")
	cmd.Flags().Bool("cc", false, "enable AIMD congestion control (auto-enables reliable delivery for loss feedback)")
	return cmd
}

func runBench(cmd *cobra.Command, _ []string) error {
	dur, _ := cmd.Flags().GetDuration("duration")
	mtus, _ := cmd.Flags().GetIntSlice("mtu")
	sizes, _ := cmd.Flags().GetIntSlice("size")
	coalesce, _ := cmd.Flags().GetDuration("coalesce")
	reliable, _ := cmd.Flags().GetBool("reliable")
	rateLimit, _ := cmd.Flags().GetInt64("rate-limit")
	cc, _ := cmd.Flags().GetBool("cc")

	type result struct {
		mtu      int
		size     int
		skipped  bool
		txMsgS   float64
		txGbps   float64
		rxMsgS   float64
		rxGbps   float64
		lossRate float64 // lost / tx * 100
		drained  int64   // echoes recovered during drain (timer-caused apparent loss)
		lost     int64   // echoes never received (genuine drops)
		p50      string  // median round-trip time
		p99      string  // 99th-percentile round-trip time
		retx     int64   // retransmit events (non-zero only with --reliable)
	}
	var results []result

	for _, mtu := range mtus {
		for _, size := range sizes {
			skipped := size > wiresocket.MaxEventPayload(mtu)
			r, err := runOne(dur, mtu, size, coalesce, reliable, rateLimit, cc)
			if err != nil {
				return fmt.Errorf("bench mtu=%d size=%d: %w", mtu, size, err)
			}
			results = append(results, result{
				mtu:      mtu,
				size:     size,
				skipped:  skipped,
				txMsgS:   r.txMsgS,
				txGbps:   r.txGbps,
				rxMsgS:   r.rxMsgS,
				rxGbps:   r.rxGbps,
				lossRate: r.lossRate,
				drained:  r.drained,
				lost:     r.lost,
				p50:      r.p50,
				p99:      r.p99,
				retx:     r.retx,
			})
		}
	}

	// Summary table.
	fmt.Fprintf(os.Stdout, "\n  ─── summary ──────────────────────────────────────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(os.Stdout, "  %6s  %8s  %10s  %10s  %10s  %10s  %7s  %8s  %7s  %8s  %8s  %6s\n",
		"MTU", "payload", "tx msg/s", "tx Gbit/s", "rx msg/s", "rx Gbit/s", "loss%", "drained", "lost", "p50", "p99", "retx")
	for _, r := range results {
		if r.skipped {
			fmt.Fprintf(os.Stdout, "  %6d  %8s  %10s  %10s  %10s  %10s  %7s  %8s  %7s  %8s  %8s  %6s\n",
				r.mtu, fmtSize(int64(r.size)), "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A")
			continue
		}
		fmt.Fprintf(os.Stdout, "  %6d  %8s  %10.0f  %10.3f  %10.0f  %10.3f  %7.3f  %8d  %7d  %8s  %8s  %6d\n",
			r.mtu, fmtSize(int64(r.size)),
			r.txMsgS, r.txGbps, r.rxMsgS, r.rxGbps,
			r.lossRate, r.drained, r.lost, r.p50, r.p99, r.retx)
	}
	return nil
}

// oneResult holds the output of a single runOne sub-benchmark.
type oneResult struct {
	txMsgS float64
	txGbps float64
	// rxMsgS is the receive rate during the benchmark window only (excludes
	// echoes recovered during the post-timer drain).
	rxMsgS   float64
	rxGbps   float64
	lossRate float64 // lost / tx * 100
	// drained is the number of echoes received during the post-timer drain
	// window.  These were in-flight when the benchmark timer fired and are
	// not genuine losses — they are timer-caused apparent loss.
	drained int64
	// lost is the number of sent events whose echo never arrived, even after
	// the full drain.  These are genuine packet drops.
	lost int64
	p50  string // median round-trip time
	p99  string // 99th-percentile round-trip time
	retx int64  // retransmit events (non-zero only with reliable=true)
}

// rttHistogram is a power-of-two bucket histogram for round-trip time.
// Bucket i accumulates samples where 2^(i-1) ≤ nanoseconds < 2^i.
// Written exclusively by the receiver goroutine; read by the main goroutine
// after rxDone.Wait() — no locking required.
type rttHistogram struct {
	counts [64]int64
	total  int64
}

func (h *rttHistogram) record(d time.Duration) {
	ns := d.Nanoseconds()
	if ns < 1 {
		ns = 1
	}
	b := bits.Len64(uint64(ns))
	if b >= 64 {
		b = 63
	}
	h.counts[b]++
	h.total++
}

// percentile returns the approximate duration at the given percentile (0–100).
// Returns the lower bound of the containing bucket, which is a conservative
// (under) estimate.
func (h *rttHistogram) percentile(pct float64) time.Duration {
	if h.total == 0 {
		return 0
	}
	target := int64(math.Ceil(float64(h.total) * pct / 100.0))
	var cum int64
	for i, c := range h.counts {
		cum += c
		if cum >= target {
			if i == 0 {
				return time.Nanosecond
			}
			// Lower bound of bucket i: 2^(i-1) nanoseconds.
			return time.Duration(int64(1) << uint(i-1))
		}
	}
	return time.Duration(int64(1) << 62)
}

// fmtDuration formats a duration for display in the benchmark table.
func fmtDuration(d time.Duration) string {
	switch {
	case d == 0:
		return "—"
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1e3)
	case d < time.Second:
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

// runOne starts an in-process echo server + client, drives traffic for dur,
// and returns throughput, loss, latency, and retransmit metrics.
// Returns a zero result (not an error) when the payload cannot be sent at the
// given MTU.
func runOne(dur time.Duration, mtu, payloadSize int, coalesce time.Duration, reliable bool, rateLimit int64, cc bool) (oneResult, error) {
	if payloadSize > wiresocket.MaxEventPayload(mtu) {
		fmt.Fprintf(os.Stderr, "  skipping mtu=%-5d payload=%-10s — exceeds 255-fragment limit\n",
			mtu, fmtSize(int64(payloadSize)))
		return oneResult{}, nil
	}
	fmt.Fprintf(os.Stderr, "  running mtu=%-5d payload=%-10s duration=%s …\n",
		mtu, fmtSize(int64(payloadSize)), dur)
	wiresocket.ResetDebugCounters()

	kp, err := wiresocket.GenerateKeypair()
	if err != nil {
		return oneResult{}, err
	}

	port, err := freeUDPPort()
	if err != nil {
		return oneResult{}, err
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	var echo echoState
	srv, err := wiresocket.NewServer(wiresocket.ServerConfig{
		Addr:                addr,
		PrivateKey:          kp.Private,
		OnConnect:           makeEchoConn(reliable, &echo),
		MaxPacketSize:       mtu,
		CoalesceInterval:    coalesce,
		MaxEventPayloadSize: payloadSize,
	})
	if err != nil {
		return oneResult{}, err
	}

	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	go srv.Serve(srvCtx) //nolint:errcheck

	// Wait for the server socket to be ready.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("udp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	dialCfg := wiresocket.DialConfig{
		ServerPublicKey:     kp.Public,
		HandshakeTimeout:    5 * time.Second,
		MaxRetries:          10,
		MaxPacketSize:       mtu,
		CoalesceInterval:    coalesce,
		MaxEventPayloadSize: payloadSize,
		SendRateLimitBPS:    rateLimit,
	}
	if cc {
		dialCfg.CongestionControl = &wiresocket.CongestionConfig{}
	}
	conn, err := wiresocket.Dial(context.Background(), addr, dialCfg)
	if err != nil {
		return oneResult{}, fmt.Errorf("dial: %w", err)
	}

	// inflightCap is the number of events that can be in-flight simultaneously
	// without overflowing the socket receive buffer.  The library derives this
	// from the probed kernel buffer size and MaxEventPayloadSize.
	inflightCap := conn.InflightCap()

	// RTT ring buffer: the sender writes a send-timestamp at index
	// (txCount & rttMask) before each send; the receiver reads it at
	// (rxCount & rttMask) on echo receipt.  The ring must be strictly larger
	// than inflightCap so sender and receiver never alias the same slot.
	rttRingSize := 1
	for rttRingSize <= inflightCap {
		rttRingSize <<= 1
	}
	rttMask := rttRingSize - 1
	sendTimes := make([]atomic.Int64, rttRingSize)

	ch := conn.Channel(benchChannel)
	// Channels are reliable by default with the window auto-sized from
	// MaxEventPayloadSize.  Only switch to unreliable when requested.
	if !reliable {
		ch.SetUnreliable()
	}
	payload := make([]byte, payloadSize)

	var txMsgs, txBytes, rxMsgs, rxBytes atomic.Int64

	benchCtx, benchCancel := context.WithTimeout(context.Background(), dur)
	defer benchCancel()

	// drainCtx lives until we have confirmed all echoes are received.
	drainCtx, drainCancel := context.WithCancel(context.Background())
	defer drainCancel()

	// tokens is a sliding-window semaphore: the sender must hold a token
	// for each event it has sent but not yet received an echo for.
	tokens := make(chan struct{}, inflightCap)
	for i := 0; i < inflightCap; i++ {
		tokens <- struct{}{}
	}

	var hist rttHistogram

	// Receiver goroutine — reads from ch.Events() signal channel rather than
	// ch.Recv so that closing ch.done (which happens inside conn.Close)
	// does NOT cause it to exit before draining the buffer.  It runs until
	// drainCtx is cancelled, which we defer until all echoes are confirmed.
	var rxDone sync.WaitGroup
	rxDone.Add(1)
	go func() {
		defer rxDone.Done()
		sigCh := ch.Events()
		var rxCount int
		for {
			select {
			case <-sigCh:
				// Drain all available events after the signal.
				for {
					e, ok := ch.PopEvent()
					if !ok {
						break
					}
					// Compute RTT using the timestamp stored by the sender for
					// this event.  rxCount matches txCount because the echo
					// server reflects events in order and there is a single
					// sender goroutine.
					ts := sendTimes[rxCount&rttMask].Load()
					if ts > 0 {
						hist.record(time.Duration(time.Now().UnixNano() - ts))
					}
					rxCount++
					rxMsgs.Add(1)
					rxBytes.Add(int64(len(e.Payload)))
					// Return the token so the sender can issue another event.
					select {
					case tokens <- struct{}{}:
					default: // sender already stopped; discard
					}
				}
			case <-drainCtx.Done():
				return
			}
		}
	}()

	// Sender goroutine.
	var txDone sync.WaitGroup
	txDone.Add(1)
	go func() {
		defer txDone.Done()
		e := &wiresocket.Event{Type: 1, Payload: payload}
		var txCount int
		for {
			// Acquire a token before sending; block here when the echo
			// path falls behind, naturally yielding CPU to server and
			// receiver goroutines.
			select {
			case <-benchCtx.Done():
				return
			case <-tokens:
			}
			// Record send timestamp before the send so the receiver can
			// compute RTT as soon as the echo arrives.
			sendTimes[txCount&rttMask].Store(time.Now().UnixNano())
			if err := ch.Send(benchCtx, e); err != nil {
				return
			}
			txMsgs.Add(1)
			txBytes.Add(int64(payloadSize))
			txCount++
		}
	}()

	<-benchCtx.Done()
	txDone.Wait()

	// Snapshot counts at timer expiry before the echo drain runs.
	txAtStop := txMsgs.Load()
	rxAtStop := rxMsgs.Load()

	// Flush the coalescer so all events queued since the last timer tick
	// reach the server.  Flush does not close the connection, so the receiver
	// goroutine continues running and can receive the echoes.
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	flushStart := time.Now()
	conn.Flush(flushCtx)
	flushDur := time.Since(flushStart)
	flushCancel()

	// Wait for all in-flight echoes to return before closing the connection.
	//
	// Reliable mode: conn.Flush guarantees every sent event reached the server
	// and the server has sent (or will send) an echo for each.  Echoes are
	// guaranteed to arrive eventually; the only source of delay is flow-control
	// back-pressure (the server's S→C window being throttled by a temporarily
	// full client receive buffer).  We wait up to 10 s for rxMsgs == txAtStop.
	//
	// Unreliable mode: some echoes may be genuinely lost; a fixed drain window
	// is used to avoid waiting forever.
	if reliable {
		sessCallsAtFlush := wiresocket.DebugSessionReceiveCalls.Load()
		drainStart := time.Now()
		srvNumPending := int32(0)
		srvRingLen := 0
		srvRecv := int64(0)
		srvSent := int64(0)
		if echo.ch != nil {
			srvNumPending = echo.ch.NumPending()
			srvRingLen = echo.ch.RingLen()
			srvRecv = echo.recvCount.Load()
			srvSent = echo.sendCount.Load()
		}
		fmt.Fprintf(os.Stderr, "  [drain0] rxMsgs=%d txAtStop=%d evtDelivered=%d cli(numPending=%d ringLen=%d) srv(numPending=%d ringLen=%d echoRecv=%d echoSent=%d) flushDur=%s retxFired=%d retxSent=%d rtoArmed=%d rtoStopped=%d reset=%d preSendBlocked=%d coalPreSendFailed=%d coalSendFailed=%d\n",
			rxMsgs.Load(), txAtStop,
			wiresocket.DebugEventsDelivered.Load(),
			ch.NumPending(), ch.RingLen(),
			srvNumPending, srvRingLen, srvRecv, srvSent,
			flushDur.Round(time.Millisecond),
			wiresocket.DebugRetransmitFired.Load(),
			wiresocket.DebugRetransmitSent.Load(),
			wiresocket.DebugRTOTimerArmed.Load(),
			wiresocket.DebugRTOTimerStopped.Load(),
			wiresocket.DebugReliableReset.Load(),
			wiresocket.DebugPreSendBlocked.Load(),
			wiresocket.DebugCoalescerPreSendFailed.Load(),
			wiresocket.DebugCoalescerSendFailed.Load())
		drainDeadline := drainStart.Add(10 * time.Second)
		lastRx := rxMsgs.Load()
		lastCheck := time.Now()
		goroutineDumped := false
		for rxMsgs.Load() < txAtStop && time.Now().Before(drainDeadline) {
			time.Sleep(500 * time.Millisecond)
			curRx := rxMsgs.Load()
			if curRx != lastRx || time.Since(lastCheck) > 2*time.Second {
				srvNP := int32(0)
				srvRL := 0
				if echo.ch != nil {
					srvNP = echo.ch.NumPending()
					srvRL = echo.ch.RingLen()
				}
				fmt.Fprintf(os.Stderr, "  [drain] t+%.2fs rxMsgs=%d (+%d) cli(np=%d rl=%d) srv(np=%d rl=%d) sessRecv=%d retxFired=%d retxSent=%d rtoArmed=%d rtoStopped=%d reset=%d\n",
					time.Since(drainStart).Seconds(), curRx, curRx-lastRx,
					ch.NumPending(), ch.RingLen(), srvNP, srvRL,
					wiresocket.DebugSessionReceiveCalls.Load()-sessCallsAtFlush,
					wiresocket.DebugRetransmitFired.Load(),
					wiresocket.DebugRetransmitSent.Load(),
					wiresocket.DebugRTOTimerArmed.Load(),
					wiresocket.DebugRTOTimerStopped.Load(),
					wiresocket.DebugReliableReset.Load())
				lastRx = curRx
				lastCheck = time.Now()
			}
			// After 5 s of no progress, dump all goroutines to stderr once.
			if !goroutineDumped && curRx == rxMsgs.Load() && time.Since(drainStart) > 5*time.Second {
				goroutineDumped = true
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				fmt.Fprintf(os.Stderr, "  [goroutine dump at t+%.2fs]\n%s\n", time.Since(drainStart).Seconds(), buf[:n])
			}
		}
	} else {
		drainWait := 10 * coalesce
		if drainWait < 100*time.Millisecond {
			drainWait = 100 * time.Millisecond
		}
		if fragDelay := time.Duration(payloadSize/mtu+1) * time.Millisecond; fragDelay > drainWait {
			drainWait = fragDelay
		}
		time.Sleep(drainWait)
	}

	conn.Close()

	// Cancel the drain context so the receiver goroutine exits.
	drainCancel()
	rxDone.Wait()

	finalRx := rxMsgs.Load()
	// drained: echoes that arrived during the drain window — in-flight when
	// the timer fired, not genuine loss.
	drained := finalRx - rxAtStop
	// lost: echoes never received even after full drain — genuine drops.
	lost := txAtStop - finalRx

	var lossRate float64
	if txAtStop > 0 {
		lossRate = float64(lost) / float64(txAtStop) * 100
	}

	// Print diagnostic counters only when there is genuine packet loss —
	// teardown-time errors (flushLoopErrors, dataDroppedUnknown) are expected
	// when the server closes while the client has in-flight retransmits and
	// do not indicate a bug when lost == 0.
	if lost > 0 {
		if flushErrs := wiresocket.DebugFlushLoopErrors.Load(); flushErrs != 0 {
			fmt.Fprintf(os.Stderr, "  [diag] flushLoopErrors=%d\n", flushErrs)
		}
		if dropped := wiresocket.DebugDataDroppedClosed.Load(); dropped != 0 {
			fmt.Fprintf(os.Stderr, "  [diag] dataDroppedClosed=%d\n", dropped)
		}
		if dropped := wiresocket.DebugDataDroppedUnknown.Load(); dropped != 0 {
			fmt.Fprintf(os.Stderr, "  [diag] dataDroppedUnknown=%d\n", dropped)
		}
		if dropped := wiresocket.DebugWorkerQueueFull.Load(); dropped != 0 {
			fmt.Fprintf(os.Stderr, "  [diag] workerQueueFull=%d\n", dropped)
		}
		if dropped := wiresocket.DebugRingDropped.Load(); dropped != 0 {
			fmt.Fprintf(os.Stderr, "  [diag] ringDropped=%d\n", dropped)
		}
		if dropped := wiresocket.DebugOOOTooFar.Load(); dropped != 0 {
			fmt.Fprintf(os.Stderr, "  [diag] oooTooFar=%d\n", dropped)
		}
		if n := wiresocket.DebugProbesFired.Load(); n != 0 {
			fmt.Fprintf(os.Stderr, "  [diag] probesFired=%d\n", n)
		}
		if n := wiresocket.DebugOnAckNoUnblock.Load(); n != 0 {
			fmt.Fprintf(os.Stderr, "  [diag] onAckNoUnblock=%d\n", n)
		}
		if n := wiresocket.DebugPreSendBlocked.Load(); n != 0 {
			fmt.Fprintf(os.Stderr, "  [diag] preSendBlocked=%d\n", n)
		}
		fmt.Fprintf(os.Stderr, "  [diag] eventsDelivered=%d onRecvInOrder=%d onRecvDuplicate=%d\n",
			wiresocket.DebugEventsDelivered.Load(),
			wiresocket.DebugOnRecvInOrder.Load(),
			wiresocket.DebugOnRecvDuplicate.Load())
		fmt.Fprintf(os.Stderr, "  [diag] sessReceiveCalls=%d replayRejected=%d\n",
			wiresocket.DebugSessionReceiveCalls.Load(),
			wiresocket.DebugReplayRejected.Load())
		fmt.Fprintf(os.Stderr, "  [diag] retxFired=%d batchEmpty=%d retxSent=%d sendErr=%d retxInFlight=%d retxSessNil=%d retxNoPending=%d epochAbort=%d rearmSkipped=%d\n",
			wiresocket.DebugRetransmitFired.Load(),
			wiresocket.DebugRetransmitBatchEmpty.Load(),
			wiresocket.DebugRetransmitSent.Load(),
			wiresocket.DebugRetransmitSendErr.Load(),
			wiresocket.DebugRetransmitInFlight.Load(),
			wiresocket.DebugRetransmitSessNil.Load(),
			wiresocket.DebugRetransmitNumPendingZero.Load(),
			wiresocket.DebugRetransmitEpochAbort.Load(),
			wiresocket.DebugRetransmitRearmSkipped.Load())
		fmt.Fprintf(os.Stderr, "  [diag] rtoArmed=%d rtoStopped=%d reliableReset=%d\n",
			wiresocket.DebugRTOTimerArmed.Load(),
			wiresocket.DebugRTOTimerStopped.Load(),
			wiresocket.DebugReliableReset.Load())
		fmt.Fprintf(os.Stderr, "  [diag] probesFired=%d workerQueueFull=%d flushLoopErrors=%d\n",
			wiresocket.DebugProbesFired.Load(),
			wiresocket.DebugWorkerQueueFull.Load(),
			wiresocket.DebugFlushLoopErrors.Load())
		fmt.Fprintf(os.Stderr, "  [diag] coalPreSendFailed=%d coalSendFailed=%d\n",
			wiresocket.DebugCoalescerPreSendFailed.Load(),
			wiresocket.DebugCoalescerSendFailed.Load())
	}

	secs := dur.Seconds()
	tx := txBytes.Load()
	rx := rxBytes.Load()
	return oneResult{
		txMsgS:   float64(txAtStop) / secs,
		txGbps:   float64(tx) * 8 / 1e9 / secs,
		rxMsgS:   float64(rxAtStop) / secs,
		rxGbps:   float64(rx) * 8 / 1e9 / secs,
		lossRate: lossRate,
		drained:  drained,
		lost:     lost,
		p50:      fmtDuration(hist.percentile(50)),
		p99:      fmtDuration(hist.percentile(99)),
		retx:     ch.Retransmits(),
	}, nil
}

// freeUDPPort returns an available local UDP port.
func freeUDPPort() (int, error) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return 0, err
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	return port, nil
}
