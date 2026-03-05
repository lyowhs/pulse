package bench

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"net"
	"os"
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
	cmd.Flags().Bool("cc", false, "enable AIMD congestion control (auto-enables reliable delivery for loss feedback)")
	return cmd
}

func runBench(cmd *cobra.Command, _ []string) error {
	dur, _ := cmd.Flags().GetDuration("duration")
	mtus, _ := cmd.Flags().GetIntSlice("mtu")
	sizes, _ := cmd.Flags().GetIntSlice("size")
	coalesce, _ := cmd.Flags().GetDuration("coalesce")
	reliable, _ := cmd.Flags().GetBool("reliable")
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
			skipped := size > maxPayloadForMTU(mtu)
			r, err := runOne(dur, mtu, size, coalesce, reliable, cc)
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

// maxPayloadForMTU returns the maximum single-frame payload in bytes for the
// given UDP MTU.  A frame that exceeds this requires more than 65535 fragments
// and cannot be sent.
func maxPayloadForMTU(mtu int) int {
	maxFrag := wiresocket.MaxFragmentPayload(mtu)
	if maxFrag <= 0 {
		return 0
	}
	return 65535 * maxFrag
}

// runOne starts an in-process echo server + client, drives traffic for dur,
// and returns throughput, loss, latency, and retransmit metrics.
// Returns a zero result (not an error) when the payload cannot be sent at the
// given MTU.
func runOne(dur time.Duration, mtu, payloadSize int, coalesce time.Duration, reliable, cc bool) (oneResult, error) {
	if payloadSize > maxPayloadForMTU(mtu) {
		fmt.Fprintf(os.Stderr, "  skipping mtu=%-5d payload=%-10s — exceeds 255-fragment limit\n",
			mtu, fmtSize(int64(payloadSize)))
		return oneResult{}, nil
	}
	fmt.Fprintf(os.Stderr, "  running mtu=%-5d payload=%-10s duration=%s …\n",
		mtu, fmtSize(int64(payloadSize)), dur)

	// Compute pipeline parameters before starting the server and client so
	// both can be configured consistently.
	//
	// eventsPerFrame: maximum events in one coalesced UDP packet.  With
	// coalescing disabled each packet carries exactly one event.
	//
	// inflightCap: token-semaphore capacity.  Capping at maxReassembly frames
	// (= 512 * eventsPerFrame events) keeps the server's reassembly buffer
	// within its MaxIncompleteFrames limit and prevents the sender from racing
	// so far ahead that it starves the echo path.
	//
	// eventBufSize: ch.events channel depth on both server and client.  The
	// server read loop calls ipv4.ReadBatch with a window of srvReadBatchSz=64
	// packets; the router delivers all events from that batch before the
	// consumer goroutine (echoConn / bench receiver) can run.  If ch.events
	// overflows the drop-oldest policy discards an event whose token is never
	// returned, stalling the sender.  Using srvReadBatchSz*eventsPerFrame as
	// a floor prevents any drops regardless of goroutine scheduling.
	const (
		maxReassembly  = 512 // matches MaxIncompleteFrames set on the benchmark server
		srvReadBatchSz = 64  // server.go readBatchSz
	)
	maxFrag := wiresocket.MaxFragmentPayload(mtu)
	eventsPerFrame := 1
	if coalesce > 0 && maxFrag > 0 && payloadSize < maxFrag {
		eventsPerFrame = maxFrag / payloadSize
	}
	inflightCap := maxReassembly * eventsPerFrame

	// fragsPerEvent: how many UDP fragments one event requires on the wire.
	// 1 for non-fragmented payloads; ceil(payload/maxFrag) otherwise.
	fragsPerEvent := 1
	if maxFrag > 0 && payloadSize > maxFrag {
		fragsPerEvent = (payloadSize + maxFrag - 1) / maxFrag
	}

	// Cap inflightCap so that all in-flight fragments fit inside the kernel
	// receive buffer.  We probe the actual achievable buffer size rather than
	// assuming 6 MiB: on Linux without CAP_NET_ADMIN, SO_RCVBUF is clamped by
	// net.core.rmem_max (≈ 104 KiB on stock kernels), far below the requested
	// 4 MiB.  Using the hardcoded constant caused massive socket-level drops on
	// Linux because inflightCap was set orders of magnitude too high.
	//
	// Derivation of the cap:
	//   in-flight UDP packets = inflightCap / eventsPerFrame × fragsPerEvent
	//   in-flight bytes       ≈ (inflightCap / eventsPerFrame) × fragsPerEvent × mtu
	//   constraint            ≤ socketBuf
	//   ⟹ inflightCap        ≤ socketBuf × eventsPerFrame / (fragsPerEvent × mtu)
	//
	// The cap is applied unconditionally (not just for fragsPerEvent > 1) so
	// that large single-fragment frames (e.g. mtu=65507, size=4096) are also
	// bounded — they can overflow the socket buffer just as easily.
	{
		const requested = 4 << 20 // matches dialSession / Serve socket buffer request
		actualBuf := wiresocket.ProbeUDPRecvBufSize(requested)
		socketBuf := actualBuf * 3 / 4 // 75 % headroom margin
		maxByBuf := socketBuf * eventsPerFrame / (fragsPerEvent * mtu)
		if maxByBuf < 1 {
			maxByBuf = 1
		}
		if inflightCap > maxByBuf {
			inflightCap = maxByBuf
		}
	}

	eventBufSize := 256
	if burst := srvReadBatchSz * eventsPerFrame; burst > eventBufSize {
		eventBufSize = burst
	}
	// ch.events must hold all in-flight echoes without dropping any, even if
	// they all arrive in a single burst before the receiver goroutine runs.
	if inflightCap > eventBufSize {
		eventBufSize = inflightCap
	}

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

	kp, err := wiresocket.GenerateKeypair()
	if err != nil {
		return oneResult{}, err
	}

	port, err := freeUDPPort()
	if err != nil {
		return oneResult{}, err
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// srvMaxIncomplete: MaxIncompleteFrames is a FRAME count (one entry per
	// logical frame being reassembled), not a fragment count.  The server
	// needs at most inflightCap concurrent reassembly entries — one per
	// in-flight event.  512 is a safe default minimum.
	srvMaxIncomplete := inflightCap
	if srvMaxIncomplete < 512 {
		srvMaxIncomplete = 512
	}
	// workerCount: reliable delivery requires in-order frame processing so
	// that reliableState.onRecv never sees OOO gaps larger than
	// reliableOOOWindow (256).  With GOMAXPROCS workers, goroutine scheduling
	// stalls let frames overtake each other on loopback, creating gaps that
	// exceed 256 → permanent frame drops → retransmit storm → conn.Flush
	// timeout → large lost count.  A single worker serialises onRecv calls,
	// keeping the gap ≤ 1 on an in-order loopback path.  When reliable is
	// disabled the multi-worker path is safe (no OOO state to overflow).
	workerCount := 0 // 0 = default (GOMAXPROCS)
	if reliable {
		workerCount = 1
	}
	srv, err := wiresocket.NewServer(wiresocket.ServerConfig{
		Addr:             addr,
		PrivateKey:       kp.Private,
		OnConnect:        makeEchoConn(reliable),
		MaxPacketSize:    mtu,
		CoalesceInterval: coalesce,
		MaxIncompleteFrames: srvMaxIncomplete,
		EventBufSize:        eventBufSize,
		WorkerCount:         workerCount,
		// WorkChannelSize must hold all fragments of all in-flight events so
		// that the UDP reader goroutine never drops a fragment before a worker
		// can reassemble it.  Add a 64-packet headroom for keepalives.
		WorkChannelSize: inflightCap*fragsPerEvent + 64,
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
		ServerPublicKey:  kp.Public,
		HandshakeTimeout: 5 * time.Second,
		MaxRetries:       10,
		MaxPacketSize:    mtu,
		CoalesceInterval: coalesce,
		EventBufSize:     eventBufSize,
		// Double inflightCap so the client has headroom to reassemble the
		// next batch of frames while echoes from the current batch are still
		// in-flight back to the sender.
		MaxIncompleteFrames: inflightCap * 2,
	}
	if cc {
		dialCfg.CongestionControl = &wiresocket.CongestionConfig{}
	}
	conn, err := wiresocket.Dial(context.Background(), addr, dialCfg)
	if err != nil {
		return oneResult{}, fmt.Errorf("dial: %w", err)
	}

	ch := conn.Channel(benchChannel)
	// Configure per-channel reliability.  Channels are reliable by default; set
	// the window to inflightCap so the reliable send window matches the token
	// semaphore.  Disable reliability when reliable=false.
	if reliable {
		ch.SetReliable(wiresocket.ReliableCfg{WindowSize: inflightCap})
	} else {
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

	// Receiver goroutine — reads from ch.Events() directly rather than
	// ch.Recv so that closing ch.done (which happens inside conn.Close)
	// does NOT cause it to exit before draining the buffer.  It runs until
	// drainCtx is cancelled, which we defer until all echoes are confirmed.
	var rxDone sync.WaitGroup
	rxDone.Add(1)
	go func() {
		defer rxDone.Done()
		evCh := ch.Events()
		var rxCount int
		for {
			select {
			case e := <-evCh:
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
	conn.Flush(flushCtx)
	flushCancel()

	// Wait a fixed window for in-flight echoes to return.  We use a bounded
	// sleep rather than waiting for a target count because some echoes may be
	// genuinely lost (dropped by the server or OS buffers), in which case
	// waiting for rxMsgs >= txAtStop would hang forever.
	// drainWait — long enough for the slowest coalesced round-trip to
	// complete under moderate load.  For fragmented payloads, each event
	// requires fragsPerEvent UDP packets in each direction; at ~5 µs per
	// syscall that is roughly fragsPerEvent × 10 µs of serialisation delay.
	// Use max(10 × coalesce, 100ms, fragsPerEvent × 1ms) to scale
	// proportionally with payload size.
	drainWait := 10 * coalesce
	if drainWait < 100*time.Millisecond {
		drainWait = 100 * time.Millisecond
	}
	if fragDelay := time.Duration(fragsPerEvent) * time.Millisecond; fragDelay > drainWait {
		drainWait = fragDelay
	}
	time.Sleep(drainWait)

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
