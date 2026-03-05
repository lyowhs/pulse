package bench

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/wiresocket"
)

func clientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client <server-addr>",
		Short: "Connect to a bench server and measure round-trip throughput",
		Args:  cobra.ExactArgs(1),
		RunE:  runClient,
	}
	cmd.Flags().String("pubkey", "", "hex-encoded server public key (required)")
	cmd.MarkFlagRequired("pubkey")
	cmd.Flags().DurationP("duration", "d", 10*time.Second, "how long to run the benchmark")
	cmd.Flags().Int("size", 32*1024, "event payload size in bytes")
	cmd.Flags().Int("parallel", 1, "number of concurrent sender goroutines")
	cmd.Flags().Int("mtu", 1472, "UDP payload MTU in bytes")
	cmd.Flags().Duration("coalesce", 200*time.Microsecond, "coalesce interval; 0 disables coalescing")
	cmd.Flags().Bool("reliable", true, "use reliable delivery (default: on; set --reliable=false to disable)")
	cmd.Flags().Bool("cc", false, "enable AIMD congestion control (auto-enables reliable delivery for loss feedback)")
	return cmd
}

func runClient(cmd *cobra.Command, args []string) error {
	serverAddr := args[0]
	pubkeyHex, _ := cmd.Flags().GetString("pubkey")
	dur, _ := cmd.Flags().GetDuration("duration")
	size, _ := cmd.Flags().GetInt("size")
	parallel, _ := cmd.Flags().GetInt("parallel")
	mtu, _ := cmd.Flags().GetInt("mtu")
	coalesce, _ := cmd.Flags().GetDuration("coalesce")
	reliable, _ := cmd.Flags().GetBool("reliable")
	cc, _ := cmd.Flags().GetBool("cc")

	var serverPub [32]byte
	b, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("--pubkey must be a 64-character hex string (32 bytes)")
	}
	copy(serverPub[:], b)

	// Compute pipeline parameters to avoid overwhelming the socket buffers.
	// Mirrors the inflightCap calculation in bench run so that the number of
	// in-flight fragments never exceeds what the kernel can actually buffer.
	const (
		sizeDataHdr = 16
		sizeFragHdr = 8
		sizeAEAD    = 16
		requested   = 4 << 20 // matches dialSession socket buffer request
	)
	maxFrag := mtu - sizeDataHdr - sizeFragHdr - sizeAEAD
	fragsPerEvent := 1
	if maxFrag > 0 && size > maxFrag {
		fragsPerEvent = (size + maxFrag - 1) / maxFrag
	}
	actualBuf := wiresocket.ProbeUDPRecvBufSize(requested)
	socketBuf := actualBuf * 3 / 4 // 75% headroom margin
	inflightCap := socketBuf / (fragsPerEvent * mtu)
	if inflightCap < 4 {
		inflightCap = 4
	}

	// eventBufSize bounds the client's advertised echo receive window
	// (myWindow = eventBufSize - len(ch.events)).  Setting it to inflightCap
	// ensures the server's echo peerWindow stays at inflightCap, so the
	// server never sends more than inflightCap × fragsPerEvent echo fragments
	// at once — keeping them within the client's socket buffer.
	eventBufSize := inflightCap
	maxIncomplete := 64
	if inflightCap*2 > maxIncomplete {
		maxIncomplete = inflightCap * 2
	}

	var reliableCfg *wiresocket.ReliableCfg
	if reliable {
		reliableCfg = &wiresocket.ReliableCfg{WindowSize: inflightCap}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "connecting to %s …\n", serverAddr)

	dialCfg := wiresocket.DialConfig{
		ServerPublicKey:        serverPub,
		HandshakeTimeout:       5 * time.Second,
		MaxRetries:             10,
		MaxPacketSize:          mtu,
		CoalesceInterval:       coalesce,
		EventBufSize:           eventBufSize,
		MaxIncompleteFrames:    maxIncomplete,
		DisableDefaultReliable: !reliable,
		DefaultReliable:        reliableCfg,
	}
	if cc {
		dialCfg.CongestionControl = &wiresocket.CongestionConfig{}
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := wiresocket.Dial(dialCtx, serverAddr, dialCfg)
	dialCancel()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	fmt.Fprintf(os.Stderr, "connected\n\n")

	ch := conn.Channel(benchChannel)

	var txMsgs, txBytes, rxMsgs, rxBytes atomic.Int64

	benchCtx, benchCancel := context.WithCancel(ctx)
	defer benchCancel()

	// drainCtx outlives benchCtx so the receiver can collect echoes that
	// were already in-flight when the benchmark window closed.
	drainCtx, drainCancel := context.WithCancel(context.Background())
	defer drainCancel()

	// Receiver goroutine — uses drainCtx so it outlives benchCtx.
	var rxDone sync.WaitGroup
	rxDone.Add(1)
	go func() {
		defer rxDone.Done()
		for {
			e, err := ch.Recv(drainCtx)
			if err != nil {
				return
			}
			rxMsgs.Add(1)
			rxBytes.Add(int64(len(e.Payload)))
		}
	}()

	// Sender goroutines — each drives its own send loop.
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := &wiresocket.Event{Type: 1, Payload: make([]byte, size)}
			for {
				if err := ch.Send(benchCtx, e); err != nil {
					return
				}
				txMsgs.Add(1)
				txBytes.Add(int64(size))
			}
		}()
	}

	// Print header.
	reliableStr := "no"
	if reliable {
		reliableStr = "yes"
	}
	ccStr := "no"
	if cc {
		ccStr = "yes"
	}
	fmt.Fprintf(os.Stdout, "  payload %-10s  duration %-8s  senders %d  mtu %d  coalesce %s  reliable %s  cc %s\n\n",
		fmtSize(int64(size)), dur, parallel, mtu, coalesce, reliableStr, ccStr)
	if cc {
		fmt.Fprintf(os.Stdout, "  %7s   %10s   %10s   %10s   %10s   %10s\n",
			"elapsed", "tx msg/s", "tx Gbit/s", "rx msg/s", "rx Gbit/s", "cc KiB/s")
	} else {
		fmt.Fprintf(os.Stdout, "  %7s   %10s   %10s   %10s   %10s\n",
			"elapsed", "tx msg/s", "tx Gbit/s", "rx msg/s", "rx Gbit/s")
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	timer := time.NewTimer(dur)
	defer timer.Stop()

	start := time.Now()
	var prevTXM, prevTXB, prevRXM, prevRXB int64

	// drain stops senders, flushes the coalescer and any reliable in-flight
	// frames, then waits for the receiver goroutine to exit.
	drain := func() {
		drainStart := time.Now()
		conn.Close()
		drainElapsed := time.Since(drainStart)
		drainCancel()
		rxDone.Wait()
		fmt.Fprintf(os.Stderr, "  drain: %s\n", drainElapsed.Round(time.Millisecond))
	}

	for {
		select {
		case <-ctx.Done():
			benchCancel()
			wg.Wait()
			drain()
			return nil

		case <-ticker.C:
			elapsed := time.Since(start).Round(time.Second)
			curTXM, curTXB := txMsgs.Load(), txBytes.Load()
			curRXM, curRXB := rxMsgs.Load(), rxBytes.Load()

			if cc {
				fmt.Fprintf(os.Stdout, "  %7s   %10d   %10.3f   %10d   %10.3f   %10.1f\n",
					elapsed,
					curTXM-prevTXM, float64(curTXB-prevTXB)*8/1e9,
					curRXM-prevRXM, float64(curRXB-prevRXB)*8/1e9,
					conn.CongestionRateKBps())
			} else {
				fmt.Fprintf(os.Stdout, "  %7s   %10d   %10.3f   %10d   %10.3f\n",
					elapsed,
					curTXM-prevTXM, float64(curTXB-prevTXB)*8/1e9,
					curRXM-prevRXM, float64(curRXB-prevRXB)*8/1e9)
			}

			prevTXM, prevTXB, prevRXM, prevRXB = curTXM, curTXB, curRXM, curRXB

		case <-timer.C:
			benchCancel()
			wg.Wait()

			secs := time.Since(start).Seconds()
			totalTXM, totalTXB := txMsgs.Load(), txBytes.Load()
			totalRXM, totalRXB := rxMsgs.Load(), rxBytes.Load()

			fmt.Fprintf(os.Stdout, "\n  ─── summary ────────────────────────────────────────\n")
			fmt.Fprintf(os.Stdout, "  TX  %10d msgs   %10s   %6.3f Gbit/s\n",
				totalTXM, fmtSize(totalTXB), float64(totalTXB)*8/1e9/secs)
			fmt.Fprintf(os.Stdout, "  RX  %10d msgs   %10s   %6.3f Gbit/s\n",
				totalRXM, fmtSize(totalRXB), float64(totalRXB)*8/1e9/secs)

			// Warn when the echo return rate is very low.  This usually means
			// the OS accepted packets into the socket send buffer faster than
			// the network path can deliver them (VPN bottleneck, ISP shaping,
			// congestion).  TX counts socket-buffer acceptances, not wire
			// transmissions; RX is always ground truth.
			if totalTXM > 0 {
				deliveryPct := float64(totalRXM) / float64(totalTXM) * 100
				fmt.Fprintf(os.Stdout, "  echo delivery: %.1f%%", deliveryPct)
				if deliveryPct < 50 {
					fmt.Fprintf(os.Stdout, "  ⚠  TX overcounts: the network dropped ~%.0f%% of packets\n"+
						"     (VPN, ISP shaping, or congestion on the path — TX ≠ wire transmissions)\n",
						100-deliveryPct)
				} else {
					fmt.Fprintf(os.Stdout, "\n")
				}
			}

			drain()
			return nil
		}
	}
}
