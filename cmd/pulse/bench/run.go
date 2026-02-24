package bench

import (
	"context"
	"fmt"
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
	cmd.Flags().Duration("coalesce", 0, "coalesce interval (e.g. 200µs); 0 disables coalescing")
	return cmd
}

func runBench(cmd *cobra.Command, _ []string) error {
	dur, _ := cmd.Flags().GetDuration("duration")
	mtus, _ := cmd.Flags().GetIntSlice("mtu")
	sizes, _ := cmd.Flags().GetIntSlice("size")
	coalesce, _ := cmd.Flags().GetDuration("coalesce")

	type result struct {
		mtu     int
		size    int
		skipped bool
		txMsgS  float64
		txMBS   float64
		rxMsgS  float64
		rxMBS   float64
	}
	var results []result

	for _, mtu := range mtus {
		for _, size := range sizes {
			skipped := size > maxPayloadForMTU(mtu)
			r, err := runOne(dur, mtu, size, coalesce)
			if err != nil {
				return fmt.Errorf("bench mtu=%d size=%d: %w", mtu, size, err)
			}
			results = append(results, result{mtu: mtu, size: size, skipped: skipped,
				txMsgS: r[0], txMBS: r[1], rxMsgS: r[2], rxMBS: r[3]})
		}
	}

	// Summary table.
	fmt.Fprintf(os.Stdout, "\n  ─── summary ────────────────────────────────────────────────────\n")
	fmt.Fprintf(os.Stdout, "  %6s  %8s  %10s  %8s  %10s  %8s\n",
		"MTU", "payload", "tx msg/s", "tx MB/s", "rx msg/s", "rx MB/s")
	for _, r := range results {
		if r.skipped {
			fmt.Fprintf(os.Stdout, "  %6d  %8s  %10s  %8s  %10s  %8s\n",
				r.mtu, fmtSize(int64(r.size)), "N/A", "N/A", "N/A", "N/A")
			continue
		}
		fmt.Fprintf(os.Stdout, "  %6d  %8s  %10.0f  %8.2f  %10.0f  %8.2f\n",
			r.mtu, fmtSize(int64(r.size)),
			r.txMsgS, r.txMBS, r.rxMsgS, r.rxMBS)
	}
	return nil
}

// maxPayloadForMTU returns the maximum single-frame payload in bytes for the
// given UDP MTU.  A frame that exceeds this requires more than 65535 fragments
// and cannot be sent.
func maxPayloadForMTU(mtu int) int {
	const sizeDataHeader = 16
	const sizeFragmentHeader = 8
	const sizeAEADTag = 16
	maxFrag := mtu - sizeDataHeader - sizeFragmentHeader - sizeAEADTag
	if maxFrag <= 0 {
		return 0
	}
	return 65535 * maxFrag
}

// runOne starts an in-process echo server + client, drives traffic for dur,
// and returns [txMsgS, txMBS, rxMsgS, rxMBS].
// Returns an all-zero result (not an error) when the payload cannot be sent
// at the given MTU.
func runOne(dur time.Duration, mtu, payloadSize int, coalesce time.Duration) ([4]float64, error) {
	if payloadSize > maxPayloadForMTU(mtu) {
		fmt.Fprintf(os.Stderr, "  skipping mtu=%-5d payload=%-10s — exceeds 255-fragment limit\n",
			mtu, fmtSize(int64(payloadSize)))
		return [4]float64{}, nil
	}
	fmt.Fprintf(os.Stderr, "  running mtu=%-5d payload=%-10s duration=%s …\n",
		mtu, fmtSize(int64(payloadSize)), dur)

	kp, err := wiresocket.GenerateKeypair()
	if err != nil {
		return [4]float64{}, err
	}

	port, err := freeUDPPort()
	if err != nil {
		return [4]float64{}, err
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	srv, err := wiresocket.NewServer(wiresocket.ServerConfig{
		Addr:       addr,
		PrivateKey: kp.Private,
		OnConnect: func(conn *wiresocket.Conn) {
			ch := conn.Channel(benchChannel)
			for {
				e, err := ch.Recv(context.Background())
				if err != nil {
					return
				}
				if err := ch.Send(context.Background(), e); err != nil {
					return
				}
			}
		},
		MaxPacketSize:    mtu,
		CoalesceInterval: coalesce,
	})
	if err != nil {
		return [4]float64{}, err
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

	conn, err := wiresocket.Dial(context.Background(), addr, wiresocket.DialConfig{
		ServerPublicKey:  kp.Public,
		HandshakeTimeout: 5 * time.Second,
		MaxRetries:       10,
		MaxPacketSize:    mtu,
		CoalesceInterval: coalesce,
	})
	if err != nil {
		return [4]float64{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	ch := conn.Channel(benchChannel)
	payload := make([]byte, payloadSize)

	var txMsgs, txBytes, rxMsgs, rxBytes atomic.Int64

	benchCtx, benchCancel := context.WithTimeout(context.Background(), dur)
	defer benchCancel()

	// Receiver goroutine.
	var rxDone sync.WaitGroup
	rxDone.Add(1)
	go func() {
		defer rxDone.Done()
		for {
			e, err := ch.Recv(benchCtx)
			if err != nil {
				return
			}
			rxMsgs.Add(1)
			rxBytes.Add(int64(len(e.Payload)))
		}
	}()

	// Sender goroutine.
	var txDone sync.WaitGroup
	txDone.Add(1)
	go func() {
		defer txDone.Done()
		e := &wiresocket.Event{Type: 1, Payload: payload}
		for {
			if err := ch.Send(benchCtx, e); err != nil {
				return
			}
			txMsgs.Add(1)
			txBytes.Add(int64(payloadSize))
		}
	}()

	<-benchCtx.Done()
	txDone.Wait()
	rxDone.Wait()

	secs := dur.Seconds()
	tx := txBytes.Load()
	rx := rxBytes.Load()
	return [4]float64{
		float64(txMsgs.Load()) / secs,
		float64(tx) / 1e6 / secs,
		float64(rxMsgs.Load()) / secs,
		float64(rx) / 1e6 / secs,
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
