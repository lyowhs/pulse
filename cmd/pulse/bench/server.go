package bench

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/wiresocket"
)

func serverCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start a benchmark echo server",
		RunE:  runServer,
	}
	cmd.Flags().String("addr", ":9001", "UDP address to listen on")
	cmd.Flags().String("key", "", "hex-encoded server private key (generated if omitted)")
	cmd.Flags().Int("mtu", 1472, "UDP payload MTU in bytes")
	cmd.Flags().Duration("coalesce", 100*time.Microsecond, "coalesce interval; 0 disables coalescing")
	cmd.Flags().Bool("reliable", true, "use reliable delivery (default: on; set --reliable=false to disable)")
	return cmd
}

func runServer(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("addr")
	keyHex, _ := cmd.Flags().GetString("key")
	mtu, _ := cmd.Flags().GetInt("mtu")
	coalesce, _ := cmd.Flags().GetDuration("coalesce")
	reliable, _ := cmd.Flags().GetBool("reliable")

	var privKey [32]byte
	if keyHex == "" {
		kp, err := wiresocket.GenerateKeypair()
		if err != nil {
			return fmt.Errorf("generate keypair: %w", err)
		}
		privKey = kp.Private
		fmt.Fprintf(os.Stderr, "private key: %s\n", hex.EncodeToString(privKey[:]))
		fmt.Fprintf(os.Stderr, "public key:  %s\n", hex.EncodeToString(kp.Public[:]))
	} else {
		b, err := hex.DecodeString(keyHex)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("--key must be a 64-character hex string (32 bytes)")
		}
		copy(privKey[:], b)
	}

	// Compute server parameters that match what a well-configured bench client
	// will use.  The client's inflightCap is bounded by its socket buffer; we
	// probe the same buffer here so the server's reassembly table and event
	// channel never become the bottleneck.
	const (
		sizeDataHdr = 16
		sizeFragHdr = 8
		sizeAEAD    = 16
		minMaxInc   = 512 // matches bench run's maxReassembly floor
		requested   = 4 << 20
	)
	// Worst-case inflightCap: assume one fragment per frame (smallest payload).
	// A higher real fragsPerEvent reduces inflightCap further, so this is safe.
	actualBuf := wiresocket.ProbeUDPRecvBufSize(requested)
	socketBuf := actualBuf * 3 / 4
	inflightCap := socketBuf / mtu
	if inflightCap < 4 {
		inflightCap = 4
	}

	srvMaxIncomplete := minMaxInc
	if inflightCap > srvMaxIncomplete {
		srvMaxIncomplete = inflightCap
	}

	// EventBufSize must hold all in-flight events without overflow so the
	// server's myWindow() never collapses the client's send window to near zero.
	eventBufSize := 256
	if inflightCap > eventBufSize {
		eventBufSize = inflightCap
	}

	// With reliable delivery, serialise packet processing to prevent goroutine
	// scheduling reorder on loopback from creating OOO gaps larger than the
	// reliableOOOWindow.
	workerCount := 0 // default: GOMAXPROCS
	if reliable {
		workerCount = 1
	}

	srvCfg := wiresocket.ServerConfig{
		Addr:                   addr,
		PrivateKey:             privKey,
		OnConnect:              echoConn,
		MaxPacketSize:          mtu,
		CoalesceInterval:       coalesce,
		MaxIncompleteFrames:    srvMaxIncomplete,
		EventBufSize:           eventBufSize,
		WorkerCount:            workerCount,
		DisableDefaultReliable: !reliable,
	}
	srv, err := wiresocket.NewServer(srvCfg)
	if err != nil {
		return err
	}

	pub := srv.PublicKey()
	fmt.Fprintf(os.Stderr, "bench server listening on %s\n", addr)
	fmt.Fprintf(os.Stderr, "public key: %s\n", hex.EncodeToString(pub[:]))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.Serve(ctx)
}

