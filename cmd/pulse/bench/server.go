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
	cmd.Flags().StringArray("allowed-keys", nil, "hex-encoded client public key to whitelist (may be repeated)")
	return cmd
}

func runServer(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("addr")
	keyHex, _ := cmd.Flags().GetString("key")
	mtu, _ := cmd.Flags().GetInt("mtu")
	coalesce, _ := cmd.Flags().GetDuration("coalesce")
	reliable, _ := cmd.Flags().GetBool("reliable")
	allowedKeyHexes, _ := cmd.Flags().GetStringArray("allowed-keys")

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

	// Parse --allowed-keys into a slice of [32]byte public keys.
	var allowedPeers [][32]byte
	for _, h := range allowedKeyHexes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("--allowed-keys: %q must be a 64-character hex string (32 bytes)", h)
		}
		var pk [32]byte
		copy(pk[:], b)
		allowedPeers = append(allowedPeers, pk)
	}

	// With reliable delivery, serialise packet processing to prevent goroutine
	// scheduling reorder on loopback from creating OOO gaps larger than the
	// reliableOOOWindow.
	workerCount := 0 // default: GOMAXPROCS
	if reliable {
		workerCount = 1
	}

	// MaxIncompleteFrames and EventBufSize are auto-computed by the library
	// from the kernel UDP socket buffer size.
	srvCfg := wiresocket.ServerConfig{
		Addr:             addr,
		PrivateKey:       privKey,
		OnConnect:        makeEchoConn(reliable),
		MaxPacketSize:    mtu,
		CoalesceInterval: coalesce,
		WorkerCount:      workerCount,
		AllowedPeers:     allowedPeers,
	}
	srv, err := wiresocket.NewServer(srvCfg)
	if err != nil {
		return err
	}

	pub := srv.PublicKey()
	fmt.Fprintf(os.Stderr, "bench server listening on %s\n", addr)
	fmt.Fprintf(os.Stderr, "public key: %s\n", hex.EncodeToString(pub[:]))
	if len(allowedPeers) > 0 {
		fmt.Fprintf(os.Stderr, "allowed peers: %d key(s)\n", len(allowedPeers))
	} else {
		fmt.Fprintf(os.Stderr, "allowed peers: all (no whitelist)\n")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.Serve(ctx)
}

