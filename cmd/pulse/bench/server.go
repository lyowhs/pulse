package bench

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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
	return cmd
}

func runServer(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("addr")
	keyHex, _ := cmd.Flags().GetString("key")

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

	srv, err := wiresocket.NewServer(wiresocket.ServerConfig{
		Addr:      addr,
		PrivateKey: privKey,
		OnConnect: echoConn,
	})
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

