package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/wiresocket"
	"example.com/pulse/pulse/pkg/wiresocket/proto"
)

func serveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a wiresocket server and log incoming events",
		RunE:  runServe,
	}

	cmd.Flags().String("addr", ":9000", "UDP address to listen on")
	cmd.Flags().String("key", "", "hex-encoded server private key (generated if omitted)")

	return cmd
}

func runServe(cmd *cobra.Command, _ []string) error {
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

	logger := log.New(os.Stdout, "", 0)

	srv, err := wiresocket.NewServer(wiresocket.ServerConfig{
		Addr:              addr,
		PrivateKey:        privKey,
		OnConnect:         makeHandler(logger),
		KeepaliveInterval: 3 * time.Second,
	})
	if err != nil {
		return err
	}

	pub := srv.PublicKey()
	logger.Printf("wiresocket server listening on %s", addr)
	logger.Printf("public key: %s", hex.EncodeToString(pub[:]))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.Serve(ctx)
}

const (
	appChannel    = uint8(17)
	eventTypeTest = uint8(1)
)

func makeHandler(logger *log.Logger) func(*wiresocket.Conn) {
	return func(conn *wiresocket.Conn) {
		logger.Printf("[%s] connected", conn.RemoteAddr())
		defer logger.Printf("[%s] disconnected", conn.RemoteAddr())

		ch := conn.Channel(appChannel)
		for {
			e, err := ch.Recv(context.Background())
			if err != nil {
				return
			}
			logEvent(logger, conn.RemoteAddr(), e)
			if err := ch.Send(context.Background(), e); err != nil {
				logger.Printf("[%s] echo error: %v", conn.RemoteAddr(), err)
				return
			}
		}
	}
}

func logEvent(logger *log.Logger, remote string, e *proto.Event) {
	switch {
	case len(e.Payload) == 0:
		logger.Printf("[%s] ch=%-3d type=%d", remote, e.ChannelId, e.Type)
	case isPrintable(e.Payload) && len(e.Payload) <= 120:
		logger.Printf("[%s] ch=%-3d type=%d payload=%q", remote, e.ChannelId, e.Type, e.Payload)
	default:
		logger.Printf("[%s] ch=%-3d type=%d payload=<%d bytes> hex=%s",
			remote, e.ChannelId, e.Type, len(e.Payload),
			hex.EncodeToString(e.Payload[:min(len(e.Payload), 16)])+"…")
	}
}

// isPrintable reports whether b contains only printable ASCII characters.
func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
