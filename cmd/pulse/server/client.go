package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/wiresocket"
)

func clientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client <server-addr>",
		Short: "Connect to a wiresocket server, send 100 KB echo events, and verify responses",
		Args:  cobra.ExactArgs(1),
		RunE:  runClient,
	}

	cmd.Flags().String("pubkey", "", "hex-encoded server public key (required)")
	cmd.MarkFlagRequired("pubkey")
	cmd.Flags().Duration("interval", time.Minute, "how often to send a 100 KB echo event")
	cmd.Flags().String("key", "", "hex-encoded client private key (generated if omitted)")

	return cmd
}

func runClient(cmd *cobra.Command, args []string) error {
	serverAddr := args[0]

	pubkeyHex, _ := cmd.Flags().GetString("pubkey")
	interval, _ := cmd.Flags().GetDuration("interval")
	keyHex, _ := cmd.Flags().GetString("key")

	var serverPub [32]byte
	b, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("--pubkey must be a 64-character hex string (32 bytes)")
	}
	copy(serverPub[:], b)

	var privKey [32]byte
	if keyHex != "" {
		b, err := hex.DecodeString(keyHex)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("--key must be a 64-character hex string (32 bytes)")
		}
		copy(privKey[:], b)
	}

	logger := log.New(os.Stdout, "", 0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Printf("connecting to %s …", serverAddr)

	conn, err := wiresocket.Dial(ctx, serverAddr, wiresocket.DialConfig{
		ServerPublicKey:   serverPub,
		PrivateKey:        privKey,
		ReconnectMin:      250 * time.Millisecond,
		KeepaliveInterval: 2 * time.Second,
		SessionTimeout:    10 * time.Second,
		MaxPacketSize:     65000,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	logger.Printf("connected to %s", serverAddr)

	ch := conn.Channel(appChannel)

	// echoCh carries the payload most recently sent so the receive loop can
	// verify the server echoed it back correctly.  Capacity 1: at most one
	// echo is in-flight at a time.
	echoCh := make(chan []byte, 1)

	// Receive loop: match incoming events against the pending echo payload.
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for {
			e, err := ch.Recv(ctx)
			if err != nil {
				return
			}
			select {
			case expected := <-echoCh:
				if bytes.Equal(e.Payload, expected) {
					logger.Printf("← echo ok    %d bytes verified", len(expected))
				} else {
					logger.Printf("← echo FAIL  got %d bytes, want %d bytes",
						len(e.Payload), len(expected))
				}
			default:
				logger.Printf("← unexpected %s", formatEvent(serverAddr, appChannel, e))
			}
		}
	}()

	// Send loop: every interval generate a fresh 100 KB random payload and
	// send it as an echo request.
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var seq uint64

	for {
		select {
		case <-ctx.Done():
			<-recvDone
			return nil
		case <-recvDone:
			return fmt.Errorf("receive loop ended unexpectedly")
		case <-ticker.C:
			payload := make([]byte, 100*1024)
			if _, err := rand.Read(payload); err != nil {
				return fmt.Errorf("generate payload: %w", err)
			}
			seq++
			e := &wiresocket.Event{
				Type:    eventTypeTest,
				Payload: payload,
			}
			if err := ch.Send(ctx, e); err != nil {
				return fmt.Errorf("send: %w", err)
			}
			// Register expected payload; discard any unverified previous one.
			select {
			case echoCh <- payload:
			default:
				<-echoCh
				echoCh <- payload
			}
			logger.Printf("→ echo req   #%-6d 100 KB sent", seq)
		}
	}
}

// formatEvent returns a single-line description of an event.
func formatEvent(remote string, ch uint16, e *wiresocket.Event) string {
	base := fmt.Sprintf("[%s] ch=%-3d type=%d", remote, ch, e.Type)
	switch {
	case len(e.Payload) == 0:
		return base
	case isPrintable(e.Payload) && len(e.Payload) <= 120:
		return base + fmt.Sprintf(" payload=%q", e.Payload)
	default:
		return base + fmt.Sprintf(" payload=<%d bytes> hex=%s",
			len(e.Payload),
			hex.EncodeToString(e.Payload[:min(len(e.Payload), 16)])+"…")
	}
}
