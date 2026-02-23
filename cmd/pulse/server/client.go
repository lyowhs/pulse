package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/wiresocket"
	"example.com/pulse/pulse/pkg/wiresocket/proto"
)

func clientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client <server-addr>",
		Short: "Connect to a wiresocket server and send periodic test events",
		Args:  cobra.ExactArgs(1),
		RunE:  runClient,
	}

	cmd.Flags().String("pubkey", "", "hex-encoded server public key (required)")
	cmd.MarkFlagRequired("pubkey")
	cmd.Flags().Duration("interval", 3*time.Second, "how often to send a test event")
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
		ServerPublicKey: serverPub,
		PrivateKey:      privKey,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	logger.Printf("connected (local session index %d)", conn.LocalIndex())

	ch := conn.Channel(appChannel)

	var seq atomic.Uint64

	// Receive loop.
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for {
			e, err := ch.Recv(ctx)
			if err != nil {
				return
			}
			logger.Printf("← " + formatEvent(serverAddr, e))
		}
	}()

	// Send loop: fire a test event every interval.
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			<-recvDone
			return nil
		case <-conn.Done():
			<-recvDone
			return fmt.Errorf("connection closed by server")
		case <-recvDone:
			return fmt.Errorf("receive loop ended unexpectedly")
		case t := <-ticker.C:
			s := seq.Add(1)
			e := &proto.Event{
				Sequence:    s,
				TimestampUs: t.UnixMicro(),
				Type:        eventTypeTest,
				Payload:     []byte(fmt.Sprintf("event #%d from pulse client", s)),
			}
			if err := ch.Send(ctx, e); err != nil {
				return fmt.Errorf("send: %w", err)
			}
			logger.Printf("→ " + formatEvent(serverAddr, e))
		}
	}
}

// formatEvent returns a single-line description of an event, reusing the same
// payload rendering logic as logEvent in serve.go.
func formatEvent(remote string, e *proto.Event) string {
	ts := time.UnixMicro(e.TimestampUs).UTC().Format(time.RFC3339Nano)
	base := fmt.Sprintf("[%s] seq=%-6d ts=%s type=%d",
		remote, e.Sequence, ts, e.Type)
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
