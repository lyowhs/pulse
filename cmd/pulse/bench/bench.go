package bench

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// benchChannel is the logical channel used for all benchmark traffic.
const benchChannel = uint16(1)

// Command returns the bench cobra command with server and client subcommands.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Measure wiresocket protocol throughput between a client and server",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			debug, _ := cmd.Flags().GetBool("debug")
			if debug {
				h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
				wiresocket.SetDebugLogger(slog.New(h))
			}
			return nil
		},
	}
	cmd.PersistentFlags().Bool("debug", false, "Enable verbose wiresocket protocol debug logging")
	cmd.AddCommand(serverCommand())
	cmd.AddCommand(clientCommand())
	cmd.AddCommand(runCommand())
	return cmd
}

// makeEchoConn returns an OnConnect handler that echoes every event received
// on benchChannel back to the sender.  When reliable is false, the channel is
// switched to unreliable (fire-and-forget) mode before the echo loop starts.
//
// With server-side coalescing enabled, ch.Send is non-blocking (pushes into
// the coalescer's input buffer and returns immediately), so a simple
// sequential recv→send loop is sufficient.
func makeEchoConn(reliable bool) func(*wiresocket.Conn) {
	return func(conn *wiresocket.Conn) {
		ch := conn.Channel(benchChannel)
		if !reliable {
			ch.SetUnreliable()
		}
		ctx := context.Background()
		for {
			e, err := ch.Recv(ctx)
			if err != nil {
				return
			}
			if err := ch.Send(ctx, e); err != nil {
				return
			}
		}
	}
}

// fmtSize formats a byte count using SI units (1 MB = 10^6 B).
func fmtSize(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.2f GB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.2f MB", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.2f KB", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d B", n)
	}
}
