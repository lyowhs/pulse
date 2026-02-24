package bench

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// benchChannel is the logical channel used for all benchmark traffic.
const benchChannel = uint8(1)

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
