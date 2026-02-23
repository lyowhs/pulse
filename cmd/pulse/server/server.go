package server

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/wiresocket"
)

// Command returns the server cobra command with all subcommands registered.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Wiresocket server operations",
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
	cmd.AddCommand(serveCommand())
	cmd.AddCommand(pingCommand())
	return cmd
}
