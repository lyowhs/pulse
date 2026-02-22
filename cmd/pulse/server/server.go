package server

import "github.com/spf13/cobra"

// Command returns the server cobra command with all subcommands registered.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Wiresocket server operations",
	}
	cmd.AddCommand(serveCommand())
	cmd.AddCommand(pingCommand())
	return cmd
}
