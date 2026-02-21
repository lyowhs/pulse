package keys

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Command returns the keys cobra command with all subcommands registered.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Key generation and signature operations",
	}

	cmd.PersistentFlags().String("key", "", "hex or base58 encoded signing key (env: PULSE_KEY)")
	viper.BindPFlag("key", cmd.PersistentFlags().Lookup("key"))

	cmd.AddCommand(keygenCommand())
	cmd.AddCommand(pubkeyCommand())
	cmd.AddCommand(signCommand())
	cmd.AddCommand(verifyCommand())

	return cmd
}
