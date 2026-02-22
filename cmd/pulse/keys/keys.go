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

	cmd.PersistentFlags().String("key", "", "hex, base58, or binary encoded signing key (env: PULSE_KEY)")
	cmd.PersistentFlags().String("key-file", "", "file containing the signing key — binary-safe alternative to --key (env: PULSE_KEY_FILE)")
	viper.BindPFlag("key", cmd.PersistentFlags().Lookup("key"))
	viper.BindPFlag("key-file", cmd.PersistentFlags().Lookup("key-file"))
	cmd.MarkFlagsMutuallyExclusive("key", "key-file")

	cmd.AddCommand(keygenCommand())
	cmd.AddCommand(pubkeyCommand())
	cmd.AddCommand(signCommand())
	cmd.AddCommand(verifyCommand())

	return cmd
}
