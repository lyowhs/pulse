package keys

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"example.com/pulse/pulse/pkg/keys"
)

func pubkeyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "pubkey",
		Short: "Derive the public key from a secret key",
		Long:  "Derive the Falcon verifying (public) key from a hex or base58 encoded signing (secret) key. The output encoding matches the input encoding.",
		RunE:  runPubkey,
	}
}

func runPubkey(cmd *cobra.Command, args []string) error {
	input := viper.GetString("key")
	if input == "" {
		return fmt.Errorf("--key is required")
	}

	pk, err := keys.PublicKey(input)
	if err != nil {
		return err
	}

	fmt.Println(pk)
	return nil
}
