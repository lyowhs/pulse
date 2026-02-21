package keys

import (
	"fmt"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/keys"
)

func keygenCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new Falcon-512 key pair",
		Long:  "Generate a Falcon-512 (FN-DSA) key pair and print the signing key to stdout.",
		RunE:  runKeygen,
	}

	cmd.Flags().Bool("hex", false, "output signing key as a hex-encoded string")
	cmd.Flags().Bool("base58", false, "output signing key as a base58-encoded string")
	cmd.MarkFlagsMutuallyExclusive("hex", "base58")

	return cmd
}

func runKeygen(cmd *cobra.Command, args []string) error {
	useHex, _ := cmd.Flags().GetBool("hex")
	useBase58, _ := cmd.Flags().GetBool("base58")

	if !useHex && !useBase58 {
		return fmt.Errorf("one of --hex or --base58 is required")
	}

	enc := keys.Base58
	if useHex {
		enc = keys.Hex
	}

	sk, err := keys.Generate(enc)
	if err != nil {
		return err
	}

	fmt.Println(sk)
	return nil
}
