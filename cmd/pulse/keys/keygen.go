package keys

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"example.com/pulse/pulse/pkg/keys"
)

func keygenCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new signing key pair",
		Long:  "Generate an FN-DSA key pair and print the signing key to stdout.",
		RunE:  runKeygen,
	}

	cmd.Flags().Bool("hex", false, "output signing key as a hex-encoded string")
	cmd.Flags().Bool("base58", false, "output signing key as a base58-encoded string")
	cmd.Flags().Bool("binary", false, "output signing key as raw binary bytes")
	cmd.MarkFlagsMutuallyExclusive("hex", "base58", "binary")

	return cmd
}

func runKeygen(cmd *cobra.Command, args []string) error {
	useHex, _ := cmd.Flags().GetBool("hex")
	useBase58, _ := cmd.Flags().GetBool("base58")
	useBinary, _ := cmd.Flags().GetBool("binary")

	if !useHex && !useBase58 && !useBinary {
		return fmt.Errorf("one of --hex, --base58, or --binary is required")
	}

	enc := keys.Base58
	switch {
	case useHex:
		enc = keys.Hex
	case useBinary:
		enc = keys.Binary
	}

	sk, err := keys.Generate(enc)
	if err != nil {
		return err
	}

	if useBinary {
		os.Stdout.Write([]byte(sk))
		return nil
	}
	fmt.Println(sk)
	return nil
}
