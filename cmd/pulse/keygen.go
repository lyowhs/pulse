package main

import (
	"encoding/hex"
	"fmt"

	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"

	falcon "example.com/pulse/pulse/pkg/falcon"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new Falcon-512 key pair",
	Long:  "Generate a Falcon-512 (FN-DSA) key pair and print the signing key to stdout.",
	RunE:  runKeygen,
}

func init() {
	keygenCmd.Flags().Bool("hex", false, "output signing key as a hex-encoded string")
	keygenCmd.Flags().Bool("base58", false, "output signing key as a base58-encoded string")
	keygenCmd.MarkFlagsMutuallyExclusive("hex", "base58")
	keysCmd.AddCommand(keygenCmd)
}

func runKeygen(cmd *cobra.Command, args []string) error {
	useHex, _ := cmd.Flags().GetBool("hex")
	useBase58, _ := cmd.Flags().GetBool("base58")

	if !useHex && !useBase58 {
		return fmt.Errorf("one of --hex or --base58 is required")
	}

	skey, _, err := falcon.KeyGen(9, nil)
	if err != nil {
		return fmt.Errorf("keygen failed: %w", err)
	}

	if useHex {
		fmt.Println(hex.EncodeToString(skey))
	} else {
		fmt.Println(base58.Encode(skey))
	}
	return nil
}
