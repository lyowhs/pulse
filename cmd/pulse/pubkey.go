package main

import (
	"encoding/hex"
	falcon "example.com/pulse/pulse/pkg/crypto/falcon"
	"fmt"

	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var pubkeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Derive the public key from a secret key",
	Long:  "Derive the Falcon verifying (public) key from a hex or base58 encoded signing (secret) key. The output encoding matches the input encoding.",
	RunE:  runPubkey,
}

func init() {
	keysCmd.AddCommand(pubkeyCmd)
}

func runPubkey(cmd *cobra.Command, args []string) error {
	input := viper.GetString("key")
	if input == "" {
		return fmt.Errorf("--key is required")
	}

	skey, isHex, err := decodeKey(input)
	if err != nil {
		return fmt.Errorf("failed to decode secret key: %w", err)
	}

	vkey, err := falcon.PublicKeyFromSecretKey(skey)
	if err != nil {
		return fmt.Errorf("failed to derive public key: %w", err)
	}

	if isHex {
		fmt.Println(hex.EncodeToString(vkey))
	} else {
		fmt.Println(base58.Encode(vkey))
	}
	return nil
}

// decodeKey attempts to decode the input as hex first, then falls back to
// base58. Returns the decoded bytes and whether hex encoding was used.
func decodeKey(input string) ([]byte, bool, error) {
	if b, err := hex.DecodeString(input); err == nil {
		return b, true, nil
	}
	b, err := base58.Decode(input)
	if err != nil {
		return nil, false, fmt.Errorf("input is neither valid hex nor valid base58")
	}
	return b, false, nil
}
