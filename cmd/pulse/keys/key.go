package keys

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// signingKeyString returns the signing key for pubkey and sign commands.
// It reads raw bytes from --key-file when specified, otherwise falls back to
// --key (or PULSE_KEY from the environment).
func signingKeyString(cmd *cobra.Command) (string, error) {
	if keyFile := viper.GetString("key-file"); keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("--key-file: %w", err)
		}
		return string(data), nil
	}
	key := viper.GetString("key")
	if key == "" {
		return "", fmt.Errorf("one of --key or --key-file is required")
	}
	return key, nil
}

// verifyingKeyString returns the verifying key for the verify command.
// It reads raw bytes from --pubkey-file when specified, otherwise falls back
// to --pubkey (or PULSE_PUBKEY from the environment).
func verifyingKeyString(cmd *cobra.Command) (string, error) {
	if pubkeyFile, _ := cmd.Flags().GetString("pubkey-file"); pubkeyFile != "" {
		data, err := os.ReadFile(pubkeyFile)
		if err != nil {
			return "", fmt.Errorf("--pubkey-file: %w", err)
		}
		return string(data), nil
	}
	pubkey := viper.GetString("pubkey")
	if pubkey == "" {
		return "", fmt.Errorf("one of --pubkey or --pubkey-file is required")
	}
	return pubkey, nil
}
