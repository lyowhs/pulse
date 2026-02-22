package keys

import (
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"example.com/pulse/pulse/pkg/keys"
)

func verifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a signature",
		RunE:  runVerify,
	}

	cmd.Flags().String("pubkey", "", "hex, base58, or binary encoded verifying key (env: PULSE_PUBKEY)")
	cmd.Flags().String("pubkey-file", "", "file containing the verifying key — binary-safe alternative to --pubkey (env: PULSE_PUBKEY_FILE)")
	cmd.MarkFlagsMutuallyExclusive("pubkey", "pubkey-file")

	cmd.Flags().String("message", "", "message string that was signed (env: PULSE_MESSAGE)")
	cmd.Flags().String("message-file", "", "file whose contents were signed (binary-safe)")
	cmd.MarkFlagsMutuallyExclusive("message", "message-file")

	cmd.Flags().String("signature", "", "base64 or binary encoded signature (required, env: PULSE_SIGNATURE)")

	viper.BindPFlag("pubkey", cmd.Flags().Lookup("pubkey"))
	viper.BindPFlag("pubkey-file", cmd.Flags().Lookup("pubkey-file"))
	viper.BindPFlag("signature", cmd.Flags().Lookup("signature"))

	return cmd
}

func runVerify(cmd *cobra.Command, args []string) error {
	pubkey, err := verifyingKeyString(cmd)
	if err != nil {
		return err
	}
	sigStr := viper.GetString("signature")
	if sigStr == "" {
		return fmt.Errorf("--signature is required")
	}

	msgBytes, err := messageBytes(cmd)
	if err != nil {
		return err
	}

	// Auto-detect encoding: if the value is not valid base64, treat it as raw
	// binary bytes and encode it so keys.Verify always receives base64.
	if _, err := base64.StdEncoding.DecodeString(sigStr); err != nil {
		sigStr = base64.StdEncoding.EncodeToString([]byte(sigStr))
	}

	ok, err := keys.Verify(pubkey, msgBytes, sigStr)
	if err != nil {
		return err
	}
	if ok {
		fmt.Println("signature valid")
		return nil
	}

	return fmt.Errorf("signature invalid")
}
