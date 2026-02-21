package keys

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	fndsa "example.com/pulse/pulse/pkg/crypto/falcon"
)

func verifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a Falcon signature",
		RunE:  runVerify,
	}

	cmd.Flags().String("pubkey", "", "hex or base58 encoded verifying key (required, env: PULSE_PUBKEY)")
	cmd.Flags().String("message", "", "message that was signed (required, env: PULSE_MESSAGE)")
	cmd.Flags().String("signature", "", "base64 encoded signature (required, env: PULSE_SIGNATURE)")

	viper.BindPFlag("pubkey", cmd.Flags().Lookup("pubkey"))
	viper.BindPFlag("signature", cmd.Flags().Lookup("signature"))

	return cmd
}

func runVerify(cmd *cobra.Command, args []string) error {
	pubkey := viper.GetString("pubkey")
	msg, _ := cmd.Flags().GetString("message")
	if msg == "" {
		msg = viper.GetString("message")
	}
	sigStr := viper.GetString("signature")

	if pubkey == "" {
		return fmt.Errorf("--pubkey is required")
	}
	if msg == "" {
		return fmt.Errorf("--message is required")
	}
	if sigStr == "" {
		return fmt.Errorf("--signature is required")
	}

	vkey, _, err := decodeKey(pubkey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	ok := fndsa.Verify(vkey, fndsa.DOMAIN_NONE, crypto.Hash(0), []byte(msg), sig)
	if ok {
		fmt.Println("signature valid")
		return nil
	}

	return fmt.Errorf("signature invalid")
}
