package keys

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	fndsa "example.com/pulse/pulse/pkg/crypto/falcon"
)

func signCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a message using a Falcon signing key",
		RunE:  runSign,
	}

	cmd.Flags().String("message", "", "message to sign (required, env: PULSE_MESSAGE)")

	return cmd
}

func runSign(cmd *cobra.Command, args []string) error {
	key := viper.GetString("key")
	msg, _ := cmd.Flags().GetString("message")
	if msg == "" {
		msg = viper.GetString("message")
	}

	if key == "" {
		return fmt.Errorf("--key is required")
	}
	if msg == "" {
		return fmt.Errorf("--message is required")
	}

	skey, _, err := decodeKey(key)
	if err != nil {
		return fmt.Errorf("failed to decode signing key: %w", err)
	}

	sig, err := fndsa.Sign(nil, skey, fndsa.DOMAIN_NONE, crypto.Hash(0), []byte(msg))
	if err != nil {
		return fmt.Errorf("sign failed: %w", err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(sig))
	return nil
}
