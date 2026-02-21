package main

import (
	"crypto"
	"encoding/base64"
	"example.com/pulse/pulse/pkg/crypto/falcon"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a message using a Falcon signing key",
	RunE:  runSign,
}

func init() {
	signCmd.Flags().String("key", "", "hex or base58 encoded signing key (required, env: PULSE_KEY)")
	signCmd.Flags().String("message", "", "message to sign (required, env: PULSE_MESSAGE)")

	viper.BindPFlag("key", signCmd.Flags().Lookup("key"))
	viper.BindPFlag("message", signCmd.Flags().Lookup("message"))

	keysCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) error {
	key := viper.GetString("key")
	msg := viper.GetString("message")

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
