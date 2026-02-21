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
	signCmd.Flags().String("sk", "", "hex or base58 encoded signing key (required, env: PULSE_SK)")
	signCmd.Flags().String("msg", "", "message to sign (required, env: PULSE_MSG)")

	viper.BindPFlag("sk", signCmd.Flags().Lookup("sk"))
	viper.BindPFlag("msg", signCmd.Flags().Lookup("msg"))

	keysCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) error {
	skPath := viper.GetString("sk")
	msg := viper.GetString("msg")

	if skPath == "" {
		return fmt.Errorf("--sk is required")
	}
	if msg == "" {
		return fmt.Errorf("--msg is required")
	}

	skey, _, err := decodeKey(skPath)
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
