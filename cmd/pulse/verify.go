package main

import (
	"crypto"
	"encoding/base64"
	"example.com/pulse/pulse/pkg/crypto/falcon"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a Falcon signature",
	RunE:  runVerify,
}

func init() {
	verifyCmd.Flags().String("pubkey", "", "path to verifying key file (required, env: PULSE_PUBKEY)")
	verifyCmd.Flags().String("message", "", "message that was signed (required, env: PULSE_MESSAGE)")
	verifyCmd.Flags().String("signature", "", "base64 encoded signature (required, env: PULSE_SIGNATURE)")

	viper.BindPFlag("pubkey", verifyCmd.Flags().Lookup("pubkey"))
	viper.BindPFlag("signature", verifyCmd.Flags().Lookup("signature"))

	keysCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	pubkey := viper.GetString("pubkey")
	msg := viper.GetString("message")
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

	sig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	ok := fndsa.Verify([]byte(pubkey), fndsa.DOMAIN_NONE, crypto.Hash(0), []byte(msg), sig)
	if ok {
		fmt.Println("signature valid")
		return nil
	}

	return fmt.Errorf("signature invalid")
}
