package main

import (
	"crypto"
	"example.com/pulse/pulse/pkg/crypto/falcon"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a message using a Falcon signing key",
	RunE:  runSign,
}

func init() {
	signCmd.Flags().String("sk", "", "path to signing key file (required, env: PULSE_SK)")
	signCmd.Flags().String("msg", "", "message to sign (required, env: PULSE_MSG)")
	signCmd.Flags().String("out", "sig.bin", "output path for signature")

	viper.BindPFlag("sk", signCmd.Flags().Lookup("sk"))
	viper.BindPFlag("msg", signCmd.Flags().Lookup("msg"))
	viper.BindPFlag("out", signCmd.Flags().Lookup("out"))

	keysCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) error {
	skPath := viper.GetString("sk")
	msg := viper.GetString("msg")
	outPath := viper.GetString("out")

	if skPath == "" {
		return fmt.Errorf("--sk is required")
	}
	if msg == "" {
		return fmt.Errorf("--msg is required")
	}

	skey, err := os.ReadFile(skPath)
	if err != nil {
		return fmt.Errorf("failed to read signing key: %w", err)
	}

	sig, err := fndsa.Sign(nil, skey, fndsa.DOMAIN_NONE, crypto.Hash(0), []byte(msg))
	if err != nil {
		return fmt.Errorf("sign failed: %w", err)
	}

	if err := os.WriteFile(outPath, sig, 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	fmt.Printf("signature → %s (%d bytes)\n", outPath, len(sig))
	return nil
}
