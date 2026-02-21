package main

import (
	"crypto"
	"example.com/pulse/pulse/pkg/crypto/falcon"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a Falcon signature",
	RunE:  runVerify,
}

func init() {
	verifyCmd.Flags().String("vk", "", "path to verifying key file (required, env: PULSE_VK)")
	verifyCmd.Flags().String("msg", "", "message that was signed (required, env: PULSE_MSG)")
	verifyCmd.Flags().String("sig", "", "path to signature file (required, env: PULSE_SIG)")

	viper.BindPFlag("vk", verifyCmd.Flags().Lookup("vk"))
	viper.BindPFlag("sig", verifyCmd.Flags().Lookup("sig"))

	keysCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	vkPath := viper.GetString("vk")
	msg := viper.GetString("msg")
	sigPath := viper.GetString("sig")

	if vkPath == "" {
		return fmt.Errorf("--vk is required")
	}
	if msg == "" {
		return fmt.Errorf("--msg is required")
	}
	if sigPath == "" {
		return fmt.Errorf("--sig is required")
	}

	vkey, err := os.ReadFile(vkPath)
	if err != nil {
		return fmt.Errorf("failed to read verifying key: %w", err)
	}

	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	ok := fndsa.Verify(vkey, fndsa.DOMAIN_NONE, crypto.Hash(0), []byte(msg), sig)
	if ok {
		fmt.Println("signature valid")
		return nil
	}

	return fmt.Errorf("signature invalid")
}
