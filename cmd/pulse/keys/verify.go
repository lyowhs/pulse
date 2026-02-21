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

	cmd.Flags().String("pubkey", "", "hex, base58, or binary encoded verifying key (required, env: PULSE_PUBKEY)")
	cmd.Flags().String("message", "", "message that was signed (required, env: PULSE_MESSAGE)")
	cmd.Flags().String("signature", "", "signature to verify (required, env: PULSE_SIGNATURE)")
	cmd.Flags().Bool("base64", false, "signature is base64-encoded")
	cmd.Flags().Bool("binary", false, "signature is raw binary bytes")
	cmd.MarkFlagsMutuallyExclusive("base64", "binary")

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
	useBase64, _ := cmd.Flags().GetBool("base64")
	useBinary, _ := cmd.Flags().GetBool("binary")

	if pubkey == "" {
		return fmt.Errorf("--pubkey is required")
	}
	if msg == "" {
		return fmt.Errorf("--message is required")
	}
	if sigStr == "" {
		return fmt.Errorf("--signature is required")
	}
	if !useBase64 && !useBinary {
		return fmt.Errorf("one of --base64 or --binary is required")
	}

	// keys.Verify expects a base64-encoded signature; encode raw bytes if needed.
	if useBinary {
		sigStr = base64.StdEncoding.EncodeToString([]byte(sigStr))
	}

	ok, err := keys.Verify(pubkey, []byte(msg), sigStr)
	if err != nil {
		return err
	}
	if ok {
		fmt.Println("signature valid")
		return nil
	}

	return fmt.Errorf("signature invalid")
}
