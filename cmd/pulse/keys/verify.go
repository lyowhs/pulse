package keys

import (
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
