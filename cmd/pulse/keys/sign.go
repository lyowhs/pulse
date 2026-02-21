package keys

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"example.com/pulse/pulse/pkg/keys"
)

func signCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a message using a signing key",
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

	sig, err := keys.Sign(key, []byte(msg))
	if err != nil {
		return err
	}

	fmt.Println(sig)
	return nil
}
