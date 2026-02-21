package keys

import (
	"encoding/base64"
	"fmt"
	"os"

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
	cmd.Flags().Bool("base64", false, "output signature as a base64-encoded string")
	cmd.Flags().Bool("binary", false, "output signature as raw binary bytes")
	cmd.MarkFlagsMutuallyExclusive("base64", "binary")

	return cmd
}

func runSign(cmd *cobra.Command, args []string) error {
	key := viper.GetString("key")
	msg, _ := cmd.Flags().GetString("message")
	if msg == "" {
		msg = viper.GetString("message")
	}
	useBase64, _ := cmd.Flags().GetBool("base64")
	useBinary, _ := cmd.Flags().GetBool("binary")

	if key == "" {
		return fmt.Errorf("--key is required")
	}
	if msg == "" {
		return fmt.Errorf("--message is required")
	}
	if !useBase64 && !useBinary {
		return fmt.Errorf("one of --base64 or --binary is required")
	}

	sig, err := keys.Sign(key, []byte(msg))
	if err != nil {
		return err
	}

	if useBinary {
		raw, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			return err
		}
		os.Stdout.Write(raw)
		return nil
	}

	fmt.Println(sig)
	return nil
}
