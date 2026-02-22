package keys

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"example.com/pulse/pulse/pkg/keys"
)

func signCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a message using a signing key",
		RunE:  runSign,
	}

	cmd.Flags().String("message", "", "message string to sign (env: PULSE_MESSAGE)")
	cmd.Flags().String("message-file", "", "file whose contents to sign (binary-safe)")
	cmd.MarkFlagsMutuallyExclusive("message", "message-file")

	cmd.Flags().Bool("base64", false, "output signature as a base64-encoded string")
	cmd.Flags().Bool("binary", false, "output signature as raw binary bytes")
	cmd.MarkFlagsMutuallyExclusive("base64", "binary")

	return cmd
}

func runSign(cmd *cobra.Command, args []string) error {
	key, err := signingKeyString(cmd)
	if err != nil {
		return err
	}
	useBase64, _ := cmd.Flags().GetBool("base64")
	useBinary, _ := cmd.Flags().GetBool("binary")

	if !useBase64 && !useBinary {
		return fmt.Errorf("one of --base64 or --binary is required")
	}

	msgBytes, err := messageBytes(cmd)
	if err != nil {
		return err
	}

	sig, err := keys.Sign(key, msgBytes)
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
