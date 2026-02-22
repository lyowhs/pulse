package keys

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// messageBytes returns the message bytes for sign/verify commands.
// It reads from --message-file when specified, otherwise falls back to
// --message (or PULSE_MESSAGE from the environment).
func messageBytes(cmd *cobra.Command) ([]byte, error) {
	msgFile, _ := cmd.Flags().GetString("message-file")
	if msgFile != "" {
		data, err := os.ReadFile(msgFile)
		if err != nil {
			return nil, fmt.Errorf("--message-file: %w", err)
		}
		return data, nil
	}

	msg, _ := cmd.Flags().GetString("message")
	if msg == "" {
		msg = viper.GetString("message")
	}
	if msg == "" {
		return nil, fmt.Errorf("one of --message or --message-file is required")
	}
	return []byte(msg), nil
}
