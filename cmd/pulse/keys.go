package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Key generation and signature operations",
}

func init() {
	keysCmd.PersistentFlags().String("key", "", "hex or base58 encoded signing key (env: PULSE_KEY)")
	viper.BindPFlag("key", keysCmd.PersistentFlags().Lookup("key"))
	rootCmd.AddCommand(keysCmd)
}
