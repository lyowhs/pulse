package main

import "github.com/spf13/cobra"

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Key generation and signature operations",
}

func init() {
	rootCmd.AddCommand(keysCmd)
}
