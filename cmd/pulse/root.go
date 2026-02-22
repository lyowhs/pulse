package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"example.com/pulse/pulse/cmd/pulse/keys"
	"example.com/pulse/pulse/cmd/pulse/server"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "pulse",
	Short: "Post-quantum cryptography CLI",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.pulse.yaml)")
	rootCmd.AddCommand(keys.Command())
	rootCmd.AddCommand(server.Command())
}

func initConfig() {
	viper.SetEnvPrefix("PULSE")
	viper.AutomaticEnv()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		viper.AddConfigPath(home)
		viper.SetConfigName(".pulse")
		viper.SetConfigType("yaml")
	}

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "using config file:", viper.ConfigFileUsed())
	}
}
