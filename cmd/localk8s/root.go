package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "localk8s",
	Short: "Create, manage, and destroy a local k8s cluster for testing the policy controller",
	Long:  "Create, manage, and destroy a local k8s cluster for testing the policy controller",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
