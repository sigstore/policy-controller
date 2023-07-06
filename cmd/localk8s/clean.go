package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addCleanFlags(cmd *cobra.Command) {
	cmd.Flags().String("cluster-name", "policy-controller-demo", "name of the dev policy controller cluster")
}

func init() {
	addCleanFlags(cleanCmd)
	rootCmd.AddCommand(cleanCmd)
}

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "cleanup the local k8s cluster",
	Long:  "Cleanup the local k8s cluster",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Fatal("Error initializing cmd line args: ", err)
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		clean()
	},
}

func clean() {
	var stderr bytes.Buffer

	// clean up the local cluster
	fmt.Println("Cleaning up the kind cluster...")

	clusterName := viper.GetString("cluster-name")
	removeCluster := exec.Command("kind", "delete", "cluster", fmt.Sprintf("--name=%s", clusterName))
	removeCluster.Stderr = &stderr
	if err := removeCluster.Run(); err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}
}
