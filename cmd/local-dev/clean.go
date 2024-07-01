//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
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
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Fatal("Error initializing cmd line args: ", err)
		}
		return nil
	},
	Run: func(_ *cobra.Command, _ []string) {
		clean()
	},
}

func clean() {
	var stderr bytes.Buffer

	// clean up the local cluster
	clusterName := viper.GetString("cluster-name")
	fmt.Printf("Cleaning up the kind cluster %s...\n", clusterName)

	removeCluster := exec.Command("kind", "delete", "cluster", "--name", clusterName)
	removeCluster.Stderr = &stderr
	if err := removeCluster.Run(); err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}

	if err := cleanUpRegistry(); err != nil {
		log.Fatal(err)
	}
}

func cleanUpRegistry() error {
	ctx := context.Background()
	dockerCLI, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return err
	}
	defer dockerCLI.Close()

	containers, err := dockerCLI.ContainerList(ctx, container.ListOptions{Filters: filters.NewArgs(filters.KeyValuePair{Key: "name", Value: "registry.local"})})
	if err != nil {
		return err
	}

	if len(containers) > 0 {
		fmt.Println("Cleaning up registry.local...")
		if err := dockerCLI.ContainerStop(ctx, containers[0].ID, container.StopOptions{}); err != nil {
			return err
		}
		if err := dockerCLI.ContainerRemove(ctx, containers[0].ID, container.RemoveOptions{}); err != nil {
			return err
		}
	}
	return nil
}
