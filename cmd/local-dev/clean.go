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

	"github.com/docker/docker/api/types"
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
	clusterName := viper.GetString("cluster-name")
	fmt.Printf("Cleaning up the kind cluster %s...\n", clusterName)

	removeCluster := exec.Command("kind", "delete", "cluster", "--name", clusterName)
	removeCluster.Stderr = &stderr
	if err := removeCluster.Run(); err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}

	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{Filters: filters.NewArgs(filters.KeyValuePair{Key: "name", Value: "registry.local"})})
	if err != nil {
		log.Fatal(err)
	}

	if containers != nil {
		fmt.Println("Cleaning up registry.local...")
		if err := cli.ContainerStop(context.Background(), containers[0].ID, container.StopOptions{}); err != nil {
			log.Fatal(err)
		}
		if err := cli.ContainerRemove(context.Background(), containers[0].ID, types.ContainerRemoveOptions{}); err != nil {
			log.Fatal(err)
		}
	}
}
