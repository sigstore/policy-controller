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
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	localRegistryName = "registry.local"
	localRegistryPort = 5001
)

var kindClusterConfig = `
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
name: "%s"
nodes:
- role: control-plane
  image: "%s"
# Configure registry for KinD.
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."%s:%d"]
    endpoint = ["http://%s:%d"]
`

func addSetupFlags(cmd *cobra.Command) {
	cmd.Flags().String("cluster-name", "policy-controller-demo", "name of the dev policy controller cluster")
	cmd.Flags().String("registry-url", "registry.local", "URL of the Ko Docker registry to use. If no registry is provided, the local Kind registry will be used")
	cmd.Flags().String("k8s-version", "v1.26.x", "name of the Ko Docker repository to use")
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "setup local k8s cluster for testing policy controller",
	Long:  "Setup a local k8s cluster for testing policy controller",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Fatal("Error initializing cmd line args: ", err)
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		setup()
	},
}

func buildFatalMessage(err error, stderr bytes.Buffer) string {
	return fmt.Sprintf("%v: %s", err, stderr.String())
}

func setup() {
	var stderr bytes.Buffer

	registryURL := viper.GetString("registry-url")
	if registryURL == localRegistryName {
		fullLocalRegistryURL := fmt.Sprintf("%s:%d/sigstore", localRegistryName, localRegistryPort)
		err := os.Setenv("KO_DOCKER_REPO", fullLocalRegistryURL)
		if err != nil {
			log.Fatal(buildFatalMessage(err, stderr))
		}
	} else {
		err := os.Setenv("KO_DOCKER_REPO", registryURL)
		if err != nil {
			log.Fatal(buildFatalMessage(err, stderr))
		}
	}

	// Create the new Kind cluster
	clusterName := viper.GetString("cluster-name")
	fmt.Println("Creating Kind cluster " + clusterName)

	k8sVersion := viper.GetString("k8s-version")
	kindImage := getKindImage(k8sVersion)

	clusterConfig := fmt.Sprintf(kindClusterConfig, clusterName, kindImage, localRegistryName, localRegistryPort, localRegistryName, localRegistryPort)
	d1 := []byte(clusterConfig)
	err := os.WriteFile("kind.yaml", d1, 0644)
	if err != nil {
		panic(err)
	}

	startKindCluster := exec.Command("kind", "create", "cluster", "--config", "kind.yaml")
	startKindCluster.Stderr = &stderr
	if err := startKindCluster.Run(); err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}

	if registryURL == localRegistryName {
		cli, err := client.NewClientWithOpts(
			client.FromEnv,
			client.WithAPIVersionNegotiation(),
		)
		if err != nil {
			panic(err)
		}
		defer cli.Close()

		fmt.Printf("\nStarting local registry %s...\n", localRegistryName)

		resp, err := cli.ContainerCreate(context.Background(), &container.Config{
			Image:        "registry:2",
			Env:          []string{fmt.Sprintf("REGISTRY_HTTP_ADDR=0.0.0.0:%d", localRegistryPort)},
			ExposedPorts: nat.PortSet{"5001/tcp": struct{}{}},
		}, &container.HostConfig{
			RestartPolicy: container.RestartPolicy{Name: "always"},
			PortBindings: nat.PortMap{
				"5001/tcp": []nat.PortBinding{
					{HostIP: "127.0.0.1", HostPort: "5001"},
				},
			},
		}, nil, nil, localRegistryName)

		if err := cli.ContainerStart(context.Background(), resp.ID, types.ContainerStartOptions{}); err != nil {
			panic(err)
		}

		fmt.Println("Connecting network between kind with local registry ...")

		cli.NetworkConnect(context.Background(), "kind", localRegistryName, nil)
	}

	setGitHash := exec.Command("git", "rev-parse", "HEAD")
	setGitHash.Stderr = &stderr
	outBytes, err := setGitHash.Output()
	if err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}

	err = os.Setenv("GIT_HASH", string(outBytes))
	if err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}

	setGitVersion := exec.Command("git", "describe", "--tags", "--always", "--dirty")
	setGitVersion.Stderr = &stderr
	outBytes, err = setGitVersion.Output()
	if err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}

	err = os.Setenv("GIT_VERSION", string(outBytes))
	if err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}

	var configFiles []string
	err = filepath.WalkDir("config", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(d.Name()) == ".yaml" && d.Name() != "kustomization.yaml" {
			configFiles = append(configFiles, path)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Applying local policy controller manifests...")
	for _, configFile := range configFiles {
		koApply := exec.Command("ko", "apply", "-f", configFile)
		koApply.Stderr = &stderr
		_, err = koApply.Output()
		if err != nil {
			log.Fatal(buildFatalMessage(err, stderr))
		}
	}
}

func getKindImage(k8sVersion string) string {
	switch k8sVersion {
	case "v1.23.x":
		k8sVersionPatch := "1.23.13"
		kindImageSHA := "sha256:ef453bb7c79f0e3caba88d2067d4196f427794086a7d0df8df4f019d5e336b61"
		return fmt.Sprintf("kindest/node:v%s@%s", k8sVersionPatch, kindImageSHA)
	case "v1.24.x":
		k8sVersionPatch := "1.24.7"
		kindImageSHA := "sha256:577c630ce8e509131eab1aea12c022190978dd2f745aac5eb1fe65c0807eb315"
		return fmt.Sprintf("kindest/node:v%s@%s", k8sVersionPatch, kindImageSHA)
	case "v1.25.x":
		k8sVersionPatch := "1.25.3"
		kindImageSHA := "sha256:f52781bc0d7a19fb6c405c2af83abfeb311f130707a0e219175677e366cc45d1"
		return fmt.Sprintf("kindest/node:v%s@%s", k8sVersionPatch, kindImageSHA)

	case "v1.26.x":
		k8sVersionPatch := "1.26.0"
		kindImageSHA := "sha256:691e24bd2417609db7e589e1a479b902d2e209892a10ce375fab60a8407c7352"
		return fmt.Sprintf("kindest/node:v%s@%s", k8sVersionPatch, kindImageSHA)
	default:
		fmt.Println("Unsupported version: " + k8sVersion)
	}
	return ""
}

func init() {
	addSetupFlags(setupCmd)
	rootCmd.AddCommand(setupCmd)
}
