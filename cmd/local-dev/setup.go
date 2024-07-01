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
	"regexp"
	"strconv"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	localRegistryName            = "registry.local"
	localRegistryPort            = 5001
	defaultKindestNodeVersionTag = "v1.27.3"
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

// check that a supplied image version is in the expected semver format: v<major>.<minor>.<patch>
var semverRegexp = regexp.MustCompile("^v[0-9]+.[0-9]+.[0-9]+$")

// check that registry URLs are in the expected format <url>:<port>
var registryURLRegexp = regexp.MustCompile("^[a-zA-Z0-9]+.[a-z]+:[0-9]+$")

func addSetupFlags(cmd *cobra.Command) {
	cmd.Flags().String("cluster-name", "policy-controller-demo", "name of the dev policy controller cluster")
	cmd.Flags().String("k8s-version", defaultKindestNodeVersionTag, "name of the Ko Docker repository to use")
	cmd.Flags().String("registry-url", "registry.local", "URL and port of the Ko Docker registry to use. Expected format: <url>:<port>. If no registry is provided, the local Kind registry will be used")
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "setup local k8s cluster for testing policy controller",
	Long:  "Setup a local k8s cluster for testing policy controller",
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			log.Fatal("Error initializing cmd line args: ", err)
		}
		return nil
	},
	Run: func(_ *cobra.Command, _ []string) {
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
		if !registryURLRegexp.Match([]byte(registryURL)) {
			log.Fatal(fmt.Errorf("provided registry URL is not in the expected format: <url>:<port>"))
		}
		err := os.Setenv("KO_DOCKER_REPO", registryURL)
		if err != nil {
			log.Fatal(buildFatalMessage(err, stderr))
		}
	}

	// Create the new Kind cluster
	clusterName := viper.GetString("cluster-name")
	fmt.Printf("Creating Kind cluster %s...\n", clusterName)

	clusterConfig, err := createKindConfig(clusterName, viper.GetString("k8s-version"))
	if err != nil {
		log.Fatal(err)
	}

	configBytes := []byte(clusterConfig)
	err = os.WriteFile("kind.yaml", configBytes, 0600)
	if err != nil {
		log.Fatal(err)
	}

	startKindCluster := exec.Command("kind", "create", "cluster", "--config", "kind.yaml")
	startKindCluster.Stderr = &stderr
	if err := startKindCluster.Run(); err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}

	if registryURL == localRegistryName {
		if err = setupLocalRegistry(); err != nil {
			log.Fatal(err)
		}
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

func createKindConfig(clusterName, k8sVersion string) (string, error) {
	// check that the provided version is in the expected format and use it
	if !semverRegexp.Match([]byte(k8sVersion)) {
		return "", fmt.Errorf("provided k8s version %s is not in the expected semver format v<major>.<minor>.<patch>", k8sVersion)
	}

	kindImage := fmt.Sprintf("kindest/node:%s", k8sVersion)
	return fmt.Sprintf(kindClusterConfig, clusterName, kindImage, localRegistryName, localRegistryPort, localRegistryName, localRegistryPort), nil
}

func setupLocalRegistry() error {
	dockerCLI, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil
	}
	defer dockerCLI.Close()

	fmt.Printf("\nStarting local registry %s...\n", localRegistryName)

	ctx := context.Background()
	resp, err := dockerCLI.ContainerCreate(ctx, &container.Config{
		Image:        "registry:2",
		Env:          []string{fmt.Sprintf("REGISTRY_HTTP_ADDR=0.0.0.0:%d", localRegistryPort)},
		ExposedPorts: nat.PortSet{"5001/tcp": struct{}{}},
	}, &container.HostConfig{
		RestartPolicy: container.RestartPolicy{Name: "always"},
		PortBindings: nat.PortMap{
			"5001/tcp": []nat.PortBinding{
				{HostIP: "127.0.0.1", HostPort: strconv.Itoa(localRegistryPort)},
			},
		},
	}, nil, nil, localRegistryName)
	if err != nil {
		return err
	}

	if err := dockerCLI.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return err
	}

	fmt.Println("Connecting network between kind with local registry ...")

	return dockerCLI.NetworkConnect(ctx, "kind", localRegistryName, nil)
}

func init() {
	addSetupFlags(setupCmd)
	rootCmd.AddCommand(setupCmd)
}
