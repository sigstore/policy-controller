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
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func addSetupFlags(cmd *cobra.Command) {
	cmd.Flags().String("cluster-name", "policy-controller-demo", "name of the dev policy controller cluster")
	cmd.Flags().String("ko-docker-repo", "", "name of the Ko Docker repository to use")
	cmd.MarkFlagRequired("ko-docker-repo") //nolint:errcheck
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

	koDockerRepo := viper.GetString("ko-docker-repo")
	err := os.Setenv("KO_DOCKER_REPO", koDockerRepo)
	if err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
	}

	// Create the new Kind cluster
	clusterName := viper.GetString("cluster-name")
	fmt.Println("Creating Kind cluster " + clusterName)
	startKindCluster := exec.Command("kind", "create", "cluster", fmt.Sprintf("--name=%s", clusterName)) //nolint:gosec
	startKindCluster.Stderr = &stderr
	if err = startKindCluster.Run(); err != nil {
		log.Fatal(buildFatalMessage(err, stderr))
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

func init() {
	addSetupFlags(setupCmd)
	rootCmd.AddCommand(setupCmd)
}
