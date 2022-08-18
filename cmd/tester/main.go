//
// Copyright 2022 The Sigstore Authors.
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
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"go.uber.org/zap"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/logging"
	"sigs.k8s.io/yaml"

	"github.com/sigstore/policy-controller/pkg/apis/glob"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/webhook"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
)

var (
	ns = "unused"

	remoteOpts = []ociremote.Option{
		ociremote.WithRemoteOptions(
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
		),
	}

	ctx = logging.WithLogger(context.Background(), func() *zap.SugaredLogger {
		x, _ := zap.NewDevelopmentConfig().Build()
		return x.Sugar()
	}())
)

type output struct {
	Errors   []string              `json:"errors,omitempty"`
	Warnings []string              `json:"warnings,omitempty"`
	Result   *webhook.PolicyResult `json:"result"`
}

func main() {
	cipFilePath := flag.String("policy", "", "path to ClusterImagePolicy")
	image := flag.String("image", "", "image to compare against policy")
	flag.Parse()
	if *cipFilePath == "" || *image == "" {
		flag.Usage()
		os.Exit(1)
	}

	cipRaw, err := ioutil.ReadFile(*cipFilePath)
	if err != nil {
		log.Fatal(err)
	}

	// TODO(jdolitsky): This should use v1beta1 once there exists a
	// webhookcip.ConvertClusterImagePolicyV1beta1ToWebhook() method
	var v1alpha1cip v1alpha1.ClusterImagePolicy
	if err := yaml.Unmarshal(cipRaw, &v1alpha1cip); err != nil {
		log.Fatal(err)
	}
	v1alpha1cip.SetDefaults(ctx)

	// Show what the defaults look like
	defaulted, err := yaml.Marshal(v1alpha1cip)
	if err != nil {
		log.Fatalf("Failed to marshal the defaulted cip: %s", err)
	}

	log.Printf("Using the following cip:\n%s", defaulted)

	validateErrs := v1alpha1cip.Validate(ctx)
	if validateErrs != nil {
		log.Fatalf("CIP is invalid: %s", validateErrs.Error())
	}
	cip := webhookcip.ConvertClusterImagePolicyV1alpha1ToWebhook(&v1alpha1cip)

	// We have to marshal/unmarshal the CIP since that handles converting
	// inlined Data into PublicKey objects that validator uses.
	webhookCip, err := json.Marshal(cip)
	if err != nil {
		log.Fatalf("Failed to marshal the webhook cip: %s", err)
	}
	if err := json.Unmarshal(webhookCip, &cip); err != nil {
		log.Fatalf("Failed to unmarshal the webhook CIP: %s", err)
	}
	ref, err := name.ParseReference(*image)
	if err != nil {
		log.Fatal(err)
	}

	matches := false
	for _, pattern := range cip.Images {
		if pattern.Glob != "" {
			if matched, err := glob.Match(pattern.Glob, *image); err != nil {
				log.Fatalf("Failed to match glob: %s", err)
			} else if matched {
				log.Printf("image matches glob %q", pattern.Glob)
				matches = true
			}
		}
	}
	if !matches {
		log.Fatalf("Image does not match any of the provided globs")
	}

	result, errs := webhook.ValidatePolicy(ctx, ns, ref, *cip, remoteOpts...)
	errStrings := []string{}
	warningStrings := []string{}
	for _, err := range errs {
		var fe *apis.FieldError
		if errors.As(err, &fe) {
			if fe.Level == apis.WarningLevel {
				warningStrings = append(warningStrings, strings.Trim(err.Error(), "\n"))
				continue
			}
		}
		errStrings = append(errStrings, strings.Trim(err.Error(), "\n"))
	}
	var o []byte
	o, err = json.Marshal(&output{
		Errors:   errStrings,
		Warnings: warningStrings,
		Result:   result,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(o))
	if len(errs) > 0 {
		os.Exit(1)
	}
}
