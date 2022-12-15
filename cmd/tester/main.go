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
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/logging"
	"sigs.k8s.io/release-utils/version"
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
	cipFilePath := flag.String("policy", "", "path to ClusterImagePolicy or URL to fetch from (http/https)")
	versionFlag := flag.Bool("version", false, "return the policy-controller tester version")
	image := flag.String("image", "", "image to compare against policy")
	resourceFilePath := flag.String("resource", "", "path to a kubernetes resource to use with includeSpec, includeObjectMeta")
	flag.Parse()

	if *versionFlag {
		v := version.GetVersionInfo()
		fmt.Println(v.String())
		os.Exit(0)
	}

	if *cipFilePath == "" || *image == "" {
		flag.Usage()
		os.Exit(1)
	}

	var cipRaw []byte
	var err error
	if strings.HasPrefix(*cipFilePath, "https://") || strings.HasPrefix(*cipFilePath, "http://") {
		log.Printf("Fetching CIP from: %s", *cipFilePath)
		resp, err := http.Get(*cipFilePath)
		if err != nil {
			log.Fatal(err)
		}
		cipRaw, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		cipRaw, err = os.ReadFile(*cipFilePath)
		if err != nil {
			log.Fatal(err)
		}
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

	if *resourceFilePath != "" {
		raw, err := os.ReadFile(*resourceFilePath)
		if err != nil {
			log.Fatal(err)
		}
		uo := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(raw, uo); err != nil {
			log.Fatal(err)
		}
		m, ok := uo.Object["metadata"]
		if !ok {
			log.Fatal("kubernetes resource is missing metadata key")
		}
		ctx = webhook.IncludeObjectMeta(ctx, m)
		spec, ok := uo.Object["spec"]
		if !ok {
			log.Fatal("kubernetes resource is missing spec key")
		}
		ctx = webhook.IncludeSpec(ctx, spec)
		kind, ok := uo.Object["kind"]
		if !ok {
			log.Fatal("kubernetes resource is missing kind key")
		}
		apiVersion, ok := uo.Object["apiVersion"]
		if !ok {
			log.Fatal("kubernetes resource is missing apiVersion key")
		}
		typeMeta := make(map[string]interface{})
		typeMeta["kind"] = kind
		typeMeta["apiVersion"] = apiVersion
		ctx = webhook.IncludeTypeMeta(ctx, typeMeta)
	}

	validateErrs := v1alpha1cip.Validate(ctx)
	if validateErrs != nil {
		// CIP validation can return Warnings so let's just go through them
		// and only exit if there are Errors.
		if warnFE := validateErrs.Filter(apis.WarningLevel); warnFE != nil {
			log.Printf("CIP has warnings:\n%s\n", warnFE.Error())
		}
		if errorFE := validateErrs.Filter(apis.ErrorLevel); errorFE != nil {
			log.Fatalf("CIP is invalid: %s", errorFE.Error())
		}
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

	result, errs := webhook.ValidatePolicy(ctx, ns, ref, *cip, authn.DefaultKeychain, remoteOpts...)
	errStrings := []string{}
	warningStrings := []string{}
	for _, err := range errs {
		var fe *apis.FieldError
		if errors.As(err, &fe) {
			if warnFE := fe.Filter(apis.WarningLevel); warnFE != nil {
				warningStrings = append(warningStrings, strings.Trim(warnFE.Error(), "\n"))
			}
			if errorFE := fe.Filter(apis.ErrorLevel); errorFE != nil {
				errStrings = append(errStrings, strings.Trim(errorFE.Error(), "\n"))
			}
		} else {
			errStrings = append(errStrings, strings.Trim(err.Error(), "\n"))
		}
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
