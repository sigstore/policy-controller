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
	"knative.dev/pkg/logging"
	"sigs.k8s.io/yaml"

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
	Errors []string              `json:"errors"`
	Result *webhook.PolicyResult `json:"result"`
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
	var tmp v1alpha1.ClusterImagePolicy
	if err := yaml.Unmarshal(cipRaw, &tmp); err != nil {
		log.Fatal(err)
	}
	cip := webhookcip.ConvertClusterImagePolicyV1alpha1ToWebhook(&tmp)
	ref, err := name.ParseReference(*image)
	if err != nil {
		log.Fatal(err)
	}

	result, errs := webhook.ValidatePolicy(ctx, ns, ref, *cip, remoteOpts...)
	errStrings := []string{}
	for _, err := range errs {
		errStrings = append(errStrings, strings.Trim(err.Error(), "\n"))
	}
	o, err := json.Marshal(&output{
		Errors: errStrings,
		Result: result,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(o))
	if len(errs) > 0 {
		os.Exit(1)
	}
}
