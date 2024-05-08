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
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/logging"
	"sigs.k8s.io/release-utils/version"
	"sigs.k8s.io/yaml"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/policy"
	"github.com/sigstore/policy-controller/pkg/webhook"
)

type output struct {
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

func getSugaredLogger(value string) (*zap.SugaredLogger, error) {
	ll := LogLevel(value)
	switch ll {
	case LevelDebug, LevelInfo, LevelWarn, LevelError:
		return setSugaredLogger(ll)
	default:
		return nil, fmt.Errorf("invalid log level")
	}
}

func setSugaredLogger(logLevel LogLevel) (*zap.SugaredLogger, error) {
	cfg := zap.NewDevelopmentConfig()
	switch logLevel {
	case LevelDebug:
		cfg.Level.SetLevel(zap.DebugLevel)
	case LevelInfo:
		cfg.Level.SetLevel(zap.InfoLevel)
	case LevelWarn:
		cfg = zap.NewProductionConfig()
		cfg.Level.SetLevel(zap.WarnLevel)
	case LevelError:
		cfg = zap.NewProductionConfig()
		cfg.Level.SetLevel(zap.ErrorLevel)
	default:
		panic("invalid log level")
	}

	logger, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}
	return logger.Sugar(), nil
}

func main() {
	cipFilePath := flag.String("policy", "", "path to ClusterImagePolicy or URL to fetch from (http/https)")
	versionFlag := flag.Bool("version", false, "return the policy-controller tester version")
	image := flag.String("image", "", "image to compare against policy")
	resourceFilePath := flag.String("resource", "", "path to a kubernetes resource to use with includeSpec, includeObjectMeta")
	trustRootFilePath := flag.String("trustroot", "", "path to a kubernetes TrustRoot resource to use with the ClusterImagePolicy")
	logLevelStr := flag.String("log-level", "info", "configure the tool's log level (debug, info, warn, error)")
	flag.Parse()

	logger, err := getSugaredLogger(*logLevelStr)
	if err != nil {
		flag.Usage()
		os.Exit(1)
	}

	ctx := logging.WithLogger(context.Background(), logger)

	if *versionFlag {
		v := version.GetVersionInfo()
		fmt.Println(v.String())
		os.Exit(0)
	}

	if *cipFilePath == "" || *image == "" {
		flag.Usage()
		os.Exit(1)
	}

	pols := make([]policy.Source, 0, 1)

	if strings.HasPrefix(*cipFilePath, "https://") || strings.HasPrefix(*cipFilePath, "http://") {
		pols = append(pols, policy.Source{
			URL: *cipFilePath,
		})
	} else {
		pols = append(pols, policy.Source{
			Path: *cipFilePath,
		})
	}

	logging.FromContext(ctx).Infof("Validating policy\n")

	v := policy.Verification{
		NoMatchPolicy: "deny",
		Policies:      &pols,
	}
	if err := v.Validate(ctx); err != nil {
		// CIP validation can return Warnings so let's just go through them
		// and only exit if there are Errors.
		if warnFE := err.Filter(apis.WarningLevel); warnFE != nil {
			log.Printf("CIP has warnings:\n%s\n", warnFE.Error())
		}
		if errorFE := err.Filter(apis.ErrorLevel); errorFE != nil {
			log.Fatalf("CIP is invalid: %s", errorFE.Error())
		}
	}

	logging.FromContext(ctx).Infof("Policy was successfully validated\n")

	ref, err := name.ParseReference(*image)
	if err != nil {
		log.Fatal(err)
	}

	warningStrings := []string{}
	vfy, err := policy.Compile(ctx, v, func(s string, i ...interface{}) {
		warningStrings = append(warningStrings, fmt.Sprintf(s, i...))
	})
	if err != nil {
		log.Fatal(err)
	}

	if *resourceFilePath != "" {
		logging.FromContext(ctx).Infof("Parsing the provided Kubernetes resource\n")

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

		logging.FromContext(ctx).Infof("The Kuberentes resource will be used with includeSpec\n")
	}

	if *trustRootFilePath != "" {
		logging.FromContext(ctx).Infof("Parsing the custom trust root\n")

		configCtx := config.FromContextOrDefaults(ctx)
		raw, err := os.ReadFile(*trustRootFilePath)
		if err != nil {
			log.Fatal(err)
		}

		tr := &v1alpha1.TrustRoot{}
		if err := yaml.Unmarshal(raw, tr); err != nil {
			log.Fatal(err)
		}

		keys, err := GetKeysFromTrustRoot(ctx, tr)
		if err != nil {
			log.Fatal(err)
		}

		maps := make(map[string]*config.SigstoreKeys, 0)

		maps[tr.Name] = keys
		configCtx.SigstoreKeysConfig = &config.SigstoreKeysMap{SigstoreKeys: maps}

		ctx = config.ToContext(ctx, configCtx)

		logging.FromContext(ctx).Infof("The custom trust root has been successfully added\n")
	}

	logging.FromContext(ctx).Infof("Verifying the provided image against the policy\n")

	errStrings := []string{}
	if err := vfy.Verify(ctx, ref, authn.DefaultKeychain); err != nil {
		errStrings = append(errStrings, strings.Trim(err.Error(), "\n"))
	}

	if len(errStrings) != 0 {
		logging.FromContext(ctx).Infof("Errors encountered during verification\n")

		var o []byte
		o, err = json.Marshal(&output{
			Errors:   errStrings,
			Warnings: warningStrings,
		})
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(string(o))
		os.Exit(1)
	}
	logging.FromContext(ctx).Infof("Verification was successful!\n")
}
