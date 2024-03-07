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

package config

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
	"google.golang.org/protobuf/testing/protocmp"
	"k8s.io/apimachinery/pkg/api/resource"
	logtesting "knative.dev/pkg/logging/testing"

	. "knative.dev/pkg/configmap/testing"
)

var ignoreStuff = cmp.Options{
	protocmp.Transform(),
	cmpopts.IgnoreUnexported(resource.Quantity{}),
	// Ignore functional remote options
	cmpopts.IgnoreTypes((remote.Option)(nil)),
}

func TestStoreLoadWithContext(t *testing.T) {
	store := NewStore(logtesting.TestLogger(t))

	_, imagePolicies := ConfigMapsFromTestFile(t, ImagePoliciesConfigName)
	_, sigstoreKeysMap := ConfigMapsFromTestFile(t, SigstoreKeysConfigName)

	store.OnConfigChanged(imagePolicies)
	store.OnConfigChanged(sigstoreKeysMap)

	config := FromContextOrDefaults(store.ToContext(context.Background()))

	t.Run("image-policies", func(t *testing.T) {
		expected, _ := NewImagePoliciesConfigFromConfigMap(imagePolicies)
		if diff := cmp.Diff(expected, config.ImagePolicyConfig, ignoreStuff...); diff != "" {
			t.Error("Unexpected defaults config (-want, +got):", diff)
		}
	})
	t.Run("sigstore-keys", func(t *testing.T) {
		expected, _ := NewSigstoreKeysFromConfigMap(sigstoreKeysMap)
		if diff := cmp.Diff(expected, config.SigstoreKeysConfig, ignoreStuff...); diff != "" {
			t.Error("Unexpected defaults config (-want, +got):", diff)
		}
	})
}

func TestStoreLoadWithContextOrDefaults(t *testing.T) {
	imagePolicies := ConfigMapFromTestFile(t, ImagePoliciesConfigName)
	sigstoreKeysMap := ConfigMapFromTestFile(t, SigstoreKeysConfigName)
	config := FromContextOrDefaults(context.Background())

	t.Run("image-policies", func(t *testing.T) {
		expected, _ := NewImagePoliciesConfigFromConfigMap(imagePolicies)
		if diff := cmp.Diff(expected, config.ImagePolicyConfig, ignoreStuff...); diff != "" {
			t.Error("Unexpected defaults config (-want, +got):", diff)
		}
	})
	t.Run("sigstore-keys", func(t *testing.T) {
		expected, _ := NewSigstoreKeysFromConfigMap(sigstoreKeysMap)
		if diff := cmp.Diff(expected, config.SigstoreKeysConfig, ignoreStuff...); diff != "" {
			t.Error("Unexpected defaults config (-want, +got):", diff)
		}
	})
}
