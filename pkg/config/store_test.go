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
	logtesting "knative.dev/pkg/logging/testing"

	. "knative.dev/pkg/configmap/testing"
)

var testfiles = []string{"allow-all", "deny-all-explicit", "warn-all", "deny-all-default"}

func TestStoreLoadWithContext(t *testing.T) {
	store := NewStore(logtesting.TestLogger(t))

	for _, file := range testfiles {
		_, policyControllerConfig := ConfigMapsFromTestFile(t, file)

		store.OnConfigChanged(policyControllerConfig)

		config := FromContextOrDefaults(store.ToContext(context.Background()))

		t.Run("policy-controller-config-test"+file, func(t *testing.T) {
			expected, _ := NewPolicyControllerConfigFromConfigMap(policyControllerConfig)
			if diff := cmp.Diff(expected, config); diff != "" {
				t.Error("Unexpected defaults config (-want, +got):", diff)
			}
		})
	}
}

func TestStoreLoadWithContextOrDefaults(t *testing.T) {
	for _, file := range testfiles {
		policyControllerConfig := ConfigMapFromTestFile(t, file)
		config := FromContextOrDefaults(context.Background())

		t.Run("policy-controller-config-tests"+file, func(t *testing.T) {
			expected, _ := NewPolicyControllerConfigFromConfigMap(policyControllerConfig)
			if diff := cmp.Diff(expected, config); diff != "" {
				t.Error("Unexpected defaults config (-want, +got):", diff)
			}
		})
	}
}
