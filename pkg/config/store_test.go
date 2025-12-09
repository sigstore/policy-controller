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

type testData struct {
	noMatchPolicy          string
	failOnEmptyAuthorities bool
	enableOCI11            bool
}

var testfiles = map[string]testData{
	"allow-all":               {noMatchPolicy: AllowAll, failOnEmptyAuthorities: true, enableOCI11: false},
	"deny-all-explicit":       {noMatchPolicy: DenyAll, failOnEmptyAuthorities: true, enableOCI11: false},
	"warn-all":                {noMatchPolicy: WarnAll, failOnEmptyAuthorities: true, enableOCI11: false},
	"deny-all-default":        {noMatchPolicy: DenyAll, failOnEmptyAuthorities: true, enableOCI11: false},
	"allow-empty-authorities": {noMatchPolicy: DenyAll, failOnEmptyAuthorities: false, enableOCI11: false},
}

func TestStoreLoadWithContext(t *testing.T) {
	store := NewStore(logtesting.TestLogger(t))

	for file, want := range testfiles {
		_, policyControllerConfig := ConfigMapsFromTestFile(t, file)

		store.OnConfigChanged(policyControllerConfig)

		config := FromContextOrDefaults(store.ToContext(context.Background()))

		t.Run("policy-controller-config-test-"+file, func(t *testing.T) {
			expected, _ := NewPolicyControllerConfigFromConfigMap(policyControllerConfig)
			if diff := cmp.Diff(want.noMatchPolicy, expected.NoMatchPolicy); diff != "" {
				t.Error("Unexpected defaults config (-want, +got):", diff)
			}
			if diff := cmp.Diff(want.failOnEmptyAuthorities, expected.FailOnEmptyAuthorities); diff != "" {
				t.Error("Unexpected defaults config (-want, +got):", diff)
			}
			if diff := cmp.Diff(want.enableOCI11, expected.EnableOCI11); diff != "" {
				t.Error("Unexpected EnableOCI11 config (-want, +got):", diff)
			}
			if diff := cmp.Diff(expected, config); diff != "" {
				t.Error("Unexpected defaults config (-want, +got):", diff)
			}
		})
	}
}

func TestStoreLoadWithContextOrDefaults(t *testing.T) {
	for file := range testfiles {
		policyControllerConfig := ConfigMapFromTestFile(t, file)
		config := FromContextOrDefaults(context.Background())

		t.Run("policy-controller-config-tests-"+file, func(t *testing.T) {
			expected, _ := NewPolicyControllerConfigFromConfigMap(policyControllerConfig)
			// These all should have the default, because we don't parse the
			// _example in these tests.
			if diff := cmp.Diff(DenyAll, expected.NoMatchPolicy); diff != "" {
				t.Error("Unexpected defaults config (-want, +got):", diff)
			}
			if diff := cmp.Diff(expected, config); diff != "" {
				t.Error("Unexpected defaults config (-want, +got):", diff)
			}
		})
	}
}

func TestEnableOCI11Config(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string]string
		wantOCI11 bool
		wantErr   bool
	}{
		{
			name:      "enable-oci11 true",
			data:      map[string]string{"enable-oci11": "true"},
			wantOCI11: true,
			wantErr:   false,
		},
		{
			name:      "enable-oci11 false",
			data:      map[string]string{"enable-oci11": "false"},
			wantOCI11: false,
			wantErr:   false,
		},
		{
			name:      "enable-oci11 not set (default false)",
			data:      map[string]string{},
			wantOCI11: false,
			wantErr:   false,
		},
		{
			name:    "enable-oci11 invalid value",
			data:    map[string]string{"enable-oci11": "not-a-boolean"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewPolicyControllerConfigFromMap(tt.data)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewPolicyControllerConfigFromMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if cfg.EnableOCI11 != tt.wantOCI11 {
					t.Errorf("EnableOCI11 = %v, want %v", cfg.EnableOCI11, tt.wantOCI11)
				}
			}
		})
	}
}

func TestFromContextOrDefaultsWithOCI11(t *testing.T) {
	// Test default returns EnableOCI11 = false
	cfg := FromContextOrDefaults(context.Background())
	if cfg.EnableOCI11 != false {
		t.Errorf("Default EnableOCI11 = %v, want false", cfg.EnableOCI11)
	}

	// Test with EnableOCI11 = true in context
	customCfg := &PolicyControllerConfig{
		NoMatchPolicy:          DenyAll,
		FailOnEmptyAuthorities: true,
		EnableOCI11:            true,
	}
	ctx := ToContext(context.Background(), customCfg)

	cfg = FromContextOrDefaults(ctx)
	if cfg.EnableOCI11 != true {
		t.Errorf("Context EnableOCI11 = %v, want true", cfg.EnableOCI11)
	}
}
