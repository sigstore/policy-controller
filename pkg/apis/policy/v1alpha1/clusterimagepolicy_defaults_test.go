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

package v1alpha1

import (
	"context"

	"testing"

	"knative.dev/pkg/apis"
)

func TestNameDefaulting(t *testing.T) {
	tests := []struct {
		in        *ClusterImagePolicy
		wantNames []string
	}{
		{in: cipWithNames([]string{""}),
			wantNames: []string{"authority-0"},
		},
		{in: cipWithNames([]string{"", "vuln-scan"}),
			wantNames: []string{"authority-0", "vuln-scan"},
		},
		{in: cipWithNames([]string{"vuln-scan", ""}),
			wantNames: []string{"vuln-scan", "authority-1"},
		},
		{in: cipWithNames([]string{"first", "second"}),
			wantNames: []string{"first", "second"},
		}}
	for _, tc := range tests {
		tc.in.SetDefaults(context.TODO())
		if len(tc.in.Spec.Authorities) != len(tc.wantNames) {
			t.Fatalf("Mismatch number of wantNames: %d vs authorities: %d", len(tc.wantNames), len(tc.in.Spec.Authorities))
		}
		for i, wantName := range tc.wantNames {
			if tc.in.Spec.Authorities[i].Name != wantName {
				t.Errorf("Wanted name: %s got %s", wantName, tc.in.Spec.Authorities[i].Name)
			}
		}
	}
}

func TestModeDefaulting(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		wantMode string
	}{{name: "empty",
		wantMode: "enforce",
	}, {
		name:     "enforce",
		mode:     "enforce",
		wantMode: "enforce",
	}, {
		name:     "warn",
		mode:     "warn",
		wantMode: "warn",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			in := ClusterImagePolicy{Spec: ClusterImagePolicySpec{Mode: tc.mode}}
			in.SetDefaults(context.TODO())
			if in.Spec.Mode != tc.wantMode {
				t.Errorf("Wanted mode: %s got %s", tc.wantMode, in.Spec.Mode)
			}
		})
	}
}

func TestKeylessURLDefaulting(t *testing.T) {
	tests := []struct {
		name    string
		in      *ClusterImagePolicy
		wantURL string
	}{
		{name: "static specified, no default",
			in: &ClusterImagePolicy{Spec: ClusterImagePolicySpec{Authorities: []Authority{{Static: &StaticRef{Action: "pass"}}}}}},
		{name: "key specified, no default",
			in: &ClusterImagePolicy{Spec: ClusterImagePolicySpec{Authorities: []Authority{{Key: &KeyRef{Data: "Keydata here"}}}}}},
		{name: "kms specified, no default",
			in: &ClusterImagePolicy{Spec: ClusterImagePolicySpec{Authorities: []Authority{{Keyless: &KeylessRef{CACert: &KeyRef{KMS: "Keydata here"}}}}}}},
		{name: "keyless specified, do not overwite fulcio",
			in:      &ClusterImagePolicy{Spec: ClusterImagePolicySpec{Authorities: []Authority{{Keyless: &KeylessRef{URL: apis.HTTP("fulcio.fulcio-system.svc")}}}}},
			wantURL: "http://fulcio.fulcio-system.svc",
		},
		{name: "keyless specified, public fulcio",
			in:      &ClusterImagePolicy{Spec: ClusterImagePolicySpec{Authorities: []Authority{{Keyless: &KeylessRef{Identities: []Identity{{Issuer: "someissuer"}}}}}}},
			wantURL: "https://fulcio.sigstore.dev",
		},
	}
	for _, tc := range tests {
		in := tc.in.DeepCopy()
		in.SetDefaults(context.TODO())
		switch tc.wantURL {
		case "":
			if in.Spec.Authorities[0].Keyless != nil && in.Spec.Authorities[0].Keyless.URL != nil {
				t.Errorf("Wanted no defaulting, got %s", in.Spec.Authorities[0].Keyless.URL)
			}
		default:
			if in.Spec.Authorities[0].Keyless == nil || in.Spec.Authorities[0].Keyless.URL == nil {
				t.Errorf("Wanted defaulting %s, got none", tc.wantURL)
			} else if in.Spec.Authorities[0].Keyless.URL.String() != tc.wantURL {
				t.Errorf("Wanted defaulting %s, got %s", tc.wantURL, in.Spec.Authorities[0].Keyless.URL)
			}
		}
	}
}

func cipWithNames(names []string) *ClusterImagePolicy {
	cip := &ClusterImagePolicy{
		Spec: ClusterImagePolicySpec{},
	}
	for _, name := range names {
		cip.Spec.Authorities = append(cip.Spec.Authorities, Authority{Name: name, Keyless: &KeylessRef{URL: &apis.URL{Host: "tests.example.com"}}})
	}
	return cip
}
