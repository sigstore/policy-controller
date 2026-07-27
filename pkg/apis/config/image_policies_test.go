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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	. "knative.dev/pkg/configmap/testing"
	_ "knative.dev/pkg/system/testing"
)

const (
	// Just some public key that was laying around, only format matters.
	inlineKeyData = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J
RCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==
-----END PUBLIC KEY-----`
)

func TestDefaultsConfigurationFromFile(t *testing.T) {
	_, example := ConfigMapsFromTestFile(t, ImagePoliciesConfigName)
	if _, err := NewImagePoliciesConfigFromConfigMap(example); err != nil {
		t.Error("NewImagePoliciesConfigFromConfigMap(example) =", err)
	}
}

func TestGetAuthorities(t *testing.T) {
	getAuthority := func(t *testing.T, m map[string]webhookcip.ClusterImagePolicy, mp string) webhookcip.Authority {
		t.Helper()
		cip, found := m[mp]
		if !found {
			t.Fatalf("failed to find matching policy %q", mp)
		}
		if len(cip.Authorities) == 0 {
			t.Fatalf("no authorities for matching policy %q", mp)
		}
		return cip.Authorities[0]
	}

	_, example := ConfigMapsFromTestFile(t, ImagePoliciesConfigName)
	defaults, err := NewImagePoliciesConfigFromConfigMap(example)
	if err != nil {
		t.Fatal("NewImagePoliciesConfigFromConfigMap(example) =", err)
	}

	// Scenarios that match a single policy with an inline key authority. Some of
	// them also carry a parsed public key that we verify round-trips correctly.
	t.Run("single key-authority matches", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			image         string
			matchedPolicy string
			checkPubKey   bool
			checkUIDRV    bool
		}{
			{name: "exact glob", image: "rando", matchedPolicy: "cluster-image-policy-0", checkUIDRV: true},
			{name: "glob suffix", image: "randomstuffhere", matchedPolicy: "cluster-image-policy-1", checkUIDRV: true},
			{name: "regex", image: "regexstringstuff", matchedPolicy: "cluster-image-policy-4", checkPubKey: true, checkUIDRV: true},
			{name: "multiline yaml cert", image: "inlinecert", matchedPolicy: "cluster-image-policy-3", checkPubKey: true},
			{name: "multiline json cert", image: "ghcr.io/example/foo", matchedPolicy: "cluster-image-policy-json", checkPubKey: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, err := defaults.GetMatchingPolicies(tc.image, "Pod", "v1", map[string]string{})
				checkGetMatches(t, c, err)
				if got := getAuthority(t, c, tc.matchedPolicy).Key.Data; got != inlineKeyData {
					t.Errorf("Did not get what I wanted %q, got %+v", inlineKeyData, got)
				}
				if tc.checkPubKey {
					checkPublicKey(t, getAuthority(t, c, tc.matchedPolicy).Key.PublicKeys[0])
				}
				if tc.checkUIDRV {
					// Make sure UID and ResourceVersion are unserialized properly
					checkUIDAndResourceVersion(t, tc.matchedPolicy, c[tc.matchedPolicy])
				}
			})
		}
	})

	t.Run("keyless authority", func(t *testing.T) {
		matchedPolicy := "cluster-image-policy-2"
		c, err := defaults.GetMatchingPolicies("rando3", "Pod", "v1", map[string]string{})
		checkGetMatches(t, c, err)
		authority := getAuthority(t, c, matchedPolicy)
		if authority.Keyless == nil {
			t.Fatalf("expected keyless authority for %q", matchedPolicy)
		}
		if got := authority.Keyless.CACert.Data; got != inlineKeyData {
			t.Errorf("Did not get what I wanted %q, got %+v", inlineKeyData, got)
		}
		if got := authority.Keyless.InsecureIgnoreSCT; got == nil {
			t.Errorf("InsecureIgnoreSCT was nil, wanted %v", true)
		} else if *got != true {
			t.Errorf("Did not get what I wanted %v, got %+v", true, *got)
		}
		if len(authority.Keyless.Identities) == 0 {
			t.Fatalf("no identities for matching policy %q", matchedPolicy)
		}
		if got := authority.Keyless.Identities[0].Issuer; got != "issuer" {
			t.Errorf("Did not get what I wanted %q, got %+v", "issuer", got)
		}
		if got := authority.Keyless.Identities[0].Subject; got != "subject" {
			t.Errorf("Did not get what I wanted %q, got %+v", "subject", got)
		}
		if got := authority.RFC3161Timestamp.TrustRootRef; got != "trustroot-tsa-ref" {
			t.Errorf("Did not get the tsa what I wanted %q, got %+v", "trustroot-tsa-ref", got)
		}
		// Make sure UID and ResourceVersion are unserialized properly
		checkUIDAndResourceVersion(t, matchedPolicy, c[matchedPolicy])
	})

	t.Run("multiple matches", func(t *testing.T) {
		c, err := defaults.GetMatchingPolicies("regexstringtoo", "Pod", "v1", map[string]string{})
		checkGetMatches(t, c, err)
		if len(c) != 2 {
			t.Errorf("Wanted two matches, got %d", len(c))
		}
		for _, matchedPolicy := range []string{"cluster-image-policy-4", "cluster-image-policy-5"} {
			if got := getAuthority(t, c, matchedPolicy).Key.Data; got != inlineKeyData {
				t.Errorf("Did not get what I wanted %q, got %+v", inlineKeyData, got)
			}
		}
		checkPublicKey(t, getAuthority(t, c, "cluster-image-policy-4").Key.PublicKeys[0])
	})

	t.Run("attestations and top level policy", func(t *testing.T) {
		matchedPolicy := "cluster-image-policy-with-policy-attestations"
		c, err := defaults.GetMatchingPolicies("withattestations", "Pod", "v1", map[string]string{})
		checkGetMatches(t, c, err)
		if len(c) != 1 {
			t.Errorf("Wanted 1 match, got %d", len(c))
		}
		authority := getAuthority(t, c, matchedPolicy)
		if got := authority.Name; got != "attestation-0" {
			t.Errorf("Did not get what I wanted %q, got %+v", "attestation-0", got)
		}
		// Both top & authority policy is using cue
		if got := c[matchedPolicy].Policy.Type; got != "cue" {
			t.Errorf("Did not get what I wanted %q, got %+v", "cue", got)
		}
		if got := c[matchedPolicy].Policy.Data; got != "cip level cue here" {
			t.Errorf("Did not get what I wanted %q, got %+v", "cip level cue here", got)
		}
		if len(authority.Attestations) == 0 {
			t.Fatalf("no attestations for matching policy %q", matchedPolicy)
		}
		if got := authority.Attestations[0].Type; got != "cue" {
			t.Errorf("Did not get what I wanted %q, got %+v", "cue", got)
		}
		if got := authority.Attestations[0].Data; got != "test-cue-here" {
			t.Errorf("Did not get what I wanted %q, got %+v", "test-cue-here", got)
		}
	})

	t.Run("source oci", func(t *testing.T) {
		matchedPolicy := "cluster-image-policy-source-oci"
		c, err := defaults.GetMatchingPolicies("sourceocionly", "Pod", "v1", map[string]string{})
		checkGetMatches(t, c, err)
		if len(c) != 1 {
			t.Errorf("Wanted 1 match, got %d", len(c))
		}
		checkSourceOCI(t, c[matchedPolicy].Authorities)
		authority := getAuthority(t, c, matchedPolicy)
		if len(authority.Sources) == 0 {
			t.Fatalf("no sources for matching policy %q", matchedPolicy)
		}
		if got := authority.Sources[0].OCI; got != "example.registry.com/alternative/signature" {
			t.Errorf("Did not get what I wanted %q, got %+v", "example.registry.com/alternative/signature", got)
		}
	})

	t.Run("source signature pull secrets", func(t *testing.T) {
		matchedPolicy := "cluster-image-policy-source-oci-signature-pull-secrets"
		c, err := defaults.GetMatchingPolicies("sourceocisignaturepullsecrets", "Pod", "v1", map[string]string{"match": "match"})
		checkGetMatches(t, c, err)
		if len(c) != 1 {
			t.Errorf("Wanted 1 match, got %d", len(c))
		}
		checkSourceOCI(t, c[matchedPolicy].Authorities)
		authority := getAuthority(t, c, matchedPolicy)
		if len(authority.Sources) == 0 {
			t.Fatalf("no sources for matching policy %q", matchedPolicy)
		}
		if got := len(authority.Sources[0].SignaturePullSecrets); got != 1 {
			t.Errorf("Did not get what I wanted %d, got %d", 1, got)
		}
		if len(authority.Sources[0].SignaturePullSecrets) > 0 {
			if got := authority.Sources[0].SignaturePullSecrets[0].Name; got != "examplePullSecret" {
				t.Errorf("Did not get what I wanted %q, got %+v", "examplePullSecret", got)
			}
		}
	})

	t.Run("resource matching", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			apiVersion  string
			wantMatches int
		}{
			{name: "matching apiVersion", apiVersion: "v1", wantMatches: 1},
			{name: "non-matching apiVersion", apiVersion: "apps/v1", wantMatches: 0},
			{name: "unknown apiVersion", apiVersion: "blah/v1alpha1", wantMatches: 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, err := defaults.GetMatchingPolicies("match-pods", "Pod", tc.apiVersion, map[string]string{"match": "match"})
				if tc.wantMatches > 0 {
					checkGetMatches(t, c, err)
				} else if err != nil {
					t.Fatalf("GetMatchingPolicies() = %v", err)
				}
				if got := len(c); got != tc.wantMatches {
					t.Errorf("Wanted %d matches, got %d", tc.wantMatches, got)
				}
			})
		}
	})
}

func TestFailsToLoadInvalid(t *testing.T) {
	wantErr := "failed to parse the entry \"cluster-image-policy-0\""
	_, example := ConfigMapsFromTestFile(t, "config-invalid-image-policy")
	_, err := NewImagePoliciesConfigFromConfigMap(example)
	if err == nil {
		t.Error("Did not fail with invalid configmap")
	} else if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("Unexpected error, wanted to contain %s : got %v", wantErr, err)
	}
}

func checkGetMatches(t *testing.T, c map[string]webhookcip.ClusterImagePolicy, err error) {
	t.Helper()
	if err != nil {
		t.Error("GetMatches Failed =", err)
	}
	if len(c) == 0 {
		t.Error("Wanted a config, got none.")
	}
	for _, v := range c {
		if v.Authorities != nil || len(v.Authorities) > 0 {
			return
		}
	}
	t.Error("Wanted a config and non-zero authorities, got no authorities")
}

func checkPublicKey(t *testing.T, gotKey crypto.PublicKey) {
	t.Helper()

	derBytes, err := x509.MarshalPKIXPublicKey(gotKey)
	if err != nil {
		t.Error("Failed to Marshal Key =", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	// pem.EncodeToMemory has an extra newline at the end
	got := strings.TrimSuffix(string(pemBytes), "\n")
	if got != inlineKeyData {
		t.Errorf("Did not get what I wanted %s, got %s", inlineKeyData, string(pemBytes))
	}
}

func checkSourceOCI(t *testing.T, authority []webhookcip.Authority) {
	t.Helper()

	if got := len(authority); got != 1 {
		t.Errorf("Did not get what I wanted %d, got %d", 1, got)
	}
	if got := len(authority[0].Sources); got != 1 {
		t.Errorf("Did not get what I wanted %d, got %d", 1, got)
	}

	want := len(authority[0].Sources)
	if got := len(authority[0].RemoteOpts); got != want {
		t.Errorf("Did not get what I wanted %d, got %d", want, got)
	}
}

func checkUIDAndResourceVersion(t *testing.T, cipName string, cip webhookcip.ClusterImagePolicy) {
	t.Helper()
	wantUID := fmt.Sprintf("%s-uid", cipName)
	if wantUID != string(cip.UID) {
		t.Errorf("UID mismatch want: %s got: %s", wantUID, cip.UID)
	}
	wantResourceVersion := fmt.Sprintf("%s-resource-version", cipName)
	if wantResourceVersion != cip.ResourceVersion {
		t.Errorf("UID mismatch want: %s got: %s", wantResourceVersion, cip.ResourceVersion)
	}
}
