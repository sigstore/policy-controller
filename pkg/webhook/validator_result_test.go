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

package webhook

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sigstore/policy-controller/pkg/webhook/policy"
)

func TestCrossAttestationPolicy(t *testing.T) {
	const rule = `package sigstore
default isCompliant = false
isCompliant {
    scan := input.authorityMatches.scanner.attestations.scan[_].predicate.runID
    approval := input.authorityMatches.approver.attestations.approval[_].predicate.runID
    is_string(scan)
    scan != ""
    scan == approval
}`

	for _, tc := range []struct {
		name     string
		include  bool
		approval string
		allowed  bool
	}{
		{"same run", true, `{"predicate":{"runID":"run-7"}}`, true},
		{"different runs", true, `{"predicate":{"runID":"run-8"}}`, false},
		{"missing run", true, `{"predicate":{}}`, false},
		{"opted out", false, `{"predicate":{"runID":"run-7"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := &PolicyResult{AuthorityMatches: map[string]AuthorityMatch{
				"scanner": {Attestations: map[string][]PolicyAttestation{
					"scan": {{PredicateType: "https://example.invalid/scan", Payload: []byte(`{"predicate":{"runID":"run-7"}}`)}},
				}},
				"approver": {Attestations: map[string][]PolicyAttestation{
					"approval": {{PredicateType: "https://example.invalid/approval", Payload: []byte(tc.approval)}},
				}},
			}}
			input, err := result.marshalPolicyInput(tc.include)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.include {
				original, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				if string(input) != string(original) {
					t.Fatal("policy input changed without opt-in")
				}
			}
			warn, err := policy.EvaluatePolicyAgainstJSON(context.Background(), "cross-attestation", "rego", rule, input)
			if allowed := warn == nil && err == nil; allowed != tc.allowed {
				t.Fatalf("allowed = %t, want %t (warn: %v; err: %v)", allowed, tc.allowed, warn, err)
			}
		})
	}
}
