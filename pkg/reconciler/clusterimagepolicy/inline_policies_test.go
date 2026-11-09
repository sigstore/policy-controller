// Copyright 2026 The Sigstore Authors.
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

package clusterimagepolicy

import (
	"context"
	"testing"

	"knative.dev/pkg/apis"

	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
)

// An attestation can carry its own policy.remote while the CIP has no
// top level spec.policy. When the fetch for that attestation failed, the
// error was logged with cip.Spec.Policy.Remote.URL, the top level policy,
// which is nil in that shape.
func TestInlinePoliciesAttestationRemoteFetchFailure(t *testing.T) {
	// Port 1 on loopback so nothing leaves the machine.
	u, err := apis.ParseURL("http://127.0.0.1:1/policy.yaml")
	if err != nil {
		t.Fatalf("parsing url: %v", err)
	}

	cip := &v1alpha1.ClusterImagePolicy{
		Spec: v1alpha1.ClusterImagePolicySpec{
			Authorities: []v1alpha1.Authority{{
				Attestations: []v1alpha1.Attestation{{
					Name:          "must-have-sbom",
					PredicateType: "custom",
					Policy: &v1alpha1.Policy{
						Type:   "cue",
						Remote: &v1alpha1.RemotePolicy{URL: *u},
					},
				}},
			}},
		},
	}

	r := &Reconciler{}

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("inlinePolicies panicked instead of returning an error: %v", p)
		}
	}()

	if err := r.inlinePolicies(context.Background(), cip); err == nil {
		t.Error("expected an error for an unreachable attestation policy url")
	}
}

// The top level policy keeps working on its own.
func TestInlinePoliciesTopLevelRemoteFetchFailure(t *testing.T) {
	u, err := apis.ParseURL("http://127.0.0.1:1/policy.yaml")
	if err != nil {
		t.Fatalf("parsing url: %v", err)
	}

	cip := &v1alpha1.ClusterImagePolicy{
		Spec: v1alpha1.ClusterImagePolicySpec{
			Policy: &v1alpha1.Policy{
				Type:   "cue",
				Remote: &v1alpha1.RemotePolicy{URL: *u},
			},
		},
	}

	r := &Reconciler{}

	if err := r.inlinePolicies(context.Background(), cip); err == nil {
		t.Error("expected an error for an unreachable top level policy url")
	}
}
