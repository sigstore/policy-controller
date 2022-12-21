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
)

const defaultTargets = "targets"

func TestTargetsDefaulting(t *testing.T) {
	tests := []struct {
		in                   *TrustRoot
		wantRepositoryTarget string
		wantRemoteTarget     string
	}{
		{in: trustrootWithTargets("", ""),
			wantRepositoryTarget: defaultTargets,
			wantRemoteTarget:     defaultTargets,
		}, {in: trustrootWithTargets("foo", ""),
			wantRepositoryTarget: "foo",
			wantRemoteTarget:     defaultTargets,
		}, {in: trustrootWithTargets("", "bar"),
			wantRepositoryTarget: defaultTargets,
			wantRemoteTarget:     "bar",
		}, {in: trustrootWithTargets("foo", "bar"),
			wantRepositoryTarget: "foo",
			wantRemoteTarget:     "bar",
		}}
	for _, tc := range tests {
		tc.in.SetDefaults(context.TODO())
		if tc.wantRemoteTarget != tc.in.Spec.Remote.Targets {
			t.Errorf("Wanted remote target: %s got: %s", tc.wantRemoteTarget, tc.in.Spec.Remote.Targets)
		}
		if tc.wantRepositoryTarget != tc.in.Spec.Repository.Targets {
			t.Errorf("Wanted remote target: %s got: %s", tc.wantRepositoryTarget, tc.in.Spec.Repository.Targets)
		}
	}
}

func trustrootWithTargets(repoTargets, remoteTargets string) *TrustRoot {
	return &TrustRoot{
		Spec: TrustRootSpec{
			Repository: &Repository{Targets: repoTargets},
			Remote:     &Remote{Targets: remoteTargets},
		},
	}
}
