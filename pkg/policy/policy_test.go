// Copyright 2023 The Sigstore Authors.
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

package policy

import (
	"context"
	"errors"
	"testing"
)

const (
	// This is an example of what the default ko policy should be
	// as of 2023/01/03.
	goodPolicy = `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: ko-default-base-image-policy
spec:
  images:
  - glob: cgr.dev/chainguard/static*
  authorities:
  - keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuer: https://token.actions.githubusercontent.com
        subject: https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main
    ctlog:
      url: https://rekor.sigstore.dev
`

	// This is a policy that has warnings when compiled because it is missing
	// identity verification in its keyless block.
	warnPolicy = `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: ko-default-base-image-policy
spec:
  images:
  - glob: cgr.dev/chainguard/static*
  authorities:
  - keyless:
      url: https://fulcio.sigstore.dev
    # TODO(https://github.com/sigstore/policy-controller/issues/479):
    # Remove this once the above is fixed.
    ctlog:
      url: https://rekor.sigstore.dev
`

	badPolicy = `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: ko-default-base-image-policy
spec:
  bad: field
`
)

func TestVerificationValidate(t *testing.T) {
	tests := []struct {
		name    string
		v       Verification
		wantErr error
	}{{
		name: "legacy compatibility settings",
		v: Verification{
			NoMatchPolicy: "allow",
			Policies:      &[]Source{},
		},
	}, {
		name: "sample ko default settings",
		v: Verification{
			NoMatchPolicy: "warn",
			Policies: &[]Source{{
				Data: goodPolicy,
			}},
		},
	}, {
		name: "sample strict settings",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				Data: goodPolicy,
			}},
		},
	}, {
		name: "sample URL settings",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				URL: "https://raw.githubusercontent.com/sigstore/policy-controller/d6ef1f37c9c634fdb2693c11f8aa91c19e76e7d8/examples/policies/allow-only-pods.yaml",
			}},
		},
	}, {
		name: "sample path settings",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				Path: "../../examples/policies/allow-only-pods.yaml",
			}},
		},
	}, {
		name: "missing no match policy",
		v: Verification{
			NoMatchPolicy: "",
			Policies: &[]Source{{
				Data: goodPolicy,
			}},
		},
		wantErr: errors.New(`missing field(s): noMatchPolicy`),
	}, {
		name: "bad no match policy",
		v: Verification{
			NoMatchPolicy: "bad",
			Policies: &[]Source{{
				Data: goodPolicy,
			}},
		},
		wantErr: errors.New(`invalid value: bad: noMatchPolicy`),
	}, {
		name: "missing policies",
		v: Verification{
			NoMatchPolicy: "warn",
		},
		wantErr: errors.New(`missing field(s): policies`),
	}, {
		name: "missing policy data",
		v: Verification{
			NoMatchPolicy: "warn",
			Policies:      &[]Source{{
				// NO BODY
			}},
		},
		wantErr: errors.New(`expected exactly one, got neither: policies[0].data, policies[0].path, policies[0].url`),
	}, {
		name: "bad policy data",
		v: Verification{
			NoMatchPolicy: "warn",
			Policies: &[]Source{{
				Data: badPolicy,
			}},
		},
		wantErr: errors.New(`invalid value: unable to unmarshal: json: unknown field "bad": policies[0].data`),
	}, {
		name: "bad URL",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				URL: "bad",
			}},
		},
		wantErr: errors.New(`Get "bad": unsupported protocol scheme "": policies[0].url`),
	}, {
		name: "bad URL content",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				URL: "https://raw.githubusercontent.com/sigstore/policy-controller/d6ef1f37c9c634fdb2693c11f8aa91c19e76e7d8/README.md",
			}},
		},
		wantErr: errors.New(`invalid value: decoding object[0]: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type map[string]interface {}: policies[0].url`),
	}, {
		name: "both provided",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				Data: goodPolicy,
				URL:  "https://raw.githubusercontent.com/sigstore/policy-controller/d6ef1f37c9c634fdb2693c11f8aa91c19e76e7d8/examples/policies/allow-only-pods.yaml",
			}},
		},
		wantErr: errors.New(`expected exactly one, got both: policies[0].data, policies[0].url`),
	}, {
		name: "path not found",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				Path: "not-found.yaml",
			}},
		},
		wantErr: errors.New(`open not-found.yaml: no such file or directory: policies[0].path`),
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testContext := context.Background()
			gotErr := test.v.Validate(testContext)
			if (gotErr != nil) != (test.wantErr != nil) {
				t.Fatalf("Validate() = %v, wanted %v", gotErr, test.wantErr)
			}
			if gotErr != nil && gotErr.Error() != test.wantErr.Error() {
				t.Fatalf("Validate() = %v, wanted %v", gotErr, test.wantErr)
			}
		})

		t.Run("compile: "+test.name, func(t *testing.T) {
			testContext := context.Background()
			_, gotErr := Compile(testContext, test.v, t.Logf)
			if (gotErr != nil) != (test.wantErr != nil) {
				t.Fatalf("Validate() = %v, wanted %v", gotErr, test.wantErr)
			}
			if gotErr != nil && gotErr.Error() != test.wantErr.Error() {
				t.Fatalf("Validate() = %v, wanted %v", gotErr, test.wantErr)
			}
		})
	}
}
