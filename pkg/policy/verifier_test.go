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
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

const (
	// This is the digest of cgr.dev/chainguard/static as of 2023/01/03.
	// It is verifiable with goodPolicy.
	staticDigest = "sha256:39ae0654d64cb72003216f6148e581e6d7cf239ac32325867af46666e31739d2"

	// This is the digest of ghcr.io/distroless/static as of 2023/01/03.
	// It is not verifiable with goodPolicy.
	ancientDigest = "sha256:a9650a15060275287ebf4530b34020b8d998bd2de9aea00d113c332d8c41eb0b"
)

func TestVerifierDeny(t *testing.T) {
	tests := []struct {
		name    string
		v       Verification
		d       name.Digest
		wantErr error
	}{{
		name: "successful policy evaluation",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				Data: goodPolicy,
			}},
		},
		d: name.MustParseReference("cgr.dev/chainguard/static@" + staticDigest).(name.Digest),
	}, {
		name: "no match policy failure",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				Data: goodPolicy,
			}},
		},
		d:       name.MustParseReference("cgr.dev/chainguard/busybox@" + staticDigest).(name.Digest),
		wantErr: errors.New("cgr.dev/chainguard/busybox@sha256:39ae0654d64cb72003216f6148e581e6d7cf239ac32325867af46666e31739d2 is uncovered by policy"),
	}, {
		name: "policy evaluation failure",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				Data: goodPolicy,
			}},
		},
		d:       name.MustParseReference("cgr.dev/chainguard/static@" + ancientDigest).(name.Digest),
		wantErr: errors.New("signature keyless validation failed for authority authority-0 for cgr.dev/chainguard/static@sha256:a9650a15060275287ebf4530b34020b8d998bd2de9aea00d113c332d8c41eb0b: no matching signatures:\nnone of the expected identities matched what was in the certificate: "),
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vfy, err := Compile(context.Background(), test.v,
				t.Errorf /* we expect no warnings! */)
			if err != nil {
				t.Fatalf("Compile() = %v", err)
			}

			gotErr := vfy.Verify(context.Background(), test.d, authn.DefaultKeychain)
			if (gotErr != nil) != (test.wantErr != nil) {
				t.Fatalf("Verify() = %v, wanted %v", gotErr, test.wantErr)
			}
			if gotErr != nil && gotErr.Error() != test.wantErr.Error() {
				t.Fatalf("Verify() = %v, wanted %v", gotErr, test.wantErr)
			}
		})
	}
}

func TestVerifierWarn(t *testing.T) {
	tests := []struct {
		name    string
		v       Verification
		d       name.Digest
		wantErr error
	}{{
		name: "successful policy evaluation (warn mode)",
		v: Verification{
			NoMatchPolicy: "warn",
			Policies: &[]Source{{
				Data: goodPolicy,
			}},
		},
		d: name.MustParseReference("cgr.dev/chainguard/static@" + staticDigest).(name.Digest),
	}, {
		name: "no match policy failure",
		v: Verification{
			NoMatchPolicy: "warn",
			Policies: &[]Source{{
				Data: goodPolicy,
			}},
		},
		d:       name.MustParseReference("cgr.dev/chainguard/busybox@" + staticDigest).(name.Digest),
		wantErr: errors.New("cgr.dev/chainguard/busybox@sha256:39ae0654d64cb72003216f6148e581e6d7cf239ac32325867af46666e31739d2 is uncovered by policy"),
	}, {
		name: "policy evaluation failure (warn mode)",
		v: Verification{
			NoMatchPolicy: "deny",
			Policies: &[]Source{{
				Data: goodPolicy + "  mode: warn",
			}},
		},
		d:       name.MustParseReference("cgr.dev/chainguard/static@" + ancientDigest).(name.Digest),
		wantErr: errors.New("signature keyless validation failed for authority authority-0 for cgr.dev/chainguard/static@sha256:a9650a15060275287ebf4530b34020b8d998bd2de9aea00d113c332d8c41eb0b: no matching signatures:\nnone of the expected identities matched what was in the certificate: "),
	}, {
		name: "duplicate policies",
		v: Verification{
			NoMatchPolicy: "deny", // This is always surfaced as a warning.
			Policies: &[]Source{{
				Data: goodPolicy,
			}, {
				Data: goodPolicy,
			}},
		},
		d:       name.MustParseReference("cgr.dev/chainguard/static@" + staticDigest).(name.Digest),
		wantErr: errors.New(`duplicate policy named "ko-default-base-image-policy", skipping`),
	}, {
		name: "compilation warnings",
		v: Verification{
			NoMatchPolicy: "deny", // This is always surfaced as a warning.
			Policies: &[]Source{{
				Data: warnPolicy,
			}},
		},
		d:       name.MustParseReference("cgr.dev/chainguard/static@" + ancientDigest).(name.Digest),
		wantErr: errors.New(`policy 0: missing field(s): spec.authorities[0].keyless.identities`),
	}}

	for _, test := range tests {
		t.Run("warn: "+test.name, func(t *testing.T) {
			var gotErr error
			vfy, err := Compile(context.Background(), test.v,
				func(s string, i ...interface{}) {
					gotErr = fmt.Errorf(s, i...)
				})
			if err != nil {
				t.Fatalf("Compile() = %v", err)
			}

			err = vfy.Verify(context.Background(), test.d, authn.DefaultKeychain)
			if err != nil {
				t.Fatalf("Verify() = %v", err)
			}

			if (gotErr != nil) != (test.wantErr != nil) {
				t.Fatalf("Verify() = %v, wanted %v", gotErr, test.wantErr)
			}
			if gotErr != nil && gotErr.Error() != test.wantErr.Error() {
				t.Fatalf("Verify() = %v, wanted %v", gotErr, test.wantErr)
			}
		})
	}
}
