//
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

package webhook

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/empty"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/types"
	policycontrollerconfig "github.com/sigstore/policy-controller/pkg/config"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

// TestValidAttestationsOCI11Verification checks that attestations discovered
// through the OCI 1.1 referrers API are only accepted after cosign has
// verified their DSSE signature and in-toto subject.
func TestValidAttestationsOCI11Verification(t *testing.T) {
	const imageHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imageRef := name.MustParseReference("registry.example.com/img@sha256:" + imageHex)

	authorityKey := newTestSignerVerifier(t)
	otherKey := newTestSignerVerifier(t)

	signedBy := func(sv signature.SignerVerifier, subjectHex string) []byte {
		stmt, err := json.Marshal(map[string]interface{}{
			"_type":         "https://in-toto.io/Statement/v0.1",
			"predicateType": "https://slsa.dev/provenance/v1",
			"subject": []map[string]interface{}{
				{"name": "registry.example.com/img", "digest": map[string]string{"sha256": subjectHex}},
			},
			"predicate": map[string]interface{}{},
		})
		if err != nil {
			t.Fatal(err)
		}
		env, err := dsse.WrapSigner(sv, types.IntotoPayloadType).SignMessage(bytes.NewReader(stmt))
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	forged := func() []byte {
		env := map[string]interface{}{}
		if err := json.Unmarshal(signedBy(authorityKey, imageHex), &env); err != nil {
			t.Fatal(err)
		}
		env["signatures"] = []map[string]string{{"sig": base64.StdEncoding.EncodeToString([]byte("forged"))}}
		b, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	tests := []struct {
		name     string
		envelope []byte
		wantErr  bool
	}{{
		name:     "signed by the authority key",
		envelope: signedBy(authorityKey, imageHex),
	}, {
		name:     "signed by another key",
		envelope: signedBy(otherKey, imageHex),
		wantErr:  true,
	}, {
		name:     "forged signature",
		envelope: forged(),
		wantErr:  true,
	}, {
		name:     "signed for another image",
		envelope: signedBy(authorityKey, strings.Repeat("b", 64)),
		wantErr:  true,
	}}

	origResolve, origReferrers, origSignatures, origVerifyAtts := ociremoteResolveDigest, ociremoteReferrers, ociremoteSignatures, cosignVerifyAttestations
	defer func() {
		ociremoteResolveDigest, ociremoteReferrers, ociremoteSignatures, cosignVerifyAttestations = origResolve, origReferrers, origSignatures, origVerifyAtts
	}()
	ociremoteResolveDigest = func(name.Reference, ...cosignremote.Option) (name.Digest, error) {
		return imageRef.(name.Digest), nil
	}
	ociremoteReferrers = func(name.Digest, string, ...cosignremote.Option) (*v1.IndexManifest, error) {
		return &v1.IndexManifest{Manifests: []v1.Descriptor{{
			ArtifactType: types.IntotoPayloadType,
			Digest:       v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("c", 64)},
		}}}, nil
	}
	// The legacy .att tag lookup runs when OCI 1.1 discovery fails; keep it
	// off the network so only the OCI 1.1 path can produce a result.
	cosignVerifyAttestations = func(context.Context, name.Reference, *cosign.CheckOpts, ...name.Option) ([]oci.Signature, bool, error) {
		return nil, false, errors.New("no legacy attestations")
	}

	ctx := policycontrollerconfig.ToContext(context.Background(), &policycontrollerconfig.PolicyControllerConfig{EnableOCI11: true})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ociremoteSignatures = func(name.Reference, ...cosignremote.Option) (oci.Signatures, error) {
				att, err := static.NewAttestation(tt.envelope)
				if err != nil {
					return nil, err
				}
				return mutate.AppendSignatures(empty.Signatures(), false, att)
			}
			checkOpts := &cosign.CheckOpts{SigVerifier: authorityKey, IgnoreTlog: true}

			atts, err := validAttestations(ctx, imageRef, checkOpts)
			if tt.wantErr {
				if err == nil || len(atts) != 0 {
					t.Fatalf("expected the attestation to be rejected, got %d attestations, err=%v", len(atts), err)
				}
				return
			}
			if err != nil || len(atts) != 1 {
				t.Fatalf("expected 1 verified attestation, got %d, err=%v", len(atts), err)
			}
		})
	}
}

func newTestSignerVerifier(t *testing.T) signature.SignerVerifier {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return sv
}
