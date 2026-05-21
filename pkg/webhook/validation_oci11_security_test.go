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
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	policycontrollerconfig "github.com/sigstore/policy-controller/pkg/config"
)

// TestValidAttestationsOCI11_RejectsForgedDSSE asserts that an attacker who
// controls only the OCI registry cannot get an unsigned/forged DSSE envelope
// accepted as a "verified" attestation by validAttestations when EnableOCI11
// is set. Prior to the fix, discoverAttestationsOCI11/processAttestationArtifact
// returned the envelope as a verified oci.Signature without ever invoking a
// cryptographic verifier; ValidatePolicyAttestationsForAuthority then treated
// len(result) > 0 as success and admitted the image. This regression test
// pins the post-fix behavior: with no verifier, no trust roots, and a forged
// signature byte, validAttestations must return an error rather than a
// signature.
func TestValidAttestationsOCI11_RejectsForgedDSSE(t *testing.T) {
	ctx := context.Background()

	origResolve := ociremoteResolveDigest
	origReferrers := ociremoteReferrers
	origSignedImg := ociremoteSignedImage
	defer func() {
		ociremoteResolveDigest = origResolve
		ociremoteReferrers = origReferrers
		ociremoteSignedImage = origSignedImg
	}()

	cfg := &policycontrollerconfig.PolicyControllerConfig{EnableOCI11: true}
	ctx = policycontrollerconfig.ToContext(ctx, cfg)

	imageRef := name.MustParseReference(
		"attacker.example.com/evil/img@sha256:" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	ociremoteResolveDigest = func(_ name.Reference, _ ...cosignremote.Option) (name.Digest, error) {
		return imageRef.(name.Digest), nil
	}
	ociremoteReferrers = func(_ name.Digest, _ string, _ ...cosignremote.Option) (*v1.IndexManifest, error) {
		return &v1.IndexManifest{
			Manifests: []v1.Descriptor{
				{
					ArtifactType: "application/vnd.dsse.envelope.v1+json; in-toto",
					Digest: v1.Hash{
						Algorithm: "sha256",
						Hex:       "0123456789012345678901234567890123456789012345678901234567890123",
					},
				},
			},
		}, nil
	}

	innerStatement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]interface{}{
			{"name": "attacker.example.com/evil/img", "digest": map[string]string{"sha256": "aaaa"}},
		},
		"predicate": map[string]interface{}{
			"builder":   map[string]string{"id": "https://attacker.example.com"},
			"buildType": "https://attacker.example.com/forged",
		},
	}
	stmtJSON, _ := json.Marshal(innerStatement)
	dsse, _ := json.Marshal(map[string]interface{}{
		"payload":     base64.StdEncoding.EncodeToString(stmtJSON),
		"payloadType": "application/vnd.in-toto+json",
		"signatures": []map[string]string{
			{"sig": "ATTACKER_FORGED_SIGNATURE"},
		},
	})

	ociremoteSignedImage = func(_ name.Reference, _ ...cosignremote.Option) (oci.SignedImage, error) {
		return &mockSignedImage{layers: []v1.Layer{&mockLayer{content: dsse}}}, nil
	}

	// A CheckOpts with no SigVerifier, no RootCerts, no TrustedMaterial -
	// the attacker holds no signing key, and the verifier has no trust roots,
	// so verification MUST fail. Prior to the fix this returned 1 "verified"
	// attestation.
	checkOpts := &cosign.CheckOpts{
		Identities: []cosign.Identity{
			{Issuer: "https://accounts.google.com", Subject: "builder@google"},
		},
	}

	sigs, err := validAttestations(ctx, imageRef, checkOpts)
	if err == nil {
		t.Fatalf("OCI 1.1 attestation bypass regression: validAttestations returned %d 'verified' attestations for a forged DSSE envelope with no verifier configured", len(sigs))
	}
	if len(sigs) != 0 {
		t.Fatalf("expected zero verified attestations on error, got %d", len(sigs))
	}
}
