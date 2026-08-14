//
// Copyright 2021 The Sigstore Authors.
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
	"crypto"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"knative.dev/pkg/logging"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/empty"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	policycontrollerconfig "github.com/sigstore/policy-controller/pkg/config"
	"github.com/sigstore/sigstore/pkg/signature"
)

func valid(ctx context.Context, ref name.Reference, keys []crypto.PublicKey, hashAlgo crypto.Hash, checkOpts *cosign.CheckOpts) ([]oci.Signature, error) {
	if len(keys) == 0 {
		return validSignatures(ctx, ref, checkOpts)
	}
	// We return nil if ANY key matches
	var lastErr error
	for _, k := range keys {
		verifier, err := signature.LoadVerifier(k, hashAlgo)
		if err != nil {
			logging.FromContext(ctx).Errorf("error creating verifier: %v", err)
			lastErr = err
			continue
		}
		checkOpts.SigVerifier = verifier
		sps, err := validSignatures(ctx, ref, checkOpts)
		if err != nil {
			logging.FromContext(ctx).Errorf("error validating signatures: %v", err)
			lastErr = err
			continue
		}
		return sps, nil
	}
	logging.FromContext(ctx).Debug("No valid signatures were found.")
	return nil, lastErr
}

// For testing
var cosignVerifySignatures = cosign.VerifyImageSignatures
var cosignVerifyAttestations = cosign.VerifyImageAttestations
var cosignVerifyAttestation = cosign.VerifyImageAttestation
var ociremoteResolveDigest = ociremote.ResolveDigest
var ociremoteReferrers = ociremote.Referrers
var ociremoteSignedImage = ociremote.SignedImage
var testProcessAttestationArtifact = processAttestationArtifact

func validSignatures(ctx context.Context, ref name.Reference, checkOpts *cosign.CheckOpts) ([]oci.Signature, error) {
	checkOpts.ClaimVerifier = cosign.SimpleClaimVerifier
	sigs, _, err := cosignVerifySignatures(ctx, ref, checkOpts)
	return sigs, err
}

func validAttestations(ctx context.Context, ref name.Reference, checkOpts *cosign.CheckOpts) ([]oci.Signature, error) {
	cfg := policycontrollerconfig.FromContextOrDefaults(ctx)
	if cfg.EnableOCI11 {
		if attestations, err := discoverAttestationsOCI11(ctx, ref, checkOpts); err == nil {
			return attestations, nil
		}
	}

	checkOpts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	attestations, _, err := cosignVerifyAttestations(ctx, ref, checkOpts)
	return attestations, err
}

func discoverAttestationsOCI11(ctx context.Context, ref name.Reference, checkOpts *cosign.CheckOpts) ([]oci.Signature, error) {
	digest, err := ociremoteResolveDigest(ref, checkOpts.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}

	indexManifest, err := ociremoteReferrers(digest, "", checkOpts.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}

	var allSigs []oci.Signature
	for _, manifest := range indexManifest.Manifests {
		if strings.Contains(manifest.ArtifactType, "in-toto") {
			sigs, err := testProcessAttestationArtifact(manifest, digest.Repository, checkOpts.RegistryClientOpts)
			if err != nil {
				logging.FromContext(ctx).Debugf("Failed to process attestation artifact: %v", err)
				continue
			}
			allSigs = append(allSigs, sigs...)
		}
	}

	if len(allSigs) == 0 {
		return nil, fmt.Errorf("no attestations found")
	}

	hash, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, fmt.Errorf("resolving image digest: %w", err)
	}
	atts := empty.Signatures()
	for _, s := range allSigs {
		atts, err = mutate.AppendSignatures(atts, false, s)
		if err != nil {
			return nil, fmt.Errorf("collecting OCI 1.1 attestations: %w", err)
		}
	}
	checkOpts.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	verified, _, err := cosignVerifyAttestation(ctx, atts, hash, checkOpts)
	if err != nil {
		return nil, err
	}
	return verified, nil
}

func processAttestationArtifact(result v1.Descriptor, repository name.Repository, registryOpts []ociremote.Option) ([]oci.Signature, error) {
	attRef, err := name.ParseReference(fmt.Sprintf("%s@%s", repository, result.Digest.String()))
	if err != nil {
		return nil, err
	}

	signedEntity, err := ociremoteSignedImage(attRef, registryOpts...)
	if err != nil {
		return nil, err
	}

	layers, err := signedEntity.Layers()
	if err != nil || len(layers) == 0 {
		return nil, fmt.Errorf("no layers found")
	}

	rc, err := layers[0].Uncompressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	dsseEnvelope, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	var probe struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(dsseEnvelope, &probe); err != nil {
		return nil, fmt.Errorf("invalid DSSE envelope: %w", err)
	}
	if probe.PayloadType == "" || probe.Payload == "" || len(probe.Signatures) == 0 {
		return nil, fmt.Errorf("malformed DSSE envelope: missing payloadType, payload, or signatures")
	}

	// One oci.Signature per attestation referrer. The full DSSE envelope is the
	// signature payload; cosign.verifyOCIAttestation re-parses payloadType and
	// signatures from this payload before performing cryptographic verification.
	att, err := static.NewAttestation(dsseEnvelope)
	if err != nil {
		return nil, err
	}
	return []oci.Signature{att}, nil
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}
