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
	"crypto/x509"
	"encoding/pem"

	"github.com/google/go-containerregistry/pkg/name"
	"knative.dev/pkg/logging"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	v1alpha1 "github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/signature"
	timestampauthority "github.com/sigstore/timestamp-authority/pkg/generated/client"
)

func valid(ctx context.Context, ref name.Reference, tsaClient *timestampauthority.TimestampAuthority, tsaCertPool *x509.CertPool, rekorClient *client.Rekor, keys []crypto.PublicKey, hashAlgo crypto.Hash, opts ...ociremote.Option) ([]oci.Signature, error) {
	if len(keys) == 0 {
		// If there are no keys, then verify against the fulcio root.
		fulcioRoots, err := fulcioroots.Get()
		if err != nil {
			return nil, err
		}
		return validSignaturesWithFulcio(ctx, ref, fulcioRoots, nil, nil, nil /* rekor */, nil /* no identities */, opts...)
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

		sps, err := validSignatures(ctx, ref, verifier, tsaClient, tsaCertPool, rekorClient, opts...)
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

func validSignatures(ctx context.Context, ref name.Reference, verifier signature.Verifier, tsaClient *timestampauthority.TimestampAuthority, tsaCertPool *x509.CertPool, rekorClient *client.Rekor, opts ...ociremote.Option) ([]oci.Signature, error) {
	sigs, _, err := cosignVerifySignatures(ctx, ref, &cosign.CheckOpts{
		RegistryClientOpts: opts,
		SigVerifier:        verifier,
		RekorClient:        rekorClient,
		TSAClient:          tsaClient,
		TSACerts:           tsaCertPool, // Path isn't valid to be reusable
		ClaimVerifier:      cosign.SimpleClaimVerifier,
	})
	return sigs, err
}

// validSignaturesWithFulcio expects a Fulcio Cert to verify against. An
// optional rekorClient can also be given, if nil passed, default is assumed.
func validSignaturesWithFulcio(ctx context.Context, ref name.Reference, fulcioRoots *x509.CertPool, tsaClient *timestampauthority.TimestampAuthority, tsaCertPool *x509.CertPool, rekorClient *client.Rekor, identities []v1alpha1.Identity, opts ...ociremote.Option) ([]oci.Signature, error) {
	ids := make([]cosign.Identity, len(identities))
	for i, id := range identities {
		ids[i] = cosign.Identity{Issuer: id.Issuer, Subject: id.Subject, IssuerRegExp: id.IssuerRegExp, SubjectRegExp: id.SubjectRegExp}
	}
	sigs, _, err := cosignVerifySignatures(ctx, ref, &cosign.CheckOpts{
		RegistryClientOpts: opts,
		RootCerts:          fulcioRoots,
		RekorClient:        rekorClient,
		TSAClient:          tsaClient,
		TSACerts:           tsaCertPool,
		ClaimVerifier:      cosign.SimpleClaimVerifier,
		Identities:         ids,
	})
	return sigs, err
}

func validAttestations(ctx context.Context, ref name.Reference, verifier signature.Verifier, tsaClient *timestampauthority.TimestampAuthority, tsaCertPool *x509.CertPool, rekorClient *client.Rekor, opts ...ociremote.Option) ([]oci.Signature, error) {
	attestations, _, err := cosignVerifyAttestations(ctx, ref, &cosign.CheckOpts{
		RegistryClientOpts: opts,
		SigVerifier:        verifier,
		RekorClient:        rekorClient,
		TSAClient:          tsaClient,
		TSACerts:           tsaCertPool,
		ClaimVerifier:      cosign.IntotoSubjectClaimVerifier,
	})
	return attestations, err
}

// validAttestationsWithFulcio expects a Fulcio Cert to verify against. An
// optional rekorClient can also be given, if nil passed, default is assumed.
func validAttestationsWithFulcio(ctx context.Context, ref name.Reference, fulcioRoots *x509.CertPool, tsaClient *timestampauthority.TimestampAuthority, tsaCertPool *x509.CertPool, rekorClient *client.Rekor, identities []v1alpha1.Identity, opts ...ociremote.Option) ([]oci.Signature, error) {
	ids := make([]cosign.Identity, len(identities))
	for i, id := range identities {
		ids[i] = cosign.Identity{Issuer: id.Issuer, Subject: id.Subject, IssuerRegExp: id.IssuerRegExp, SubjectRegExp: id.SubjectRegExp}
	}

	attestations, _, err := cosignVerifyAttestations(ctx, ref, &cosign.CheckOpts{
		RegistryClientOpts: opts,
		RootCerts:          fulcioRoots,
		RekorClient:        rekorClient,
		TSAClient:          tsaClient,
		TSACerts:           tsaCertPool,
		ClaimVerifier:      cosign.IntotoSubjectClaimVerifier,
		Identities:         ids,
	})
	return attestations, err
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
