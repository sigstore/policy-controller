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
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/sigstore/policy-controller/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"knative.dev/pkg/apis"
)

// validRepository is a TUF repository that's been tarred, gzipped and base64
// encoded. These are vars because conversion to []byte seems to make them not
// constant
var (
	validRepository = `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`

	// This is valid base64 (hello world), but should not be able to gunzip
	// untar.
	invalidRepository = []byte(`aGVsbG8gd29ybGQK`)

	// TUF Root json, generated via scaffolding
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI0LTEyLTE4VDE4OjQ3OjIyWiIsCiAgImtleXMiOiB7CiAgICI0MjUyMTk0NDhjNDBiOGMwZWM5MGE5NDg0ZjlhYzkwMTA1YzQ1OWY0NzM2OWNjOWY2OGJiNmIzYTEyNjIyNTU4IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIyMmJmMmVmOGFmMGNjNDk0MTQwMjNhYWU2MTJjMjFhZTI5YzRjN2FiNjJjOTcwZTcxOTYyNTA1OTVmZGM4ZDEyIgogICAgfQogICB9LAogICAiNTk4Mzc3ZWZlODMxZTA2ZDMwOTZjZDQ3OWU3ZjMyNzc5MzE0NTRhNWI1MWE0NDM0MWU0Yjk4ZTAyMmVhNDYxZCI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiMjQ3NzFmZjI4MDcyZDMwZTExZDFhOThmMDY5MWZiNDViYTc4MzkxODc2OTY4NDgyNmM0OTc5OGIzODUwMzJkOCIKICAgIH0KICAgfSwKICAgIjgxZTdmNWM3ODZkODdmMzRkNDVhYjlkMzFlNGNlZWEyODkyZjRiN2EwM2ZlOThhYWNhOWZhZWY4NmY4NzJjOGYiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjVjNzFlMWVhY2ViMjE1MTIwZjMwNzk5YmYwNmQ3ZDZjOTFmMzgxMjNjMzJiNGJjYjlmZDM3ZGJlYmVhNTYxNGEiCiAgICB9CiAgIH0sCiAgICJjNzZlN2FhOTdjY2RhMTMxNDVkOTg3ZjViNDQ4MTI2NTVlMjcwODI3NzNjYjg5NmE2OTZmZjhiNmQzMjE2MDZlIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI5YjU3MmQ4N2FlOWQwMDM2NjdlYmM0NjFkZjQ5NDE4ODBjYjM1M2FiMjQ5Y2Y1NzFjMGJmMDhjMTg4MzBlZTI1IgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiYzc2ZTdhYTk3Y2NkYTEzMTQ1ZDk4N2Y1YjQ0ODEyNjU1ZTI3MDgyNzczY2I4OTZhNjk2ZmY4YjZkMzIxNjA2ZSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICI0MjUyMTk0NDhjNDBiOGMwZWM5MGE5NDg0ZjlhYzkwMTA1YzQ1OWY0NzM2OWNjOWY2OGJiNmIzYTEyNjIyNTU4IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiNTk4Mzc3ZWZlODMxZTA2ZDMwOTZjZDQ3OWU3ZjMyNzc5MzE0NTRhNWI1MWE0NDM0MWU0Yjk4ZTAyMmVhNDYxZCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiODFlN2Y1Yzc4NmQ4N2YzNGQ0NWFiOWQzMWU0Y2VlYTI4OTJmNGI3YTAzZmU5OGFhY2E5ZmFlZjg2Zjg3MmM4ZiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IGZhbHNlCiB9LAogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiYzc2ZTdhYTk3Y2NkYTEzMTQ1ZDk4N2Y1YjQ0ODEyNjU1ZTI3MDgyNzczY2I4OTZhNjk2ZmY4YjZkMzIxNjA2ZSIsCiAgICJzaWciOiAiNjM2MDMzNjVmNzgxYzM1NzViNjAzZjE5YWVkYjViNjRkN2E2NmJlYWUwYTAzMzkwMTQwYjE3ZTA1Yjk0YmQ1ZjNkMzlmMDNkYjg5MjgwMzY1MTE4NGQzNjg1NTI2ZDJiOTk1MDdlNzU1NDIzZGI2NmNlMjFmNTJmYmM5MDA0MDAiCiAgfQogXQp9`
)

func TestTrustRootValidation(t *testing.T) {
	rootJSONDecoded, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		t.Fatalf("Failed to decode rootJSON for testing: %v", err)
	}
	validRepositoryDecoded, err := base64.StdEncoding.DecodeString(validRepository)
	if err != nil {
		t.Fatalf("Failed to decode validRepository for testing: %v", err)
	}
	tests := []struct {
		name        string
		trustroot   TrustRoot
		errorString string
	}{{
		name: "Should work with a valid repository",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSONDecoded,
					MirrorFS: validRepositoryDecoded,
					Targets:  "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.root",
		errorString: "missing field(s): spec.repository.root",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					MirrorFS: validRepositoryDecoded,
					Targets:  "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.repository",
		errorString: "missing field(s): spec.repository.repository",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:    rootJSONDecoded,
					Targets: "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.targets",
		errorString: "missing field(s): spec.repository.targets",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSONDecoded,
					MirrorFS: validRepositoryDecoded,
				},
			},
		},
	}, {
		name:        "Should fail with an invalid repository.mirrorFS, not a gzip/tar file",
		errorString: "invalid value: failed to construct a TUF client: spec.repository.mirrorFS\nfailed to uncompress: gzip: invalid header",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSONDecoded,
					MirrorFS: invalidRepository,
					Targets:  "targets",
				},
			},
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.trustroot.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestTimeStampAuthorityValidation(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	rootCert2, rootKey2, _ := test.GenerateRootCa()
	subCert2, subKey2, _ := test.GenerateSubordinateCa(rootCert2, rootKey2)
	leafCert2, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert2, subKey2)

	pem, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{rootCert, subCert, leafCert})
	if err != nil {
		t.Fatalf("unexpected error marshalling certificates to PEM: %v", err)
	}
	tooManyLeavesPem, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{rootCert, subCert, leafCert, leafCert2})
	if err != nil {
		t.Fatalf("unexpected error marshalling certificates to PEM: %v", err)
	}

	tests := []struct {
		name        string
		tsa         CertificateAuthority
		errorString string
	}{{
		name: "Should work with a valid repository",
		tsa: CertificateAuthority{
			Subject: DistinguishedName{
				Organization: "fulcio-organization",
				CommonName:   "fulcio-common-name",
			},
			URI:       *apis.HTTPS("fulcio.example.com"),
			CertChain: pem,
		},
	}, {
		name:        "Should fail splitting the certificates of the certChain",
		errorString: "invalid value: error splitting the certificates: certChain\nerror during PEM decoding",
		tsa: CertificateAuthority{
			Subject: DistinguishedName{
				Organization: "fulcio-organization",
				CommonName:   "fulcio-common-name",
			},
			URI:       *apis.HTTPS("fulcio.example.com"),
			CertChain: []byte("INVALID"),
		},
	}, {
		name:        "Should fail with a must contain at most one TSA certificate",
		errorString: "invalid value: certificate chain must contain at most one TSA certificate: certChain",
		tsa: CertificateAuthority{
			Subject: DistinguishedName{
				Organization: "fulcio-organization",
				CommonName:   "fulcio-common-name",
			},
			URI:       *apis.HTTPS("fulcio.example.com"),
			CertChain: tooManyLeavesPem,
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTimeStampAuthority(context.TODO(), test.tsa)
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestIgnoreStatusUpdatesTrustRoot(t *testing.T) {
	tr := &TrustRoot{Spec: TrustRootSpec{}}

	if err := tr.Validate(apis.WithinSubResourceUpdate(context.Background(), &tr, "status")); err != nil {
		t.Errorf("Failed to update status on invalid resource: %v", err)
	}
}
