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
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI0LTA2LTE0VDE4OjUyOjQ1WiIsCiAgImtleXMiOiB7CiAgICIwOGYzZThjZTZiYzMwYTA2YjBhMTQzODNmMjg2YzJmODZmM2YzYzZlMWJjZjNkNDgxNmNiMGIwNDUxZmY2NGFjIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI0NGFlNzMzZDk1MWY1YzM5MWJhZjQ5NmNiMDExNzMzYjFjZDFjYmZhYzg1ZTViMTg0YjJiMjI4N2YzMDgxMDA2IgogICAgfQogICB9LAogICAiMjUwZGFlNzZlOWVkNTM3MjU4MmViMzE5OGMyZDUzNDBjNmM2NWY0ZTdiYmUyMzAzNmJjNWExZjkwN2ZkNDUwOSI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiY2VhNmE0OGJmNGQ1YzFkZDc1MDQ0NmMxMzVjZWNhZjkyMDczZGU2OGRjMjVjYTkxZjgwNTgzZjE3NzYzZjI5NSIKICAgIH0KICAgfSwKICAgIjRlMDA0ZDRlMDM3ZThjMzBkN2YxZTMzODU1MmRlNDcyNzg2ZDkyYTM3NzEwYjExYTc2YTVjNDdiMDBkOTZkOTkiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjIwOTkyNGE0OTAxMDBkNDhhNWVkYTcyYjg1OTE4NThmZGUyMGU1MTVkMDgyZGNiMTBhNDllNzA1NDAwZTg5ZTMiCiAgICB9CiAgIH0sCiAgICJhMGUyMTFlMjQyNzVlZTJlY2NlYmI3Yzc5YTJhYzc4NjhkMGIzMDhjMTBmNjBjYTgxZTA2YmIxMzIxNjY3ZjFmIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJlOGM1NzhjNDJmMDEzZTJjNTk1N2JmOWI3ZGI2N2RjNjgwODUwOWJhNzQxMTM2OGY4Y2M1YzNjM2ZiOTBkNGI5IgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiMjUwZGFlNzZlOWVkNTM3MjU4MmViMzE5OGMyZDUzNDBjNmM2NWY0ZTdiYmUyMzAzNmJjNWExZjkwN2ZkNDUwOSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJhMGUyMTFlMjQyNzVlZTJlY2NlYmI3Yzc5YTJhYzc4NjhkMGIzMDhjMTBmNjBjYTgxZTA2YmIxMzIxNjY3ZjFmIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiNGUwMDRkNGUwMzdlOGMzMGQ3ZjFlMzM4NTUyZGU0NzI3ODZkOTJhMzc3MTBiMTFhNzZhNWM0N2IwMGQ5NmQ5OSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiMDhmM2U4Y2U2YmMzMGEwNmIwYTE0MzgzZjI4NmMyZjg2ZjNmM2M2ZTFiY2YzZDQ4MTZjYjBiMDQ1MWZmNjRhYyIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IGZhbHNlCiB9LAogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiMjUwZGFlNzZlOWVkNTM3MjU4MmViMzE5OGMyZDUzNDBjNmM2NWY0ZTdiYmUyMzAzNmJjNWExZjkwN2ZkNDUwOSIsCiAgICJzaWciOiAiMzJkNDUwYjBmMmFiZDI0NmY3M2NlNzZkMGNkYWE3MTEzZGFmNWRjMTYxN2MyZTEwODZmYmI1MWYyYTU4NDU4YjExNTUzN2YwYWM0MTdlZTM0NjllZWM2ZTFiOWE0YmQwZmIwZWEyNzEzZWE0MTdiNGExZGQ5ZDViODIxZjRkMGMiCiAgfQogXQp9`
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
