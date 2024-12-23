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
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI1LTA2LTIwVDEwOjA3OjIzWiIsCiAgImtleXMiOiB7CiAgICIxOGRhNDVlN2Y5ZmY5NTRiNzJmMTliNGViZDczNmU4OGI2NjhjMjNkZjRkZWM0ZTU4ZjZhMDM3MWFmOWJiMzY2IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI2OWIzOWRlOTY3NGRlYjc3N2VhNTgwMmYwMjU5MmUzYTg3YzRiZDNhMDEwZTRkMWM5OGU1M2FkMjdjOTBjNGI4IgogICAgfQogICB9LAogICAiNmUzMTk3M2RkMjU1ZGM5MWRjYTgwOGU0MzcxZjNlY2EyMjM2OTBkNjJhZWFmYmE0MmQxNGIwM2YzODYzOTMwOCI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiYzc0NGVhODUzNjg5Yjg5YzYyZjBmMDZjYjgyOGE4OTVhYTQ3ODZlOTEzZWE3ZmE5Y2NhYzRkODgxZDcxYmJmZSIKICAgIH0KICAgfSwKICAgIjZlNWI3NzUzNmMwMjhjMWZiYzIwNGRjYjRlOTczMjZjZWRkNjY5YmZiNDVmOTlkYTdmYjRmMjYyNThhMDM5ODYiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogImU0ODA1NGYxYzhmYzQzNDUxY2E2NmU4ZmE1MjQ4NzA5YzYyYThmZjM5ZGU4ZjliYjIxZGRiOGM2YTM3YzcyZWQiCiAgICB9CiAgIH0sCiAgICJkNmY0MTc0Zjk1YjM3YWEyYTBmOGIxZWM1NGRmOWQwY2NmZWQ4MjQzMzEyZDE5ZjIxYWM1OWFkNTAxYmM2YTZiIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIwY2I5MzFjNTAzY2EzYjBjNjRjN2E3Mzc3Mzc3YWYzYTgwMjA2ZTk2Yzc5NGY4NTA5NzkzOTk0YTE5MGEzYzMzIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiNmU1Yjc3NTM2YzAyOGMxZmJjMjA0ZGNiNGU5NzMyNmNlZGQ2NjliZmI0NWY5OWRhN2ZiNGYyNjI1OGEwMzk4NiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJkNmY0MTc0Zjk1YjM3YWEyYTBmOGIxZWM1NGRmOWQwY2NmZWQ4MjQzMzEyZDE5ZjIxYWM1OWFkNTAxYmM2YTZiIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiMThkYTQ1ZTdmOWZmOTU0YjcyZjE5YjRlYmQ3MzZlODhiNjY4YzIzZGY0ZGVjNGU1OGY2YTAzNzFhZjliYjM2NiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiNmUzMTk3M2RkMjU1ZGM5MWRjYTgwOGU0MzcxZjNlY2EyMjM2OTBkNjJhZWFmYmE0MmQxNGIwM2YzODYzOTMwOCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICI2ZTViNzc1MzZjMDI4YzFmYmMyMDRkY2I0ZTk3MzI2Y2VkZDY2OWJmYjQ1Zjk5ZGE3ZmI0ZjI2MjU4YTAzOTg2IiwKICAgInNpZyI6ICJmM2IyMjMwNTk2ZmUzZTU1MzA2OTJmMGY4NGQxMjIxZjQ2YzhhMGRmODQzMGI5OTVjMjZkMjFkYzI3YTY5YTM5ZmQwNWE1MjMzMDBjNTE5ZWVhYzAzNmFkZDNlYmZkOTM3YmY3MjM1ZTcwNjU5YWMyMDgyYzhlYzQ4NTI5ZmYwMCIKICB9CiBdCn0=`
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
