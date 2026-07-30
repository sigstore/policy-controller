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

	// TUF Root json for the above validRepository.
	// IMPORTANT: The next expiration is on '2027-01-28T17:36:23Z'
	// To regenerate rootJSON and the matching validRepository above, run
	// `make generate-testdata` and base64-encode the resulting
	// pkg/reconciler/trustroot/testdata/root.json and tufRepo.tar respectively.
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI3LTAxLTI4VDE3OjM2OjIzWiIsCiAgImtleXMiOiB7CiAgICIzZDk1NWRlZTk5ODMwYmUwNTc1MWQyMmNjMDUwYTQ3NWI2OTIwZGUyZDM2MWNiZGVhNjJmYzE0YTY2MTg3MzU5IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIwOWI2MjM5ZTkyNTBjMWEzODIyY2UwY2YzZmMxMjdiMjY3YmUwZTUyYWZlYjA0YWY4MDQ2MmM0ZmM2MWE4NDI0IgogICAgfQogICB9LAogICAiNTU0NjRhMzRhMzk1NWQ3NTMxMzE0M2Y0ZThmZGE0NzRlNWRkMmYwNjcwYTc5ZGE0ZDIzZDhiMWNkZDQ3ZDNlMiI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiYjIyYzQ3NDM5ZGIxNDk5MDhlY2ZhOTA0MDZhZDA5MzJjMzNkOTkwOThhODQ3MWY1ZmU3MjMwZjRkZjRjZmJkZSIKICAgIH0KICAgfSwKICAgIjZjMDc5MzVkY2RjZDRjNmM4NmUxZGM3OTc1NmY2MTY5MDZkZDhhNWQ1YWRjN2NlN2NlMzg1YTllYTIyMTlmMGEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogImZkNWM1YzhkNmU2MTFkNTdkYWIxYzk0YjEyODVkMmE1NWI3OWQ5MTg3MGY0ZjBhZjg1ZDRiMTkyZmRlYjdkMjUiCiAgICB9CiAgIH0sCiAgICJmMDBlMTU3YTc1OGU3ZGZlMmY3OTc0N2RmNzgwNjM4MmFmNzBhODc0YmIzZTJjZTc2MmJhOThkOWQ4NGU5YWRmIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI5MmU0NGFmNTgyNzU4NjQ1ODVmYzVlMjI2NmRjMDdkZWFjNzFiY2RmN2Q3YzVkYWI2NWQ2MTYxY2E1MDAxN2JiIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiNTU0NjRhMzRhMzk1NWQ3NTMxMzE0M2Y0ZThmZGE0NzRlNWRkMmYwNjcwYTc5ZGE0ZDIzZDhiMWNkZDQ3ZDNlMiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICIzZDk1NWRlZTk5ODMwYmUwNTc1MWQyMmNjMDUwYTQ3NWI2OTIwZGUyZDM2MWNiZGVhNjJmYzE0YTY2MTg3MzU5IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiNmMwNzkzNWRjZGNkNGM2Yzg2ZTFkYzc5NzU2ZjYxNjkwNmRkOGE1ZDVhZGM3Y2U3Y2UzODVhOWVhMjIxOWYwYSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiZjAwZTE1N2E3NThlN2RmZTJmNzk3NDdkZjc4MDYzODJhZjcwYTg3NGJiM2UyY2U3NjJiYTk4ZDlkODRlOWFkZiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICI1NTQ2NGEzNGEzOTU1ZDc1MzEzMTQzZjRlOGZkYTQ3NGU1ZGQyZjA2NzBhNzlkYTRkMjNkOGIxY2RkNDdkM2UyIiwKICAgInNpZyI6ICJjNDg2MDhlYTRjMzY3N2QyNTE5OTQyMWJiYTM5YTE3NTM5YjRmOGUyMzU4MWEzMWQ3YjY2NDIyNTAxOGYxNmRjOTE1OTgyNjM2YjlhMDMxODc2ZjAyYzY5YmQxMTFjZTA4YTg0ZWQzODY5YjI0ZDZhNDg0YTY1YjJmZmE2Y2IwOSIKICB9CiBdCn0=`
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
