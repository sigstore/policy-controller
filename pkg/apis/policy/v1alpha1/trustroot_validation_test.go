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
	// IMPORTANT: The next expiration is on '2026-07-18T08:24:13Z'
	// Steps to generate:
	// 1. cgit clone github.com/sigstore/scaffolding
	// 2. run ./hack/setup-kind.sh
	// 3. export KO_DOCKER_REPO=registry.local:5001/sigstore
	// 4. run ./hack/setup-scaffolding.sh
	// 5. get the secrets from the kind cluster
	//    kubectl get secrets -o yaml -n tuf-system tuf-root
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI2LTA3LTE4VDA4OjI0OjEzWiIsCiAgImtleXMiOiB7CiAgICIwZjA1MmFkMzk5NTYwZDc1YzQzZjgwZGQ0NGZjZjZhMTBjNDk3MWZiYTczNTE3YTA2M2FhYjI3MTQwNjc2NjI4IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIwMWZiZjZlZDMxZjRhNjBmNGRkYzIwNjg0YzliNmE2MjIxMGY3Y2M4MWJmMzdjOGFiYjJmMThlMjUxOGExYzU5IgogICAgfQogICB9LAogICAiNDdmMjJjNmFlODI5MjlmNjU3ZTU2MmVmNWE1ZjdhNDRkYWI5ZjJhNDIzZWE2MGM5NjNiZWYzZjVhNjc5YTViOCI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiOGNhMDRmOTIxYjc0MjI0ZTNjN2I4ZmRhMGQ4ZTFjMGE0MGQyOWU5ZGRhYTQwNjgyNjhjNmUxZTk0NWZlN2IzMyIKICAgIH0KICAgfSwKICAgIjk4MzYyYTNiNGE5OTQyODRjNWI3MjUwN2Q3MzhlY2RkZTgyNzNlMmNmZTQ2NjM5Y2JlZmVjMTJkNzdhYjNjODEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogImI0MjI1OWNlYjBhOTI5ZTdmMGUzNGRlN2M2ZjEwMTQ1NjI4NzhjNTMxZjFjY2E4OTAwODg2MjcyM2YwNjA0ZTMiCiAgICB9CiAgIH0sCiAgICJiNTJlMzhiODdmY2Q4NmJlZmQxNDZiMDVjOTBjMDIxYThmOGFjNGMxMmY3MzdlOTU0ODhmNWM0NzMyZTE3NmJlIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI2NjZhMTUwYjM4MjRjNzZkMGIxZmQxMmI0ZjA3OGQ1NmE0MTNlYmM3ZTUyYWYyN2VhNDE0M2RjNWZlZmU5ZWJkIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiOTgzNjJhM2I0YTk5NDI4NGM1YjcyNTA3ZDczOGVjZGRlODI3M2UyY2ZlNDY2MzljYmVmZWMxMmQ3N2FiM2M4MSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJiNTJlMzhiODdmY2Q4NmJlZmQxNDZiMDVjOTBjMDIxYThmOGFjNGMxMmY3MzdlOTU0ODhmNWM0NzMyZTE3NmJlIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiNDdmMjJjNmFlODI5MjlmNjU3ZTU2MmVmNWE1ZjdhNDRkYWI5ZjJhNDIzZWE2MGM5NjNiZWYzZjVhNjc5YTViOCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiMGYwNTJhZDM5OTU2MGQ3NWM0M2Y4MGRkNDRmY2Y2YTEwYzQ5NzFmYmE3MzUxN2EwNjNhYWIyNzE0MDY3NjYyOCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICI5ODM2MmEzYjRhOTk0Mjg0YzViNzI1MDdkNzM4ZWNkZGU4MjczZTJjZmU0NjYzOWNiZWZlYzEyZDc3YWIzYzgxIiwKICAgInNpZyI6ICIzMjIyYzY2YmNlZGY4YmM2YTlkMGRjMzJkMmZlNWM4Yzg1OTlkYmZiODk0OGE3NDRhMzBhN2U2YmQ2MjgyOTliODY2NzQ4NjQ0NDYyMzZhNTllNjc0MmQyMjM2ZTM4YzJiNTZmNzg2YjNkMjU3ZGIyZTZlZDJjMjM4M2M3MzQwNSIKICB9CiBdCn0=`
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
