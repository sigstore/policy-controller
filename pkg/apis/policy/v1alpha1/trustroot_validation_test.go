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
	// IMPORTANT: The next expiration is on '2026-01-01T11:46:29Z'
	// Steps to generate:
	// 1. cgit clone github.com/sigstore/scaffolding
	// 2. run ./hack/setup-kind.sh
	// 3. export KO_DOCKER_REPO=registry.local:5001/sigstore
	// 4. run ./hack/setup-scaffolding.sh
	// 5. get the secrets from the kind cluster
	//    kubectl get secrets -o yaml -n tuf-system tuf-root
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI2LTAxLTAxVDExOjQ2OjI5WiIsCiAgImtleXMiOiB7CiAgICIwZjhjNWYzNmZiNDMwNzEyMmZiNzk3MGUyMjRiNGUwODY0ZjRhZmE0ZTRmNjM0YmU3Nzg4ZTllYmQ5ZjI2Nzg1IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIzMWQ1MzNiMDJlNTgyNGI1NDEwYmNmMjI4NGZlNzVkMmZiNjdhMTA4Y2I1ZTdkNjhmOTc1YzljOWM1ODYyYzVjIgogICAgfQogICB9LAogICAiOTE4MmI1ODVlNzFiOTVmMDA1YzIyZWNkYjQwN2QxMDY5YTlkMjdiOGMzZmFmMzBmMmUxZmM5NTRhNWFkOWNmNiI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiZTcxN2Y2NDY0YzMwYWFmMzVhOWE3MzgwY2M4NTkzNjRhNmMxNDgyOGRmNGE4MjJhNWRmYzA5ZTdjODJkMWIxZCIKICAgIH0KICAgfSwKICAgImU4YzZiMWQyMzA3NmYyOThhMTJjOTA4ZDlhODU3ZDFkZWU3MTI3NWQ1ZDdhNmVlOTQ2YTIzM2U4MzEwZjI3NmEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjU0Y2FlMzk2MzFjYmFiYmZmM2RlYjhmMzQ1ZjczMGU3ZmI3YjhkOGNlMTY3ZWZiOGNlMzg3YzQxMTIxOTg3ZjQiCiAgICB9CiAgIH0sCiAgICJmNWYzMTMzYjcwMzljYTMzZjk2ZDI5OTMzN2Q1ZTQyNWVhNzk4MzIyMDEzNjY5OWJlODhhZjU2NWU5NmIyZWVhIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJhNzliYWQ3MGE4OWJjNjQwODkzZThiMDM1ODQ4YmYyZTU2YWE4NWU1N2MwYzUwODVjNGEzZjVhNWMyZmUwNGYzIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiZThjNmIxZDIzMDc2ZjI5OGExMmM5MDhkOWE4NTdkMWRlZTcxMjc1ZDVkN2E2ZWU5NDZhMjMzZTgzMTBmMjc2YSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJmNWYzMTMzYjcwMzljYTMzZjk2ZDI5OTMzN2Q1ZTQyNWVhNzk4MzIyMDEzNjY5OWJlODhhZjU2NWU5NmIyZWVhIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiOTE4MmI1ODVlNzFiOTVmMDA1YzIyZWNkYjQwN2QxMDY5YTlkMjdiOGMzZmFmMzBmMmUxZmM5NTRhNWFkOWNmNiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiMGY4YzVmMzZmYjQzMDcxMjJmYjc5NzBlMjI0YjRlMDg2NGY0YWZhNGU0ZjYzNGJlNzc4OGU5ZWJkOWYyNjc4NSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICJlOGM2YjFkMjMwNzZmMjk4YTEyYzkwOGQ5YTg1N2QxZGVlNzEyNzVkNWQ3YTZlZTk0NmEyMzNlODMxMGYyNzZhIiwKICAgInNpZyI6ICI1MmM2YTkyNGFiZWYwMGY1YzY2NDE0OGIzMWRjMDRkOTVhNWE5ZjY1MjJlNTkwMDAyMzViNTAxNDUxYjRmYzc0MjEwZTVhY2NhOTRkZWIyZmNhNTgzZmM4ZTY4NDY0NTRiYTY2YzFhNzY4NWMxMDJhMDQ5N2JiMDNlMTEzYjIwMyIKICB9CiBdCn0=`
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
