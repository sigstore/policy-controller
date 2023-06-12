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
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDIzLTEyLTEyVDA4OjU4OjI4WiIsCiAgImtleXMiOiB7CiAgICI0OGZiNzRkODYyMThiZTM2MWM0NDJiNDZkOWQxZmEyOGM4ZjlmZTYzMjBmMzFkNWIyM2YxNGU1MDhmMzE4ZjZjIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJhZWZmZjY5YTg3MDRiOGU4NWI0YzI4ODljY2QwYzBjYTdkM2FhYTZiYjlkMDEyNDY3MDkzYzQ0YjBhYWZiMDI0IgogICAgfQogICB9LAogICAiYjIyNGJkNzNkYjcxMmFiNzk2MjJhZDU5YjY0ZTk4ZGU2YjUzM2ViZTlhYWQ2NTUyZTc3NjkxNzkxMWViNmVmMSI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiNGM2ZTNhZjFjNTEzZWM1NzhmZDk1MGIyODlhNmFiMzJlOGZkMmFjZGQ0ZGYzNjYxMDIwOTA5NGYxNjE4M2ZhNCIKICAgIH0KICAgfSwKICAgImQxNmZhYzQ1YjQ3ZTNlMjMxNzIxZDQ0NTQxYjJmMWY5OTk5YWZmODQxZTRlZTYzYTkwOGQ3NDcxYjI4MTFiODkiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjM1NjdjOTk1ZDBkZWI4NzAyYzA2NTFkYTU1OTE3NzU3YzNlZjI5ZGQ0MmNlNGQ5ZmY5MzU3YTMxNWFmMzM2NzMiCiAgICB9CiAgIH0sCiAgICJkOGFhOTdkNDk5ODk1MzNkMDE2NmE0YjRhMjdmYmU4YzVjMTRiOThiYjVkMDI1NThiODUwN2RiZDNmNTA5ZWU2IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJlNjg5NDkyM2EyY2M5MDA1MzU3OTA4NGQxNWIzMWFlNDBlNjBhMDRhODdiNzYxZjEzN2ZkMzRlOTY4MDAzNzNkIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiZDE2ZmFjNDViNDdlM2UyMzE3MjFkNDQ1NDFiMmYxZjk5OTlhZmY4NDFlNGVlNjNhOTA4ZDc0NzFiMjgxMWI4OSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJkOGFhOTdkNDk5ODk1MzNkMDE2NmE0YjRhMjdmYmU4YzVjMTRiOThiYjVkMDI1NThiODUwN2RiZDNmNTA5ZWU2IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiYjIyNGJkNzNkYjcxMmFiNzk2MjJhZDU5YjY0ZTk4ZGU2YjUzM2ViZTlhYWQ2NTUyZTc3NjkxNzkxMWViNmVmMSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiNDhmYjc0ZDg2MjE4YmUzNjFjNDQyYjQ2ZDlkMWZhMjhjOGY5ZmU2MzIwZjMxZDViMjNmMTRlNTA4ZjMxOGY2YyIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IGZhbHNlCiB9LAogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiZDE2ZmFjNDViNDdlM2UyMzE3MjFkNDQ1NDFiMmYxZjk5OTlhZmY4NDFlNGVlNjNhOTA4ZDc0NzFiMjgxMWI4OSIsCiAgICJzaWciOiAiNjBmMzI2ZDg3OGE1MzliMDc1NDVjNDZmMDI2Y2IxZDE0NTIxNWRhOWIzNmM1NzNjMWIzNGFlOGI3NGNlYWZiYjM1NDlmOTVmMjgyYjJmZjVhZmFiMjhmMTJjYWM2OTE0MDRjYzg5YmYwOTUyMWY2ODdiZmRkMzZmM2JkZjZlMDkiCiAgfQogXQp9`
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
