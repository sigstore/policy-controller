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

package v1beta1

import (
	"context"
	"strings"
	"testing"

	"github.com/sigstore/policy-controller/pkg/apis/signaturealgo"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/ptr"

	policycontrollerconfig "github.com/sigstore/policy-controller/pkg/config"
)

const validPublicKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaEOVJCFtduYr3xqTxeRWSW32CY/s\nTBNZj4oIUPl8JvhVPJ1TKDPlNcuT4YphSt6t3yOmMvkdQbCj8broX6vijw==\n-----END PUBLIC KEY-----"

const (
	signatureSHA512HashAlgorithm     = "sha512"
	signatureSHAInvalidHashAlgorithm = "shaInvalid"
)

func TestImagePatternValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		policy      ClusterImagePolicy
	}{{
		name:        "Should fail when glob is not present",
		errorString: "missing field(s): spec.authorities, spec.images[0].glob",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{},
				},
			},
		},
	}, {
		name:        "Glob should fail with invalid glob",
		errorString: "invalid value: [: spec.images[0].glob\nglob is invalid: syntax error in pattern\nmissing field(s): spec.authorities",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "[",
					},
				},
			},
		},
	}, {
		name:        "Glob should fail with invalid regexp",
		errorString: "invalid value: $FOO*: spec.images[0].glob\nglob is invalid: invalid glob \"$FOO*\"\nmissing field(s): spec.authorities",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "$FOO*",
					},
				},
			},
		},
	}, {
		name:        "missing image and authorities in the spec",
		errorString: "missing field(s): spec.authorities, spec.images",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{},
		},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testContext := policycontrollerconfig.ToContext(context.TODO(), &policycontrollerconfig.PolicyControllerConfig{NoMatchPolicy: policycontrollerconfig.AllowAll, FailOnEmptyAuthorities: true})

			err := test.policy.Validate(testContext)
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestKeyValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		policy      ClusterImagePolicy
	}{{
		name:        "Should fail when key has multiple properties",
		errorString: "expected exactly one, got both: spec.authorities[0].key.data, spec.authorities[0].key.kms, spec.authorities[0].key.secretref",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "myglob",
					},
				},
				Authorities: []Authority{
					{
						Key: &KeyRef{
							Data: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaEOVJCFtduYr3xqTxeRWSW32CY/s\nTBNZj4oIUPl8JvhVPJ1TKDPlNcuT4YphSt6t3yOmMvkdQbCj8broX6vijw==\n-----END PUBLIC KEY-----",
							KMS:  "hashivault://key/path",
						},
					},
				},
			},
		},
	}, {
		name:        "Should fail when key has malformed pubkey data",
		errorString: "invalid value: ---some key data----: spec.authorities[0].key.data",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "myglob",
					},
				},
				Authorities: []Authority{
					{
						Key: &KeyRef{
							Data: "---some key data----",
						},
					},
				},
			},
		},
	}, {
		name:        "Should fail when key is empty",
		errorString: "expected exactly one, got neither: spec.authorities[0].key.data, spec.authorities[0].key.kms, spec.authorities[0].key.secretref",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "myglob*",
					},
				},
				Authorities: []Authority{
					{
						Key: &KeyRef{},
					},
				},
			},
		},
	}, {
		name:        "Should fail with invalid AWS KMS for Keyful",
		errorString: "invalid value: awskms://localhost:8888/arn:butnotvalid: spec.authorities[0].key.kms\nkms key should be in the format awskms://[ENDPOINT]/[ID/ALIAS/ARN] (endpoint optional)",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key:     &KeyRef{KMS: "awskms://localhost:8888/arn:butnotvalid"},
						Sources: []Source{{OCI: "registry.example.com"}},
					},
				},
			},
		},
	}, {
		name:        "Should fail with invalid OCI value",
		errorString: "invalid value: registry.example.com/repo/*: spec.authorities[0].source[0].oci\nrepository can only contain the characters `abcdefghijklmnopqrstuvwxyz0123456789_-./`: repo/*",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key:     &KeyRef{KMS: "hashivault://key/path"},
						Sources: []Source{{OCI: "registry.example.com/repo/*"}},
					},
				},
			},
		},
	}, {
		name:        "Should fail with invalid OCI value usign wrong characters",
		errorString: "invalid value: re@gistry/reponame: spec.authorities[0].source[0].oci\nregistries must be valid RFC 3986 URI authorities: re@gistry/reponame",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key:     &KeyRef{KMS: "hashivault://key/path"},
						Sources: []Source{{OCI: "re@gistry/reponame"}},
					},
				},
			},
		},
	}, {
		name: "Should pass with valid OCI repository name",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key:     &KeyRef{KMS: "hashivault://key/path"},
						Sources: []Source{{OCI: "gcr.io/google.com/project/hello-world"}},
					},
				},
			},
		},
	}, {
		name: "Should pass with valid OCI repository name",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key:     &KeyRef{KMS: "hashivault://key/path"},
						Sources: []Source{{OCI: "registry.example.com/repository"}},
					},
				},
			},
		},
	}, {
		name: "Should pass when key has only one property: %v",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "yepanotherglob",
					},
				},
				Authorities: []Authority{
					{
						Key: &KeyRef{
							KMS: "hashivault://key/path",
						},
					},
				},
			},
		},
	}, {
		name: "Glob should pass with exact digest image",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "ghcr.io/foo@sha256:5504f2a95018e3d8a52d80d9e1a128c6ea337581808ff9fe96f5628ce2336350",
					},
				},
				Authorities: []Authority{
					{
						Key: &KeyRef{
							KMS: "hashivault://key/path",
						},
					},
				},
			},
		},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestKeylessValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		policy      ClusterImagePolicy
	}{{
		name:        "Should fail when keyless is empty",
		errorString: "expected exactly one, got neither: spec.authorities[0].keyless.ca-cert, spec.authorities[0].keyless.url\nmissing field(s): spec.authorities[0].keyless.identities",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{},
					},
				},
			},
		},
	}, {
		name:        "Should fail when keyless has multiple properties",
		errorString: "expected exactly one, got both: spec.authorities[0].keyless.ca-cert, spec.authorities[0].keyless.url\nmissing field(s): spec.authorities[0].keyless.identities",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},
							CACert: &KeyRef{
								Data: validPublicKey,
							},
						},
					},
				},
			},
		},
	}, {
		name:        "Should warn when valid keyless ref is specified, but no identities given",
		errorString: "missing field(s): spec.authorities[0].keyless.identities",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},
						},
					},
				},
			},
		},
	}, {
		name: "Should pass when valid keyless ref is specified",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},
							Identities: []Identity{
								{
									Subject: "somesubject",
									Issuer:  "someissuer",
								},
							},
						},
					},
				},
			},
		},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestStaticValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		policy      ClusterImagePolicy
	}{{
		name:        "Should fail when static is empty",
		errorString: "missing field(s): spec.authorities[0].static.action",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static: &StaticRef{},
					},
				},
			},
		},
	}, {
		name:        "Should fail when action is invalid",
		errorString: "invalid value: garbage: spec.authorities[0].static.action\nunsupported action",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static: &StaticRef{Action: "garbage"},
					},
				},
			},
		},
	}, {
		name: "Works with pass",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static: &StaticRef{Action: "pass"},
					},
				},
			},
		},
	}, {
		name: "Works with pass, and Spec.Policy.FetchConfigFile",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static: &StaticRef{Action: "pass"},
					},
				},
				Policy: &Policy{
					Type:            "cue",
					Data:            `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
					FetchConfigFile: ptr.Bool(true),
				},
			},
		},
	}, {
		name: "Works with pass, and Spec.Policy.IncludeSpec",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static: &StaticRef{Action: "pass"},
					},
				},
				Policy: &Policy{
					Type:        "cue",
					Data:        `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
					IncludeSpec: ptr.Bool(true),
				},
			},
		},
	}, {
		name: "Works with pass, and Spec.Policy.IncludeObjectMeta",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static: &StaticRef{Action: "pass"},
					},
				},
				Policy: &Policy{
					Type:              "cue",
					Data:              `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
					IncludeObjectMeta: ptr.Bool(true),
				},
			},
		},
	}, {
		name: "Works with pass, and Spec.Policy.IncludeTypeMeta",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static: &StaticRef{Action: "pass"},
					},
				},
				Policy: &Policy{
					Type:            "cue",
					Data:            `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
					IncludeTypeMeta: ptr.Bool(true),
				},
			},
		},
	}, {
		name: "Works with fail",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static: &StaticRef{Action: "fail"},
					},
				},
			},
		},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestModeValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		mode        string
	}{{
		name: "Should work when mode is empty",
		mode: "",
	}, {
		name: "Should work with mode enforce",
		mode: "enforce",
	}, {
		name: "Should work with mode warn",
		mode: "warn",
	}, {
		name:        "Should not work with mode garbage",
		mode:        "garbage",
		errorString: "invalid value: garbage: spec.mode\nunsupported mode",
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images:      []ImagePattern{{Glob: "globbityglob"}},
					Authorities: []Authority{{Static: &StaticRef{Action: "pass"}}},
					Mode:        test.mode,
				},
			}
			err := policy.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestAuthoritiesValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		policy      ClusterImagePolicy
	}{{
		name:        "Should fail when authority is empty",
		errorString: "expected exactly one, got neither: spec.authorities[0].key, spec.authorities[0].keyless, spec.authorities[0].rfc3161timestamp, spec.authorities[0].static",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{},
				},
			},
		},
	}, {
		name:        "Should fail when key/keyless specified",
		errorString: "expected exactly one, got both: spec.authorities[0].key, spec.authorities[0].keyless, spec.authorities[0].rfc3161timestamp, spec.authorities[0].static",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Key:     &KeyRef{Data: validPublicKey},
						Keyless: &KeylessRef{URL: apis.HTTPS("fulcio.sigstore.dev")},
					},
				},
			},
		},
	}, {
		name:        "Should fail when key/static specified",
		errorString: "expected exactly one, got both: spec.authorities[0].key, spec.authorities[0].keyless, spec.authorities[0].rfc3161timestamp, spec.authorities[0].static",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Key:    &KeyRef{Data: validPublicKey},
						Static: &StaticRef{Action: "pass"},
					},
				},
			},
		},
	}, {
		name:        "Should fail when keyless/static specified",
		errorString: "expected exactly one, got both: spec.authorities[0].key, spec.authorities[0].keyless, spec.authorities[0].rfc3161timestamp, spec.authorities[0].static",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static:  &StaticRef{Action: "fail"},
						Keyless: &KeylessRef{URL: apis.HTTPS("fulcio.sigstore.dev")},
					},
				},
			},
		},
	}, {
		name:        "Should fail when key/keyless/static specified",
		errorString: "expected exactly one, got both: spec.authorities[0].key, spec.authorities[0].keyless, spec.authorities[0].rfc3161timestamp, spec.authorities[0].static",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Key:     &KeyRef{Data: validPublicKey},
						Keyless: &KeylessRef{URL: apis.HTTPS("fulcio.sigstore.dev")},
						Static:  &StaticRef{Action: "fail"},
					},
				},
			},
		},
	}, {
		name:        "Should fail when static and sources,attestations, and ctlog is specified",
		errorString: "expected exactly one, got both: spec.authorities[0].attestations, spec.authorities[0].ctlog, spec.authorities[0].source, spec.authorities[0].static",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static:       &StaticRef{Action: "fail"},
						Attestations: []Attestation{{Name: "first", PredicateType: "vuln"}},
						Sources: []Source{
							{
								OCI: "registry1",
								SignaturePullSecrets: []v1.LocalObjectReference{
									{Name: "placeholder"},
								},
							},
						},
						CTLog: &TLog{},
					},
				},
			},
		},
	}, {
		name:        "Should fail with invalid kms prefix",
		errorString: "invalid value: fookms://localhost:8888/xpa:butnotvalid: spec.authorities[0].key.kms\nmalformed KMS format, should be prefixed by any of the supported providers: [awskms:// azurekms:// hashivault:// gcpkms://]",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key:     &KeyRef{KMS: "fookms://localhost:8888/xpa:butnotvalid"},
						Sources: []Source{{OCI: "registry.example.com"}},
					},
				},
			},
		},
	}, {
		name:        "Should fail when static and sources,attestations, and rfc3161timestamp is specified",
		errorString: "expected exactly one, got both: spec.authorities[0].key, spec.authorities[0].keyless, spec.authorities[0].rfc3161timestamp, spec.authorities[0].static",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Static:       &StaticRef{Action: "fail"},
						Attestations: []Attestation{{Name: "first", PredicateType: "vuln"}},
						Sources: []Source{
							{
								OCI: "registry1",
								SignaturePullSecrets: []v1.LocalObjectReference{
									{Name: "placeholder"},
								},
							},
						},
						RFC3161Timestamp: &RFC3161Timestamp{},
					},
				},
			},
		},
	}, {
		name:        "Should fail when authorities is empty",
		errorString: "missing field(s): spec.authorities",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{},
			},
		},
	}, {
		name: "Should pass when source oci is present",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{
						Key:     &KeyRef{KMS: "hashivault://key/path"},
						Sources: []Source{{OCI: "registry.example.com"}},
					},
				},
			},
		},
	}, {
		name: "Should pass with multiple source oci is present",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path"},
						Sources: []Source{
							{OCI: "registry1"},
							{OCI: "registry2"},
						},
					},
				},
			},
		},
	}, {
		name:        "Should fail with invalid AWS KMS for Keyful",
		errorString: "invalid value: awskms://localhost:8888/arn:butnotvalid: spec.authorities[0].key.kms\nkms key should be in the format awskms://[ENDPOINT]/[ID/ALIAS/ARN] (endpoint optional)",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key:     &KeyRef{KMS: "awskms://localhost:8888/arn:butnotvalid"},
						Sources: []Source{{OCI: "registry.example.com"}},
					},
				},
			},
		},
	}, {
		name:        "Should fail with invalid AWS KMS for Keyless",
		errorString: "invalid value: awskms://localhost:8888/arn:butnotvalid: spec.authorities[0].keyless.ca-cert.kms\nkms key should be in the format awskms://[ENDPOINT]/[ID/ALIAS/ARN] (endpoint optional)\nmissing field(s): spec.authorities[0].keyless.identities",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{CACert: &KeyRef{KMS: "awskms://localhost:8888/arn:butnotvalid"}},
					},
				},
			},
		},
	}, {
		name: "Should pass with attestations present",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path"},
						Attestations: []Attestation{
							{Name: "first", PredicateType: "vuln"},
							{Name: "second", PredicateType: "custom", Policy: &Policy{
								Type: "cue",
								Data: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
							},
							},
						},
					},
				},
			},
		},
	}, {
		name: "Should fail with attestations policy specifying fetchConfigFile",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path"},
						Attestations: []Attestation{
							{Name: "first", PredicateType: "vuln"},
							{Name: "second", PredicateType: "custom", Policy: &Policy{
								Type:            "cue",
								Data:            `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
								FetchConfigFile: ptr.Bool(true),
							},
							},
						},
					},
				},
			},
		},
		errorString: "must not set the field(s): spec.authorities[0].attestations.policy.fetchConfigFile",
	}, {
		name: "Should fail with attestations policy specifying includeSpec",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path"},
						Attestations: []Attestation{
							{Name: "first", PredicateType: "vuln"},
							{Name: "second", PredicateType: "custom", Policy: &Policy{
								Type:        "cue",
								Data:        `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
								IncludeSpec: ptr.Bool(true),
							},
							},
						},
					},
				},
			},
		},
		errorString: "must not set the field(s): spec.authorities[0].attestations.policy.includeSpec",
	}, {
		name: "Should fail with attestations policy specifying includeObjectMeta",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path"},
						Attestations: []Attestation{
							{Name: "first", PredicateType: "vuln"},
							{Name: "second", PredicateType: "custom", Policy: &Policy{
								Type:              "cue",
								Data:              `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
								IncludeObjectMeta: ptr.Bool(true),
							},
							},
						},
					},
				},
			},
		},
		errorString: "must not set the field(s): spec.authorities[0].attestations.policy.includeObjectMeta",
	}, {
		name: "Should fail with attestations policy specifying includeTypeMeta",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "gcr.io/*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path"},
						Attestations: []Attestation{
							{Name: "first", PredicateType: "vuln"},
							{Name: "second", PredicateType: "custom", Policy: &Policy{
								Type:            "cue",
								Data:            `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
								IncludeTypeMeta: ptr.Bool(true),
							},
							},
						},
					},
				},
			},
		},
		errorString: "must not set the field(s): spec.authorities[0].attestations.policy.includeTypeMeta",
	}, {
		name:        "Should fail with signaturePullSecret name empty",
		errorString: "missing field(s): spec.authorities[0].source[0].signaturePullSecrets[0].name",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path"},
						Sources: []Source{
							{
								OCI: "registry1",
								SignaturePullSecrets: []v1.LocalObjectReference{
									{Name: ""},
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "Should pass with signaturePullSecret name filled",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path"},
						Sources: []Source{
							{
								OCI: "registry1",
								SignaturePullSecrets: []v1.LocalObjectReference{
									{Name: "testPullSecrets"},
								},
							},
						},
					},
				},
			},
		},
	}, {
		name:        "Should fail with invalid signature hash algorithm",
		errorString: "invalid value: " + signatureSHAInvalidHashAlgorithm + ": spec.authorities[0].key.hashAlgorithm",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path", HashAlgorithm: signatureSHAInvalidHashAlgorithm},
					},
				},
			},
		},
	}, {
		name: "Should pass with sha256 signature hash algorithm",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path", HashAlgorithm: signaturealgo.DefaultSignatureAlgorithm},
						Sources: []Source{
							{
								OCI: "registry1",
								SignaturePullSecrets: []v1.LocalObjectReference{
									{Name: "testPullSecrets"},
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "Should pass with sha512 signature hash algorithm",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{
						Key: &KeyRef{KMS: "hashivault://key/path", HashAlgorithm: signatureSHA512HashAlgorithm},
						Sources: []Source{
							{
								OCI: "registry1",
								SignaturePullSecrets: []v1.LocalObjectReference{
									{Name: "testPullSecrets"},
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "Should pass when source oci is empty",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{
					{
						Key:     &KeyRef{KMS: "hashivault://key/path"},
						Sources: []Source{{OCI: ""}},
					},
				},
			},
		},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testContext := policycontrollerconfig.ToContext(context.TODO(), &policycontrollerconfig.PolicyControllerConfig{NoMatchPolicy: policycontrollerconfig.AllowAll, FailOnEmptyAuthorities: true})

			err := test.policy.Validate(testContext)
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestEmptyAuthoritiesValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		policy      ClusterImagePolicy
	}{{
		name: "Should pass when Authorities is empty",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images:      []ImagePattern{{Glob: "*"}},
				Authorities: []Authority{},
			},
		},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testContext := policycontrollerconfig.ToContext(context.TODO(), &policycontrollerconfig.PolicyControllerConfig{NoMatchPolicy: policycontrollerconfig.AllowAll, FailOnEmptyAuthorities: false})

			err := test.policy.Validate(testContext)
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestAttestationsValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		attestation Attestation
	}{{
		name:        "vuln",
		attestation: Attestation{Name: "first", PredicateType: "vuln"},
	}, {
		name:        "fully specified URL",
		attestation: Attestation{Name: "fullyspecified", PredicateType: "https://cyclonedx.org/schema"},
	}, {
		name:        "missing name",
		attestation: Attestation{PredicateType: "vuln"},
		errorString: "missing field(s): name",
	}, {
		name:        "missing predicatetype",
		attestation: Attestation{Name: "first"},
		errorString: "missing field(s): predicateType",
	}, {
		name:        "invalid predicatetype",
		attestation: Attestation{Name: "first", PredicateType: "notsupported"},
		errorString: "invalid value: notsupported: predicateType\nunsupported predicate type",
	}, {
		name: "custom with invalid policy type",
		attestation: Attestation{Name: "second", PredicateType: "custom",
			Policy: &Policy{
				Type: "not-cue",
				Data: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
			},
		},
		errorString: "invalid value: not-cue: policy.type\nonly [cue,rego] are supported at the moment",
	}, {
		name: "custom with missing policy data and configMapRef",
		attestation: Attestation{Name: "second", PredicateType: "custom",
			Policy: &Policy{
				Type: "cue",
			},
		},
		errorString: "missing field(s): policy.configMapRef, policy.data",
	}, {
		name: "custom with both policy data and configMapRef",
		attestation: Attestation{Name: "second", PredicateType: "custom",
			Policy: &Policy{
				Type: "cue",
				Data: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
				ConfigMapRef: &ConfigMapReference{
					Name: "cmname",
					Key:  "keyname",
				},
			},
		},
		errorString: "expected exactly one, got both: policy.configMapRef, policy.data",
	}, {
		name: "custom with invalid configMapRef, missing key",
		attestation: Attestation{Name: "second", PredicateType: "custom",
			Policy: &Policy{
				Type: "cue",
				ConfigMapRef: &ConfigMapReference{
					Name: "cmname",
				},
			},
		},
		errorString: "missing field(s): policy.configMapRef.key",
	}, {
		name: "custom with policy",
		attestation: Attestation{Name: "second", PredicateType: "custom",
			Policy: &Policy{
				Type: "cue",
				Data: `predicateType: "cosign.sigstore.dev/attestation/vuln/v1"`,
			},
		},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.attestation.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}
func TestIdentitiesValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		policy      ClusterImagePolicy
	}{{
		name: "Should pass with identities",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},
							Identities: []Identity{{SubjectRegExp: ".*subject.*", IssuerRegExp: ".*issuer.*"}},
						},
					},
				},
			},
		},
	}, {
		name:        "Should warn when identities fields are empty",
		errorString: "missing field(s): spec.authorities[0].keyless.identities[0].issuer, spec.authorities[0].keyless.identities[0].issuerRegExp, spec.authorities[0].keyless.identities[0].subject, spec.authorities[0].keyless.identities[0].subjectRegExp",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},
							Identities: []Identity{{Issuer: ""}},
						},
					},
				},
			},
		},
	}, {
		name:        "Should fail with both issuer and issuerRegExp",
		errorString: "expected exactly one, got both: spec.authorities[0].keyless.identities[0].issuer, spec.authorities[0].keyless.identities[0].issuerRegExp",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},

							Identities: []Identity{{Issuer: "issuer", IssuerRegExp: "issuerregexp", Subject: "subject"}},
						},
					},
				},
			},
		},
	}, {
		name:        "Should fail with both subject and subjectRegExp",
		errorString: "expected exactly one, got both: spec.authorities[0].keyless.identities[0].subject, spec.authorities[0].keyless.identities[0].subjectRegExp",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},

							Identities: []Identity{{Subject: "subject", SubjectRegExp: "subjectregexp", Issuer: "issuer"}},
						},
					},
				},
			},
		},
	}, {
		name:        "Should fail when issuer has invalid regex",
		errorString: "invalid value: ****: spec.authorities[0].keyless.identities[0].issuerRegExp\nregex is invalid: error parsing regexp: missing argument to repetition operator: `*`",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},

							Identities: []Identity{{IssuerRegExp: "****", Subject: "subject"}},
						},
					},
				},
			},
		},
	}, {
		name:        "Should warn when issuer or issuerRegExp is missing",
		errorString: "missing field(s): spec.authorities[0].keyless.identities[0].issuer, spec.authorities[0].keyless.identities[0].issuerRegExp",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},

							Identities: []Identity{{Subject: "subject"}},
						},
					},
				},
			},
		},
	}, {
		name:        "Should warn when subject or subjectRegExp is missing",
		errorString: "missing field(s): spec.authorities[0].keyless.identities[0].subject, spec.authorities[0].keyless.identities[0].subjectRegExp",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},

							Identities: []Identity{{Issuer: "issuer"}},
						},
					},
				},
			},
		},
	}, {
		name:        "Should fail when subject has invalid regex",
		errorString: "invalid value: ****: spec.authorities[0].keyless.identities[0].subjectRegExp\nregex is invalid: error parsing regexp: missing argument to repetition operator: `*`",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},

							Identities: []Identity{{Issuer: "issuer", SubjectRegExp: "****"}},
						},
					},
				},
			},
		},
	}, {
		name: "Should pass when subject and issuer have valid regex",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},

							Identities: []Identity{{SubjectRegExp: ".*subject.*", IssuerRegExp: ".*issuer.*"}},
						},
					},
				},
			},
		},
	}, {
		name: "Should pass when identities is valid",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},

							Identities: []Identity{
								{
									Issuer:  "some issuer",
									Subject: "some subject",
								},
							},
						},
					},
				},
			},
		},
	},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestAWSKMSValidation(t *testing.T) {
	// Note the error messages betweeen the kms / cacert validation is
	// identical, with the only difference being `kms` or `ca-cert.kms`. Reason
	// for the ca-cert.kms is because it's embedded within the ca-cert that
	// we pass in. So we put a KMSORCACERT into the err string that we then
	// replace based on the tests so we don't have to write identical tests
	// for both of them.
	tests := []struct {
		name        string
		errorString string
		kms         string
	}{{
		name:        "malformed, only 2 slashes ",
		errorString: "invalid value: awskms://1234abcd-12ab-34cd-56ef-1234567890ab: KMSORCACERT\nmalformed AWS KMS format 'awskms://$ENDPOINT/$KEYID', should be conformant with KMS standard documented here: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id",
		kms:         "awskms://1234abcd-12ab-34cd-56ef-1234567890ab",
	}, {
		name:        "fails with invalid host",
		errorString: "invalid value: awskms://localhost:::4566/alias/exampleAlias: KMSORCACERT\nmalformed endpoint: address localhost:::4566: too many colons in address",
		kms:         "awskms://localhost:::4566/alias/exampleAlias",
	}, {
		name:        "fails with non-arn alias",
		errorString: "invalid value: awskms://localhost:4566/alias/exampleAlias: KMSORCACERT\nfailed to parse either key or alias arn: arn: invalid prefix",
		kms:         "awskms://localhost:4566/alias/exampleAlias",
	}, {
		name:        "Should fail when arn is invalid",
		errorString: "invalid value: awskms://localhost:4566/arn:sonotvalid: KMSORCACERT\nkms key should be in the format awskms://[ENDPOINT]/[ID/ALIAS/ARN] (endpoint optional)",
		kms:         "awskms://localhost:4566/arn:sonotvalid",
	}, {
		name:        "Should fail with key is invalid",
		errorString: "invalid value: awskms://arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab: KMSORCACERT\nkms key should be in the format awskms://[ENDPOINT]/[ID/ALIAS/ARN] (endpoint optional)",
		kms:         "awskms://arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
	}, {
		name: "works with valid arn key and endpoint",
		kms:  "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
	}, {
		name: "works with valid arn key and no endpoint",
		kms:  "awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
	}, {
		name: "works with valid arn alias and endpoint",
		kms:  "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
	}, {
		name: "works with valid arn alias and no endpoint",
		kms:  "awskms:///arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
	},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// First test with KeyRef
			keyRef := KeyRef{KMS: test.kms}
			err := keyRef.Validate(context.TODO())
			kmsErrString := strings.Replace(test.errorString, "KMSORCACERT", "kms", 1)
			validateError(t, kmsErrString, "", err)
			// Then with Keyless with CACert as KeyRef
			keylessRef := KeylessRef{CACert: &keyRef, Identities: []Identity{{Subject: "testsubject", Issuer: "testIssuer"}}}
			err = keylessRef.Validate(context.TODO())
			caCertErrString := strings.Replace(test.errorString, "KMSORCACERT", "ca-cert.kms", 1)
			validateError(t, caCertErrString, "", err)
		})
	}
}

// validateError checks the given error against wanted error/warning strings
// if either is "" then it's assume an error/warning is not wanted and if
// one is given, will error.
// nolint since currently we do not have warnings we expect, but having this
// around makes it easier to add warning validations in the future.
//
//nolint:all
func validateError(t *testing.T, wantErrStr, wantWarnStr string, fe *apis.FieldError) {
	t.Helper()
	// Grab warning and check it first
	warnFE := fe.Filter(apis.WarningLevel)
	if wantWarnStr != "" {
		require.NotNil(t, warnFE)
		require.EqualError(t, warnFE, wantWarnStr)
	} else {
		require.Nil(t, warnFE)
	}

	// Then grab error and check it
	errFE := fe.Filter(apis.ErrorLevel)
	if wantErrStr != "" {
		require.NotNil(t, errFE)
		require.EqualError(t, errFE, wantErrStr)
	} else {
		require.Nil(t, errFE)
	}
}

func TestMatchValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorString string
		policy      ClusterImagePolicy
	}{{
		name: "Should pass with identities",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},
							Identities: []Identity{{SubjectRegExp: ".*subject.*", IssuerRegExp: ".*issuer.*"}},
						},
					},
				},
			},
		},
	}, {
		name: "Should pass with match label selector",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Match: []MatchResource{
					{
						GroupVersionResource: metav1.GroupVersionResource{
							Group:    "apps",
							Version:  "v1",
							Resource: "replicasets",
						},
						ResourceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"a": "b", "c": "d"},
						},
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},

							Identities: []Identity{
								{
									Issuer:  "some issuer",
									Subject: "some subject",
								},
							},
						},
					},
				},
			},
		},
	}, {
		name: "Should pass with match resource types",
		policy: ClusterImagePolicy{
			Spec: ClusterImagePolicySpec{
				Images: []ImagePattern{
					{
						Glob: "globbityglob",
					},
				},
				Match: []MatchResource{
					{
						GroupVersionResource: metav1.GroupVersionResource{
							Group:    "apps",
							Version:  "v1",
							Resource: "replicasets",
						},
					},
				},
				Authorities: []Authority{
					{
						Keyless: &KeylessRef{
							URL: &apis.URL{
								Host: "myhost",
							},
							InsecureIgnoreSCT: ptr.Bool(true),
							Identities: []Identity{
								{
									Issuer:  "some issuer",
									Subject: "some subject",
								},
							},
						},
					},
				},
			},
		},
	},
		{
			name:        "Should fail with invalid match resource type",
			errorString: "invalid value: myobject: spec.match[0].resource\nunsupported resource name",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Match: []MatchResource{
						{
							GroupVersionResource: metav1.GroupVersionResource{
								Group:    "",
								Version:  "v1",
								Resource: "myobject",
							},
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{
								URL: &apis.URL{
									Host: "myhost",
								},

								Identities: []Identity{
									{
										Issuer:  "some issuer",
										Subject: "some subject",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}
