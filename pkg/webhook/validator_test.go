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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/policy-controller/pkg/apis/config"
	policyduckv1beta1 "github.com/sigstore/policy-controller/pkg/apis/duck/v1beta1"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/apis/signaturealgo"
	policycontrollerconfig "github.com/sigstore/policy-controller/pkg/config"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/tuf"
	admissionv1 "k8s.io/api/admission/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	fakekube "knative.dev/pkg/client/injection/kube/client/fake"
	"knative.dev/pkg/ptr"
	rtesting "knative.dev/pkg/reconciler/testing"
	"knative.dev/pkg/system"
)

const (
	fulcioRootCert = "-----BEGIN CERTIFICATE-----\nMIICNzCCAd2gAwIBAgITPLBoBQhl1hqFND9S+SGWbfzaRTAKBggqhkjOPQQDAjBo\nMQswCQYDVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlw\ncGVuaGFtMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMI\ndGVzdGNlcnQwHhcNMjEwMzEyMjMyNDQ5WhcNMzEwMjI4MjMyNDQ5WjBoMQswCQYD\nVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlwcGVuaGFt\nMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMIdGVzdGNl\ncnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQRn+Alyof6xP3GQClSwgV0NFuY\nYEwmKP/WLWr/LwB6LUYzt5v49RlqG83KuaJSpeOj7G7MVABdpIZYWwqAiZV3o2Yw\nZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU\nT8Jwm6JuVb0dsiuHUROiHOOVHVkwHwYDVR0jBBgwFoAUT8Jwm6JuVb0dsiuHUROi\nHOOVHVkwCgYIKoZIzj0EAwIDSAAwRQIhAJkNZmP6sKA+8EebRXFkBa9DPjacBpTc\nOljJotvKidRhAiAuNrIazKEw2G4dw8x1z6EYk9G+7fJP5m93bjm/JfMBtA==\n-----END CERTIFICATE-----"
	rekorResponse  = "bad response"

	// Random public key (cosign generate-key-pair) 2022-03-18
	authorityKeyCosignPubString = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENAyijLvRu5QpCPp2uOj8C79ZW1VJ
SID/4H61ZiRzN4nqONzp+ZF22qQTk3MFO3D0/ZKmWHAosIf2pf2GHH7myA==
-----END PUBLIC KEY-----`

	certChain = `-----BEGIN CERTIFICATE-----
MIIBzDCCAXKgAwIBAgIUfyGKDoFa7y6s/W1p1CiTmBRs1eAwCgYIKoZIzj0EAwIw
MDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0
ZTAeFw0yMjExMDkyMDMxMzRaFw0zMTExMDkyMDM0MzRaMDAxDjAMBgNVBAoTBWxv
Y2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmcwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAR3KcDy9jwARX0rDvyr+MGGkG3n1OA0MU5+ZiDmgusFyk6U
6bovKWVMfD8J8NTcJZE0RaYJr8/dE9kgcIIXlhMwo2owaDAOBgNVHQ8BAf8EBAMC
B4AwHQYDVR0OBBYEFHNn5R3b3MtUdSNrFO49Q6XDVSnkMB8GA1UdIwQYMBaAFNLS
6gno7Om++Qt5zIa+H9o0HiT2MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqG
SM49BAMCA0gAMEUCIQCF0olohnvdUq6T7/wPk19Z5aQP/yxRTjCWYuhn/TCyHgIg
azV3air4GRZbN9bdYtcQ7JUAKq89GOhtFfl6kcoVUvU=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB0jCCAXigAwIBAgIUXpBmYJFFaGW3cC8p6b/DHr1i8IowCgYIKoZIzj0EAwIw
KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjIx
MTA5MjAyOTM0WhcNMzIxMTA5MjAzNDM0WjAwMQ4wDAYDVQQKEwVsb2NhbDEeMBwG
A1UEAxMVVGVzdCBUU0EgSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEKDPDRIwDS1ZCymub6yanCG5ma0qDjLpNonDvooSkRHEgU0TNibeJn6M+
5W608hCw8nwuucMbXQ41kNeuBeevyqN4MHYwDgYDVR0PAQH/BAQDAgEGMBMGA1Ud
JQQMMAoGCCsGAQUFBwMIMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNLS6gno
7Om++Qt5zIa+H9o0HiT2MB8GA1UdIwQYMBaAFB1nvXpNK7AuQlbJ+ya6nPSqWi+T
MAoGCCqGSM49BAMCA0gAMEUCIGiwqCI29w7C4V8TltCsi728s5DtklCPySDASUSu
a5y5AiEA40Ifdlwf7Uj8q8NSD6Z4g/0js0tGNdLSUJ1do/WoN0s=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBlDCCATqgAwIBAgIUYZx9sS14En7SuHDOJJP4IPopMjUwCgYIKoZIzj0EAwIw
KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjIx
MTA5MjAyOTM0WhcNMzIxMTA5MjAzNDM0WjAoMQ4wDAYDVQQKEwVsb2NhbDEWMBQG
A1UEAxMNVGVzdCBUU0EgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAbB
B0SU8G75hVIUphChA4nfOwNWP347TjScIdsEPrKVn+/Y1HmmLHJDjSfn+xhEFoEk
7jqgrqon48i4xbo7xAujQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBQdZ716TSuwLkJWyfsmupz0qlovkzAKBggqhkjOPQQDAgNI
ADBFAiBe5P56foqmFcZAVpEeAOFZrAlEiq05CCpMNYh5EjLvmAIhAKNF6xIV5uFd
pSTJsAwzjW78CKQm7qol0uPmPPu6mNaw
-----END CERTIFICATE-----
`

	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7D2WvgqSzs9jpdJsOJ5Nl6xg8JXm
Nmo7M3bN7+dQddw9Ibc2R3SV8tzBZw0rST8FKcn4apJepcKM4qUpYUeNfw==
-----END PUBLIC KEY-----
`
	// This is the Rekor LogID constructed from above public key.
	rekorLogID = "0bac0fddd0c15fbc46f8b1bf51c2b57676a9f262294fe13417d85602e73f392a"

	ctfePublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJvCJi707fv5tMJ1U2TVMZ+uO4dKG
aEcvjlCkgBCKXbrkumZV0m0dSlK1V1gxEiyQ8y6hk1MxJNe2AZrZUt7a4w==
-----END PUBLIC KEY-----
`
	// This is the LogID for above PublicKey
	ctfeLogID = "39d1c085f7d5f3fe7a0de9e52a3ead14186891e52a9269d90de7990a30b55083"
)

func TestValidatePodSpec(t *testing.T) {
	tag := name.MustParseReference("gcr.io/distroless/static:nonroot")
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	// Resolved via crane digest on 2022/09/29
	digestNewer := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:2a9e2b4fa771d31fe3346a873be845bfc2159695b9f90ca08e950497006ccc2e")

	ctx, _ := rtesting.SetupFakeContext(t)

	// Non-existent URL for testing complete failure
	badURL := apis.HTTP("http://example.com/")

	fulcioURL, err := apis.ParseURL("https://fulcio.sigstore.dev")
	if err != nil {
		t.Fatalf("Failed to parse fake Fulcio URL")
	}

	rekorServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(rekorResponse))
	}))
	t.Cleanup(rekorServer.Close)
	rekorURL, err := apis.ParseURL(rekorServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse fake Rekor URL")
	}

	var authorityKeyCosignPub *ecdsa.PublicKey

	pems := parsePems([]byte(authorityKeyCosignPubString))
	if len(pems) > 0 {
		key, _ := x509.ParsePKIXPublicKey(pems[0].Bytes)
		authorityKeyCosignPub = key.(*ecdsa.PublicKey)
	} else {
		t.Errorf("Error parsing authority key from string")
	}

	kc := fakekube.Get(ctx)
	// Setup service acc and fakeSignaturePullSecrets for "default" and "cosign-system" namespace
	for _, ns := range []string{"default", system.Namespace()} {
		kc.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}, metav1.CreateOptions{})

		kc.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "fakeSignaturePullSecrets",
			},
			Data: map[string][]byte{
				"dockerconfigjson": []byte(`{"auths":{"https://index.docker.io/v1/":{"username":"username","password":"password","auth":"dXNlcm5hbWU6cGFzc3dvcmQ="}}`),
			},
		}, metav1.CreateOptions{})
	}

	v := NewValidator(ctx)

	cvs := cosignVerifySignatures
	defer func() {
		cosignVerifySignatures = cvs
	}()
	// Let's just say that everything is verified.
	pass := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		sig, err := static.NewSignature(nil, "")
		if err != nil {
			return nil, false, err
		}
		return []oci.Signature{sig}, true, nil
	}
	// Let's just say that everything is not verified.
	fail := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		return nil, false, errors.New("bad signature")
	}

	// Let's say it is verified if it is the expected Public Key
	authorityPublicKeyCVS := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		actualPublicKey, _ := co.SigVerifier.PublicKey()
		actualECDSAPubkey := actualPublicKey.(*ecdsa.PublicKey)
		actualKeyData := elliptic.Marshal(actualECDSAPubkey, actualECDSAPubkey.X, actualECDSAPubkey.Y)

		expectedKeyData := elliptic.Marshal(authorityKeyCosignPub, authorityKeyCosignPub.X, authorityKeyCosignPub.Y)

		if bytes.Equal(actualKeyData, expectedKeyData) {
			return pass(ctx, signedImgRef, co)
		}

		return fail(ctx, signedImgRef, co)
	}

	tests := []struct {
		name          string
		ps            *corev1.PodSpec
		want          *apis.FieldError
		cvs           func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
		customContext context.Context
	}{{
		name: "simple, no error",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		cvs: pass,
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:              authorityKeyCosignPubString,
										PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
										HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
										HashAlgorithmCode: crypto.SHA256,
									},
								},
							},
						},
					},
				},
			},
		),
	}, {
		name: "bad reference",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: "in@valid",
			}},
		},
		want: &apis.FieldError{
			Message: `could not parse reference: in@valid`,
			Paths:   []string{"containers[0].image"},
		},
		cvs: fail,
	}, {
		name: "not digest",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		want: &apis.FieldError{
			Message: `invalid value: gcr.io/distroless/static:nonroot must be an image digest`,
			Paths:   []string{"containers[0].image"},
		},
		cvs: fail,
	}, {
		name: "simple, no error, authority key",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:              authorityKeyCosignPubString,
										PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
										HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
										HashAlgorithmCode: crypto.SHA256,
									},
								},
							},
						},
					},
				},
			},
		),
		cvs: authorityPublicKeyCVS,
	}, {
		name: "simple, error, authority keyless, bad fulcio",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: badURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe.Details = fmt.Sprintf("%s %s", digest.String(), `signature keyless validation failed for authority  for gcr.io/distroless/static@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4: bad signature`)
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe2.Details = fe.Details
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: fail,
	}, {
		name: "simple, error, authority keyless, good fulcio, no rekor",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: fail,
	}, {
		name: "simple, authority keyless checks out, good fulcio, bad cip policy",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless-bad-cip": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
								},
							},
							Policy: &webhookcip.AttestationPolicy{
								Name: "invalid json policy",
								Type: "cue",
								Data: `{"wontgo`,
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless-bad-cip", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s failed evaluating cue policy for ClusterImagePolicy: failed to compile the cue policy with error: string literal not terminated", digest.String())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless-bad-cip", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s failed evaluating cue policy for ClusterImagePolicy: failed to compile the cue policy with error: string literal not terminated", digest.String())
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: pass,
	}, {
		name: "simple, no error, authority keyless, good fulcio",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
								},
							},
						},
					},
				},
			},
		),
		cvs: pass,
	}, {
		name: "simple, error, authority keyless, good fulcio, bad rekor",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
									CTLog: &v1alpha1.TLog{
										URL: rekorURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: fail,
	}, {
		name: "simple with 2 containers, error, authority keyless, good fulcio, bad rekor",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}, {
				Name:  "user-container-2",
				Image: digestNewer.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
									CTLog: &v1alpha1.TLog{
										URL: rekorURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe2)
			fe3 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 1)
			fe3.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digestNewer.String(), digestNewer.Name())
			errs = errs.Also(fe3)
			return errs
		}(),
		cvs: fail,
	}, {
		name: "simple, no error, authority source signaturePullSecrets, non existing secret",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(ctx,
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:              authorityKeyCosignPubString,
										PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
										HashAlgorithmCode: crypto.SHA256,
										HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
									},
									Sources: []v1alpha1.Source{{
										OCI: "example.com/alternative/signature",
										SignaturePullSecrets: []corev1.LocalObjectReference{{
											Name: "non-existing-secret",
										}},
									}},
								},
							},
						},
					},
				},
			},
		),
		cvs: pass,
	}, {
		name: "simple, no error, authority source signaturePullSecrets, valid secret",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}, {
				Name:  "user-container-2",
				Image: digestNewer.String(),
			}},
		},
		customContext: config.ToContext(ctx,
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:              authorityKeyCosignPubString,
										PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
										HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
										HashAlgorithmCode: crypto.SHA256,
									},
									Sources: []v1alpha1.Source{{
										OCI: "example.com/alternative/signature",
										SignaturePullSecrets: []corev1.LocalObjectReference{{
											Name: "fakeSignaturePullSecrets",
										}},
									}},
								},
							},
						},
					},
				},
			},
		),
		cvs: authorityPublicKeyCVS,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"", "enforce", "warn"} {
				cosignVerifySignatures = test.cvs
				testContext := context.Background()
				// By default we want errors. However, iff the mode above is
				// warn, and we're using a custom context and therefore
				// triggering the CIP.mode twiddling below, check for warnings.
				wantWarn := false
				if test.customContext != nil {
					if mode == "warn" {
						wantWarn = true
					}
					// If we are testing with custom context, loop through
					// all the modes here. It's a bit silly that we spin through
					// all the tests 3 times, but for now this is better than
					// duplicating all the CIPs with just different modes.
					testContext = test.customContext

					// Twiddle the mode for tests.
					cfg := config.FromContext(testContext)
					newPolicies := make(map[string]webhookcip.ClusterImagePolicy, len(cfg.ImagePolicyConfig.Policies))
					for k, v := range cfg.ImagePolicyConfig.Policies {
						v.Mode = mode
						newPolicies[k] = v
					}
					cfg.ImagePolicyConfig.Policies = newPolicies
					config.ToContext(testContext, cfg)
				}

				testContext = context.WithValue(testContext, kubeclient.Key{}, kc)

				// Check the core mechanics
				got := v.validatePodSpec(testContext, system.Namespace(), "Pod", "v1", map[string]string{}, test.ps, k8schain.Options{})
				if (got != nil) != (test.want != nil) {
					t.Errorf("validatePodSpec() = %v, wanted %v", got, test.want)
				} else if got != nil && got.Error() != test.want.Error() {
					t.Errorf("validatePodSpec() = %v, wanted %v", got, test.want)
				}

				if test.want != nil {
					if wantWarn {
						test.want.Level = apis.WarningLevel
					} else {
						test.want.Level = apis.ErrorLevel
					}
				}
				// Check wrapped in a Pod
				pod := &duckv1.Pod{
					Spec: *test.ps,
				}
				got = v.ValidatePod(testContext, pod)
				want := test.want.ViaField("spec")
				if (got != nil) != (want != nil) {
					t.Errorf("ValidatePod() = %v, wanted %v", got, want)
				} else if got != nil && got.Error() != want.Error() {
					t.Errorf("ValidatePod() = %v, wanted %v", got, want)
				}
				// Check the warning/error level.
				if got != nil && test.want != nil {
					if got.Level != want.Level {
						t.Errorf("ValidatePod() Wrong Level = %v, wanted %v", got.Level, want.Level)
					}
				}
				// Check that we don't block things being deleted.
				if got := v.ValidatePod(apis.WithinDelete(testContext), pod); got != nil {
					t.Errorf("ValidatePod() = %v, wanted nil", got)
				}

				// Check wrapped in a WithPod
				withPod := &duckv1.WithPod{
					Spec: duckv1.WithPodSpec{
						Template: duckv1.PodSpecable{
							Spec: *test.ps,
						},
					},
				}
				got = v.ValidatePodSpecable(testContext, withPod)
				want = test.want.ViaField("spec.template.spec")
				if (got != nil) != (want != nil) {
					t.Errorf("ValidatePodSpecable() = %v, wanted %v", got, want)
				} else if got != nil && got.Error() != want.Error() {
					t.Errorf("ValidatePodSpecable() = %v, wanted %v", got, want)
				}
				// Check the warning/error level.
				if got != nil && test.want != nil {
					if got.Level != want.Level {
						t.Errorf("ValidatePodSpecable() Wrong Level = %v, wanted %v", got.Level, want.Level)
					}
				}

				// Check that we don't block things being deleted.
				if got := v.ValidatePodSpecable(apis.WithinDelete(testContext), withPod); got != nil {
					t.Errorf("ValidatePodSpecable() = %v, wanted nil", got)
				}

				// Check wrapped in a podScalable
				podScalable := &policyduckv1beta1.PodScalable{
					Spec: policyduckv1beta1.PodScalableSpec{
						Replicas: ptr.Int32(3),
						Template: corev1.PodTemplateSpec{
							Spec: *test.ps,
						},
					},
				}
				got = v.ValidatePodScalable(testContext, podScalable)
				want = test.want.ViaField("spec.template.spec")
				if (got != nil) != (want != nil) {
					t.Errorf("ValidatePodScalable() = %v, wanted %v", got, want)
				} else if got != nil && got.Error() != want.Error() {
					t.Errorf("ValidatePodScalable() = %v, wanted %v", got, want)
				}
				// Check the warning/error level.
				if got != nil && test.want != nil {
					if got.Level != want.Level {
						t.Errorf("ValidatePodScalable() Wrong Level = %v, wanted %v", got.Level, want.Level)
					}
				}

				// Check that we don't block things being deleted.
				if got := v.ValidatePodScalable(apis.WithinDelete(testContext), podScalable); got != nil {
					t.Errorf("ValidatePodSpecable() = %v, wanted nil", got)
				}

				// Check that we don't block things being scaled down.
				original := podScalable.DeepCopy()
				original.Spec.Replicas = ptr.Int32(4)
				if got := v.ValidatePodScalable(apis.WithinUpdate(testContext, original), podScalable); got != nil {
					t.Errorf("ValidatePodSpecable() scaling down = %v, wanted nil", got)
				}

				// Check that we fail as expected if being scaled up.
				original.Spec.Replicas = ptr.Int32(2)
				got = v.ValidatePodScalable(apis.WithinUpdate(testContext, original), podScalable)
				want = test.want.ViaField("spec.template.spec")
				if (got != nil) != (want != nil) {
					t.Errorf("ValidatePodScalable() scaling up = %v, wanted %v", got, want)
				} else if got != nil && got.Error() != want.Error() {
					t.Errorf("ValidatePodScalable() scaling up = %v, wanted %v", got, want)
				}
				// Check the warning/error level.
				if got != nil && test.want != nil {
					if got.Level != want.Level {
						t.Errorf("ValidatePodScalable() scaling up Wrong Level = %v, wanted %v", got.Level, want.Level)
					}
				}
			}
		})
	}
}

func TestValidateCronJob(t *testing.T) {
	tag := name.MustParseReference("gcr.io/distroless/static:nonroot")
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	ctx, _ := rtesting.SetupFakeContext(t)

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx)

	cvs := cosignVerifySignatures
	defer func() {
		cosignVerifySignatures = cvs
	}()
	// Let's just say that everything is verified.
	/*pass := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		sig, err := static.NewSignature(nil, "")
		if err != nil {
			return nil, false, err
		}
		return []oci.Signature{sig}, true, nil
	}*/
	// Let's just say that everything is not verified.
	fail := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		return nil, false, errors.New("bad signature")
	}

	tests := []struct {
		name string
		c    *duckv1.CronJob
		want *apis.FieldError
		cvs  func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
	}{{
		name: "k8schain ignore (bad service account)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ServiceAccountName: "not-found",
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: digest.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: digest.String(),
								}},
							},
						},
					},
				},
			},
		},
	}, {
		name: "k8schain ignore (bad pull secret)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								ImagePullSecrets: []corev1.LocalObjectReference{{
									Name: "not-found",
								}},
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: digest.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: digest.String(),
								}},
							},
						},
					},
				},
			},
		},
	}, {
		name: "bad reference",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		want: &apis.FieldError{
			Message: `could not parse reference: in@valid`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec.containers[0].image"},
		},
		cvs: fail,
	}, {
		name: "not digest",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: tag.String(),
								}},
							},
						},
					},
				},
			},
		},
		want: &apis.FieldError{
			Message: `invalid value: gcr.io/distroless/static:nonroot must be an image digest`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec.containers[0].image"},
		},
		cvs: fail,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cosignVerifySignatures = test.cvs

			testContext := context.WithValue(context.Background(), kubeclient.Key{}, kc)

			// Check the core mechanics
			got := v.ValidateCronJob(testContext, test.c)
			if (got != nil) != (test.want != nil) {
				t.Errorf("validateCronJob() = %v, wanted %v", got, test.want)
			} else if got != nil && got.Error() != test.want.Error() {
				t.Errorf("validateCronJob() = %v, wanted %v", got, test.want)
			}
			// Check that we don't block things being deleted.
			cronJob := test.c.DeepCopy()
			if got := v.ValidateCronJob(apis.WithinDelete(testContext), cronJob); got != nil {
				t.Errorf("ValidateCronJob() = %v, wanted nil", got)
			}
			// Check that we don't block things already deleted.
			cronJob = test.c.DeepCopy()
			cronJob.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			if got := v.ValidateCronJob(context.Background(), cronJob); got != nil {
				t.Errorf("ValidateCronJob() = %v, wanted nil", got)
			}
		})
	}
}

func TestResolvePodSpec(t *testing.T) {
	tag := name.MustParseReference("gcr.io/distroless/static:nonroot")
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	ctx, _ := rtesting.SetupFakeContext(t)

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx)

	rrd := remoteResolveDigest
	defer func() {
		remoteResolveDigest = rrd
	}()
	resolve := func(ref name.Reference, opts ...remote.Option) (name.Digest, error) {
		return digest.(name.Digest), nil
	}

	tests := []struct {
		name string
		ps   *corev1.PodSpec
		want *corev1.PodSpec
		wc   func(context.Context) context.Context
		rrd  func(name.Reference, ...remote.Option) (name.Digest, error)
	}{{
		name: "nothing changed (not the right update)",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: tag.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		want: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: tag.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		rrd: resolve,
	}, {
		name: "nothing changed (bad reference)",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: "in@valid",
			}},
		},
		want: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: "in@valid",
			}},
		},
		wc:  apis.WithinCreate,
		rrd: resolve,
	}, {
		name: "nothing changed (unable to resolve)",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		want: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		wc: apis.WithinCreate,
		rrd: func(r name.Reference, o ...remote.Option) (name.Digest, error) {
			return name.Digest{}, errors.New("boom")
		},
	}, {
		name: "digests resolve (in create)",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: tag.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		want: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		wc:  apis.WithinCreate,
		rrd: resolve,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remoteResolveDigest = test.rrd
			ctx := context.Background()
			if test.wc != nil {
				ctx = test.wc(context.Background())
			}

			ctx = context.WithValue(ctx, kubeclient.Key{}, kc)

			// Check the core mechanics.
			got := test.ps.DeepCopy()
			v.resolvePodSpec(ctx, got, k8schain.Options{})
			if !cmp.Equal(got, test.want) {
				t.Errorf("resolvePodSpec = %s", cmp.Diff(got, test.want))
			}

			var want runtime.Object

			// Check wrapped in a Pod
			pod := &duckv1.Pod{Spec: *test.ps.DeepCopy()}
			want = &duckv1.Pod{Spec: *test.want.DeepCopy()}
			v.ResolvePod(ctx, pod)
			if !cmp.Equal(pod, want) {
				t.Errorf("ResolvePod = %s", cmp.Diff(pod, want))
			}

			// Check that nothing happens when it's being deleted.
			pod = &duckv1.Pod{Spec: *test.ps.DeepCopy()}
			want = pod.DeepCopy()
			v.ResolvePod(apis.WithinDelete(ctx), pod)
			if !cmp.Equal(pod, want) {
				t.Errorf("ResolvePod = %s", cmp.Diff(pod, want))
			}

			// Check that nothing happens when it's already deleted.
			pod = &duckv1.Pod{Spec: *test.ps.DeepCopy()}
			pod.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			want = pod.DeepCopy()
			v.ResolvePod(ctx, pod)
			if !cmp.Equal(pod, want) {
				t.Errorf("ResolvePod = %s", cmp.Diff(pod, want))
			}

			// Check wrapped in a WithPod
			withPod := &duckv1.WithPod{
				Spec: duckv1.WithPodSpec{
					Template: duckv1.PodSpecable{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}
			want = &duckv1.WithPod{
				Spec: duckv1.WithPodSpec{
					Template: duckv1.PodSpecable{
						Spec: *test.want.DeepCopy(),
					},
				},
			}
			v.ResolvePodSpecable(ctx, withPod)
			if !cmp.Equal(withPod, want) {
				t.Errorf("ResolvePodSpecable = %s", cmp.Diff(withPod, want))
			}

			// Check that nothing happens when it's being deleted.
			withPod = &duckv1.WithPod{
				Spec: duckv1.WithPodSpec{
					Template: duckv1.PodSpecable{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}
			want = withPod.DeepCopy()
			v.ResolvePodSpecable(apis.WithinDelete(ctx), withPod)
			if !cmp.Equal(withPod, want) {
				t.Errorf("ResolvePodSpecable = %s", cmp.Diff(withPod, want))
			}

			// Check that nothing happens when it's already deleted.
			withPod = &duckv1.WithPod{
				Spec: duckv1.WithPodSpec{
					Template: duckv1.PodSpecable{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}
			withPod.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			want = withPod.DeepCopy()
			v.ResolvePodSpecable(ctx, withPod)
			if !cmp.Equal(withPod, want) {
				t.Errorf("ResolvePodSpecable = %s", cmp.Diff(withPod, want))
			}

			// Check wrapped in a PodScalable
			podScalable := &policyduckv1beta1.PodScalable{
				Spec: policyduckv1beta1.PodScalableSpec{
					Replicas: ptr.Int32(3),
					Template: corev1.PodTemplateSpec{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}
			want = &policyduckv1beta1.PodScalable{
				Spec: policyduckv1beta1.PodScalableSpec{
					Replicas: ptr.Int32(3),
					Template: corev1.PodTemplateSpec{
						Spec: *test.want.DeepCopy(),
					},
				},
			}
			v.ResolvePodScalable(ctx, podScalable)
			if !cmp.Equal(podScalable, want) {
				t.Errorf("ResolvePodSpecable = %s", cmp.Diff(podScalable, want))
			}

			// Check that nothing happens when it's being deleted.
			podScalable = &policyduckv1beta1.PodScalable{
				Spec: policyduckv1beta1.PodScalableSpec{
					Replicas: ptr.Int32(2),
					Template: corev1.PodTemplateSpec{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}
			want = podScalable.DeepCopy()
			v.ResolvePodScalable(apis.WithinDelete(ctx), podScalable)
			if !cmp.Equal(podScalable, want) {
				t.Errorf("ResolvePodSpecable = %s", cmp.Diff(podScalable, want))
			}

			// Check that nothing happens when it's already deleted.
			podScalable = &policyduckv1beta1.PodScalable{
				Spec: policyduckv1beta1.PodScalableSpec{
					Replicas: ptr.Int32(2),
					Template: corev1.PodTemplateSpec{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}
			podScalable.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			want = podScalable.DeepCopy()
			v.ResolvePodScalable(ctx, podScalable)
			if !cmp.Equal(podScalable, want) {
				t.Errorf("ResolvePodSpecable = %s", cmp.Diff(podScalable, want))
			}

			// Check that nothing happens when it's being scaled down.
			podScalable = &policyduckv1beta1.PodScalable{
				Spec: policyduckv1beta1.PodScalableSpec{
					Replicas: ptr.Int32(2),
					Template: corev1.PodTemplateSpec{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}
			want = podScalable.DeepCopy()
			original := &policyduckv1beta1.PodScalable{
				Spec: policyduckv1beta1.PodScalableSpec{
					Replicas: ptr.Int32(3),
					Template: corev1.PodTemplateSpec{
						Spec: *test.ps.DeepCopy(),
					},
				},
			}

			v.ResolvePodScalable(apis.WithinUpdate(ctx, original), podScalable)
			if !cmp.Equal(podScalable, want) {
				t.Errorf("ResolvePodSpecable = %s", cmp.Diff(podScalable, want))
			}
		})
	}
}

func TestResolveCronJob(t *testing.T) {
	tag := name.MustParseReference("gcr.io/distroless/static:nonroot")
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	ctx, _ := rtesting.SetupFakeContext(t)

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx)

	rrd := remoteResolveDigest
	defer func() {
		remoteResolveDigest = rrd
	}()
	resolve := func(ref name.Reference, opts ...remote.Option) (name.Digest, error) {
		return digest.(name.Digest), nil
	}

	tests := []struct {
		name string
		c    *duckv1.CronJob
		want *duckv1.CronJob
		wc   func(context.Context) context.Context
		rrd  func(name.Reference, ...remote.Option) (name.Digest, error)
	}{{
		name: "nothing changed (not the right update)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: tag.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: tag.String(),
								}},
							},
						},
					},
				},
			},
		},
		want: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: tag.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: tag.String(),
								}},
							},
						},
					},
				},
			},
		},
		rrd: resolve,
	}, {
		name: "nothing changed (bad reference)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		want: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		wc:  apis.WithinCreate,
		rrd: resolve,
	}, {
		name: "nothing changed (unable to resolve)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		want: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: "in@valid",
								}},
							},
						},
					},
				},
			},
		},
		wc: apis.WithinCreate,
		rrd: func(r name.Reference, o ...remote.Option) (name.Digest, error) {
			return name.Digest{}, errors.New("boom")
		},
	}, {
		name: "digests resolve (in create)",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: tag.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: tag.String(),
								}},
							},
						},
					},
				},
			},
		},
		want: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								InitContainers: []corev1.Container{{
									Name:  "setup-stuff",
									Image: digest.String(),
								}},
								Containers: []corev1.Container{{
									Name:  "user-container",
									Image: digest.String(),
								}},
							},
						},
					},
				},
			},
		},
		wc:  apis.WithinCreate,
		rrd: resolve,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remoteResolveDigest = test.rrd
			ctx := context.Background()
			if test.wc != nil {
				ctx = test.wc(context.Background())
			}

			ctx = context.WithValue(ctx, kubeclient.Key{}, kc)

			var want runtime.Object

			cronJob := test.c.DeepCopy()
			want = test.want.DeepCopy()
			v.ResolveCronJob(ctx, cronJob)
			if !cmp.Equal(cronJob, want) {
				t.Errorf("ResolveCronJob = %s", cmp.Diff(cronJob, want))
			}

			// Check that nothing happens when it's being deleted.
			cronJob = test.c.DeepCopy()
			want = cronJob.DeepCopy()
			v.ResolveCronJob(apis.WithinDelete(ctx), cronJob)
			if !cmp.Equal(cronJob, want) {
				t.Errorf("ResolveCronJob = %s", cmp.Diff(cronJob, want))
			}
		})
	}
}

func TestValidatePolicy(t *testing.T) {
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	// Non-existent URL for testing complete failure
	badURL := apis.HTTP("http://example.com/")
	t.Logf("badURL: %s", badURL.String())

	// Spin up a Fulcio that responds with a Root Cert
	fulcioServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(fulcioRootCert))
	}))
	t.Cleanup(fulcioServer.Close)

	fulcioURL, err := apis.ParseURL("https://fulcio.sigstore.dev")
	if err != nil {
		t.Fatalf("Failed to parse fake Fulcio URL")
	}

	rekorServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(rekorResponse))
	}))
	t.Cleanup(rekorServer.Close)
	rekorURL, err := apis.ParseURL(rekorServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse fake Rekor URL")
	}
	t.Logf("rekorURL: %s", rekorURL.String())
	var authorityKeyCosignPub *ecdsa.PublicKey

	pems := parsePems([]byte(authorityKeyCosignPubString))
	if len(pems) > 0 {
		key, _ := x509.ParsePKIXPublicKey(pems[0].Bytes)
		authorityKeyCosignPub = key.(*ecdsa.PublicKey)
	} else {
		t.Errorf("Error parsing authority key from string")
	}

	cvs := cosignVerifySignatures
	defer func() {
		cosignVerifySignatures = cvs
	}()
	// Let's just say that everything is verified.
	pass := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		sig, err := static.NewSignature(nil, "")
		if err != nil {
			return nil, false, err
		}
		return []oci.Signature{sig}, true, nil
	}
	// Let's just say that everything is verified.
	passKeyless := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		// This is from 2022/07/29
		// ghcr.io/distroless/static@sha256:a1e82f6a5f6dfc735165d3442e7cc5a615f72abac3db19452481f5f3c90fbfa8
		payload := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2Nvc2lnbi5zaWdzdG9yZS5kZXYvYXR0ZXN0YXRpb24vdnVsbi92MSIsInN1YmplY3QiOlt7Im5hbWUiOiJnaGNyLmlvL2Rpc3Ryb2xlc3Mvc3RhdGljIiwiZGlnZXN0Ijp7InNoYTI1NiI6ImExZTgyZjZhNWY2ZGZjNzM1MTY1ZDM0NDJlN2NjNWE2MTVmNzJhYmFjM2RiMTk0NTI0ODFmNWYzYzkwZmJmYTgifX1dLCJwcmVkaWNhdGUiOnsiaW52b2NhdGlvbiI6eyJwYXJhbWV0ZXJzIjpudWxsLCJ1cmkiOiJodHRwczovL2dpdGh1Yi5jb20vZGlzdHJvbGVzcy9zdGF0aWMvYWN0aW9ucy9ydW5zLzI3NTc5NTMxMzkiLCJldmVudF9pZCI6IjI3NTc5NTMxMzkiLCJidWlsZGVyLmlkIjoiQ3JlYXRlIFJlbGVhc2UifSwic2Nhbm5lciI6eyJ1cmkiOiJodHRwczovL2dpdGh1Yi5jb20vYXF1YXNlY3VyaXR5L3RyaXZ5IiwidmVyc2lvbiI6IjAuMjkuMiIsImRiIjp7InVyaSI6IiIsInZlcnNpb24iOiIifSwicmVzdWx0Ijp7IiRzY2hlbWEiOiJodHRwczovL2pzb24uc2NoZW1hc3RvcmUub3JnL3NhcmlmLTIuMS4wLXJ0bS41Lmpzb24iLCJydW5zIjpbeyJjb2x1bW5LaW5kIjoidXRmMTZDb2RlVW5pdHMiLCJvcmlnaW5hbFVyaUJhc2VJZHMiOnsiUk9PVFBBVEgiOnsidXJpIjoiZmlsZTovLy8ifX0sInJlc3VsdHMiOltdLCJ0b29sIjp7ImRyaXZlciI6eyJmdWxsTmFtZSI6IlRyaXZ5IFZ1bG5lcmFiaWxpdHkgU2Nhbm5lciIsImluZm9ybWF0aW9uVXJpIjoiaHR0cHM6Ly9naXRodWIuY29tL2FxdWFzZWN1cml0eS90cml2eSIsIm5hbWUiOiJUcml2eSIsInJ1bGVzIjpbXSwidmVyc2lvbiI6IjAuMjkuMiJ9fX1dLCJ2ZXJzaW9uIjoiMi4xLjAifX0sIm1ldGFkYXRhIjp7InNjYW5TdGFydGVkT24iOiIyMDIyLTA3LTI5VDAyOjI4OjQyWiIsInNjYW5GaW5pc2hlZE9uIjoiMjAyMi0wNy0yOVQwMjoyODo0OFoifX19","signatures":[{"keyid":"","sig":"MEYCIQDeQXMMojIpNvxEDLDXUC5aAwCbPPr/0uckP8TCcdTLjgIhAJG6M00kY40bz/C90W0FeUc2YcWY+txD4BPXhzd8E+tP"}]}`)
		set, err := base64.StdEncoding.DecodeString("MEQCIDBYWwwDW+nH+1vFoTOqHS4jAtVm4Yezq2nAy7vjcV8zAiBkznmgMrz9em4NuB/hl5X/umubhLgwoXgUAY2NJJwu5A==")
		if err != nil {
			return nil, false, err
		}
		sig, err := static.NewSignature(payload, "", static.WithCertChain(
			[]byte("-----BEGIN CERTIFICATE-----\nMIIDnDCCAyOgAwIBAgIUVGZ4TQgYi4VCLLFghYMU/taKrD8wCgYIKoZIzj0EAwMw\nNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl\ncm1lZGlhdGUwHhcNMjIwNzI5MDIyODQ4WhcNMjIwNzI5MDIzODQ4WjAAMFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAEhiVvK5Tqk1+HnXSstf/8byA1RDpZu+Jvn9X6\nZoaCL/IjSJ7fBakvKAQ0BlzFg/JEtDreg/TFNiX2wnlMBlMV16OCAkIwggI+MA4G\nA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUiMn3\nza+9v+99n385GpkXzZxZiBIwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y\nZD8wYQYDVR0RAQH/BFcwVYZTaHR0cHM6Ly9naXRodWIuY29tL2Rpc3Ryb2xlc3Mv\nc3RhdGljLy5naXRodWIvd29ya2Zsb3dzL3JlbGVhc2UueWFtbEByZWZzL2hlYWRz\nL21haW4wOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1\nYnVzZXJjb250ZW50LmNvbTAWBgorBgEEAYO/MAECBAhzY2hlZHVsZTA2BgorBgEE\nAYO/MAEDBCg3ZTc1NzJlNTc4ZGU3YzUxYTJmMWExNzkxZjAyNWNmMzE1NTAzYWEy\nMBwGCisGAQQBg78wAQQEDkNyZWF0ZSBSZWxlYXNlMB8GCisGAQQBg78wAQUEEWRp\nc3Ryb2xlc3Mvc3RhdGljMB0GCisGAQQBg78wAQYED3JlZnMvaGVhZHMvbWFpbjCB\nigYKKwYBBAHWeQIEAgR8BHoAeAB2AAhgkvAoUv9oRdHRayeEnEVnGKwWPcM40m3m\nvCIGNm9yAAABgkfI9c8AAAQDAEcwRQIgPm4AoftGQF2abbFxMLvtzTjXy+sxwxTp\nCh5ZsoesBDMCIQCNlwmLpuu1KiqjY74l5527AffSd4kOapDMfpHAlMrpCTAKBggq\nhkjOPQQDAwNnADBkAjAe7jfVc1OJNhbaZF8BJRJ9nQOAcY6kwFYMav1XfQsJPE0x\naYpNg/oXVA5UrFcSBLkCMFa4124w3qUzrXSTGq99nlALKQ8HFR8ri17wM5/ZiWxi\nrtABq5eub32TXpAnfqGSmw==\n-----END CERTIFICATE-----\n"),
			[]byte("-----BEGIN CERTIFICATE-----\nMIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C\nAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7\n7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS\n0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB\nBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp\nKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI\nzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR\nnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP\nmygUY7Ii2zbdCdliiow=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7\nXeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex\nX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j\nYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY\nwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ\nKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM\nWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9\nTNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ\n-----END CERTIFICATE-----"),
		), static.WithBundle(&bundle.RekorBundle{
			SignedEntryTimestamp: set,
			Payload: bundle.RekorPayload{
				Body:           "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaW50b3RvIiwic3BlYyI6eyJjb250ZW50Ijp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIyYjY1Y2JmMGU3OTAxYmEzMWQ1NWIxMmQzMTliY2EzOTQyMGFmNDM4OGQzZTU3MTRkMTZmMjAxOWQ3NGUzYWI3In0sInBheWxvYWRIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiYzFiNWYwZjRiOGVjZDU1ZWRhMjUwY2Q4NDk2NGQwYzFmYjVkN2E4YTM0OGY0YjdmZmI3ZGFhMmUwNmM0ODM3MyJ9fSwicHVibGljS2V5IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVUnVSRU5EUVhsUFowRjNTVUpCWjBsVlZrZGFORlJSWjFscE5GWkRURXhHWjJoWlRWVXZkR0ZMY2tRNGQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcEpkMDU2U1RWTlJFbDVUMFJSTkZkb1kwNU5ha2wzVG5wSk5VMUVTWHBQUkZFMFYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZvYVZaMlN6VlVjV3N4SzBodVdGTnpkR1l2T0dKNVFURlNSSEJhZFN0S2RtNDVXRFlLV205aFEwd3ZTV3BUU2pkbVFtRnJka3RCVVRCQ2JIcEdaeTlLUlhSRWNtVm5MMVJHVG1sWU1uZHViRTFDYkUxV01UWlBRMEZyU1hkblowa3JUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZwVFc0ekNucGhLemwyS3prNWJqTTROVWR3YTFoNlduaGFhVUpKZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDFsUldVUldVakJTUVZGSUwwSkdZM2RXV1ZwVVlVaFNNR05JVFRaTWVUbHVZVmhTYjJSWFNYVlpNamwwVERKU2NHTXpVbmxpTW5oc1l6Tk5kZ3BqTTFKb1pFZHNha3g1Tlc1aFdGSnZaRmRKZG1ReU9YbGhNbHB6WWpOa2Vrd3pTbXhpUjFab1l6SlZkV1ZYUm5SaVJVSjVXbGRhZWt3eWFHeFpWMUo2Q2t3eU1XaGhWelIzVDFGWlMwdDNXVUpDUVVkRWRucEJRa0ZSVVhKaFNGSXdZMGhOTmt4NU9UQmlNblJzWW1rMWFGa3pVbkJpTWpWNlRHMWtjR1JIYURFS1dXNVdlbHBZU21waU1qVXdXbGMxTUV4dFRuWmlWRUZYUW1kdmNrSm5SVVZCV1U4dlRVRkZRMEpCYUhwWk1taHNXa2hXYzFwVVFUSkNaMjl5UW1kRlJRcEJXVTh2VFVGRlJFSkRaek5hVkdNeFRucEtiRTVVWXpSYVIxVXpXWHBWZUZsVVNtMU5WMFY0VG5wcmVGcHFRWGxPVjA1dFRYcEZNVTVVUVhwWlYwVjVDazFDZDBkRGFYTkhRVkZSUW1jM09IZEJVVkZGUkd0T2VWcFhSakJhVTBKVFdsZDRiRmxZVG14TlFqaEhRMmx6UjBGUlVVSm5OemgzUVZGVlJVVlhVbkFLWXpOU2VXSXllR3hqTTAxMll6TlNhR1JIYkdwTlFqQkhRMmx6UjBGUlVVSm5OemgzUVZGWlJVUXpTbXhhYmsxMllVZFdhRnBJVFhaaVYwWndZbXBEUWdwcFoxbExTM2RaUWtKQlNGZGxVVWxGUVdkU09FSkliMEZsUVVJeVFVRm9aMnQyUVc5VmRqbHZVbVJJVW1GNVpVVnVSVlp1UjB0M1YxQmpUVFF3YlROdENuWkRTVWRPYlRsNVFVRkJRbWRyWmtrNVl6aEJRVUZSUkVGRlkzZFNVVWxuVUcwMFFXOW1kRWRSUmpKaFltSkdlRTFNZG5SNlZHcFllU3R6ZUhkNFZIQUtRMmcxV25OdlpYTkNSRTFEU1ZGRFRteDNiVXh3ZFhVeFMybHhhbGszTkd3MU5USTNRV1ptVTJRMGEwOWhjRVJOWm5CSVFXeE5jbkJEVkVGTFFtZG5jUXBvYTJwUFVGRlJSRUYzVG01QlJFSnJRV3BCWlRkcVpsWmpNVTlLVG1oaVlWcEdPRUpLVWtvNWJsRlBRV05aTm10M1JsbE5ZWFl4V0daUmMwcFFSVEI0Q21GWmNFNW5MMjlZVmtFMVZYSkdZMU5DVEd0RFRVWmhOREV5TkhjemNWVjZjbGhUVkVkeE9UbHViRUZNUzFFNFNFWlNPSEpwTVRkM1RUVXZXbWxYZUdrS2NuUkJRbkUxWlhWaU16SlVXSEJCYm1aeFIxTnRkejA5Q2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkxTMHRMUzBLIn19",
				IntegratedTime: 1659061729,
				LogIndex:       3059470,
				LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
			},
		}))
		if err != nil {
			return nil, false, err
		}
		return []oci.Signature{sig}, true, nil
	}
	// Let's just say that everything is not verified.
	fail := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		return nil, false, errors.New("bad signature")
	}

	// Let's say it is verified if it is the expected Public Key
	authorityPublicKeyCVS := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		// Because we use this below and it gets called for both key / keyless
		// in the keyless case there's no SigVerifier, so fail it.
		if co.SigVerifier == nil {
			return nil, false, errors.New("Keyless used for key")
		}
		actualPublicKey, _ := co.SigVerifier.PublicKey()
		actualECDSAPubkey := actualPublicKey.(*ecdsa.PublicKey)
		actualKeyData := elliptic.Marshal(actualECDSAPubkey, actualECDSAPubkey.X, actualECDSAPubkey.Y)

		expectedKeyData := elliptic.Marshal(authorityKeyCosignPub, authorityKeyCosignPub.X, authorityKeyCosignPub.Y)

		if bytes.Equal(actualKeyData, expectedKeyData) {
			return pass(ctx, signedImgRef, co)
		}

		return fail(ctx, signedImgRef, co)
	}

	tests := []struct {
		name          string
		policy        webhookcip.ClusterImagePolicy
		want          *PolicyResult
		wantErrs      []string
		cva           func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
		cvs           func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
		customContext context.Context
	}{{
		name: "fail with no public key",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Key:  &webhookcip.KeyRef{},
			}},
		},
		wantErrs: []string{"there are no public keys for authority authority-0"},
	}, {
		name: "simple, public key, no matches",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Key: &webhookcip.KeyRef{
					PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
					HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
					HashAlgorithmCode: crypto.SHA256,
				},
			}},
		},
		wantErrs: []string{"key validation failed for authority authority-0 for gcr.io/distroless/static@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4: bad signature"},
		cvs:      fail,
	}, {
		name: "simple, public key, works",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Key: &webhookcip.KeyRef{
					PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
					HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
					HashAlgorithmCode: crypto.SHA256,
				},
			}},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Signatures: []PolicySignature{{
						ID: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						// TODO(mattmoor): Is there anything we should encode for key-based?
					}},
				}},
		},
		cvs: pass,
	}, {
		name: "simple, public key and keyless, one works, one doesn't",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Key: &webhookcip.KeyRef{
					PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
					HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
					HashAlgorithmCode: crypto.SHA256,
				},
			}, {
				Name: "authority-1",
				Keyless: &webhookcip.KeylessRef{
					URL: badURL,
				},
			}},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Signatures: []PolicySignature{{
						ID: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						// TODO(mattmoor): Is there anything we should encode for key-based?
					}},
				}},
		},
		wantErrs: []string{`signature keyless validation failed for authority authority-1 for gcr.io/distroless/static@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4: Keyless used for key`},
		cvs:      authorityPublicKeyCVS,
	}, {
		name: "simple, static set to pass",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Static: &webhookcip.StaticRef{
					Action: "pass",
				},
			}},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Static: true,
				},
			},
		},
	}, {
		name: "simple, static set to fail",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Static: &webhookcip.StaticRef{
					Action: "fail",
				},
			}},
		},
		wantErrs: []string{"disallowed by static policy"},
	}, {
		name: "simple, public key, no error",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Key: &webhookcip.KeyRef{
					PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
					HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
					HashAlgorithmCode: crypto.SHA256,
				},
			}},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Signatures: []PolicySignature{{
						ID: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						// TODO(mattmoor): Is there anything we should encode for key-based?
					}},
				}},
		},
		cvs: authorityPublicKeyCVS,
	}, {
		name: "simple, keyless attestation, works",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Keyless: &webhookcip.KeylessRef{
					URL: fulcioURL,
				},
				Attestations: []webhookcip.AttestationPolicy{{
					Name:          "test-att",
					PredicateType: "vuln",
				}},
			},
			},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Attestations: map[string][]PolicyAttestation{
						"test-att": {{
							PolicySignature: PolicySignature{
								ID:      "01bd6aec99ad7c5d045d9aab649fd95b7af2b3b23887d34d7fce8b2e3c38ca0e",
								Subject: "https://github.com/distroless/static/.github/workflows/release.yaml@refs/heads/main",
								Issuer:  "https://token.actions.githubusercontent.com",
								GithubExtensions: GithubExtensions{
									WorkflowTrigger: "schedule",
									WorkflowSHA:     "7e7572e578de7c51a2f1a1791f025cf315503aa2",
									WorkflowName:    "Create Release",
									WorkflowRepo:    "distroless/static",
									WorkflowRef:     "refs/heads/main",
								},
							},
							PredicateType: "vuln",
							Payload:       []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://cosign.sigstore.dev/attestation/vuln/v1","subject":[{"name":"ghcr.io/distroless/static","digest":{"sha256":"a1e82f6a5f6dfc735165d3442e7cc5a615f72abac3db19452481f5f3c90fbfa8"}}],"predicate":{"invocation":{"parameters":null,"uri":"https://github.com/distroless/static/actions/runs/2757953139","event_id":"2757953139","builder.id":"Create Release"},"scanner":{"uri":"https://github.com/aquasecurity/trivy","version":"0.29.2","db":{"uri":"","version":""},"result":{"$schema":"https://json.schemastore.org/sarif-2.1.0-rtm.5.json","runs":[{"columnKind":"utf16CodeUnits","originalUriBaseIds":{"ROOTPATH":{"uri":"file:///"}},"results":[],"tool":{"driver":{"fullName":"Trivy Vulnerability Scanner","informationUri":"https://github.com/aquasecurity/trivy","name":"Trivy","rules":[],"version":"0.29.2"}}}],"version":"2.1.0"}},"metadata":{"scanStartedOn":"2022-07-29T02:28:42Z","scanFinishedOn":"2022-07-29T02:28:48Z"}}}`),
						}},
					},
				},
			},
		},
		cva: passKeyless,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cosignVerifySignatures = test.cvs
			cosignVerifyAttestations = test.cva
			testContext := context.Background()

			if test.customContext != nil {
				testContext = test.customContext
			}
			kc, err := k8schain.NewNoClient(testContext)
			if err != nil {
				t.Fatalf("Failed to construct no client k8schain for testing")
			}
			got, gotErrs := ValidatePolicy(testContext, system.Namespace(), digest, test.policy, kc)
			validateErrors(t, test.wantErrs, gotErrs)
			if !reflect.DeepEqual(test.want, got) {
				t.Errorf("unexpected PolicyResult, want: %+v got: %+v", test.want, got)
			}
		})
	}
}

func validateErrors(t *testing.T, wantErr []string, got []error) {
	t.Helper()
	if len(wantErr) != len(got) {
		t.Errorf("Wanted %d errors got %d", len(wantErr), len(got))
	} else {
		for i, want := range wantErr {
			if !strings.Contains(got[i].Error(), want) {
				t.Errorf("Unwanted error at %d want: %s got: %s", i, want, got[i])
			}
		}
	}
}

func TestValidatePodSpecNonDefaultNamespace(t *testing.T) {
	tag := name.MustParseReference("gcr.io/distroless/static:nonroot")
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	ctx, _ := rtesting.SetupFakeContext(t)

	// Non-existent URL for testing complete failure
	badURL := apis.HTTP("http://example.com/")

	// Spin up a Fulcio that responds with a Root Cert
	fulcioServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(fulcioRootCert))
	}))
	t.Cleanup(fulcioServer.Close)
	fulcioURL, err := apis.ParseURL("https://fulcio.sigstore.dev")
	if err != nil {
		t.Fatalf("Failed to parse fake Fulcio URL")
	}

	rekorServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(rekorResponse))
	}))
	t.Cleanup(rekorServer.Close)
	rekorURL, err := apis.ParseURL(rekorServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse fake Rekor URL")
	}

	var authorityKeyCosignPub *ecdsa.PublicKey

	pems := parsePems([]byte(authorityKeyCosignPubString))
	if len(pems) > 0 {
		key, _ := x509.ParsePKIXPublicKey(pems[0].Bytes)
		authorityKeyCosignPub = key.(*ecdsa.PublicKey)
	} else {
		t.Errorf("Error parsing authority key from string")
	}

	kc := fakekube.Get(ctx)
	// Setup service acc and fakeSignaturePullSecrets for "default", "cosign-system" and "my-secure-ns" namespace
	for _, ns := range []string{"default", system.Namespace(), "my-secure-ns"} {
		kc.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}, metav1.CreateOptions{})

		kc.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "fakeSignaturePullSecrets",
			},
			Data: map[string][]byte{
				"dockerconfigjson": []byte(`{"auths":{"https://index.docker.io/v1/":{"username":"username","password":"password","auth":"dXNlcm5hbWU6cGFzc3dvcmQ="}}`),
			},
		}, metav1.CreateOptions{})
	}

	// Create fake secret in a non-default namespace and patch the default service acc
	kc.CoreV1().Secrets("my-secure-ns").Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fakeSignaturePullSecretsNonDefault",
		},
		Data: map[string][]byte{
			"dockerconfigjson": []byte(`{"auths":{"https://index.docker.io/v1/":{"username":"username","password":"password","auth":"dXNlcm5hbWU6cGFzc3dvcmQ="}}`),
		},
	}, metav1.CreateOptions{})

	mergePatch := map[string]interface{}{
		"imagePullSecrets": map[string]interface{}{
			"name": "fakeSignaturePullSecretsNonDefault",
		},
	}
	patch, err := json.Marshal(mergePatch)
	if err != nil {
		t.Fatalf("Failed to marshal merge patch: %v", err)
	}
	kc.CoreV1().ServiceAccounts("my-secure-ns").Patch(ctx, "default", types.MergePatchType, patch, metav1.PatchOptions{})

	v := NewValidator(ctx)

	cvs := cosignVerifySignatures
	defer func() {
		cosignVerifySignatures = cvs
	}()
	// Let's just say that everything is verified.
	pass := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		sig, err := static.NewSignature(nil, "")
		if err != nil {
			return nil, false, err
		}
		return []oci.Signature{sig}, true, nil
	}
	// Let's just say that everything is not verified.
	fail := func(_ context.Context, _ name.Reference, _ *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		return nil, false, errors.New("bad signature")
	}

	// Let's say it is verified if it is the expected Public Key
	authorityPublicKeyCVS := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		actualPublicKey, _ := co.SigVerifier.PublicKey()
		actualECDSAPubkey := actualPublicKey.(*ecdsa.PublicKey)
		actualKeyData := elliptic.Marshal(actualECDSAPubkey, actualECDSAPubkey.X, actualECDSAPubkey.Y)

		expectedKeyData := elliptic.Marshal(authorityKeyCosignPub, authorityKeyCosignPub.X, authorityKeyCosignPub.Y)

		if bytes.Equal(actualKeyData, expectedKeyData) {
			return pass(ctx, signedImgRef, co)
		}

		return fail(ctx, signedImgRef, co)
	}

	tests := []struct {
		name          string
		ps            *corev1.PodSpec
		want          *apis.FieldError
		cvs           func(context.Context, name.Reference, *cosign.CheckOpts) ([]oci.Signature, bool, error)
		customContext context.Context
	}{{
		name: "simple, no error",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:              authorityKeyCosignPubString,
										PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
										HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
										HashAlgorithmCode: crypto.SHA256,
									},
								},
							},
						},
					},
				},
			},
		),
		cvs: pass,
	}, {
		name: "bad reference",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: "in@valid",
			}},
		},
		want: &apis.FieldError{
			Message: `could not parse reference: in@valid`,
			Paths:   []string{"containers[0].image"},
		},
		cvs: fail,
	}, {
		name: "not digest",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: tag.String(),
			}},
		},
		want: &apis.FieldError{
			Message: `invalid value: gcr.io/distroless/static:nonroot must be an image digest`,
			Paths:   []string{"containers[0].image"},
		},
		cvs: fail,
	}, {
		name: "simple, no error, authority key",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:              authorityKeyCosignPubString,
										PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
										HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
										HashAlgorithmCode: crypto.SHA256,
									},
								},
							},
						},
					},
				},
			},
		),
		cvs: authorityPublicKeyCVS,
	}, {
		name: "simple, error, authority keyless, bad fulcio",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: badURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe.Details = fmt.Sprintf("%s %s", digest.String(), `signature keyless validation failed for authority  for gcr.io/distroless/static@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4: bad signature`)
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe2.Details = fe.Details
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: fail,
	}, {
		name: "simple, error, authority keyless, good fulcio, no rekor",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: fail,
	}, {
		name: "simple, authority keyless checks out, good fulcio, bad cip policy",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless-bad-cip": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
								},
							},
							Policy: &webhookcip.AttestationPolicy{
								Name: "invalid json policy",
								Type: "cue",
								Data: `{"wontgo`,
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless-bad-cip", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s failed evaluating cue policy for ClusterImagePolicy: failed to compile the cue policy with error: string literal not terminated", digest.String())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless-bad-cip", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s failed evaluating cue policy for ClusterImagePolicy: failed to compile the cue policy with error: string literal not terminated", digest.String())
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: pass,
	}, {
		name: "simple, no error, authority keyless, good fulcio",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
								},
							},
						},
					},
				},
			},
		),
		cvs: pass,
	}, {
		name: "simple, error, authority keyless, good fulcio, bad rekor",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy-keyless": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Keyless: &webhookcip.KeylessRef{
										URL: fulcioURL,
									},
									CTLog: &v1alpha1.TLog{
										URL: rekorURL,
									},
								},
							},
						},
					},
				},
			},
		),
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s signature keyless validation failed for authority  for %s: bad signature", digest.String(), digest.Name())
			errs = errs.Also(fe2)
			return errs
		}(),
		cvs: fail,
	}, {
		name: "simple, error, authority source signaturePullSecrets, non existing secret",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(ctx,
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:              authorityKeyCosignPubString,
										PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
										HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
										HashAlgorithmCode: crypto.SHA256,
									},
									Sources: []v1alpha1.Source{{
										OCI: "example.com/alternative/signature",
										SignaturePullSecrets: []corev1.LocalObjectReference{{
											Name: "non-existing-secret",
										}},
									}},
								},
							},
						},
					},
				},
			},
		),
		cvs: pass,
	}, {
		name: "simple, no error, authority source signaturePullSecrets, valid secret",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(ctx,
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:              authorityKeyCosignPubString,
										PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
										HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
										HashAlgorithmCode: crypto.SHA256,
									},
									Sources: []v1alpha1.Source{{
										OCI: "example.com/alternative/signature",
										SignaturePullSecrets: []corev1.LocalObjectReference{{
											Name: "fakeSignaturePullSecrets",
										}},
									}},
								},
							},
						},
					},
				},
			},
		),
		cvs: authorityPublicKeyCVS,
	}, {
		name: "simple, no error, with a resource selector based on labels and resource version",
		ps: &corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup-stuff",
				Image: digest.String(),
			}},
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		customContext: config.ToContext(context.Background(),
			&config.Config{
				ImagePolicyConfig: &config.ImagePolicyConfig{
					Policies: map[string]webhookcip.ClusterImagePolicy{
						"cluster-image-policy": {
							Images: []v1alpha1.ImagePattern{{
								Glob: "gcr.io/*/*",
							}},
							Match: []v1alpha1.MatchResource{
								{
									GroupVersionResource: metav1.GroupVersionResource{
										Group:    "",
										Version:  "v1",
										Resource: "pods",
									},
									ResourceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"test": "test"},
									},
								},
							},
							Authorities: []webhookcip.Authority{
								{
									Key: &webhookcip.KeyRef{
										Data:              authorityKeyCosignPubString,
										PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
										HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
										HashAlgorithmCode: crypto.SHA256,
									},
								},
							},
						},
					},
				},
			},
		),
		cvs: pass,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"", "enforce", "warn"} {
				cosignVerifySignatures = test.cvs
				testContext := context.Background()
				// By default we want errors. However, iff the mode above is
				// warn, and we're using a custom context and therefore
				// triggering the CIP.mode twiddling below, check for warnings.
				wantWarn := false
				if test.customContext != nil {
					if mode == "warn" {
						wantWarn = true
					}
					// If we are testing with custom context, loop through
					// all the modes here. It's a bit silly that we spin through
					// all the tests 3 times, but for now this is better than
					// duplicating all the CIPs with just different modes.
					testContext = test.customContext

					// Twiddle the mode for tests.
					cfg := config.FromContext(testContext)
					newPolicies := make(map[string]webhookcip.ClusterImagePolicy, len(cfg.ImagePolicyConfig.Policies))
					for k, v := range cfg.ImagePolicyConfig.Policies {
						v.Mode = mode
						newPolicies[k] = v
					}
					cfg.ImagePolicyConfig.Policies = newPolicies
					config.ToContext(testContext, cfg)
				}

				// The Request body bytes are consumed in every call, so we need
				// to set an new request for every call
				attachHTTPRequestToContext := func(context.Context) context.Context {
					// Build fake HTTP Request
					admissionreq := &admissionv1.AdmissionReview{
						Request: &admissionv1.AdmissionRequest{
							Operation: admissionv1.Create,
							Kind: metav1.GroupVersionKind{
								Group:   "",
								Version: "v1",
								Kind:    "Pod",
							},
							Namespace: "my-secure-ns",
						},
					}

					reqBuf := new(bytes.Buffer)
					err = json.NewEncoder(reqBuf).Encode(&admissionreq)
					if err != nil {
						t.Fatalf("Failed to marshal admission review: %v", err)
					}
					req, err := http.NewRequest("GET", "foo", reqBuf)
					if err != nil {
						t.Fatalf("NewRequest() = %v", err)
					}
					return apis.WithHTTPRequest(testContext, req)
				}

				testContext = attachHTTPRequestToContext(testContext)
				testContext = context.WithValue(testContext, kubeclient.Key{}, kc)

				// Check the core mechanics
				got := v.validatePodSpec(testContext, "my-secure-ns", "Pod", "v1", map[string]string{"test": "test"}, test.ps, k8schain.Options{})
				if (got != nil) != (test.want != nil) {
					t.Errorf("validatePodSpec() = %v, wanted %v", got, test.want)
				} else if got != nil && got.Error() != test.want.Error() {
					t.Errorf("validatePodSpec() = %v, wanted %v", got, test.want)
				}

				if test.want != nil {
					if wantWarn {
						test.want.Level = apis.WarningLevel
					} else {
						test.want.Level = apis.ErrorLevel
					}
				}
				// Check wrapped in a Pod
				pod := &duckv1.Pod{
					Spec: *test.ps,
				}
				testContext = attachHTTPRequestToContext(testContext)
				// Set the policy config to pass anything that doesn't match any
				// policies.
				testContext = policycontrollerconfig.ToContext(testContext, &policycontrollerconfig.PolicyControllerConfig{NoMatchPolicy: policycontrollerconfig.AllowAll, FailOnEmptyAuthorities: true})

				got = v.ValidatePod(testContext, pod)
				want := test.want.ViaField("spec")
				if (got != nil) != (want != nil) {
					t.Errorf("ValidatePod() = %v, wanted %v", got, want)
				} else if got != nil && got.Error() != want.Error() {
					t.Errorf("ValidatePod() = %v, wanted %v", got, want)
				}
				// Check the warning/error level.
				if got != nil && test.want != nil {
					if got.Level != want.Level {
						t.Errorf("ValidatePod() Wrong Level = %v, wanted %v", got.Level, want.Level)
					}
				}
				// Check that we don't block things being deleted.
				testContext = attachHTTPRequestToContext(testContext)
				if got := v.ValidatePod(apis.WithinDelete(testContext), pod); got != nil {
					t.Errorf("ValidatePod() = %v, wanted nil", got)
				}

				// Check wrapped in a WithPod
				withPod := &duckv1.WithPod{
					Spec: duckv1.WithPodSpec{
						Template: duckv1.PodSpecable{
							Spec: *test.ps,
						},
					},
				}
				testContext = attachHTTPRequestToContext(testContext)
				got = v.ValidatePodSpecable(testContext, withPod)
				want = test.want.ViaField("spec.template.spec")
				if (got != nil) != (want != nil) {
					t.Errorf("ValidatePodSpecable() = %v, wanted %v", got, want)
				} else if got != nil && got.Error() != want.Error() {
					t.Errorf("ValidatePodSpecable() = %v, wanted %v", got, want)
				}
				// Check the warning/error level.
				if got != nil && test.want != nil {
					if got.Level != want.Level {
						t.Errorf("ValidatePodSpecable() Wrong Level = %v, wanted %v", got.Level, want.Level)
					}
				}

				// Check that we don't block things being deleted.
				testContext = attachHTTPRequestToContext(testContext)
				if got := v.ValidatePodSpecable(apis.WithinDelete(testContext), withPod); got != nil {
					t.Errorf("ValidatePodSpecable() = %v, wanted nil", got)
				}

				// Check wrapped in a podScalable
				podScalable := &policyduckv1beta1.PodScalable{
					Spec: policyduckv1beta1.PodScalableSpec{
						Replicas: ptr.Int32(3),
						Template: corev1.PodTemplateSpec{
							Spec: *test.ps,
						},
					},
				}
				testContext = attachHTTPRequestToContext(testContext)
				got = v.ValidatePodScalable(testContext, podScalable)
				want = test.want.ViaField("spec.template.spec")
				if (got != nil) != (want != nil) {
					t.Errorf("ValidatePodScalable() = %v, wanted %v", got, want)
				} else if got != nil && got.Error() != want.Error() {
					t.Errorf("ValidatePodScalable() = %v, wanted %v", got, want)
				}
				// Check the warning/error level.
				if got != nil && test.want != nil {
					if got.Level != want.Level {
						t.Errorf("ValidatePodScalable() Wrong Level = %v, wanted %v", got.Level, want.Level)
					}
				}

				// Check that we don't block things being deleted.
				testContext = attachHTTPRequestToContext(testContext)
				if got := v.ValidatePodScalable(apis.WithinDelete(testContext), podScalable); got != nil {
					t.Errorf("ValidatePodSpecable() = %v, wanted nil", got)
				}

				// Check that we don't block things being scaled down.
				original := podScalable.DeepCopy()
				original.Spec.Replicas = ptr.Int32(4)
				testContext = attachHTTPRequestToContext(testContext)
				if got := v.ValidatePodScalable(apis.WithinUpdate(testContext, original), podScalable); got != nil {
					t.Errorf("ValidatePodSpecable() scaling down = %v, wanted nil", got)
				}

				// Check that we fail as expected if being scaled up.
				original.Spec.Replicas = ptr.Int32(2)
				testContext = attachHTTPRequestToContext(testContext)
				got = v.ValidatePodScalable(apis.WithinUpdate(testContext, original), podScalable)
				want = test.want.ViaField("spec.template.spec")
				if (got != nil) != (want != nil) {
					t.Errorf("ValidatePodScalable() scaling up = %v, wanted %v", got, want)
				} else if got != nil && got.Error() != want.Error() {
					t.Errorf("ValidatePodScalable() scaling up = %v, wanted %v", got, want)
				}
				// Check the warning/error level.
				if got != nil && test.want != nil {
					if got.Level != want.Level {
						t.Errorf("ValidatePodScalable() scaling up Wrong Level = %v, wanted %v", got.Level, want.Level)
					}
				}
			}
		})
	}
}

func TestValidatePodSpecCancelled(t *testing.T) {
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	ctx, _ := rtesting.SetupFakeContext(t)
	kc := fakekube.Get(ctx)
	// Setup service account and fakeSignaturePullSecrets for "default"
	// namespace
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	kc.CoreV1().Secrets("default").Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fakeSignaturePullSecrets",
		},
		Data: map[string][]byte{
			"dockerconfigjson": []byte(`{"auths":{"https://index.docker.io/v1/":{"username":"username","password":"password","auth":"dXNlcm5hbWU6cGFzc3dvcmQ="}}`),
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx)

	ps := &corev1.PodSpec{
		InitContainers: []corev1.Container{{
			Name:  "setup-stuff",
			Image: digest.String(),
		}},
		Containers: []corev1.Container{{
			Name:  "user-container",
			Image: digest.String(),
		}},
	}
	ctx = config.ToContext(ctx,
		&config.Config{
			ImagePolicyConfig: &config.ImagePolicyConfig{
				Policies: map[string]webhookcip.ClusterImagePolicy{
					"cluster-image-policy": {
						Images: []v1alpha1.ImagePattern{{
							Glob: "gcr.io/*/*",
						}},
						Authorities: []webhookcip.Authority{
							{
								Keyless: &webhookcip.KeylessRef{
									URL: apis.HTTP("fulcio.sigstore.dev"),
								}},
						},
					},
				},
			},
		})

	cancelledContext, cancelFunc := context.WithCancel(ctx)
	wantErr := "context was canceled before validation completed"
	cancelFunc()
	gotErrs := v.validatePodSpec(cancelledContext, "default", "pod", "v1", map[string]string{}, ps, k8schain.Options{})
	if gotErrs == nil {
		t.Errorf("Did not get an error on canceled context")
	} else if !strings.Contains(gotErrs.Error(), wantErr) {
		t.Errorf("Did not get canceled error, got: %s", gotErrs.Error())
	}
}

func TestValidatePolicyCancelled(t *testing.T) {
	var authorityKeyCosignPub *ecdsa.PublicKey
	pems := parsePems([]byte(authorityKeyCosignPubString))
	if len(pems) > 0 {
		key, _ := x509.ParsePKIXPublicKey(pems[0].Bytes)
		authorityKeyCosignPub = key.(*ecdsa.PublicKey)
	} else {
		t.Errorf("Error parsing authority key from string")
	}
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	testContext, cancelFunc := context.WithCancel(context.Background())
	cip := webhookcip.ClusterImagePolicy{
		Authorities: []webhookcip.Authority{{
			Name: "authority-0",
			Key: &webhookcip.KeyRef{
				PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
				HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
				HashAlgorithmCode: crypto.SHA256,
			},
		}},
	}
	kc, err := k8schain.NewNoClient(testContext)
	if err != nil {
		t.Fatalf("Failed to construct no client k8schain for testing")
	}

	wantErrs := []string{"context canceled before validation completed"}
	cancelFunc()
	_, gotErrs := ValidatePolicy(testContext, system.Namespace(), digest, cip, kc)
	validateErrors(t, wantErrs, gotErrs)
}

func TestValidatePoliciesCancelled(t *testing.T) {
	var authorityKeyCosignPub *ecdsa.PublicKey
	pems := parsePems([]byte(authorityKeyCosignPubString))
	if len(pems) > 0 {
		key, _ := x509.ParsePKIXPublicKey(pems[0].Bytes)
		authorityKeyCosignPub = key.(*ecdsa.PublicKey)
	} else {
		t.Errorf("Error parsing authority key from string")
	}
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	testContext, cancelFunc := context.WithCancel(context.Background())
	cip := webhookcip.ClusterImagePolicy{
		Authorities: []webhookcip.Authority{{
			Name: "authority-0",
			Key: &webhookcip.KeyRef{
				PublicKeys:        []crypto.PublicKey{authorityKeyCosignPub},
				HashAlgorithm:     signaturealgo.DefaultSignatureAlgorithm,
				HashAlgorithmCode: crypto.SHA256,
			},
		}},
	}
	kc, err := k8schain.NewNoClient(testContext)
	if err != nil {
		t.Fatalf("Failed to construct no client k8schain for testing")
	}
	wantErrs := []string{"context was canceled before validation completed"}
	cancelFunc()
	_, gotErrs := validatePolicies(testContext, system.Namespace(), digest, map[string]webhookcip.ClusterImagePolicy{"testcip": cip}, kc)
	validateErrors(t, wantErrs, gotErrs["internalerror"])
}

func TestPolicyControllerConfigNoMatchPolicy(t *testing.T) {
	digest := "gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4"

	testPodSpec := &corev1.PodSpec{
		Containers: []corev1.Container{{
			Name:  "test-container",
			Image: digest,
		}},
	}

	ctx, _ := rtesting.SetupFakeContext(t)
	policies := &config.ImagePolicyConfig{
		Policies: map[string]webhookcip.ClusterImagePolicy{},
	}
	ctx = config.ToContext(ctx, &config.Config{ImagePolicyConfig: policies})
	v := NewValidator(ctx)
	// no policies
	kc := fakekube.Get(ctx)
	// Setup service acc and fakeSignaturePullSecrets for "default", "cosign-system" and "my-secure-ns" namespace
	for _, ns := range []string{"default", system.Namespace()} {
		kc.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}, metav1.CreateOptions{})

		kc.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "fakeSignaturePullSecrets",
			},
			Data: map[string][]byte{
				"dockerconfigjson": []byte(`{"auths":{"https://index.docker.io/v1/":{"username":"username","password":"password","auth":"dXNlcm5hbWU6cGFzc3dvcmQ="}}`),
			},
		}, metav1.CreateOptions{})
	}

	tests := []struct {
		name          string
		noMatchPolicy string
		want          *apis.FieldError
		// If above should be at warning level.
		wantWarn bool
	}{{
		name: "empty value - implicit deny", // this will fail because default is deny.
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("no matching policies", "image").ViaFieldIndex("containers", 0)
			fe.Details = digest
			errs = errs.Also(fe)
			return errs
		}(),
	}, {
		name:          "explicit deny",
		noMatchPolicy: "deny",
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("no matching policies", "image").ViaFieldIndex("containers", 0)
			fe.Details = digest
			errs = errs.Also(fe)
			return errs
		}(),
	}, {
		name:          "warn",
		noMatchPolicy: "warn",
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("no matching policies", "image").ViaFieldIndex("containers", 0)
			fe.Details = digest
			errs = errs.Also(fe)
			return errs
		}(),
	}, {
		name:          "allow",
		noMatchPolicy: "allow",
	}}
	for _, tc := range tests {
		testCtx := policycontrollerconfig.ToContext(ctx, &policycontrollerconfig.PolicyControllerConfig{NoMatchPolicy: tc.noMatchPolicy, FailOnEmptyAuthorities: true})

		got := v.validatePodSpec(testCtx, system.Namespace(), "pod", "v1", map[string]string{}, testPodSpec, k8schain.Options{})
		if (got != nil) != (tc.want != nil) {
			t.Errorf("ValidatePodSpecable() = %v, wanted %v", got, tc.want)
		} else if got != nil && got.Error() != tc.want.Error() {
			t.Errorf("ValidatePodSpecable() = %v, wanted %v", got, tc.want)
		}
		if tc.want != nil && tc.wantWarn {
			tc.want.Level = apis.WarningLevel
		}
		// Check the warning/error level.
		if got != nil && tc.want != nil {
			if got.Level != tc.want.Level {
				t.Errorf("ValidatePod() Wrong Level = %v, wanted %v", got.Level, tc.want.Level)
			}
		}
	}
}

func TestFulcioCertsFromAuthority(t *testing.T) {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(certChain))
	if err != nil {
		t.Fatalf("Failed to unmarshal certs for testing: %v", err)
	}

	roots := x509.NewCertPool()
	// last cert is the root
	roots.AddCert(certs[2])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(certs[0])
	intermediates.AddCert(certs[1])

	embeddedRoots, err := fulcioroots.Get()
	if err != nil {
		t.Fatalf("Failed to get embedded fulcioroots for testing")
	}
	embeddedIntermediates, err := fulcioroots.GetIntermediates()
	if err != nil {
		t.Fatalf("Failed to get embedded fulcioroots for testing")
	}

	embeddedCTLogKeys, err := cosign.GetCTLogPubs(context.Background())
	if err != nil {
		t.Fatalf("Failed to get embedded CTLog Public keys for testing")
	}
	sk := config.SigstoreKeys{
		CertificateAuthorities: []config.CertificateAuthority{{
			Subject: config.DistinguishedName{
				Organization: "testorg",
				CommonName:   "testcommonname",
			},
			CertChain: []byte(certChain),
		}},
		CTLogs: []config.TransparencyLogInstance{{LogID: ctfeLogID, PublicKey: []byte(ctfePublicKey)}},
	}
	c := &config.Config{
		SigstoreKeysConfig: &config.SigstoreKeysMap{
			SigstoreKeys: map[string]config.SigstoreKeys{
				"test-trust-root": sk,
			},
		},
	}
	marshalledPK, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(ctfePublicKey))
	if err != nil {
		t.Fatalf("Failed to unmarshal CTLog public key: %v", err)
	}

	testCtx := config.ToContext(context.Background(), c)

	tests := []struct {
		name              string
		keylessRef        *webhookcip.KeylessRef
		wantErr           string
		wantRoots         *x509.CertPool
		wantIntermediates *x509.CertPool
		wantCTLogKeys     *cosign.TrustedTransparencyLogPubKeys
		ctx               context.Context
	}{{
		name:              "no trustroots, uses embedded",
		keylessRef:        &webhookcip.KeylessRef{},
		wantRoots:         embeddedRoots,
		wantIntermediates: embeddedIntermediates,
		wantCTLogKeys:     embeddedCTLogKeys,
	}, {
		name:       "config does not exist",
		keylessRef: &webhookcip.KeylessRef{TrustRootRef: "not-there"},
		wantErr:    "getting SigstoreKeys: trustRootRef not-there not found, config missing",
		ctx:        config.ToContext(context.Background(), nil),
	}, {
		name:       "SigstoreKeys does not exist",
		keylessRef: &webhookcip.KeylessRef{TrustRootRef: "not-there"},
		wantErr:    "getting SigstoreKeys: trustRootRef not-there not found, SigstoreKeys missing",
		ctx:        config.ToContext(context.Background(), &config.Config{}),
	}, {
		name:       "trustroot does not exist",
		keylessRef: &webhookcip.KeylessRef{TrustRootRef: "not-there"},
		ctx:        testCtx,
		wantErr:    "trustRootRef not-there not found",
	}, {
		name:              "trustroot found",
		keylessRef:        &webhookcip.KeylessRef{TrustRootRef: "test-trust-root"},
		ctx:               testCtx,
		wantRoots:         roots,
		wantIntermediates: intermediates,
		wantCTLogKeys:     &cosign.TrustedTransparencyLogPubKeys{Keys: map[string]cosign.TransparencyLogPubKey{ctfeLogID: {PubKey: marshalledPK, Status: tuf.Active}}},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tCtx := tc.ctx
			if tCtx == nil {
				tCtx = context.Background()
			}
			roots, intermediates, ctlogKeys, err := fulcioCertsFromAuthority(tCtx, tc.keylessRef)
			if err != nil {
				if tc.wantErr == "" {
					t.Errorf("unexpected error: %v wanted none", err)
				} else if err.Error() != tc.wantErr {
					t.Errorf("unexpected error: %v wanted %q", err, tc.wantErr)
				}
			} else if err == nil && tc.wantErr != "" {
				t.Errorf("wanted error: %q got none", tc.wantErr)
			}
			if !roots.Equal(tc.wantRoots) {
				t.Errorf("Roots differ")
			}
			if !intermediates.Equal(tc.wantIntermediates) {
				t.Errorf("Intermediates differ")
			}
			if diff := cmp.Diff(tc.wantCTLogKeys, ctlogKeys); diff != "" {
				t.Errorf("CTLog keys differ: %s", diff)
			}
		})
	}
}

func TestRekorClientAndKeysFromAuthority(t *testing.T) {
	pk, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(rekorPublicKey))
	if err != nil {
		t.Fatalf("Failed to unmarshal public key for testing: %v", err)
	}
	ecpk, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("pk is not a ecsda public key")
	}

	embeddedPKs, err := cosign.GetRekorPubs(context.Background())
	if err != nil {
		t.Fatalf("Failed to get embedded rekor pubs for testing")
	}
	if len(embeddedPKs.Keys) != 1 {
		t.Fatalf("Did not get a single Public Key for Rekor")
	}
	var embeddedLogID string
	var embeddedPK crypto.PublicKey
	for k, v := range embeddedPKs.Keys {
		embeddedLogID = k
		embeddedPK = v.PubKey
	}

	sk := config.SigstoreKeys{
		TLogs: []config.TransparencyLogInstance{{
			PublicKey: []byte(rekorPublicKey),
			LogID:     rekorLogID,
			BaseURL:   *apis.HTTPS("rekor.example.com"),
		}},
	}
	c := &config.Config{
		SigstoreKeysConfig: &config.SigstoreKeysMap{
			SigstoreKeys: map[string]config.SigstoreKeys{
				"test-trust-root": sk,
			},
		},
	}
	testCtx := config.ToContext(context.Background(), c)

	tests := []struct {
		name       string
		tlog       *v1alpha1.TLog
		wantErr    string
		wantPK     crypto.PublicKey
		wantLogID  string
		wantClient bool
		ctx        context.Context
	}{{
		name:       "no trustroots, uses embedded",
		tlog:       &v1alpha1.TLog{URL: apis.HTTPS("rekor.sigstore.dev")},
		wantPK:     embeddedPK,
		wantLogID:  embeddedLogID,
		wantClient: true,
	}, {

		name:    "config does not exist",
		tlog:    &v1alpha1.TLog{TrustRootRef: "not-there"},
		wantErr: "fetching keys for trustRootRef: getting SigstoreKeys: trustRootRef not-there not found, config missing",
		ctx:     config.ToContext(context.Background(), nil),
	}, {
		name:    "SigstoreKeys does not exist",
		tlog:    &v1alpha1.TLog{TrustRootRef: "not-there"},
		wantErr: "fetching keys for trustRootRef: getting SigstoreKeys: trustRootRef not-there not found, SigstoreKeys missing",
		ctx:     config.ToContext(context.Background(), &config.Config{}),
	}, {
		name:    "trustroot does not exist",
		tlog:    &v1alpha1.TLog{TrustRootRef: "not-there"},
		ctx:     testCtx,
		wantErr: "fetching keys for trustRootRef: trustRootRef not-there not found",
	}, {
		name:       "trustroot found",
		tlog:       &v1alpha1.TLog{TrustRootRef: "test-trust-root"},
		wantPK:     ecpk,
		wantLogID:  rekorLogID,
		ctx:        testCtx,
		wantClient: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tCtx := tc.ctx
			if tCtx == nil {
				tCtx = context.Background()
			}
			rekorClient, gotPKs, err := rekorClientAndKeysFromAuthority(tCtx, webhookcip.Authority{CTLog: tc.tlog})
			if err != nil {
				if tc.wantErr == "" {
					t.Errorf("unexpected error: %v wanted none", err)
				} else if err.Error() != tc.wantErr {
					t.Errorf("unexpected error: %v wanted %q", err, tc.wantErr)
				}
			} else if err == nil && tc.wantErr != "" {
				t.Errorf("wanted error: %q got none", tc.wantErr)
			}
			if tc.wantLogID != "" {
				if gotPKs == nil || gotPKs.Keys == nil {
					t.Errorf("Wanted logid %s got none", tc.wantLogID)
				} else if diff := cmp.Diff(gotPKs.Keys[tc.wantLogID].PubKey, tc.wantPK); diff != "" {
					t.Errorf("did not get wanted PK: %s", diff)
				}
			} else if gotPKs != nil {
				t.Errorf("did not want PK, %+v", gotPKs)
			}
			if tc.wantClient && rekorClient == nil {
				t.Errorf("wanted rekor client, but got none")
			} else if !tc.wantClient && rekorClient != nil {
				t.Errorf("did not want rekor client, but got one")
			}
		})
	}
}

func TestCheckOptsFromAuthority(t *testing.T) {
	pk, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(rekorPublicKey))
	if err != nil {
		t.Fatalf("Failed to unmarshal public key for testing: %v", err)
	}
	ecpk, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("pk is not a ecsda public key")
	}

	embeddedPKs, err := cosign.GetRekorPubs(context.Background())
	if err != nil {
		t.Fatalf("Failed to get embedded rekor pubs for testing")
	}
	if len(embeddedPKs.Keys) != 1 {
		t.Fatalf("Did not get a single Public Key for Rekor")
	}
	var embeddedLogID string
	var embeddedPK crypto.PublicKey
	for k, v := range embeddedPKs.Keys {
		embeddedLogID = k
		embeddedPK = v.PubKey
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(certChain))
	if err != nil {
		t.Fatalf("Failed to unmarshal certs for testing: %v", err)
	}

	roots := x509.NewCertPool()
	// last cert is the root
	roots.AddCert(certs[2])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(certs[0])
	intermediates.AddCert(certs[1])

	embeddedRoots, err := fulcioroots.Get()
	if err != nil {
		t.Fatalf("Failed to get embedded fulcioroots for testing")
	}
	embeddedIntermediates, err := fulcioroots.GetIntermediates()
	if err != nil {
		t.Fatalf("Failed to get embedded fulcioroots for testing")
	}

	embeddedCTLogKeys, err := cosign.GetCTLogPubs(context.Background())
	if err != nil {
		t.Fatalf("Failed to get embedded CTLog Public keys for testing")
	}

	marshalledPK, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(ctfePublicKey))
	if err != nil {
		t.Fatalf("Failed to unmarshal CTLog public key: %v", err)
	}

	skRekor := config.SigstoreKeys{
		TLogs: []config.TransparencyLogInstance{{
			PublicKey: []byte(rekorPublicKey),
			LogID:     "rekor-logid",
			BaseURL:   *apis.HTTPS("rekor.example.com"),
		}},
	}
	skFulcio := config.SigstoreKeys{
		CertificateAuthorities: []config.CertificateAuthority{{
			Subject: config.DistinguishedName{
				Organization: "testorg",
				CommonName:   "testcommonname",
			},
			CertChain: []byte(certChain),
		}},
		CTLogs: []config.TransparencyLogInstance{{LogID: ctfeLogID, PublicKey: []byte(ctfePublicKey)}},
	}
	skCombined := config.SigstoreKeys{
		TLogs: []config.TransparencyLogInstance{{
			PublicKey: []byte(rekorPublicKey),
			LogID:     "rekor-logid",
			BaseURL:   *apis.HTTPS("rekor.example.com"),
		}},
		CertificateAuthorities: []config.CertificateAuthority{{
			Subject: config.DistinguishedName{
				Organization: "testorg",
				CommonName:   "testcommonname",
			},
			CertChain: []byte(certChain),
		}},
		CTLogs: []config.TransparencyLogInstance{{LogID: ctfeLogID, PublicKey: []byte(ctfePublicKey)}},
	}
	c := &config.Config{
		SigstoreKeysConfig: &config.SigstoreKeysMap{
			SigstoreKeys: map[string]config.SigstoreKeys{
				"test-trust-rekor":    skRekor,
				"test-trust-fulcio":   skFulcio,
				"test-trust-combined": skCombined,
			},
		},
	}
	testCtx := config.ToContext(context.Background(), c)

	tests := []struct {
		name          string
		authority     webhookcip.Authority
		wantErr       string
		wantCheckOpts *cosign.CheckOpts
		ctx           context.Context
		wantClient    bool
	}{{
		name: "no trustroots, uses embedded",
		authority: webhookcip.Authority{
			CTLog:   &v1alpha1.TLog{URL: apis.HTTPS("rekor.sigstore.dev")},
			Keyless: &webhookcip.KeylessRef{URL: apis.HTTPS("fulcio.sigstore.dev")},
		},
		wantCheckOpts: &cosign.CheckOpts{
			RekorPubKeys:      &cosign.TrustedTransparencyLogPubKeys{Keys: map[string]cosign.TransparencyLogPubKey{embeddedLogID: {PubKey: embeddedPK, Status: tuf.Active}}},
			RootCerts:         embeddedRoots,
			IntermediateCerts: embeddedIntermediates,
			CTLogPubKeys:      embeddedCTLogKeys,
		},
		wantClient: true,
	}, {
		name: "SigstoreKeys does not exist for Rekor",
		authority: webhookcip.Authority{
			Name: "test-authority",
			CTLog: &v1alpha1.TLog{
				URL:          apis.HTTPS("rekor.example.com"),
				TrustRootRef: "not-there"}},
		wantErr: "getting Rekor public keys: test-authority: fetching keys for trustRootRef: trustRootRef not-there not found",
		ctx:     testCtx,
	}, {
		name: "SigstoreKeys does not exist for Fulcio",
		authority: webhookcip.Authority{
			Name: "test-authority",
			Keyless: &webhookcip.KeylessRef{
				URL:          apis.HTTPS("fulcio.example.com"),
				TrustRootRef: "not-there"}},
		wantErr: "getting Fulcio certs: test-authority: trustRootRef not-there not found",
		ctx:     testCtx,
	}, {
		name: "trustroot found, Rekor",
		authority: webhookcip.Authority{
			CTLog: &v1alpha1.TLog{
				URL:          apis.HTTPS("rekor.example.com"),
				TrustRootRef: "test-trust-rekor"}},
		ctx:        testCtx,
		wantClient: true,
		wantCheckOpts: &cosign.CheckOpts{
			RekorPubKeys: &cosign.TrustedTransparencyLogPubKeys{Keys: map[string]cosign.TransparencyLogPubKey{"rekor-logid": {PubKey: ecpk, Status: tuf.Active}}},
		},
	}, {
		name: "trustroot found, Fulcio",
		authority: webhookcip.Authority{
			Keyless: &webhookcip.KeylessRef{
				URL:          apis.HTTPS("fulcio.example.com"),
				TrustRootRef: "test-trust-fulcio"}},
		ctx: testCtx,
		wantCheckOpts: &cosign.CheckOpts{
			RootCerts:         roots,
			IntermediateCerts: intermediates,
			IgnoreTlog:        true,
			CTLogPubKeys:      &cosign.TrustedTransparencyLogPubKeys{Keys: map[string]cosign.TransparencyLogPubKey{ctfeLogID: {PubKey: marshalledPK, Status: tuf.Active}}},
		},
	}, {
		name: "trustroot found, combined, with Identities",
		authority: webhookcip.Authority{
			CTLog: &v1alpha1.TLog{
				URL:          apis.HTTPS("rekor.example.com"),
				TrustRootRef: "test-trust-rekor"},
			Keyless: &webhookcip.KeylessRef{
				Identities: []v1alpha1.Identity{{
					Issuer:  "issuer",
					Subject: "subject",
				}},
				URL:          apis.HTTPS("rekor.example.com"),
				TrustRootRef: "test-trust-combined"}},
		ctx:        testCtx,
		wantClient: true,
		wantCheckOpts: &cosign.CheckOpts{
			RootCerts:         roots,
			IntermediateCerts: intermediates,
			RekorPubKeys:      &cosign.TrustedTransparencyLogPubKeys{Keys: map[string]cosign.TransparencyLogPubKey{"rekor-logid": {PubKey: ecpk, Status: tuf.Active}}},
			Identities: []cosign.Identity{{
				Issuer:  "issuer",
				Subject: "subject",
			}},
			CTLogPubKeys: &cosign.TrustedTransparencyLogPubKeys{Keys: map[string]cosign.TransparencyLogPubKey{ctfeLogID: {PubKey: marshalledPK, Status: tuf.Active}}},
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tCtx := tc.ctx
			if tCtx == nil {
				tCtx = context.Background()
			}
			gotCheckOpts, err := checkOptsFromAuthority(tCtx, tc.authority)
			if err != nil {
				if tc.wantErr == "" {
					t.Errorf("unexpected error: %v wanted none", err)
				} else if err.Error() != tc.wantErr {
					t.Errorf("unexpected error: %v wanted %q", err, tc.wantErr)
				}
			} else if err == nil && tc.wantErr != "" {
				t.Errorf("wanted error: %q got none", tc.wantErr)
			}
			if tc.wantClient && (gotCheckOpts == nil || gotCheckOpts.RekorClient == nil) {
				t.Errorf("wanted rekor client, but got none")
			} else if !tc.wantClient && gotCheckOpts != nil && gotCheckOpts.RekorClient != nil {
				t.Errorf("did not want rekor client, but got one")
			}
			// nil out the rekorclient since we can't meaningfully diff it, and
			// we check above that we get one when we expect one, and don't when
			// we don't.
			if gotCheckOpts != nil {
				gotCheckOpts.RekorClient = nil
			}
			if diff := cmp.Diff(gotCheckOpts, tc.wantCheckOpts); diff != "" {
				t.Errorf("CheckOpts differ: %s", diff)
			}
		})
	}
}
