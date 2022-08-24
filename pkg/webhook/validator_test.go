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
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	"github.com/sigstore/policy-controller/pkg/apis/config"
	policyduckv1beta1 "github.com/sigstore/policy-controller/pkg/apis/duck/v1beta1"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	fakekube "knative.dev/pkg/client/injection/kube/client/fake"
	fakesecret "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret/fake"
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
)

func TestValidatePodSpec(t *testing.T) {
	tag := name.MustParseReference("gcr.io/distroless/static:nonroot")
	// Resolved via crane digest on 2021/09/25
	digest := name.MustParseReference("gcr.io/distroless/static:nonroot@sha256:be5d77c62dbe7fedfb0a4e5ec2f91078080800ab1f18358e5f31fcc8faa023c4")

	ctx, _ := rtesting.SetupFakeContext(t)
	si := fakesecret.Get(ctx)

	secretName := "blah"

	// Non-existent URL for testing complete failure
	badURL := apis.HTTP("http://example.com/")

	// Spin up a Fulcio that responds with a Root Cert
	fulcioServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(fulcioRootCert))
	}))
	t.Cleanup(fulcioServer.Close)
	fulcioURL, err := apis.ParseURL(fulcioServer.URL)
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

	si.Informer().GetIndexer().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      secretName,
		},
		Data: map[string][]byte{
			// Random public key (cosign generate-key-pair) 2021-09-25
			"cosign.pub": []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEapTW568kniCbL0OXBFIhuhOboeox
UoJou2P8sbDxpLiE/v3yLw1/jyOrCPWYHWFXnyyeGlkgSVefG54tNoK7Uw==
-----END PUBLIC KEY-----
`),
		},
	})

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

	v := NewValidator(ctx, secretName)

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
		name: "bad signature",
		ps: &corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "user-container",
				Image: digest.String(),
			}},
		},
		want: &apis.FieldError{
			Message: `bad signature`,
			Paths:   []string{"containers[0].image"},
			Details: digest.String(),
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
										Data:       authorityKeyCosignPubString,
										PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
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
			fe := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s %s", digest.String(), `fetching FulcioRoot: getting root cert: request: parse "http://http:%2F%2Fexample.com%2F/api/v1/rootCert": invalid port ":%2F%2Fexample.com%2F" after host`)
			errs = errs.Also(fe)
			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy-keyless", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s %s", digest.String(), `fetching FulcioRoot: getting root cert: request: parse "http://http:%2F%2Fexample.com%2F/api/v1/rootCert": invalid port ":%2F%2Fexample.com%2F" after host`)
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
										Data:       authorityKeyCosignPubString,
										PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
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
		want: func() *apis.FieldError {
			var errs *apis.FieldError
			fe := apis.ErrGeneric("failed policy: cluster-image-policy", "image").ViaFieldIndex("initContainers", 0)
			fe.Details = fmt.Sprintf("%s secrets \"non-existing-secret\" not found", digest.String())
			errs = errs.Also(fe)

			fe2 := apis.ErrGeneric("failed policy: cluster-image-policy", "image").ViaFieldIndex("containers", 0)
			fe2.Details = fmt.Sprintf("%s secrets \"non-existing-secret\" not found", digest.String())
			errs = errs.Also(fe2)

			return errs
		}(),
		cvs: fail,
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
										Data:       authorityKeyCosignPubString,
										PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
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

				// Check the core mechanics
				got := v.validatePodSpec(testContext, system.Namespace(), test.ps, k8schain.Options{})
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
	si := fakesecret.Get(ctx)

	secretName := "blah"

	si.Informer().GetIndexer().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      secretName,
		},
		Data: map[string][]byte{
			// No data should make us verify against Fulcio.
		},
	})

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx, secretName)

	cvs := cosignVerifySignatures
	defer func() {
		cosignVerifySignatures = cvs
	}()
	// Let's just say that everything is verified.
	pass := func(ctx context.Context, signedImgRef name.Reference, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
		sig, err := static.NewSignature(nil, "")
		if err != nil {
			return nil, false, err
		}
		return []oci.Signature{sig}, true, nil
	}
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
		name: "simple, no error",
		c: &duckv1.CronJob{
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
		cvs: pass,
	}, {
		name: "k8schain error (bad service account)",
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
		want: &apis.FieldError{
			Message: `serviceaccounts "not-found" not found`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec"},
		},
	}, {
		name: "k8schain error (bad pull secret)",
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
		want: &apis.FieldError{
			Message: `secrets "not-found" not found`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec"},
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
	}, {
		name: "bad signature",
		c: &duckv1.CronJob{
			Spec: batchv1.CronJobSpec{
				JobTemplate: batchv1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
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
		want: &apis.FieldError{
			Message: `bad signature`,
			Paths:   []string{"spec.jobTemplate.spec.template.spec.containers[0].image"},
			Details: digest.String(),
		},
		cvs: fail,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cosignVerifySignatures = test.cvs

			// Check the core mechanics
			got := v.ValidateCronJob(context.Background(), test.c)
			if (got != nil) != (test.want != nil) {
				t.Errorf("validateCronJob() = %v, wanted %v", got, test.want)
			} else if got != nil && got.Error() != test.want.Error() {
				t.Errorf("validateCronJob() = %v, wanted %v", got, test.want)
			}
			// Check that we don't block things being deleted.
			cronJob := test.c.DeepCopy()
			if got := v.ValidateCronJob(apis.WithinDelete(context.Background()), cronJob); got != nil {
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
	si := fakesecret.Get(ctx)
	secretName := "blah"
	si.Informer().GetIndexer().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      secretName,
		},
		Data: map[string][]byte{
			// Random public key (cosign generate-key-pair) 2021-09-25
			"cosign.pub": []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEapTW568kniCbL0OXBFIhuhOboeox
UoJou2P8sbDxpLiE/v3yLw1/jyOrCPWYHWFXnyyeGlkgSVefG54tNoK7Uw==
-----END PUBLIC KEY-----
`),
		},
	})

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx, secretName)

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
	si := fakesecret.Get(ctx)
	secretName := "blah"
	si.Informer().GetIndexer().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      secretName,
		},
		Data: map[string][]byte{
			// Random public key (cosign generate-key-pair) 2021-09-25
			"cosign.pub": []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEapTW568kniCbL0OXBFIhuhOboeox
UoJou2P8sbDxpLiE/v3yLw1/jyOrCPWYHWFXnyyeGlkgSVefG54tNoK7Uw==
-----END PUBLIC KEY-----
`),
		},
	})

	kc := fakekube.Get(ctx)
	kc.CoreV1().ServiceAccounts("default").Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}, metav1.CreateOptions{})

	v := NewValidator(ctx, secretName)

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

	ctx, _ := rtesting.SetupFakeContext(t)
	si := fakesecret.Get(ctx)

	secretName := "blah"

	// Non-existent URL for testing complete failure
	badURL := apis.HTTP("http://example.com/")
	t.Logf("badURL: %s", badURL.String())

	// Spin up a Fulcio that responds with a Root Cert
	fulcioServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(fulcioRootCert))
	}))
	t.Cleanup(fulcioServer.Close)
	fulcioURL, err := apis.ParseURL(fulcioServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse fake Fulcio URL")
	}
	t.Logf("fulcioURL: %s", fulcioURL.String())

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

	si.Informer().GetIndexer().Add(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      secretName,
		},
		Data: map[string][]byte{
			// Random public key (cosign generate-key-pair) 2021-09-25
			"cosign.pub": []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEapTW568kniCbL0OXBFIhuhOboeox
UoJou2P8sbDxpLiE/v3yLw1/jyOrCPWYHWFXnyyeGlkgSVefG54tNoK7Uw==
-----END PUBLIC KEY-----
`),
		},
	})

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
		payload := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJjb3NpZ24uc2lnc3RvcmUuZGV2L2F0dGVzdGF0aW9uL3Z1bG4vdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoiZ2hjci5pby9kaXN0cm9sZXNzL3N0YXRpYyIsImRpZ2VzdCI6eyJzaGEyNTYiOiJhMWU4MmY2YTVmNmRmYzczNTE2NWQzNDQyZTdjYzVhNjE1ZjcyYWJhYzNkYjE5NDUyNDgxZjVmM2M5MGZiZmE4In19XSwicHJlZGljYXRlIjp7Imludm9jYXRpb24iOnsicGFyYW1ldGVycyI6bnVsbCwidXJpIjoiaHR0cHM6Ly9naXRodWIuY29tL2Rpc3Ryb2xlc3Mvc3RhdGljL2FjdGlvbnMvcnVucy8yNzU3OTUzMTM5IiwiZXZlbnRfaWQiOiIyNzU3OTUzMTM5IiwiYnVpbGRlci5pZCI6IkNyZWF0ZSBSZWxlYXNlIn0sInNjYW5uZXIiOnsidXJpIjoiaHR0cHM6Ly9naXRodWIuY29tL2FxdWFzZWN1cml0eS90cml2eSIsInZlcnNpb24iOiIwLjI5LjIiLCJkYiI6eyJ1cmkiOiIiLCJ2ZXJzaW9uIjoiIn0sInJlc3VsdCI6eyIkc2NoZW1hIjoiaHR0cHM6Ly9qc29uLnNjaGVtYXN0b3JlLm9yZy9zYXJpZi0yLjEuMC1ydG0uNS5qc29uIiwicnVucyI6W3siY29sdW1uS2luZCI6InV0ZjE2Q29kZVVuaXRzIiwib3JpZ2luYWxVcmlCYXNlSWRzIjp7IlJPT1RQQVRIIjp7InVyaSI6ImZpbGU6Ly8vIn19LCJyZXN1bHRzIjpbXSwidG9vbCI6eyJkcml2ZXIiOnsiZnVsbE5hbWUiOiJUcml2eSBWdWxuZXJhYmlsaXR5IFNjYW5uZXIiLCJpbmZvcm1hdGlvblVyaSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9hcXVhc2VjdXJpdHkvdHJpdnkiLCJuYW1lIjoiVHJpdnkiLCJydWxlcyI6W10sInZlcnNpb24iOiIwLjI5LjIifX19XSwidmVyc2lvbiI6IjIuMS4wIn19LCJtZXRhZGF0YSI6eyJzY2FuU3RhcnRlZE9uIjoiMjAyMi0wNy0yOVQwMjoyODo0MloiLCJzY2FuRmluaXNoZWRPbiI6IjIwMjItMDctMjlUMDI6Mjg6NDhaIn19fQ==","signatures":[{"keyid":"","sig":"MEYCIQDeQXMMojIpNvxEDLDXUC5aAwCbPPr/0uckP8TCcdTLjgIhAJG6M00kY40bz/C90W0FeUc2YcWY+txD4BPXhzd8E+tP"}]}`)
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
		name: "simple, public key, no matches",
		policy: webhookcip.ClusterImagePolicy{
			Authorities: []webhookcip.Authority{{
				Name: "authority-0",
				Key: &webhookcip.KeyRef{
					PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
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
					PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
				},
			}},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Signatures: []PolicySignature{{
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
					PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
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
						// TODO(mattmoor): Is there anything we should encode for key-based?
					}},
				}},
		},
		wantErrs: []string{`fetching FulcioRoot: getting root cert: request: parse "http://http:%2F%2Fexample.com%2F/api/v1/rootCert": invalid port ":%2F%2Fexample.com%2F" after host`},
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
					PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
				},
			}},
		},
		want: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {
					Signatures: []PolicySignature{{
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
							Payload:       []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"cosign.sigstore.dev/attestation/vuln/v1","subject":[{"name":"ghcr.io/distroless/static","digest":{"sha256":"a1e82f6a5f6dfc735165d3442e7cc5a615f72abac3db19452481f5f3c90fbfa8"}}],"predicate":{"invocation":{"parameters":null,"uri":"https://github.com/distroless/static/actions/runs/2757953139","event_id":"2757953139","builder.id":"Create Release"},"scanner":{"uri":"https://github.com/aquasecurity/trivy","version":"0.29.2","db":{"uri":"","version":""},"result":{"$schema":"https://json.schemastore.org/sarif-2.1.0-rtm.5.json","runs":[{"columnKind":"utf16CodeUnits","originalUriBaseIds":{"ROOTPATH":{"uri":"file:///"}},"results":[],"tool":{"driver":{"fullName":"Trivy Vulnerability Scanner","informationUri":"https://github.com/aquasecurity/trivy","name":"Trivy","rules":[],"version":"0.29.2"}}}],"version":"2.1.0"}},"metadata":{"scanStartedOn":"2022-07-29T02:28:42Z","scanFinishedOn":"2022-07-29T02:28:48Z"}}}`),
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
			got, gotErrs := ValidatePolicy(testContext, system.Namespace(), digest, test.policy)
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
				PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
			},
		}},
	}
	wantErrs := []string{"context canceled before validation completed"}
	cancelFunc()
	_, gotErrs := ValidatePolicy(testContext, system.Namespace(), digest, cip)
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
				PublicKeys: []crypto.PublicKey{authorityKeyCosignPub},
			},
		}},
	}
	wantErrs := []string{"context was canceled before validation completed"}
	cancelFunc()
	_, gotErrs := validatePolicies(testContext, system.Namespace(), digest, map[string]webhookcip.ClusterImagePolicy{"testcip": cip})
	validateErrors(t, wantErrs, gotErrs["internalerror"])
}
