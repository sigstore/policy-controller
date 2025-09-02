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

package clusterimagepolicy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	k8sfake "k8s.io/client-go/kubernetes/fake"
	logtesting "knative.dev/pkg/logging/testing"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/apis/signaturealgo"
	fakecosignclient "github.com/sigstore/policy-controller/pkg/client/injection/client/fake"
	"github.com/sigstore/policy-controller/pkg/client/injection/reconciler/policy/v1alpha1/clusterimagepolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgotesting "k8s.io/client-go/testing"
	"knative.dev/pkg/apis"
	fakekubeclient "knative.dev/pkg/client/injection/kube/client/fake"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/system"
	"knative.dev/pkg/tracker"

	. "github.com/sigstore/policy-controller/pkg/reconciler/testing/v1alpha1"
	. "knative.dev/pkg/reconciler/testing"
	_ "knative.dev/pkg/system/testing"

	"github.com/sigstore/sigstore/pkg/signature/kms/fake"
)

const (
	cipName           = "test-cip"
	cipKMSName        = "test-kms-cip"
	testKey           = "test-cip"
	cipName2          = "test-cip-2"
	testKey2          = "test-cip-2"
	keySecretName     = "publickey-key"
	keylessSecretName = "publickey-keyless"
	glob              = "ghcr.io/example/*"
	fakeKMSKey        = "fakekms://keycip"
	policyCMName      = "policy-configmap"
	policyCMKey       = "policy-configmap-key"

	testPolicy = `predicateType: "cosign.sigstore.dev/attestation/v1"
predicate: Data: "foobar key e2e test"`

	// This is above ran through shasum -a 256. Note that there's no trailing
	// newline.
	testPolicySHA256 = "c694cc08146070e84751ce7416d4befd70ea779071f457df8127586a29ac6580"

	// Same as above with one change just to make it fail
	testPolicySHA256Bad = "c694cc08146070e84751ce7416d4befd70ea779071f457df8107586a29ac6580"

	// Just some public key that was laying around, only format matters.
	validPublicKeyData = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J
RCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==
-----END PUBLIC KEY-----`

	// This is the patch for replacing a single entry in the ConfigMap
	replaceCIPPatch = `[{"op":"replace","path":"/data/test-cip","value":"{\"uid\":\"test-uid\",\"resourceVersion\":\"0123456789\",\"images\":[{\"glob\":\"ghcr.io/example/*\"}],\"authorities\":[{\"name\":\"authority-0\",\"key\":{\"data\":\"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\\n-----END PUBLIC KEY-----\",\"hashAlgorithm\":\"sha256\"}}],\"mode\":\"enforce\"}"}]`

	// This is the patch for adding an entry for non-existing KMS for cipName2
	addCIP2Patch = `[{"op":"add","path":"/data/test-cip-2","value":"{\"uid\":\"test-uid\",\"resourceVersion\":\"0123456789\",\"images\":[{\"glob\":\"ghcr.io/example/*\"}],\"authorities\":[{\"name\":\"authority-0\",\"key\":{\"data\":\"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\\n-----END PUBLIC KEY-----\",\"hashAlgorithm\":\"sha256\"}}],\"mode\":\"enforce\"}"}]`

	// This is the patch for removing the last entry, leaving just the
	// configmap objectmeta, no data.
	removeDataPatch = `[{"op":"remove","path":"/data"}]`

	// This is the patch for removing only a single entry from a map that has
	// two entries but only one is being removed. For key entry
	removeSingleEntryKeyPatch = `[{"op":"remove","path":"/data/test-cip"}]`

	// This is the patch for removing only a single entry from a map that has
	// two entries but only one is being removed. For keyless entry.
	removeSingleEntryKeylessPatch = `[{"op":"remove","path":"/data/test-cip-2"}]`

	// This is the patch for inlined cip policy configmap ref.
	inlinedPolicyPatch = `[{"op":"replace","path":"/data/test-cip","value":"{\"uid\":\"test-uid\",\"resourceVersion\":\"0123456789\",\"images\":[{\"glob\":\"ghcr.io/example/*\"}],\"authorities\":[{\"name\":\"authority-0\",\"static\":{\"action\":\"pass\"}}],\"policy\":{\"name\":\"\",\"predicateType\":\"\",\"type\":\"cue\",\"data\":\"predicateType: \\\"cosign.sigstore.dev/attestation/v1\\\"\\npredicate: Data: \\\"foobar key e2e test\\\"\"},\"mode\":\"enforce\"}"}]`

	// This is the patch for inlined secret for keyless cakey ref data
	inlinedSecretKeylessPatch = `[{"op":"replace","path":"/data/test-cip-2","value":"{\"uid\":\"test-uid\",\"resourceVersion\":\"0123456789\",\"images\":[{\"glob\":\"ghcr.io/example/*\"}],\"authorities\":[{\"name\":\"authority-0\",\"keyless\":{\"identities\":[{\"issuerRegExp\":\"iss.*\",\"subjectRegExp\":\"sub.*\"}],\"ca-cert\":{\"data\":\"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\\n-----END PUBLIC KEY-----\",\"hashAlgorithm\":\"sha256\"}}}],\"mode\":\"enforce\"}"}]`

	// This is the patch for inlined secret with matching resource, version and group
	inlinedSecretKeylessMatchResourcePatch = `[{"op":"replace","path":"/data/test-cip-2","value":"{\"uid\":\"test-uid\",\"resourceVersion\":\"0123456789\",\"images\":[{\"glob\":\"ghcr.io/example/*\"}],\"authorities\":[{\"name\":\"authority-0\",\"keyless\":{\"identities\":[{\"issuerRegExp\":\"iss.*\",\"subjectRegExp\":\"sub.*\"}],\"ca-cert\":{\"data\":\"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\\n-----END PUBLIC KEY-----\",\"hashAlgorithm\":\"sha256\"}}}],\"mode\":\"enforce\",\"match\":[{\"group\":\"apps\",\"version\":\"v1\",\"resource\":\"deployments\"}]}"}]`

	// This is the patch for inlined secret with matching labels
	inlinedSecretKeylessMatchLabelsPatch = `[{"op":"replace","path":"/data/test-cip-2","value":"{\"uid\":\"test-uid\",\"resourceVersion\":\"0123456789\",\"images\":[{\"glob\":\"ghcr.io/example/*\"}],\"authorities\":[{\"name\":\"authority-0\",\"keyless\":{\"identities\":[{\"issuerRegExp\":\"iss.*\",\"subjectRegExp\":\"sub.*\"}],\"ca-cert\":{\"data\":\"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\\n-----END PUBLIC KEY-----\",\"hashAlgorithm\":\"sha256\"}}}],\"mode\":\"enforce\",\"match\":[{\"group\":\"apps\",\"version\":\"v1\",\"resource\":\"replicasets\",\"selector\":{\"matchLabels\":{\"match\":\"match\"}}}]}"}]`

	replaceCIPKeySourcePatch = `[{"op":"replace","path":"/data/test-cip","value":"{\"uid\":\"test-uid\",\"resourceVersion\":\"0123456789\",\"images\":[{\"glob\":\"ghcr.io/example/*\"}],\"authorities\":[{\"name\":\"authority-0\",\"key\":{\"data\":\"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\\n-----END PUBLIC KEY-----\",\"hashAlgorithm\":\"sha256\"},\"source\":[{\"oci\":\"example.com/alternative/signature\",\"signaturePullSecrets\":[{\"name\":\"signaturePullSecretName\"}]}]}],\"mode\":\"enforce\"}"}]`

	replaceCIPKeySourceWithoutOCIPatch = `[{"op":"replace","path":"/data/test-cip","value":"{\"uid\":\"test-uid\",\"resourceVersion\":\"0123456789\",\"images\":[{\"glob\":\"ghcr.io/example/*\"}],\"authorities\":[{\"name\":\"authority-0\",\"key\":{\"data\":\"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\\n-----END PUBLIC KEY-----\",\"hashAlgorithm\":\"sha256\"},\"source\":[{\"signaturePullSecrets\":[{\"name\":\"signaturePullSecretName\"}]}]}],\"mode\":\"enforce\"}"}]`

	resourceVersion = "0123456789"
	uid             = "test-uid"

	statusUpdateFailureFmt = `Failed to update status for "test-cip": invalid value: %s: spec.remote.url
url valid is invalid. host and https scheme are expected`

	invalidSHAMsg = "failed to check sha256sum from policy remote: c694cc08146070e84751ce7416d4befd70ea779071f457df8107586a29ac6580 got c694cc08146070e84751ce7416d4befd70ea779071f457df8127586a29ac6580"
)

var (
	// Just define these here so that we can use them in various identity
	// places where we just need a placeholder.
	placeholderIdentities = []v1alpha1.Identity{{SubjectRegExp: "sub.*", IssuerRegExp: "iss.*"}}
)

func TestReconcile(t *testing.T) {
	privKMSKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating ecdsa private key: %v", err)
	}
	mainContext := context.WithValue(context.Background(), fake.KmsCtxKey{}, privKMSKey)

	// Note that this is just an HTTP server, so it will cause a problem
	// after the Status update because of the upstream does not appear to set
	// the apis.IsInStatusUpdate correctly in the tests. So it validates the
	// status update even though it shouldn't. This is tested elsewhere, so
	// we just work around it here by expecting that benign error.
	policyServerGood := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Write([]byte(testPolicy))
	}))
	t.Cleanup(policyServerGood.Close)
	policyURLGood, err := apis.ParseURL(policyServerGood.URL)
	if err != nil {
		t.Fatalf("Failed to parse the URL: %v", err)
	}
	statusUpdateFailureMsg := fmt.Sprintf(statusUpdateFailureFmt, policyURLGood.String())

	table := TableTest{{
		Name: "bad workqueue key",
		// Make sure Reconcile handles bad keys.
		Key: "too/many/parts",
	}, {
		Name: "key not found",
		// Make sure Reconcile handles good keys that don't exist.
		Key: "foo/not-found",
	}, {
		Name: "ClusterImagePolicy not found",
		Key:  testKey,
	}, {
		Name: "ClusterImagePolicy is being deleted, doesn't exist, no changes",
		Key:  testKey,
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithClusterImagePolicyDeletionTimestamp),
		},
	}, {
		Name: "ClusterImagePolicy with glob and inline key data, added to cm and finalizer",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithUID(uid),
				WithResourceVersion(resourceVersion),
				WithMode("warn"),
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: validPublicKeyData,
					}}))},
		WantCreates: []runtime.Object{
			makeConfigMapWithWarn(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchFinalizers(system.Namespace(), cipName),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-cip" finalizers`),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewClusterImagePolicy(cipName,
				WithUID(uid),
				WithResourceVersion(resourceVersion),
				WithMode("warn"),
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: validPublicKeyData,
					}}),
				MarkReady),
		}},
	}, {
		Name: "ClusterImagePolicy with glob and inline key data, already exists, no patch, no status update",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithUID(uid),
				WithResourceVersion(resourceVersion),
				WithMode("enforce"),
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: validPublicKeyData,
					}}),
				MarkReady),
			makeConfigMap(),
		},
	}, {
		Name: "ClusterImagePolicy with glob and inline key data, needs a patch",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithUID(uid),
				WithResourceVersion(resourceVersion),
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: validPublicKeyData,
					}})),
			makeDifferentConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(replaceCIPPatch),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewClusterImagePolicy(cipName,
				WithUID(uid),
				WithResourceVersion(resourceVersion),
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: validPublicKeyData,
					}}),
				MarkReady),
		}},
	}, {
		Name: "ClusterImagePolicy with glob and inline key data, needs a patch but fails",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName,
				WithUID(uid),
				WithResourceVersion(resourceVersion),
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: validPublicKeyData,
					}})),
			makeDifferentConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(replaceCIPPatch),
		},
		WithReactors: []clientgotesting.ReactionFunc{
			InduceFailure("patch", "configmaps"),
		},
		WantErr: true,
		WantEvents: []string{
			Eventf(corev1.EventTypeWarning, "InternalError", "inducing failure for patch configmaps"),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewClusterImagePolicy(cipName,
				WithUID(uid),
				WithResourceVersion(resourceVersion),
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: validPublicKeyData,
					}}),
				WithInitConditions,
				WithObservedGeneration(1),
				WithMarkInlineKeysOk,
				WithMarkInlinePoliciesOk,
				WithMarkCMUpdateFailed("inducing failure for patch configmaps"),
			),
		}},
	}, {
		Name: "ClusterImagePolicy with glob and KMS key data, added as a patch",
		Key:  testKey2,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewClusterImagePolicy(cipName2,
				WithUID(uid),
				WithResourceVersion(resourceVersion),
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: validPublicKeyData,
					}})),
			makeConfigMap(), // Make the existing configmap
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(addCIP2Patch),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewClusterImagePolicy(cipName2,
				WithUID(uid),
				WithResourceVersion(resourceVersion),
				WithFinalizer,
				WithImagePattern(v1alpha1.ImagePattern{
					Glob: glob,
				}),
				WithAuthority(v1alpha1.Authority{
					Key: &v1alpha1.KeyRef{
						Data: validPublicKeyData,
					}}),
				MarkReady),
		}},
	},
		{
			Name: "ClusterImagePolicy with glob and inline key data, already exists, deleted",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							Data: validPublicKeyData,
						}}),
					WithClusterImagePolicyDeletionTimestamp),
				makeConfigMap(),
			},
			WantPatches: []clientgotesting.PatchActionImpl{
				patchRemoveFinalizers(system.Namespace(), cipName),
				makePatch(removeDataPatch),
			},
			WantEvents: []string{
				Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-cip" finalizers`),
			},
		}, {
			Name: "Two entries, remove only one",
			Key:  testKey2,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName2,
					WithFinalizer,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							Data: validPublicKeyData,
						}}),
					WithClusterImagePolicyDeletionTimestamp),
				makeConfigMapWithTwoEntries(),
			},
			WantPatches: []clientgotesting.PatchActionImpl{
				patchRemoveFinalizers(system.Namespace(), cipName2),
				makePatch(removeSingleEntryKeylessPatch),
			},
			WantEvents: []string{
				Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-cip-2" finalizers`),
			},
		}, {
			Name: "Key with secret, secret does not exist, no entry in configmap",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
				),
				makeEmptyConfigMap(),
			},
			WantErr: true,
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "InternalError", `secret "publickey-key" not found`),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysFailed(`secret "publickey-key" not found`)),
			}},

			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keySecretName),
			},
		}, {
			Name: "Key with secret, secret does not exist, entry removed from configmap",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
				),
				makeConfigMapWithTwoEntries(),
			},
			WantErr: true,
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "InternalError", `secret "publickey-key" not found`),
			},
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(removeSingleEntryKeyPatch),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysFailed(`secret "publickey-key" not found`)),
			}},
			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keySecretName),
			},
		}, {
			Name: "Key with secret, secret does not exist, cm does not exist",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
				),
			},
			WantErr: true,
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "InternalError", `secret "publickey-key" not found`),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysFailed(`secret "publickey-key" not found`)),
			}},
			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keySecretName),
			},
		}, {
			Name: "Keyless with secret, secret does not exist.",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Keyless: &v1alpha1.KeylessRef{
							CACert: &v1alpha1.KeyRef{
								SecretRef: &corev1.SecretReference{
									Name: keylessSecretName,
								},
							},
							Identities: placeholderIdentities,
						}}),
				),
				makeConfigMapWithTwoEntries(),
			},
			WantErr: true,
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "InternalError", `secret "publickey-keyless" not found`),
			},
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(removeSingleEntryKeyPatch),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Keyless: &v1alpha1.KeylessRef{
							CACert: &v1alpha1.KeyRef{
								SecretRef: &corev1.SecretReference{
									Name: keylessSecretName,
								},
							},
							Identities: placeholderIdentities,
						}}),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysFailed(`secret "publickey-keyless" not found`)),
			}},

			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keylessSecretName),
			},
		}, {
			Name: "Key with secret, no data.",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
				),
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: system.Namespace(),
						Name:      keySecretName,
					},
				},
				makeEmptyConfigMap(),
			},
			WantErr: true,
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "InternalError", `secret "publickey-key" contains no data`),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysFailed(`secret "publickey-key" contains no data`)),
			}},
			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keySecretName),
			},
		}, {
			Name: "Key with secret, multiple data entries.",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
				),
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: system.Namespace(),
						Name:      keySecretName,
					},
					Data: map[string][]byte{
						"first":  []byte("first data"),
						"second": []byte("second data"),
					},
				},
				makeEmptyConfigMap(),
			},
			WantErr: true,
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "InternalError", `secret "publickey-key" contains multiple data entries, only one is supported`),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysFailed(`secret "publickey-key" contains multiple data entries, only one is supported`)),
			}},
			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keySecretName),
			},
		}, {
			Name: "Key with secret, secret exists, invalid public key",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
				),
				makeEmptyConfigMap(),
				makeSecret(keySecretName, "garbage secret value, not a public key"),
			},
			WantErr: true,
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "InternalError", `secret "publickey-key" contains an invalid public key: PEM decoding failed`),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysFailed(`secret "publickey-key" contains an invalid public key: PEM decoding failed`)),
			}},
			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keySecretName),
			},
		}, {
			Name: "Key with secret, secret exists, inlined",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
				),
				makeSecret(keySecretName, validPublicKeyData),
			},
			WantCreates: []runtime.Object{
				makeConfigMap(),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							SecretRef: &corev1.SecretReference{
								Name: keySecretName,
							},
						}}),
					MarkReady),
			}},

			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keySecretName),
			},
		}, {
			Name: "Keyless with secret, secret exists, inlined",
			Key:  testKey2,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName2,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Keyless: &v1alpha1.KeylessRef{
							CACert: &v1alpha1.KeyRef{
								SecretRef: &corev1.SecretReference{
									Name: keylessSecretName,
								}},
							Identities: placeholderIdentities,
						}}),
				),
				makeConfigMapWithTwoEntries(),
				makeSecret(keylessSecretName, validPublicKeyData),
			},
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(inlinedSecretKeylessPatch),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName2,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Keyless: &v1alpha1.KeylessRef{
							CACert: &v1alpha1.KeyRef{
								SecretRef: &corev1.SecretReference{
									Name: keylessSecretName,
								}},
							Identities: placeholderIdentities,
						}}),
					MarkReady),
			}},
			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keylessSecretName),
			},
		}, {
			Name: "ClusterImagePolicy with glob and KMS key, added the data after querying the fake signer",
			Key:  cipKMSName,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipKMSName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							KMS:           fakeKMSKey,
							HashAlgorithm: signaturealgo.DefaultSignatureAlgorithm,
						}})),
				makeEmptyConfigMap(), // Make the existing configmap
			},
			WantPatches: []clientgotesting.PatchActionImpl{
				patchKMS(mainContext, t, fakeKMSKey, signaturealgo.DefaultSignatureAlgorithm),
			},
			// TODO(vaikas): We have to do some upstream work here. Doing
			// status updates does not behave correctly by setting the
			// IsInStatusUpdate in Table Driven tests.
			// This means, that even though we're sending a valid request to
			// only patch the status subResource, the validate logic is still
			// ran and results in an error that's not an error in real
			// reconciler.
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "UpdateFailed", `Failed to update status for "test-kms-cip": invalid value: fakekms://keycip: spec.authorities[0].key.kms
malformed KMS format, should be prefixed by any of the supported providers: [awskms:// azurekms:// hashivault:// gcpkms://]`),
			},
			WantErr: true,
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipKMSName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							KMS:           fakeKMSKey,
							HashAlgorithm: signaturealgo.DefaultSignatureAlgorithm,
						}}),
					MarkReady),
			}},
		}, {
			Name: "Key with data, source, and signature pull secrets",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							Data: validPublicKeyData,
						},
						Sources: []v1alpha1.Source{{
							OCI: "example.com/alternative/signature",
							SignaturePullSecrets: []corev1.LocalObjectReference{
								{Name: "signaturePullSecretName"},
							},
						}},
					}),
				),
				makeConfigMap(),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							Data: validPublicKeyData,
						},
						Sources: []v1alpha1.Source{{
							OCI: "example.com/alternative/signature",
							SignaturePullSecrets: []corev1.LocalObjectReference{
								{Name: "signaturePullSecretName"},
							},
						}}}),
					MarkReady),
			}},
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(replaceCIPKeySourcePatch),
			},
		}, {
			Name: "Key with data, source, no oci but signature pull secrets",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							Data: validPublicKeyData,
						},
						Sources: []v1alpha1.Source{{
							SignaturePullSecrets: []corev1.LocalObjectReference{
								{Name: "signaturePullSecretName"},
							},
						}},
					}),
				),
				makeConfigMap(),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							Data: validPublicKeyData,
						},
						Sources: []v1alpha1.Source{{
							SignaturePullSecrets: []corev1.LocalObjectReference{
								{Name: "signaturePullSecretName"},
							},
						}},
					}),
					MarkReady),
			}},
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(replaceCIPKeySourceWithoutOCIPatch),
			},
		}, {
			Name: "ClusterImagePolicy with glob and KMS key, for invalid KMS key",
			Key:  cipKMSName,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipKMSName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							KMS: "gcpkms://blah",
						}},
					)),
				makeEmptyConfigMap(), // Make the existing configmap
			},
			WantErr: true,
			WantPatches: []clientgotesting.PatchActionImpl{
				patchFinalizers(system.Namespace(), cipKMSName),
			},
			WantEvents: []string{
				Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-kms-cip" finalizers`),
				Eventf(corev1.EventTypeWarning, "InternalError", `kms specification should be in the format gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]/cryptoKeyVersions/[VERSION]`),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipKMSName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Key: &v1alpha1.KeyRef{
							KMS: "gcpkms://blah",
						}},
					),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysFailed(`kms specification should be in the format gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]/cryptoKeyVersions/[VERSION]`)),
			}},
		}, {
			Name: "Keyless with match label selector",
			Key:  testKey2,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName2,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithMatch(v1alpha1.MatchResource{
						GroupVersionResource: metav1.GroupVersionResource{
							Group:    "apps",
							Version:  "v1",
							Resource: "replicasets",
						},
						ResourceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"match": "match"},
						},
					}),
					WithAuthority(v1alpha1.Authority{
						Keyless: &v1alpha1.KeylessRef{
							CACert: &v1alpha1.KeyRef{
								SecretRef: &corev1.SecretReference{
									Name: keylessSecretName,
								}},
							Identities: placeholderIdentities,
						}}),
				),
				makeConfigMapWithTwoEntries(),
				makeSecret(keylessSecretName, validPublicKeyData),
			},
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(inlinedSecretKeylessMatchLabelsPatch),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName2,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithMatch(v1alpha1.MatchResource{
						GroupVersionResource: metav1.GroupVersionResource{
							Group:    "apps",
							Version:  "v1",
							Resource: "replicasets",
						},
						ResourceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"match": "match"},
						},
					}),
					WithAuthority(v1alpha1.Authority{
						Keyless: &v1alpha1.KeylessRef{
							CACert: &v1alpha1.KeyRef{
								SecretRef: &corev1.SecretReference{
									Name: keylessSecretName,
								}},
							Identities: placeholderIdentities,
						}}),
					MarkReady),
			}},
			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keylessSecretName),
			},
		}, {
			Name: "Keyless with resource group and version selector",
			Key:  testKey2,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName2,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithMatch(v1alpha1.MatchResource{
						GroupVersionResource: metav1.GroupVersionResource{
							Group:    "apps",
							Version:  "v1",
							Resource: "deployments",
						},
					}),
					WithAuthority(v1alpha1.Authority{
						Keyless: &v1alpha1.KeylessRef{
							CACert: &v1alpha1.KeyRef{
								SecretRef: &corev1.SecretReference{
									Name: keylessSecretName,
								}},
							Identities: placeholderIdentities,
						}}),
				),
				makeConfigMapWithTwoEntries(),
				makeSecret(keylessSecretName, validPublicKeyData),
			},
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(inlinedSecretKeylessMatchResourcePatch),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName2,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithMatch(v1alpha1.MatchResource{
						GroupVersionResource: metav1.GroupVersionResource{
							Group:    "apps",
							Version:  "v1",
							Resource: "deployments",
						},
					}),
					WithAuthority(v1alpha1.Authority{
						Keyless: &v1alpha1.KeylessRef{
							CACert: &v1alpha1.KeyRef{
								SecretRef: &corev1.SecretReference{
									Name: keylessSecretName,
								}},
							Identities: placeholderIdentities,
						}}),
					MarkReady),
			}},
			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingSecret(system.Namespace(), keylessSecretName),
			},
		}, {
			Name: "Static with CIP level policy, configmapref exists, inlined",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Static: &v1alpha1.StaticRef{
							Action: "pass",
						}}),
					WithPolicy(&v1alpha1.Policy{
						Type: "cue",
						ConfigMapRef: &v1alpha1.ConfigMapReference{
							Name: policyCMName,
							Key:  policyCMKey,
						},
					}),
				),
				makeConfigMap(),
				makePolicyConfigMap(policyCMName, map[string]string{policyCMKey: testPolicy}),
			},
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(inlinedPolicyPatch),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Static: &v1alpha1.StaticRef{
							Action: "pass",
						}}),
					WithPolicy(&v1alpha1.Policy{
						Type: "cue",
						ConfigMapRef: &v1alpha1.ConfigMapReference{
							Name: policyCMName,
							Key:  policyCMKey,
						},
					}),
					MarkReady),
			}},

			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingConfigMap(system.Namespace(), policyCMName),
			},
		}, {
			Name: "Static with CIP level policy, configmapref does not exist",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Static: &v1alpha1.StaticRef{
							Action: "pass",
						}}),
					WithPolicy(&v1alpha1.Policy{
						Type: "cue",
						ConfigMapRef: &v1alpha1.ConfigMapReference{
							Name: policyCMName,
							Key:  policyCMKey,
						},
					}),
				),
				makeConfigMap(),
			},
			WantErr: true,
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(removeDataPatch),
			},
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "InternalError", `configmap "policy-configmap" not found`),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Static: &v1alpha1.StaticRef{
							Action: "pass",
						}}),
					WithPolicy(&v1alpha1.Policy{
						Type: "cue",
						ConfigMapRef: &v1alpha1.ConfigMapReference{
							Name: policyCMName,
							Key:  policyCMKey,
						},
					}),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysOk,
					WithMarkInlinePoliciesFailed(`configmap "policy-configmap" not found`),
				),
			}},

			PostConditions: []func(*testing.T, *TableRow){
				AssertTrackingConfigMap(system.Namespace(), policyCMName),
			},
		}, {
			Name: "Static with CIP level URL policy, works",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Static: &v1alpha1.StaticRef{
							Action: "pass",
						}}),
					WithPolicy(&v1alpha1.Policy{
						Type: "cue",
						Remote: &v1alpha1.RemotePolicy{
							URL:       *policyURLGood,
							Sha256sum: testPolicySHA256,
						},
					}),
				),
				makeConfigMap(),
			},
			WantErr: true,
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(inlinedPolicyPatch),
			},
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "UpdateFailed", statusUpdateFailureMsg),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Static: &v1alpha1.StaticRef{
							Action: "pass",
						}}),
					WithPolicy(&v1alpha1.Policy{
						Type: "cue",
						Remote: &v1alpha1.RemotePolicy{
							URL:       *policyURLGood,
							Sha256sum: testPolicySHA256,
						},
					}),
					MarkReady,
				),
			}},
		}, {
			Name: "Static with CIP level URL policy, SHA does not match",
			Key:  testKey,

			SkipNamespaceValidation: true, // Cluster scoped
			Objects: []runtime.Object{
				NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Static: &v1alpha1.StaticRef{
							Action: "pass",
						}}),
					WithPolicy(&v1alpha1.Policy{
						Type: "cue",
						Remote: &v1alpha1.RemotePolicy{
							URL:       *policyURLGood,
							Sha256sum: testPolicySHA256Bad,
						},
					}),
				),
				makeConfigMap(),
			},
			WantErr: true,
			WantPatches: []clientgotesting.PatchActionImpl{
				makePatch(removeDataPatch),
			},
			WantEvents: []string{
				Eventf(corev1.EventTypeWarning, "UpdateFailed", statusUpdateFailureMsg),
			},
			WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
				Object: NewClusterImagePolicy(cipName,
					WithUID(uid),
					WithResourceVersion(resourceVersion),
					WithFinalizer,
					WithImagePattern(v1alpha1.ImagePattern{
						Glob: glob,
					}),
					WithAuthority(v1alpha1.Authority{
						Static: &v1alpha1.StaticRef{
							Action: "pass",
						}}),
					WithPolicy(&v1alpha1.Policy{
						Type: "cue",
						Remote: &v1alpha1.RemotePolicy{
							URL:       *policyURLGood,
							Sha256sum: testPolicySHA256Bad,
						},
					}),
					WithInitConditions,
					WithObservedGeneration(1),
					WithMarkInlineKeysOk,
					WithMarkInlinePoliciesFailed(invalidSHAMsg),
				),
			}},
		},
	}

	logger := logtesting.TestLogger(t)
	table.Test(t, MakeFactory(func(ctx context.Context, listers *Listers, _ configmap.Watcher) controller.Reconciler {
		r := &Reconciler{
			secretlister:    listers.GetSecretLister(),
			configmaplister: listers.GetConfigMapLister(),
			kubeclient:      fakekubeclient.Get(ctx),
			tracker:         ctx.Value(TrackerKey).(tracker.Interface),
		}
		return clusterimagepolicy.NewReconciler(ctx, logger,
			fakecosignclient.Get(ctx), listers.GetClusterImagePolicyLister(),
			controller.GetEventRecorder(ctx),
			r)
	},
		false,
		logger,
		privKMSKey,
	))
}

func makeSecret(name, secret string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      name,
		},
		Data: map[string][]byte{
			"publicKey": []byte(secret),
		},
	}
}

func makePolicyConfigMap(name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      name,
		},
		Data: data,
	}
}

func makeEmptyConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.ImagePoliciesConfigName,
		},
	}
}

func makeConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.ImagePoliciesConfigName,
		},
		Data: map[string]string{
			cipName: `{"uid":"test-uid","resourceVersion":"0123456789","images":[{"glob":"ghcr.io/example/*"}],"authorities":[{"name":"authority-0","key":{"data":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END PUBLIC KEY-----","hashAlgorithm":"sha256"}}],"mode":"enforce"}`,
		},
	}
}

func makeConfigMapWithWarn() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.ImagePoliciesConfigName,
		},
		Data: map[string]string{
			cipName: `{"uid":"test-uid","resourceVersion":"0123456789","images":[{"glob":"ghcr.io/example/*"}],"authorities":[{"name":"authority-0","key":{"data":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END PUBLIC KEY-----","hashAlgorithm":"sha256"}}],"mode":"warn"}`,
		},
	}
}

func patchKMS(ctx context.Context, t *testing.T, kmsKey, hashAlgorithm string) clientgotesting.PatchActionImpl {
	pubKey, err := getKMSPublicKey(ctx, kmsKey, hashAlgorithm)
	if err != nil {
		t.Fatalf("Failed to read KMS key ID %q: %v", kmsKey, err)
	}

	patch := `[{"op":"add","path":"/data","value":{"test-kms-cip":"{\"uid\":\"test-uid\",\"resourceVersion\":\"0123456789\",\"images\":[{\"glob\":\"ghcr.io/example/*\"}],\"authorities\":[{\"name\":\"authority-0\",\"key\":{\"data\":\"` + strings.ReplaceAll(pubKey, "\n", "\\\\n") + `\",\"hashAlgorithm\":\"` + hashAlgorithm + `\"}}],\"mode\":\"enforce\"}"}}]`

	return clientgotesting.PatchActionImpl{
		ActionImpl: clientgotesting.ActionImpl{
			Namespace: system.Namespace(),
		},
		Name:  config.ImagePoliciesConfigName,
		Patch: []byte(patch),
	}
}

// Same as above, just forcing an update by changing PUBLIC => NOTPUBLIC
func makeDifferentConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.ImagePoliciesConfigName,
		},
		Data: map[string]string{
			cipName: `{"uid":"test-uid","resourceVersion":"0123456789",
images":[{"glob":"ghcr.io/example/*"}],"authorities":[{"name":"authority-0","key":{"data":"-----BEGIN NOTPUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END NOTPUBLIC KEY-----"}}]}`,
		},
	}
}

// Same as MakeConfigMap but a placeholder for second entry so we can remove it.
func makeConfigMapWithTwoEntries() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.ImagePoliciesConfigName,
		},
		Data: map[string]string{
			cipName:  `{"images":[{"glob":"ghcr.io/example/*"}],"authorities":[{"name":"authority-0","key":{"data":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END PUBLIC KEY-----"}}],"mode":"enforce"}`,
			cipName2: "remove me please",
		},
	}
}

func makePatch(patch string) clientgotesting.PatchActionImpl {
	return clientgotesting.PatchActionImpl{
		ActionImpl: clientgotesting.ActionImpl{
			Namespace: system.Namespace(),
		},
		Name:  config.ImagePoliciesConfigName,
		Patch: []byte(patch),
	}
}

func patchFinalizers(namespace, name string) clientgotesting.PatchActionImpl {
	action := clientgotesting.PatchActionImpl{}
	action.Name = name
	action.Namespace = namespace
	patch := `{"metadata":{"finalizers":["` + finalizerName + `"],"resourceVersion":"` + resourceVersion + `"}}`
	action.Patch = []byte(patch)
	return action
}

func patchRemoveFinalizers(namespace, name string) clientgotesting.PatchActionImpl {
	action := clientgotesting.PatchActionImpl{}
	action.Name = name
	action.Namespace = namespace
	patch := `{"metadata":{"finalizers":[],"resourceVersion":"` + resourceVersion + `"}}`
	action.Patch = []byte(patch)
	return action
}

func TestInlineNamespaces(t *testing.T) {
	tests := []struct {
		name           string
		cip            *v1alpha1.ClusterImagePolicy
		pods           []corev1.Pod
		expectedErr    bool
		expectedErrMsg string
	}{
		{
			name: "Image matches pattern and pod is in correct namespace",
			cip: &v1alpha1.ClusterImagePolicy{
				Spec: v1alpha1.ClusterImagePolicySpec{
					Images: []v1alpha1.ImagePattern{{
						Glob: "ghcr.io/sigstore/timestamp-server**",
					}},
					Policy: &v1alpha1.Policy{
						NamespaceSelector: "namespace-a",
					},
				},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-a",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Image: "ghcr.io/sigstore/timestamp-server:v1",
						}},
					},
				},
			},
			expectedErr:    false,
			expectedErrMsg: "",
		},
		{
			name: "Image matches pattern but pod is in wrong namespace",
			cip: &v1alpha1.ClusterImagePolicy{
				Spec: v1alpha1.ClusterImagePolicySpec{
					Images: []v1alpha1.ImagePattern{{
						Glob: "ghcr.io/sigstore/timestamp-server**",
					}},
					Policy: &v1alpha1.Policy{
						NamespaceSelector: "namespace-a",
					},
				},
			},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-b",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Image: "ghcr.io/sigstore/timestamp-server:v1",
						}},
					},
				},
			},
			expectedErr:    true,
			expectedErrMsg: "image ghcr.io/sigstore/timestamp-server:v1 can only be used in the namespace namespace-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := k8sfake.NewSimpleClientset(&corev1.PodList{Items: tt.pods})
			r := &Reconciler{kubeclient: fakeClient}

			err := r.inlineNamespaces(tt.cip)

			if tt.expectedErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if err.Error() != tt.expectedErrMsg {
					t.Errorf("expected error message %q, got %q", tt.expectedErrMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
