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

package trustroot

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"knative.dev/pkg/apis"
	logtesting "knative.dev/pkg/logging/testing"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	fakecosignclient "github.com/sigstore/policy-controller/pkg/client/injection/client/fake"
	"github.com/sigstore/policy-controller/pkg/client/injection/reconciler/policy/v1alpha1/trustroot"
	pbcommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgotesting "k8s.io/client-go/testing"
	fakekubeclient "knative.dev/pkg/client/injection/kube/client/fake"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/system"

	. "github.com/sigstore/policy-controller/pkg/reconciler/testing/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/reconciler/trustroot/resources"
	"github.com/sigstore/policy-controller/pkg/reconciler/trustroot/testdata"
	. "knative.dev/pkg/reconciler/testing"
	_ "knative.dev/pkg/system/testing"
)

const (
	trName   = "test-trustroot"
	testKey  = "test-trustroot"
	tkName2  = "test-trustroot-2"
	testKey2 = "test-trustroot-2"

	resourceVersion = "0123456789"
	uid             = "test-uid"
	uid2            = "test-uid-2"

	// These are the public keys from an airgapped TUF repository.
	/* TODO(vaikas): Uncomment and test these make the roundtrip
		tufCTFE = `-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJvCJi707fv5tMJ1U2TVMZ+uO4dKG
		aEcvjlCkgBCKXbrkumZV0m0dSlK1V1gxEiyQ8y6hk1MxJNe2AZrZUt7a4w==
		-----END PUBLIC KEY-----
	`
		tufFulcio = `-----BEGIN CERTIFICATE-----
		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
		-----END CERTIFICATE-----
	`
		tufRekor = `-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEenlW+tMJ9ymhl858kKiD14CC06x9
		r36rTqTSiLYrdl2ZVE3mOD/KcbyBZM1/RHVKx/g1r3d0YSoVCKbF4DAvcQ==
		-----END PUBLIC KEY-----
	`
	*/

	// Just some formatting strings that make it easier to construct patches
	// to config map.
	replacePatchFmtString = `[{"op":"replace","path":"/data/%s","value":"%s"}]`
	removePatchFmtString  = `[{"op":"remove","path":"/data/%s"}]`
)

// testmap with prepopulated entries for creating TrustRoot resource.
// ctfe   => CTLog Public Key
// fulcio => CertificateAuthority certificate
// rekor  => TLog PublicKey
// tsa    => TimeStampAuthorities certificate chain (root, intermediate, leaf)
var sigstoreKeys = map[string]string{
	"ctfe":   string(testdata.Get("ctfePublicKey.pem")),
	"fulcio": string(testdata.Get("fulcioCertChain.pem")),
	"rekor":  string(testdata.Get("rekorPublicKey.pem")),
	"tsa":    string(testdata.Get("tsaCertChain.pem")),
}

// canonicalizeSigstoreKeys round-trips the SigstoreKeys through protojson so
// the output is deterministic for the current test run. This is necessary
// because protojson has "randomly deterministic" output, meaning it will add
// whitespace randomly depending on the digest of the executable.
// See https://go-review.googlesource.com/c/protobuf/+/151340 and
// https://github.com/golang/protobuf/issues/1121
func canonicalizeSigstoreKeys(in []byte) []byte {
	keys := &config.SigstoreKeys{}
	err := protojson.Unmarshal(in, keys)
	if err != nil {
		panic(err)
	}
	out, err := protojson.Marshal(keys)
	if err != nil {
		panic(err)
	}
	return out
}

// This is the marshalled entry from above keys/certs with fixed values
// (for ease of testing) for other parts.
var marshalledEntry = string(canonicalizeSigstoreKeys(testdata.Get("marshalledEntry.json")))

// this is the marshalled entry for when we construct from the repository.
var marshalledEntryFromMirrorFS = string(canonicalizeSigstoreKeys(testdata.Get("marshalledEntryFromMirrorFS.json")))

var rekorLogID = string(testdata.Get("rekorLogID.txt"))
var ctfeLogID = string(testdata.Get("ctfeLogID.txt"))

// validRepository is a valid tarred repository representing an air-gap
// TUF repository.
var validRepository = testdata.Get("tufRepo.tar")

// IMPORTANT: The next expiration is on 2024-09-21
// rootJSON is a valid root.json for above TUF repository.
var rootJSON = testdata.Get("root.json")

func TestReconcile(t *testing.T) {
	table := TableTest{{
		Name: "bad workqueue key",
		// Make sure Reconcile handles bad keys.
		Key: "too/many/parts",
	}, {
		Name: "key not found",
		// Make sure Reconcile handles good keys that don't exist.
		Key: "foo/not-found",
	}, {
		Name: "TrustRoot not found",
		Key:  testKey,
	}, {
		Name: "TrustRoot is being deleted, doesn't exist, no changes",
		Key:  testKey,
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootDeletionTimestamp),
		},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm created and finalizer",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
			)},
		WantCreates: []runtime.Object{
			makeConfigMapWithSigstoreKeys(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchFinalizers(system.Namespace(), trName),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-trustroot" finalizers`),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				MarkReadyTrustRoot,
			)}},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm exists with entry, no changes",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
			),
			makeConfigMapWithSigstoreKeys(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchFinalizers(system.Namespace(), trName),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-trustroot" finalizers`),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				MarkReadyTrustRoot,
			)}},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm exists with different, replace patched",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
			),
			makeDifferentConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(replacePatchFmtString, trName, marshalledEntry),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
				MarkReadyTrustRoot,
			)}},
	}, {
		Name: "TrustRoot with SigstoreKeys, cm exists with different, replace patched but fails",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
			),
			makeDifferentConfigMap(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			makePatch(replacePatchFmtString, trName, marshalledEntry),
		},
		WithReactors: []clientgotesting.ReactionFunc{
			InduceFailure("patch", "configmaps"),
		},
		WantErr: true,
		WantEvents: []string{
			Eventf(corev1.EventTypeWarning, "InternalError", "inducing failure for patch configmaps"),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
				WithInitConditionsTrustRoot,
				WithObservedGenerationTrustRoot(1),
				WithMarkInlineKeysOkTrustRoot,
				WithMarkCMUpdateFailedTrustRoot("inducing failure for patch configmaps"),
			)}},
	}, {
		Name: "Two SigstoreKeys, one deleted, verify it is removed",
		Key:  testKey2,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
			),
			NewTrustRoot(tkName2,
				WithTrustRootUID(uid2),
				WithTrustRootResourceVersion(resourceVersion),
				WithSigstoreKeys(sigstoreKeys),
				WithTrustRootFinalizer,
				WithTrustRootDeletionTimestamp,
			),
			makeConfigMapWithTwoEntries(),
		},
		WantPatches: []clientgotesting.PatchActionImpl{
			patchRemoveFinalizers(system.Namespace(), testKey2),
			makeRemovePatch(tkName2),
		},
		WantEvents: []string{
			Eventf(corev1.EventTypeNormal, "FinalizerUpdate", `Updated "test-trustroot-2" finalizers`),
		},
	}, {
		Name: "With repository",
		Key:  testKey,

		SkipNamespaceValidation: true, // Cluster scoped
		Objects: []runtime.Object{
			NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithRepository("targets", rootJSON, validRepository),
				WithTrustRootFinalizer,
			),
		},
		WantCreates: []runtime.Object{
			makeConfigMapWithMirrorFS(),
		},
		WantStatusUpdates: []clientgotesting.UpdateActionImpl{{
			Object: NewTrustRoot(trName,
				WithTrustRootUID(uid),
				WithTrustRootResourceVersion(resourceVersion),
				WithRepository("targets", rootJSON, validRepository),
				WithTrustRootFinalizer,
				MarkReadyTrustRoot,
			)}},
	}}

	logger := logtesting.TestLogger(t)
	table.Test(t, MakeFactory(func(ctx context.Context, listers *Listers, cmw configmap.Watcher) controller.Reconciler {
		r := &Reconciler{
			configmaplister: listers.GetConfigMapLister(),
			kubeclient:      fakekubeclient.Get(ctx),
		}
		return trustroot.NewReconciler(ctx, logger,
			fakecosignclient.Get(ctx), listers.GetTrustRootLister(),
			controller.GetEventRecorder(ctx),
			r)
	},
		false,
		logger,
		nil, // Only meaningful for CIP reconciler, but reuse the same factory.
	))
}

func makeConfigMapWithSigstoreKeys() *corev1.ConfigMap {
	ret := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: make(map[string]string),
	}
	source := NewTrustRoot(trName, WithSigstoreKeys(sigstoreKeys))
	c := config.ConvertSigstoreKeys(context.Background(), source.Spec.SigstoreKeys)
	for i := range c.Tlogs {
		c.Tlogs[i].LogId = &config.LogID{KeyId: []byte(rekorLogID)}
	}
	for i := range c.Ctlogs {
		c.Ctlogs[i].LogId = &config.LogID{KeyId: []byte(ctfeLogID)}
	}
	marshalled, err := resources.Marshal(c)
	if err != nil {
		panic("failed to marshal test SigstoreKeys")
	}
	ret.Data[trName] = marshalled
	return ret
}

func makeConfigMapWithMirrorFS() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: map[string]string{"test-trustroot": marshalledEntryFromMirrorFS},
	}
}

// Same as above, just forcing an update because the entry in the configMap
// is not what we expect, it doesn't really matter what it is.
func makeDifferentConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: map[string]string{
			trName: `{"uid":"test-uid","resourceVersion":"0123456789",
images":[{"glob":"ghcr.io/example/*"}],"authorities":[{"name":"authority-0","key":{"data":"-----BEGIN NOTPUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExB6+H6054/W1SJgs5JR6AJr6J35J\nRCTfQ5s1kD+hGMSE1rH7s46hmXEeyhnlRnaGF8eMU/SBJE/2NKPnxE7WzQ==\n-----END NOTPUBLIC KEY-----"}}]}`,
		},
	}
}

// Same as MakeConfigMap but a placeholder for second entry so we can remove it.
func makeConfigMapWithTwoEntries() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: system.Namespace(),
			Name:      config.SigstoreKeysConfigName,
		},
		Data: map[string]string{
			trName:  marshalledEntry,
			tkName2: "remove me please",
		},
	}
}

// makePatch makes a patch that one would be able to patch ConfigMap with.
// fmtstr defines the ops/targets, key is the actual key the operation is
// in the configmap. patch is the unescape quoted (for ease of readability in
// constants) that will then be escaped before creating the patch.
func makePatch(fmtstr, key, patch string) clientgotesting.PatchActionImpl {
	escapedPatch := strings.ReplaceAll(patch, "\"", "\\\"")
	out := fmt.Sprintf(fmtstr, key, escapedPatch)
	return clientgotesting.PatchActionImpl{
		ActionImpl: clientgotesting.ActionImpl{
			Namespace: system.Namespace(),
		},
		Name:  config.SigstoreKeysConfigName,
		Patch: []byte(out),
	}
}

// makeRemovePatch makes a patch suitable for removing from a configmap.
func makeRemovePatch(key string) clientgotesting.PatchActionImpl {
	return clientgotesting.PatchActionImpl{
		ActionImpl: clientgotesting.ActionImpl{
			Namespace: system.Namespace(),
		},
		Name:  config.SigstoreKeysConfigName,
		Patch: []byte(fmt.Sprintf(removePatchFmtString, key)),
	}
}

func patchFinalizers(namespace, name string) clientgotesting.PatchActionImpl {
	action := clientgotesting.PatchActionImpl{}
	action.Name = name
	action.Namespace = namespace
	patch := `{"metadata":{"finalizers":["` + FinalizerName + `"],"resourceVersion":"` + resourceVersion + `"}}`
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

// TestConvertSigstoreKeys tests marshalling / unmarshalling to the configmap and back.
// This is here instead of in the pkg/apis/config because of import cycles and
// having both types v1alpha1.SigstoreTypes and config.SigstoreTypes being
// available makes testing way easier, and due to import cycles we can't put
// that in config and yet import v1alpha1.
func TestConvertSigstoreKeys(t *testing.T) {
	itemsPerEntry := 2

	type key struct {
		pem []byte
		der []byte
	}
	type testTlog struct {
		url           string
		hashAlgorithm string
		publicKey     key
	}
	type testCA struct {
		url        string
		org        string
		commonName string
		certChain  []key
	}
	type testData struct {
		tlogs  []testTlog
		ctlogs []testTlog
		cas    []testCA
		tsas   []testCA
	}

	hashAlgorithms := []string{"sha-256", "sha-512"}
	hashAlgorithmMap := map[string]pbcommon.HashAlgorithm{"sha-256": pbcommon.HashAlgorithm_SHA2_256, "sha-512": pbcommon.HashAlgorithm_SHA2_512}

	test := testData{}

	// construct test data
	for i := 0; i < itemsPerEntry; i++ {
		for _, service := range []string{"tlog", "ctlog"} {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ecdsa key: %v", err)
			}
			der, err := x509.MarshalPKIXPublicKey(priv.Public().(*ecdsa.PublicKey))
			if err != nil {
				t.Fatalf("failed to marshal ecdsa key: %v", err)
			}
			pem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
			tlog := testTlog{
				url:           fmt.Sprintf("https://%s-%d.example.com", service, i),
				hashAlgorithm: hashAlgorithms[i%2],
				publicKey:     key{pem, der},
			}

			switch service {
			case "tlog":
				test.tlogs = append(test.tlogs, tlog)
			case "ctlog":
				test.ctlogs = append(test.ctlogs, tlog)
			}
		}
		for _, service := range []string{"fulcio", "tsa"} {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ecdsa key: %v", err)
			}
			template := x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "Test Certificate",
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().AddDate(1, 0, 0),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
			}
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
			if err != nil {
				t.Fatalf("failed to create x509 certificate: %v", err)
			}
			pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			ca := testCA{
				url:        fmt.Sprintf("https://%s-%d.example.com", service, i),
				org:        fmt.Sprintf("Test Org %d for %s", i, service),
				commonName: fmt.Sprintf("Test CA %d for %s", i, service),
				certChain:  []key{{pem, der}},
			}

			switch service {
			case "fulcio":
				test.cas = append(test.cas, ca)
			case "tsa":
				test.tsas = append(test.tsas, ca)
			}
		}
	}

	// create and populate source
	source := v1alpha1.SigstoreKeys{}

	for _, tlog := range test.tlogs {
		url, err := apis.ParseURL(tlog.url)
		if err != nil {
			t.Fatalf("failed to parse url: %v", err)
		}
		source.TLogs = append(source.TLogs, v1alpha1.TransparencyLogInstance{
			BaseURL:       *url,
			HashAlgorithm: tlog.hashAlgorithm,
			PublicKey:     tlog.publicKey.pem,
		})
	}
	for _, ctlog := range test.ctlogs {
		url, err := apis.ParseURL(ctlog.url)
		if err != nil {
			t.Fatalf("failed to parse url: %v", err)
		}
		source.CTLogs = append(source.CTLogs, v1alpha1.TransparencyLogInstance{
			BaseURL:       *url,
			HashAlgorithm: ctlog.hashAlgorithm,
			PublicKey:     ctlog.publicKey.pem,
		})
	}
	for _, ca := range test.cas {
		url, err := apis.ParseURL(ca.url)
		if err != nil {
			t.Fatalf("failed to parse url: %v", err)
		}
		source.CertificateAuthorities = append(source.CertificateAuthorities, v1alpha1.CertificateAuthority{
			Subject: v1alpha1.DistinguishedName{
				Organization: ca.org,
				CommonName:   ca.commonName,
			},
			URI:       *url,
			CertChain: ca.certChain[0].pem,
		})
	}
	for _, tsa := range test.tsas {
		url, err := apis.ParseURL(tsa.url)
		if err != nil {
			t.Fatalf("failed to parse url: %v", err)
		}
		source.TimeStampAuthorities = append(source.TimeStampAuthorities, v1alpha1.CertificateAuthority{
			Subject: v1alpha1.DistinguishedName{
				Organization: tsa.org,
				CommonName:   tsa.commonName,
			},
			URI:       *url,
			CertChain: tsa.certChain[0].pem,
		})
	}

	// convert from v1alpha1 to config and let's marshal to configmap and back
	// to make sure we exercise the path from:
	// v1alpha1 => config => configMap => back (this is what reconciler will
	// use to call cosign verification functions with).
	converted := config.ConvertSigstoreKeys(context.Background(), &source)
	marshalled, err := resources.Marshal(converted)
	if err != nil {
		t.Fatalf("Failed to marshal entry: %v", err)
	}
	tkMap := map[string]string{"test-entry": marshalled}
	skMap, err := config.NewSigstoreKeysFromMap(tkMap)
	if err != nil {
		t.Fatalf("Failed to construct from map entry: %v", err)
	}
	sk := skMap.SigstoreKeys["test-entry"]
	if len(sk.Tlogs) != 2 {
		t.Errorf("Not enough TLog entries, want 2 got %d", len(sk.Tlogs))
	}
	if len(sk.Ctlogs) != 2 {
		t.Errorf("Not enough CTLog entries, want 2 got %d", len(sk.Ctlogs))
	}
	if len(sk.CertificateAuthorities) != 2 {
		t.Errorf("Not enough CertificateAuthority entries, want 2 got %d", len(sk.CertificateAuthorities))
	}
	if len(sk.TimestampAuthorities) != 2 {
		t.Errorf("Not enough TimestampAuthorities entries, want 2 got %d", len(sk.TimestampAuthorities))
	}
	// Verify TLog, CTLog
	for i := 0; i < itemsPerEntry; i++ {
		for _, service := range []string{"tlog", "ctlog"} {
			var entry *config.TransparencyLogInstance
			var tlog testTlog
			switch service {
			case "tlog":
				entry = sk.Tlogs[i]
				tlog = test.tlogs[i]
			case "ctlog":
				entry = sk.Ctlogs[i]
				tlog = test.ctlogs[i]
			default:
				panic("invalid type")
			}
			if entry.BaseUrl != tlog.url {
				t.Errorf("Unexpected BaseUrl for %s %d wanted %s got %s", service, i, tlog.url, entry.BaseUrl)
			}
			if entry.HashAlgorithm != hashAlgorithmMap[tlog.hashAlgorithm] {
				t.Errorf("Unexpected HashAlgorithm for %s %d wanted %s got %s", service, i, tlog.hashAlgorithm, entry.HashAlgorithm)
			}
			if !bytes.Equal(entry.PublicKey.RawBytes, tlog.publicKey.der) {
				t.Errorf("Unexpected PublicKey for %s %d wanted %s got %s", service, i, tlog.publicKey.der, entry.PublicKey.RawBytes)
			}
		}
	}
	// Verify CertificateAuthority, TimestampAuthorities
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"fulcio", "tsa"} {
			var entry *config.CertificateAuthority
			var ca testCA
			switch prefix {
			case "fulcio":
				entry = sk.CertificateAuthorities[i]
				ca = test.cas[i]
			case "tsa":
				entry = sk.TimestampAuthorities[i]
				ca = test.tsas[i]
			default:
				panic("invalid type")
			}
			if entry.Uri != ca.url {
				t.Errorf("Unexpected Uri for %s %d wanted %s got %s", prefix, i, ca.url, entry.Uri)
			}
			if entry.Subject.Organization != ca.org {
				t.Errorf("Unexpected Organization for %s %d wanted %s got %s", prefix, i, ca.org, entry.Subject.Organization)
			}
			if entry.Subject.CommonName != ca.commonName {
				t.Errorf("Unexpected CommonName for %s %d wanted %s got %s", prefix, i, ca.commonName, entry.Subject.CommonName)
			}
			if !bytes.Equal(entry.CertChain.Certificates[0].RawBytes, ca.certChain[0].der) {
				t.Errorf("Unexpected CertChain for %s %d wanted %s got %s", prefix, i, ca.certChain[0].der, entry.CertChain.Certificates[0].RawBytes)
			}
		}
	}
}
