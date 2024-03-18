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
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"knative.dev/pkg/apis"
	logtesting "knative.dev/pkg/logging/testing"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	fakecosignclient "github.com/sigstore/policy-controller/pkg/client/injection/client/fake"
	"github.com/sigstore/policy-controller/pkg/client/injection/reconciler/policy/v1alpha1/trustroot"
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
		MIIFwzCCA6ugAwIBAgIIK7xb+rqY4gEwDQYJKoZIhvcNAQELBQAwfjEMMAoGA1UE
		BhMDVVNBMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNp
		c2NvMRYwFAYDVQQJEw01NDggTWFya2V0IFN0MQ4wDAYDVQQREwU1NzI3NDEZMBcG
		A1UEChMQTGludXggRm91bmRhdGlvbjAeFw0yMjEyMDgwMjE3NTFaFw0yMzEyMDgw
		MjE3NTFaMH4xDDAKBgNVBAYTA1VTQTETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQG
		A1UEBxMNU2FuIEZyYW5jaXNjbzEWMBQGA1UECRMNNTQ4IE1hcmtldCBTdDEOMAwG
		A1UEERMFNTcyNzQxGTAXBgNVBAoTEExpbnV4IEZvdW5kYXRpb24wggIiMA0GCSqG
		SIb3DQEBAQUAA4ICDwAwggIKAoICAQC142Ejlg2QxIwpNjbaeW/ft9sH1TXU6CWg
		bsvVp77vRgckSnpM3RTC/gwEwJHtX+GOTrP9ro6nFJN3G3hcFnaMHLKdGrof9iHu
		/w/lZLwQzXzVT+0ZyZxytHAWGFBvmYM4J33jH6Dj9PvqONwtSBSmZBPc/H/8EvYs
		UzxPWukhOtotSH3VXDqZ4jl96MLe0+5g2Wi7MxRX44X1RiPS14ba1ES538bThhcQ
		4SMj3uhbdsCIkcm7eF4EY3pEXQpXEEGnZGfwYgQr+6cT07Zd/WDM0NX3KxH6qRk9
		gDjPnfcMuFbOTbfD/nuvx6FNX6OUrzrZSglkLvcPIBVOW7Ln41LAb7aXmbWLFEJn
		uLooPpYYr+6NhnFDNGpsBKGKr/kvbQyDKKst3CKj9otPS1363ni41qnoA7YWSqxw
		z4185dKKc+Y7yvJQsRlr6qG1sNLO+c77fSS5VZImzNozBcRkuLJFlX+WB0uzgQU5
		s45IZW+fK92nfu8MmKjzHR+idyr4OyjS0YSN3GMgc0UP7K6hVphLedApFpykBSFG
		UgiPZwrT+mGSVgmOXq5n1dQTCD14lEh2qt3/rff8zNc0CMANWybaMGBGQ4bhVVXe
		RKYx9u2PZjPv53p7Yb/DCdqnGEDw/HCBDiCs4oYe4daE36xUojxDSm3DaeNG68z9
		RL7gfUjAxQIDAQABo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB
		/wIBATAdBgNVHQ4EFgQUf+lbNX0Wh4h+Q0SRthRK+KfLjqEwDQYJKoZIhvcNAQEL
		BQADggIBAEhJja0ZSKwXcaOXCYRXTE06+JbpezI5LevBhmbRQK789Rq10JeAXa7m
		EToRGlGFLH2uDT11msFKyM3v67KlE1SYVcqKmClYfIVEYH3La0uI+9rHZnWgb4Bl
		y1B8wblKJzhYQD9Z4H/gs+BAsoRX5VoFyIgkNBk1p3ftaVCbkQvS0OYtYs5iw4eK
		cI71/IsTIT3Zppj9R8IGsqwLKgzfnyNcFJdz+ohc6V22PjZMEBHCsHPO4av2LlWK
		5Y1flL+2bqTqbmO/bjfX0w4Z1DuojRcOZF7SH4O3Qu2Y7/69gH7Cp0niVCm5z+S5
		011V6PvMjrmiE+xVkxLHbYEgocbFhd5DciMCXpvsuDZojaI3FREmBqiIhKoki3rb
		wuElya78bMwkZ1krp76nWso47/0+51io/WriAdr0cjmzonho7RqIE3DC77CEMkag
		ZvKSmL3sff+WNSrnPlznK19NA2z4ImW9MszqPrCTQGP//BBu7SamzofVM9f4PAIr
		FTpnW6sGdpCzP8E0WUu9B+viKrtfM/9sxnI9WhfJPdrEP0iZW3vhwvgQbKb5D2OS
		U4nrVov6BWr/BnhQK8IXo1tq3j8FCRIoleXNhks4gnkOaDsW2KtVqwtK3iO3BvPb
		L5w0gdLjwMLkek72y61Xqz5WxZwNhl5YcmBKuSvmVSHvA68BVSbB
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

// compactJSON compacts the given JSON, as the test data is formatted with
// indentation for readability, but the expected patches are compacted.
func compactJSON(in []byte) []byte {
	out := bytes.NewBuffer([]byte{})
	err := json.Compact(out, in)
	if err != nil {
		panic("error compacting json test data: " + err.Error())
	}
	return out.Bytes()
}

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

// This is the marshalled entry from above keys/certs with fixed values
// (for ease of testing) for other parts.
var marshalledEntry = string(compactJSON(testdata.Get("marshalledEntry.json")))

// this is the marshalled entry for when we construct from the repository.
var marshalledEntryFromMirrorFS = string(compactJSON(testdata.Get("marshalledEntryFromMirrorFS.json")))

var rekorLogID = string(testdata.Get("rekorLogID.txt"))
var ctfeLogID = string(testdata.Get("ctfeLogID.txt"))

// validRepository is a valid tar/gzipped repository representing an air-gap
// TUF repository.
var validRepository = testdata.Get("tufRepo.tar")

// IMPORTANT: The next expiration is on 2024-09-21
// rootJSON is a valid base64 encoded root.json for above TUF repository.
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
	c := &config.SigstoreKeys{}
	c.ConvertFrom(context.Background(), source.Spec.SigstoreKeys)
	for i := range c.TLogs {
		c.TLogs[i].LogID = rekorLogID
	}
	for i := range c.CTLogs {
		c.CTLogs[i].LogID = ctfeLogID
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

// TestConvertFrom tests marshalling / unmarshalling to the configmap and back.
// This is here instead of in the pkg/apis/config because of import cycles and
// having both types v1alpha1.SigstoreTypes and config.SigstoreTypes being
// available makes testing way easier, and due to import cycles we can't put
// that in config and yet import v1alpha1.
func TestConvertFrom(t *testing.T) {
	source := v1alpha1.SigstoreKeys{}

	itemsPerEntry := 2

	// Create TransparencyLogInstances.
	// Values are not valid for proper usage, but we want to make sure
	// we properly handle the serialize/unserialize so we use fixed values
	// for testing that.
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"tlog", "ctlog"} {
			entry := v1alpha1.TransparencyLogInstance{
				BaseURL:       *apis.HTTP(fmt.Sprintf("%s-%d.example.com", prefix, i)),
				HashAlgorithm: fmt.Sprintf("%s-hash-%d", prefix, i),
				PublicKey:     []byte(fmt.Sprintf("%s-publickey-%d", prefix, i)),
			}
			switch prefix {
			case "tlog":
				source.TLogs = append(source.TLogs, entry)
			case "ctlog":
				source.CTLogs = append(source.CTLogs, entry)
			default:
				panic("invalid type")
			}
		}
	}
	// Create CertificateAuthorities.
	// Values are not valid for proper usage, but we want to make sure
	// we properly handle the serialize/unserialize so we use fixed values
	// for testing that.
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"fulcio", "tsa"} {
			entry := v1alpha1.CertificateAuthority{
				Subject: v1alpha1.DistinguishedName{
					Organization: fmt.Sprintf("%s-organization-%d", prefix, i),
					CommonName:   fmt.Sprintf("%s-commonname-%d", prefix, i),
				},
				URI:       *apis.HTTP(fmt.Sprintf("%s-%d.example.com", prefix, i)),
				CertChain: []byte(fmt.Sprintf("%s-certchain-%d", prefix, i)),
			}
			switch prefix {
			case "fulcio":
				source.CertificateAuthorities = append(source.CertificateAuthorities, entry)
			case "tsa":
				source.TimeStampAuthorities = append(source.TimeStampAuthorities, entry)
			default:
				panic("invalid type")
			}
		}
	}
	converted := &config.SigstoreKeys{}
	// convert from v1alpha1 to config and let's marshal to configmap and back
	// to make sure we exercise the path from:
	// v1alpha1 => config => configMap => back (this is what reconciler will
	// use to call cosign verification functions with).
	converted.ConvertFrom(context.Background(), &source)
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
	if len(sk.TLogs) != 2 {
		t.Errorf("Not enough TLog entries, want 2 got %d", len(sk.TLogs))
	}
	if len(sk.CTLogs) != 2 {
		t.Errorf("Not enough CTLog entries, want 2 got %d", len(sk.CTLogs))
	}
	if len(sk.CertificateAuthorities) != 2 {
		t.Errorf("Not enough CertificateAuthority entries, want 2 got %d", len(sk.CertificateAuthorities))
	}
	if len(sk.TimeStampAuthorities) != 2 {
		t.Errorf("Not enough TimestampAuthorities entries, want 2 got %d", len(sk.TimeStampAuthorities))
	}
	// Verify TLog, CTLog
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"tlog", "ctlog"} {
			var entry config.TransparencyLogInstance
			switch prefix {
			case "tlog":
				entry = sk.TLogs[i]
			case "ctlog":
				entry = sk.CTLogs[i]
			default:
				panic("invalid type")
			}
			wantURL := fmt.Sprintf("http://%s-%d.example.com", prefix, i)
			wantHash := fmt.Sprintf("%s-hash-%d", prefix, i)
			wantPublicKey := fmt.Sprintf("%s-publickey-%d", prefix, i)
			if entry.BaseURL.String() != wantURL {
				t.Errorf("Unexpected BaseURL for %s %d wanted %s got %s", prefix, i, wantURL, entry.BaseURL.String())
			}
			if entry.HashAlgorithm != wantHash {
				t.Errorf("Unexpected HashAlgorithm for %s %d wanted %s got %s", prefix, i, wantHash, entry.HashAlgorithm)
			}
			if string(entry.PublicKey) != wantPublicKey {
				t.Errorf("Unexpected PublicKey for %s %d wanted %s got %s", prefix, i, wantPublicKey, string(entry.PublicKey))
			}
		}
	}
	// Verify CertificateAuthority, TimeStampAuthorities
	for i := 0; i < itemsPerEntry; i++ {
		for _, prefix := range []string{"fulcio", "tsa"} {
			var entry config.CertificateAuthority
			switch prefix {
			case "fulcio":
				entry = sk.CertificateAuthorities[i]
			case "tsa":
				entry = sk.TimeStampAuthorities[i]
			default:
				panic("invalid type")
			}
			wantOrganization := fmt.Sprintf("%s-organization-%d", prefix, i)
			wantCommonName := fmt.Sprintf("%s-commonname-%d", prefix, i)
			wantURI := fmt.Sprintf("http://%s-%d.example.com", prefix, i)
			wantCertChain := fmt.Sprintf("%s-certchain-%d", prefix, i)

			if entry.Subject.Organization != wantOrganization {
				t.Errorf("Unexpected Organization for %s %d wanted %s got %s", prefix, i, wantOrganization, entry.Subject.Organization)
			}
			if entry.Subject.CommonName != wantCommonName {
				t.Errorf("Unexpected CommonName for %s %d wanted %s got %s", prefix, i, wantCommonName, entry.Subject.CommonName)
			}
			if string(entry.CertChain) != wantCertChain {
				t.Errorf("Unexpected CertChain for %s %d wanted %s got %s", prefix, i, wantCertChain, string(entry.CertChain))
			}
			if entry.URI.String() != wantURI {
				t.Errorf("Unexpected URI for %s %d wanted %s got %s", prefix, i, wantURI, entry.URI.String())
			}
		}
	}
}
