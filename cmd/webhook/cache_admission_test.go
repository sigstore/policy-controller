//
// Copyright 2026 The Sigstore Authors.
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

package main

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	policycontrollerconfig "github.com/sigstore/policy-controller/pkg/config"
	cwebhook "github.com/sigstore/policy-controller/pkg/webhook"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"knative.dev/pkg/configmap"
	rtesting "knative.dev/pkg/reconciler/testing"
	"knative.dev/pkg/system"
	"knative.dev/pkg/webhook"
	wtesting "knative.dev/pkg/webhook/testing"

	_ "knative.dev/pkg/client/injection/kube/informers/admissionregistration/v1/validatingwebhookconfiguration/fake"
	_ "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret/fake"
	_ "knative.dev/pkg/system/testing"
)

const testImage = "registry.example.com/app@sha256:0000000000000000000000000000000000000000000000000000000000000001"

func cipConfigMap(action string, includeSpec bool) *corev1.ConfigMap {
	cip := webhookcip.ClusterImagePolicy{
		UID:             "cip-uid",
		ResourceVersion: "1",
		Images:          []v1alpha1.ImagePattern{{Glob: "registry.example.com/**"}},
		Authorities:     []webhookcip.Authority{{Name: "static", Static: &webhookcip.StaticRef{Action: action}}},
	}
	if includeSpec {
		cip.Policy = &webhookcip.AttestationPolicy{Type: "cue", Data: "spec: {...}", IncludeSpec: &includeSpec}
	}
	b, _ := json.Marshal(cip)
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: system.Namespace(), Name: config.ImagePoliciesConfigName},
		Data:       map[string]string{"cip": string(b)},
	}
}

// spyCache wraps a real LRUCache and counts Get hits/misses.
type spyCache struct {
	*cwebhook.LRUCache
	hits, misses atomic.Int32
}

func (s *spyCache) Get(ctx context.Context, image, uid, resourceVersion string) *cwebhook.CacheResult {
	r := s.LRUCache.Get(ctx, image, uid, resourceVersion)
	if r == nil {
		s.misses.Add(1)
	} else {
		s.hits.Add(1)
	}
	return r
}

func podRequest() *admissionv1.AdmissionRequest {
	pod := corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: testImage}}},
	}
	raw, _ := json.Marshal(pod)
	return &admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
		Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
		Namespace: "default",
		Object:    runtime.RawExtension{Raw: raw},
	}
}

func TestValidatingAdmissionCache(t *testing.T) {
	passCIP := cipConfigMap("pass", false)
	keysCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: system.Namespace(), Name: config.SigstoreKeysConfigName}}
	req := podRequest()
	// Each step optionally pushes a ConfigMap through the watcher, admits the
	// pod, and checks cumulative cache hits/misses.
	type step struct {
		update       *corev1.ConfigMap
		hits, misses int32
		deny         string
	}
	tests := []struct {
		name   string
		enable bool
		cip    *corev1.ConfigMap
		steps  []step
	}{
		{"second admit hits", true, passCIP, []step{{misses: 1}, {misses: 1, hits: 1}}},
		// same resourceVersion: only the onAfterStore purge can cause the miss
		{"config change purges", true, passCIP, []step{{misses: 1}, {update: passCIP, misses: 2}}},
		{"keys change purges", true, passCIP, []step{{misses: 1}, {update: keysCM, misses: 2}}},
		{"includeSpec never cached", true, cipConfigMap("pass", true), []step{{}, {}}},
		{"static deny re-evaluated", true, cipConfigMap("fail", false), []step{
			{misses: 1, deny: "disallowed by static policy"}, {misses: 2, deny: "disallowed by static policy"}}},
		{"cache disabled", false, passCIP, []step{{}, {}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old := *enableCache
			*enableCache = tc.enable
			t.Cleanup(func() { *enableCache = old })

			var spy *spyCache
			oldNew := newResultCache
			newResultCache = func(size int, ttl time.Duration) resultCache {
				spy = &spyCache{LRUCache: cwebhook.NewLRUCache(size, ttl)}
				return spy
			}
			t.Cleanup(func() { newResultCache = oldNew })

			ctx, _ := rtesting.SetupFakeContext(t)
			ctx = webhook.WithOptions(ctx, webhook.Options{SecretName: "webhook-certs"})

			cmw := &configmap.ManualWatcher{Namespace: system.Namespace()}
			ac := NewValidatingAdmissionController(ctx, cmw).Reconciler.(webhook.AdmissionController)
			for _, cm := range []*corev1.ConfigMap{
				tc.cip,
				keysCM,
				{ObjectMeta: metav1.ObjectMeta{Namespace: system.Namespace(), Name: policycontrollerconfig.PolicyControllerConfigName}},
			} {
				cmw.OnChange(cm)
			}
			if (spy != nil) != tc.enable {
				t.Fatalf("cache constructed = %v, want %v", spy != nil, tc.enable)
			}
			if spy == nil {
				spy = &spyCache{}
			}

			for i, s := range tc.steps {
				if s.update != nil {
					cmw.OnChange(s.update)
				}
				resp := ac.Admit(ctx, req)
				if s.deny != "" {
					wtesting.ExpectFailsWith(t, resp, s.deny)
				} else {
					wtesting.ExpectAllowed(t, resp)
				}
				if h, m := spy.hits.Load(), spy.misses.Load(); h != s.hits || m != s.misses {
					t.Errorf("step %d: hits=%d misses=%d, want hits=%d misses=%d", i, h, m, s.hits, s.misses)
				}
			}
		})
	}
}
