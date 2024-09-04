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

package testing

import (
	"context"
	"time"

	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"knative.dev/pkg/apis"
)

const finalizerNameTrustRoot = "trustroots.policy.sigstore.dev"

// TrustRootOption enables further configuration of a ClusterImagePolicy.
type TrustRootOption func(*v1alpha1.TrustRoot)

// NewTrustRoot creates a TrustRoot with TrustRootOptions.
func NewTrustRoot(name string, o ...TrustRootOption) *v1alpha1.TrustRoot {
	tr := &v1alpha1.TrustRoot{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Generation: 1,
		},
	}
	for _, opt := range o {
		opt(tr)
	}
	tr.SetDefaults(context.Background())
	return tr
}

func WithTrustRootUID(uid string) TrustRootOption {
	return func(tr *v1alpha1.TrustRoot) {
		tr.UID = types.UID(uid)
	}
}

func WithTrustRootResourceVersion(resourceVersion string) TrustRootOption {
	return func(tr *v1alpha1.TrustRoot) {
		tr.ResourceVersion = resourceVersion
	}
}

func WithTrustRootDeletionTimestamp(tr *v1alpha1.TrustRoot) {
	t := metav1.NewTime(time.Unix(1e9, 0))
	tr.ObjectMeta.SetDeletionTimestamp(&t)
}

func WithTrustRootFinalizer(tr *v1alpha1.TrustRoot) {
	tr.Finalizers = []string{finalizerNameTrustRoot}
}

// WithSigstoreKeys constructs a TrustRootOption which is suitable
// for reconciler table driven testing. It hardcodes things like
// organizations/common names, and URI/BaseURLs with predictable
// values.
func WithSigstoreKeys(sk map[string]string) TrustRootOption {
	return func(tr *v1alpha1.TrustRoot) {
		tr.Spec.SigstoreKeys = &v1alpha1.SigstoreKeys{
			CertificateAuthorities: []v1alpha1.CertificateAuthority{{
				Subject: v1alpha1.DistinguishedName{
					Organization: "fulcio-organization",
					CommonName:   "fulcio-common-name",
				},
				URI:       *apis.HTTPS("fulcio.example.com"),
				CertChain: []byte(sk["fulcio"]),
			}},
			TLogs: []v1alpha1.TransparencyLogInstance{{
				BaseURL:       *apis.HTTPS("rekor.example.com"),
				HashAlgorithm: "sha-256",
				PublicKey:     []byte(sk["rekor"]),
			}},
			CTLogs: []v1alpha1.TransparencyLogInstance{{
				BaseURL:       *apis.HTTPS("ctfe.example.com"),
				HashAlgorithm: "sha-256",
				PublicKey:     []byte(sk["ctfe"]),
			}},
			TimeStampAuthorities: []v1alpha1.CertificateAuthority{{
				Subject: v1alpha1.DistinguishedName{
					Organization: "tsa-organization",
					CommonName:   "tsa-common-name",
				},
				URI:       *apis.HTTPS("tsa.example.com"),
				CertChain: []byte(sk["tsa"]),
			}},
		}
	}
}

// WithRepository constructs a TrustRootOption which is suitable
// for reconciler table driven testing.
func WithRepository(targets string, root, repository []byte, trustedRootTarget string) TrustRootOption {
	return func(tr *v1alpha1.TrustRoot) {
		tr.Spec.Repository = &v1alpha1.Repository{
			Root:              root,
			MirrorFS:          repository,
			Targets:           targets,
			TrustedRootTarget: trustedRootTarget,
		}
	}
}

func WithInitConditionsTrustRoot(tr *v1alpha1.TrustRoot) {
	tr.Status.InitializeConditions()
}
func WithObservedGenerationTrustRoot(gen int64) TrustRootOption {
	return func(tr *v1alpha1.TrustRoot) {
		tr.Status.ObservedGeneration = gen
	}
}

func MarkReadyTrustRoot(tr *v1alpha1.TrustRoot) {
	WithInitConditionsTrustRoot(tr)
	tr.Status.MarkInlineKeysOk()
	tr.Status.MarkCMUpdatedOK()
	tr.Status.ObservedGeneration = tr.Generation
}

func WithMarkInlineKeysOkTrustRoot(tr *v1alpha1.TrustRoot) {
	tr.Status.MarkInlineKeysOk()
}

func WithMarkInlineKeysFailedTrustRoot(msg string) TrustRootOption {
	return func(tr *v1alpha1.TrustRoot) {
		tr.Status.MarkInlineKeysFailed(msg)
	}
}

func WithMarkCMUpdateFailedTrustRoot(msg string) TrustRootOption {
	return func(tr *v1alpha1.TrustRoot) {
		tr.Status.MarkCMUpdateFailed(msg)
	}
}
