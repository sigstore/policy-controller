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
)

const finalizerName = "clusterimagepolicies.policy.sigstore.dev"

// ClusterImagePolicyOption enables further configuration of a ClusterImagePolicy.
type ClusterImagePolicyOption func(*v1alpha1.ClusterImagePolicy)

// NewClusterImagePolicy creates a ClusterImagePolicy with ClusterImagePolicyOptions.
func NewClusterImagePolicy(name string, o ...ClusterImagePolicyOption) *v1alpha1.ClusterImagePolicy {
	cip := &v1alpha1.ClusterImagePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Generation: 1,
		},
	}
	for _, opt := range o {
		opt(cip)
	}
	cip.SetDefaults(context.Background())
	return cip
}

func WithUID(uid string) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.UID = types.UID(uid)
	}
}

func WithResourceVersion(resourceVersion string) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.ResourceVersion = resourceVersion
	}
}

func WithClusterImagePolicyDeletionTimestamp(cip *v1alpha1.ClusterImagePolicy) {
	t := metav1.NewTime(time.Unix(1e9, 0))
	cip.ObjectMeta.SetDeletionTimestamp(&t)
}

func WithImagePattern(ip v1alpha1.ImagePattern) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Spec.Images = append(cip.Spec.Images, ip)
	}
}

func WithAuthority(a v1alpha1.Authority) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Spec.Authorities = append(cip.Spec.Authorities, a)
	}
}

func WithPolicy(p *v1alpha1.Policy) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Spec.Policy = p
	}
}

func WithMatch(a v1alpha1.MatchResource) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Spec.Match = append(cip.Spec.Match, a)
	}
}

func WithMode(m string) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Spec.Mode = m
	}
}

func WithFinalizer(cip *v1alpha1.ClusterImagePolicy) {
	cip.Finalizers = []string{finalizerName}
}

func WithInitConditions(cip *v1alpha1.ClusterImagePolicy) {
	cip.Status.InitializeConditions()
}
func WithObservedGeneration(gen int64) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Status.ObservedGeneration = gen
	}
}

func MarkReady(cip *v1alpha1.ClusterImagePolicy) {
	WithInitConditions(cip)
	cip.Status.MarkInlineKeysOk()
	cip.Status.MarkInlinePoliciesOk()
	cip.Status.MarkCMUpdatedOK()
	cip.Status.ObservedGeneration = cip.Generation
}

func WithMarkInlineKeysOk(cip *v1alpha1.ClusterImagePolicy) {
	cip.Status.MarkInlineKeysOk()
}

func WithMarkInlineKeysFailed(msg string) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Status.MarkInlineKeysFailed(msg)
	}
}

func WithMarkInlinePoliciesOk(cip *v1alpha1.ClusterImagePolicy) {
	cip.Status.MarkInlinePoliciesOk()
}
func WithMarkInlinePoliciesFailed(msg string) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Status.MarkInlinePoliciesFailed(msg)
	}
}

func WithMarkCMUpdateFailed(msg string) ClusterImagePolicyOption {
	return func(cip *v1alpha1.ClusterImagePolicy) {
		cip.Status.MarkCMUpdateFailed(msg)
	}
}
