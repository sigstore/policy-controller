//
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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/ptr"
)

func TestPodScalableIsScalingDown(t *testing.T) {
	original := &PodScalable{
		Spec: PodScalableSpec{
			Replicas: ptr.Int32(2),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "blah",
						Image: "busybox",
					}},
				},
			},
		},
	}
	tests := []struct {
		name string
		new  *PodScalable
		with func(context.Context) context.Context
		want bool
	}{{
		name: "not in update",
		new:  original.DeepCopy(),
		want: false,
	}, {
		name: "scaling up",
		new: &PodScalable{
			Spec: PodScalableSpec{
				Replicas: ptr.Int32(4),
			}},
		want: false,
		with: func(ctx context.Context) context.Context {
			return apis.WithinUpdate(ctx, original)
		},
	}, {
		name: "scaling down",
		new: &PodScalable{
			Spec: PodScalableSpec{
				Replicas: ptr.Int32(1),
			}},
		want: true,
		with: func(ctx context.Context) context.Context {
			return apis.WithinUpdate(ctx, original)
		},
	}, {
		name: "scaling down with /scale",
		new: &PodScalable{
			Spec: PodScalableSpec{
				Replicas: ptr.Int32(1),
			}},
		want: true,
		with: func(ctx context.Context) context.Context {
			return apis.WithinSubResourceUpdate(ctx, original, "scale")
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.with != nil {
				ctx = tc.with(ctx)
			}
			if got := tc.new.IsScalingDown(ctx); tc.want != got {
				t.Errorf("Unexpected scaling down result, want %v got %v", tc.want, got)
			}
		})
	}
}
