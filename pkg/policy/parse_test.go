// Copyright 2023 The Sigstore Authors.
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

package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"knative.dev/pkg/apis"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		want    []*unstructured.Unstructured
		wantErr error
	}{{
		name: "good single object",
		doc: `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: blah
spec: {}
`,
		want: []*unstructured.Unstructured{{
			Object: map[string]interface{}{
				"apiVersion": "policy.sigstore.dev/v1beta1",
				"kind":       "ClusterImagePolicy",
				"metadata": map[string]interface{}{
					"name": "blah",
				},
				"spec": map[string]interface{}{},
			},
		}},
	}, {
		name: "good multi-object",
		doc: `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: blah
spec: {}
---
---
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: foo
spec: {}
---
---
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: bar
spec: {}
`,
		want: []*unstructured.Unstructured{{
			Object: map[string]interface{}{
				"apiVersion": "policy.sigstore.dev/v1beta1",
				"kind":       "ClusterImagePolicy",
				"metadata": map[string]interface{}{
					"name": "blah",
				},
				"spec": map[string]interface{}{},
			},
		}, {
			Object: map[string]interface{}{
				"apiVersion": "policy.sigstore.dev/v1beta1",
				"kind":       "ClusterImagePolicy",
				"metadata": map[string]interface{}{
					"name": "foo",
				},
				"spec": map[string]interface{}{},
			},
		}, {
			Object: map[string]interface{}{
				"apiVersion": "policy.sigstore.dev/v1beta1",
				"kind":       "ClusterImagePolicy",
				"metadata": map[string]interface{}{
					"name": "bar",
				},
				"spec": map[string]interface{}{},
			},
		}},
	}, {
		name: "bad missing apiVersion",
		doc: `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: blah
spec: {}
---
# Missing: apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: foo
spec: {}
---
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: bar
spec: {}
`,
		wantErr: apis.ErrMissingField("[1].apiVersion"),
	}, {
		name: "bad missing kind",
		doc: `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: blah
spec: {}
---
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: foo
spec: {}
---
apiVersion: policy.sigstore.dev/v1beta1
# Missing: kind: ClusterImagePolicy
metadata:
  name: bar
spec: {}
`,
		wantErr: errors.New(`decoding object[2]: error unmarshaling JSON: while decoding JSON: Object 'Kind' is missing in '{"apiVersion":"policy.sigstore.dev/v1beta1","metadata":{"name":"bar"},"spec":{}}'`),
	}, {
		name: "bad missing apiVersion",
		doc: `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  # Missing: name: blah
sp dec: {}
---
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: foo
spec: {}
---
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: bar
spec: {}
`,
		wantErr: apis.ErrMissingField("[0].metadata.name"),
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotErr := Parse(context.Background(), test.doc)

			switch {
			case (gotErr != nil) != (test.wantErr != nil):
				t.Fatalf("Parse() = %v, wanted %v", gotErr, test.wantErr)
			case gotErr != nil && gotErr.Error() != test.wantErr.Error():
				t.Fatalf("Parse() = %v, wanted %v", gotErr, test.wantErr)
			case gotErr != nil:
				return // This was an error test.
			}

			if diff := cmp.Diff(got, test.want); diff != "" {
				t.Errorf("Parse (-got, +want) = %s", diff)
			}
		})
	}
}

func TestParseCIP(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		want    []*v1alpha1.ClusterImagePolicy
		wantErr error
	}{{
		name: "good alpha object",
		doc: `
apiVersion: policy.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: blah
spec:
  images:
  - glob: '**'
  authorities:
  - static:
      action: pass
`,
		want: []*v1alpha1.ClusterImagePolicy{{
			TypeMeta: v1.TypeMeta{
				APIVersion: "policy.sigstore.dev/v1alpha1",
				Kind:       "ClusterImagePolicy",
			},
			ObjectMeta: v1.ObjectMeta{
				Name: "blah",
			},
			Spec: v1alpha1.ClusterImagePolicySpec{
				Images: []v1alpha1.ImagePattern{{
					Glob: "**",
				}},
				Authorities: []v1alpha1.Authority{{
					Static: &v1alpha1.StaticRef{
						Action: "pass",
					},
				}},
			},
		}},
	}, {
		name: "good beta object",
		doc: `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: blah
spec:
  images:
  - glob: '**'
  authorities:
  - static:
      action: pass
`,
		want: []*v1alpha1.ClusterImagePolicy{{
			// TODO(mattmoor): We should be setting TypeMeta when converting.
			// TypeMeta: v1.TypeMeta{
			// 	APIVersion: "policy.sigstore.dev/v1alpha1",
			// 	Kind:       "ClusterImagePolicy",
			// },
			ObjectMeta: v1.ObjectMeta{
				Name: "blah",
			},
			Spec: v1alpha1.ClusterImagePolicySpec{
				Images: []v1alpha1.ImagePattern{{
					Glob: "**",
				}},
				Authorities: []v1alpha1.Authority{{
					Static: &v1alpha1.StaticRef{
						Action: "pass",
					},
				}},
			},
		}},
	}, {
		name: "early validation failure",
		doc: `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: blah
spec:
  bad: field
`,
		wantErr: errors.New(`unable to unmarshal: json: unknown field "bad"`),
	}, {
		name: "non CIP resource",
		doc: `
apiVersion: v1
kind: Secret
metadata:
  name: blah
  namespace: cosign-system
stringData:
  key: value
`,
		want: []*v1alpha1.ClusterImagePolicy{},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _, gotErr := ParseClusterImagePolicies(context.Background(), test.doc)

			switch {
			case (gotErr != nil) != (test.wantErr != nil):
				t.Fatalf("Parse() = %v, wanted %v", gotErr, test.wantErr)
			case gotErr != nil && gotErr.Error() != test.wantErr.Error():
				t.Fatalf("Parse() = %v, wanted %v", gotErr, test.wantErr)
			case gotErr != nil:
				return // This was an error test.
			}

			if diff := cmp.Diff(got, test.want); diff != "" {
				t.Errorf("Parse (-got, +want) = %s", diff)
			}
		})
	}
}
