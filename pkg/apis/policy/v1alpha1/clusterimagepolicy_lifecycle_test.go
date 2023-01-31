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

package v1alpha1

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"knative.dev/pkg/apis"
	"knative.dev/pkg/apis/duck"
	duckv1 "knative.dev/pkg/apis/duck/v1"
)

func TestClusterImagePolicyDuckTypes(t *testing.T) {
	tests := []struct {
		name string
		t    duck.Implementable
	}{{
		name: "conditions",
		t:    &duckv1.Conditions{},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := duck.VerifyType(&ClusterImagePolicy{}, test.t)
			if err != nil {
				t.Errorf("VerifyType(ClusterImagePolicy, %T) = %v", test.t, err)
			}
		})
	}
}

func TestClusterImagePolicyGetConditionSet(t *testing.T) {
	r := &ClusterImagePolicy{}

	if got, want := r.GetConditionSet().GetTopLevelConditionType(), apis.ConditionReady; got != want {
		t.Errorf("GetTopLevelCondition=%v, want=%v", got, want)
	}
}

func TestClusterImagePolicyIsReady(t *testing.T) {
	cases := []struct {
		name    string
		status  ClusterImagePolicyStatus
		isReady bool
	}{{
		name:    "empty status should not be ready",
		status:  ClusterImagePolicyStatus{},
		isReady: false,
	}, {
		name: "Single condition type ready should not be ready",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{{
					Type:   ClusterImagePolicyConditionCMUpdated,
					Status: corev1.ConditionTrue,
				}},
			},
		},
		isReady: false,
	}, {
		name: "False condition status should not be ready",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{{
					Type:   ClusterImagePolicyConditionCMUpdated,
					Status: corev1.ConditionFalse,
				}},
			},
		},
		isReady: false,
	}, {
		name: "Unknown condition status should not be ready",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{

				Conditions: duckv1.Conditions{{
					Type:   ClusterImagePolicyConditionReady,
					Status: corev1.ConditionUnknown,
				}},
			},
		},
		isReady: false,
	}, {
		name: "Missing condition status should not be ready",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{{
					Type: ClusterImagePolicyConditionReady,
				}},
			},
		},
		isReady: false,
	}, {
		name: "True condition status should be ready",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{{
					Type:   ClusterImagePolicyConditionReady,
					Status: corev1.ConditionTrue,
				}},
			},
		},
		isReady: true,
	}, {
		name: "All conditions with ready status should be ready",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{{
					Type:   ClusterImagePolicyConditionPoliciesInlined,
					Status: corev1.ConditionTrue,
				}, {
					Type:   ClusterImagePolicyConditionKeysInlined,
					Status: corev1.ConditionTrue,
				}, {
					Type:   ClusterImagePolicyConditionCMUpdated,
					Status: corev1.ConditionTrue,
				}, {
					Type:   ClusterImagePolicyConditionReady,
					Status: corev1.ConditionTrue,
				}},
			},
		},
		isReady: true,
	}, {
		name: "Multiple conditions with ready status false should not be ready",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{{
					Type:   ClusterImagePolicyConditionKeysInlined,
					Status: corev1.ConditionTrue,
				}, {
					Type:   ClusterImagePolicyConditionReady,
					Status: corev1.ConditionFalse,
				}},
			},
		},
		isReady: false,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ClusterImagePolicy{Status: tc.status}
			if e, a := tc.isReady, r.IsReady(); e != a {
				t.Errorf("%q expected: %v got: %v", tc.name, e, a)
			}

			r.Generation = 1
			r.Status.ObservedGeneration = 2
			if r.IsReady() {
				t.Error("Expected IsReady() to be false when Generation != ObservedGeneration")
			}
		})
	}
}

func TestClusterImagePolicyIsFailed(t *testing.T) {
	cases := []struct {
		name     string
		status   ClusterImagePolicyStatus
		isFailed bool
	}{{
		name:     "empty status should not be failed",
		status:   ClusterImagePolicyStatus{},
		isFailed: false,
	}, {
		name: "False condition status should be failed",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{{
					Type:   ClusterImagePolicyConditionReady,
					Status: corev1.ConditionFalse,
				}},
			},
		},
		isFailed: true,
	}, {
		name: "Unknown condition status should not be failed",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{

				Conditions: duckv1.Conditions{{
					Type:   ClusterImagePolicyConditionReady,
					Status: corev1.ConditionUnknown,
				}},
			},
		},
		isFailed: false,
	}, {
		name: "Missing condition status should not be failed",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{{
					Type: ClusterImagePolicyConditionReady,
				}},
			},
		},
		isFailed: false,
	}, {
		name: "True condition status should not be failed",
		status: ClusterImagePolicyStatus{
			Status: duckv1.Status{
				Conditions: duckv1.Conditions{{
					Type:   ClusterImagePolicyConditionReady,
					Status: corev1.ConditionTrue,
				}},
			},
		},
		isFailed: false,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ClusterImagePolicy{Status: tc.status}
			if e, a := tc.isFailed, r.IsFailed(); e != a {
				t.Errorf("%q expected: %v got: %v", tc.name, e, a)
			}
		})
	}
}
