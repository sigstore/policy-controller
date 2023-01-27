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

package v1alpha1

import (
	"knative.dev/pkg/apis"
)

const (
	inlineKeysFailedReason     = "InliningKeysFailed"
	inlinePoliciesFailedReason = "InliningPoliciesFailed"
	updateCMFailedReason       = "UpdatingConfigMap"
)

var cipCondSet = apis.NewLivingConditionSet(
	ClusterImagePolicyConditionKeysInlined,
	ClusterImagePolicyConditionPoliciesInlined,
	ClusterImagePolicyConditionCMUpdated,
)

// GetConditionSet retrieves the condition set for this resource.
// Implements the KRShaped interface.
func (*ClusterImagePolicy) GetConditionSet() apis.ConditionSet {
	return cipCondSet
}

// IsReady returns if the ClusterImagePolicy was compiled successfully to
// ConfigMap.
func (c *ClusterImagePolicy) IsReady() bool {
	cs := c.Status
	return cs.ObservedGeneration == c.Generation &&
		cs.GetCondition(ClusterImagePolicyConditionReady).IsTrue()
}

// IsFailed returns true if the resource has observed
// the latest generation and ready is false.
func (c *ClusterImagePolicy) IsFailed() bool {
	cs := c.Status
	return cs.ObservedGeneration == c.Generation &&
		cs.GetCondition(ClusterImagePolicyConditionReady).IsFalse()
}

// InitializeConditions sets the initial values to the conditions.
func (cs *ClusterImagePolicyStatus) InitializeConditions() {
	cipCondSet.Manage(cs).InitializeConditions()
}

// MarkInlineKeysFailed surfaces a failure that we were unable to inline
// the keys (from secrets or from KMS).
func (cs *ClusterImagePolicyStatus) MarkInlineKeysFailed(msg string) {
	cipCondSet.Manage(cs).MarkFalse(ClusterImagePolicyConditionKeysInlined, inlineKeysFailedReason, msg)
}

// MarkInlineKeysOk marks the status saying that the inlining of the keys
// had no errors.
func (cs *ClusterImagePolicyStatus) MarkInlineKeysOk() {
	cipCondSet.Manage(cs).MarkTrue(ClusterImagePolicyConditionKeysInlined)
}

// MarkInlinePoliciesFailed surfaces a failure that we were unable to inline
// the policies, either from ConfigMap or from URL.
func (cs *ClusterImagePolicyStatus) MarkInlinePoliciesFailed(msg string) {
	cipCondSet.Manage(cs).MarkFalse(ClusterImagePolicyConditionPoliciesInlined, inlinePoliciesFailedReason, msg)
}

// MarkInlinePoliciesdOk marks the status saying that the inlining of the
// policies had no errors.
func (cs *ClusterImagePolicyStatus) MarkInlinePoliciesOk() {
	cipCondSet.Manage(cs).MarkTrue(ClusterImagePolicyConditionPoliciesInlined)
}

// MarkCMUpdateFailed surfaces a failure that we were unable to reflect the
// CIP into the compiled ConfigMap.
func (cs *ClusterImagePolicyStatus) MarkCMUpdateFailed(msg string) {
	cipCondSet.Manage(cs).MarkFalse(ClusterImagePolicyConditionCMUpdated, updateCMFailedReason, msg)
}

// MarkCMUpdated marks the status saying that the ConfigMap has been updated.
func (cs *ClusterImagePolicyStatus) MarkCMUpdatedOK() {
	cipCondSet.Manage(cs).MarkTrue(ClusterImagePolicyConditionCMUpdated)
}
