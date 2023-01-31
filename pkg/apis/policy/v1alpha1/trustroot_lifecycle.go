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

var trCondSet = apis.NewLivingConditionSet(
	TrustRootConditionKeysInlined,
	TrustRootConditionCMUpdated,
)

// GetConditionSet retrieves the condition set for this resource.
// Implements the KRShaped interface.
func (*TrustRoot) GetConditionSet() apis.ConditionSet {
	return trCondSet
}

// IsReady returns if the TrustRoot was compiled successfully to
// ConfigMap.
func (tr *TrustRoot) IsReady() bool {
	ts := tr.Status
	return ts.ObservedGeneration == tr.Generation &&
		ts.GetCondition(TrustRootConditionReady).IsTrue()
}

// IsFailed returns true if the resource has observed
// the latest generation and ready is false.
func (tr *TrustRoot) IsFailed() bool {
	ts := tr.Status
	return ts.ObservedGeneration == tr.Generation &&
		ts.GetCondition(TrustRootConditionReady).IsFalse()
}

// InitializeConditions sets the initial values to the conditions.
func (ts *TrustRootStatus) InitializeConditions() {
	trCondSet.Manage(ts).InitializeConditions()
}

// MarkInlineKeysFailed surfaces a failure that we were unable to inline
// the keys (from secrets or from KMS).
func (ts *TrustRootStatus) MarkInlineKeysFailed(msg string) {
	cipCondSet.Manage(ts).MarkFalse(TrustRootConditionKeysInlined, inlineKeysFailedReason, msg)
}

// MarkInlineKeysOk marks the status saying that the inlining of the keys
// had no errors.
func (ts *TrustRootStatus) MarkInlineKeysOk() {
	cipCondSet.Manage(ts).MarkTrue(TrustRootConditionKeysInlined)
}

// MarkCMUpdateFailed surfaces a failure that we were unable to reflect the
// TrustRoot into the compiled ConfigMap.
func (ts *TrustRootStatus) MarkCMUpdateFailed(msg string) {
	trCondSet.Manage(ts).MarkFalse(TrustRootConditionCMUpdated, updateCMFailedReason, msg)
}

// MarkCMUpdated marks the status saying that the ConfigMap has been updated.
func (ts *TrustRootStatus) MarkCMUpdatedOK() {
	trCondSet.Manage(ts).MarkTrue(TrustRootConditionCMUpdated)
}
