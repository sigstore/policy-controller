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

package resources

import (
	"fmt"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"google.golang.org/protobuf/encoding/protojson"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/apis/duck"
)

// NewConfigMap returns a new ConfigMap with an entry for the given TrustRoot.
func NewConfigMap(ns, name, trName string, sk *config.SigstoreKeys) (*corev1.ConfigMap, error) {
	entry, err := Marshal(sk)
	if err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Data: map[string]string{
			trName: entry,
		},
	}
	return cm, nil
}

// CreatePatch updates a particular entry to see if they are differing and
// returning the patch bytes for it that's suitable for calling
// ConfigMap.Patch with.
func CreatePatch(ns, name, tkName string, cm *corev1.ConfigMap, sk *config.SigstoreKeys) ([]byte, error) { //nolint: revive
	entry, err := Marshal(sk)
	if err != nil {
		return nil, err
	}
	after := cm.DeepCopy()
	if after.Data == nil {
		after.Data = make(map[string]string)
	}
	after.Data[tkName] = entry
	jsonPatch, err := duck.CreatePatch(cm, after)
	if err != nil {
		return nil, fmt.Errorf("creating JSON patch: %w", err)
	}
	if len(jsonPatch) == 0 {
		return nil, nil
	}
	return jsonPatch.MarshalJSON()
}

// CreateRemovePatch removes an entry from the ConfigMap and returns the patch
// bytes for it that's suitable for calling ConfigMap.Patch with.
func CreateRemovePatch(ns, name string, cm *corev1.ConfigMap, tkName string) ([]byte, error) { //nolint: revive
	after := cm.DeepCopy()
	// Just remove it without checking if it exists. If it doesn't, then no
	// patch bytes are created.
	delete(after.Data, tkName)
	jsonPatch, err := duck.CreatePatch(cm, after)
	if err != nil {
		return nil, fmt.Errorf("creating JSON patch: %w", err)
	}
	if len(jsonPatch) == 0 {
		return nil, nil
	}
	return jsonPatch.MarshalJSON()
}

func Marshal(spec *config.SigstoreKeys) (string, error) {
	bytes, err := protojson.Marshal(spec)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
