//
// Copyright 2024 The Sigstore Authors.
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
	"fmt"
	"log"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/reconciler/trustroot"
	"github.com/sigstore/policy-controller/pkg/tuf"
	"sigs.k8s.io/yaml"
)

func GetTrustRoot(raw []byte) (*config.SigstoreKeys, error) {
	tr := &v1alpha1.TrustRoot{}
	if err := yaml.Unmarshal(raw, tr); err != nil {
		log.Fatal(err)
	}

	if tr.Spec.Remote != nil {
		mirror := tr.Spec.Remote.Mirror.String()
		client, err := tuf.ClientFromRemote(context.Background(), mirror, tr.Spec.Remote.Root, tr.Spec.Remote.Targets)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TUF client from remote: %w", err)
		}

		return trustroot.GetSigstoreKeysFromTuf(context.TODO(), client)
	} else if tr.Spec.Repository != nil {
		client, err := tuf.ClientFromSerializedMirror(context.Background(), tr.Spec.Repository.MirrorFS, tr.Spec.Repository.Root, tr.Spec.Repository.Targets, v1alpha1.DefaultTUFRepoPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TUF client from remote: %w", err)
		}

		return trustroot.GetSigstoreKeysFromTuf(context.TODO(), client)
	} else if tr.Spec.SigstoreKeys != nil {
		c, err := config.ConvertSigstoreKeys(context.Background(), tr.Spec.SigstoreKeys)
		if err != nil {
			log.Fatal(err)
		}
		return c, nil
	}
	return nil, fmt.Errorf("provided trust root configuration is invalid")
}
