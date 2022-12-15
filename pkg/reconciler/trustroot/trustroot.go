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

package trustroot

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign/fulcioverifier/ctutil"
	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	trustrootreconciler "github.com/sigstore/policy-controller/pkg/client/injection/reconciler/policy/v1alpha1/trustroot"
	"github.com/sigstore/policy-controller/pkg/reconciler/trustroot/resources"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"knative.dev/pkg/logging"
	"knative.dev/pkg/reconciler"
	"knative.dev/pkg/system"
)

// Reconciler implements ConfigMap reconciler.
// TrustRoot resources.
type Reconciler struct {
	configmaplister corev1listers.ConfigMapLister
	kubeclient      kubernetes.Interface
}

// Check that our Reconciler implements Interface as well as finalizer
var _ trustrootreconciler.Interface = (*Reconciler)(nil)
var _ trustrootreconciler.Finalizer = (*Reconciler)(nil)

// ReconcileKind implements Interface.ReconcileKind.
func (r *Reconciler) ReconcileKind(ctx context.Context, trustroot *v1alpha1.TrustRoot) reconciler.Event {
	var sigstoreKeys *config.SigstoreKeys
	var err error
	switch {
	case trustroot.Spec.Repository != nil:
		sigstoreKeys, err = r.getSigstoreKeysFromMirrorFS(ctx, trustroot.Spec.Repository)
	case trustroot.Spec.Remote != nil:
		sigstoreKeys, err = r.getSigstoreKeysFromRemote(ctx, trustroot.Spec.Remote)
	case trustroot.Spec.SigstoreKeys != nil:
		sigstoreKeys = &config.SigstoreKeys{}
		sigstoreKeys.ConvertFrom(ctx, trustroot.Spec.SigstoreKeys)
	default:
		err = fmt.Errorf("invalid TrustRoot entry: %s missing repository,remote, and sigstoreKeys", trustroot.Name)
		logging.FromContext(ctx).Errorf("Invalid trustroot entry: %s missing repository,remote, and sigstoreKeys", trustroot.Name)
	}

	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to get Sigstore Keys: %v", err)
		return err
	}
	// LogIDs for Rekor get created from the PublicKey, so we need to construct
	// them before serializing.
	// Note this is identical to what we do with CTLog PublicKeys, but they
	// are not restricted to being only ecdsa.PublicKey.
	for i, tlog := range sigstoreKeys.TLogs {
		pk, err := cryptoutils.UnmarshalPEMToPublicKey(tlog.PublicKey)
		if err != nil {
			return fmt.Errorf("unmarshaling rekor public key %d failed: %w", i, err)
		}
		// This needs to be ecdsa instead of crypto.PublicKey
		// https://github.com/sigstore/cosign/issues/2540
		pkecdsa, ok := pk.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key %d is not ecdsa.PublicKey", i)
		}
		logID, err := ctutil.GetCTLogID(pkecdsa)
		if err != nil {
			return fmt.Errorf("failed to construct LogID for rekor: %w", err)
		}
		sigstoreKeys.TLogs[i].LogID = hex.EncodeToString(logID[:])
	}
	for i, ctlog := range sigstoreKeys.CTLogs {
		pk, err := cryptoutils.UnmarshalPEMToPublicKey(ctlog.PublicKey)
		if err != nil {
			return fmt.Errorf("unmarshaling ctlog public key %d failed: %w", i, err)
		}
		logID, err := ctutil.GetCTLogID(pk)
		if err != nil {
			return fmt.Errorf("failed to construct LogID for ctlog: %w", err)
		}
		sigstoreKeys.CTLogs[i].LogID = hex.EncodeToString(logID[:])
	}

	// See if the CM holding configs exists
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.SigstoreKeysConfigName)
	if err != nil {
		if !apierrs.IsNotFound(err) {
			logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
			return err
		}
		// Does not exist, create it.
		cm, err := resources.NewConfigMap(system.Namespace(), config.SigstoreKeysConfigName, trustroot.Name, sigstoreKeys)
		if err != nil {
			logging.FromContext(ctx).Errorf("Failed to construct configmap: %v", err)
			return err
		}
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Create(ctx, cm, metav1.CreateOptions{})
		return err
	}

	// Check if we need to update the configmap or not.
	patchBytes, err := resources.CreatePatch(system.Namespace(), config.SigstoreKeysConfigName, trustroot.Name, existing.DeepCopy(), sigstoreKeys)
	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to create patch: %v", err)
		return err
	}
	if len(patchBytes) > 0 {
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Patch(ctx, config.SigstoreKeysConfigName, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
		return err
	}
	return nil
}

// FinalizeKind implements Interface.ReconcileKind.
func (r *Reconciler) FinalizeKind(ctx context.Context, trustroot *v1alpha1.TrustRoot) reconciler.Event {
	// See if the CM holding configs even exists
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.SigstoreKeysConfigName)
	if err != nil {
		if !apierrs.IsNotFound(err) {
			// There's very little we can do here. This could happen if it's
			// intermittent error, which is fine when we retry. But if something
			// goofy happens like we lost access to it, then it's a bit of a
			// pickle since the entry will exist there and we can't remove it.
			// So keep trying. Other option would be just to bail.
			logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
			return err
		}
		// Since the CM doesn't exist, there's nothing for us to clean up.
		return nil
	}
	// TrustRoot exists, so remove our entry from it.
	return r.removeTrustRootEntry(ctx, existing, trustroot.Name)
}

// getSigstoreKeys will take a TUF Repository specification, and fetch the
// necessary Keys / Certificates from there for Fulcio, Rekor, and CTLog.
func (r *Reconciler) getSigstoreKeysFromMirrorFS(ctx context.Context, repository *v1alpha1.Repository) (*config.SigstoreKeys, error) {
	// TODO: Uncomment and add proper tests for this.
	/*
		tufClient, err := tuf.TUFClientFromSerializedMirror(ctx, repository.MirrorFS, repository.Targets)
		if err != nil {
			return nil, fmt.Errorf(err, "failed to construct TUF client from mirror: %w", err)
		}

		return tuf.GetSigstoreKeysFromTUF(ctx, tufClient)
		local := client.MemoryLocalStore()
		remote := client.NewFileRemoteStore()
		tufClient := client.NewClient(local, remote)
	*/
	return &config.SigstoreKeys{}, errors.New("not implemented yet")
}

func (r *Reconciler) getSigstoreKeysFromRemote(ctx context.Context, remote *v1alpha1.Remote) (*config.SigstoreKeys, error) {
	return nil, errors.New("not implemented yet")
}

// remoteTrustRootEntry removes a TrustRoot entry from a CM. If no entry exists, it's a nop.
func (r *Reconciler) removeTrustRootEntry(ctx context.Context, cm *corev1.ConfigMap, trustrootName string) error {
	patchBytes, err := resources.CreateRemovePatch(system.Namespace(), config.SigstoreKeysConfigName, cm.DeepCopy(), trustrootName)
	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to create remove patch: %v", err)
		return err
	}
	if len(patchBytes) > 0 {
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Patch(ctx, config.SigstoreKeysConfigName, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
		return err
	}
	return nil
}
