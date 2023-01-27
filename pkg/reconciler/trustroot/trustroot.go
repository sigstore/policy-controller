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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	trustrootreconciler "github.com/sigstore/policy-controller/pkg/client/injection/reconciler/policy/v1alpha1/trustroot"
	"github.com/sigstore/policy-controller/pkg/reconciler/trustroot/resources"
	"github.com/sigstore/policy-controller/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoretuf "github.com/sigstore/sigstore/pkg/tuf"
	"github.com/theupdateframework/go-tuf/client"
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
	trustroot.Status.InitializeConditions()
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
		// This should not happen since the CRD has been validated.
		err = fmt.Errorf("invalid TrustRoot entry: %s missing repository,remote, and sigstoreKeys", trustroot.Name)
		logging.FromContext(ctx).Errorf("Invalid trustroot entry: %s missing repository,remote, and sigstoreKeys", trustroot.Name)
	}

	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to get Sigstore Keys: %v", err)
		trustroot.Status.MarkInlineKeysFailed(err.Error())
		return err
	}
	trustroot.Status.MarkInlineKeysOk()
	// LogIDs for Rekor get created from the PublicKey, so we need to construct
	// them before serializing.
	// Note this is identical to what we do with CTLog PublicKeys, but they
	// are not restricted to being only ecdsa.PublicKey.
	for i, tlog := range sigstoreKeys.TLogs {
		pk, logID, err := pemToKeyAndID(tlog.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid rekor public key %d: %w", i, err)
		}
		// This needs to be ecdsa instead of crypto.PublicKey
		// https://github.com/sigstore/cosign/issues/2540
		_, ok := pk.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key %d is not ecdsa.PublicKey", i)
		}
		sigstoreKeys.TLogs[i].LogID = logID
	}
	for i, ctlog := range sigstoreKeys.CTLogs {
		_, logID, err := pemToKeyAndID(ctlog.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid ctlog public key %d: %w", i, err)
		}
		sigstoreKeys.CTLogs[i].LogID = logID
	}

	// See if the CM holding configs exists
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.SigstoreKeysConfigName)
	if err != nil {
		if !apierrs.IsNotFound(err) {
			logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
			trustroot.Status.MarkCMUpdateFailed(err.Error())
			return err
		}
		// Does not exist, create it.
		cm, err := resources.NewConfigMap(system.Namespace(), config.SigstoreKeysConfigName, trustroot.Name, sigstoreKeys)
		if err != nil {
			logging.FromContext(ctx).Errorf("Failed to construct configmap: %v", err)
			trustroot.Status.MarkCMUpdateFailed(err.Error())
			return err
		}
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Create(ctx, cm, metav1.CreateOptions{})
		if err != nil {
			trustroot.Status.MarkCMUpdateFailed(err.Error())
			return err
		}
		trustroot.Status.MarkCMUpdatedOK()
		return nil
	}

	// Check if we need to update the configmap or not.
	patchBytes, err := resources.CreatePatch(system.Namespace(), config.SigstoreKeysConfigName, trustroot.Name, existing.DeepCopy(), sigstoreKeys)
	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to construct patch: %v", err)
		trustroot.Status.MarkCMUpdateFailed(err.Error())
		return err
	}
	if len(patchBytes) > 0 {
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Patch(ctx, config.SigstoreKeysConfigName, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
		if err != nil {
			logging.FromContext(ctx).Errorf("Failed to patch: %v", err)
			trustroot.Status.MarkCMUpdateFailed(err.Error())
			return err
		}
	}
	trustroot.Status.MarkCMUpdatedOK()
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
	tufClient, err := tuf.ClientFromSerializedMirror(ctx, repository.MirrorFS, repository.Root, repository.Targets, v1alpha1.DefaultTUFRepoPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to construct TUF client from mirror: %w", err)
	}

	return getSigstoreKeysFromTuf(ctx, tufClient)
}

func (r *Reconciler) getSigstoreKeysFromRemote(ctx context.Context, remote *v1alpha1.Remote) (*config.SigstoreKeys, error) {
	tufClient, err := tuf.ClientFromRemote(ctx, remote.Mirror.String(), remote.Root, remote.Targets)
	if err != nil {
		return nil, fmt.Errorf("failed to construct TUF client from remote: %w", err)
	}
	return getSigstoreKeysFromTuf(ctx, tufClient)
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

// pemToKeyAndID takes a public key in PEM format, and turns it into
// crypto.PublicKey and the CTLog LogID.
func pemToKeyAndID(pem []byte) (crypto.PublicKey, string, error) {
	pk, err := cryptoutils.UnmarshalPEMToPublicKey(pem)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshaling PEM public key: %w", err)
	}
	logID, err := cosign.GetTransparencyLogID(pk)
	if err != nil {
		return nil, "", fmt.Errorf("failed to construct LogID for rekor: %w", err)
	}
	return pk, logID, nil
}

// These are private to sigstore/sigstore even though I don't think they should
// be.
type customMetadata struct {
	Usage  sigstoretuf.UsageKind  `json:"usage"`
	Status sigstoretuf.StatusKind `json:"status"`
}

type sigstoreCustomMetadata struct {
	Sigstore customMetadata `json:"sigstore"`
}

// getSigstoreKeysFromTuf returns the sigstore keys from the TUF client. Note
// that this should really be exposed from the sigstore/sigstore TUF pkg, but
// is currently not.
func getSigstoreKeysFromTuf(ctx context.Context, tufClient *client.Client) (*config.SigstoreKeys, error) {
	targets, err := tufClient.Targets()
	if err != nil {
		return nil, fmt.Errorf("error getting targets: %w", err)
	}
	ret := &config.SigstoreKeys{}
	for name, targetMeta := range targets {
		// Skip any targets that do not include custom metadata.
		if targetMeta.Custom == nil {
			continue
		}
		var scm sigstoreCustomMetadata
		err := json.Unmarshal(*targetMeta.Custom, &scm)
		if err != nil {
			logging.FromContext(ctx).Warnf("Custom metadata not configured properly for target %s, skipping target: %v", name, err)
			continue
		}
		dl := newDownloader()
		if err = tufClient.Download(name, &dl); err != nil {
			return nil, fmt.Errorf("downloading target %s: %w", name, err)
		}
		switch scm.Sigstore.Usage {
		case sigstoretuf.Fulcio:
			ret.CertificateAuthorities = append(ret.CertificateAuthorities, config.CertificateAuthority{CertChain: dl.Bytes()})
		case sigstoretuf.CTFE:
			ret.CTLogs = append(ret.CTLogs, config.TransparencyLogInstance{PublicKey: dl.Bytes()})
		case sigstoretuf.Rekor:
			ret.TLogs = append(ret.TLogs, config.TransparencyLogInstance{PublicKey: dl.Bytes()})
		}
	}
	// Make sure there's at least a single CertificateAuthority (Fulcio there).
	// Some others could be optional.
	if len(ret.CertificateAuthorities) == 0 {
		return nil, errors.New("no certificate authorities found")
	}
	return ret, nil
}

func newDownloader() downloader {
	return downloader{&bytes.Buffer{}}
}

type downloader struct {
	b *bytes.Buffer
}

func (d downloader) Delete() error                     { return nil }
func (d downloader) Bytes() []byte                     { return d.b.Bytes() }
func (d downloader) Write(p []byte) (n int, err error) { return d.b.Write(p) }
