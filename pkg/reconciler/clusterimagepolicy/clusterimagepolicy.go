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

package clusterimagepolicy

import (
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/sigstore/policy-controller/pkg/apis/config"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	"github.com/sigstore/policy-controller/pkg/apis/signaturealgo"
	clusterimagepolicyreconciler "github.com/sigstore/policy-controller/pkg/client/injection/reconciler/policy/v1alpha1/clusterimagepolicy"
	"github.com/sigstore/policy-controller/pkg/reconciler/clusterimagepolicy/resources"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
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
	"knative.dev/pkg/tracker"

	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// Reconciler implements clusterimagepolicyreconciler.Interface for
// ClusterImagePolicy resources.
type Reconciler struct {
	// Tracker builds an index of what resources are watching other resources
	// so that we can immediately react to changes tracked resources.
	tracker tracker.Interface
	// We need to be able to read Secrets, which are really holding public
	// keys.
	secretlister    corev1listers.SecretLister
	configmaplister corev1listers.ConfigMapLister
	kubeclient      kubernetes.Interface
}

// Check that our Reconciler implements Interface as well as finalizer
var _ clusterimagepolicyreconciler.Interface = (*Reconciler)(nil)
var _ clusterimagepolicyreconciler.Finalizer = (*Reconciler)(nil)

// ReconcileKind implements Interface.ReconcileKind.
func (r *Reconciler) ReconcileKind(ctx context.Context, cip *v1alpha1.ClusterImagePolicy) reconciler.Event {
	cip.Status.InitializeConditions()
	cipCopy, cipErr := r.inlinePublicKeys(ctx, cip)
	if cipErr != nil {
		r.handleCIPError(ctx, cip.Name)
		// Update the status to reflect that we were unable to inline keys.
		cip.Status.MarkInlineKeysFailed(cipErr.Error())
		// Note that we return the error about the Invalid cip here to make
		// sure that it's surfaced.
		return cipErr
	}
	cip.Status.MarkInlineKeysOk()

	cipErr = r.inlinePolicies(ctx, cipCopy)
	if cipErr != nil {
		r.handleCIPError(ctx, cip.Name)
		// Update the status to reflect that we were unable to inline policies.
		cip.Status.MarkInlinePoliciesFailed(cipErr.Error())
		// Note that we return the error about the Invalid cip here to make
		// sure that it's surfaced.
		return cipErr
	}
	cip.Status.MarkInlinePoliciesOk()

	cipNserr := r.inlineNamespaces(cipCopy)
	if cipNserr != nil {
		r.handleCIPError(ctx, cip.Name)
		cip.Status.MarkNamespaceValidationFailed(cipNserr.Error())
		return cipNserr
	}

	webhookCIP := webhookcip.ConvertClusterImagePolicyV1alpha1ToWebhook(cipCopy)

	// See if the CM holding configs exists
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.ImagePoliciesConfigName)
	if err != nil {
		if !apierrs.IsNotFound(err) {
			logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
			cip.Status.MarkCMUpdateFailed(err.Error())
			return err
		}
		// Does not exist, create it.
		cm, err := resources.NewConfigMap(system.Namespace(), config.ImagePoliciesConfigName, cip.Name, webhookCIP)
		if err != nil {
			logging.FromContext(ctx).Errorf("Failed to construct configmap: %v", err)
			cip.Status.MarkCMUpdateFailed(err.Error())
			return err
		}
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Create(ctx, cm, metav1.CreateOptions{})
		if err != nil {
			cip.Status.MarkCMUpdateFailed(err.Error())
			return err
		}
		cip.Status.MarkCMUpdatedOK()
		return err
	}

	// Check if we need to update the configmap or not.
	patchBytes, err := resources.CreatePatch(system.Namespace(), config.ImagePoliciesConfigName, cip.Name, existing.DeepCopy(), webhookCIP)
	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to create patch: %v", err)
		cip.Status.MarkCMUpdateFailed(err.Error())
		return err
	}
	if len(patchBytes) > 0 {
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Patch(ctx, config.ImagePoliciesConfigName, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
		if err != nil {
			cip.Status.MarkCMUpdateFailed(err.Error())
			return err
		}
	}
	cip.Status.MarkCMUpdatedOK()
	return nil
}

// FinalizeKind implements Interface.ReconcileKind.
func (r *Reconciler) FinalizeKind(ctx context.Context, cip *v1alpha1.ClusterImagePolicy) reconciler.Event {
	// See if the CM holding configs even exists
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.ImagePoliciesConfigName)
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
	// CM exists, so remove our entry from it.
	return r.removeCIPEntry(ctx, existing, cip.Name)
}

func (r *Reconciler) handleCIPError(ctx context.Context, cipName string) {
	// The CIP is invalid, try to remove CIP from the configmap
	existing, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(config.ImagePoliciesConfigName)
	if err != nil {
		if !apierrs.IsNotFound(err) {
			logging.FromContext(ctx).Errorf("Failed to get configmap: %v", err)
		}
	} else if err := r.removeCIPEntry(ctx, existing, cipName); err != nil {
		logging.FromContext(ctx).Errorf("Failed to remove CIP entry from configmap: %v", err)
	}
}

// inlinePublicKeys will go through the CIP and try to read the referenced
// secrets, KMS keys and convert them into inlined data. Makes a copy of the CIP
// before modifying it and returns the copy.
func (r *Reconciler) inlinePublicKeys(ctx context.Context, cip *v1alpha1.ClusterImagePolicy) (*v1alpha1.ClusterImagePolicy, error) {
	ret := cip.DeepCopy()
	for _, authority := range ret.Spec.Authorities {
		if authority.Key != nil && authority.Key.SecretRef != nil {
			if err := r.inlineAndTrackSecret(ctx, ret, authority.Key); err != nil {
				logging.FromContext(ctx).Errorf("Failed to read secret %q: %v", authority.Key.SecretRef.Name, err)
				return nil, err
			}
		}
		if authority.Keyless != nil && authority.Keyless.CACert != nil &&
			authority.Keyless.CACert.SecretRef != nil {
			if err := r.inlineAndTrackSecret(ctx, ret, authority.Keyless.CACert); err != nil {
				logging.FromContext(ctx).Errorf("Failed to read secret %q: %v", authority.Keyless.CACert.SecretRef.Name, err)
				return nil, err
			}
		}
		if authority.Key != nil && strings.Contains(authority.Key.KMS, "://") {
			pubKeyString, err := getKMSPublicKey(ctx, authority.Key.KMS, authority.Key.HashAlgorithm)
			if err != nil {
				return nil, err
			}

			authority.Key.Data = pubKeyString
			authority.Key.KMS = ""
		}
	}
	return ret, nil
}

// getKMSPublicKey returns the public key as a string from the configured KMS service using the key ID
func getKMSPublicKey(ctx context.Context, keyID string, hashAlgorithm string) (string, error) {
	algorithm := crypto.SHA256
	if hashAlgorithm != "" {
		var err error
		algorithm, err = signaturealgo.HashAlgorithm(hashAlgorithm)
		if err != nil {
			logging.FromContext(ctx).Errorf("Failed to extract the signature hash algorithm: %w", err)
			return "", fmt.Errorf("failed to extract the signature hash algorithm: %w", err)
		}
	}
	kmsSigner, err := kms.Get(ctx, keyID, algorithm)
	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to read KMS key ID %q: %v", keyID, err)
		return "", err
	}
	pemBytes, err := sigs.PublicKeyPem(kmsSigner, signatureoptions.WithContext(ctx))
	if err != nil {
		return "", err
	}
	return string(pemBytes), nil
}

// inlineSecret will take in a KeyRef and tries to read the Secret, finding the
// first key from it and will inline it in place of Data and then clear out
// the SecretRef and return it.
// Additionally, we set up a tracker so we will be notified if the secret
// is modified.
// There's still some discussion about how to handle multiple keys in a secret
// for now, just grab one from it. For reference, the discussion is here:
// TODO(vaikas): https://github.com/sigstore/cosign/issues/1573
func (r *Reconciler) inlineAndTrackSecret(ctx context.Context, cip *v1alpha1.ClusterImagePolicy, keyref *v1alpha1.KeyRef) error {
	if err := r.tracker.TrackReference(tracker.Reference{
		APIVersion: "v1",
		Kind:       "Secret",
		Namespace:  system.Namespace(),
		Name:       keyref.SecretRef.Name,
	}, cip); err != nil {
		return fmt.Errorf("failed to track changes to secret %q : %w", keyref.SecretRef.Name, err)
	}
	secret, err := r.secretlister.Secrets(system.Namespace()).Get(keyref.SecretRef.Name)
	if err != nil {
		return err
	}
	if len(secret.Data) == 0 {
		return fmt.Errorf("secret %q contains no data", keyref.SecretRef.Name)
	}
	if len(secret.Data) > 1 {
		return fmt.Errorf("secret %q contains multiple data entries, only one is supported", keyref.SecretRef.Name)
	}
	for k, v := range secret.Data {
		logging.FromContext(ctx).Infof("inlining secret %q key %q", keyref.SecretRef.Name, k)
		publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(v)
		if err != nil || publicKey == nil {
			return fmt.Errorf("secret %q contains an invalid public key: %w", keyref.SecretRef.Name, err)
		}
		keyref.Data = string(v)
		keyref.SecretRef = nil
	}
	return nil
}

// inlinePolicies will go through the CIP and try to read the referenced
// ConfigMapRefs and convert them into inlined data. Modifies the cip in-place
func (r *Reconciler) inlinePolicies(ctx context.Context, cip *v1alpha1.ClusterImagePolicy) error {
	for _, authority := range cip.Spec.Authorities {
		for _, att := range authority.Attestations {
			if att.Policy != nil && att.Policy.ConfigMapRef != nil {
				err := r.inlineAndTrackConfigMap(ctx, cip, att.Policy)
				if err != nil {
					logging.FromContext(ctx).Errorf("Failed to read configmap %q: %v", att.Policy.ConfigMapRef.Name, err)
					return err
				}
			}
			if att.Policy != nil && att.Policy.Remote != nil {
				err := r.inlinePolicyURL(ctx, att.Policy)
				if err != nil {
					logging.FromContext(ctx).Errorf("Failed to read policy url %s: %v", cip.Spec.Policy.Remote.URL.String(), err)
					return err
				}
			}
		}
	}
	if cip.Spec.Policy != nil && cip.Spec.Policy.ConfigMapRef != nil {
		err := r.inlineAndTrackConfigMap(ctx, cip, cip.Spec.Policy)
		if err != nil {
			logging.FromContext(ctx).Errorf("Failed to read configmap %q: %v", cip.Spec.Policy.ConfigMapRef.Name, err)
			return err
		}
	}
	if cip.Spec.Policy != nil && cip.Spec.Policy.Remote != nil {
		err := r.inlinePolicyURL(ctx, cip.Spec.Policy)
		if err != nil {
			logging.FromContext(ctx).Errorf("Failed to read policy url %s: %v", cip.Spec.Policy.Remote.URL.String(), err)
			return err
		}
	}
	return nil
}

func (r *Reconciler) inlineNamespaces(cip *v1alpha1.ClusterImagePolicy) error {
	var podList *corev1.PodList
	podList, err := r.kubeclient.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			image := container.Image
			for _, pattern := range cip.Spec.Images {
				if pattern.Glob != "" {
					matched, err := filepath.Match(pattern.Glob, image)
					if err != nil {
						return fmt.Errorf("invalid glob pattern: %w", err)
					}
					if matched {
						if cip.Spec.Policy.NamespaceSelector != "" && pod.Namespace != cip.Spec.Policy.NamespaceSelector {
							return fmt.Errorf("image %s can only be used in the namespace %s", image, cip.Spec.Policy.NamespaceSelector)
						}
						return nil // If mage matches, and namespace is correct (or no namespace restriction then dont care about namespace)
					}
				}
			}
		}
	}
	return nil
}

func (r *Reconciler) inlinePolicyURL(ctx context.Context, policyRef *v1alpha1.Policy) error {
	logging.FromContext(ctx).Infof("inlining policy url %q", policyRef.Remote.URL.String())
	resp, err := http.Get(policyRef.Remote.URL.String())
	if err != nil {
		return fmt.Errorf("failed to fetch content from policy url: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("failed to fetch content from policy url with code %q", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read policy url response: %w", err)
	}
	// Checking the sha256sum value in comparison with the one set in the policy
	sha256Sum := fmt.Sprintf("%x", sha256.Sum256(data))
	if sha256Sum != policyRef.Remote.Sha256sum {
		return fmt.Errorf("failed to check sha256sum from policy remote: %s got %s", policyRef.Remote.Sha256sum, sha256Sum)
	}
	policyRef.Data = string(data)
	policyRef.Remote = nil
	return nil
}

// inlineAndTrackConfigMap will take in a ConfigMapRef and tries to read the ConfigMap,
// finding the first key from it and will inline it in place of Data and then
// clear out the ConfigMapRef and return it.
// Additionally, we set up a tracker so we will be notified if the ConfigMap
// is modified.
func (r *Reconciler) inlineAndTrackConfigMap(ctx context.Context, cip *v1alpha1.ClusterImagePolicy, policyRef *v1alpha1.Policy) error {
	cmName := policyRef.ConfigMapRef.Name
	keyName := policyRef.ConfigMapRef.Key
	if err := r.tracker.TrackReference(tracker.Reference{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Namespace:  system.Namespace(),
		Name:       cmName,
	}, cip); err != nil {
		return fmt.Errorf("failed to track changes to configmap %q : %w", cmName, err)
	}
	cm, err := r.configmaplister.ConfigMaps(system.Namespace()).Get(cmName)
	if err != nil {
		return err
	}
	if len(cm.Data) == 0 {
		return fmt.Errorf("configmap %q contains no data", cmName)
	}
	if cm.Data[keyName] == "" {
		return fmt.Errorf("configmap %q does not contain key %s", cmName, keyName)
	}
	logging.FromContext(ctx).Infof("inlining configmap %q key %q", cmName, keyName)
	policyRef.Data = cm.Data[keyName]
	policyRef.ConfigMapRef = nil
	return nil
}

// removeCIPEntry removes an entry from a CM. If no entry exists, it's a nop.
func (r *Reconciler) removeCIPEntry(ctx context.Context, cm *corev1.ConfigMap, cipName string) error {
	patchBytes, err := resources.CreateRemovePatch(system.Namespace(), config.ImagePoliciesConfigName, cm.DeepCopy(), cipName)
	if err != nil {
		logging.FromContext(ctx).Errorf("Failed to create remove patch: %v", err)
		return err
	}
	if len(patchBytes) > 0 {
		_, err = r.kubeclient.CoreV1().ConfigMaps(system.Namespace()).Patch(ctx, config.ImagePoliciesConfigName, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
		return err
	}
	return nil
}
