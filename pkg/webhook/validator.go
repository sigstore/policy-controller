//
// Copyright 2021 The Sigstore Authors.
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

package webhook

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/policy"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/policy-controller/pkg/apis/config"
	policyduckv1beta1 "github.com/sigstore/policy-controller/pkg/apis/duck/v1beta1"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/signature"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"

	kubeclient "knative.dev/pkg/client/injection/kube/client"
	secretinformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/system"
)

type Validator struct {
	client     kubernetes.Interface
	lister     listersv1.SecretLister
	secretName string
}

func NewValidator(ctx context.Context, secretName string) *Validator {
	return &Validator{
		client:     kubeclient.Get(ctx),
		lister:     secretinformer.Get(ctx).Lister(),
		secretName: secretName,
	}
}

// isDeletedOrStatusUpdate returns true if the resource in question is being
// deleted, is already deleted or Status is being updated. In any of those
// cases, we do not validate the resource
func isDeletedOrStatusUpdate(ctx context.Context, deletionTimestamp *metav1.Time) bool {
	return apis.IsInDelete(ctx) || deletionTimestamp != nil || apis.IsInStatusUpdate(ctx)
}

// ValidatePodScalable implements policyduckv1beta1.PodScalableValidator
// It is very similar to ValidatePodSpecable, but allows for spec.replicas
// to be decremented. This allows for scaling down pods with non-compliant
// images that would otherwise be forbidden.
func (v *Validator) ValidatePodScalable(ctx context.Context, ps *policyduckv1beta1.PodScalable) *apis.FieldError {
	// If we are deleting (or already deleted) or updating status, don't block.
	if isDeletedOrStatusUpdate(ctx, ps.DeletionTimestamp) {
		return nil
	}

	// If we are being scaled down don't block it.
	if ps.IsScalingDown(ctx) {
		logging.FromContext(ctx).Debugf("Skipping validations due to scale down request %s/%s", &ps.ObjectMeta.Name, &ps.ObjectMeta.Namespace)
		return nil
	}

	imagePullSecrets := make([]string, 0, len(ps.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range ps.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          ps.Namespace,
		ServiceAccountName: ps.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, ps.Namespace, &ps.Spec.Template.Spec, opt).ViaField("spec.template.spec")
}

// ValidatePodSpecable implements duckv1.PodSpecValidator
func (v *Validator) ValidatePodSpecable(ctx context.Context, wp *duckv1.WithPod) *apis.FieldError {
	// If we are deleting (or already deleted) or updating status, don't block.
	if isDeletedOrStatusUpdate(ctx, wp.DeletionTimestamp) {
		return nil
	}

	imagePullSecrets := make([]string, 0, len(wp.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range wp.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          wp.Namespace,
		ServiceAccountName: wp.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, wp.Namespace, &wp.Spec.Template.Spec, opt).ViaField("spec.template.spec")
}

// ValidatePod implements duckv1.PodValidator
func (v *Validator) ValidatePod(ctx context.Context, p *duckv1.Pod) *apis.FieldError {
	// If we are deleting (or already deleted) or updating status, don't block.
	if isDeletedOrStatusUpdate(ctx, p.DeletionTimestamp) {
		return nil
	}

	imagePullSecrets := make([]string, 0, len(p.Spec.ImagePullSecrets))
	for _, s := range p.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          p.Namespace,
		ServiceAccountName: p.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, p.Namespace, &p.Spec, opt).ViaField("spec")
}

// ValidateCronJob implements duckv1.CronJobValidator
func (v *Validator) ValidateCronJob(ctx context.Context, c *duckv1.CronJob) *apis.FieldError {
	// If we are deleting (or already deleted) or updating status, don't block.
	if isDeletedOrStatusUpdate(ctx, c.DeletionTimestamp) {
		return nil
	}

	imagePullSecrets := make([]string, 0, len(c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          c.Namespace,
		ServiceAccountName: c.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, c.Namespace, &c.Spec.JobTemplate.Spec.Template.Spec, opt).ViaField("spec.jobTemplate.spec.template.spec")
}

func (v *Validator) validatePodSpec(ctx context.Context, namespace string, ps *corev1.PodSpec, opt k8schain.Options) (errs *apis.FieldError) {
	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return apis.ErrGeneric(err.Error(), apis.CurrentField)
	}

	s, err := v.lister.Secrets(system.Namespace()).Get(v.secretName)
	if err != nil && !apierrs.IsNotFound(err) {
		return apis.ErrGeneric(err.Error(), apis.CurrentField)
	}
	// If the secret is not found, we verify against the fulcio root.
	keys := make([]crypto.PublicKey, 0)
	if err == nil {
		var kerr *apis.FieldError
		keys, kerr = getKeys(ctx, s.Data)
		if kerr != nil {
			return kerr
		}
	}

	checkContainers := func(cs []corev1.Container, field string) {
		for i, c := range cs {
			ref, err := name.ParseReference(c.Image)
			if err != nil {
				errs = errs.Also(apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i))
				continue
			}

			// Require digests, otherwise the validation is meaningless
			// since the tag can move.
			if _, ok := ref.(name.Digest); !ok {
				errs = errs.Also(apis.ErrInvalidValue(
					fmt.Sprintf("%s must be an image digest", c.Image),
					"image",
				).ViaFieldIndex(field, i))
				continue
			}

			containerKeys := keys
			config := config.FromContext(ctx)

			// During the migration from the secret only validation into policy
			// based ones. If there were matching policies that successfully
			// validated the image, keep tally of it and if all Policies that
			// matched validated, skip the traditional one since they are not
			// necessarily going to play nicely together.
			passedPolicyChecks := false
			if config != nil {
				policies, err := config.ImagePolicyConfig.GetMatchingPolicies(ref.Name())
				if err != nil {
					errorField := apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i)
					errorField.Details = c.Image
					errs = errs.Also(errorField)
					continue
				}

				// If there is at least one policy that matches, that means it
				// has to be satisfied.
				if len(policies) > 0 {
					signatures, fieldErrors := validatePolicies(ctx, namespace, ref, policies, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc)))

					if len(signatures) != len(policies) {
						logging.FromContext(ctx).Warnf("Failed to validate at least one policy for %s", ref.Name())
						// Do we really want to add all the error details here?
						// Seems like we can just say which policy failed, so
						// doing that for now.
						for failingPolicy, policyErrs := range fieldErrors {
							errorField := apis.ErrGeneric(fmt.Sprintf("failed policy: %s", failingPolicy), "image").ViaFieldIndex(field, i)
							errDetails := c.Image
							for _, policyErr := range policyErrs {
								errDetails = errDetails + " " + policyErr.Error()
							}
							errorField.Details = errDetails
							errs = errs.Also(errorField)
						}
						// Because there was at least one policy that was
						// supposed to be validated, but it failed, then fail
						// this image. It should not fall through to the
						// traditional secret checking so it does not slip
						// through the policy cracks, and also to reduce noise
						// in the errors returned to the user.
						continue
					} else {
						logging.FromContext(ctx).Warnf("Validated authorities for %s", ref.Name())
						// Only say we passed (aka, we skip the traditidional check
						// below) if more than one authority was validated, which
						// means that there was a matching ClusterImagePolicy.
						if len(signatures) > 0 {
							passedPolicyChecks = true
						}
					}
				}
				logging.FromContext(ctx).Errorf("policies: for %v", policies)
			}

			if passedPolicyChecks {
				logging.FromContext(ctx).Debugf("Found at least one matching policy and it was validated for %s", ref.Name())
				continue
			}
			logging.FromContext(ctx).Errorf("ref: for %v", ref)
			logging.FromContext(ctx).Errorf("container Keys: for %v", containerKeys)

			if _, err := valid(ctx, ref, nil, containerKeys, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc))); err != nil {
				errorField := apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i)
				errorField.Details = c.Image
				errs = errs.Also(errorField)
				continue
			}
		}
	}

	checkContainers(ps.InitContainers, "initContainers")
	checkContainers(ps.Containers, "containers")

	return errs
}

// validatePolicies will go through all the matching Policies and their
// Authorities for a given image. Returns the map of policy=>Validated
// signatures. From the map you can see the number of matched policies along
// with the signatures that were verified.
// If there's a policy that did not match, it will be returned in the errors map
// along with all the errors that caused it to fail.
// Note that if an image does not match any policies, it's perfectly
// reasonable that the return value is 0, nil since there were no errors, but
// the image was not validated against any matching policy and hence authority.
func validatePolicies(ctx context.Context, namespace string, ref name.Reference, policies map[string]webhookcip.ClusterImagePolicy, remoteOpts ...ociremote.Option) (map[string]*PolicyResult, map[string][]error) {
	type retChannelType struct {
		name         string
		policyResult *PolicyResult
		errors       []error
	}
	results := make(chan retChannelType, len(policies))

	// For each matching policy it must validate at least one Authority within
	// it.
	// From the Design document, the part about multiple Policies matching:
	// "If multiple policies match a particular image, then ALL of those
	// policies must be satisfied for the image to be admitted."
	// If none of the Authorities for a given policy pass the checks, gather
	// the errors here. If one passes, do not return the errors.
	for cipName, cip := range policies {
		// Due to running in gofunc
		cipName := cipName
		cip := cip
		logging.FromContext(ctx).Debugf("Checking Policy: %s", cipName)
		go func() {
			result := retChannelType{name: cipName}

			result.policyResult, result.errors = ValidatePolicy(ctx, namespace, ref, cip, remoteOpts...)
			results <- result
		}()
	}
	// Gather all validated policies here.
	policyResults := make(map[string]*PolicyResult)
	// For a policy that does not pass at least one authority, gather errors
	// here so that we can give meaningful errors to the user.
	ret := map[string][]error{}

	for i := 0; i < len(policies); i++ {
		select {
		case <-ctx.Done():
			ret["internalerror"] = append(ret["internalerror"], fmt.Errorf("context was canceled before validation completed"))
		case result, ok := <-results:
			if !ok {
				ret["internalerror"] = append(ret["internalerror"], fmt.Errorf("results channel failed to produce a result"))
				continue
			}
			switch {
			// Return AuthorityMatches before errors, since even if there
			// are errors, if there are 0 or more authorities that match,
			// it will pass the Policy. Of course, a CIP level policy can
			// override this behaviour, but that has been checked above and
			// if it failed, it will nil out the policyResult.
			case result.policyResult != nil:
				policyResults[result.name] = result.policyResult
			case len(result.errors) > 0:
				ret[result.name] = append(ret[result.name], result.errors...)
			default:
				ret[result.name] = append(ret[result.name], fmt.Errorf("failed to process policy: %s", result.name))
			}
		}
	}

	return policyResults, ret
}

// ValidatePolicy will go through all the Authorities for a given image/policy
// and return validated authorities if at least one of the Authorities
// validated the signatures OR attestations if atttestations were specified.
// Returns PolicyResult if one or more authorities matched, otherwise nil.
// In any case returns all errors encountered if none of the authorities
// passed.
func ValidatePolicy(ctx context.Context, namespace string, ref name.Reference, cip webhookcip.ClusterImagePolicy, remoteOpts ...ociremote.Option) (*PolicyResult, []error) {
	// Each gofunc creates and puts one of these into a results channel.
	// Once each gofunc finishes, we go through the channel and pull out
	// the results.
	type retChannelType struct {
		name         string
		attestations map[string][]PolicySignature
		signatures   []PolicySignature
		err          error
	}
	results := make(chan retChannelType, len(cip.Authorities))
	for _, authority := range cip.Authorities {
		authority := authority // due to gofunc
		logging.FromContext(ctx).Debugf("Checking Authority: %s", authority.Name)

		go func() {
			result := retChannelType{name: authority.Name}
			// Assignment for appendAssign lint error
			authorityRemoteOpts := remoteOpts
			authorityRemoteOpts = append(authorityRemoteOpts, authority.RemoteOpts...)

			signaturePullSecretsOpts, err := authority.SourceSignaturePullSecretsOpts(ctx, namespace)
			if err != nil {
				result.err = err
				results <- result
				return
			}
			authorityRemoteOpts = append(authorityRemoteOpts, signaturePullSecretsOpts...)

			switch {
			case authority.Static != nil:
				if authority.Static.Action == "fail" {
					result.err = errors.New("disallowed by static policy")
					results <- result
					return
				}
				result.signatures = []PolicySignature{{Subject: "allowed by static policy", Issuer: "allowed by static policy"}}
			case len(authority.Attestations) > 0:
				// We're doing the verify-attestations path, so validate (.att)
				validatedAttestations, err := ValidatePolicyAttestationsForAuthority(ctx, ref, authority, authorityRemoteOpts...)
				if err != nil {
					result.err = err
				} else {
					result.attestations = validatedAttestations
				}
			default:
				validatedSignatures, err := ValidatePolicySignaturesForAuthority(ctx, ref, authority, authorityRemoteOpts...)
				if err != nil {
					result.err = err
				} else {
					result.signatures = validatedSignatures
				}
			}
			results <- result
		}()
	}
	// If none of the Authorities for a given policy pass the checks, gather
	// the errors here. Even if there are errors, return the matched
	// authoritypolicies.
	authorityErrors := []error{}
	// We collect all the successfully satisfied Authorities into this and
	// return it.
	policyResult := &PolicyResult{AuthorityMatches: make(map[string]AuthorityMatch)}
	for i := 0; i < len(cip.Authorities); i++ {
		select {
		case <-ctx.Done():
			authorityErrors = append(authorityErrors, fmt.Errorf("context was canceled before validation completed"))
		case result, ok := <-results:
			if !ok {
				authorityErrors = append(authorityErrors, fmt.Errorf("results channel failed to produce a result"))
				continue
			}
			switch {
			case result.err != nil:
				authorityErrors = append(authorityErrors, result.err)
			case len(result.signatures) > 0:
				policyResult.AuthorityMatches[result.name] = AuthorityMatch{Signatures: result.signatures}
			case len(result.attestations) > 0:
				policyResult.AuthorityMatches[result.name] = AuthorityMatch{Attestations: result.attestations}
			default:
				authorityErrors = append(authorityErrors, fmt.Errorf("failed to process authority: %s", result.name))
			}
		}
	}
	// Even if there are errors, return the policies, since as per the
	// spec, we just need one authority to pass checks. If more than
	// one are required, that is enforced at the CIP policy level.
	// If however there are no authorityMatches, return nil so we don't have
	// to keep checking the length on the returned calls.
	if len(policyResult.AuthorityMatches) == 0 {
		return nil, authorityErrors
	}
	// Ok, there's at least one valid authority that matched. If there's a CIP
	// level policy, validate it here before returning.
	if cip.Policy != nil {
		logging.FromContext(ctx).Info("Validating CIP level policy")
		policyJSON, err := json.Marshal(policyResult)
		if err != nil {
			return nil, append(authorityErrors, err)
		}
		err = policy.EvaluatePolicyAgainstJSON(ctx, "ClusterImagePolicy", cip.Policy.Type, cip.Policy.Data, policyJSON)
		if err != nil {
			logging.FromContext(ctx).Warnf("Failed to validate CIP level policy against %s", string(policyJSON))
			return nil, append(authorityErrors, err)
		}
	}
	return policyResult, authorityErrors
}

func ociSignatureToPolicySignature(ctx context.Context, sigs []oci.Signature) []PolicySignature {
	// TODO(vaikas): Validate whether these are useful at all, or if we should
	// simplify at least for starters.
	ret := []PolicySignature{}
	for _, ociSig := range sigs {
		logging.FromContext(ctx).Debugf("Converting signature %+v", ociSig)
		ret = append(ret, PolicySignature{Subject: "PLACEHOLDER", Issuer: "PLACEHOLDER"})
	}
	return ret
}

// ValidatePolicySignaturesForAuthority takes the Authority and tries to
// verify a signature against it.
func ValidatePolicySignaturesForAuthority(ctx context.Context, ref name.Reference, authority webhookcip.Authority, remoteOpts ...ociremote.Option) ([]PolicySignature, error) {
	name := authority.Name

	var rekorClient *client.Rekor
	var err error
	if authority.CTLog != nil && authority.CTLog.URL != nil {
		logging.FromContext(ctx).Debugf("Using CTLog %s for %s", authority.CTLog.URL, ref.Name())
		rekorClient, err = rekor.GetRekorClient(authority.CTLog.URL.String())
		if err != nil {
			logging.FromContext(ctx).Errorf("failed creating rekor client: +v", err)
			return nil, fmt.Errorf("creating Rekor client: %w", err)
		}
	}

	switch {
	case authority.Key != nil && len(authority.Key.PublicKeys) > 0:
		// TODO(vaikas): What should happen if there are multiple keys
		// Is it even allowed? 'valid' returns success if any key
		// matches.
		// https://github.com/sigstore/policy-controller/issues/1652
		sps, err := valid(ctx, ref, rekorClient, authority.Key.PublicKeys, remoteOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to validate public keys with authority %s for %s: %w", name, ref.Name(), err)
		} else if len(sps) > 0 {
			logging.FromContext(ctx).Debugf("validated signature for %s with authority %s got %d signatures", ref.Name(), authority.Name, len(sps))
			return ociSignatureToPolicySignature(ctx, sps), nil
		}
		logging.FromContext(ctx).Errorf("no validSignatures found with authority %s for %s", name, ref.Name())
		return nil, fmt.Errorf("no valid signatures found with authority %s for %s", name, ref.Name())
	case authority.Keyless != nil:
		if authority.Keyless != nil && authority.Keyless.URL != nil {
			logging.FromContext(ctx).Debugf("Fetching FulcioRoot for %s : From: %s ", ref.Name(), authority.Keyless.URL)
			fulcioroot, err := getFulcioCert(authority.Keyless.URL)
			if err != nil {
				return nil, fmt.Errorf("fetching FulcioRoot: %w", err)
			}
			sps, err := validSignaturesWithFulcio(ctx, ref, fulcioroot, rekorClient, authority.Keyless.Identities, remoteOpts...)
			if err != nil {
				logging.FromContext(ctx).Errorf("failed validSignatures for authority %s with fulcio for %s: %v", name, ref.Name(), err)
				return nil, fmt.Errorf("validate signatures with fulcio: %w", err)
			} else if len(sps) > 0 {
				logging.FromContext(ctx).Debugf("validated signature for %s, got %d signatures", ref.Name(), len(sps))
				return ociSignatureToPolicySignature(ctx, sps), nil
			}
			logging.FromContext(ctx).Errorf("no validSignatures found for %s", ref.Name())
			return nil, fmt.Errorf("no valid signatures found with authority %s for  %s", name, ref.Name())
		}
	}
	// This should never happen because authority has to have been
	// validated to be either having a Key or Keyless
	return nil, fmt.Errorf("authority has neither key, keyless, or static specified")
}

// ValidatePolicyAttestationsForAuthority takes the Authority and tries to
// verify attestations against it.
func ValidatePolicyAttestationsForAuthority(ctx context.Context, ref name.Reference, authority webhookcip.Authority, remoteOpts ...ociremote.Option) (map[string][]PolicySignature, error) {
	name := authority.Name
	var rekorClient *client.Rekor
	var err error
	if authority.CTLog != nil && authority.CTLog.URL != nil {
		logging.FromContext(ctx).Debugf("Using CTLog %s for %s", authority.CTLog.URL, ref.Name())
		rekorClient, err = rekor.GetRekorClient(authority.CTLog.URL.String())
		if err != nil {
			logging.FromContext(ctx).Errorf("failed creating rekor client: +v", err)
			return nil, fmt.Errorf("creating Rekor client: %w", err)
		}
	}

	verifiedAttestations := []oci.Signature{}
	switch {
	case authority.Key != nil && len(authority.Key.PublicKeys) > 0:
		for _, k := range authority.Key.PublicKeys {
			verifier, err := signature.LoadVerifier(k, crypto.SHA256)
			if err != nil {
				logging.FromContext(ctx).Errorf("error creating verifier: %v", err)
				return nil, fmt.Errorf("creating verifier: %w", err)
			}
			va, err := validAttestations(ctx, ref, verifier, rekorClient, remoteOpts...)
			if err != nil {
				logging.FromContext(ctx).Errorf("error validating attestations: %v", err)
				return nil, fmt.Errorf("validating attestations: %w", err)
			}
			verifiedAttestations = append(verifiedAttestations, va...)
		}
		logging.FromContext(ctx).Debug("No valid signatures were found.")
	case authority.Keyless != nil:
		if authority.Keyless != nil && authority.Keyless.URL != nil {
			logging.FromContext(ctx).Debugf("Fetching FulcioRoot for %s : From: %s ", ref.Name(), authority.Keyless.URL)
			fulcioroot, err := getFulcioCert(authority.Keyless.URL)
			if err != nil {
				return nil, fmt.Errorf("fetching FulcioRoot: %w", err)
			}
			va, err := validAttestationsWithFulcio(ctx, ref, fulcioroot, rekorClient, authority.Keyless.Identities, remoteOpts...)
			if err != nil {
				logging.FromContext(ctx).Errorf("failed validAttestationsWithFulcio for authority %s with fulcio for %s: %v", name, ref.Name(), err)
				return nil, fmt.Errorf("validate signatures with fulcio: %w", err)
			}
			verifiedAttestations = append(verifiedAttestations, va...)
		}
	}
	// If we didn't get any verified attestations either from the Key or Keyless
	// path, then error out
	if len(verifiedAttestations) == 0 {
		logging.FromContext(ctx).Errorf("no valid attestations found with authority %s for %s", name, ref.Name())
		return nil, fmt.Errorf("no valid attestations found with authority %s for %s", name, ref.Name())
	}
	logging.FromContext(ctx).Debugf("Found %d valid attestations, validating policies for them", len(verifiedAttestations))
	// Now spin through the Attestations that the user specified and validate
	// them.
	// TODO(vaikas): Pretty inefficient here, figure out a better way if
	// possible.
	ret := map[string][]PolicySignature{}
	for _, wantedAttestation := range authority.Attestations {
		// If there's no type / policy to do more checking against,
		// then we're done here. It matches all the attestations
		if wantedAttestation.Type == "" {
			ret[wantedAttestation.Name] = ociSignatureToPolicySignature(ctx, verifiedAttestations)
			continue
		}
		// There's a particular type, so we need to go through all the verified
		// attestations and make sure that our particular one is satisfied.
		for _, va := range verifiedAttestations {
			attBytes, err := policy.AttestationToPayloadJSON(ctx, wantedAttestation.PredicateType, va)
			if err != nil {
				return nil, fmt.Errorf("failed to convert attestation payload to json: %w", err)
			}
			if attBytes == nil {
				// This happens when we ask for a predicate type that this
				// attestation is not for. It's not an error, so we skip it.
				continue
			}
			if err := policy.EvaluatePolicyAgainstJSON(ctx, wantedAttestation.Name, wantedAttestation.Type, wantedAttestation.Data, attBytes); err != nil {
				return nil, err
			}
			// Ok, so this passed aok, jot it down to our result set as
			// verified attestation with the predicate type match
			ret[wantedAttestation.Name] = ociSignatureToPolicySignature(ctx, verifiedAttestations)
		}
	}
	return ret, nil
}

// ResolvePodScalable implements policyduckv1beta1.PodScalableValidator
func (v *Validator) ResolvePodScalable(ctx context.Context, ps *policyduckv1beta1.PodScalable) {
	// Don't mess with things that are being deleted or already deleted or
	// if status is being updated
	if isDeletedOrStatusUpdate(ctx, ps.DeletionTimestamp) {
		return
	}

	if ps.IsScalingDown(ctx) {
		logging.FromContext(ctx).Debugf("Skipping validations due to scale down request %s/%s", &ps.ObjectMeta.Name, &ps.ObjectMeta.Namespace)
		return
	}

	imagePullSecrets := make([]string, 0, len(ps.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range ps.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          ps.Namespace,
		ServiceAccountName: ps.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &ps.Spec.Template.Spec, opt)
}

// ResolvePodSpecable implements duckv1.PodSpecValidator
func (v *Validator) ResolvePodSpecable(ctx context.Context, wp *duckv1.WithPod) {
	// Don't mess with things that are being deleted or already deleted or
	// status update.
	if isDeletedOrStatusUpdate(ctx, wp.DeletionTimestamp) {
		return
	}

	imagePullSecrets := make([]string, 0, len(wp.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range wp.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          wp.Namespace,
		ServiceAccountName: wp.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &wp.Spec.Template.Spec, opt)
}

// ResolvePod implements duckv1.PodValidator
func (v *Validator) ResolvePod(ctx context.Context, p *duckv1.Pod) {
	// Don't mess with things that are being deleted or already deleted or
	// status update.
	if isDeletedOrStatusUpdate(ctx, p.DeletionTimestamp) {
		return
	}
	imagePullSecrets := make([]string, 0, len(p.Spec.ImagePullSecrets))
	for _, s := range p.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          p.Namespace,
		ServiceAccountName: p.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &p.Spec, opt)
}

// ResolveCronJob implements duckv1.CronJobValidator
func (v *Validator) ResolveCronJob(ctx context.Context, c *duckv1.CronJob) {
	// Don't mess with things that are being deleted or already deleted or
	// status update.
	if isDeletedOrStatusUpdate(ctx, c.DeletionTimestamp) {
		return
	}

	imagePullSecrets := make([]string, 0, len(c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	opt := k8schain.Options{
		Namespace:          c.Namespace,
		ServiceAccountName: c.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	v.resolvePodSpec(ctx, &c.Spec.JobTemplate.Spec.Template.Spec, opt)
}

// For testing
var remoteResolveDigest = ociremote.ResolveDigest

func (v *Validator) resolvePodSpec(ctx context.Context, ps *corev1.PodSpec, opt k8schain.Options) {
	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return
	}

	resolveContainers := func(cs []corev1.Container) {
		for i, c := range cs {
			ref, err := name.ParseReference(c.Image)
			if err != nil {
				logging.FromContext(ctx).Debugf("Unable to parse reference: %v", err)
				continue
			}

			// If we are in the context of a mutating webhook, then resolve the tag to a digest.
			switch {
			case apis.IsInCreate(ctx), apis.IsInUpdate(ctx):
				digest, err := remoteResolveDigest(ref, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc)))
				if err != nil {
					logging.FromContext(ctx).Debugf("Unable to resolve digest %q: %v", ref.String(), err)
					continue
				}
				cs[i].Image = digest.String()
			}
		}
	}

	resolveContainers(ps.InitContainers)
	resolveContainers(ps.Containers)
}

func getFulcioCert(u *apis.URL) (*x509.CertPool, error) {
	fClient := api.NewClient(u.URL())
	rootCertResponse, err := fClient.RootCert()
	if err != nil {
		return nil, fmt.Errorf("getting root cert: %w", err)
	}

	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(rootCertResponse.ChainPEM) {
		return nil, errors.New("error appending to root cert pool")
	}
	return cp, nil
}
