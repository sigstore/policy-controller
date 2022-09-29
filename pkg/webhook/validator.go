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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/policy"
	csigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/policy-controller/pkg/apis/config"
	policyduckv1beta1 "github.com/sigstore/policy-controller/pkg/apis/duck/v1beta1"
	policycontrollerconfig "github.com/sigstore/policy-controller/pkg/config"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/signature"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"

	kubeclient "knative.dev/pkg/client/injection/kube/client"
	"knative.dev/pkg/logging"
)

type Validator struct {
	client kubernetes.Interface
}

func NewValidator(ctx context.Context) *Validator {
	return &Validator{
		client: kubeclient.Get(ctx),
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
	ns := getNamespace(ctx, ps.Namespace)
	opt := k8schain.Options{
		Namespace:          ns,
		ServiceAccountName: ps.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}

	return v.validatePodSpec(ctx, ns, ps.Kind, ps.APIVersion, ps.ObjectMeta.Labels, &ps.Spec.Template.Spec, opt).ViaField("spec.template.spec")
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
	ns := getNamespace(ctx, wp.Namespace)
	opt := k8schain.Options{
		Namespace:          ns,
		ServiceAccountName: wp.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, ns, wp.Kind, wp.APIVersion, wp.ObjectMeta.Labels, &wp.Spec.Template.Spec, opt).ViaField("spec.template.spec")
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
	ns := getNamespace(ctx, p.Namespace)
	opt := k8schain.Options{
		Namespace:          ns,
		ServiceAccountName: p.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}
	return v.validatePodSpec(ctx, ns, p.Kind, p.APIVersion, p.ObjectMeta.Labels, &p.Spec, opt).ViaField("spec")
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
	ns := getNamespace(ctx, c.Namespace)
	opt := k8schain.Options{
		Namespace:          ns,
		ServiceAccountName: c.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName,
		ImagePullSecrets:   imagePullSecrets,
	}

	return v.validatePodSpec(ctx, ns, c.Kind, c.APIVersion, c.ObjectMeta.Labels, &c.Spec.JobTemplate.Spec.Template.Spec, opt).ViaField("spec.jobTemplate.spec.template.spec")
}

func (v *Validator) validatePodSpec(ctx context.Context, namespace, kind, apiVersion string, labels map[string]string, ps *corev1.PodSpec, opt k8schain.Options) (errs *apis.FieldError) {
	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return apis.ErrGeneric(err.Error(), apis.CurrentField)
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

			config := config.FromContext(ctx)

			// During the migration from the secret only validation into policy
			// based ones. If there were matching policies that successfully
			// validated the image, keep tally of it and if all Policies that
			// matched validated, skip the traditional one since they are not
			// necessarily going to play nicely together.
			passedPolicyChecks := false
			if config != nil {
				policies, err := config.ImagePolicyConfig.GetMatchingPolicies(ref.Name(), kind, apiVersion, labels)
				if err != nil {
					errorField := apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i)
					errorField.Details = c.Image
					errs = errs.Also(errorField)
					continue
				}

				// If there is at least one policy that matches, that means it
				// has to be satisfied.
				if len(policies) > 0 {
					signatures, fieldErrors := validatePolicies(ctx, namespace, ref, policies, ociremote.WithRemoteOptions(
						remote.WithContext(ctx),
						remote.WithAuthFromKeychain(kc),
					))

					if len(signatures) != len(policies) {
						logging.FromContext(ctx).Warnf("Failed to validate at least one policy for %s", ref.Name())
						// Do we really want to add all the error details here?
						// Seems like we can just say which policy failed, so
						// doing that for now.
						// Split the errors and warnings to their own
						// error levels.
						hasWarnings := false
						hasErrors := false
						for failingPolicy, policyErrs := range fieldErrors {
							errDetails := c.Image
							warnDetails := c.Image
							for _, policyErr := range policyErrs {
								var fe *apis.FieldError
								if errors.As(policyErr, &fe) {
									if fe.Filter(apis.WarningLevel) != nil {
										warnDetails = warnDetails + " " + fe.Message
										hasWarnings = true
									} else {
										errDetails = errDetails + " " + fe.Message
										hasErrors = true
									}
								} else {
									// Just a regular error.
									errDetails = errDetails + " " + policyErr.Error()
								}
							}
							if hasWarnings {
								warnField := apis.ErrGeneric(fmt.Sprintf("failed policy: %s", failingPolicy), "image").ViaFieldIndex(field, i)
								warnField.Details = warnDetails
								errs = errs.Also(warnField).At(apis.WarningLevel)
							}
							if hasErrors {
								errorField := apis.ErrGeneric(fmt.Sprintf("failed policy: %s", failingPolicy), "image").ViaFieldIndex(field, i)
								errorField.Details = errDetails
								errs = errs.Also(errorField)
							}
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
						// Only say we passed if more than one authority was validated, which
						// means that there was a matching ClusterImagePolicy.
						if len(signatures) > 0 {
							passedPolicyChecks = true
						}
					}
				}
			}

			if passedPolicyChecks {
				logging.FromContext(ctx).Debugf("Found at least one matching policy and it was validated for %s", ref.Name())
				continue
			}

			// No matching policies, so go ahead and do the right thing based
			// on what the config is.
			// Note that if the default is allow, errs.Also works just fine
			// Also'ing a nil to it.
			errs = errs.Also(setNoMatchingPoliciesError(ctx, c.Image, field, i))
		}
	}

	checkContainers(ps.InitContainers, "initContainers")
	checkContainers(ps.Containers, "containers")

	return errs
}

// setNoMatchingPoliciesError returns nil if the no matching policies behaviour
// has been set to allow or has not been set. Otherwise returns either a warning
// or error based on the NoMatchPolicy.
func setNoMatchingPoliciesError(ctx context.Context, image, field string, index int) *apis.FieldError {
	// Check what the configuration is and act accordingly.
	pcConfig := policycontrollerconfig.FromContext(ctx)

	noMatchingPolicyError := apis.ErrGeneric("no matching policies", "image").ViaFieldIndex(field, index)
	noMatchingPolicyError.Details = image
	if pcConfig == nil {
		// This should not happen, but handle it as fail close
		return noMatchingPolicyError
	}
	switch pcConfig.NoMatchPolicy {
	case policycontrollerconfig.AllowAll:
		// Allow it through, nothing to do.
		return nil
	case policycontrollerconfig.DenyAll:
		return noMatchingPolicyError
	case policycontrollerconfig.WarnAll:
		return noMatchingPolicyError.At(apis.WarningLevel)
	default:
		// Fail closed.
		return noMatchingPolicyError
	}
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

func asFieldError(warn bool, err error) *apis.FieldError {
	r := &apis.FieldError{Message: err.Error()}
	if warn {
		return r.At(apis.WarningLevel)
	}
	return r.At(apis.ErrorLevel)
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
		static       bool
		attestations map[string][]PolicyAttestation
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
					result.err = cosign.NewVerificationError("disallowed by static policy")
					results <- result
					return
				}
				result.static = true

			case len(authority.Attestations) > 0:
				// We're doing the verify-attestations path, so validate (.att)
				result.attestations, result.err = ValidatePolicyAttestationsForAuthority(ctx, ref, authority, authorityRemoteOpts...)

			default:
				result.signatures, result.err = ValidatePolicySignaturesForAuthority(ctx, ref, authority, authorityRemoteOpts...)
			}
			results <- result
		}()
	}

	// If none of the Authorities for a given policy pass the checks, gather
	// the errors here. Even if there are errors, return the matched
	// authoritypolicies.
	authorityErrors := make([]error, 0, len(cip.Authorities))
	// We collect all the successfully satisfied Authorities into this and
	// return it.
	policyResult := &PolicyResult{
		AuthorityMatches: make(map[string]AuthorityMatch, len(cip.Authorities)),
	}
	for range cip.Authorities {
		select {
		case <-ctx.Done():
			authorityErrors = append(authorityErrors, fmt.Errorf("%w before validation completed", ctx.Err()))

		case result, ok := <-results:
			if !ok {
				authorityErrors = append(authorityErrors, errors.New("results channel closed before all results were sent"))
				continue
			}
			switch {
			case result.err != nil:
				// We only wrap actual policy failures as FieldErrors with the
				// possibly Warn level. Other things imho should be still
				// be considered errors.
				authorityErrors = append(authorityErrors, asFieldError(cip.Mode == "warn", result.err))

			case len(result.signatures) > 0:
				policyResult.AuthorityMatches[result.name] = AuthorityMatch{Signatures: result.signatures}

			case len(result.attestations) > 0:
				policyResult.AuthorityMatches[result.name] = AuthorityMatch{Attestations: result.attestations}

			case result.static:
				// This happens when we encounter a policy with:
				//   static:
				//     action: "pass"
				policyResult.AuthorityMatches[result.name] = AuthorityMatch{
					Static: true,
				}

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
			return nil, append(authorityErrors, asFieldError(cip.Mode == "warn", err))
		}
	}
	return policyResult, authorityErrors
}

func ociSignatureToPolicySignature(ctx context.Context, sigs []oci.Signature) []PolicySignature {
	ret := make([]PolicySignature, 0, len(sigs))
	for _, ociSig := range sigs {
		logging.FromContext(ctx).Debugf("Converting signature %+v", ociSig)

		if cert, err := ociSig.Cert(); err == nil && cert != nil {
			ce := cosign.CertExtensions{
				Cert: cert,
			}
			ret = append(ret, PolicySignature{
				Subject: csigs.CertSubject(cert),
				Issuer:  ce.GetIssuer(),
				GithubExtensions: GithubExtensions{
					WorkflowTrigger: ce.GetCertExtensionGithubWorkflowTrigger(),
					WorkflowSHA:     ce.GetExtensionGithubWorkflowSha(),
					WorkflowName:    ce.GetCertExtensionGithubWorkflowName(),
					WorkflowRepo:    ce.GetCertExtensionGithubWorkflowRepository(),
					WorkflowRef:     ce.GetCertExtensionGithubWorkflowRef(),
				},
			})
		} else {
			ret = append(ret, PolicySignature{
				// TODO(mattmoor): Is there anything we should encode for key-based?
			})
		}
	}
	return ret
}

// attestation is used to accumulate the signature along with extracted and
// validated metadata during validation to construct a list of
// PolicyAttestations upon completion without needing to refetch any of the
// parts.
type attestation struct {
	oci.Signature

	PredicateType string
	Payload       []byte
}

func attestationToPolicyAttestations(ctx context.Context, atts []attestation) []PolicyAttestation {
	ret := make([]PolicyAttestation, 0, len(atts))
	for _, att := range atts {
		logging.FromContext(ctx).Debugf("Converting attestation %+v", att)

		if cert, err := att.Cert(); err == nil && cert != nil {
			ce := cosign.CertExtensions{
				Cert: cert,
			}
			ret = append(ret, PolicyAttestation{
				PolicySignature: PolicySignature{
					Subject: csigs.CertSubject(cert),
					Issuer:  ce.GetIssuer(),
					GithubExtensions: GithubExtensions{
						WorkflowTrigger: ce.GetCertExtensionGithubWorkflowTrigger(),
						WorkflowSHA:     ce.GetExtensionGithubWorkflowSha(),
						WorkflowName:    ce.GetCertExtensionGithubWorkflowName(),
						WorkflowRepo:    ce.GetCertExtensionGithubWorkflowRepository(),
						WorkflowRef:     ce.GetCertExtensionGithubWorkflowRef(),
					},
				},
				PredicateType: att.PredicateType,
				Payload:       att.Payload,
			})
		} else {
			ret = append(ret, PolicyAttestation{
				PolicySignature: PolicySignature{
					// TODO(mattmoor): Is there anything we should encode for key-based?
				},
				PredicateType: att.PredicateType,
				Payload:       att.Payload,
			})
		}
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
	case authority.Key != nil:
		if len(authority.Key.PublicKeys) == 0 {
			return nil, fmt.Errorf("there are no public keys for authority %s", name)
		}
		// TODO(vaikas): What should happen if there are multiple keys
		// Is it even allowed? 'valid' returns success if any key
		// matches.
		// https://github.com/sigstore/policy-controller/issues/1652
		sps, err := valid(ctx, ref, rekorClient, authority.Key.PublicKeys, authority.Key.HashAlgorithmCode, remoteOpts...)
		if err != nil {
			return nil, fmt.Errorf("signature key validation failed for authority %s for %s: %w", name, ref.Name(), err)
		}
		logging.FromContext(ctx).Debugf("validated signature for %s for authority %s got %d signatures", ref.Name(), authority.Name, len(sps))
		return ociSignatureToPolicySignature(ctx, sps), nil

	case authority.Keyless != nil:
		if authority.Keyless.URL != nil {
			// TODO: This will probably need to change for:
			// https://github.com/sigstore/policy-controller/issues/138
			fulcioRoots, err := fulcioroots.Get()
			if err != nil {
				return nil, fmt.Errorf("fetching FulcioRoot: %w", err)
			}
			sps, err := validSignaturesWithFulcio(ctx, ref, fulcioRoots, rekorClient, authority.Keyless.Identities, remoteOpts...)
			if err != nil {
				logging.FromContext(ctx).Errorf("failed validSignatures for authority %s with fulcio for %s: %v", name, ref.Name(), err)
				return nil, fmt.Errorf("signature keyless validation failed for authority %s for %s: %w", name, ref.Name(), err)
			}
			logging.FromContext(ctx).Debugf("validated signature for %s, got %d signatures", ref.Name(), len(sps))
			return ociSignatureToPolicySignature(ctx, sps), nil
		}
		return nil, fmt.Errorf("no Keyless URL specified")
	}

	// This should never happen because authority has to have been validated to
	// be either having a Key, Keyless, or Static (handled elsewhere)
	return nil, errors.New("authority has neither key, keyless, or static specified")
}

// ValidatePolicyAttestationsForAuthority takes the Authority and tries to
// verify attestations against it.
func ValidatePolicyAttestationsForAuthority(ctx context.Context, ref name.Reference, authority webhookcip.Authority, remoteOpts ...ociremote.Option) (map[string][]PolicyAttestation, error) {
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
			verifier, err := signature.LoadVerifier(k, authority.Key.HashAlgorithmCode)
			if err != nil {
				logging.FromContext(ctx).Errorf("error creating verifier: %v", err)
				return nil, fmt.Errorf("creating verifier: %w", err)
			}
			va, err := validAttestations(ctx, ref, verifier, rekorClient, remoteOpts...)
			if err != nil {
				logging.FromContext(ctx).Errorf("error validating attestations: %v", err)
				return nil, fmt.Errorf("attestation key validation failed for authority %s for %s: %w", name, ref.Name(), err)
			}
			verifiedAttestations = append(verifiedAttestations, va...)
		}

	case authority.Keyless != nil:
		if authority.Keyless != nil && authority.Keyless.URL != nil {
			// TODO: This will probably need to change for:
			// https://github.com/sigstore/policy-controller/issues/138
			fulcioRoots, err := fulcioroots.Get()
			if err != nil {
				return nil, fmt.Errorf("fetching FulcioRoot: %w", err)
			}
			va, err := validAttestationsWithFulcio(ctx, ref, fulcioRoots, rekorClient, authority.Keyless.Identities, remoteOpts...)
			if err != nil {
				logging.FromContext(ctx).Errorf("failed validAttestationsWithFulcio for authority %s with fulcio for %s: %v", name, ref.Name(), err)
				return nil, fmt.Errorf("attestation keyless validation failed for authority %s for %s: %w", name, ref.Name(), err)
			}
			verifiedAttestations = append(verifiedAttestations, va...)
		}
	}

	// If we didn't get any verified attestations either from the Key or Keyless
	// path, then error out
	if len(verifiedAttestations) == 0 {
		logging.FromContext(ctx).Errorf("no valid attestations found for authority %s for %s", name, ref.Name())
		return nil, fmt.Errorf("%w for authority %s for %s", cosign.ErrNoMatchingAttestations, name, ref.Name())
	}
	logging.FromContext(ctx).Debugf("Found %d valid attestations, validating policies for them", len(verifiedAttestations))

	// Now spin through the Attestations that the user specified and validate
	// them.
	// TODO(vaikas): Pretty inefficient here, figure out a better way if
	// possible.
	ret := make(map[string][]PolicyAttestation, len(authority.Attestations))
	for _, wantedAttestation := range authority.Attestations {
		// There's a particular type, so we need to go through all the verified
		// attestations and make sure that our particular one is satisfied.
		checkedAttestations := make([]attestation, 0, len(verifiedAttestations))
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
			if wantedAttestation.Type != "" {
				if err := policy.EvaluatePolicyAgainstJSON(ctx, wantedAttestation.Name, wantedAttestation.Type, wantedAttestation.Data, attBytes); err != nil {
					return nil, err
				}
			}
			// Ok, so this passed aok, jot it down to our result set as
			// verified attestation with the predicate type match
			checkedAttestations = append(checkedAttestations, attestation{
				Signature:     va,
				PredicateType: wantedAttestation.PredicateType,
				Payload:       attBytes,
			})
		}
		if len(checkedAttestations) == 0 {
			return nil, fmt.Errorf("%w with type %s", cosign.ErrNoMatchingAttestations, wantedAttestation.PredicateType)
		}
		ret[wantedAttestation.Name] = attestationToPolicyAttestations(ctx, checkedAttestations)
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
		Namespace:          getNamespace(ctx, ps.Namespace),
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
		Namespace:          getNamespace(ctx, wp.Namespace),
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
		Namespace:          getNamespace(ctx, p.Namespace),
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
		Namespace:          getNamespace(ctx, c.Namespace),
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
				digest, err := remoteResolveDigest(ref, ociremote.WithRemoteOptions(
					remote.WithContext(ctx),
					remote.WithAuthFromKeychain(kc),
				))
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

// getNamespace tries to extract the namespace from the HTTPRequest
// if the namespace passed as argument is empty. This is a workaround
// for a bug in k8s <= 1.24.
func getNamespace(ctx context.Context, namespace string) string {
	if namespace == "" {
		r := apis.GetHTTPRequest(ctx)
		if r != nil && r.Body != nil {
			var review admissionv1.AdmissionReview
			if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
				logging.FromContext(ctx).Errorf("could not decode body:", err)
				return ""
			}
			return review.Request.Namespace
		}
	}
	return namespace
}
