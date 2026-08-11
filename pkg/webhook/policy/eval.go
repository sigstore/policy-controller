//
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

// Package policy contains the policy code that lived in
// github.com/sigstore/cosign/v3/pkg/policy: the CUE/rego evaluation code
// removed in cosign v3.1.2 (sigstore/cosign#4936), and the pre-v3.0.6
// AttestationToPayloadJSON. cosign v3.0.6 dropped the `_type` key from
// vuln attestation payloads (struct tag change) and moved generic
// statement marshaling to protojson, which reorders fields and produces
// non-deterministic whitespace.
package policy

import (
	"context"
	"fmt"

	"cuelang.org/go/cue/cuecontext"
)

// EvaluatePolicyAgainstJSON is used to run a policy engine against JSON bytes.
// These bytes can be for example Attestations, or ClusterImagePolicy result
// types.
// name - which attestation are we evaluating
// policyType - cue|rego
// policyBody - String representing either cue or rego language
// jsonBytes - Bytes to evaluate against the policyBody in the given language
func EvaluatePolicyAgainstJSON(ctx context.Context, name, policyType string, policyBody string, jsonBytes []byte) (warnings error, errors error) {
	switch policyType {
	case "cue":
		cueValidationErr := evaluateCue(ctx, jsonBytes, policyBody)
		if cueValidationErr != nil {
			return nil, &EvaluationFailure{
				fmt.Errorf("failed evaluating cue policy for %s: %w", name, cueValidationErr),
			}
		}
	case "rego":
		regoValidationWarn, regoValidationErr := evaluateRego(ctx, jsonBytes, policyBody)
		if regoValidationErr != nil {
			return regoValidationWarn, &EvaluationFailure{
				fmt.Errorf("failed evaluating rego policy for type %s: %w", name, regoValidationErr),
			}
		}
		// It is possible to return warning messages when the policy is compliant
		return regoValidationWarn, regoValidationErr
	default:
		return nil, fmt.Errorf("sorry Type %s is not supported yet", policyType)
	}
	return nil, nil
}

// evaluateCue evaluates a cue policy `evaluator` against `attestation`
func evaluateCue(_ context.Context, attestation []byte, evaluator string) error {
	cueCtx := cuecontext.New()
	cueEvaluator := cueCtx.CompileString(evaluator)
	if cueEvaluator.Err() != nil {
		return fmt.Errorf("failed to compile the cue policy with error: %w", cueEvaluator.Err())
	}
	cueAtt := cueCtx.CompileBytes(attestation)
	if cueAtt.Err() != nil {
		return fmt.Errorf("failed to compile the attestation data with error: %w", cueAtt.Err())
	}
	result := cueEvaluator.Unify(cueAtt)
	if err := result.Validate(); err != nil {
		return fmt.Errorf("failed to evaluate the policy with error: %w", err)
	}
	return nil
}

// evaluateRego evaluates a rego policy `evaluator` against `attestation`
func evaluateRego(_ context.Context, attestation []byte, evaluator string) (warnings error, errors error) {
	return validateJSONWithModuleInput(attestation, evaluator)
}
