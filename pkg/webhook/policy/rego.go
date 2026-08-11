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

// The rego evaluation code below lived in
// github.com/sigstore/cosign/v3/pkg/cosign/rego until it was removed in
// cosign v3.1.2 (sigstore/cosign#4936).

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// cosignRegoPackageName defines the expected package name of a provided rego module
const cosignRegoPackageName = "sigstore"

// cosignEvaluationRule defines the expected evaluation role of a provided rego module
const cosignEvaluationRule = "isCompliant"

// cosignRuleResult defines a expected result object when wrapping the custom messages of the result of our cosign rego rule
type cosignRuleResult struct {
	Warning string `json:"warning,omitempty"`
	Error   string `json:"error,omitempty"`
	Result  bool   `json:"result,omitempty"`
}

// validateJSONWithModuleInput takes the body of the results to evaluate and the defined module
// in a policy to validate against the input data
func validateJSONWithModuleInput(jsonBody []byte, moduleInput string) (warnings error, errors error) {
	ctx := context.Background()
	query := fmt.Sprintf("%s = data.%s.%s", cosignEvaluationRule, cosignRegoPackageName, cosignEvaluationRule)
	module := fmt.Sprintf("%s.rego", cosignRegoPackageName)

	r := rego.New(
		rego.Query(query),
		rego.Module(module, moduleInput),
		rego.SetRegoVersion(ast.RegoV0),
	)

	evalQuery, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	var input interface{}
	dec := json.NewDecoder(bytes.NewBuffer(jsonBody))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil {
		return nil, err
	}

	rs, err := evalQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	for _, result := range rs {
		switch response := result.Bindings[cosignEvaluationRule].(type) {
		case []interface{}:
			return evaluateRegoEvalMapResult(query, response)
		case bool:
			if response {
				return nil, nil
			}
		}
	}

	return nil, fmt.Errorf("policy is not compliant for query '%s'", query)
}

func evaluateRegoEvalMapResult(query string, response []interface{}) (warning error, retErr error) {
	retErr = fmt.Errorf("policy is not compliant for query %q", query) //nolint: revive
	for _, r := range response {
		// Upstream cosign asserted the map type unchecked and panicked on
		// non-map rule results; fail closed instead.
		rMap, ok := r.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("policy is not compliant for query '%s': unexpected result type %T", query, r)
		}
		mapBytes, err := json.Marshal(rMap)
		if err != nil {
			return nil, fmt.Errorf("policy is not compliant for query '%s' due to parsing errors: %w", query, err)
		}
		var resultObject cosignRuleResult
		err = json.Unmarshal(mapBytes, &resultObject)
		if err != nil {
			return nil, fmt.Errorf("policy is not compliant for query '%s' due to parsing errors: %w", query, err)
		}

		// Check if it is complaint
		if resultObject.Result {
			if resultObject.Warning == "" {
				return nil, nil
			}
			return fmt.Errorf("warning: %s", resultObject.Warning), nil
		}
		warning = errors.New(resultObject.Warning)
		retErr = fmt.Errorf("policy is not compliant for query '%s' with errors: %s", query, resultObject.Error) //nolint: revive
	}
	return warning, retErr
}
