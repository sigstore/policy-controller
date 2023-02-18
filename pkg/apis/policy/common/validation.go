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

package common

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	registryfuncs "github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"github.com/sigstore/sigstore/pkg/signature/kms/azure"
	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	"github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
	"k8s.io/apimachinery/pkg/util/sets"
	"knative.dev/pkg/apis"
)

const (
	ociRepoDelimiter = "/"
)

var (
	SupportedKMSProviders = []string{aws.ReferenceScheme, azure.ReferenceScheme, hashivault.ReferenceScheme, gcp.ReferenceScheme}

	// TODO: create constants in to cosign?
	ValidPredicateTypes = sets.NewString("custom", "slsaprovenance", "spdx",
		"spdxjson", "cyclonedx", "link", "vuln")

	// If a static matches, define the behaviour for it.
	ValidStaticRefTypes = sets.NewString("fail", "pass")

	// Valid modes for a policy
	ValidModes = sets.NewString("enforce", "warn")

	// ValidResourceNames for a policy match selector.
	// By default, this is empty, which should allow any resource name, however,
	// this can be populated with the set of resources to allow in the validating
	// webhook, which should match the set of resources.
	ValidResourceNames = sets.NewString()
)

func ValidateOCI(oci string) error {
	// We want to validate both registry uris only or registry with valid repository names
	parts := strings.SplitN(oci, ociRepoDelimiter, 2)
	if len(parts) == 2 && (strings.ContainsRune(parts[0], '.') || strings.ContainsRune(parts[0], ':')) {
		_, err := registryfuncs.NewRepository(oci, registryfuncs.StrictValidation)
		if err != nil {
			return err
		}
		return nil
	}
	_, err := registryfuncs.NewRegistry(oci, registryfuncs.StrictValidation)
	if err != nil {
		return err
	}
	return nil
}

var (
	errKMSReference = errors.New("kms key should be in the format awskms://[ENDPOINT]/[ID/ALIAS/ARN] (endpoint optional)")

	// Key ID/ALIAS/ARN conforms to KMS standard documented here: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
	// Key format examples:
	// Key ID: awskms:///1234abcd-12ab-34cd-56ef-1234567890ab
	// Key ID with endpoint: awskms://localhost:4566/1234abcd-12ab-34cd-56ef-1234567890ab
	// Key ARN: awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
	// Key ARN with endpoint: awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
	// Alias name: awskms:///alias/ExampleAlias
	// Alias name with endpoint: awskms://localhost:4566/alias/ExampleAlias
	// Alias ARN: awskms:///arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias
	// Alias ARN with endpoint: awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias
	uuidRE      = `m?r?k?-?[A-Fa-f0-9]{8}-?[A-Fa-f0-9]{4}-?[A-Fa-f0-9]{4}-?[A-Fa-f0-9]{4}-?[A-Fa-f0-9]{12}`
	arnRE       = `arn:(?:aws|aws-us-gov):kms:[a-z0-9-]+:\d{12}:`
	hostRE      = `([^/]*)/`
	keyIDRE     = regexp.MustCompile(`^awskms://` + hostRE + `(` + uuidRE + `)$`)
	keyARNRE    = regexp.MustCompile(`^awskms://` + hostRE + `(` + arnRE + `key/` + uuidRE + `)$`)
	aliasNameRE = regexp.MustCompile(`^awskms://` + hostRE + `((alias/.*))$`)
	aliasARNRE  = regexp.MustCompile(`^awskms://` + hostRE + `(` + arnRE + `(alias/.*))$`)
	allREs      = []*regexp.Regexp{keyIDRE, keyARNRE, aliasNameRE, aliasARNRE}
)

// validAWSKMSRegex returns a non-nil error if the reference string is invalid
func validAWSKMSRegex(ref string) error {
	for _, re := range allREs {
		if re.MatchString(ref) {
			return nil
		}
	}
	return errKMSReference
}

// validateAWSKMS validates that the KMS conforms to AWS
// KMS format:
// awskms://$ENDPOINT/$KEYID
// Where:
// $ENDPOINT is optional
// $KEYID is either the key ARN or an alias ARN
// Key ID/ALIAS/ARN conforms to KMS standard documented here: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id
// Reasoning for only supporting these formats is that other
// formats require additional configuration via ENV variables.
func validateAWSKMS(kms string) *apis.FieldError {
	parts := strings.Split(kms, "/")
	// Either it is a key id reference or an endpoint, it should be composed of more than 4 parts.
	if len(parts) < 4 {
		return apis.ErrInvalidValue(kms, apis.CurrentField, "malformed AWS KMS format 'awskms://$ENDPOINT/$KEYID', should be conformant with KMS standard documented here: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id")
	}

	// validate the awskms reference against valid regular expressions
	if err := validAWSKMSRegex(kms); err != nil {
		return apis.ErrInvalidValue(kms, apis.CurrentField, err.Error())
	}

	endpoint := parts[2]
	// Sometimes this logic assumes the endpoint is part of the KEY e.g. awskms://arn:...
	// These examples are invalid, so we need to throw proper errors
	if endpoint != "" && (strings.HasPrefix(endpoint, "arn") || strings.HasPrefix(endpoint, "alias")) {
		return apis.ErrInvalidValue(kms, apis.CurrentField, errKMSReference.Error())
	}
	// Even if the reference is valid, the endpoint could NOT be, only validate if not empty
	if endpoint != "" {
		_, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			return apis.ErrInvalidValue(kms, apis.CurrentField, fmt.Sprintf("malformed endpoint: %s", err))
		}
	}
	keyID := parts[3]
	arn, err := arn.Parse(keyID)
	if err != nil {
		return apis.ErrInvalidValue(kms, apis.CurrentField, fmt.Sprintf("failed to parse either key or alias arn: %s", err))
	}
	// Only support key or alias ARN.
	if arn.Resource != "key" && arn.Resource != "alias" {
		return apis.ErrInvalidValue(kms, apis.CurrentField, fmt.Sprintf("Got ARN: %+v Resource: %s", arn, arn.Resource))
	}
	return nil
}

func ValidateKMS(kms string) *apis.FieldError {
	var errs *apis.FieldError
	validPrefix := false
	for _, prefix := range SupportedKMSProviders {
		if strings.HasPrefix(kms, prefix) {
			validPrefix = true
			break
		}
	}
	if !validPrefix {
		return apis.ErrInvalidValue(kms, apis.CurrentField, fmt.Sprintf("malformed KMS format, should be prefixed by any of the supported providers: %v", SupportedKMSProviders))
	}
	if strings.HasPrefix(kms, aws.ReferenceScheme) {
		errs = errs.Also(validateAWSKMS(kms))
	}
	return errs
}
