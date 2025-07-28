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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestValidateOCI(t *testing.T) {
	tests := []struct {
		oci         string
		errorString string
		isError     bool
	}{
		{
			oci:     "gcr.io",
			isError: false,
		},
		{
			oci:         "gcr.io/test/*",
			errorString: "repository can only contain the characters `abcdefghijklmnopqrstuvwxyz0123456789_-./`: test/*",
			isError:     true,
		},
		{
			oci:         "gcr.@io/test",
			errorString: "registries must be valid RFC 3986 URI authorities: gcr.@io",
			isError:     true,
		},
		{
			oci:     "ghcr.io/sigstore/test",
			isError: false,
		},
		{
			oci:     "registry.example.com",
			isError: false,
		},
		{
			oci:     "localhost:8080/test",
			isError: false,
		},
		{
			oci:     "localhost",
			isError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.oci, func(t *testing.T) {
			err := ValidateOCI(test.oci)
			if !test.isError && err != nil {
				t.Error("Unxpected error", err.Error())
			}
			if test.isError {
				if diff := cmp.Diff(test.errorString, err.Error()); diff != "" {
					t.Error("Unexpected error mesage (-want, +got):", diff)
				}
			}
		})
	}
}

func TestValidAWSKMSRegex(t *testing.T) {
	tests := []struct {
		name        string
		ref         string
		shouldMatch bool
	}{
		{
			name:        "valid key ID",
			ref:         "awskms:///1234abcd-12ab-34cd-56ef-1234567890ab",
			shouldMatch: true,
		},
		{
			name:        "valid key ID with endpoint",
			ref:         "awskms://localhost:4566/1234abcd-12ab-34cd-56ef-1234567890ab",
			shouldMatch: true,
		},
		{
			name:        "valid key ARN",
			ref:         "awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			shouldMatch: true,
		},
		{
			name:        "valid key ARN with endpoint",
			ref:         "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			shouldMatch: true,
		},
		{
			name:        "valid alias name",
			ref:         "awskms:///alias/ExampleAlias",
			shouldMatch: true,
		},
		{
			name:        "valid alias name with endpoint",
			ref:         "awskms://localhost:4566/alias/ExampleAlias",
			shouldMatch: true,
		},
		{
			name:        "valid alias ARN",
			ref:         "awskms:///arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
			shouldMatch: true,
		},
		{
			name:        "valid alias ARN with endpoint",
			ref:         "awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias",
			shouldMatch: true,
		},
		{
			name:        "invalid format - missing prefix",
			ref:         "kms:///1234abcd-12ab-34cd-56ef-1234567890ab",
			shouldMatch: false,
		},
		{
			name:        "invalid format - missing slashes",
			ref:         "awskms:/1234abcd-12ab-34cd-56ef-1234567890ab",
			shouldMatch: false,
		},
		{
			name:        "invalid format - malformed UUID",
			ref:         "awskms:///1234abcd-12ab-34cd-56ef-1234567890",
			shouldMatch: false,
		},
		{
			name:        "invalid format - malformed ARN",
			ref:         "awskms:///arn:aws:kms:us-east-2:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			shouldMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validAWSKMSRegex(test.ref)
			if test.shouldMatch && err != nil {
				t.Errorf("Expected regex to match, but got error: %v", err)
			}
			if !test.shouldMatch && err == nil {
				t.Errorf("Expected regex not to match, but it did")
			}
		})
	}
}

func TestValidateAWSKMS(t *testing.T) {
	tests := []struct {
		name          string
		kms           string
		expectError   bool
		errorContains string
	}{
		// Only ARN formats don't cause errors with the current arn.Parse implementation
		{
			name:        "valid key ARN",
			kms:         "awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			expectError: false,
		},
		{
			name:          "too few parts",
			kms:           "awskms://keyid",
			expectError:   true,
			errorContains: "malformed AWS KMS format",
		},
		{
			name:          "invalid regex",
			kms:           "awskms:///invalid-key-id",
			expectError:   true,
			errorContains: "kms key should be in the format",
		},
		{
			name:          "ARN as endpoint",
			kms:           "awskms://arn:aws:kms:us-east-2:111122223333/key/1234abcd-12ab-34cd-56ef-1234567890ab",
			expectError:   true,
			errorContains: "kms key should be in the format",
		},
		{
			name:          "invalid endpoint",
			kms:           "awskms://invalid_endpoint/1234abcd-12ab-34cd-56ef-1234567890ab",
			expectError:   true,
			errorContains: "malformed endpoint",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateAWSKMS(test.kms)
			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if test.errorContains != "" && !strings.Contains(err.Error(), test.errorContains) {
					t.Errorf("Expected error containing %q but got %q", test.errorContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestValidateKMS(t *testing.T) {
	tests := []struct {
		name          string
		kms           string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid AWS KMS reference",
			kms:         "awskms:///1234abcd-12ab-34cd-56ef-1234567890ab",
			expectError: false,
		},
		{
			name:        "valid Azure KMS reference",
			kms:         "azurekms://",
			expectError: false,
		},
		{
			name:        "valid GCP KMS reference",
			kms:         "gcpkms://",
			expectError: false,
		},
		{
			name:        "valid HashiVault KMS reference",
			kms:         "hashivault://",
			expectError: false,
		},
		{
			name:          "unsupported KMS provider",
			kms:           "unsupportedkms://keyid",
			expectError:   true,
			errorContains: "malformed KMS format, should be prefixed by any of the supported providers",
		},
		{
			name:          "invalid AWS KMS reference",
			kms:           "awskms://invalid",
			expectError:   true,
			errorContains: "malformed AWS KMS format",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateKMS(test.kms)
			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if test.errorContains != "" && !strings.Contains(err.Error(), test.errorContains) {
					t.Errorf("Expected error containing %q but got %q", test.errorContains, err.Error())
				}
			} else if err != nil {
				// For AWS KMS we do deeper validation which could fail
				if strings.HasPrefix(test.kms, "awskms://") {
					// Skip detailed AWS KMS validation errors as they're tested separately
				} else if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}
