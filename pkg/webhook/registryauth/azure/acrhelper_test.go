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

package azure

import (
	"strings"
	"testing"
)

func TestNewACRHelper(t *testing.T) {
	helper := NewACRHelper()
	if helper == nil {
		t.Fatal("Expected non-nil helper, got nil")
	}

	// The helper type already implements credentials.Helper, so we don't need a type assertion
	// Just verify it's not nil
	if helper == nil {
		t.Error("Helper is nil")
	}
}

func TestIsACR(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		want     bool
	}{
		{
			name:     "valid ACR registry",
			registry: "myregistry.azurecr.io",
			want:     true,
		},
		{
			name:     "valid ACR with subdomain",
			registry: "myteam.myregistry.azurecr.io",
			want:     true,
		},
		{
			name:     "not an ACR registry",
			registry: "gcr.io",
			want:     false,
		},
		{
			name:     "Docker Hub",
			registry: "docker.io",
			want:     false,
		},
		{
			name:     "ECR registry",
			registry: "123456789012.dkr.ecr.us-west-2.amazonaws.com",
			want:     false,
		},
		{
			name:     "missing registry name",
			registry: ".azurecr.io",
			want:     true, // This is technically valid based on the current implementation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isACR(tt.registry); got != tt.want {
				t.Errorf("isACR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddOperation(t *testing.T) {
	helper := &ACRHelper{}
	err := helper.Add(nil)
	if err == nil {
		t.Error("Expected error for unimplemented Add operation, got nil")
	}
	if !strings.Contains(err.Error(), "unimplemented") {
		t.Errorf("Expected 'unimplemented' in error message, got: %s", err.Error())
	}
}

func TestDeleteOperation(t *testing.T) {
	helper := &ACRHelper{}
	err := helper.Delete("registry.azurecr.io")
	if err == nil {
		t.Error("Expected error for unimplemented Delete operation, got nil")
	}
	if !strings.Contains(err.Error(), "unimplemented") {
		t.Errorf("Expected 'unimplemented' in error message, got: %s", err.Error())
	}
}

func TestListOperation(t *testing.T) {
	helper := &ACRHelper{}
	_, err := helper.List()
	if err == nil {
		t.Error("Expected error for unimplemented List operation, got nil")
	}
	if !strings.Contains(err.Error(), "unimplemented") {
		t.Errorf("Expected 'unimplemented' in error message, got: %s", err.Error())
	}
}

// We can't easily test the Get method without mocking Azure SDK components,
// but we can at least test the non-ACR registry case
func TestGetNonACRRegistry(t *testing.T) {
	helper := &ACRHelper{}
	_, _, err := helper.Get("gcr.io")
	if err == nil {
		t.Error("Expected error for non-ACR registry, got nil")
	}
	if !strings.Contains(err.Error(), "not an ACR registry") {
		t.Errorf("Expected 'not an ACR registry' in error message, got: %s", err.Error())
	}
}
