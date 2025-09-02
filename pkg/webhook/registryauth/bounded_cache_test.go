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

package registryauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	lru "github.com/hashicorp/golang-lru/v2"
)

// mockECRHelper is used to mock the ECR helper for testing
type mockECRHelper struct {
	getFunc     func(string) (string, string, error)
	addFunc     func(interface{}) error
	deleteFunc  func(string) error
	listFunc    func() (map[string]string, error)
	callHistory []string
}

func (m *mockECRHelper) Get(serverURL string) (string, string, error) {
	m.callHistory = append(m.callHistory, "Get:"+serverURL)
	return m.getFunc(serverURL)
}

func (m *mockECRHelper) Add(creds interface{}) error {
	m.callHistory = append(m.callHistory, "Add")
	return m.addFunc(creds)
}

func (m *mockECRHelper) Delete(serverURL string) error {
	m.callHistory = append(m.callHistory, "Delete:"+serverURL)
	return m.deleteFunc(serverURL)
}

func (m *mockECRHelper) List() (map[string]string, error) {
	m.callHistory = append(m.callHistory, "List")
	return m.listFunc()
}

func newMockECRHelper() *mockECRHelper {
	return &mockECRHelper{
		getFunc: func(serverURL string) (string, string, error) {
			return "testuser", "testpassword", nil
		},
		addFunc: func(creds interface{}) error {
			return ErrCredentialsNotFound
		},
		deleteFunc: func(serverURL string) error {
			return ErrCredentialsNotFound
		},
		listFunc: func() (map[string]string, error) {
			return map[string]string{}, nil
		},
		callHistory: []string{},
	}
}

func TestNewECRCredentialCache(t *testing.T) {
	// Test that we can create a new cache
	cache, err := NewECRCredentialCache(10, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	if cache == nil {
		t.Fatal("Cache is nil")
	}

	// Check initial state
	if cache.cache.Len() != 0 {
		t.Errorf("Expected empty cache, got size %d", cache.cache.Len())
	}

	// Test with invalid cache size
	_, err = NewECRCredentialCache(-1, 1*time.Hour)
	if err == nil {
		t.Error("Expected error for negative cache size, got nil")
	}
}

func TestNewDockerCredentialHelper(t *testing.T) {
	cache, err := NewECRCredentialCache(10, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	helper := NewDockerCredentialHelper(cache)
	if helper == nil {
		t.Fatal("Helper is nil")
	}

	// Test Add (should always return error)
	err = helper.Add(struct{}{})
	if !errors.Is(err, ErrCredentialsNotFound) {
		t.Errorf("Expected ErrCredentialsNotFound, got %v", err)
	}

	// Test Delete (should always return error)
	err = helper.Delete("test-url")
	if !errors.Is(err, ErrCredentialsNotFound) {
		t.Errorf("Expected ErrCredentialsNotFound, got %v", err)
	}

	// Test List (should return empty map)
	list, err := helper.List()
	if err != nil {
		t.Errorf("List returned error: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("Expected empty list, got %d entries", len(list))
	}
}

func TestGetEnvVars(t *testing.T) {
	envVars := GetEnvVars()
	if len(envVars) != 1 {
		t.Errorf("Expected 1 environment variable, got %d", len(envVars))
	}
	if envVars[0] != "AWS_ECR_DISABLE_CACHE=true" {
		t.Errorf("Expected AWS_ECR_DISABLE_CACHE=true, got %s", envVars[0])
	}
}

func TestCache_Get(t *testing.T) {
	// Create a mock ECR helper
	mockHelper := newMockECRHelper()

	// Create a cache manually with the mock helper
	cache := &ECRCredentialCache{
		cache: func() *lru.Cache[string, Credential] {
			cache, _ := lru.New[string, Credential](10)
			return cache
		}(),
		helper: mockHelper,
		ttl:    1 * time.Hour,
		expiry: make(map[string]time.Time),
		mu:     sync.Mutex{},
	}

	// First call should fetch from the helper
	username, password, err := cache.Get("registry1.amazonaws.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if username != "testuser" || password != "testpassword" {
		t.Errorf("Expected testuser/testpassword, got %s/%s", username, password)
	}

	// Check that the helper was called
	if len(mockHelper.callHistory) != 1 || mockHelper.callHistory[0] != "Get:registry1.amazonaws.com" {
		t.Errorf("Expected helper Get to be called once, got %v", mockHelper.callHistory)
	}

	// Check that the cache now has an entry
	if cache.cache.Len() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.cache.Len())
	}

	// Reset call history
	mockHelper.callHistory = []string{}

	// Second call should use the cache
	username, password, err = cache.Get("registry1.amazonaws.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if username != "testuser" || password != "testpassword" {
		t.Errorf("Expected testuser/testpassword, got %s/%s", username, password)
	}

	// Check that the helper was NOT called again
	if len(mockHelper.callHistory) != 0 {
		t.Errorf("Expected helper not to be called, got %v", mockHelper.callHistory)
	}
}

func TestCache_Expiration(t *testing.T) {
	// Create a mock ECR helper
	mockHelper := newMockECRHelper()

	// Create a cache with a very short TTL (1 millisecond)
	cache := &ECRCredentialCache{
		cache: func() *lru.Cache[string, Credential] {
			cache, _ := lru.New[string, Credential](10)
			return cache
		}(),
		helper: mockHelper,
		ttl:    1 * time.Millisecond,
		expiry: make(map[string]time.Time),
		mu:     sync.Mutex{},
	}

	// First call should fetch from the helper
	_, _, err := cache.Get("registry1.amazonaws.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check that the helper was called
	if len(mockHelper.callHistory) != 1 {
		t.Errorf("Expected helper Get to be called once, got %v", mockHelper.callHistory)
	}

	// Wait for the entry to expire
	time.Sleep(2 * time.Millisecond)

	// Reset call history
	mockHelper.callHistory = []string{}

	// After expiration, the helper should be called again
	_, _, err = cache.Get("registry1.amazonaws.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check that the helper was called again
	if len(mockHelper.callHistory) != 1 || mockHelper.callHistory[0] != "Get:registry1.amazonaws.com" {
		t.Errorf("Expected helper Get to be called again, got %v", mockHelper.callHistory)
	}
}

func TestCache_MaxSize(t *testing.T) {
	// Create a mock ECR helper
	mockHelper := newMockECRHelper()

	// Create a cache with a small size (3 entries)
	smallCache := &ECRCredentialCache{
		cache: func() *lru.Cache[string, Credential] {
			cache, _ := lru.New[string, Credential](3)
			return cache
		}(),
		helper: mockHelper,
		ttl:    1 * time.Hour,
		expiry: make(map[string]time.Time),
		mu:     sync.Mutex{},
	}

	// Fill the cache with entries
	for i := 0; i < 5; i++ {
		registry := fmt.Sprintf("registry%d.amazonaws.com", i)
		_, _, err := smallCache.Get(registry)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	// Cache should only have 3 entries (most recent ones)
	if smallCache.cache.Len() != 3 {
		t.Errorf("Expected cache size 3, got %d", smallCache.cache.Len())
	}

	// The oldest entries should have been evicted
	// Check that registry0 and registry1 are no longer in the cache
	for i := 0; i < 2; i++ {
		registry := fmt.Sprintf("registry%d.amazonaws.com", i)
		contains := smallCache.cache.Contains(registry)
		if contains {
			t.Errorf("Expected registry%d to be evicted from cache", i)
		}
	}

	// The newest entries should still be in the cache
	for i := 2; i < 5; i++ {
		registry := fmt.Sprintf("registry%d.amazonaws.com", i)
		contains := smallCache.cache.Contains(registry)
		if !contains {
			t.Errorf("Expected registry%d to be in cache", i)
		}
	}
}

func TestIntegrationWithRealECRHelper(t *testing.T) {
	// This test uses the real ECR helper but doesn't make actual network calls
	// It verifies that our wrapper works correctly with the ECR helper

	// Create a real ECR helper with logging disabled
	realHelper := ecr.NewECRHelper(ecr.WithLogger(io.Discard))

	// Adapt it to our interface
	adapter := NewECRHelperAdapter(realHelper)

	// Create a cache using the adapter
	cache := &ECRCredentialCache{
		cache: func() *lru.Cache[string, Credential] {
			cache, _ := lru.New[string, Credential](10)
			return cache
		}(),
		helper: adapter,
		ttl:    1 * time.Hour,
		expiry: make(map[string]time.Time),
		mu:     sync.Mutex{},
	}

	// Create a docker credential helper using our cache
	helper := NewDockerCredentialHelper(cache)

	// Verify that the helper is created correctly
	if helper == nil {
		t.Fatal("DockerCredentialHelper is nil")
	}

	// Unsupported operations should return ErrCredentialsNotFound
	if err := helper.Add(struct{}{}); !errors.Is(err, ErrCredentialsNotFound) {
		t.Errorf("Expected ErrCredentialsNotFound for Add, got %v", err)
	}

	if err := helper.Delete("test"); !errors.Is(err, ErrCredentialsNotFound) {
		t.Errorf("Expected ErrCredentialsNotFound for Delete, got %v", err)
	}
}

func TestGetAmazonKeychainBasic(t *testing.T) {
	// Using a test context
	ctx := context.Background()

	// Get the keychain
	keychain := getAmazonKeychain(ctx)

	// Verify that the keychain is created
	if keychain == nil {
		t.Fatal("Keychain is nil")
	}
}
