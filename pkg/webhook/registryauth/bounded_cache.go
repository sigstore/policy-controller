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
	"errors"
	"io"
	"sync"
	"time"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	lru "github.com/hashicorp/golang-lru/v2"
)

// Credential represents a username/password pair for a specific registry server
type Credential struct {
	ServerURL string
	Username  string
	Password  string
}

// ErrCredentialsNotFound is returned when credentials are not found
var ErrCredentialsNotFound = errors.New("credentials not found")

// CredentialHelper defines the interface for credential helpers
type CredentialHelper interface {
	Get(string) (string, string, error)
	Add(interface{}) error
	Delete(string) error
	List() (map[string]string, error)
}

// ECRCredentialCache wraps the ECR credential helper with a bounded LRU cache
// to prevent memory leaks in long-running processes
type ECRCredentialCache struct {
	// LRU cache for storing credentials with an eviction policy
	cache *lru.Cache[string, Credential]
	// The underlying ECR credential helper
	helper CredentialHelper
	// Mutex for concurrent access
	mu sync.Mutex
	// Time when entries should expire (enforce re-fetching credentials)
	ttl time.Duration
	// Cache entries have an expiration timestamp
	expiry map[string]time.Time
}

// ECRHelperAdapter adapts the ECR helper to our CredentialHelper interface
type ECRHelperAdapter struct {
	helper *ecr.ECRHelper
}

// NewECRHelperAdapter creates a new adapter for the ECR helper
func NewECRHelperAdapter(helper *ecr.ECRHelper) *ECRHelperAdapter {
	return &ECRHelperAdapter{helper: helper}
}

// Get delegates to the underlying ECR helper
func (a *ECRHelperAdapter) Get(serverURL string) (string, string, error) {
	return a.helper.Get(serverURL)
}

// Add delegates to the underlying ECR helper
func (a *ECRHelperAdapter) Add(_ interface{}) error {
	return ErrCredentialsNotFound
}

// Delete delegates to the underlying ECR helper
func (a *ECRHelperAdapter) Delete(serverURL string) error {
	return ErrCredentialsNotFound
}

// List delegates to the underlying ECR helper
func (a *ECRHelperAdapter) List() (map[string]string, error) {
	return a.helper.List()
}

// NewECRCredentialCache creates a new credential cache with bounded memory.
// The cacheSize parameter defines the maximum number of entries.
// The ttl parameter defines how long an entry is valid for.
func NewECRCredentialCache(cacheSize int, ttl time.Duration) (*ECRCredentialCache, error) {
	// Create an LRU cache with a fixed size
	cache, err := lru.New[string, Credential](cacheSize)
	if err != nil {
		return nil, err
	}

	// Create the ECR helper with discarded logging
	ecrHelper := ecr.NewECRHelper(ecr.WithLogger(io.Discard))

	// Adapt the ECR helper to our interface
	adapter := NewECRHelperAdapter(ecrHelper)

	return &ECRCredentialCache{
		cache:  cache,
		helper: adapter,
		ttl:    ttl,
		expiry: make(map[string]time.Time),
	}, nil
}

// Get retrieves credentials from the cache if they exist and are valid,
// otherwise it fetches new credentials from ECR
func (c *ECRCredentialCache) Get(serverURL string) (string, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Check if we have a valid cache entry
	if creds, ok := c.cache.Get(serverURL); ok {
		// Check if the entry has expired
		if expiry, exists := c.expiry[serverURL]; exists && now.Before(expiry) {
			// Return the cached credentials
			return creds.Username, creds.Password, nil
		}
		// Entry has expired, remove it from the cache
		c.cache.Remove(serverURL)
		delete(c.expiry, serverURL)
	}

	// Fetch fresh credentials from ECR
	username, password, err := c.helper.Get(serverURL)
	if err != nil {
		return "", "", err
	}

	// Cache the new credentials with an expiry
	c.cache.Add(serverURL, Credential{
		ServerURL: serverURL,
		Username:  username,
		Password:  password,
	})
	c.expiry[serverURL] = now.Add(c.ttl)

	return username, password, nil
}

// GetEnvVars returns the environment variables with AWS_ECR_DISABLE_CACHE set to true
func GetEnvVars() []string {
	return []string{"AWS_ECR_DISABLE_CACHE=true"}
}

// DockerCredentialHelper adapts the ECRCredentialCache to implement the
// docker-credential-helpers interface
type DockerCredentialHelper struct {
	cache *ECRCredentialCache
}

// NewDockerCredentialHelper creates a new helper that satisfies the docker credentials interface
func NewDockerCredentialHelper(cache *ECRCredentialCache) *DockerCredentialHelper {
	return &DockerCredentialHelper{
		cache: cache,
	}
}

// Add is not supported, as ECR only uses temporary credentials
func (d *DockerCredentialHelper) Add(creds interface{}) error {
	return ErrCredentialsNotFound
}

// Delete is not supported, as ECR only uses temporary credentials
func (d *DockerCredentialHelper) Delete(serverURL string) error {
	return ErrCredentialsNotFound
}

// Get retrieves credentials for the given server URL
func (d *DockerCredentialHelper) Get(serverURL string) (string, string, error) {
	return d.cache.Get(serverURL)
}

// List is not implemented as it's not needed for our use case
func (d *DockerCredentialHelper) List() (map[string]string, error) {
	return map[string]string{}, nil
}
