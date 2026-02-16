//
// Copyright 2026 The Sigstore Authors.
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
	"fmt"
	"time"

	expirable "github.com/hashicorp/golang-lru/v2/expirable"
	"knative.dev/pkg/logging"
)

// LRUCache implements ResultCache using an LRU cache with TTL expiration.
// Only successful validations (PolicyResult non-nil) are cached.
// Failed validations (PolicyResult nil) are not cached to allow retries.
type LRUCache struct {
	cache *expirable.LRU[string, *CacheResult]
}

// NewLRUCache creates a new LRU cache with the given size and TTL.
func NewLRUCache(size int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		cache: expirable.NewLRU[string, *CacheResult](size, nil, ttl),
	}
}

func cacheKeyFor(image, uid, resourceVersion string) string {
	return fmt.Sprintf("%s/%s/%s", image, uid, resourceVersion)
}

func (c *LRUCache) Get(ctx context.Context, image, uid, resourceVersion string) *CacheResult {
	result, ok := c.cache.Get(cacheKeyFor(image, uid, resourceVersion))
	if !ok {
		logging.FromContext(ctx).Debugf("cache miss for image %s, policy UID %s", image, uid)
		return nil
	}
	logging.FromContext(ctx).Debugf("cache hit for image %s, policy UID %s", image, uid)
	return result
}

func (c *LRUCache) Set(_ context.Context, image, name, uid, resourceVersion string, cacheResult *CacheResult) { //nolint: revive
	if cacheResult.PolicyResult == nil {
		return
	}
	copied := &CacheResult{
		PolicyResult: cacheResult.PolicyResult,
		Errors:       append([]error(nil), cacheResult.Errors...),
	}
	c.cache.Add(cacheKeyFor(image, uid, resourceVersion), copied)
}
