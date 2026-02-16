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

package webhook

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLRUCacheSetGet(t *testing.T) {
	cache := NewLRUCache(10, 1*time.Hour)
	ctx := context.Background()

	want := &CacheResult{
		PolicyResult: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{},
		},
	}
	cache.Set(ctx, "gcr.io/foo/bar@sha256:abc", "my-policy", "uid-1", "v1", want)

	got := cache.Get(ctx, "gcr.io/foo/bar@sha256:abc", "uid-1", "v1")
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	if got.PolicyResult == nil {
		t.Fatal("expected PolicyResult, got nil")
	}
}

func TestLRUCacheMiss(t *testing.T) {
	cache := NewLRUCache(10, 1*time.Hour)
	ctx := context.Background()

	got := cache.Get(ctx, "gcr.io/foo/bar@sha256:abc", "uid-1", "v1")
	if got != nil {
		t.Fatalf("expected cache miss (nil), got %v", got)
	}
}

func TestLRUCacheSkipsErrors(t *testing.T) {
	cache := NewLRUCache(10, 1*time.Hour)
	ctx := context.Background()

	// Failed validation: PolicyResult is nil, only errors present.
	// This is the case when no authorities matched (validator.go:590-591).
	cache.Set(ctx, "gcr.io/foo/bar@sha256:abc", "my-policy", "uid-1", "v1", &CacheResult{
		Errors: []error{errors.New("image not signed")},
	})

	got := cache.Get(ctx, "gcr.io/foo/bar@sha256:abc", "uid-1", "v1")
	if got != nil {
		t.Fatalf("expected cache miss for failed validation, got %v", got)
	}
}

func TestLRUCachePartialSuccess(t *testing.T) {
	cache := NewLRUCache(10, 1*time.Hour)
	ctx := context.Background()

	// Partial success: PolicyResult is non-nil (at least one authority matched)
	// but there are also errors from authorities that didn't match.
	// This is the common case with multi-authority CIPs (validator.go:641).
	cache.Set(ctx, "gcr.io/foo/bar@sha256:abc", "my-policy", "uid-1", "v1", &CacheResult{
		PolicyResult: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {Static: true},
			},
		},
		Errors: []error{errors.New("authority-1: signature invalid")},
	})

	got := cache.Get(ctx, "gcr.io/foo/bar@sha256:abc", "uid-1", "v1")
	if got == nil {
		t.Fatal("expected cache hit for partial success (PolicyResult non-nil), got nil")
	}
	if got.PolicyResult == nil {
		t.Fatal("expected PolicyResult in cached result")
	}
	if len(got.Errors) != 1 {
		t.Fatalf("expected 1 error in cached result, got %d", len(got.Errors))
	}
}

func TestLRUCacheTTLExpiry(t *testing.T) {
	cache := NewLRUCache(10, 50*time.Millisecond)
	ctx := context.Background()

	cache.Set(ctx, "gcr.io/foo/bar@sha256:abc", "my-policy", "uid-1", "v1", &CacheResult{
		PolicyResult: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{},
		},
	})

	// Should hit immediately
	if got := cache.Get(ctx, "gcr.io/foo/bar@sha256:abc", "uid-1", "v1"); got == nil {
		t.Fatal("expected cache hit before TTL expiry")
	}

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	if got := cache.Get(ctx, "gcr.io/foo/bar@sha256:abc", "uid-1", "v1"); got != nil {
		t.Fatalf("expected cache miss after TTL expiry, got %v", got)
	}
}

func TestLRUCacheEviction(t *testing.T) {
	cache := NewLRUCache(2, 1*time.Hour)
	ctx := context.Background()
	result := &CacheResult{
		PolicyResult: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{},
		},
	}

	cache.Set(ctx, "image-1", "p", "uid-1", "v1", result)
	cache.Set(ctx, "image-2", "p", "uid-1", "v1", result)
	cache.Set(ctx, "image-3", "p", "uid-1", "v1", result) // evicts image-1

	if got := cache.Get(ctx, "image-1", "uid-1", "v1"); got != nil {
		t.Fatal("expected image-1 to be evicted")
	}
	if got := cache.Get(ctx, "image-2", "uid-1", "v1"); got == nil {
		t.Fatal("expected image-2 to still be cached")
	}
	if got := cache.Get(ctx, "image-3", "uid-1", "v1"); got == nil {
		t.Fatal("expected image-3 to still be cached")
	}
}

func TestLRUCacheKeyIsolation(t *testing.T) {
	cache := NewLRUCache(10, 1*time.Hour)
	ctx := context.Background()
	result := &CacheResult{
		PolicyResult: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{},
		},
	}

	cache.Set(ctx, "image-a", "p", "uid-1", "v1", result)

	// Different image
	if got := cache.Get(ctx, "image-b", "uid-1", "v1"); got != nil {
		t.Fatal("expected miss for different image")
	}
	// Different UID
	if got := cache.Get(ctx, "image-a", "uid-2", "v1"); got != nil {
		t.Fatal("expected miss for different UID")
	}
	// Correct key
	if got := cache.Get(ctx, "image-a", "uid-1", "v1"); got == nil {
		t.Fatal("expected hit for matching key")
	}
}

func TestLRUCacheResourceVersionInvalidation(t *testing.T) {
	cache := NewLRUCache(10, 1*time.Hour)
	ctx := context.Background()
	result := &CacheResult{
		PolicyResult: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{},
		},
	}

	cache.Set(ctx, "image-a", "my-policy", "uid-1", "v1", result)

	// Same image+uid but new resourceVersion (policy was updated)
	if got := cache.Get(ctx, "image-a", "uid-1", "v2"); got != nil {
		t.Fatal("expected miss for updated resourceVersion")
	}
	// Original version still hits
	if got := cache.Get(ctx, "image-a", "uid-1", "v1"); got == nil {
		t.Fatal("expected hit for original resourceVersion")
	}
}
