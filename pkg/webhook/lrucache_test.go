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
	"errors"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"
)

func passResult() *CacheResult {
	return &CacheResult{PolicyResult: &PolicyResult{AuthorityMatches: map[string]AuthorityMatch{}}}
}

func TestLRUCacheKey(t *testing.T) {
	tests := []struct {
		name           string
		image, uid, rv string
		wantHit        bool
	}{
		{name: "hit", image: "image-a", uid: "uid-1", rv: "v1", wantHit: true},
		{name: "different image", image: "image-b", uid: "uid-1", rv: "v1"},
		{name: "different uid", image: "image-a", uid: "uid-2", rv: "v1"},
		{name: "different resourceVersion", image: "image-a", uid: "uid-1", rv: "v2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cache := NewLRUCache(10, time.Hour)
			cache.Set(ctx, "image-a", "my-policy", "uid-1", "v1", passResult())
			if got := cache.Get(ctx, tc.image, tc.uid, tc.rv); (got != nil) != tc.wantHit {
				t.Fatalf("Get() hit = %v, want %v", got != nil, tc.wantHit)
			}
		})
	}
}

func TestLRUCacheSkipsErrors(t *testing.T) {
	cache := NewLRUCache(10, time.Hour)
	ctx := context.Background()

	// No authority matched: PolicyResult is nil, only errors present.
	cache.Set(ctx, "gcr.io/foo/bar@sha256:abc", "my-policy", "uid-1", "v1", &CacheResult{
		Errors: []error{errors.New("image not signed")},
	})

	if got := cache.Get(ctx, "gcr.io/foo/bar@sha256:abc", "uid-1", "v1"); got != nil {
		t.Fatalf("expected cache miss for failed validation, got %v", got)
	}
}

func TestLRUCachePartialSuccess(t *testing.T) {
	cache := NewLRUCache(10, time.Hour)
	ctx := context.Background()

	// Some authorities matched: PolicyResult is non-nil, alongside errors
	// from the authorities that didn't match.
	cache.Set(ctx, "gcr.io/foo/bar@sha256:abc", "my-policy", "uid-1", "v1", &CacheResult{
		PolicyResult: &PolicyResult{
			AuthorityMatches: map[string]AuthorityMatch{
				"authority-0": {Static: true},
			},
		},
		Errors: []error{errors.New("authority-1: signature invalid")},
	})

	got := cache.Get(ctx, "gcr.io/foo/bar@sha256:abc", "uid-1", "v1")
	if got == nil || got.PolicyResult == nil {
		t.Fatal("expected cache hit with PolicyResult for partial success")
	}
	if len(got.Errors) != 1 {
		t.Fatalf("expected 1 error in cached result, got %d", len(got.Errors))
	}
}

func TestLRUCacheTTLExpiry(t *testing.T) {
	clock := clocktesting.NewFakeClock(time.Now())
	cache := newLRUCacheWithClock(10, time.Minute, clock)
	ctx := context.Background()

	cache.Set(ctx, "image-a", "my-policy", "uid-1", "v1", passResult())

	clock.Step(time.Minute - time.Second)
	if got := cache.Get(ctx, "image-a", "uid-1", "v1"); got == nil {
		t.Fatal("expected cache hit before TTL expiry")
	}

	clock.Step(2 * time.Second)
	if got := cache.Get(ctx, "image-a", "uid-1", "v1"); got != nil {
		t.Fatalf("expected cache miss after TTL expiry, got %v", got)
	}
}

func TestLRUCachePurge(t *testing.T) {
	cache := NewLRUCache(10, time.Hour)
	ctx := context.Background()

	cache.Set(ctx, "image-a", "my-policy", "uid-1", "v1", passResult())
	cache.Set(ctx, "image-b", "my-policy", "uid-1", "v1", passResult())
	cache.Purge()

	for _, image := range []string{"image-a", "image-b"} {
		if got := cache.Get(ctx, image, "uid-1", "v1"); got != nil {
			t.Fatalf("expected miss for %s after Purge, got %v", image, got)
		}
	}
}
