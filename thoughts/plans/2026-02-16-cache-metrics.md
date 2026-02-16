# Cache Metrics Implementation Plan

## Overview

Add OpenTelemetry metrics to the LRU cache in `pkg/webhook/` to track cache operations, writes, entries, and evictions. Uses the global OTEL MeterProvider set up by knative's `sharedmain.MainWithContext()`.

## Current State Analysis

- **Zero custom metrics** in the codebase
- LRU cache in `pkg/webhook/lrucache.go` has clear instrumentation points (Get hit/miss, Set stored/skipped)
- The `onEvict` callback in `NewLRUCache` is currently `nil` (lrucache.go:37)
- OTEL v1.39.0 dependencies available transitively via `knative.dev/pkg`
- `NoCache` implementation (nocache.go) is a no-op and should not emit metrics
- Existing tests in `lrucache_test.go` use stdlib `testing` (no testify, no external assertion libs)

### Key Discoveries:
- `Set` method uses `_ context.Context` (lrucache.go:55) - needs to be changed to `ctx` for metric recording
- `expirable.LRU`'s onEvict callback fires for both LRU eviction and TTL expiration - so `cache.entries` tracking will be accurate
- The onEvict callback signature is `func(key string, value *CacheResult)` - no context, so eviction metrics use `context.Background()`
- OTEL's global meter delegation means package-level instrument vars work with later MeterProvider setup (both knative's sharedmain and test providers)

## Desired End State

Four cache metrics emitted by `LRUCache` (not `NoCache`):

| OTEL Instrument | Name | Type | Attributes | Prometheus Output |
|-----------------|------|------|------------|-------------------|
| Int64Counter | `cache.operations` | Counter | `result=hit\|miss` | `cache_operations_total{result="hit"}` |
| Int64Counter | `cache.writes` | Counter | `result=stored\|skipped` | `cache_writes_total{result="stored"}` |
| Int64UpDownCounter | `cache.entries` | UpDownCounter | (none) | `cache_entries` |
| Int64Counter | `cache.evictions` | Counter | (none) | `cache_evictions_total` |

### Verification:
- `go test ./pkg/webhook/ -run TestCacheMetrics -v` passes with metric value assertions
- `go test ./pkg/webhook/` passes (existing tests still pass)
- `make test` passes
- `golangci-lint run ./pkg/webhook/...` passes
- `go mod tidy` produces no diff

## What We're NOT Doing

- Updating `config/config-observability.yaml` (separate PR)
- Adding validation/admission/signature metrics (future work)
- Adding a `cache.enabled` gauge
- Metrics for `NoCache` implementation
- Histogram metrics (no duration tracking in cache operations)

## Implementation Approach

Single phase - the change is small and self-contained. Create a `metrics.go` file with package-level OTEL instruments, wire them into `LRUCache.Get()`, `LRUCache.Set()`, and the onEvict callback, then add tests.

## Phase 1: Cache Metrics

### Overview
Define 4 OTEL instruments, add recording calls to LRUCache, add tests with OTEL SDK test utilities.

### Changes Required:

#### 1. New file: `pkg/webhook/metrics.go`
**File**: `pkg/webhook/metrics.go`
**Purpose**: Define OTEL meter and cache instruments as package-level vars

```go
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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var meter = otel.Meter("policy-controller")

var (
	cacheOps        metric.Int64Counter
	cacheWrites     metric.Int64Counter
	cacheEntries    metric.Int64UpDownCounter
	cacheEvictions  metric.Int64Counter
)

func init() {
	registerCacheMetrics(meter)
}

// registerCacheMetrics initializes cache metric instruments from the given meter.
// Called from init() for production use. Tests call this with a test meter
// to capture metric values.
func registerCacheMetrics(m metric.Meter) {
	cacheOps, _ = m.Int64Counter(
		"cache.operations",
		metric.WithDescription("Number of cache lookup operations"),
		metric.WithUnit("{operation}"),
	)
	cacheWrites, _ = m.Int64Counter(
		"cache.writes",
		metric.WithDescription("Number of cache write operations"),
		metric.WithUnit("{operation}"),
	)
	cacheEntries, _ = m.Int64UpDownCounter(
		"cache.entries",
		metric.WithDescription("Current number of entries in the validation result cache"),
		metric.WithUnit("{entry}"),
	)
	cacheEvictions, _ = m.Int64Counter(
		"cache.evictions",
		metric.WithDescription("Number of cache entries evicted"),
		metric.WithUnit("{eviction}"),
	)
}
```

**Design decisions**:
- `registerCacheMetrics(m metric.Meter)` is separated from `init()` so tests can reinitialize instruments with a test meter. This avoids global MeterProvider issues in tests.
- Errors from instrument creation are intentionally ignored (the `_` pattern). These only fail for invalid metric names, which is a developer error caught during development.
- The meter scope name `"policy-controller"` appears as `otel_scope_name` label in Prometheus output.
- No `_total` suffix or component prefix in names - the OTEL Prometheus exporter adds `_total` for counters automatically.

#### 2. Modify: `pkg/webhook/lrucache.go`
**File**: `pkg/webhook/lrucache.go`
**Changes**: Add metric recording to Get, Set, and onEvict callback

The full file after changes:

```go
package webhook

import (
	"context"
	"fmt"
	"time"

	expirable "github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"knative.dev/pkg/logging"
)

type LRUCache struct {
	cache *expirable.LRU[string, *CacheResult]
}

func NewLRUCache(size int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		cache: expirable.NewLRU[string, *CacheResult](size, func(_ string, _ *CacheResult) {
			cacheEvictions.Add(context.Background(), 1)
			cacheEntries.Add(context.Background(), -1)
		}, ttl),
	}
}

func cacheKeyFor(image, uid, resourceVersion string) string {
	return fmt.Sprintf("%s/%s/%s", image, uid, resourceVersion)
}

func (c *LRUCache) Get(ctx context.Context, image, uid, resourceVersion string) *CacheResult {
	result, ok := c.cache.Get(cacheKeyFor(image, uid, resourceVersion))
	if !ok {
		cacheOps.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "miss")))
		logging.FromContext(ctx).Debugf("cache miss for image %s, policy UID %s", image, uid)
		return nil
	}
	cacheOps.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "hit")))
	logging.FromContext(ctx).Debugf("cache hit for image %s, policy UID %s", image, uid)
	return result
}

func (c *LRUCache) Set(ctx context.Context, image, name, uid, resourceVersion string, cacheResult *CacheResult) { //nolint: revive
	if cacheResult.PolicyResult == nil {
		cacheWrites.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "skipped")))
		return
	}
	copied := &CacheResult{
		PolicyResult: cacheResult.PolicyResult,
		Errors:       append([]error(nil), cacheResult.Errors...),
	}
	c.cache.Add(cacheKeyFor(image, uid, resourceVersion), copied)
	cacheWrites.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "stored")))
	cacheEntries.Add(ctx, 1)
}
```

**Key changes from current code**:
- Added imports: `go.opentelemetry.io/otel/attribute`, `go.opentelemetry.io/otel/metric`
- `NewLRUCache`: Changed `nil` onEvict callback to a function that records eviction and decrements entries
- `Get`: Added `cacheOps.Add()` calls with `result=hit` and `result=miss` attributes
- `Set`: Changed `_ context.Context` to `ctx context.Context`, added `cacheWrites.Add()` calls with `result=stored` and `result=skipped`, added `cacheEntries.Add(ctx, 1)` on store
- Kept existing debug logging unchanged
- Kept `//nolint: revive` for the unused `name` parameter

#### 3. New file: `pkg/webhook/metrics_test.go`
**File**: `pkg/webhook/metrics_test.go`
**Purpose**: Test that cache operations record correct metric values

Tests use OTEL SDK's `ManualReader` to capture and assert metric values. The test structure:

```go
package webhook

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// setupTestMetrics creates a test MeterProvider and reinitializes the
// package-level cache instruments. Returns a ManualReader for asserting
// metric values. Restores the original instruments on test cleanup.
func setupTestMetrics(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m := provider.Meter("policy-controller")
	registerCacheMetrics(m)
	t.Cleanup(func() {
		registerCacheMetrics(meter) // restore package-level instruments
		provider.Shutdown(context.Background())
	})
	return reader
}

// getCounterValue extracts an Int64Counter value by metric name and attributes.
func getCounterValue(t *testing.T, reader *sdkmetric.ManualReader, name string, attrs ...attribute.KeyValue) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}
	set := attribute.NewSet(attrs...)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
				for _, dp := range sum.DataPoints {
					if dp.Attributes.Equals(&set) {
						return dp.Value
					}
				}
			}
		}
	}
	return 0
}

// getUpDownCounterValue extracts an Int64UpDownCounter value by metric name.
func getUpDownCounterValue(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
				for _, dp := range sum.DataPoints {
					return dp.Value
				}
			}
		}
	}
	return 0
}
```

**Test cases** (specific functions to implement):

1. **`TestCacheMetricsHitMiss`** - Get on empty cache records `cache.operations{result=miss}`, Set + Get records `cache.operations{result=hit}`. Assert exact counter values.

2. **`TestCacheMetricsWrites`** - Set with non-nil PolicyResult records `cache.writes{result=stored}`. Set with nil PolicyResult records `cache.writes{result=skipped}`.

3. **`TestCacheMetricsEntries`** - After Set (stored), `cache.entries` is 1. After another Set, `cache.entries` is 2. After eviction (size-limited cache), `cache.entries` goes back down.

4. **`TestCacheMetricsEviction`** - Use a size-2 cache. After 3 Sets, `cache.evictions` is 1 and `cache.entries` is 2.

#### 4. Update go.mod
**File**: `go.mod`
**Changes**: Run `go mod tidy` to promote OTEL imports from `indirect` to direct dependencies.

The following will move from `// indirect` to direct:
- `go.opentelemetry.io/otel v1.39.0`
- `go.opentelemetry.io/otel/metric v1.39.0`

The following will be added to direct dependencies for tests:
- `go.opentelemetry.io/otel/sdk/metric v1.39.0`

This is handled automatically by `go mod tidy`.

### Success Criteria:

#### Automated Verification:
- [ ] Unit tests pass: `go test ./pkg/webhook/ -run TestCacheMetrics -v`
- [ ] All existing tests still pass: `go test ./pkg/webhook/`
- [ ] Full test suite passes: `make test`
- [ ] Linting passes: `golangci-lint run ./pkg/webhook/...`
- [ ] Module is tidy: `go mod tidy` produces no diff

#### Manual Verification:
- [ ] Deploy with `config-observability` set to `metrics-protocol: prometheus` and confirm `/metrics` on `:9090` includes `cache_operations_total`, `cache_writes_total`, `cache_entries`, `cache_evictions_total`
- [ ] Trigger admission requests with cache enabled and verify counters increment

## Testing Strategy

### Unit Tests (in this PR):
- Test hit/miss counter values after Get operations
- Test stored/skipped counter values after Set operations
- Test entries UpDownCounter tracks current cache size accurately
- Test eviction counter fires on LRU eviction
- Use OTEL SDK `ManualReader` + `metricdata` for precise value assertions

### Integration/Manual Testing (optional, for confidence):
- Deploy with `--enable-cache=true` and `metrics-protocol: prometheus`
- Curl `:9090/metrics` and verify metric lines appear
- Submit admission requests and verify counters change

## References

- Research: `thoughts/research/2026-02-16-cache-metrics-implementation.md`
- Cache interface: `pkg/webhook/cache.go:47-56`
- LRU implementation: `pkg/webhook/lrucache.go`
- Existing cache tests: `pkg/webhook/lrucache_test.go`
- NoCache (no changes): `pkg/webhook/nocache.go`
