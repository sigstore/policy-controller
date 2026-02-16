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
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// setupTestMetrics creates a test MeterProvider and reinitializes the
// package-level cache instruments including the Observable Gauge for
// cache.entries. Returns a ManualReader for asserting metric values.
// Restores the original instruments on test cleanup.
func setupTestMetrics(t *testing.T, cache *LRUCache) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m := provider.Meter("policy-controller")
	registerCacheMetrics(m)
	registerCacheEntriesGauge(m, cache.cache.Len)
	t.Cleanup(func() {
		registerCacheMetrics(meter) // restore package-level instruments
		provider.Shutdown(context.Background())
	})
	return reader
}

// getCounterValue extracts an Int64Counter value by metric name and attributes.
// Fails the test immediately if the metric name is not found (catches typos).
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
			t.Fatalf("metric %q found but no data point matching attributes %v", name, attrs)
		}
	}
	t.Fatalf("metric %q not found in collected metrics", name)
	return 0
}

// getGaugeValue extracts an Int64ObservableGauge value by metric name.
// Fails the test immediately if the metric name is not found (catches typos).
func getGaugeValue(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
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
			if gauge, ok := m.Data.(metricdata.Gauge[int64]); ok {
				for _, dp := range gauge.DataPoints {
					return dp.Value
				}
			}
			t.Fatalf("metric %q found but no gauge data points", name)
		}
	}
	t.Fatalf("metric %q not found in collected metrics", name)
	return 0
}

func TestCacheMetricsHitMiss(t *testing.T) {
	cache := NewLRUCache(10, 1*time.Hour)
	reader := setupTestMetrics(t, cache)
	ctx := context.Background()

	// Miss on empty cache
	cache.Get(ctx, "img", "uid-1", "v1")

	if got := getCounterValue(t, reader, "cache.operations", attribute.String("result", "miss")); got != 1 {
		t.Fatalf("expected 1 miss, got %d", got)
	}

	// Store an entry, then hit
	cache.Set(ctx, "img", "p", "uid-1", "v1", &CacheResult{
		PolicyResult: &PolicyResult{AuthorityMatches: map[string]AuthorityMatch{}},
	})
	cache.Get(ctx, "img", "uid-1", "v1")

	if got := getCounterValue(t, reader, "cache.operations", attribute.String("result", "hit")); got != 1 {
		t.Fatalf("expected 1 hit, got %d", got)
	}
	if got := getCounterValue(t, reader, "cache.operations", attribute.String("result", "miss")); got != 1 {
		t.Fatalf("expected miss count still 1, got %d", got)
	}
}

func TestCacheMetricsWrites(t *testing.T) {
	cache := NewLRUCache(10, 1*time.Hour)
	reader := setupTestMetrics(t, cache)
	ctx := context.Background()

	// Stored write (non-nil PolicyResult)
	cache.Set(ctx, "img", "p", "uid-1", "v1", &CacheResult{
		PolicyResult: &PolicyResult{AuthorityMatches: map[string]AuthorityMatch{}},
	})

	if got := getCounterValue(t, reader, "cache.writes", attribute.String("result", "stored")); got != 1 {
		t.Fatalf("expected 1 stored write, got %d", got)
	}

	// Skipped write (nil PolicyResult)
	cache.Set(ctx, "img2", "p", "uid-1", "v1", &CacheResult{
		Errors: []error{nil},
	})

	if got := getCounterValue(t, reader, "cache.writes", attribute.String("result", "skipped")); got != 1 {
		t.Fatalf("expected 1 skipped write, got %d", got)
	}
}

func TestCacheMetricsEntries(t *testing.T) {
	cache := NewLRUCache(10, 1*time.Hour)
	reader := setupTestMetrics(t, cache)
	ctx := context.Background()
	result := &CacheResult{
		PolicyResult: &PolicyResult{AuthorityMatches: map[string]AuthorityMatch{}},
	}

	cache.Set(ctx, "img-1", "p", "uid-1", "v1", result)
	if got := getGaugeValue(t, reader, "cache.entries"); got != 1 {
		t.Fatalf("expected 1 entry, got %d", got)
	}

	cache.Set(ctx, "img-2", "p", "uid-1", "v1", result)
	if got := getGaugeValue(t, reader, "cache.entries"); got != 2 {
		t.Fatalf("expected 2 entries, got %d", got)
	}
}

func TestCacheMetricsEviction(t *testing.T) {
	cache := NewLRUCache(2, 1*time.Hour)
	reader := setupTestMetrics(t, cache)
	ctx := context.Background()
	result := &CacheResult{
		PolicyResult: &PolicyResult{AuthorityMatches: map[string]AuthorityMatch{}},
	}

	cache.Set(ctx, "img-1", "p", "uid-1", "v1", result)
	cache.Set(ctx, "img-2", "p", "uid-1", "v1", result)
	cache.Set(ctx, "img-3", "p", "uid-1", "v1", result) // evicts img-1

	if got := getCounterValue(t, reader, "cache.evictions"); got != 1 {
		t.Fatalf("expected 1 eviction, got %d", got)
	}
	if got := getGaugeValue(t, reader, "cache.entries"); got != 2 {
		t.Fatalf("expected 2 entries after eviction, got %d", got)
	}
}
