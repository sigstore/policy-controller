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

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"
	clocktesting "k8s.io/utils/clock/testing"
)

// setupTestMetrics points the cache instruments and cache's entries gauge at a
// test MeterProvider and returns its reader.
func setupTestMetrics(t *testing.T, cache *LRUCache) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m := provider.Meter("test")
	registerCacheMetrics(m)
	registerEntriesGauge(m, cache.len)
	t.Cleanup(func() {
		registerCacheMetrics(meter)
		_ = provider.Shutdown(context.Background())
	})
	return reader
}

// collect returns the data of the named metric, failing the test if it is absent.
func collect(t *testing.T, reader *sdkmetric.ManualReader, name string) metricdata.Aggregation {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m.Data
			}
		}
	}
	t.Fatalf("metric %q not found", name)
	return nil
}

func counter(key string, values map[string]int64) metricdata.Sum[int64] {
	s := metricdata.Sum[int64]{Temporality: metricdata.CumulativeTemporality, IsMonotonic: true}
	for v, n := range values {
		s.DataPoints = append(s.DataPoints, metricdata.DataPoint[int64]{
			Attributes: attribute.NewSet(attribute.String(key, v)),
			Value:      n,
		})
	}
	return s
}

func gauge(n int64) metricdata.Gauge[int64] {
	return metricdata.Gauge[int64]{DataPoints: []metricdata.DataPoint[int64]{{Value: n}}}
}

func assertMetric[T metricdata.Sum[int64] | metricdata.Gauge[int64]](t *testing.T, reader *sdkmetric.ManualReader, name string, want T) {
	t.Helper()
	got, ok := collect(t, reader, name).(T)
	if !ok {
		t.Fatalf("metric %q has unexpected type", name)
	}
	metricdatatest.AssertEqual(t, want, got, metricdatatest.IgnoreTimestamp())
}

func TestCacheMetricsHitMiss(t *testing.T) {
	cache := NewLRUCache(10, time.Hour)
	reader := setupTestMetrics(t, cache)
	ctx := context.Background()

	cache.Get(ctx, "img", "uid-1", "v1")
	assertMetric(t, reader, metricCacheOperations, counter("result", map[string]int64{"miss": 1}))

	cache.Set(ctx, "img", "p", "uid-1", "v1", passResult())
	cache.Get(ctx, "img", "uid-1", "v1")
	assertMetric(t, reader, metricCacheOperations, counter("result", map[string]int64{"miss": 1, "hit": 1}))
}

func TestCacheMetricsWrites(t *testing.T) {
	cache := NewLRUCache(10, time.Hour)
	reader := setupTestMetrics(t, cache)
	ctx := context.Background()

	cache.Set(ctx, "img", "p", "uid-1", "v1", passResult())
	cache.Set(ctx, "img2", "p", "uid-1", "v1", &CacheResult{Errors: []error{errors.New("denied")}})

	assertMetric(t, reader, metricCacheWrites, counter("result", map[string]int64{"stored": 1, "skipped": 1}))
}

func TestCacheMetricsEntries(t *testing.T) {
	cache := NewLRUCache(10, time.Hour)
	reader := setupTestMetrics(t, cache)
	ctx := context.Background()

	cache.Set(ctx, "img-1", "p", "uid-1", "v1", passResult())
	assertMetric(t, reader, metricCacheEntries, gauge(1))

	cache.Set(ctx, "img-2", "p", "uid-1", "v1", passResult())
	assertMetric(t, reader, metricCacheEntries, gauge(2))
}

func TestCacheMetricsPurge(t *testing.T) {
	cache := NewLRUCache(10, time.Hour)
	reader := setupTestMetrics(t, cache)
	ctx := context.Background()

	cache.Set(ctx, "img-1", "p", "uid-1", "v1", passResult())
	cache.Set(ctx, "img-2", "p", "uid-1", "v1", passResult())
	cache.Purge()

	assertMetric(t, reader, metricCacheEntries, gauge(0))
	assertMetric(t, reader, metricCacheEvictions, counter("reason", map[string]int64{"purge": 2}))
}

func TestCacheMetricsEntriesExcludesExpired(t *testing.T) {
	clock := clocktesting.NewFakeClock(time.Now())
	cache := newLRUCacheWithClock(10, time.Minute, clock)
	reader := setupTestMetrics(t, cache)

	cache.Set(context.Background(), "img", "p", "uid-1", "v1", passResult())
	clock.Step(2 * time.Minute)

	assertMetric(t, reader, metricCacheEntries, gauge(0))
}
