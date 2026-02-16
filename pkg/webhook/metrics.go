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

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var meter = otel.Meter("policy-controller")

var (
	cacheOps       metric.Int64Counter
	cacheWrites    metric.Int64Counter
	cacheEvictions metric.Int64Counter
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
	cacheEvictions, _ = m.Int64Counter(
		"cache.evictions",
		metric.WithDescription("Number of cache entries evicted"),
		metric.WithUnit("{eviction}"),
	)
}

// cacheEntriesLenFunc is the function called by the Observable Gauge to report
// the current number of cache entries. Nil when no cache is registered.
var cacheEntriesLenFunc func() int

// registerCacheEntriesGauge registers an Observable Gauge that reads the
// current cache size via lenFunc at collection time. This is race-free
// because it reads the source of truth (cache.Len()) rather than maintaining
// a running counter.
func registerCacheEntriesGauge(m metric.Meter, lenFunc func() int) {
	cacheEntriesLenFunc = lenFunc
	gauge, _ := m.Int64ObservableGauge(
		"cache.entries",
		metric.WithDescription("Current number of entries in the validation result cache"),
		metric.WithUnit("{entry}"),
	)
	_, _ = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		if cacheEntriesLenFunc != nil {
			o.ObserveInt64(gauge, int64(cacheEntriesLenFunc()))
		}
		return nil
	}, gauge)
}
