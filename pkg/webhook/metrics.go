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

const (
	metricCacheOperations = "policy_controller.cache.operations"
	metricCacheWrites     = "policy_controller.cache.writes"
	metricCacheEvictions  = "policy_controller.cache.evictions"
	metricCacheEntries    = "policy_controller.cache.entries"
)

var meter = otel.Meter("github.com/sigstore/policy-controller/pkg/webhook")

var (
	cacheOps       metric.Int64Counter
	cacheWrites    metric.Int64Counter
	cacheEvictions metric.Int64Counter
)

func init() {
	registerCacheMetrics(meter)
}

// registerCacheMetrics (re)creates the package-level cache counters from m.
func registerCacheMetrics(m metric.Meter) {
	var err error
	cacheOps, err = m.Int64Counter(
		metricCacheOperations,
		metric.WithDescription("Number of cache lookup operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		otel.Handle(err)
	}
	cacheWrites, err = m.Int64Counter(
		metricCacheWrites,
		metric.WithDescription("Number of cache write operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		otel.Handle(err)
	}
	cacheEvictions, err = m.Int64Counter(
		metricCacheEvictions,
		metric.WithDescription("Number of entries removed from the cache"),
		metric.WithUnit("{entry}"),
	)
	if err != nil {
		otel.Handle(err)
	}
}

// registerEntriesGauge reports lenFunc() as the cache entries gauge at collection time.
func registerEntriesGauge(m metric.Meter, lenFunc func() int) {
	gauge, err := m.Int64ObservableGauge(
		metricCacheEntries,
		metric.WithDescription("Current number of entries in the validation result cache"),
		metric.WithUnit("{entry}"),
	)
	if err != nil {
		otel.Handle(err)
	}
	_, err = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(gauge, int64(lenFunc()))
		return nil
	}, gauge)
	if err != nil {
		otel.Handle(err)
	}
}
