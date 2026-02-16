---
date: 2026-02-16T19:10:00+01:00
researcher: Claude
git_commit: 2d1dd2646c4d1d3522e2420b0a9d8529d954fd59
branch: metrics
repository: sigstore/policy-controller
topic: "Cache metrics implementation - library choice, metric suggestions, label-based patterns"
tags: [research, codebase, metrics, prometheus, cache, observability]
status: complete
last_updated: 2026-02-16
last_updated_by: Claude
last_updated_note: "Updated library recommendation from prometheus/client_golang to OpenTelemetry based on knative/pkg migration"
---

# Research: Cache Metrics Implementation

**Date**: 2026-02-16T19:10:00+01:00
**Researcher**: Claude
**Git Commit**: 2d1dd2646c4d1d3522e2420b0a9d8529d954fd59
**Branch**: metrics
**Repository**: sigstore/policy-controller

## Research Question

How to add Prometheus metrics for the LRU cache solution in policy-controller, which library to use, and what metrics to implement (with label-based "new style" patterns).

## Summary

The policy-controller currently uses `knative.dev/pkg v0.0.0-20230612155445-74c4be5e935e` (June 2023), which uses OpenCensus internally. However, **the latest knative/pkg (main branch, 2025+) has fully migrated to OpenTelemetry** (confirmed via GitHub issue knative/pkg#2174 and verified in source). The latest knative/pkg go.mod shows `go.opentelemetry.io/otel v1.39.0` as a direct dependency, with zero OpenCensus imports. Their metrics package (`observability/metrics/`) uses `go.opentelemetry.io/otel/metric` for instruments (Int64Counter, Float64Histogram, etc.) and `go.opentelemetry.io/otel/exporters/prometheus` for Prometheus export.

**Recommendation: Use OpenTelemetry (`go.opentelemetry.io/otel/metric`)** to align with where knative/pkg is headed. This ensures forward compatibility when policy-controller eventually bumps its knative.dev/pkg dependency. The OTel Prometheus exporter will serve metrics on the same `/metrics` endpoint via `promhttp.Handler()`.

The codebase currently has **zero custom metrics**. The cache has clear instrumentation points in `LRUCache.Get()` and `LRUCache.Set()`.

## Detailed Findings

### 1. Existing Observability Infrastructure

#### Knative sharedmain provides automatic metrics
- `cmd/webhook/main.go:157` calls `sharedmain.MainWithContext()` which starts a metrics HTTP server on port 9090
- `config/config-observability.yaml` has the template for `metrics.backend-destination: prometheus`
- `config/webhook.yaml:70-71` sets `METRICS_DOMAIN=sigstore.dev/policy`
- The `/metrics` endpoint is already live and serves controller queue/reconciliation metrics

#### Dependencies already available (go.mod indirect)
- `github.com/prometheus/client_golang v1.21.1` (line 223)
- `github.com/prometheus/client_model v0.6.1` (line 224)
- `contrib.go.opencensus.io/exporter/prometheus v0.4.2` (line 87)
- `go.opencensus.io v0.24.0` (line 253)

#### No custom metrics exist anywhere in the codebase
- Zero imports of `prometheus`, `opencensus`, or `opentelemetry` in any `.go` file
- No `stats.Record`, `view.Register`, `prometheus.NewCounter`, etc. calls

### 2. Library Recommendation: OpenTelemetry (`go.opentelemetry.io/otel/metric`)

#### knative/pkg has migrated to OpenTelemetry

Verified by examining the latest knative/pkg source on GitHub (main branch):

- **go.mod**: Direct dependencies on `go.opentelemetry.io/otel v1.39.0`, `go.opentelemetry.io/otel/metric v1.39.0`, `go.opentelemetry.io/otel/exporters/prometheus v0.61.0`. **Zero OpenCensus dependencies.**
- **observability/metrics/provider.go**: Uses `sdkmetric.NewMeterProvider()` from OTel SDK
- **observability/metrics/prometheus_enabled.go**: Uses `otelprom.New()` from `go.opentelemetry.io/otel/exporters/prometheus` to create a Prometheus exporter, served via `promhttp.Handler()` on port 9090
- **observability/metrics/k8s/instruments.go**: Wraps OTel `metric.Int64Counter`, `metric.Float64Histogram`, `metric.Int64UpDownCounter`, `metric.Float64Gauge` for workqueue metrics
- **GitHub issue knative/pkg#2174**: Closed by maintainer @dprotaso with comment "We've migrated to OpenTelemetry so this isn't an issue anymore."

#### Why OTel over prometheus/client_golang

1. **Forward compatibility** - policy-controller currently pins `knative.dev/pkg v0.0.0-20230612155445-74c4be5e935e` (old, OpenCensus-era). When this is bumped, the metrics infrastructure will be OTel-native. Using OTel now avoids a migration later.
2. **Knative ecosystem alignment** - New knative/pkg metrics API is `go.opentelemetry.io/otel/metric`. Using the same API means custom metrics integrate cleanly with the framework's MeterProvider.
3. **OTel Prometheus exporter serves to same `/metrics` endpoint** - knative's new `prometheus_enabled.go` uses `promhttp.Handler()` which serves from `prometheus.DefaultRegistry`. The OTel Prometheus exporter automatically registers there.
4. **OTel is the CNCF standard** - not deprecated like OpenCensus, and has broader backend support than raw prometheus/client_golang.

#### API pattern (from knative/pkg source)

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/metric"
)

// Get a meter from the global provider
var meter = otel.Meter("policy-controller")

// Create instruments
cacheOperations, _ := meter.Int64Counter(
    "policy_controller_cache_operations",
    metric.WithDescription("Total number of cache operations"),
    metric.WithUnit("{operation}"),
)

// Record with attributes (OTel equivalent of Prometheus labels)
cacheOperations.Add(ctx, 1, metric.WithAttributes(
    attribute.String("result", "hit"),
))
```

#### Note on current knative.dev/pkg version

The policy-controller currently uses an old knative/pkg (June 2023) which still has OpenCensus. This means the existing `sharedmain.MainWithContext()` wires up OpenCensus exporters. For the OTel metrics to appear on `/metrics`, we need to either:
- **Option A**: Set up our own OTel MeterProvider with a Prometheus exporter (standalone, ~10 lines of setup code)
- **Option B**: Use `prometheus/client_golang` with `promauto` directly, which registers to `prometheus.DefaultRegistry` and appears via the existing OpenCensus Prometheus bridge

**Practical recommendation**: Since bumping knative.dev/pkg is a separate effort and the current version uses OpenCensus, **use `prometheus/client_golang` with `promauto` for this PR** - it's the simplest path that works today. The metrics will appear on `/metrics` immediately. When knative/pkg is bumped, migrating to OTel instruments is straightforward (similar API, just different import). Add a TODO comment noting the planned migration.

### 3. Cache Metrics Suggestions (Label-Based Style)

Following the label-based pattern requested (e.g., single metric with labels rather than separate `_hit`/`_miss` metrics):

#### Primary Cache Metrics (This PR)

**a) `policy_controller_cache_operations_total`** - Counter with labels
```go
var cacheOperations = promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "policy_controller_cache_operations_total",
        Help: "Total number of cache operations by result type.",
    },
    []string{"result"}, // "hit", "miss"
)
```
- Increment with `result="hit"` on cache hit in `LRUCache.Get()`
- Increment with `result="miss"` on cache miss in `LRUCache.Get()`
- Enables: hit rate = `rate(cache_operations_total{result="hit"}) / rate(cache_operations_total)`

**b) `policy_controller_cache_writes_total`** - Counter with labels
```go
var cacheWrites = promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "policy_controller_cache_writes_total",
        Help: "Total number of cache write operations by result type.",
    },
    []string{"result"}, // "stored", "skipped"
)
```
- `result="stored"` when a successful validation is cached in `LRUCache.Set()`
- `result="skipped"` when `PolicyResult` is nil (failed validation, not cached)

**c) `policy_controller_cache_entries`** - Gauge
```go
var cacheEntries = prometheus.NewGauge(
    prometheus.GaugeOpts{
        Name: "policy_controller_cache_entries",
        Help: "Current number of entries in the validation result cache.",
    },
)
```
- Updated on Set/eviction. The underlying `expirable.LRU` has a `Len()` method.
- Alternatively, sample on each Get/Set rather than on eviction callback.

**d) `policy_controller_cache_evictions_total`** - Counter
```go
var cacheEvictions = promauto.NewCounter(
    prometheus.CounterOpts{
        Name: "policy_controller_cache_evictions_total",
        Help: "Total number of cache entries evicted (LRU or TTL).",
    },
)
```
- The `expirable.NewLRU` constructor accepts an `onEvict` callback (currently `nil` on line 37 of `lrucache.go`). Wire this up to increment the counter.

### 4. Future Metrics Suggestions (Not This PR)

These are areas where metrics would add observability value to the broader policy-controller:

#### Validation Metrics

**a) `policy_controller_validation_duration_seconds`** - Histogram with labels
```go
var validationDuration = promauto.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:    "policy_controller_validation_duration_seconds",
        Help:    "Duration of image validation in seconds.",
        Buckets: prometheus.DefBuckets,
    },
    []string{"result", "cached"},
    // result: "allow", "deny", "warn", "error"
    // cached: "true", "false"
)
```
- Instrument in `ValidatePolicy()` (validator.go:474) or `validateContainerImage()` (validator.go:1156)
- Shows how much time cache saves vs full validation

**b) `policy_controller_policy_evaluations_total`** - Counter with labels
```go
var policyEvaluations = promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "policy_controller_policy_evaluations_total",
        Help: "Total number of policy evaluations.",
    },
    []string{"result", "mode"},
    // result: "pass", "fail"
    // mode: "enforce", "warn"
)
```
- Instrument in `validatePolicies()` (validator.go:393)

**c) `policy_controller_images_validated_total`** - Counter with labels
```go
var imagesValidated = promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "policy_controller_images_validated_total",
        Help: "Total number of container images validated.",
    },
    []string{"result"},
    // result: "allow", "deny", "warn", "no_match"
)
```
- Instrument in `validateContainerImage()` (validator.go:1156)

#### Webhook Admission Metrics

**d) `policy_controller_admission_requests_total`** - Counter with labels
```go
// result: "allow", "deny", "warn"
// resource_kind: "Pod", "Deployment", etc.
```
- Instrument at the ValidatePodSpecable/ValidatePod/etc. level

**e) `policy_controller_admission_duration_seconds`** - Histogram
- End-to-end webhook response time per admission request

#### Signature/Attestation Verification Metrics

**f) `policy_controller_signature_verifications_total`** - Counter with labels
```go
// type: "signature", "attestation"
// method: "key", "keyless", "static", "rfc3161"
// result: "success", "failure"
```
- Instrument in `ValidatePolicySignaturesForAuthority()` and `ValidatePolicyAttestationsForAuthority()`

### 5. Implementation Location

The natural place for the metrics definitions is a new file:
```
pkg/webhook/metrics.go
```

The instrumentation points are:
- `pkg/webhook/lrucache.go:45-53` (Get - hit/miss)
- `pkg/webhook/lrucache.go:55-64` (Set - stored/skipped)
- `pkg/webhook/lrucache.go:37` (onEvict callback in NewLRUCache)

For the `NoCache` implementation (`pkg/webhook/nocache.go`), no metrics should be emitted since the cache is disabled.

### 6. Metric Naming Conventions

Following Prometheus naming best practices and the label-based style:
- Prefix: `policy_controller_` (matches the component name from `sharedmain.MainWithContext(ctx, "policy-controller", ...)`)
- Units in suffix: `_seconds`, `_bytes`, `_total` for counters
- Use labels for dimensions rather than separate metric names
- Example: `policy_controller_cache_operations_total{result="hit"}` not `policy_controller_cache_hits_total`

## Code References

- `cmd/webhook/main.go:157` - sharedmain.MainWithContext bootstrap (metrics server)
- `cmd/webhook/main.go:107-111` - Cache CLI flags (enable-cache, cache-size, cache-ttl)
- `cmd/webhook/main.go:247-251` - Cache initialization
- `pkg/webhook/cache.go:47-56` - ResultCache interface
- `pkg/webhook/lrucache.go:35-38` - NewLRUCache constructor (onEvict callback is nil)
- `pkg/webhook/lrucache.go:45-53` - Get() method (hit/miss instrumentation point)
- `pkg/webhook/lrucache.go:55-64` - Set() method (store/skip instrumentation point)
- `pkg/webhook/nocache.go:23-31` - NoCache implementation (no metrics should be emitted)
- `pkg/webhook/validator.go:474-479` - Cache lookup in ValidatePolicy
- `pkg/webhook/validator.go:637-640` - Cache write in ValidatePolicy
- `config/config-observability.yaml` - Observability config template
- `go.mod:223` - prometheus/client_golang v1.21.1 (indirect)

## Architecture Documentation

### Cache Flow
1. Admission request -> `validateContainerImage()` -> `validatePolicies()` -> `ValidatePolicy()`
2. `ValidatePolicy()` checks cache via `FromContext(ctx).Get()` (validator.go:476)
3. If cache miss, full validation occurs
4. If validation succeeds (PolicyResult != nil), result cached via `FromContext(ctx).Set()` (validator.go:637)
5. Failed validations (PolicyResult nil) are NOT cached, allowing retries

### Metrics Endpoint
- knative's `sharedmain` starts metrics server on port 9090
- Current knative.dev/pkg version (June 2023): OpenCensus Prometheus exporter bridges to `prometheus.DefaultRegistry`
- Latest knative.dev/pkg (2025+): OTel Prometheus exporter via `go.opentelemetry.io/otel/exporters/prometheus`, served via `promhttp.Handler()` on same port
- In both cases, metrics registered with `promauto` on `prometheus.DefaultRegistry` appear on `/metrics`

## Open Questions

1. **Should `NoCache` emit a "disabled" metric?** - Could add a gauge `policy_controller_cache_enabled{} 0/1` to indicate cache state
2. **Cardinality concerns** - Should any labels include image name or policy name? Probably not for cache metrics (high cardinality), but worth considering for future validation metrics
3. **Histogram buckets for validation duration** - What are typical validation times? This affects bucket configuration for future duration histograms
