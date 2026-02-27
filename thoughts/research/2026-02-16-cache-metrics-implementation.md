---
date: 2026-02-16T19:10:00+01:00
researcher: Claude
git_commit: e0276230
branch: metrics
repository: sigstore/policy-controller
topic: "Cache metrics implementation - OTEL metrics with knative/pkg"
tags: [research, codebase, metrics, opentelemetry, cache, observability]
status: complete
last_updated: 2026-02-16
last_updated_by: Claude
last_updated_note: "Rewrote after bumping knative/pkg to v0.0.0-20260213150858. Corrected metric naming to OTEL conventions, documented knative metrics infrastructure."
---

# Research: Cache Metrics Implementation

**Date**: 2026-02-16T19:10:00+01:00
**Researcher**: Claude
**Git Commit**: e0276230
**Branch**: metrics
**Repository**: sigstore/policy-controller

## Research Question

How to add metrics for the LRU cache in policy-controller using OpenTelemetry, following label-based naming patterns (short metric names, dimensions as attributes).

## Summary

With the knative/pkg bump to `v0.0.0-20260213150858` (Feb 2026), the metrics infrastructure is now fully OpenTelemetry-based. knative's `sharedmain.MainWithContext()` sets up an OTEL MeterProvider and, when configured with `metrics-protocol: prometheus`, serves a pull-based `/metrics` endpoint on port 9090 via the OTEL Prometheus exporter. This is the standard operator pattern.

**Recommendation: Use `go.opentelemetry.io/otel/metric`** with the global MeterProvider that knative sets up. Use short, descriptive metric names with attributes for dimensions (e.g., `cache_operations{result="hit"}` not `policy_controller_cache_operations_total{result="hit"}`). The OTEL Prometheus exporter handles `_total` suffixes and unit suffixes automatically.

The codebase currently has **zero custom metrics**. The cache has clear instrumentation points in `LRUCache.Get()` and `LRUCache.Set()`.

## Detailed Findings

### 1. Knative Metrics Infrastructure (Post-Bump)

#### How sharedmain sets up metrics

`sharedmain.MainWithContext()` calls `SetupObservabilityOrDie()` which:

1. Reads `config-observability` ConfigMap from the system namespace
2. Creates an OTEL `MeterProvider` based on the configured protocol
3. Registers it globally via `otel.SetMeterProvider()`
4. Sets up workqueue metrics, client-go metrics, and Go runtime metrics

**Supported protocols** (from `observability/metrics/config.go`):

| Protocol | Type | Default Endpoint | ConfigMap value |
|----------|------|------------------|-----------------|
| `prometheus` | Pull-based | `0.0.0.0:9090` | `metrics-protocol: "prometheus"` |
| `grpc` | Push-based OTLP | (required) | `metrics-protocol: "grpc"` |
| `http/protobuf` | Push-based OTLP | (required) | `metrics-protocol: "http/protobuf"` |
| `none` | Disabled | N/A | `metrics-protocol: "none"` (default) |

**Important**: The default is `none` (disabled). The existing `config-observability.yaml` references old OpenCensus-era keys (`metrics.backend-destination`) that the new knative/pkg no longer reads. It needs to be updated to use `metrics-protocol: prometheus` for metrics to work.

#### Prometheus mode details

When `metrics-protocol: prometheus` is set:
- `otelprom.New()` creates an OTEL Prometheus exporter with `UnderscoreEscapingWithSuffixes` translation
- A dedicated HTTP server starts on port 9090 serving `promhttp.Handler()` at `/metrics`
- Port can be overridden via `METRICS_PROMETHEUS_PORT` env var
- All metrics registered with the global OTEL MeterProvider appear on the endpoint automatically

This is pull-based scraping - the standard pattern for Kubernetes operators. No push infrastructure needed.

#### Key source files (in module cache)

- `observability/metrics/config.go` - Config struct, protocol constants, `DefaultConfig()`
- `observability/metrics/provider.go` - `NewMeterProvider()`, protocol routing via `readerFor()`
- `observability/metrics/prometheus_enabled.go` - `buildPrometheus()`, OTEL exporter setup
- `observability/metrics/prometheus/server.go` - HTTP server for `/metrics` endpoint
- `injection/sharedmain/main.go:286` - `SetupObservabilityOrDie()` bootstrap

### 2. Library: OpenTelemetry (`go.opentelemetry.io/otel/metric`)

Since knative/pkg now sets up a global OTEL MeterProvider, custom metrics just need to:
1. Get a meter via `otel.Meter("scope-name")`
2. Create instruments (counters, gauges, histograms)
3. Record values with attributes

The MeterProvider handles export to whatever backend is configured (Prometheus, OTLP, etc.).

#### API pattern

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/metric"
)

// Get a meter - scope name provides component context
var meter = otel.Meter("policy-controller")

// Create instruments - short names, no prefix, no _total suffix
cacheOperations, _ := meter.Int64Counter(
    "cache.operations",
    metric.WithDescription("Number of cache lookup operations"),
    metric.WithUnit("{operation}"),
)

// Record with attributes for dimensions
cacheOperations.Add(ctx, 1, metric.WithAttributes(
    attribute.String("result", "hit"),
))
```

### 3. Metric Naming Conventions (OTEL Style)

OTEL naming differs from old Prometheus conventions:

- **No component prefix** - The meter scope name (`"policy-controller"`) provides component context, not the metric name
- **No `_total` suffix** - The OTEL Prometheus exporter adds `_total` for counters automatically
- **No `_seconds`/`_bytes` suffix for units** - Use `metric.WithUnit("s")` or `metric.WithUnit("By")` and the exporter handles suffixes
- **Use dots for namespacing** if needed (e.g., `cache.operations`)
- **Short, descriptive names** - Describe what is measured
- **Dimensions as attributes** - Use `attribute.String("key", "value")` for labels

Example of how OTEL names map to Prometheus output:

| OTEL instrument | OTEL name | Unit | Prometheus output |
|-----------------|-----------|------|-------------------|
| Int64Counter | `cache.operations` | `{operation}` | `cache_operations_total{result="hit"}` |
| Int64Counter | `cache.evictions` | `{eviction}` | `cache_evictions_total` |
| Int64UpDownCounter | `cache.entries` | `{entry}` | `cache_entries{otel_scope_name="policy-controller"}` |
| Float64Histogram | `validation.duration` | `s` | `validation_duration_seconds{...}` |

### 4. Cache Metrics (This PR)

#### a) `cache.operations` - Counter with `result` attribute
```go
cacheOps, _ := meter.Int64Counter(
    "cache.operations",
    metric.WithDescription("Number of cache lookup operations"),
    metric.WithUnit("{operation}"),
)
```
- `result="hit"` on cache hit in `LRUCache.Get()`
- `result="miss"` on cache miss in `LRUCache.Get()`
- Hit rate: `rate(cache_operations_total{result="hit"}) / rate(cache_operations_total)`

#### b) `cache.writes` - Counter with `result` attribute
```go
cacheWrites, _ := meter.Int64Counter(
    "cache.writes",
    metric.WithDescription("Number of cache write operations"),
    metric.WithUnit("{operation}"),
)
```
- `result="stored"` when a successful validation is cached in `LRUCache.Set()`
- `result="skipped"` when `PolicyResult` is nil (failed validation, not cached)

#### c) `cache.entries` - UpDownCounter (gauge-like)
```go
cacheEntries, _ := meter.Int64UpDownCounter(
    "cache.entries",
    metric.WithDescription("Current number of entries in the validation result cache"),
    metric.WithUnit("{entry}"),
)
```
- Increment on Set (stored), decrement on eviction
- The `expirable.LRU` `onEvict` callback handles the decrement

#### d) `cache.evictions` - Counter
```go
cacheEvictions, _ := meter.Int64Counter(
    "cache.evictions",
    metric.WithDescription("Number of cache entries evicted"),
    metric.WithUnit("{eviction}"),
)
```
- Wire up via the `onEvict` callback in `expirable.NewLRU` (currently `nil` at lrucache.go:37)

### 5. Future Metrics (Not This PR)

#### Validation metrics
- `validation.duration` (Histogram, unit `s`) with attributes `result`, `cached`
- `policy.evaluations` (Counter) with attributes `result`, `mode`
- `image.validations` (Counter) with attributes `result`

#### Webhook admission metrics
- `admission.requests` (Counter) with attributes `result`, `resource_kind`
- `admission.duration` (Histogram, unit `s`)

#### Signature verification metrics
- `signature.verifications` (Counter) with attributes `type`, `method`, `result`

### 6. Implementation Location

Metrics definitions in a new file:
```
pkg/webhook/metrics.go
```

Instrumentation points:
- `pkg/webhook/lrucache.go:45-53` (Get - hit/miss)
- `pkg/webhook/lrucache.go:55-64` (Set - stored/skipped)
- `pkg/webhook/lrucache.go:37` (onEvict callback in NewLRUCache)

For the `NoCache` implementation (`pkg/webhook/nocache.go`), no metrics should be emitted since the cache is disabled.

### 7. ConfigMap Update Required

The existing `config/config-observability.yaml` uses old OpenCensus-era keys that the new knative/pkg ignores. It needs to be updated:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-observability
  namespace: cosign-system
data:
  metrics-protocol: "prometheus"
```

Without this, `DefaultConfig()` returns `Protocol: "none"` and the MeterProvider is a no-op (no metrics collected or served).

## Code References

- `cmd/webhook/main.go:157` - sharedmain.MainWithContext bootstrap
- `cmd/webhook/main.go:107-111` - Cache CLI flags (enable-cache, cache-size, cache-ttl)
- `cmd/webhook/main.go:247-251` - Cache initialization
- `pkg/webhook/cache.go:47-56` - ResultCache interface
- `pkg/webhook/lrucache.go:35-38` - NewLRUCache constructor (onEvict callback is nil)
- `pkg/webhook/lrucache.go:45-53` - Get() method (hit/miss instrumentation point)
- `pkg/webhook/lrucache.go:55-64` - Set() method (store/skip instrumentation point)
- `pkg/webhook/nocache.go:23-31` - NoCache implementation
- `pkg/webhook/validator.go:474-479` - Cache lookup in ValidatePolicy
- `pkg/webhook/validator.go:637-640` - Cache write in ValidatePolicy
- `config/config-observability.yaml` - Observability config (needs update)
- `config/webhook.yaml:70-71` - METRICS_DOMAIN env var

## Architecture Documentation

### Cache Flow
1. Admission request -> `validateContainerImage()` -> `validatePolicies()` -> `ValidatePolicy()`
2. `ValidatePolicy()` checks cache via `FromContext(ctx).Get()` (validator.go:476)
3. If cache miss, full validation occurs
4. If validation succeeds (PolicyResult != nil), result cached via `FromContext(ctx).Set()` (validator.go:637)
5. Failed validations (PolicyResult nil) are NOT cached, allowing retries

### Metrics Endpoint
- knative's `sharedmain` reads `config-observability` ConfigMap
- When `metrics-protocol: prometheus`, starts OTEL Prometheus exporter on `:9090/metrics`
- All instruments created via `otel.Meter()` are automatically exported
- Pull-based: standard Prometheus scraping, no push infrastructure needed

## Open Questions

1. **Should `NoCache` emit a "disabled" metric?** - Could add a gauge `cache.enabled` (0/1) to indicate cache state
2. **Cardinality concerns** - Should any attributes include image name or policy name? Probably not for cache metrics (high cardinality), but worth considering for future validation metrics
3. **Histogram buckets for validation duration** - What are typical validation times? This affects bucket configuration for future duration histograms
