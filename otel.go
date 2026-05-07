package authz

import (
	"context"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// OTelConfig holds OpenTelemetry configuration options.
type OTelConfig struct {
	// ServiceName is the name of the service for tracing.
	ServiceName string
	// MeterName is the name of the meter for metrics.
	MeterName string
	// TracerProvider is the tracer provider to use. If nil, uses global provider.
	TracerProvider trace.TracerProvider
	// MeterProvider is the meter provider to use. If nil, uses global provider.
	MeterProvider metric.MeterProvider
	// EnableTracing enables decision tracing.
	EnableTracing bool
	// EnableMetrics enables decision metrics.
	EnableMetrics bool
}

// DefaultOTelConfig returns a sensible default configuration.
func DefaultOTelConfig() *OTelConfig {
	return &OTelConfig{
		ServiceName:   "authz",
		MeterName:     "authz",
		EnableTracing: true,
		EnableMetrics: true,
	}
}

// otelInstrumentation holds the OpenTelemetry instrumentation for the engine.
type otelInstrumentation struct {
	enabled bool
	config  *OTelConfig
	tracer  trace.Tracer
	meter   metric.Meter

	// Metrics
	decisionCounter       metric.Int64Counter
	decisionDuration      metric.Float64Histogram
	cacheHitCounter       metric.Int64Counter
	cacheMissCounter      metric.Int64Counter
	policyEvaluations     metric.Int64Counter
	roleInheritanceDepth  metric.Int64Histogram
	batchDecisionCounter  metric.Int64Counter
	batchDecisionDuration metric.Float64Histogram

	// Async metrics via callback
	cacheHitTotal  atomic.Int64
	cacheMissTotal atomic.Int64
}

// newOTelInstrumentation creates a new OpenTelemetry instrumentation instance.
func newOTelInstrumentation(cfg *OTelConfig) (*otelInstrumentation, error) {
	if cfg == nil {
		cfg = DefaultOTelConfig()
	}

	inst := &otelInstrumentation{
		enabled: cfg.EnableTracing || cfg.EnableMetrics,
		config:  cfg,
	}

	if !inst.enabled {
		return inst, nil
	}

	// Setup tracer
	if cfg.EnableTracing {
		tp := cfg.TracerProvider
		if tp == nil {
			tp = otel.GetTracerProvider()
		}
		inst.tracer = tp.Tracer(cfg.ServiceName)
	}

	// Setup meter and metrics
	if cfg.EnableMetrics {
		mp := cfg.MeterProvider
		if mp == nil {
			mp = otel.GetMeterProvider()
		}
		inst.meter = mp.Meter(cfg.MeterName)

		var err error

		// Decision counter
		inst.decisionCounter, err = inst.meter.Int64Counter(
			"authz.decisions.total",
			metric.WithDescription("Total number of authorization decisions"),
			metric.WithUnit("{decision}"),
		)
		if err != nil {
			return nil, err
		}

		// Decision duration histogram
		inst.decisionDuration, err = inst.meter.Float64Histogram(
			"authz.decision.duration",
			metric.WithDescription("Duration of authorization decisions"),
			metric.WithUnit("ms"),
			metric.WithExplicitBucketBoundaries(0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100),
		)
		if err != nil {
			return nil, err
		}

		// Cache hit counter
		inst.cacheHitCounter, err = inst.meter.Int64Counter(
			"authz.cache.hits",
			metric.WithDescription("Number of decision cache hits"),
			metric.WithUnit("{hit}"),
		)
		if err != nil {
			return nil, err
		}

		// Cache miss counter
		inst.cacheMissCounter, err = inst.meter.Int64Counter(
			"authz.cache.misses",
			metric.WithDescription("Number of decision cache misses"),
			metric.WithUnit("{miss}"),
		)
		if err != nil {
			return nil, err
		}

		// Policy evaluations counter
		inst.policyEvaluations, err = inst.meter.Int64Counter(
			"authz.policy.evaluations",
			metric.WithDescription("Number of policy evaluations"),
			metric.WithUnit("{evaluation}"),
		)
		if err != nil {
			return nil, err
		}

		// Role inheritance depth histogram
		inst.roleInheritanceDepth, err = inst.meter.Int64Histogram(
			"authz.role.inheritance_depth",
			metric.WithDescription("Depth of role inheritance chain"),
			metric.WithUnit("{level}"),
		)
		if err != nil {
			return nil, err
		}

		// Batch decision counter
		inst.batchDecisionCounter, err = inst.meter.Int64Counter(
			"authz.batch.decisions.total",
			metric.WithDescription("Total number of batch authorization decisions"),
			metric.WithUnit("{batch}"),
		)
		if err != nil {
			return nil, err
		}

		// Batch decision duration histogram
		inst.batchDecisionDuration, err = inst.meter.Float64Histogram(
			"authz.batch.decision.duration",
			metric.WithDescription("Duration of batch authorization decisions"),
			metric.WithUnit("ms"),
			metric.WithExplicitBucketBoundaries(1, 5, 10, 25, 50, 100, 250, 500, 1000),
		)
		if err != nil {
			return nil, err
		}

		// Register async callback for cache hit ratio
		_, err = inst.meter.Float64ObservableGauge(
			"authz.cache.hit_ratio",
			metric.WithDescription("Cache hit ratio (hits / total)"),
			metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
				hits := inst.cacheHitTotal.Load()
				misses := inst.cacheMissTotal.Load()
				total := hits + misses
				if total > 0 {
					o.Observe(float64(hits) / float64(total))
				} else {
					o.Observe(0)
				}
				return nil
			}),
		)
		if err != nil {
			return nil, err
		}
	}

	return inst, nil
}

// recordDecision records metrics and trace for an authorization decision.
func (i *otelInstrumentation) recordDecision(
	ctx context.Context,
	subject *Subject,
	action Action,
	resource *Resource,
	decision *Decision,
	duration time.Duration,
	cacheHit bool,
) {
	if !i.enabled {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("authz.subject.id", subject.ID),
		attribute.String("authz.subject.tenant", subject.TenantID),
		attribute.String("authz.action", string(action)),
		attribute.String("authz.resource.type", resource.Type),
		attribute.String("authz.resource.id", resource.ID),
		attribute.Bool("authz.allowed", decision.Allowed),
		attribute.String("authz.matched_by", decision.MatchedBy),
		attribute.Bool("authz.cache_hit", cacheHit),
	}

	if i.config.EnableMetrics {
		i.decisionCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
		i.decisionDuration.Record(ctx, float64(duration.Microseconds())/1000.0, metric.WithAttributes(attrs...))

		if cacheHit {
			i.cacheHitCounter.Add(ctx, 1)
			i.cacheHitTotal.Add(1)
		} else {
			i.cacheMissCounter.Add(ctx, 1)
			i.cacheMissTotal.Add(1)
		}
	}
}

// recordPolicyEvaluation records a policy evaluation.
func (i *otelInstrumentation) recordPolicyEvaluation(ctx context.Context, tenantID, policyID string, matched bool) {
	if !i.enabled || !i.config.EnableMetrics {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("authz.tenant", tenantID),
		attribute.String("authz.policy.id", policyID),
		attribute.Bool("authz.policy.matched", matched),
	}
	i.policyEvaluations.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// recordRoleInheritanceDepth records the depth of role inheritance chain.
func (i *otelInstrumentation) recordRoleInheritanceDepth(ctx context.Context, depth int64) {
	if !i.enabled || !i.config.EnableMetrics {
		return
	}
	i.roleInheritanceDepth.Record(ctx, depth)
}

// recordBatchDecision records metrics for a batch authorization request.
func (i *otelInstrumentation) recordBatchDecision(ctx context.Context, count int, duration time.Duration) {
	if !i.enabled || !i.config.EnableMetrics {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.Int("authz.batch.size", count),
	}
	i.batchDecisionCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	i.batchDecisionDuration.Record(ctx, float64(duration.Microseconds())/1000.0, metric.WithAttributes(attrs...))
}

// startSpan starts a new trace span for an authorization decision.
// Returns nil span if tracing is disabled - caller must check for nil.
func (i *otelInstrumentation) startSpan(ctx context.Context, name string, subject *Subject, action Action, resource *Resource) (context.Context, trace.Span) {
	if !i.enabled || !i.config.EnableTracing || i.tracer == nil {
		return ctx, nil
	}

	ctx, span := i.tracer.Start(ctx, name,
		trace.WithAttributes(
			attribute.String("authz.subject.id", subject.ID),
			attribute.String("authz.subject.tenant", subject.TenantID),
			attribute.String("authz.action", string(action)),
			attribute.String("authz.resource.type", resource.Type),
			attribute.String("authz.resource.id", resource.ID),
		),
	)
	return ctx, span
}

// setSpanDecision sets the decision result on a span.
func (i *otelInstrumentation) setSpanDecision(span trace.Span, decision *Decision) {
	if !i.enabled || !i.config.EnableTracing || span == nil {
		return
	}
	span.SetAttributes(
		attribute.Bool("authz.allowed", decision.Allowed),
		attribute.String("authz.reason", decision.Reason),
		attribute.String("authz.matched_by", decision.MatchedBy),
	)
}

// WithOpenTelemetry enables OpenTelemetry instrumentation on the Engine.
func WithOpenTelemetry(cfg *OTelConfig) EngineOption {
	return func(e *Engine) error {
		inst, err := newOTelInstrumentation(cfg)
		if err != nil {
			return err
		}
		e.otel = inst
		return nil
	}
}

// CacheStats returns current cache statistics.
type CacheStats struct {
	Hits      int64   `json:"hits"`
	Misses    int64   `json:"misses"`
	HitRatio  float64 `json:"hit_ratio"`
	Size      int     `json:"size"`
	Evictions int64   `json:"evictions,omitempty"`
}

// GetCacheStats returns the current cache statistics for the engine.
func (e *Engine) GetCacheStats() CacheStats {
	var hits, misses int64
	if e.otel != nil {
		hits = e.otel.cacheHitTotal.Load()
		misses = e.otel.cacheMissTotal.Load()
	}

	total := hits + misses
	var ratio float64
	if total > 0 {
		ratio = float64(hits) / float64(total)
	}

	size := 0
	e.decisionCacheMu.RLock()
	size = len(e.decisionCache)
	e.decisionCacheMu.RUnlock()

	return CacheStats{
		Hits:     hits,
		Misses:   misses,
		HitRatio: ratio,
		Size:     size,
	}
}
