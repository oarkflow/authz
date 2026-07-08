package otel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/oarkflow/authz"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

type Config struct {
	ServiceName   string
	MeterName     string
	TracerProvider trace.TracerProvider
	MeterProvider metric.MeterProvider
	EnableTracing bool
	EnableMetrics bool
	RedactPII     bool
}

func DefaultConfig() *Config {
	return &Config{
		ServiceName:   "authz",
		MeterName:     "authz",
		EnableTracing: true,
		EnableMetrics: true,
	}
}

type instrumentedObserver struct {
	enabled bool
	config  *Config
	tracer  trace.Tracer
	meter   metric.Meter

	decisionCounter       metric.Int64Counter
	decisionDuration      metric.Float64Histogram
	cacheHitCounter       metric.Int64Counter
	cacheMissCounter      metric.Int64Counter
	policyEvaluations     metric.Int64Counter
	roleInheritanceDepth  metric.Int64Histogram
	batchDecisionCounter  metric.Int64Counter
	batchDecisionDuration metric.Float64Histogram

	cacheHitTotal  atomic.Int64
	cacheMissTotal atomic.Int64
}

func New(cfg *Config) (authz.Observer, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	inst := &instrumentedObserver{
		enabled: cfg.EnableTracing || cfg.EnableMetrics,
		config:  cfg,
	}

	if !inst.enabled {
		return inst, nil
	}

	if cfg.EnableTracing {
		tp := cfg.TracerProvider
		if tp == nil {
			tp = otel.GetTracerProvider()
		}
		inst.tracer = tp.Tracer(cfg.ServiceName)
	}

	if cfg.EnableMetrics {
		mp := cfg.MeterProvider
		if mp == nil {
			mp = otel.GetMeterProvider()
		}
		inst.meter = mp.Meter(cfg.MeterName)

		var err error

		inst.decisionCounter, err = inst.meter.Int64Counter(
			"authz.decisions.total",
			metric.WithDescription("Total number of authorization decisions"),
			metric.WithUnit("{decision}"),
		)
		if err != nil {
			return nil, err
		}

		inst.decisionDuration, err = inst.meter.Float64Histogram(
			"authz.decision.duration",
			metric.WithDescription("Duration of authorization decisions"),
			metric.WithUnit("ms"),
			metric.WithExplicitBucketBoundaries(0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100),
		)
		if err != nil {
			return nil, err
		}

		inst.cacheHitCounter, err = inst.meter.Int64Counter(
			"authz.cache.hits",
			metric.WithDescription("Number of decision cache hits"),
			metric.WithUnit("{hit}"),
		)
		if err != nil {
			return nil, err
		}

		inst.cacheMissCounter, err = inst.meter.Int64Counter(
			"authz.cache.misses",
			metric.WithDescription("Number of decision cache misses"),
			metric.WithUnit("{miss}"),
		)
		if err != nil {
			return nil, err
		}

		inst.policyEvaluations, err = inst.meter.Int64Counter(
			"authz.policy.evaluations",
			metric.WithDescription("Number of policy evaluations"),
			metric.WithUnit("{evaluation}"),
		)
		if err != nil {
			return nil, err
		}

		inst.roleInheritanceDepth, err = inst.meter.Int64Histogram(
			"authz.role.inheritance_depth",
			metric.WithDescription("Depth of role inheritance chain"),
			metric.WithUnit("{level}"),
		)
		if err != nil {
			return nil, err
		}

		inst.batchDecisionCounter, err = inst.meter.Int64Counter(
			"authz.batch.decisions.total",
			metric.WithDescription("Total number of batch authorization decisions"),
			metric.WithUnit("{batch}"),
		)
		if err != nil {
			return nil, err
		}

		inst.batchDecisionDuration, err = inst.meter.Float64Histogram(
			"authz.batch.decision.duration",
			metric.WithDescription("Duration of batch authorization decisions"),
			metric.WithUnit("ms"),
			metric.WithExplicitBucketBoundaries(1, 5, 10, 25, 50, 100, 250, 500, 1000),
		)
		if err != nil {
			return nil, err
		}

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

func (o *instrumentedObserver) Enabled() bool { return o.enabled }

func (o *instrumentedObserver) StartSpan(ctx context.Context, name string, attrs ...authz.ObserverAttr) (context.Context, authz.Span) {
	if !o.enabled || !o.config.EnableTracing || o.tracer == nil {
		return ctx, nil
	}
	traceAttrs := make([]attribute.KeyValue, len(attrs))
	for i, a := range attrs {
		traceAttrs[i] = attrFromObserver(a)
	}
	cctx, span := o.tracer.Start(ctx, name, trace.WithAttributes(traceAttrs...))
	return cctx, &otelSpan{span: span}
}

func (o *instrumentedObserver) RecordDecision(ctx context.Context, subject *authz.Subject, action authz.Action, resource *authz.Resource, decision *authz.Decision, dur time.Duration) {
	if !o.enabled {
		return
	}

	subjectID := subject.ID
	tenantID := subject.TenantID
	resourceID := resource.ID
	resourceType := resource.Type
	if o.config.RedactPII {
		subjectID = hash(subjectID)
		tenantID = hash(tenantID)
		resourceID = hash(resourceID)
		resourceType = hash(resourceType)
	}
	attrs := []attribute.KeyValue{
		attribute.String("authz.subject.id", subjectID),
		attribute.String("authz.subject.tenant", tenantID),
		attribute.String("authz.action", string(action)),
		attribute.String("authz.resource.type", resourceType),
		attribute.String("authz.resource.id", resourceID),
		attribute.Bool("authz.allowed", decision.Allowed),
		attribute.String("authz.matched_by", decision.MatchedBy),
	}

	if o.config.EnableMetrics {
		o.decisionCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
		o.decisionDuration.Record(ctx, float64(dur.Microseconds())/1000.0, metric.WithAttributes(attrs...))
	}
}

func (o *instrumentedObserver) Shutdown(ctx context.Context) error { return nil }

type otelSpan struct {
	span trace.Span
}

func (s *otelSpan) End() {
	if s.span != nil {
		s.span.End()
	}
}

func (s *otelSpan) SetAttributes(attrs ...authz.ObserverAttr) {
	if s.span == nil {
		return
	}
	otelAttrs := make([]attribute.KeyValue, len(attrs))
	for i, a := range attrs {
		otelAttrs[i] = attrFromObserver(a)
	}
	s.span.SetAttributes(otelAttrs...)
}

func attrFromObserver(a authz.ObserverAttr) attribute.KeyValue {
	switch v := a.Value.(type) {
	case string:
		return attribute.String(a.Key, v)
	case bool:
		return attribute.Bool(a.Key, v)
	case int:
		return attribute.Int(a.Key, v)
	case int64:
		return attribute.Int64(a.Key, v)
	case float64:
		return attribute.Float64(a.Key, v)
	default:
		return attribute.String(a.Key, toString(v))
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
