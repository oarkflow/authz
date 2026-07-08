package authz

import (
	"context"
	"time"
)

type Observer interface {
	Enabled() bool
	StartSpan(ctx context.Context, name string, attrs ...ObserverAttr) (context.Context, Span)
	RecordDecision(ctx context.Context, subject *Subject, action Action, resource *Resource, decision *Decision, dur time.Duration)
	Shutdown(ctx context.Context) error
}

type Span interface {
	End()
	SetAttributes(attrs ...ObserverAttr)
}

type ObserverAttr struct {
	Key   string
	Value any
}

type NoopObserver struct{}

func (NoopObserver) Enabled() bool { return false }

func (NoopObserver) StartSpan(ctx context.Context, name string, attrs ...ObserverAttr) (context.Context, Span) {
	return ctx, nil
}

func (NoopObserver) RecordDecision(_ context.Context, _ *Subject, _ Action, _ *Resource, _ *Decision, _ time.Duration) {}

func (NoopObserver) Shutdown(_ context.Context) error { return nil }
