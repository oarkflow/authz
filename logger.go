package authz

// Logger is a minimal structured logging interface used by the Engine.
// Implementations should accept alternating key/value pairs as variadic arguments.
// This keeps the interface small and easy to mock in tests.
type Logger interface {
	Debug(msg string, keyvals ...any)
	Info(msg string, keyvals ...any)
	Error(msg string, keyvals ...any)
}

// TraceIDFunc generates a correlation/trace ID string for each request/log.
// It should be cheap and safe for concurrent calls.
type TraceIDFunc func() string

// WithLogger installs a Logger on the Engine via EngineOption
func WithLogger(l Logger) EngineOption {
	return func(e *Engine) error {
		e.logger = l
		return nil
	}
}

// WithTraceIDFunc installs a custom trace ID generator on the engine.
func WithTraceIDFunc(f TraceIDFunc) EngineOption {
	return func(e *Engine) error {
		e.traceIDFunc = f
		return nil
	}
}
