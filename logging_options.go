package authz

import "github.com/oarkflow/authz/logger"

// Logger is re-exported for backwards compatibility.
type Logger = logger.Logger

// WithLogger installs a Logger on the Engine via EngineOption
func WithLogger(l logger.Logger) EngineOption {
	return func(e *Engine) error {
		e.logger = l
		return nil
	}
}

// WithTraceIDFunc installs a custom trace ID generator on the engine.
func WithTraceIDFunc(f logger.TraceIDFunc) EngineOption {
	return func(e *Engine) error {
		e.traceIDFunc = f
		return nil
	}
}
