package middleware

import (
	"net/http"

	"github.com/oarkflow/authz"
)

// NewHTTP creates a standard net/http middleware for authorization.
func NewHTTP(cfg *Config) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			decision, allowed := Authorize(cfg, w, r)
			if !allowed {
				return
			}

			// Attach decision to request context
			ctx := authz.ContextWithDecision(r.Context(), decision)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// HTTPFunc creates a net/http middleware using functional options.
func HTTPFunc(engine *authz.Engine, opts ...func(*Config)) func(next http.Handler) http.Handler {
	cfg := DefaultConfig(engine)
	for _, opt := range opts {
		opt(cfg)
	}
	return NewHTTP(cfg)
}

// WithSubject sets the subject extractor.
func WithSubject(fn SubjectExtractor) func(*Config) {
	return func(c *Config) {
		c.Subject = fn
	}
}

// WithResource sets the resource extractor.
func WithResource(fn ResourceExtractor) func(*Config) {
	return func(c *Config) {
		c.Resource = fn
	}
}

// WithEnvironment sets the environment extractor.
func WithEnvironment(fn EnvironmentExtractor) func(*Config) {
	return func(c *Config) {
		c.Environment = fn
	}
}

// WithDeniedHandler sets the denied handler.
func WithDeniedHandler(fn DeniedHandler) func(*Config) {
	return func(c *Config) {
		c.OnDenied = fn
	}
}

// WithErrorHandler sets the error handler.
func WithErrorHandler(fn ErrorHandler) func(*Config) {
	return func(c *Config) {
		c.OnError = fn
	}
}

// WithSkipPaths sets paths to skip authorization for.
func WithSkipPaths(paths ...string) func(*Config) {
	return func(c *Config) {
		c.SkipPaths = paths
	}
}

// WithSkip sets the skip function.
func WithSkip(fn SkipFunc) func(*Config) {
	return func(c *Config) {
		c.Skip = fn
	}
}
