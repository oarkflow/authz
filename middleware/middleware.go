package middleware

// Package middleware provides reusable authorization middleware for various Go HTTP frameworks.

import (
	"net/http"
	"strings"
	"time"

	"github.com/oarkflow/authz"
)

// SubjectExtractor extracts the Subject from an HTTP request.
type SubjectExtractor func(r *http.Request) *authz.Subject

// ResourceExtractor extracts the Resource from an HTTP request.
type ResourceExtractor func(r *http.Request) *authz.Resource

// EnvironmentExtractor extracts the Environment from an HTTP request.
type EnvironmentExtractor func(r *http.Request) *authz.Environment

// DeniedHandler handles denied authorization responses.
type DeniedHandler func(w http.ResponseWriter, r *http.Request, decision *authz.Decision)

// ErrorHandler handles authorization errors.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// SkipFunc determines whether to skip authorization for a request.
type SkipFunc func(r *http.Request) bool

// Config holds the configuration for authorization middleware.
type Config struct {
	// Engine is the authorization engine to use. Required.
	Engine *authz.Engine

	// Subject extracts the subject from the request.
	// If nil, returns a minimal subject from X-Subject-ID and X-Tenant-ID headers.
	Subject SubjectExtractor

	// Resource extracts the resource from the request.
	// If nil, uses DefaultResourceExtractor.
	Resource ResourceExtractor

	// Environment extracts the environment from the request.
	// If nil, uses DefaultEnvironmentExtractor.
	Environment EnvironmentExtractor

	// OnDenied handles denied responses.
	// If nil, returns 403 Forbidden with JSON body.
	OnDenied DeniedHandler

	// OnError handles authorization errors.
	// If nil, returns 500 Internal Server Error with JSON body.
	OnError ErrorHandler

	// SkipPaths is a list of paths to skip authorization for.
	// Supports wildcards: /health/*, /public/**
	SkipPaths []string

	// Skip is a function that determines whether to skip authorization.
	// Takes precedence over SkipPaths.
	Skip SkipFunc
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.Engine == nil {
		return ErrMissingEngine
	}
	return nil
}

// ShouldSkip returns true if the request should skip authorization.
func (c *Config) ShouldSkip(r *http.Request) bool {
	if c.Skip != nil && c.Skip(r) {
		return true
	}
	return shouldSkipPath(r.URL.Path, c.SkipPaths)
}

// ConfigError is returned when the middleware configuration is invalid.
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}

// ErrMissingEngine is returned when Engine is nil.
var ErrMissingEngine = &ConfigError{Message: "middleware: Engine is required"}

// DefaultSubjectExtractor extracts subject info from standard headers.
func DefaultSubjectExtractor(r *http.Request) *authz.Subject {
	return &authz.Subject{
		ID:       r.Header.Get("X-Subject-ID"),
		TenantID: r.Header.Get("X-Tenant-ID"),
		Roles:    splitTrim(r.Header.Get("X-Roles"), ","),
	}
}

// DefaultResourceExtractor uses the HTTP method and path as the resource.
func DefaultResourceExtractor(r *http.Request) *authz.Resource {
	tenant := r.Header.Get("X-Tenant-ID")
	return &authz.Resource{
		ID:       r.Method + ":" + r.URL.Path,
		Type:     "route",
		TenantID: tenant,
	}
}

// DefaultEnvironmentExtractor creates an environment with the current time and tenant.
func DefaultEnvironmentExtractor(r *http.Request) *authz.Environment {
	return &authz.Environment{
		Time:     time.Now(),
		TenantID: r.Header.Get("X-Tenant-ID"),
	}
}

// DefaultDeniedHandler returns a 403 Forbidden response with JSON body.
func DefaultDeniedHandler(w http.ResponseWriter, r *http.Request, decision *authz.Decision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"forbidden","message":"access denied"}`))
}

// DefaultErrorHandler returns a 500 Internal Server Error response with JSON body.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(`{"error":"internal_error","message":"authorization check failed"}`))
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(engine *authz.Engine) *Config {
	return &Config{
		Engine:      engine,
		Subject:     DefaultSubjectExtractor,
		Resource:    DefaultResourceExtractor,
		Environment: DefaultEnvironmentExtractor,
		OnDenied:    DefaultDeniedHandler,
		OnError:     DefaultErrorHandler,
	}
}

// Authorize performs authorization using the provided config.
// Returns true if authorized, false otherwise.
// On error or denial, it writes the response and returns false.
func Authorize(cfg *Config, w http.ResponseWriter, r *http.Request) (*authz.Decision, bool) {
	// Check skip conditions
	if cfg.ShouldSkip(r) {
		return &authz.Decision{Allowed: true, Reason: "skipped"}, true
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		onError := cfg.OnError
		if onError == nil {
			onError = DefaultErrorHandler
		}
		onError(w, r, err)
		return nil, false
	}

	// Extract authorization parameters
	subjectFn := cfg.Subject
	if subjectFn == nil {
		subjectFn = DefaultSubjectExtractor
	}
	subject := subjectFn(r)

	resourceFn := cfg.Resource
	if resourceFn == nil {
		resourceFn = DefaultResourceExtractor
	}
	resource := resourceFn(r)

	envFn := cfg.Environment
	if envFn == nil {
		envFn = DefaultEnvironmentExtractor
	}
	env := envFn(r)

	// Perform authorization
	action := authz.Action(r.Method)
	decision, err := cfg.Engine.Authorize(r.Context(), subject, action, resource, env)

	if err != nil {
		onError := cfg.OnError
		if onError == nil {
			onError = DefaultErrorHandler
		}
		onError(w, r, err)
		return nil, false
	}

	if !decision.Allowed {
		onDenied := cfg.OnDenied
		if onDenied == nil {
			onDenied = DefaultDeniedHandler
		}
		onDenied(w, r, decision)
		return decision, false
	}

	return decision, true
}

// shouldSkipPath checks if the path matches any skip patterns.
func shouldSkipPath(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchPath(pattern, path) {
			return true
		}
	}
	return false
}

// matchPath matches a path against a pattern.
// Supports * (single segment) and ** (multiple segments).
func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}

	// Handle ** wildcard (matches multiple segments)
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix)
	}

	// Handle * wildcard (matches single segment)
	if strings.Contains(pattern, "*") {
		patternParts := strings.Split(pattern, "/")
		pathParts := strings.Split(path, "/")

		if len(patternParts) != len(pathParts) {
			return false
		}

		for i, pp := range patternParts {
			if pp == "*" {
				continue
			}
			if pp != pathParts[i] {
				return false
			}
		}
		return true
	}

	return false
}

// splitTrim splits a string and trims whitespace from each part.
func splitTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
