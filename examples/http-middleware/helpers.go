package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/oarkflow/authz"
)

// HTTPAuthOptions configures the behavior of the net/http authorization middleware.
// Extractor functions are supplied by the application to avoid hard-coded behavior.
// OnDenied and OnError allow the app to customize responses.
type HTTPAuthOptions struct {
	Engine   *authz.Engine
	Subject  func(r *http.Request) string
	Tenant   func(r *http.Request) string
	Resource func(r *http.Request) *authz.Resource
	OnDenied func(w http.ResponseWriter, r *http.Request, decision *authz.Decision)
	OnError  func(w http.ResponseWriter, r *http.Request, err error)
}

// DefaultHTTPAuthOptions returns reasonable handlers for OnDenied/OnError but leaves
// extractors nil so callers must provide them.
func DefaultHTTPAuthOptions() *HTTPAuthOptions {
	return &HTTPAuthOptions{
		Subject:  nil,
		Tenant:   nil,
		Resource: nil,
		OnDenied: func(w http.ResponseWriter, r *http.Request, decision *authz.Decision) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		},
		OnError: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal error"))
		},
	}
}

// NewHTTPAuthMiddleware returns a net/http middleware (handler wrapper) that uses
// the provided extractors to build Subject, Resource, and Environment and then
// calls Engine.Authorize.
func NewHTTPAuthMiddleware(opts *HTTPAuthOptions) func(next http.Handler) http.Handler {
	if opts == nil {
		opts = DefaultHTTPAuthOptions()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opts.Engine == nil {
				next.ServeHTTP(w, r)
				return
			}
			if opts.Subject == nil || opts.Tenant == nil || opts.Resource == nil {
				if opts.OnError != nil {
					opts.OnError(w, r, fmt.Errorf("middleware misconfigured: Subject, Tenant and Resource extractors are required"))
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("internal error"))
				return
			}

			subID := opts.Subject(r)
			tenant := opts.Tenant(r)
			if tenant == "" {
				tenant = ""
			}
			sub := &authz.Subject{ID: subID, TenantID: tenant, Roles: []string{}}
			env := &authz.Environment{Time: time.Now(), TenantID: tenant}

			res := opts.Resource(r)
			if res == nil {
				if opts.OnError != nil {
					opts.OnError(w, r, fmt.Errorf("middleware misconfigured: Resource extractor returned nil"))
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("internal error"))
				return
			}
			// ensure sensible defaults
			if res.TenantID == "" {
				res.TenantID = tenant
			}
			if res.Type == "" {
				res.Type = "route"
			}
			if res.ID == "" {
				res.ID = r.Method + ":" + r.URL.Path
			}

			dec, err := opts.Engine.Authorize(r.Context(), sub, authz.Action(r.Method), res, env)
			if err != nil {
				if opts.OnError != nil {
					opts.OnError(w, r, err)
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("internal error"))
				return
			}

			// attach decision to request context using library helper
			ctx := authz.ContextWithDecision(r.Context(), dec)
			r = r.WithContext(ctx)

			if dec.Allowed {
				next.ServeHTTP(w, r)
				return
			}
			if opts.OnDenied != nil {
				opts.OnDenied(w, r, dec)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		})
	}
}
