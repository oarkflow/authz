package middleware

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/oarkflow/authz"
)

// Chi creates a chi middleware for authorization.
func Chi(cfg *Config) func(next http.Handler) http.Handler {
	return NewHTTP(cfg)
}

// ChiFunc creates a chi middleware using functional options.
func ChiFunc(engine *authz.Engine, opts ...func(*Config)) func(next http.Handler) http.Handler {
	return HTTPFunc(engine, opts...)
}

// ChiURLParamExtractor returns a resource extractor that uses chi URL params.
// The paramMap maps URL param names to resource fields.
// Special keys: "id" -> Resource.ID, "type" -> Resource.Type, "owner" -> Resource.OwnerID
func ChiURLParamExtractor(paramMap map[string]string) ResourceExtractor {
	return func(r *http.Request) *authz.Resource {
		tenant := r.Header.Get("X-Tenant-ID")
		res := &authz.Resource{
			ID:       r.Method + ":" + r.URL.Path,
			Type:     "route",
			TenantID: tenant,
			Attrs:    make(map[string]any),
		}

		for urlParam, resField := range paramMap {
			val := chi.URLParam(r, urlParam)
			if val == "" {
				continue
			}
			switch resField {
			case "id":
				res.ID = val
			case "type":
				res.Type = val
			case "owner":
				res.OwnerID = val
			case "tenant":
				res.TenantID = val
			default:
				res.Attrs[resField] = val
			}
		}

		return res
	}
}

// ChiRoutePatternResource returns a resource extractor that uses the chi route pattern
// instead of the actual path, which is useful for wildcard routes.
func ChiRoutePatternResource() ResourceExtractor {
	return func(r *http.Request) *authz.Resource {
		tenant := r.Header.Get("X-Tenant-ID")
		routePattern := chi.RouteContext(r.Context()).RoutePattern()
		if routePattern == "" {
			routePattern = r.URL.Path
		}
		return &authz.Resource{
			ID:       r.Method + ":" + routePattern,
			Type:     "route",
			TenantID: tenant,
		}
	}
}

// ChiGroup returns a middleware that requires specific roles for all routes in the group.
func ChiGroup(engine *authz.Engine, requiredRoles ...string) func(next http.Handler) http.Handler {
	cfg := DefaultConfig(engine)
	cfg.Subject = func(r *http.Request) *authz.Subject {
		sub := DefaultSubjectExtractor(r)
		// For role-based group access, we check if user has any of the required roles
		return sub
	}
	cfg.Resource = func(r *http.Request) *authz.Resource {
		tenant := r.Header.Get("X-Tenant-ID")
		routePattern := chi.RouteContext(r.Context()).RoutePattern()
		if routePattern == "" {
			routePattern = r.URL.Path
		}
		return &authz.Resource{
			ID:       r.Method + ":" + routePattern,
			Type:     "route",
			TenantID: tenant,
			Attrs: map[string]any{
				"required_roles": requiredRoles,
			},
		}
	}
	return NewHTTP(cfg)
}

// ChiResourceFromPath creates a resource extractor that parses resource info from the URL path.
// Format: /{type}/{id}
func ChiResourceFromPath() ResourceExtractor {
	return func(r *http.Request) *authz.Resource {
		tenant := r.Header.Get("X-Tenant-ID")
		path := strings.Trim(r.URL.Path, "/")
		parts := strings.SplitN(path, "/", 3)

		res := &authz.Resource{
			ID:       r.Method + ":" + r.URL.Path,
			Type:     "route",
			TenantID: tenant,
		}

		if len(parts) >= 1 && parts[0] != "" {
			res.Type = parts[0]
		}
		if len(parts) >= 2 && parts[1] != "" {
			res.ID = parts[1]
		}

		return res
	}
}
