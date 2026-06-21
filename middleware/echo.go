package middleware

/*
import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/oarkflow/authz"
)

// EchoConfig holds Echo-specific middleware configuration.
type EchoConfig struct {
	// Engine is the authorization engine to use. Required.
	Engine *authz.Engine

	// Subject extracts the subject from the Echo context.
	// If nil, uses EchoDefaultSubjectExtractor.
	Subject func(c echo.Context) *authz.Subject

	// Resource extracts the resource from the Echo context.
	// If nil, uses EchoDefaultResourceExtractor.
	Resource func(c echo.Context) *authz.Resource

	// Environment extracts the environment from the Echo context.
	// If nil, uses EchoDefaultEnvironmentExtractor.
	Environment func(c echo.Context) *authz.Environment

	// OnDenied handles denied responses.
	// If nil, returns 403 Forbidden with JSON body.
	OnDenied func(c echo.Context, decision *authz.Decision) error

	// OnError handles authorization errors.
	// If nil, returns 500 Internal Server Error with JSON body.
	OnError func(c echo.Context, err error) error

	// Skipper defines a function to skip middleware.
	// If nil, all requests are processed.
	Skipper func(c echo.Context) bool

	// SkipPaths is a list of paths to skip authorization for.
	SkipPaths []string
}

// EchoDefaultSubjectExtractor extracts subject info from Echo context headers.
func EchoDefaultSubjectExtractor(c echo.Context) *authz.Subject {
	return &authz.Subject{
		ID:       c.Request().Header.Get("X-Subject-ID"),
		TenantID: c.Request().Header.Get("X-Tenant-ID"),
		Roles:    splitTrim(c.Request().Header.Get("X-Roles"), ","),
	}
}

// EchoDefaultResourceExtractor uses the HTTP method and path as the resource.
func EchoDefaultResourceExtractor(c echo.Context) *authz.Resource {
	tenant := c.Request().Header.Get("X-Tenant-ID")
	return &authz.Resource{
		ID:       c.Request().Method + ":" + c.Path(),
		Type:     "route",
		TenantID: tenant,
	}
}

// EchoDefaultEnvironmentExtractor creates an environment with the current time and tenant.
func EchoDefaultEnvironmentExtractor(c echo.Context) *authz.Environment {
	return &authz.Environment{
		Time:     time.Now(),
		TenantID: c.Request().Header.Get("X-Tenant-ID"),
		IP:       nil, // Could parse from c.RealIP()
	}
}

// EchoDefaultDeniedHandler returns a 403 Forbidden response.
func EchoDefaultDeniedHandler(c echo.Context, decision *authz.Decision) error {
	return c.JSON(http.StatusForbidden, map[string]string{
		"error":   "forbidden",
		"message": "access denied",
	})
}

// EchoDefaultErrorHandler returns a 500 Internal Server Error response.
func EchoDefaultErrorHandler(c echo.Context, err error) error {
	return c.JSON(http.StatusInternalServerError, map[string]string{
		"error":   "internal_error",
		"message": "authorization check failed",
	})
}

// EchoDefaultConfig returns an EchoConfig with sensible defaults.
func EchoDefaultConfig(engine *authz.Engine) EchoConfig {
	return EchoConfig{
		Engine:      engine,
		Subject:     EchoDefaultSubjectExtractor,
		Resource:    EchoDefaultResourceExtractor,
		Environment: EchoDefaultEnvironmentExtractor,
		OnDenied:    EchoDefaultDeniedHandler,
		OnError:     EchoDefaultErrorHandler,
	}
}

// Echo creates an Echo middleware for authorization using a minimal config.
func Echo(engine *authz.Engine) echo.MiddlewareFunc {
	return EchoWithConfig(EchoDefaultConfig(engine))
}

// EchoWithConfig creates an Echo middleware with the provided configuration.
func EchoWithConfig(cfg EchoConfig) echo.MiddlewareFunc {
	// Set defaults
	if cfg.Subject == nil {
		cfg.Subject = EchoDefaultSubjectExtractor
	}
	if cfg.Resource == nil {
		cfg.Resource = EchoDefaultResourceExtractor
	}
	if cfg.Environment == nil {
		cfg.Environment = EchoDefaultEnvironmentExtractor
	}
	if cfg.OnDenied == nil {
		cfg.OnDenied = EchoDefaultDeniedHandler
	}
	if cfg.OnError == nil {
		cfg.OnError = EchoDefaultErrorHandler
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Check skipper
			if cfg.Skipper != nil && cfg.Skipper(c) {
				return next(c)
			}

			// Check skip paths
			if shouldSkipPath(c.Request().URL.Path, cfg.SkipPaths) {
				return next(c)
			}

			// Validate engine
			if cfg.Engine == nil {
				return cfg.OnError(c, ErrMissingEngine)
			}

			// Extract authorization parameters
			subject := cfg.Subject(c)
			resource := cfg.Resource(c)
			env := cfg.Environment(c)

			// Perform authorization
			action := authz.Action(c.Request().Method)
			decision, err := cfg.Engine.Authorize(c.Request().Context(), subject, action, resource, env)
			if err != nil {
				return cfg.OnError(c, err)
			}

			if !decision.Allowed {
				return cfg.OnDenied(c, decision)
			}

			// Attach decision to request context
			ctx := authz.ContextWithDecision(c.Request().Context(), decision)
			c.SetRequest(c.Request().WithContext(ctx))

			return next(c)
		}
	}
}

// EchoParamResourceExtractor returns a resource extractor that uses Echo route params.
// The paramMap maps param names to resource fields.
// Special keys: "id" -> Resource.ID, "type" -> Resource.Type, "owner" -> Resource.OwnerID
func EchoParamResourceExtractor(paramMap map[string]string) func(c echo.Context) *authz.Resource {
	return func(c echo.Context) *authz.Resource {
		tenant := c.Request().Header.Get("X-Tenant-ID")
		res := &authz.Resource{
			ID:       c.Request().Method + ":" + c.Path(),
			Type:     "route",
			TenantID: tenant,
			Attrs:    make(map[string]any),
		}

		for urlParam, resField := range paramMap {
			val := c.Param(urlParam)
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

// EchoRoutePatternResource returns a resource extractor that uses the Echo route pattern.
func EchoRoutePatternResource() func(c echo.Context) *authz.Resource {
	return func(c echo.Context) *authz.Resource {
		tenant := c.Request().Header.Get("X-Tenant-ID")
		return &authz.Resource{
			ID:       c.Request().Method + ":" + c.Path(),
			Type:     "route",
			TenantID: tenant,
		}
	}
}

// EchoResourceFromPath creates a resource extractor that parses resource info from the URL path.
// Format: /{type}/{id}
func EchoResourceFromPath() func(c echo.Context) *authz.Resource {
	return func(c echo.Context) *authz.Resource {
		tenant := c.Request().Header.Get("X-Tenant-ID")
		path := strings.Trim(c.Request().URL.Path, "/")
		parts := strings.SplitN(path, "/", 3)

		res := &authz.Resource{
			ID:       c.Request().Method + ":" + c.Request().URL.Path,
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

// EchoRequireRoles creates a middleware that requires specific roles.
func EchoRequireRoles(engine *authz.Engine, roles ...string) echo.MiddlewareFunc {
	cfg := EchoDefaultConfig(engine)
	cfg.Resource = func(c echo.Context) *authz.Resource {
		tenant := c.Request().Header.Get("X-Tenant-ID")
		return &authz.Resource{
			ID:       c.Request().Method + ":" + c.Path(),
			Type:     "route",
			TenantID: tenant,
			Attrs: map[string]any{
				"required_roles": roles,
			},
		}
	}
	return EchoWithConfig(cfg)
}
*/
