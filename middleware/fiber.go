package middleware

/*
import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/authz"
)

// FiberConfig holds Fiber-specific middleware configuration.
type FiberConfig struct {
	// Engine is the authorization engine to use. Required.
	Engine *authz.Engine

	// Subject extracts the subject from the Fiber context.
	// If nil, uses FiberDefaultSubjectExtractor.
	Subject func(c fiber.Ctx) *authz.Subject

	// Resource extracts the resource from the Fiber context.
	// If nil, uses FiberDefaultResourceExtractor.
	Resource func(c fiber.Ctx) *authz.Resource

	// Environment extracts the environment from the Fiber context.
	// If nil, uses FiberDefaultEnvironmentExtractor.
	Environment func(c fiber.Ctx) *authz.Environment

	// OnDenied handles denied responses.
	// If nil, returns 403 Forbidden with JSON body.
	OnDenied func(c fiber.Ctx, decision *authz.Decision) error

	// OnError handles authorization errors.
	// If nil, returns 500 Internal Server Error with JSON body.
	OnError func(c fiber.Ctx, err error) error

	// Next defines a function to skip middleware.
	// If nil, all requests are processed.
	Next func(c fiber.Ctx) bool

	// SkipPaths is a list of paths to skip authorization for.
	SkipPaths []string
}

// FiberDefaultSubjectExtractor extracts subject info from Fiber context headers.
func FiberDefaultSubjectExtractor(c fiber.Ctx) *authz.Subject {
	return &authz.Subject{
		ID:       c.Get("X-Subject-ID"),
		TenantID: c.Get("X-Tenant-ID"),
		Roles:    splitTrim(c.Get("X-Roles"), ","),
	}
}

// FiberDefaultResourceExtractor uses the HTTP method and path as the resource.
func FiberDefaultResourceExtractor(c fiber.Ctx) *authz.Resource {
	tenant := c.Get("X-Tenant-ID")
	return &authz.Resource{
		ID:       c.Method() + ":" + c.Path(),
		Type:     "route",
		TenantID: tenant,
	}
}

// FiberDefaultEnvironmentExtractor creates an environment with the current time and tenant.
func FiberDefaultEnvironmentExtractor(c fiber.Ctx) *authz.Environment {
	return &authz.Environment{
		Time:     time.Now(),
		TenantID: c.Get("X-Tenant-ID"),
	}
}

// FiberDefaultDeniedHandler returns a 403 Forbidden response.
func FiberDefaultDeniedHandler(c fiber.Ctx, decision *authz.Decision) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
		"error":   "forbidden",
		"message": "access denied",
	})
}

// FiberDefaultErrorHandler returns a 500 Internal Server Error response.
func FiberDefaultErrorHandler(c fiber.Ctx, err error) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error":   "internal_error",
		"message": "authorization check failed",
	})
}

// FiberDefaultConfig returns a FiberConfig with sensible defaults.
func FiberDefaultConfig(engine *authz.Engine) FiberConfig {
	return FiberConfig{
		Engine:      engine,
		Subject:     FiberDefaultSubjectExtractor,
		Resource:    FiberDefaultResourceExtractor,
		Environment: FiberDefaultEnvironmentExtractor,
		OnDenied:    FiberDefaultDeniedHandler,
		OnError:     FiberDefaultErrorHandler,
	}
}

// Fiber creates a Fiber middleware for authorization using a minimal config.
func Fiber(engine *authz.Engine) fiber.Handler {
	return FiberWithConfig(FiberDefaultConfig(engine))
}

// FiberWithConfig creates a Fiber middleware with the provided configuration.
func FiberWithConfig(cfg FiberConfig) fiber.Handler {
	// Set defaults
	if cfg.Subject == nil {
		cfg.Subject = FiberDefaultSubjectExtractor
	}
	if cfg.Resource == nil {
		cfg.Resource = FiberDefaultResourceExtractor
	}
	if cfg.Environment == nil {
		cfg.Environment = FiberDefaultEnvironmentExtractor
	}
	if cfg.OnDenied == nil {
		cfg.OnDenied = FiberDefaultDeniedHandler
	}
	if cfg.OnError == nil {
		cfg.OnError = FiberDefaultErrorHandler
	}

	return func(c fiber.Ctx) error {
		// Check Next function
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		// Check skip paths
		if shouldSkipPath(c.Path(), cfg.SkipPaths) {
			return c.Next()
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
		action := authz.Action(c.Method())
		decision, err := cfg.Engine.Authorize(c.RequestCtx(), subject, action, resource, env)
		if err != nil {
			return cfg.OnError(c, err)
		}

		if !decision.Allowed {
			return cfg.OnDenied(c, decision)
		}

		// Store decision in Fiber locals for later retrieval
		c.Locals("authz_decision", decision)

		return c.Next()
	}
}

// FiberParamResourceExtractor returns a resource extractor that uses Fiber route params.
// The paramMap maps param names to resource fields.
// Special keys: "id" -> Resource.ID, "type" -> Resource.Type, "owner" -> Resource.OwnerID
func FiberParamResourceExtractor(paramMap map[string]string) func(c fiber.Ctx) *authz.Resource {
	return func(c fiber.Ctx) *authz.Resource {
		tenant := c.Get("X-Tenant-ID")
		res := &authz.Resource{
			ID:       c.Method() + ":" + c.Path(),
			Type:     "route",
			TenantID: tenant,
			Attrs:    make(map[string]any),
		}

		for urlParam, resField := range paramMap {
			val := c.Params(urlParam)
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

// FiberRoutePatternResource returns a resource extractor that uses the Fiber route pattern.
func FiberRoutePatternResource() func(c fiber.Ctx) *authz.Resource {
	return func(c fiber.Ctx) *authz.Resource {
		tenant := c.Get("X-Tenant-ID")
		return &authz.Resource{
			ID:       c.Method() + ":" + c.Route().Path,
			Type:     "route",
			TenantID: tenant,
		}
	}
}

// FiberResourceFromPath creates a resource extractor that parses resource info from the URL path.
// Format: /{type}/{id}
func FiberResourceFromPath() func(c fiber.Ctx) *authz.Resource {
	return func(c fiber.Ctx) *authz.Resource {
		tenant := c.Get("X-Tenant-ID")
		path := strings.Trim(c.Path(), "/")
		parts := strings.SplitN(path, "/", 3)

		res := &authz.Resource{
			ID:       c.Method() + ":" + c.Path(),
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

// FiberRequireRoles creates a middleware that requires specific roles.
func FiberRequireRoles(engine *authz.Engine, roles ...string) fiber.Handler {
	cfg := FiberDefaultConfig(engine)
	cfg.Resource = func(c fiber.Ctx) *authz.Resource {
		tenant := c.Get("X-Tenant-ID")
		return &authz.Resource{
			ID:       c.Method() + ":" + c.Path(),
			Type:     "route",
			TenantID: tenant,
			Attrs: map[string]any{
				"required_roles": roles,
			},
		}
	}
	return FiberWithConfig(cfg)
}

// FiberDecision retrieves the authorization decision from Fiber locals.
func FiberDecision(c fiber.Ctx) *authz.Decision {
	if decision, ok := c.Locals("authz_decision").(*authz.Decision); ok {
		return decision
	}
	return nil
}

// fiber:context-methods migrated
*/
