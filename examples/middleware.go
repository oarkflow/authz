package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/authz"
)

// FiberAuthOptions configures the behavior of the Fiber authorization middleware.
type FiberAuthOptions struct {
	Engine *authz.Engine
	// Subject extracts the subject ID from the request (required)
	Subject func(c *fiber.Ctx) string
	// Tenant extracts the tenant ID from the request (required)
	Tenant func(c *fiber.Ctx) string
	// Resource extracts a fully-populated Resource from the request (required)
	Resource func(c *fiber.Ctx) *authz.Resource
	// OnDenied allows customizing the response when authorization fails
	OnDenied func(c *fiber.Ctx, decision *authz.Decision) error
	// OnError allows customizing error handling
	OnError func(c *fiber.Ctx, err error) error
}

// DefaultFiberAuthOptions returns a default options struct.
func DefaultFiberAuthOptions() *FiberAuthOptions {
	return &FiberAuthOptions{
		Subject: nil, // caller must provide
		Tenant:  nil, // caller must provide
		OnDenied: func(c *fiber.Ctx, decision *authz.Decision) error {
			return c.Status(http.StatusForbidden).SendString("forbidden")
		},
		OnError: func(c *fiber.Ctx, err error) error {
			return c.Status(http.StatusInternalServerError).SendString("internal error")
		},
	}
}

// NewFiberAuthMiddleware returns a Fiber Handler that performs authorization
// using the Engine. It is configurable via FiberAuthOptions.
func NewFiberAuthMiddleware(opts *FiberAuthOptions) fiber.Handler {
	if opts == nil {
		opts = DefaultFiberAuthOptions()
	}
	return func(c *fiber.Ctx) error {
		if opts.Engine == nil {
			return c.Next()
		}
		// Build subject using configured extractors
		if opts.Subject == nil || opts.Tenant == nil {
			if opts.OnError != nil {
				_ = opts.OnError(c, fmt.Errorf("middleware misconfigured: Subject and Tenant extractors are required"))
				return nil
			}
			return c.Status(http.StatusInternalServerError).SendString("internal error")
		}
		subID := opts.Subject(c)
		tenant := opts.Tenant(c)
		if tenant == "" {
			tenant = ""
		}
		// Roles are intentionally not extracted by the middleware; the Engine may populate them
		sub := &authz.Subject{ID: subID, TenantID: tenant, Roles: []string{}}

		// Build env
		env := &authz.Environment{Time: time.Now(), TenantID: tenant}

		// Build resource using the configured extractor (middleware uses no hard-coded owner logic)
		res := opts.Resource(c)
		if res == nil {
			if opts.OnError != nil {
				_ = opts.OnError(c, fmt.Errorf("middleware misconfigured: Resource extractor returned nil"))
				return nil
			}
			return c.Status(http.StatusInternalServerError).SendString("internal error")
		}
		// Ensure tenant and basic fields are set sensibly if extractor omitted them
		if res.TenantID == "" {
			res.TenantID = tenant
		}
		if res.Type == "" {
			res.Type = "route"
		}
		if res.ID == "" {
			res.ID = c.Method() + ":" + c.Path()
		}

		// Perform check using Authorize so we can include resource.OwnerID in the evaluation
		dec, err := opts.Engine.Authorize(context.Background(), sub, authz.Action(c.Method()), res, env)
		if err != nil {
			if opts.OnError != nil {
				return opts.OnError(c, err)
			}
			return c.Status(http.StatusInternalServerError).SendString("error")
		}
		allowed := dec.Allowed
		// Attach decision to context locals for handlers to use
		c.Locals("authz_decision", dec)
		if allowed {
			return c.Next()
		}
		if opts.OnDenied != nil {
			return opts.OnDenied(c, dec)
		}
		return c.Status(http.StatusForbidden).SendString("forbidden")
	}
}
