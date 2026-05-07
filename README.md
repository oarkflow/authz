# authz

`authz` is an embeddable Go authorization and identity-management toolkit. It combines policy-based authorization, RBAC, ACLs, tenant hierarchy, route-aware HTTP authorization, admin APIs, in-memory and SQL stores, authentication helpers, audit logging, policy bundles, and optional OpenTelemetry instrumentation.

The package is centered around `Engine.Authorize(ctx, subject, action, resource, env)`. Everything else either feeds the engine with policy data, adapts HTTP requests into authorization checks, or manages the users, roles, groups, scopes, sessions, events, and stores around those checks.

## Capabilities

- ABAC policies with allow/deny effects, priorities, expressions, policy validation, simulation, history, and signed bundles.
- RBAC roles with permissions, inheritance, role memberships, cross-tenant admin checks, and owner-scoped actions.
- ACL entries for resource-specific grants and denials, including expiry support.
- HTTP route permissions using `route:<METHOD>:<path-pattern>` resources.
- Middleware for `net/http`, `chi`, `echo`, and `fiber`.
- Tenant hierarchy and owner authorization across descendant tenants.
- Decision caching, optional Ristretto cache, attribute caching, batch authorization, and audit batching.
- Admin HTTP control plane for tenants, policies, roles, ACLs, memberships, explain, and batch checks.
- Extended admin surface for users, groups, scopes, service accounts, invitations, webhooks, events, effective permissions, and auth flows.
- Password hashing, HMAC JWT access/refresh tokens, sessions, TOTP, API keys, and login lockout tracking.
- Memory and SQL store implementations with embedded SQL migrations.
- Custom `.authz` DSL and binary config format for fast static configuration loading.
- OpenTelemetry metrics/tracing and pluggable logging/trace IDs.

## Install

```bash
go get github.com/oarkflow/authz
```

The project currently targets Go `1.25.5` as declared in `go.mod`.

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func main() {
	ctx := context.Background()

	policies := stores.NewMemoryPolicyStore()
	roles := stores.NewMemoryRoleStore()
	acls := stores.NewMemoryACLStore()
	audit := stores.NewMemoryAuditStore()
	members := stores.NewMemoryRoleMembershipStore()

	engine := authz.NewEngine(
		policies,
		roles,
		acls,
		audit,
		authz.WithRoleMembershipStore(members),
	)

	_ = engine.CreatePolicy(ctx, &authz.Policy{
		ID:        "owner-docs",
		TenantID:  "tenant-1",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"read", "write"},
		Resources: []string{"document:*"},
		Condition: &authz.EqExpr{Field: "resource.owner_id", Value: "subject.id"},
		Priority:  10,
		Enabled:   true,
	})

	subject := &authz.Subject{ID: "user:alice", Type: "user", TenantID: "tenant-1"}
	resource := &authz.Resource{ID: "doc-123", Type: "document", TenantID: "tenant-1", OwnerID: "user:alice"}
	env := &authz.Environment{Time: time.Now(), TenantID: "tenant-1"}

	decision, _ := engine.Authorize(ctx, subject, "read", resource, env)
	fmt.Println(decision.Allowed)
}
```

## Authorization Model

`Subject` is the caller. It contains `ID`, `Type`, `TenantID`, `Roles`, `Groups`, and custom `Attrs`.

`Action` is the operation being attempted. Actions can be exact values like `read`, HTTP methods like `GET`, or suffix-wildcard patterns in permissions such as `document.*`.

`Resource` is the target. Generic resources are evaluated as `type:id`, for example a resource with `Type: "document"` and `ID: "123"` matches `document:*`. HTTP route resources use `Type: "route"` and an ID shaped as `<METHOD>:<path>`.

`Environment` carries request context such as time, IP, tenant, region, and extra values.

`Decision` returns `Allowed`, `Reason`, `MatchedBy`, `Trace`, and `Timestamp`. Use `Engine.Explain` when you need the trace populated for diagnostics or admin UI flows.

## Evaluation Semantics

The engine evaluates explicit denials before grants. Deny policies and deny ACLs take precedence over allows. Allows may come from policies, ACLs, RBAC permissions, owner rules, or cross-tenant admin status.

Policies are tenant-scoped and priority ordered. Higher priority policies are evaluated first. `Enabled` policies participate in checks; disabled policies are ignored.

RBAC permissions are defined on roles as `Action` plus `Resource`. Role inheritance is recursive and cycle-protected. Role membership can be supplied directly on `Subject.Roles` and through a configured `RoleMembershipStore`.

ACLs target a specific resource ID or pattern and a specific subject ID, such as `user:alice`, `group:engineering`, or `guest`.

Tenant owner checks support two paths:

- `subject.Attrs["is_tenant_owner"] = true` grants owner-style access. If `subject.Attrs["owner_allowed_actions"]` is present, it limits owner access to those action names or wildcard patterns.
- `Role.OwnerAllowedActions` limits what a role-level owner may do across descendant tenants. Patterns use the same suffix-wildcard behavior as regular actions.

## HTTP Route Permissions

HTTP route authorization uses the normal engine model with a route-specific resource convention:

- Middleware builds the requested resource as `&authz.Resource{Type: "route", ID: "<METHOD>:<path>", TenantID: tenant}`.
- Policies, roles, and ACLs match it with resources like `route:GET:/users/*` or `route:*`.
- The checked action is usually the HTTP method, for example `authz.Action("GET")`.

`.authz` example:

```authz
policy route-owner-profile org1 allow GET route:GET:/users/* resource.owner_id=subject.id priority:60
policy route-admin-api org1 allow GET,POST,PUT,DELETE route:* subject.roles@admin,superadmin priority:90

role route-admin org1 "Route Administrator" GET:route:GET:/admin/*,POST:route:POST:/admin/*
acl acl-route-public route:GET:/public/info guest GET allow
member user:erin route-admin
```

Go example:

```go
allowed, decision, err := engine.Can(ctx, subject, "GET", "/users/123", env)
_ = allowed
_ = decision
_ = err
```

For owner routes, set `Resource.OwnerID` in a custom resource extractor. The framework middleware packages include default route resource extractors and helpers for route patterns or route params where the framework supports them.

## Middleware

Use `github.com/oarkflow/authz/middleware` for reusable HTTP adapters.

Default `net/http` setup:

```go
mw := middleware.HTTPFunc(engine,
	middleware.WithSkipPaths("/healthz", "/public/**"),
)

handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	decision := authz.DecisionFromRequest(r)
	_ = decision
	w.WriteHeader(http.StatusOK)
}))
```

The default extractors read:

- Subject ID from `X-Subject-ID`.
- Tenant ID from `X-Tenant-ID`.
- Roles from comma-separated `X-Roles`.
- Resource from `r.Method + ":" + r.URL.Path` with `Type: "route"`.
- Environment from current time and `X-Tenant-ID`.

Framework adapters are available for:

- `middleware.NewHTTP` and `middleware.HTTPFunc` for `net/http`.
- `middleware.Chi` helpers for chi, including route-pattern resources.
- `middleware.Echo` helpers for Echo.
- `middleware.Fiber` helpers for Fiber.

## DSL Configuration

Static configuration can be loaded from `.authz` files:

```go
data, _ := os.ReadFile("examples/config.authz")
cfg, _ := authz.NewDSLParser().Parse(data)
_ = engine.ApplyConfig(ctx, cfg)
```

Supported directives:

```authz
tenant <id> <name> [parent:<parent_id>]
policy <id> <tenant> <effect> <actions> <resources> <condition> [priority:<n>]
role <id> <tenant> <name> <perms> [inherits:<roles>] [owner:<actions>]
acl <id> <resource> <subject> <actions> <effect> [expires:<time>]
member <subject> <role>
engine cache_ttl=<ms> attr_ttl=<ms> batch_size=<n> flush_interval=<ms> workers=<n>
```

The parser supports quoted strings, comments, comma-separated actions/resources, role permissions as `action:resource`, and route resources with additional colons such as `GET:route:GET:/admin/*`.

See [DSL.md](./DSL.md), [DSL_QUICKSTART.md](./DSL_QUICKSTART.md), and [examples/config.authz](./examples/config.authz).

## Admin HTTP API

Embed the base admin server when you need a control plane:

```go
admin := authz.NewAdminHTTPServer(engine, authz.WithAdminAuth(func(r *http.Request) error {
	return nil
}))
go admin.Start(":8081")
```

Base endpoints:

- `GET /healthz`
- `GET /tenants`
- `POST /tenants`
- `GET|POST /tenants/{tenant}/policies`
- `GET|PUT|DELETE /tenants/{tenant}/policies/{id}`
- `POST /tenants/{tenant}/policies/{id}/enable`
- `POST /tenants/{tenant}/policies/{id}/disable`
- `GET|POST /tenants/{tenant}/roles`
- `GET|PUT|DELETE /tenants/{tenant}/roles/{id}`
- `GET|POST /tenants/{tenant}/acls`
- `GET|PUT|DELETE /tenants/{tenant}/acls/{id}`
- `GET|POST /tenants/{tenant}/members/{subject}/roles`
- `DELETE /tenants/{tenant}/members/{subject}/roles/{role}`
- `POST /tenants/{tenant}/explain`
- `POST /tenants/{tenant}/batch`

The extended admin server adds IAM and operational endpoints when their stores are configured:

- `/auth/login`, `/auth/refresh`, `/auth/logout`
- `/tenants/{tenant}/users`
- `/tenants/{tenant}/groups`
- `/tenants/{tenant}/groups/{group}/members`
- `/tenants/{tenant}/groups/{group}/roles`
- `/tenants/{tenant}/scopes`
- `/tenants/{tenant}/service-accounts`
- `/tenants/{tenant}/invitations`
- `/tenants/{tenant}/webhooks`
- `/tenants/{tenant}/events`
- `/tenants/{tenant}/effective-permissions`

## Stores

The `stores` package provides memory stores for development and tests plus SQL stores for persistent deployments.

Core stores:

- Policy, role, ACL, audit, role membership, and tenant stores.
- User, session, API key, group, scope, service account, invitation, event, and webhook stores.

SQL setup:

```go
db := /* create *squealx.DB */
_ = stores.Migrate(db)

policyStore := stores.NewSQLPolicyStore(db)
roleStore := stores.NewSQLRoleStore(db)
aclStore := stores.NewSQLACLStore(db)
auditStore, _ := stores.NewSQLAuditStore(db)
```

`stores.Migrate` runs the embedded `stores/sql_migrations.sql` file. SQL ACL and role-membership stores maintain refreshed snapshots for faster read paths.

## Authentication And IAM Helpers

`authn.go` includes:

- `HashPassword` and `CheckPassword` using bcrypt.
- `TokenConfig` for HMAC-SHA256 JWT access and refresh token generation/validation.
- `Session` and `SessionStore`.
- `TOTPConfig` for RFC 6238-style one-time codes.
- `APIKey`, `APIKeyStore`, key generation, prefix lookup, and last-used tracking.
- `LoginTracker` for lockout after repeated failed login attempts.

IAM model additions include:

- `User` with status, email, profile fields, MFA fields, and custom attributes.
- `Group` plus group membership and group-role stores.
- `Scope` and role-scope mappings.
- `ServiceAccount` with client IDs/secrets, scopes, expiration, and last-used tracking.
- `Invitation` lifecycle with pending, accepted, expired, and revoked states.
- `PermissionResolver` for effective permissions from roles, ACLs, policies, and optional permission boundaries.

## Policy Bundles

`PolicyBundleDistributor` signs policy bundles with Ed25519 keys and pushes tenant-specific bundles to subscribers:

```go
dist, _ := authz.NewPolicyBundleDistributor(policyStore)
dist.RegisterSubscriber("tenant-1", authz.BundleSubscriberFunc(func(ctx context.Context, tenant string, pub ed25519.PublicKey, bundle *authz.SignedPolicyBundle) error {
	return remoteEngine.ApplySignedBundle(ctx, pub, bundle)
}))
dist.Start(context.Background())

engine.SetBundleDistributor(dist)
```

Use this for multi-engine deployments where policy changes need to propagate without process restarts.

## Observability

Use `WithLogger` and `WithTraceIDFunc` to plug in application logging and trace IDs.

Use `WithOpenTelemetry` to enable metrics/tracing instrumentation. `Engine.GetCacheStats()` returns decision-cache statistics when cache instrumentation is enabled.

Audit entries include subject, action, resource, decision, trace, and metadata. Use `GetAccessLog` for retrieval and `ReplayDecision` for replaying previous decisions.

## Testing And Benchmarks

```bash
go test ./...
go test -bench=. -benchmem -benchtime=2s -run=^$
go test -run=TestDSLFromFile
```

Example programs live under `examples/`, including DSL loading, standard HTTP middleware, and framework-specific middleware demos.
