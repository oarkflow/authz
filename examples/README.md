# Examples

Every example here is a standalone, runnable Go program (`package main` with a real
`func main()`), each in its own subdirectory. Run any of them with:

```bash
go run ./<directory>
```

from inside this `examples/` directory (it has its own `go.mod` with a `replace`
directive pointing at the parent module, so it always builds against the local
`authz` source tree, not a published version).

## Core engine

- [`quickstart/`](./quickstart) — the smallest possible setup: one policy, one
  `Engine.Authorize` call.
- [`config/`](./config) — loading a full engine configuration (policies, roles,
  ACLs) from `.authz` DSL and comparing DSL/JSON/binary encoding performance.
- [`dsl-basics/`](./dsl-basics) — parsing `.authz` files, DSL vs JSON vs binary
  round-tripping and timing.
- [`dsl-hardening/`](./dsl-hardening) — the `>`/`<` comparison operators and the
  `include` directive's path-traversal jail (`SetIncludeRoot`,
  `AllowAbsoluteIncludes`).
- [`rbac-abac-tenant/`](./rbac-abac-tenant) — RBAC roles, ABAC policies, and
  tenant-scoped authorization together, plus policy history.
- [`tenant-namespaces/`](./tenant-namespaces) — tenant hierarchies, cross-tenant
  admin access, and scoped ABAC policies within a tenant subtree.
- [`dynamic-management/`](./dynamic-management) — managing tenants, policies,
  roles, and ACLs at runtime through the admin HTTP API.

## HTTP integration

- [`http-middleware/`](./http-middleware) — a `net/http` authorization
  middleware built on `Engine.Authorize`.
- [`fiber-middleware/`](./fiber-middleware) — the same idea wired into a Fiber
  app, including a real listening server.

## Admin API & operations

- [`admin-api-hardening/`](./admin-api-hardening) — the admin server's
  fail-closed authentication (`ErrAdminAuthNotConfigured`,
  `WithAdminAuthDisabled`) and its automatic default rate limiter.
- [`bundle-distributor-redis/`](./bundle-distributor-redis) — propagating
  signed policy bundles across engine replicas with
  `contrib/redistransport`'s Redis pub/sub transport. Requires a local Redis
  (`docker run -p 6379:6379 redis`); the example explains what to expect if
  one isn't running.

## Compliance & enterprise access patterns

- [`audit-tamper-evidence/`](./audit-tamper-evidence) — the hash-chained audit
  trail: `Engine.VerifyAuditChain` detecting tampering and deletion.
- [`gdpr-erasure/`](./gdpr-erasure) — `authz.EraseSubjectData` removing a
  subject's data across every store while preserving audit-chain integrity.
- [`delegation-breakglass/`](./delegation-breakglass) — time-boxed delegation
  grants (with the anti-amplification guarantee) and break-glass emergency
  access.
- [`rebac/`](./rebac) — the relationship-tuple (Zanzibar-style) allow-path,
  including group/subject-set indirection.

## Requirements

All examples use in-memory stores and need no external services, **except**
`bundle-distributor-redis`, which needs a reachable Redis instance (it will
tell you how to start one and what it does instead if none is found).
