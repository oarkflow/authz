# Modernization & Optimization TODOs

## Modern Feature Enhancements
- [x] Policy bundle distribution service with signature rotation to push signed updates to engines without restarts, extending the `SignedPolicyBundle` helpers in `authz.go`. (see `bundle_distributor.go`, engine hooks)
- [x] Batch decision API (e.g., `Engine.BatchAuthorize`) to evaluate many subject/action/resource tuples in one pass, reducing network chattiness for UI permission matrices. (worker pool + /tenants/{id}/batch endpoint)
- [x] Delegated admin surface (HTTP) for tenant-scoped role + policy management to complement existing builder APIs in `builders.go`. (implemented admin HTTP server)
- [x] Decision explanation endpoint that reuses `Decision.Trace` to provide human-friendly narratives for UI tooling. (admin HTTP `/tenants/{id}/explain`)

## Performance Optimizations
- [x] Compile-and-cache parsed conditions so `ParseCondition` runs once per policy version instead of per evaluation path in `authz.go` (cached in SQL policy store).
- [x] Index policies by action/resource prefix to avoid scanning every policy on hot paths; leverage `ristretto` cache already imported in `authz.go` (PolicyIndex prefix map + candidate cache).
- [x] Warm subject role memberships and ACL lookups via background refreshers in `stores/memory_stores.go` and SQL stores to reduce mutex contention (snapshots w/ background refresh).
- [x] Add configurable batching for audit writes so `AuditStore.LogDecision` can flush asynchronously instead of per-request (batched audit worker + option).

## Observability & DX Enhancements
- [ ] Ship OpenTelemetry metrics/traces (decision latency, cache hit ratio) gated behind an engine option.
- [ ] Create conformance tests (and CI workflow) covering memory + SQL stores to prevent regressions when adding indexes.
- [ ] Publish reusable middleware packages (Fiber, chi, Echo) under `examples/` with shared helpers for request-to-subject translation.
- [ ] Provide a CLI (`authzctl`) for seeding policies/roles and inspecting cache state for troubleshooting.
