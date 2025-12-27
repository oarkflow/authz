# authz — Authorization Engine (ABAC/RBAC/ACL)

## Owner action scoping

- Role.OwnerAllowedActions ([]Action)
  - Optional field on a `Role` that declares which actions the role-level owner may perform across descendant tenants.
  - Supports action patterns using the same suffix-wildcard semantics as regular actions (e.g., `"document.*"` matches `"document.read"`, `"document.delete"`).
  - If `OwnerAllowedActions` is present on one or more owner roles for the subject, at least one owner role must explicitly allow the requested action for owner-based access to be granted.

- Subject attribute `owner_allowed_actions`
  - A subject can be marked as an owner with `subject.Attrs["is_tenant_owner"] = true`.
  - If present, `subject.Attrs["owner_allowed_actions"]` may be a `[]string`, `[]authz.Action`, or `[]any` representing action names or patterns.
  - Patterns are matched using the same suffix-wildcard rule (e.g., `"document.*"`).
  - If the attribute is present, it is enforced; if not present, attribute-based owners retain the previous fallback behavior (full owner rights).

Precedence and semantics
- Attribute-based owner checks are evaluated first. If attribute-based owner exists and defines `owner_allowed_actions`, that list is enforced.
- Role-based owner roles are checked next; `Role.OwnerAllowedActions` (if defined) is checked before role `Permissions`.
- Cross-tenant admins and existing RBAC/ACL/ABAC rules still apply as before.

This document provides a brief summary; see the inline comments in `authz.go` for exact behavior and examples in `examples/main.go`.
