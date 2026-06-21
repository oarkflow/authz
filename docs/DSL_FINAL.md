# Production-Hardened `.authz` DSL

The `.authz` DSL is now intended for production bootstrap and controlled declarative configuration workflows. The grammar remains intentionally small, but parsing and validation are fail-closed by default.

## Current Syntax

```authz
tenant <id> <name> [parent:<parent_id>]
policy <id> <tenant> <effect> <actions> <resources> <condition> [priority:<n>]
role <id> <tenant> <name> <perms> [inherits:<roles>] [owner:<actions>]
acl <id> <resource> <subject> <actions> <effect> [expires:<time>]
member <subject> <role>
user <id> <tenant> <email> <name> [status:<status>]
group <id> <tenant> <name> [parent:<group>] [desc:<text>]
scope <id> <tenant> <name> [parent:<scope>] [desc:<text>]
service_account <id> <tenant> <name> [client:<client_id>] [roles:<roles>] [scopes:<scopes>] [status:<status>]
invitation <id> <tenant> <email> <roles> [groups:<groups>] [status:<status>] [invited_by:<user>] [expires:<time>]
api_key <id> <tenant> <user> <prefix> <name> [scopes:<scopes>] [expires:<time>]
boundary <id> <tenant> <name> <actions> <resources>
engine cache_ttl=<ms> attr_ttl=<ms> batch_size=<n> flush_interval=<ms> workers=<n>
```

Large configs can use `include "./other.authz"`. Includes resolve relative to the including file and cycles are rejected.

Route permissions use normal resources:

```authz
policy route-owner org1 allow GET route:GET:/users/* resource.owner_id=subject.id priority:60
role route-admin org1 "Route Admin" GET:route:GET:/admin/*,POST:route:POST:/admin/*
acl route-public route:GET:/public/info guest GET allow
```

## Strict Parsing

`authz.NewDSLParser()` is strict by default. It rejects:

- Unterminated quotes
- Unknown options
- Invalid `allow`/`deny` effects
- Invalid integers and timestamps
- Empty list entries
- Malformed `action:resource` role permissions
- Unsupported condition syntax

Use `authz.NewPermissiveDSLParser()` or `authz.NewDSLParser().SetStrict(false)` only for legacy compatibility.

`authz.NewDSLParser()` uses zero-copy token strings by default. Treat the input byte slice passed to `Parse` as immutable after parsing. Use `ParseCopy(data)` for mutable buffers, or `SetZeroCopy(false)` to copy each token.

Supported conditions include simple predicates, boolean logic, comparisons, and advanced helpers:

```authz
true
subject.type=user
subject.attrs.clearance!=high
subject.roles@admin,superadmin
(subject.roles@admin,ops || resource.owner_id=subject.id) && subject.attrs.level>=3
regex(subject.id,^user:)
cidr(10.0.0.0/8)
time_between(09:00,18:00)
range(subject.attrs.score,1,10)
```

## Validation And Linting

`authz.ValidateConfig(cfg)` returns blocking semantic errors for duplicate IDs, missing tenant references, missing inherited roles, missing membership roles, empty policy/ACL actions or resources, invalid effects, nil policy conditions, and tenant hierarchy cycles.

`authz.LintConfig(cfg)` returns warnings for risky but valid configuration, including broad grants such as `*:*` and `route:*`, unused roles, tenants with no rules, and unusual ACL subjects.

CLI:

```bash
go run ./cmd/authz-config validate examples/config.authz
```

## Apply Planning

`ApplyConfig` remains additive/upsert-only for compatibility.

Declarative workflows should use:

```go
plan, err := engine.PlanConfigApply(ctx, cfg, authz.ConfigApplyOptions{
	Mode:   authz.ApplyModeSync,
	DryRun: true,
})
err = engine.ApplyConfigPlan(ctx, plan)
```

Sync mode reconciles policies, roles, ACLs, tenants, and role memberships when the store implements `EnumerableRoleMembershipStore`.

IAM objects are parsed into `Config` and applied through `ApplyConfigIAM` when matching stores are supplied.

CLI:

```bash
go run ./cmd/authz-config plan examples/config.authz --sync
go run ./cmd/authz-config apply examples/config.authz --sync --dry-run
go run ./cmd/authz-config plan examples/config.authz --sync --sqlite ./authz.db
go run ./cmd/authz-config fmt examples/config.authz
go run ./cmd/authz-config sign-keygen
go run ./cmd/authz-config sign config.authz <private-key> config.signed.authz
go run ./cmd/authz-config verify config.signed.authz <public-key>
```

## Verification

Primary checks:

```bash
GOCACHE=$PWD/.gocache go test ./...
GOCACHE=$PWD/.gocache go run ./cmd/authz-config validate examples/config.authz
GOCACHE=$PWD/.gocache go run ./cmd/authz-config plan examples/config.authz --sync
GOCACHE=$PWD/.gocache go run ./cmd/authz-config fmt examples/config.authz
```

The test suite covers strict parser failures, inline comments, permissive parser compatibility, includes with cycle detection, rich condition parsing, first-class IAM directives, config signing, semantic validation, lint warnings, dry-run/sync apply planning, and HTTP route permissions loaded from `examples/config.authz`.
