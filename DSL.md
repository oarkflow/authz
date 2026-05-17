# AuthZ DSL - Custom Configuration Language

A minimal, high-performance domain-specific language for authz configuration.

## Syntax Overview

```
<directive> <args...> [options...]
```

Large directives can also use block form:

```authz
directive id {
  field value
  list_field [
    value1
    value2
  ]
  nested_field {
    expression
  }
}
```

- Lines starting with `#` are comments
- Inline comments are supported outside quoted strings
- Whitespace-separated arguments
- Quoted strings for values with spaces
- Options use `key:value` format

## Production Strictness

`NewDSLParser()` is strict by default and fails closed. It returns line-numbered errors for malformed syntax instead of silently accepting risky configuration.

Strict parsing rejects:
- Unterminated quotes
- Unknown directive options
- Invalid `allow`/`deny` effects
- Invalid integers and RFC3339 timestamps
- Empty list entries such as `read,`
- Malformed role permissions without `action:resource`
- Unsupported condition syntax

Use `NewPermissiveDSLParser()` or `NewDSLParser().SetStrict(false)` only for legacy compatibility with old best-effort parsing.

The default parser uses zero-copy token strings for low allocation loading. Treat the input `[]byte` passed to `Parse` as immutable after parsing. Use `ParseCopy(data)` when parsing from a mutable/reused buffer, or `NewDSLParser().SetZeroCopy(false)` when every token must be copied independently.

Use `include` to split large configurations:

```authz
include "./tenants.authz"
include "./routes/admin.authz"
```

Includes are resolved relative to the including file when using `ParseFile` or `authz-config`, and cycles are rejected.

## Directives

### tenant
Define a tenant in the hierarchy.

```
tenant <id> <name> [parent:<parent_id>]
```

**Examples:**
```
tenant root "Root Organization"
tenant org1 "Engineering" parent:root
tenant team1 "Backend Team" parent:org1
```

Block form:

```authz
tenant org1 {
  name "Engineering"
  parent root
}
```

### policy
Define an ABAC policy.

```
policy <id> <tenant> <effect> <actions> <resources> <condition> [priority:<n>]
```

**Arguments:**
- `id`: Unique policy identifier
- `tenant`: Tenant ID
- `effect`: `allow` or `deny`
- `actions`: Comma-separated actions or `*`
- `resources`: Comma-separated resource patterns
- `condition`: Expression (see Conditions below)
- `priority`: Optional priority (higher = evaluated first)

**Examples:**
```
policy allow-read org1 allow read document:* subject.type=user priority:10
policy allow-admin org1 allow * * subject.roles@admin,superadmin priority:100
policy deny-sensitive org1 deny read,write document:secret:* subject.clearance=low
policy route-owner org1 allow GET route:GET:/users/* resource.owner_id=subject.id priority:60
policy route-admin org1 allow GET,POST,PUT,DELETE route:* subject.roles@admin priority:90
```

Block form:

```authz
policy allow-admin {
  tenant org1
  effect allow
  priority 100

  actions [
    read
    write
    delete
    share
  ]

  resources [
    document:*
    project:*
    route:*
  ]

  when {
    subject.roles contains any [
      admin
      superadmin
    ]
  }
}
```

### role
Define an RBAC role.

```
role <id> <tenant> <name> <perms> [inherits:<roles>] [owner:<actions>]
```

**Arguments:**
- `id`: Unique role identifier
- `tenant`: Tenant ID
- `name`: Display name (quoted if contains spaces)
- `perms`: Comma-separated `action:resource` pairs
- `inherits`: Optional comma-separated parent role IDs
- `owner`: Optional owner-allowed actions

**Examples:**
```
role admin org1 Administrator *:*
role editor org1 Editor read:document:*,write:document:*
role viewer org1 Viewer read:*
role owner org1 Owner read:* owner:read,write,delete
role lead team1 "Team Lead" *:project:* inherits:editor
role route-admin org1 "Route Admin" GET:route:GET:/admin/*,POST:route:POST:/admin/*
```

Block form:

```authz
role editor {
  tenant org1
  name "Editor"

  permissions [
    read:document:*
    write:document:*
    delete:document:*
  ]
}

role owner {
  tenant org1
  name "Owner"

  permissions {
    read:*
  }

  owner_actions [
    read
    write
    delete
    share
  ]
}
```

### acl
Define a fine-grained access control entry.

```
acl <id> <resource> <subject> <actions> <effect> [expires:<time>]
```

**Arguments:**
- `id`: Unique ACL identifier
- `resource`: Resource ID or pattern
- `subject`: Subject ID (user:id or group:id)
- `actions`: Comma-separated actions
- `effect`: `allow` or `deny`
- `expires`: Optional RFC3339 timestamp

**Examples:**
```
acl acl-1 document:123 user:alice read,write allow
acl acl-2 document:* group:engineering read allow
acl acl-3 document:secret:* user:bob * deny
acl acl-route-public route:GET:/public/info guest GET allow
acl temp-access document:123 user:charlie read allow expires:2024-12-31T23:59:59Z
```

Block form:

```authz
acl acl-route-public {
  resource route:GET:/public/info
  subject guest
  actions [GET]
  effect allow
}
```

### member
Assign a role to a subject.

```
member <subject> <role>
```

**Examples:**
```
member user:alice admin
member user:bob editor
member group:engineering viewer
```

Block forms:

```authz
member user:alice {
  roles [
    admin
    route-admin
  ]
}

members {
  user:bob [editor]
  user:charlie [viewer]
}
```

### engine
Configure engine performance settings.

```
engine <key>=<value>...
```

**Keys:**
- `cache_ttl`: Decision cache TTL in milliseconds
- `attr_ttl`: Attribute cache TTL in milliseconds
- `batch_size`: Audit batch size
- `flush_interval`: Audit flush interval in milliseconds
- `workers`: Number of batch workers

**Example:**
```
engine cache_ttl=5000 attr_ttl=10000 batch_size=128 flush_interval=50 workers=8
```

Block form:

```authz
engine {
  cache_ttl 5000
  attr_ttl 10000
  batch_size 128
  flush_interval 50
  workers 8
}
```

### IAM directives

The DSL can also declare IAM objects for single-source-of-truth configs. Core engine apply still handles tenants, policies, roles, ACLs, and memberships; `ApplyConfigIAM` applies IAM objects when the matching stores are supplied.

```
user <id> <tenant> <email> <name> [status:<status>]
group <id> <tenant> <name> [parent:<group>] [desc:<text>]
scope <id> <tenant> <name> [parent:<scope>] [desc:<text>]
service_account <id> <tenant> <name> [client:<client_id>] [roles:<roles>] [scopes:<scopes>] [status:<status>]
invitation <id> <tenant> <email> <roles> [groups:<groups>] [status:<status>] [invited_by:<user>] [expires:<time>]
api_key <id> <tenant> <user> <prefix> <name> [scopes:<scopes>] [expires:<time>]
boundary <id> <tenant> <name> <actions> <resources>
```

## Conditions

Conditions use a simple expression syntax:

### Equality
```
field=value
```
Example: `subject.type=user`

### Membership
```
field@value1,value2,value3
field contains any [value1, value2, value3]
field has_any [value1, value2, value3]
```
Example: `subject.roles@admin,editor`

### Boolean logic and advanced expressions

Use quotes around conditions that contain spaces:

```
policy p org allow read document:* "(subject.roles@admin,ops || resource.owner_id=subject.id) && subject.attrs.level>=3"
```

Supported advanced forms:

```
field>=value
regex(field,pattern)
cidr(10.0.0.0/8)
time_between(09:00,18:00)
range(field,min,max)
```

### Field References
- `subject.id`, `subject.type`, `subject.roles`, `subject.groups`
- `subject.attrs.key` - Custom attributes
- `resource.id`, `resource.type`, `resource.owner_id`
- `resource.attrs.key` - Custom attributes
- `env.time`, `env.region`

Unsupported condition text is an error in strict mode.

## HTTP Route Permissions

Route permissions use the same `policy`, `role`, and `acl` directives as other resources. The only special convention is the resource pattern.

```
route:<METHOD>:<path-pattern>
```

At request time, the HTTP middleware builds a resource with `Type: "route"` and `ID: "<METHOD>:<actual-path>"`. For a `GET /users/123` request, the checked action is usually `GET` and the resource ID is `GET:/users/123`.

**Examples:**
```
# Owner can GET their own user profile route
policy route-owner org1 allow GET route:GET:/users/* resource.owner_id=subject.id priority:60

# Admin role can manage admin routes
role route-admin org1 "Route Admin" GET:route:GET:/admin/*,POST:route:POST:/admin/*

# Public guest access to one route
acl route-public route:GET:/public/info guest GET allow
```

Use `route:*` for any route, `route:GET:/admin/*` for a method-specific path pattern, and route-pattern resource extractors in framework middleware when you want to authorize framework route templates instead of concrete paths.

## Complete Example

```
# Multi-tenant organization
tenant root "ACME Corporation"
tenant eng "Engineering" parent:root
tenant backend "Backend Team" parent:eng

# Policies
policy allow-users eng allow read,write document:* subject.type=user priority:10
policy allow-admins eng allow * * subject.roles@admin priority:100
policy deny-sensitive eng deny * document:secret:* subject.clearance=low priority:200
policy owner-access eng allow read,write,delete * resource.owner_id=subject.id priority:50
policy route-owner eng allow GET route:GET:/users/* resource.owner_id=subject.id priority:60
policy route-admin-api eng allow GET,POST,PUT,DELETE route:* subject.roles@admin priority:90

# Roles
role admin eng Administrator *:*
role editor eng Editor read:document:*,write:document:*,delete:document:*
role viewer eng Viewer read:*
role owner eng Owner read:* owner:read,write,delete,share
role team-lead backend "Team Lead" *:project:* inherits:editor
role route-admin eng "Route Admin" GET:route:GET:/admin/*,POST:route:POST:/admin/*

# ACLs
acl temp-alice document:123 user:alice read,write allow expires:2024-12-31T23:59:59Z
acl group-eng document:* group:engineering read allow
acl deny-bob document:secret:* user:bob * deny
acl route-public route:GET:/public/info guest GET allow

# Memberships
member user:alice admin
member user:bob editor
member user:charlie viewer
member user:dave team-lead

# Engine config
engine cache_ttl=5000 attr_ttl=10000 batch_size=128 workers=8
```

## Validation, Linting, And Apply Modes

Use the CLI before shipping a DSL file:

```bash
go run ./cmd/authz-config validate examples/config.authz
go run ./cmd/authz-config plan examples/config.authz --sync
go run ./cmd/authz-config apply examples/config.authz --sync --dry-run
go run ./cmd/authz-config fmt examples/config.authz
go run ./cmd/authz-config plan examples/config.authz --sync --sqlite ./authz.db
```

`validate` performs strict parsing plus semantic validation. It rejects duplicate IDs, missing tenant references, missing inherited roles, missing membership roles, invalid effects, empty actions/resources, nil policy conditions, and tenant hierarchy cycles.

`LintConfig` reports warnings that may be valid but risky, such as `*:*`, `route:*`, unused roles, tenants with no rules, and ACL subjects that do not look namespaced.

Apply modes:
- `ApplyConfig` keeps the existing additive upsert behavior.
- `PlanConfigApply` and `ApplyConfigPlan` support dry-run planning.
- `ApplyModeSync` reconciles policies, roles, ACLs, and tenants by deleting stale objects that are not present in the file.
- Role memberships are exactly reconciled when the store implements `EnumerableRoleMembershipStore`; otherwise they are assigned additively with a warning.

Signing:

```bash
go run ./cmd/authz-config sign-keygen
go run ./cmd/authz-config sign config.authz <private-key> config.signed.authz
go run ./cmd/authz-config verify config.signed.authz <public-key>
```

## Binary Protocol

The DSL can be compiled to a compact binary format for production use.

### Protocol Structure

```
Header (8 bytes):
  Magic:    0x415A4332 (4 bytes) - "AZC2"
  Version:  2 (2 bytes)
  Config:   (2 bytes)

Sections:
  Tag:  1 byte
  Size: 4 bytes (uint32)
  Data: variable

Tags:
  1: Tenants
  2: Policies
  3: Roles
  4: ACLs
  5: Memberships
  6: Engine
  7: Hierarchy
```

### Encoding

```go
parser := authz.NewDSLParser()
cfg, _ := parser.Parse(dslData)

encoder := authz.NewBinaryEncoder()
binary, _ := encoder.Encode(cfg)
```

### Decoding

```go
decoder := authz.NewBinaryDecoder(binaryData)
cfg, _ := decoder.Decode()
```

## Usage

### Load from DSL

```go
package main

import (
    "context"
    "os"
    
    "github.com/oarkflow/authz"
    "github.com/oarkflow/authz/stores"
)

func main() {
    // Parse DSL
    data, _ := os.ReadFile("config.authz")
    parser := authz.NewDSLParser()
    cfg, _ := parser.Parse(data)
    
    // Create engine
    engine := authz.NewEngine(
        stores.NewMemoryPolicyStore(),
        stores.NewMemoryRoleStore(),
        stores.NewMemoryACLStore(),
        stores.NewMemoryAuditStore(),
    )
    
    // Apply configuration
    ctx := context.Background()
    engine.ApplyConfig(ctx, cfg)
}
```

### Convert to Binary

```go
// Parse DSL
parser := authz.NewDSLParser()
cfg, _ := parser.Parse(dslData)

// Encode to binary
encoder := authz.NewBinaryEncoder()
binary, _ := encoder.Encode(cfg)

// Save binary
os.WriteFile("config.bin", binary, 0644)

// Load binary
binaryData, _ := os.ReadFile("config.bin")
decoder := authz.NewBinaryDecoder(binaryData)
cfg, _ := decoder.Decode()
```

## Performance

### DSL vs Binary

| Metric | DSL | Binary | Improvement |
|--------|-----|--------|-------------|
| Size | 100% | 35% | 2.8x smaller |
| Parse | 100% | 15% | 6.7x faster |
| Memory | 100% | 40% | 2.5x less |

### Benchmarks

```
BenchmarkDSLParse-8        50000    25000 ns/op    8192 B/op    120 allocs/op
BenchmarkBinaryDecode-8   300000     3800 ns/op    3200 B/op     45 allocs/op
```

## Best Practices

1. **Use Comments**: Document complex policies
2. **Consistent Naming**: Use prefixes (user:, group:, document:)
3. **Priority Order**: Higher priority for deny policies
4. **Binary for Prod**: Use DSL for dev, binary for production
5. **Version Control**: Store DSL files in git
6. **Validate**: Test configs before deployment

## Migration

### From YAML

Before:
```yaml
policies:
  - id: allow-read
    tenant_id: org1
    effect: allow
    actions: [read]
    resources: ["document:*"]
```

After:
```
policy allow-read org1 allow read document:* subject.type=user
```

### From Code

Before:
```go
policy := authz.NewPolicyBuilder().
    ID("p1").
    Actions("read").
    Build()
```

After:
```
policy p1 org1 allow read * subject.type=user
```

## Error Handling

Parse errors include line numbers:

```
line 5: policy requires: <id> <tenant> <effect> <actions> <resources> <condition>
line 12: unknown directive: invalid
```

## Production Extensions

The DSL includes the production features expected for managed authorization configuration: strict parsing, semantic validation, lint diagnostics, includes, canonical formatting, dry-run/sync planning, SQLite-backed diffing, config signing, schema migration hooks, first-class IAM entity directives, route permissions, and a richer condition grammar. For domain-specific predicates beyond the built-in grammar, add a typed `Expr` implementation and expose it through the condition parser.
