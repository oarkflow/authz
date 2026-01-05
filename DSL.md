# AuthZ DSL - Custom Configuration Language

A minimal, high-performance domain-specific language for authz configuration.

## Syntax Overview

```
<directive> <args...> [options...]
```

- Lines starting with `#` are comments
- Whitespace-separated arguments
- Quoted strings for values with spaces
- Options use `key:value` format

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
acl temp-access document:123 user:charlie read allow expires:2024-12-31T23:59:59Z
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
```
Example: `subject.roles@admin,editor`

### Field References
- `subject.id`, `subject.type`, `subject.roles`, `subject.groups`
- `subject.attrs.key` - Custom attributes
- `resource.id`, `resource.type`, `resource.owner_id`
- `resource.attrs.key` - Custom attributes
- `env.time`, `env.region`

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

# Roles
role admin eng Administrator *:*
role editor eng Editor read:document:*,write:document:*,delete:document:*
role viewer eng Viewer read:*
role owner eng Owner read:* owner:read,write,delete,share
role team-lead backend "Team Lead" *:project:* inherits:editor

# ACLs
acl temp-alice document:123 user:alice read,write allow expires:2024-12-31T23:59:59Z
acl group-eng document:* group:engineering read allow
acl deny-bob document:secret:* user:bob * deny

# Memberships
member user:alice admin
member user:bob editor
member user:charlie viewer
member user:dave team-lead

# Engine config
engine cache_ttl=5000 attr_ttl=10000 batch_size=128 workers=8
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

## Extensions

The DSL is designed to be minimal. For complex conditions, use the programmatic API or extend the condition parser.
