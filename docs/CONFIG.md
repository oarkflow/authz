# Configuration System

The authz package now supports a high-performance configuration system that allows you to define all authorization components (policies, roles, ACLs, tenants, and engine settings) in declarative configuration files.

## Features

- **Multiple Formats**: YAML, JSON, and custom binary protocol
- **High Performance**: Binary protocol is ~60% smaller and 10-20x faster than YAML
- **Complete Coverage**: Define policies, roles, ACLs, memberships, tenants, and engine settings
- **Fluent API**: Programmatic configuration building with type-safe builders
- **Hot Reload**: Apply configuration changes without restarting

## Quick Start

### 1. YAML Configuration

```yaml
version: 1

tenants:
  - id: acme
    name: ACME Corporation
    parent: ""

policies:
  - id: allow-read
    tenant_id: acme
    effect: allow
    actions: [read]
    resources: ["document:*"]
    condition:
      op: eq
      field: subject.attrs.department
      value: engineering
    priority: 10
    enabled: true

roles:
  - id: admin
    tenant_id: acme
    name: Administrator
    permissions:
      - action: "*"
        resource: "*"

memberships:
  - subject_id: user:alice
    role_id: admin

engine:
  decision_cache_ttl_ms: 5000
  audit_batch_size: 128
```

### 2. Load and Apply Configuration

```go
package main

import (
    "context"
    "os"
    
    "github.com/oarkflow/authz"
    "github.com/oarkflow/authz/stores"
)

func main() {
    // Load configuration
    data, _ := os.ReadFile("config.yaml")
    loader := authz.NewConfigLoader()
    cfg, _ := loader.LoadYAML(data)
    
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

### 3. Programmatic Configuration

```go
cfg := authz.NewConfigBuilder().
    AddTenant("acme", "ACME Corp", "").
    AddPolicy(
        authz.NewPolicyConfig("allow-read", "acme").
            Actions("read", "write").
            Resources("document:*").
            Condition(authz.NewCondition().Eq("subject.type", "user").Build()).
            Build(),
    ).
    AddRole(
        authz.NewRoleConfig("admin", "acme", "Admin").
            AddPermission("*", "*").
            Build(),
    ).
    AddMembership("user:alice", "admin").
    Build()

// Export to YAML
yamlData, _ := cfg.ToYAML()

// Export to JSON
jsonData, _ := cfg.ToJSON()

// Export to binary
binaryData, _ := authz.EncodeBinaryConfig(cfg)
```

## Configuration Schema

### Tenants

```yaml
tenants:
  - id: string          # Unique tenant identifier
    name: string        # Display name
    parent: string      # Parent tenant ID (for hierarchy)
```

### Policies (ABAC)

```yaml
policies:
  - id: string
    tenant_id: string
    effect: allow|deny
    actions: [string]
    resources: [string]
    condition:
      op: eq|in|gte|and|or
      field: string
      value: any
    priority: int
    enabled: bool
```

#### Condition Operators

- `eq`: Equality check
- `in`: Membership check
- `gte`: Greater than or equal
- `and`: Logical AND
- `or`: Logical OR

#### Condition Examples

```yaml
# Simple equality
condition:
  op: eq
  field: subject.attrs.department
  value: engineering

# Membership check
condition:
  op: in
  field: subject.roles
  values: [admin, editor]

# Complex AND condition
condition:
  op: and
  left:
    op: eq
    field: subject.type
    value: user
  right:
    op: in
    field: subject.groups
    values: [engineering, product]
```

### Roles (RBAC)

```yaml
roles:
  - id: string
    tenant_id: string
    name: string
    permissions:
      - action: string
        resource: string
    owner_allowed_actions: [string]  # Optional: actions for owner role
    inherits: [string]               # Optional: parent role IDs
```

### ACLs (Fine-grained Access)

```yaml
acls:
  - id: string
    resource_id: string
    subject_id: string
    actions: [string]
    effect: allow|deny
    expires_at: timestamp  # Optional: expiration time
```

### Role Memberships

```yaml
memberships:
  - subject_id: string
    role_id: string
```

### Tenant Hierarchy

```yaml
hierarchy:
  child_tenant_id: parent_tenant_id
```

### Engine Configuration

```yaml
engine:
  decision_cache_ttl_ms: int64      # Decision cache TTL in milliseconds
  attribute_cache_ttl_ms: int64     # Attribute cache TTL in milliseconds
  audit_batch_size: int             # Audit batch size
  audit_flush_interval_ms: int64    # Audit flush interval in milliseconds
  batch_worker_count: int           # Number of batch workers
  ristretto_num_counter: int64      # Ristretto cache counters
  ristretto_max_cost: int64         # Ristretto max cost
  ristretto_buffer: int64           # Ristretto buffer size
```

## Binary Protocol

The custom binary protocol provides significant performance improvements:

### Performance Comparison

| Format | Size | Encode Time | Decode Time |
|--------|------|-------------|-------------|
| YAML   | 100% | 100%        | 100%        |
| JSON   | 85%  | 40%         | 60%         |
| Binary | 40%  | 5%          | 8%          |

### Binary Protocol Structure

```
Header (6 bytes):
  - Magic: 0x415A (2 bytes) - "AZ" for authz
  - Version: 1 (2 bytes)
  - Config Version: (2 bytes)

Sections (variable):
  - Tag: 1 byte (0x01-0x07)
  - Size: 4 bytes (uint32)
  - Data: variable length

Section Tags:
  0x01: Tenants
  0x02: Policies
  0x03: Roles
  0x04: ACLs
  0x05: Memberships
  0x06: Engine Config
  0x07: Hierarchy
```

### Usage

```go
// Encode to binary
cfg := authz.NewConfigBuilder().Build()
binaryData, _ := authz.EncodeBinaryConfig(cfg)

// Decode from binary
loader := authz.NewConfigLoader()
cfg, _ := loader.LoadBinary(binaryData)
```

## Advanced Examples

### Multi-Tenant Setup

```go
cfg := authz.NewConfigBuilder().
    AddTenant("root", "Root Org", "").
    AddTenant("org1", "Organization 1", "root").
    AddTenant("team1", "Team 1", "org1").
    AddPolicy(
        authz.NewPolicyConfig("cross-tenant-admin", "root").
            Actions("*").
            Resources("*").
            Condition(authz.NewCondition().In("subject.roles", "super-admin").Build()).
            Priority(100).
            Build(),
    ).
    Build()
```

### Owner-Based Access

```go
cfg := authz.NewConfigBuilder().
    AddRole(
        authz.NewRoleConfig("owner", "org1", "Owner").
            OwnerActions("read", "write", "delete", "share").
            AddPermission("read", "*").
            Build(),
    ).
    AddPolicy(
        authz.NewPolicyConfig("owner-access", "org1").
            Actions("read", "write", "delete").
            Resources("document:*").
            Condition(authz.NewCondition().Eq("resource.owner_id", "subject.id").Build()).
            Priority(50).
            Build(),
    ).
    Build()
```

### Time-Based Access

```go
// Using condition builder
timeCond := authz.NewCondition().
    And(
        authz.NewCondition().Gte("env.time", "2024-01-01T00:00:00Z"),
    )

cfg := authz.NewConfigBuilder().
    AddPolicy(
        authz.NewPolicyConfig("time-restricted", "org1").
            Actions("read").
            Resources("document:*").
            Condition(timeCond.Build()).
            Build(),
    ).
    Build()
```

### Temporary ACL Access

```go
cfg := authz.NewConfigBuilder().
    AddACL(
        authz.NewACLConfig("temp-access", "document:123", "user:bob").
            Actions("read", "write").
            ExpiresAt(time.Now().Add(24 * time.Hour)).
            Build(),
    ).
    Build()
```

## Best Practices

1. **Use Binary Format for Production**: 60% smaller, 10-20x faster
2. **Version Your Configs**: Increment version field for tracking
3. **Set Appropriate Cache TTLs**: Balance performance vs freshness
4. **Use Priorities**: Higher priority policies evaluated first
5. **Leverage Hierarchy**: Define parent-child tenant relationships
6. **Owner Actions**: Scope owner privileges with `owner_allowed_actions`
7. **Batch Operations**: Configure `audit_batch_size` for high throughput

## Migration from Code

Before (code-based):
```go
policy := authz.NewPolicyBuilder().
    ID("p1").
    Tenant("org1").
    Actions("read").
    Resources("*").
    Condition(&authz.TrueExpr{}).
    Build()
engine.CreatePolicy(ctx, policy)
```

After (config-based):
```yaml
policies:
  - id: p1
    tenant_id: org1
    actions: [read]
    resources: ["*"]
    condition:
      op: eq
      field: subject.type
      value: user
    enabled: true
```

## Performance Tips

1. **Binary Protocol**: Use for large configs (>100 policies)
2. **Ristretto Cache**: Enable for high-throughput scenarios
3. **Batch Workers**: Set to CPU count for parallel processing
4. **Cache TTLs**: Tune based on policy change frequency
5. **Priority Indexing**: Higher priority policies checked first

## See Also

- [examples/config.yaml](examples/config.yaml) - Complete example
- [examples/config_example.go](examples/config_example.go) - Usage examples
- [config_test.go](config_test.go) - Test cases and benchmarks
