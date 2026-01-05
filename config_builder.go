package authz

import (
	"encoding/json"
	"time"
)

// ConfigBuilder provides fluent API for building configurations
type ConfigBuilder struct {
	cfg *Config
}

func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		cfg: &Config{
			Version:     1,
			Tenants:     []TenantConfig{},
			Policies:    []*Policy{},
			Roles:       []*Role{},
			ACLs:        []*ACL{},
			Memberships: []RoleMembership{},
			Hierarchy:   make(map[string]string),
			Engine: EngineConfig{
				DecisionCacheTTL:   1000,
				AttributeCacheTTL:  5000,
				AuditBatchSize:     64,
				AuditFlushInterval: 25,
				BatchWorkerCount:   4,
			},
		},
	}
}

func (b *ConfigBuilder) Version(v uint16) *ConfigBuilder {
	b.cfg.Version = v
	return b
}

func (b *ConfigBuilder) AddTenant(id, name, parent string) *ConfigBuilder {
	b.cfg.Tenants = append(b.cfg.Tenants, TenantConfig{ID: id, Name: name, Parent: parent})
	if parent != "" {
		b.cfg.Hierarchy[id] = parent
	}
	return b
}

func (b *ConfigBuilder) AddPolicy(p *Policy) *ConfigBuilder {
	b.cfg.Policies = append(b.cfg.Policies, p)
	return b
}

func (b *ConfigBuilder) AddRole(r *Role) *ConfigBuilder {
	b.cfg.Roles = append(b.cfg.Roles, r)
	return b
}

func (b *ConfigBuilder) AddACL(acl *ACL) *ConfigBuilder {
	b.cfg.ACLs = append(b.cfg.ACLs, acl)
	return b
}

func (b *ConfigBuilder) AddMembership(subjectID, roleID string) *ConfigBuilder {
	b.cfg.Memberships = append(b.cfg.Memberships, RoleMembership{SubjectID: subjectID, RoleID: roleID})
	return b
}

func (b *ConfigBuilder) EngineSettings(fn func(*EngineConfig)) *ConfigBuilder {
	fn(&b.cfg.Engine)
	return b
}

func (b *ConfigBuilder) Build() *Config {
	return b.cfg
}

func (b *ConfigBuilder) ToYAML() ([]byte, error) {
	return b.cfg.ToYAML()
}

func (b *ConfigBuilder) ToJSON() ([]byte, error) {
	return b.cfg.ToJSON()
}

// ConditionBuilder for building condition expressions in config
type ConditionBuilder struct {
	expr map[string]any
}

func NewCondition() *ConditionBuilder {
	return &ConditionBuilder{expr: make(map[string]any)}
}

func (c *ConditionBuilder) Eq(field string, value any) *ConditionBuilder {
	c.expr = map[string]any{"op": "eq", "field": field, "value": value}
	return c
}

func (c *ConditionBuilder) In(field string, values ...any) *ConditionBuilder {
	c.expr = map[string]any{"op": "in", "field": field, "values": values}
	return c
}

func (c *ConditionBuilder) Gte(field string, value any) *ConditionBuilder {
	c.expr = map[string]any{"op": "gte", "field": field, "value": value}
	return c
}

func (c *ConditionBuilder) And(other *ConditionBuilder) *ConditionBuilder {
	c.expr = map[string]any{"op": "and", "left": c.expr, "right": other.expr}
	return c
}

func (c *ConditionBuilder) Or(other *ConditionBuilder) *ConditionBuilder {
	c.expr = map[string]any{"op": "or", "left": c.expr, "right": other.expr}
	return c
}

func (c *ConditionBuilder) Build() Expr {
	return parseExprMap(c.expr)
}

func (c *ConditionBuilder) ToJSON() string {
	data, _ := json.Marshal(c.expr)
	return string(data)
}

// PolicyConfigBuilder for building policies in config
type PolicyConfigBuilder struct {
	p *Policy
}

func NewPolicyConfig(id, tenantID string) *PolicyConfigBuilder {
	return &PolicyConfigBuilder{
		p: &Policy{
			ID:        id,
			TenantID:  tenantID,
			Actions:   []Action{},
			Resources: []string{},
			Effect:    EffectAllow,
			Enabled:   true,
			Priority:  0,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
}

func (p *PolicyConfigBuilder) Effect(e Effect) *PolicyConfigBuilder {
	p.p.Effect = e
	return p
}

func (p *PolicyConfigBuilder) Actions(actions ...string) *PolicyConfigBuilder {
	for _, a := range actions {
		p.p.Actions = append(p.p.Actions, Action(a))
	}
	return p
}

func (p *PolicyConfigBuilder) Resources(resources ...string) *PolicyConfigBuilder {
	p.p.Resources = append(p.p.Resources, resources...)
	return p
}

func (p *PolicyConfigBuilder) Condition(cond Expr) *PolicyConfigBuilder {
	p.p.Condition = cond
	return p
}

func (p *PolicyConfigBuilder) Priority(pri int) *PolicyConfigBuilder {
	p.p.Priority = pri
	return p
}

func (p *PolicyConfigBuilder) Build() *Policy {
	if p.p.Condition == nil {
		p.p.Condition = &TrueExpr{}
	}
	return p.p
}

// RoleConfigBuilder for building roles in config
type RoleConfigBuilder struct {
	r *Role
}

func NewRoleConfig(id, tenantID, name string) *RoleConfigBuilder {
	return &RoleConfigBuilder{
		r: &Role{
			ID:                  id,
			TenantID:            tenantID,
			Name:                name,
			Permissions:         []Permission{},
			OwnerAllowedActions: []Action{},
			Inherits:            []string{},
			CreatedAt:           time.Now(),
		},
	}
}

func (r *RoleConfigBuilder) AddPermission(action, resource string) *RoleConfigBuilder {
	r.r.Permissions = append(r.r.Permissions, Permission{Action: Action(action), Resource: resource})
	return r
}

func (r *RoleConfigBuilder) OwnerActions(actions ...string) *RoleConfigBuilder {
	for _, a := range actions {
		r.r.OwnerAllowedActions = append(r.r.OwnerAllowedActions, Action(a))
	}
	return r
}

func (r *RoleConfigBuilder) Inherits(roleIDs ...string) *RoleConfigBuilder {
	r.r.Inherits = append(r.r.Inherits, roleIDs...)
	return r
}

func (r *RoleConfigBuilder) Build() *Role {
	return r.r
}

// ACLConfigBuilder for building ACLs in config
type ACLConfigBuilder struct {
	acl *ACL
}

func NewACLConfig(id, resourceID, subjectID string) *ACLConfigBuilder {
	return &ACLConfigBuilder{
		acl: &ACL{
			ID:         id,
			ResourceID: resourceID,
			SubjectID:  subjectID,
			Actions:    []Action{},
			Effect:     EffectAllow,
			CreatedAt:  time.Now(),
		},
	}
}

func (a *ACLConfigBuilder) Actions(actions ...string) *ACLConfigBuilder {
	for _, act := range actions {
		a.acl.Actions = append(a.acl.Actions, Action(act))
	}
	return a
}

func (a *ACLConfigBuilder) Effect(e Effect) *ACLConfigBuilder {
	a.acl.Effect = e
	return a
}

func (a *ACLConfigBuilder) ExpiresAt(t time.Time) *ACLConfigBuilder {
	a.acl.ExpiresAt = t
	return a
}

func (a *ACLConfigBuilder) Build() *ACL {
	return a.acl
}
