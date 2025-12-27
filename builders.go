package authz

import "time"

// Builders provide a fluent API for creating Policies, Roles and ACLs

// PolicyBuilder builds a Policy
type PolicyBuilder struct {
	p *Policy
}

func NewPolicyBuilder() *PolicyBuilder {
	return &PolicyBuilder{p: &Policy{Actions: []Action{}, Resources: []string{}, Enabled: true, Priority: 0}}
}

func (b *PolicyBuilder) ID(id string) *PolicyBuilder    { b.p.ID = id; return b }
func (b *PolicyBuilder) Tenant(t string) *PolicyBuilder { b.p.TenantID = t; return b }
func (b *PolicyBuilder) Effect(e Effect) *PolicyBuilder { b.p.Effect = e; return b }
func (b *PolicyBuilder) Actions(a ...Action) *PolicyBuilder {
	b.p.Actions = append(b.p.Actions, a...)
	return b
}
func (b *PolicyBuilder) Resources(r ...string) *PolicyBuilder {
	b.p.Resources = append(b.p.Resources, r...)
	return b
}
func (b *PolicyBuilder) Condition(expr Expr) *PolicyBuilder  { b.p.Condition = expr; return b }
func (b *PolicyBuilder) Priority(p int) *PolicyBuilder       { b.p.Priority = p; return b }
func (b *PolicyBuilder) Enabled(enabled bool) *PolicyBuilder { b.p.Enabled = enabled; return b }
func (b *PolicyBuilder) Build() *Policy                      { return b.p }

// RoleBuilder builds a Role
type RoleBuilder struct {
	r *Role
}

func NewRoleBuilder() *RoleBuilder {
	return &RoleBuilder{r: &Role{Permissions: []Permission{}, Inherits: []string{}}}
}
func (b *RoleBuilder) ID(id string) *RoleBuilder    { b.r.ID = id; return b }
func (b *RoleBuilder) Tenant(t string) *RoleBuilder { b.r.TenantID = t; return b }
func (b *RoleBuilder) Name(n string) *RoleBuilder   { b.r.Name = n; return b }
func (b *RoleBuilder) Permission(action Action, resource string) *RoleBuilder {
	b.r.Permissions = append(b.r.Permissions, Permission{Action: action, Resource: resource})
	return b
}
func (b *RoleBuilder) OwnerAllowedActions(a ...Action) *RoleBuilder {
	b.r.OwnerAllowedActions = append(b.r.OwnerAllowedActions, a...)
	return b
}
func (b *RoleBuilder) Inherits(ids ...string) *RoleBuilder {
	b.r.Inherits = append(b.r.Inherits, ids...)
	return b
}
func (b *RoleBuilder) Build() *Role { return b.r }

// ACLBuilder builds an ACL
type ACLBuilder struct {
	acl *ACL
}

func NewACLBuilder() *ACLBuilder                             { return &ACLBuilder{acl: &ACL{Actions: []Action{}}} }
func (b *ACLBuilder) ID(id string) *ACLBuilder               { b.acl.ID = id; return b }
func (b *ACLBuilder) Resource(resourceID string) *ACLBuilder { b.acl.ResourceID = resourceID; return b }
func (b *ACLBuilder) Subject(subjectID string) *ACLBuilder   { b.acl.SubjectID = subjectID; return b }
func (b *ACLBuilder) Actions(a ...Action) *ACLBuilder {
	b.acl.Actions = append(b.acl.Actions, a...)
	return b
}
func (b *ACLBuilder) Effect(e Effect) *ACLBuilder       { b.acl.Effect = e; return b }
func (b *ACLBuilder) ExpiresAt(t time.Time) *ACLBuilder { b.acl.ExpiresAt = t; return b }
func (b *ACLBuilder) Build() *ACL                       { return b.acl }
