package authz

import (
	"context"
	"fmt"
	"reflect"
)

type ApplyMode string

const (
	ApplyModeUpsert ApplyMode = "upsert"
	ApplyModeSync   ApplyMode = "sync"
)

type ConfigApplyOptions struct {
	Mode      ApplyMode
	DryRun    bool
	TenantIDs []string
}

type ConfigApplyOperation struct {
	Action     string `json:"action"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	TenantID   string `json:"tenant_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type ConfigApplyPlan struct {
	Config      *Config                `json:"-"`
	Options     ConfigApplyOptions     `json:"options"`
	Operations  []ConfigApplyOperation `json:"operations"`
	Diagnostics []ConfigDiagnostic     `json:"diagnostics,omitempty"`
}

func (e *Engine) PlanConfigApply(ctx context.Context, cfg *Config, opts ConfigApplyOptions) (*ConfigApplyPlan, error) {
	if opts.Mode == "" {
		opts.Mode = ApplyModeUpsert
	}
	if opts.Mode != ApplyModeUpsert && opts.Mode != ApplyModeSync {
		return nil, fmt.Errorf("unsupported apply mode: %s", opts.Mode)
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}

	plan := &ConfigApplyPlan{
		Config:      cfg,
		Options:     opts,
		Diagnostics: LintConfig(cfg),
	}
	pendingTenantDeletes := make([]ConfigApplyOperation, 0)

	tenantFilter := make(map[string]bool, len(opts.TenantIDs))
	for _, tenantID := range opts.TenantIDs {
		tenantFilter[tenantID] = true
	}
	syncTenantIDs := make(map[string]bool)
	syncTenantIDs[""] = true
	for _, tenant := range cfg.Tenants {
		syncTenantIDs[tenant.ID] = true
	}
	inScope := func(tenantID string) bool {
		return len(tenantFilter) == 0 || tenantID == "" || tenantFilter[tenantID]
	}

	if e.tenantStore == nil {
		if len(cfg.Tenants) > 0 {
			plan.Diagnostics = append(plan.Diagnostics, diag("warning", "tenant_store_not_configured", "tenant create/update/delete planning is skipped because tenant store is not configured", "tenant", ""))
		}
	} else {
		desiredTenants := make(map[string]TenantConfig, len(cfg.Tenants))
		for _, tenant := range cfg.Tenants {
			if !inScope(tenant.ID) {
				continue
			}
			desiredTenants[tenant.ID] = tenant
			existing, err := e.tenantStore.GetTenant(ctx, tenant.ID)
			if err != nil || existing == nil {
				plan.add("create", "tenant", tenant.ID, tenant.ID, "not present in store")
			} else if !tenantConfigEqualTenant(tenant, existing) {
				plan.add("update", "tenant", tenant.ID, tenant.ID, "differs from store")
			}
		}
		if opts.Mode == ApplyModeSync {
			existingTenants, err := e.tenantStore.ListTenants(ctx)
			if err != nil {
				return nil, fmt.Errorf("list tenants: %w", err)
			}
			for _, tenant := range existingTenants {
				if tenant == nil || !inScope(tenant.ID) {
					continue
				}
				syncTenantIDs[tenant.ID] = true
				if _, ok := desiredTenants[tenant.ID]; !ok {
					pendingTenantDeletes = append(pendingTenantDeletes, ConfigApplyOperation{Action: "delete", EntityType: "tenant", EntityID: tenant.ID, TenantID: tenant.ID, Reason: "not present in config"})
				}
			}
		}
	}

	desiredPolicies := make(map[string]*Policy, len(cfg.Policies))
	for _, policy := range cfg.Policies {
		if !inScope(policy.TenantID) {
			continue
		}
		desiredPolicies[policy.ID] = policy
		existing, err := e.policyStore.GetPolicy(ctx, policy.ID)
		if err != nil || existing == nil {
			plan.add("create", "policy", policy.ID, policy.TenantID, "not present in store")
		} else if !policyEquivalent(policy, existing) {
			plan.add("update", "policy", policy.ID, policy.TenantID, "differs from store")
		}
	}
	if opts.Mode == ApplyModeSync {
		existingPolicies, err := e.policyStore.ListPolicies(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("list policies: %w", err)
		}
		for _, policy := range existingPolicies {
			if policy == nil || !inScope(policy.TenantID) {
				continue
			}
			if _, ok := desiredPolicies[policy.ID]; !ok {
				plan.add("delete", "policy", policy.ID, policy.TenantID, "not present in config")
			}
		}
	}

	desiredRoles := make(map[string]*Role, len(cfg.Roles))
	for _, role := range cfg.Roles {
		if !inScope(role.TenantID) {
			continue
		}
		desiredRoles[role.ID] = role
		existing, err := e.roleStore.GetRole(ctx, role.ID)
		if err != nil || existing == nil {
			plan.add("create", "role", role.ID, role.TenantID, "not present in store")
		} else if !roleEquivalent(role, existing) {
			plan.add("update", "role", role.ID, role.TenantID, "differs from store")
		}
	}
	if opts.Mode == ApplyModeSync {
		seenExistingRoles := make(map[string]bool)
		for tenantID := range syncTenantIDs {
			existingRoles, err := e.roleStore.ListRoles(ctx, tenantID)
			if err != nil {
				return nil, fmt.Errorf("list roles: %w", err)
			}
			for _, role := range existingRoles {
				if role == nil || seenExistingRoles[role.ID] || !inScope(role.TenantID) {
					continue
				}
				seenExistingRoles[role.ID] = true
				if _, ok := desiredRoles[role.ID]; !ok {
					plan.add("delete", "role", role.ID, role.TenantID, "not present in config")
				}
			}
		}
	}

	desiredACLs := make(map[string]*ACL, len(cfg.ACLs))
	for _, acl := range cfg.ACLs {
		if !inScope(acl.TenantID) {
			continue
		}
		desiredACLs[acl.ID] = acl
		existing, err := e.aclStore.GetACL(ctx, acl.ID)
		if err != nil || existing == nil {
			plan.add("create", "acl", acl.ID, acl.TenantID, "not present in store")
		} else if !aclEquivalent(acl, existing) {
			plan.add("update", "acl", acl.ID, acl.TenantID, "differs from store")
		}
	}
	if opts.Mode == ApplyModeSync {
		existingACLs, err := e.aclStore.ListACLs(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("list ACLs: %w", err)
		}
		for _, acl := range existingACLs {
			if acl == nil || !inScope(acl.TenantID) {
				continue
			}
			if _, ok := desiredACLs[acl.ID]; !ok {
				plan.add("delete", "acl", acl.ID, acl.TenantID, "not present in config")
			}
		}
	}

	plan.Operations = append(plan.Operations, pendingTenantDeletes...)

	existingMembers := make(map[string]RoleMembership)
	enumerableMembers := false
	if e.roleMembershipStore != nil {
		if enumerable, ok := e.roleMembershipStore.(EnumerableRoleMembershipStore); ok {
			enumerableMembers = true
			existing, err := enumerable.ListRoleMemberships(ctx)
			if err != nil {
				return nil, fmt.Errorf("list role memberships: %w", err)
			}
			for _, member := range existing {
				existingMembers[member.SubjectID+"->"+member.RoleID] = member
			}
		}
	}

	desiredMembers := make(map[string]RoleMembership, len(cfg.Memberships))
	for _, member := range cfg.Memberships {
		tenantID := ""
		if role, ok := desiredRoles[member.RoleID]; ok {
			tenantID = role.TenantID
		}
		if !inScope(tenantID) {
			continue
		}
		id := member.SubjectID + "->" + member.RoleID
		desiredMembers[id] = member
		if !enumerableMembers {
			plan.add("assign", "member", id, tenantID, "configured membership")
		} else if _, ok := existingMembers[id]; !ok {
			plan.add("assign", "member", id, tenantID, "not present in store")
		}
	}
	if opts.Mode == ApplyModeSync && e.roleMembershipStore != nil {
		if !enumerableMembers {
			if len(cfg.Memberships) > 0 {
				plan.Diagnostics = append(plan.Diagnostics, diag("warning", "memberships_not_fully_syncable", "role memberships are assigned additively because RoleMembershipStore cannot enumerate all subjects", "member", ""))
			}
		} else {
			for id, member := range existingMembers {
				if _, ok := desiredMembers[id]; !ok {
					tenantID := ""
					if role, ok := desiredRoles[member.RoleID]; ok {
						tenantID = role.TenantID
					}
					plan.add("revoke", "member", id, tenantID, "not present in config")
				}
			}
		}
	}

	return plan, nil
}

func (e *Engine) ApplyConfigPlan(ctx context.Context, plan *ConfigApplyPlan) error {
	if plan == nil {
		return fmt.Errorf("config apply plan is nil")
	}
	if plan.Options.DryRun {
		return nil
	}
	if err := ValidateConfig(plan.Config); err != nil {
		return err
	}
	for _, op := range plan.Operations {
		switch op.EntityType {
		case "tenant":
			if e.tenantStore == nil {
				continue
			}
			tenantCfg, ok := findTenantConfig(plan.Config, op.EntityID)
			switch op.Action {
			case "create":
				if ok {
					if err := e.CreateTenant(ctx, tenantConfigToTenant(tenantCfg)); err != nil {
						return err
					}
				}
			case "update":
				if ok {
					if err := e.UpdateTenant(ctx, tenantConfigToTenant(tenantCfg)); err != nil {
						return err
					}
				}
			case "delete":
				if err := e.DeleteTenant(ctx, op.EntityID); err != nil {
					return err
				}
			}
		case "policy":
			policy, ok := findPolicy(plan.Config, op.EntityID)
			switch op.Action {
			case "create":
				if ok {
					if err := e.CreatePolicy(ctx, policy); err != nil {
						return err
					}
				}
			case "update":
				if ok {
					if err := e.UpdatePolicy(ctx, policy); err != nil {
						return err
					}
				}
			case "delete":
				if err := e.DeletePolicy(ctx, op.EntityID); err != nil {
					return err
				}
			}
		case "role":
			role, ok := findRole(plan.Config, op.EntityID)
			switch op.Action {
			case "create":
				if ok {
					if err := e.CreateRole(ctx, role); err != nil {
						return err
					}
				}
			case "update":
				if ok {
					if err := e.UpdateRole(ctx, role); err != nil {
						return err
					}
				}
			case "delete":
				if err := e.DeleteRole(ctx, op.EntityID); err != nil {
					return err
				}
			}
		case "acl":
			acl, ok := findACL(plan.Config, op.EntityID)
			switch op.Action {
			case "create":
				if ok {
					if err := e.GrantACL(ctx, acl); err != nil {
						return err
					}
				}
			case "update":
				if ok {
					if err := e.UpdateACL(ctx, acl); err != nil {
						return err
					}
				}
			case "delete":
				if err := e.RevokeACL(ctx, op.EntityID); err != nil {
					return err
				}
			}
		case "member":
			if e.roleMembershipStore != nil {
				subjectID, roleID, ok := splitMemberOperationID(op.EntityID)
				if ok {
					switch op.Action {
					case "assign":
						if err := e.AssignRoleToUser(ctx, subjectID, roleID); err != nil {
							return err
						}
					case "revoke":
						if err := e.RevokeRoleFromUser(ctx, subjectID, roleID); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	e.InvalidateDecisionCache()
	return nil
}

func (p *ConfigApplyPlan) add(action, entityType, entityID, tenantID, reason string) {
	p.Operations = append(p.Operations, ConfigApplyOperation{Action: action, EntityType: entityType, EntityID: entityID, TenantID: tenantID, Reason: reason})
}

func tenantConfigToTenant(t TenantConfig) *Tenant {
	return &Tenant{ID: t.ID, Name: t.Name, ParentID: t.Parent, Attrs: t.Attrs}
}

func tenantConfigEqualTenant(cfg TenantConfig, tenant *Tenant) bool {
	return tenant != nil && cfg.ID == tenant.ID && cfg.Name == tenant.Name && cfg.Parent == tenant.ParentID && mapsEqualEmpty(cfg.Attrs, tenant.Attrs)
}

func policyEquivalent(a, b *Policy) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.TenantID == b.TenantID &&
		a.Effect == b.Effect &&
		a.Priority == b.Priority &&
		a.Enabled == b.Enabled &&
		reflect.DeepEqual(a.Actions, b.Actions) &&
		reflect.DeepEqual(a.Resources, b.Resources) &&
		exprString(a.Condition) == exprString(b.Condition)
}

func roleEquivalent(a, b *Role) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.TenantID == b.TenantID &&
		a.Name == b.Name &&
		reflect.DeepEqual(a.Permissions, b.Permissions) &&
		reflect.DeepEqual(a.Inherits, b.Inherits) &&
		reflect.DeepEqual(a.OwnerAllowedActions, b.OwnerAllowedActions)
}

func aclEquivalent(a, b *ACL) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.ResourceID == b.ResourceID &&
		a.SubjectID == b.SubjectID &&
		a.Effect == b.Effect &&
		a.TenantID == b.TenantID &&
		a.ExpiresAt.Equal(b.ExpiresAt) &&
		reflect.DeepEqual(a.Actions, b.Actions)
}

func exprString(e Expr) string {
	if e == nil {
		return ""
	}
	return conditionToDSL(e)
}

func mapsEqualEmpty(a, b map[string]any) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func findTenantConfig(cfg *Config, id string) (TenantConfig, bool) {
	for _, tenant := range cfg.Tenants {
		if tenant.ID == id {
			return tenant, true
		}
	}
	return TenantConfig{}, false
}

func findPolicy(cfg *Config, id string) (*Policy, bool) {
	for _, policy := range cfg.Policies {
		if policy != nil && policy.ID == id {
			return policy, true
		}
	}
	return nil, false
}

func findRole(cfg *Config, id string) (*Role, bool) {
	for _, role := range cfg.Roles {
		if role != nil && role.ID == id {
			return role, true
		}
	}
	return nil, false
}

func findACL(cfg *Config, id string) (*ACL, bool) {
	for _, acl := range cfg.ACLs {
		if acl != nil && acl.ID == id {
			return acl, true
		}
	}
	return nil, false
}

func splitMemberOperationID(id string) (string, string, bool) {
	for i := 0; i+1 < len(id); i++ {
		if id[i:i+2] == "->" {
			return id[:i], id[i+2:], true
		}
	}
	return "", "", false
}
