package authz

import (
	"fmt"
	"strings"
)

type ConfigDiagnostic struct {
	Severity   string `json:"severity"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	EntityType string `json:"entity_type,omitempty"`
	EntityID   string `json:"entity_id,omitempty"`
}

type ConfigValidationError struct {
	Diagnostics []ConfigDiagnostic
}

func (e *ConfigValidationError) Error() string {
	if e == nil || len(e.Diagnostics) == 0 {
		return "configuration validation failed"
	}
	if len(e.Diagnostics) == 1 {
		return e.Diagnostics[0].Message
	}
	return fmt.Sprintf("configuration validation failed with %d errors: %s", len(e.Diagnostics), e.Diagnostics[0].Message)
}

func ValidateConfig(cfg *Config) error {
	diagnostics := validateConfigDiagnostics(cfg)
	if len(diagnostics) == 0 {
		return nil
	}
	return &ConfigValidationError{Diagnostics: diagnostics}
}

func LintConfig(cfg *Config) []ConfigDiagnostic {
	if cfg == nil {
		return []ConfigDiagnostic{{Severity: "warning", Code: "nil_config", Message: "configuration is nil"}}
	}
	var warnings []ConfigDiagnostic

	usedRoles := make(map[string]bool)
	for _, m := range cfg.Memberships {
		usedRoles[m.RoleID] = true
	}
	for _, role := range cfg.Roles {
		for _, parent := range role.Inherits {
			usedRoles[parent] = true
		}
		for _, p := range role.Permissions {
			if p.Action == "*" && p.Resource == "*" {
				warnings = append(warnings, diag("warning", "broad_role_permission", "role grants *:*", "role", role.ID))
			}
			if p.Resource == "route:*" {
				warnings = append(warnings, diag("warning", "broad_route_permission", "role grants access to route:*", "role", role.ID))
			}
		}
	}
	for _, role := range cfg.Roles {
		if !usedRoles[role.ID] {
			warnings = append(warnings, diag("warning", "unused_role", "role is not referenced by memberships or inheritance", "role", role.ID))
		}
	}
	for _, policy := range cfg.Policies {
		for _, resource := range policy.Resources {
			if resource == "*" {
				warnings = append(warnings, diag("warning", "broad_policy_resource", "policy applies to all resources", "policy", policy.ID))
			}
			if resource == "route:*" {
				warnings = append(warnings, diag("warning", "broad_route_policy", "policy applies to all routes", "policy", policy.ID))
			}
		}
	}
	tenantHasRules := make(map[string]bool)
	for _, policy := range cfg.Policies {
		tenantHasRules[policy.TenantID] = true
	}
	for _, role := range cfg.Roles {
		tenantHasRules[role.TenantID] = true
	}
	for _, tenant := range cfg.Tenants {
		if !tenantHasRules[tenant.ID] {
			warnings = append(warnings, diag("warning", "tenant_without_rules", "tenant has no policies or roles", "tenant", tenant.ID))
		}
	}
	for _, acl := range cfg.ACLs {
		if acl.SubjectID != "*" && acl.SubjectID != "guest" && !strings.Contains(acl.SubjectID, ":") {
			warnings = append(warnings, diag("warning", "malformed_acl_subject", "ACL subject usually uses a namespace such as user:id or group:id", "acl", acl.ID))
		}
	}
	return warnings
}

func validateConfigDiagnostics(cfg *Config) []ConfigDiagnostic {
	if cfg == nil {
		return []ConfigDiagnostic{diag("error", "nil_config", "configuration is nil", "", "")}
	}
	var errors []ConfigDiagnostic
	tenants := make(map[string]bool, len(cfg.Tenants))
	roles := make(map[string]bool, len(cfg.Roles))

	seenTenants := make(map[string]bool)
	for _, tenant := range cfg.Tenants {
		if tenant.ID == "" {
			errors = append(errors, diag("error", "missing_tenant_id", "tenant ID is required", "tenant", ""))
			continue
		}
		if seenTenants[tenant.ID] {
			errors = append(errors, diag("error", "duplicate_tenant_id", "duplicate tenant ID", "tenant", tenant.ID))
		}
		seenTenants[tenant.ID] = true
		tenants[tenant.ID] = true
	}

	seenPolicies := make(map[string]bool)
	for _, policy := range cfg.Policies {
		if policy == nil {
			errors = append(errors, diag("error", "nil_policy", "policy is nil", "policy", ""))
			continue
		}
		if policy.ID == "" {
			errors = append(errors, diag("error", "missing_policy_id", "policy ID is required", "policy", ""))
		} else if seenPolicies[policy.ID] {
			errors = append(errors, diag("error", "duplicate_policy_id", "duplicate policy ID", "policy", policy.ID))
		}
		seenPolicies[policy.ID] = true
		if !validEffect(policy.Effect) {
			errors = append(errors, diag("error", "invalid_policy_effect", "policy effect must be allow or deny", "policy", policy.ID))
		}
		if len(policy.Actions) == 0 {
			errors = append(errors, diag("error", "empty_policy_actions", "policy must have at least one action", "policy", policy.ID))
		}
		if len(policy.Resources) == 0 {
			errors = append(errors, diag("error", "empty_policy_resources", "policy must have at least one resource", "policy", policy.ID))
		}
		if policy.Condition == nil {
			errors = append(errors, diag("error", "nil_policy_condition", "policy condition is required", "policy", policy.ID))
		}
		if policy.TenantID == "" || !tenants[policy.TenantID] {
			errors = append(errors, diag("error", "missing_policy_tenant", "policy references a missing tenant", "policy", policy.ID))
		}
	}

	seenRoles := make(map[string]bool)
	for _, role := range cfg.Roles {
		if role == nil {
			errors = append(errors, diag("error", "nil_role", "role is nil", "role", ""))
			continue
		}
		if role.ID == "" {
			errors = append(errors, diag("error", "missing_role_id", "role ID is required", "role", ""))
		} else if seenRoles[role.ID] {
			errors = append(errors, diag("error", "duplicate_role_id", "duplicate role ID", "role", role.ID))
		}
		seenRoles[role.ID] = true
		roles[role.ID] = true
		if role.TenantID == "" || !tenants[role.TenantID] {
			errors = append(errors, diag("error", "missing_role_tenant", "role references a missing tenant", "role", role.ID))
		}
	}

	for _, role := range cfg.Roles {
		if role == nil {
			continue
		}
		for _, parent := range role.Inherits {
			if !roles[parent] {
				errors = append(errors, diag("error", "missing_inherited_role", fmt.Sprintf("role inherits missing role %q", parent), "role", role.ID))
			}
		}
	}

	seenACLs := make(map[string]bool)
	for _, acl := range cfg.ACLs {
		if acl == nil {
			errors = append(errors, diag("error", "nil_acl", "ACL is nil", "acl", ""))
			continue
		}
		if acl.ID == "" {
			errors = append(errors, diag("error", "missing_acl_id", "ACL ID is required", "acl", ""))
		} else if seenACLs[acl.ID] {
			errors = append(errors, diag("error", "duplicate_acl_id", "duplicate ACL ID", "acl", acl.ID))
		}
		seenACLs[acl.ID] = true
		if acl.ResourceID == "" {
			errors = append(errors, diag("error", "missing_acl_resource", "ACL resource is required", "acl", acl.ID))
		}
		if acl.SubjectID == "" {
			errors = append(errors, diag("error", "missing_acl_subject", "ACL subject is required", "acl", acl.ID))
		}
		if len(acl.Actions) == 0 {
			errors = append(errors, diag("error", "empty_acl_actions", "ACL must have at least one action", "acl", acl.ID))
		}
		if !validEffect(acl.Effect) {
			errors = append(errors, diag("error", "invalid_acl_effect", "ACL effect must be allow or deny", "acl", acl.ID))
		}
		if acl.TenantID != "" && !tenants[acl.TenantID] {
			errors = append(errors, diag("error", "missing_acl_tenant", "ACL references a missing tenant", "acl", acl.ID))
		}
	}

	for _, m := range cfg.Memberships {
		if m.SubjectID == "" {
			errors = append(errors, diag("error", "missing_member_subject", "membership subject is required", "member", ""))
		}
		if m.RoleID == "" || !roles[m.RoleID] {
			errors = append(errors, diag("error", "missing_member_role", "membership references a missing role", "member", m.SubjectID))
		}
	}

	validateTenantScoped := func(entityType, id, tenantID string) {
		if id == "" {
			errors = append(errors, diag("error", "missing_"+entityType+"_id", entityType+" ID is required", entityType, ""))
		}
		if tenantID == "" || !tenants[tenantID] {
			errors = append(errors, diag("error", "missing_"+entityType+"_tenant", entityType+" references a missing tenant", entityType, id))
		}
	}
	if len(cfg.Users) > 0 {
		seenUsers := make(map[string]bool, len(cfg.Users))
		for _, u := range cfg.Users {
			if u == nil {
				continue
			}
			if seenUsers[u.ID] {
				errors = append(errors, diag("error", "duplicate_user_id", "duplicate user ID", "user", u.ID))
			}
			seenUsers[u.ID] = true
			validateTenantScoped("user", u.ID, u.TenantID)
		}
	}
	var groupIDs map[string]bool
	if len(cfg.Groups) > 0 {
		groupIDs = make(map[string]bool, len(cfg.Groups))
		for _, g := range cfg.Groups {
			if g == nil {
				continue
			}
			if groupIDs[g.ID] {
				errors = append(errors, diag("error", "duplicate_group_id", "duplicate group ID", "group", g.ID))
			}
			groupIDs[g.ID] = true
			validateTenantScoped("group", g.ID, g.TenantID)
		}
		for _, g := range cfg.Groups {
			if g != nil && g.ParentID != "" && !groupIDs[g.ParentID] {
				errors = append(errors, diag("error", "missing_parent_group", "group references a missing parent group", "group", g.ID))
			}
		}
	}
	var scopeIDs map[string]bool
	if len(cfg.Scopes) > 0 {
		scopeIDs = make(map[string]bool, len(cfg.Scopes))
		for _, s := range cfg.Scopes {
			if s == nil {
				continue
			}
			if scopeIDs[s.ID] {
				errors = append(errors, diag("error", "duplicate_scope_id", "duplicate scope ID", "scope", s.ID))
			}
			scopeIDs[s.ID] = true
			validateTenantScoped("scope", s.ID, s.TenantID)
		}
		for _, s := range cfg.Scopes {
			if s != nil && s.ParentID != "" && !scopeIDs[s.ParentID] {
				errors = append(errors, diag("error", "missing_parent_scope", "scope references a missing parent scope", "scope", s.ID))
			}
		}
	}
	if len(cfg.PermissionBoundaries) > 0 {
		seenBoundaries := make(map[string]bool, len(cfg.PermissionBoundaries))
		for _, b := range cfg.PermissionBoundaries {
			if b == nil {
				continue
			}
			if seenBoundaries[b.ID] {
				errors = append(errors, diag("error", "duplicate_boundary_id", "duplicate permission boundary ID", "boundary", b.ID))
			}
			seenBoundaries[b.ID] = true
			validateTenantScoped("boundary", b.ID, b.TenantID)
			if len(b.MaxActions) == 0 || len(b.MaxResources) == 0 {
				errors = append(errors, diag("error", "empty_boundary_limits", "permission boundary requires actions and resources", "boundary", b.ID))
			}
		}
	}
	if len(cfg.ServiceAccounts) > 0 {
		seenServiceAccounts := make(map[string]bool, len(cfg.ServiceAccounts))
		for _, sa := range cfg.ServiceAccounts {
			if sa == nil {
				continue
			}
			if seenServiceAccounts[sa.ID] {
				errors = append(errors, diag("error", "duplicate_service_account_id", "duplicate service account ID", "service_account", sa.ID))
			}
			seenServiceAccounts[sa.ID] = true
			validateTenantScoped("service_account", sa.ID, sa.TenantID)
			for _, roleID := range sa.Roles {
				if !roles[roleID] {
					errors = append(errors, diag("error", "missing_service_account_role", fmt.Sprintf("service account references missing role %q", roleID), "service_account", sa.ID))
				}
			}
			for _, scopeID := range sa.Scopes {
				if !scopeIDs[scopeID] {
					errors = append(errors, diag("error", "missing_service_account_scope", fmt.Sprintf("service account references missing scope %q", scopeID), "service_account", sa.ID))
				}
			}
		}
	}
	if len(cfg.Invitations) > 0 {
		seenInvitations := make(map[string]bool, len(cfg.Invitations))
		for _, inv := range cfg.Invitations {
			if inv == nil {
				continue
			}
			if seenInvitations[inv.ID] {
				errors = append(errors, diag("error", "duplicate_invitation_id", "duplicate invitation ID", "invitation", inv.ID))
			}
			seenInvitations[inv.ID] = true
			validateTenantScoped("invitation", inv.ID, inv.TenantID)
			if inv.Email == "" {
				errors = append(errors, diag("error", "missing_invitation_email", "invitation email is required", "invitation", inv.ID))
			}
			for _, roleID := range inv.RoleIDs {
				if !roles[roleID] {
					errors = append(errors, diag("error", "missing_invitation_role", fmt.Sprintf("invitation references missing role %q", roleID), "invitation", inv.ID))
				}
			}
			for _, groupID := range inv.GroupIDs {
				if !groupIDs[groupID] {
					errors = append(errors, diag("error", "missing_invitation_group", fmt.Sprintf("invitation references missing group %q", groupID), "invitation", inv.ID))
				}
			}
		}
	}
	if len(cfg.APIKeys) > 0 {
		seenAPIKeys := make(map[string]bool, len(cfg.APIKeys))
		for _, key := range cfg.APIKeys {
			if key == nil {
				continue
			}
			if seenAPIKeys[key.ID] {
				errors = append(errors, diag("error", "duplicate_api_key_id", "duplicate API key ID", "api_key", key.ID))
			}
			seenAPIKeys[key.ID] = true
			validateTenantScoped("api_key", key.ID, key.TenantID)
			if key.UserID == "" {
				errors = append(errors, diag("error", "missing_api_key_user", "API key user is required", "api_key", key.ID))
			}
			if key.Prefix == "" {
				errors = append(errors, diag("error", "missing_api_key_prefix", "API key prefix is required", "api_key", key.ID))
			}
			for _, scopeID := range key.Scopes {
				if !scopeIDs[scopeID] {
					errors = append(errors, diag("error", "missing_api_key_scope", fmt.Sprintf("API key references missing scope %q", scopeID), "api_key", key.ID))
				}
			}
		}
	}

	hasHierarchy := len(cfg.Hierarchy) > 0
	if !hasHierarchy {
		for _, tenant := range cfg.Tenants {
			if tenant.Parent != "" {
				hasHierarchy = true
				break
			}
		}
	}
	if hasHierarchy {
		hierarchy := make(map[string]string, len(cfg.Hierarchy)+len(cfg.Tenants))
		for child, parent := range cfg.Hierarchy {
			hierarchy[child] = parent
		}
		for _, tenant := range cfg.Tenants {
			if tenant.Parent != "" {
				hierarchy[tenant.ID] = tenant.Parent
			}
		}
		maxDepth := len(hierarchy)
		for child, parent := range hierarchy {
			if child == "" || parent == "" {
				continue
			}
			if !tenants[child] {
				errors = append(errors, diag("error", "missing_hierarchy_child", "tenant hierarchy references a missing child tenant", "tenant", child))
			}
			if !tenants[parent] {
				errors = append(errors, diag("error", "missing_hierarchy_parent", "tenant hierarchy references a missing parent tenant", "tenant", child))
			}
			if hasTenantCycle(child, hierarchy, maxDepth) {
				errors = append(errors, diag("error", "tenant_hierarchy_cycle", "tenant hierarchy contains a cycle", "tenant", child))
			}
		}
	}

	return errors
}

func hasTenantCycle(start string, hierarchy map[string]string, maxDepth int) bool {
	cur := start
	for depth := 0; cur != ""; depth++ {
		if depth > maxDepth {
			return true
		}
		cur = hierarchy[cur]
	}
	return false
}

func diag(severity, code, message, entityType, entityID string) ConfigDiagnostic {
	return ConfigDiagnostic{Severity: severity, Code: code, Message: message, EntityType: entityType, EntityID: entityID}
}
