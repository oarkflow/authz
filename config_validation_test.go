package authz_test

import (
	"context"
	"testing"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func TestValidateConfigRejectsSemanticErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  *authz.Config
	}{
		{
			name: "duplicate policy",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.Policies = append(cfg.Policies, cfg.Policies[0])
			}),
		},
		{
			name: "missing policy tenant",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.Policies[0].TenantID = "missing"
			}),
		},
		{
			name: "missing inherited role",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.Roles[0].Inherits = []string{"missing"}
			}),
		},
		{
			name: "missing membership role",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.Memberships[0].RoleID = "missing"
			}),
		},
		{
			name: "tenant cycle",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.Tenants = append(cfg.Tenants, authz.TenantConfig{ID: "child", Name: "Child", Parent: "org"})
				cfg.Hierarchy["org"] = "child"
				cfg.Hierarchy["child"] = "org"
			}),
		},
		{
			name: "missing service account role",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.ServiceAccounts = []*authz.ServiceAccount{{ID: "svc:bot", TenantID: "org", Name: "Bot", Roles: []string{"missing"}}}
			}),
		},
		{
			name: "missing service account scope",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.ServiceAccounts = []*authz.ServiceAccount{{ID: "svc:bot", TenantID: "org", Name: "Bot", Scopes: []string{"missing.scope"}}}
			}),
		},
		{
			name: "missing invitation role",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.Invitations = []*authz.Invitation{{ID: "invite1", TenantID: "org", Email: "a@example.com", RoleIDs: []string{"missing"}}}
			}),
		},
		{
			name: "missing invitation group",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.Invitations = []*authz.Invitation{{ID: "invite1", TenantID: "org", Email: "a@example.com", RoleIDs: []string{"admin"}, GroupIDs: []string{"missing"}}}
			}),
		},
		{
			name: "missing api key scope",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.APIKeys = []*authz.APIKey{{ID: "key1", TenantID: "org", UserID: "user:alice", Prefix: "sk_", Scopes: []string{"missing.scope"}}}
			}),
		},
		{
			name: "duplicate boundary",
			cfg: validConfig(func(cfg *authz.Config) {
				cfg.PermissionBoundaries = []*authz.PermissionBoundary{
					{ID: "b1", TenantID: "org", Name: "One", MaxActions: []authz.Action{"read"}, MaxResources: []string{"document:*"}},
					{ID: "b1", TenantID: "org", Name: "Two", MaxActions: []authz.Action{"read"}, MaxResources: []string{"document:*"}},
				}
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := authz.ValidateConfig(tt.cfg); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLintConfigWarnings(t *testing.T) {
	cfg := validConfig(func(cfg *authz.Config) {
		cfg.Roles = append(cfg.Roles, &authz.Role{ID: "unused", TenantID: "org", Name: "Unused", Permissions: []authz.Permission{{Action: "*", Resource: "*"}}})
		cfg.Policies = append(cfg.Policies, &authz.Policy{ID: "route-all", TenantID: "org", Effect: authz.EffectAllow, Actions: []authz.Action{"GET"}, Resources: []string{"route:*"}, Condition: &authz.TrueExpr{}, Enabled: true})
		cfg.ACLs = append(cfg.ACLs, &authz.ACL{ID: "bad-subject", ResourceID: "document:2", SubjectID: "alice", Actions: []authz.Action{"read"}, Effect: authz.EffectAllow})
	})

	warnings := authz.LintConfig(cfg)
	codes := make(map[string]bool)
	for _, warning := range warnings {
		codes[warning.Code] = true
	}
	for _, code := range []string{"broad_role_permission", "unused_role", "broad_route_policy", "malformed_acl_subject"} {
		if !codes[code] {
			t.Fatalf("expected lint warning %q in %#v", code, warnings)
		}
	}
}

func TestPlanConfigApplyUpsertAndSync(t *testing.T) {
	ctx := context.Background()
	tenantStore := stores.NewMemoryTenantStore()
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	rmStore := stores.NewMemoryRoleMembershipStore()
	engine := authz.NewEngine(
		policyStore,
		roleStore,
		aclStore,
		stores.NewMemoryAuditStore(),
		authz.WithTenantStore(tenantStore),
		authz.WithRoleMembershipStore(rmStore),
	)

	if err := engine.CreateTenant(ctx, &authz.Tenant{ID: "stale", Name: "Stale"}); err != nil {
		t.Fatal(err)
	}
	if err := engine.CreatePolicy(ctx, &authz.Policy{ID: "stale-policy", TenantID: "stale", Effect: authz.EffectAllow, Actions: []authz.Action{"read"}, Resources: []string{"document:*"}, Condition: &authz.TrueExpr{}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := engine.CreateRole(ctx, &authz.Role{ID: "stale-role", TenantID: "stale", Name: "Stale", Permissions: []authz.Permission{{Action: "read", Resource: "*"}}}); err != nil {
		t.Fatal(err)
	}
	if err := engine.GrantACL(ctx, &authz.ACL{ID: "stale-acl", TenantID: "stale", ResourceID: "document:old", SubjectID: "user:old", Actions: []authz.Action{"read"}, Effect: authz.EffectAllow}); err != nil {
		t.Fatal(err)
	}

	cfg := validConfig()
	upsertPlan, err := engine.PlanConfigApply(ctx, cfg, authz.ConfigApplyOptions{Mode: authz.ApplyModeUpsert, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range upsertPlan.Operations {
		if op.Action == "delete" {
			t.Fatalf("upsert plan included delete operation: %#v", op)
		}
	}

	syncPlan, err := engine.PlanConfigApply(ctx, cfg, authz.ConfigApplyOptions{Mode: authz.ApplyModeSync, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasOperation(syncPlan, "delete", "policy", "stale-policy") ||
		!hasOperation(syncPlan, "delete", "role", "stale-role") ||
		!hasOperation(syncPlan, "delete", "acl", "stale-acl") ||
		!hasOperation(syncPlan, "delete", "tenant", "stale") {
		t.Fatalf("sync dry-run plan did not include stale deletes: %#v", syncPlan.Operations)
	}
	if _, err := policyStore.GetPolicy(ctx, "stale-policy"); err != nil {
		t.Fatal("dry-run mutated policy store")
	}

	syncPlan.Options.DryRun = false
	if err := engine.ApplyConfigPlan(ctx, syncPlan); err != nil {
		t.Fatal(err)
	}
	if _, err := policyStore.GetPolicy(ctx, "stale-policy"); err == nil {
		t.Fatal("expected stale policy to be deleted")
	}
	if _, err := roleStore.GetRole(ctx, "stale-role"); err == nil {
		t.Fatal("expected stale role to be deleted")
	}
	if _, err := aclStore.GetACL(ctx, "stale-acl"); err == nil {
		t.Fatal("expected stale ACL to be deleted")
	}
	roles, err := rmStore.ListRoles(ctx, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("expected additive membership assignment, got %#v", roles)
	}
	idempotentPlan, err := engine.PlanConfigApply(ctx, cfg, authz.ConfigApplyOptions{Mode: authz.ApplyModeSync, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(idempotentPlan.Operations) != 0 {
		t.Fatalf("expected sync plan to be idempotent after apply, got %#v", idempotentPlan.Operations)
	}
}

func validConfig(mutators ...func(*authz.Config)) *authz.Config {
	cfg := &authz.Config{
		Version: 1,
		Tenants: []authz.TenantConfig{
			{ID: "org", Name: "Org"},
		},
		Policies: []*authz.Policy{
			{ID: "read-docs", TenantID: "org", Effect: authz.EffectAllow, Actions: []authz.Action{"read"}, Resources: []string{"document:*"}, Condition: &authz.TrueExpr{}, Enabled: true},
		},
		Roles: []*authz.Role{
			{ID: "admin", TenantID: "org", Name: "Admin", Permissions: []authz.Permission{{Action: "*", Resource: "*"}}},
		},
		ACLs: []*authz.ACL{
			{ID: "acl-alice", ResourceID: "document:1", SubjectID: "user:alice", Actions: []authz.Action{"read"}, Effect: authz.EffectAllow},
		},
		Memberships: []authz.RoleMembership{{SubjectID: "user:alice", RoleID: "admin"}},
		Hierarchy:   map[string]string{},
	}
	for _, mutate := range mutators {
		mutate(cfg)
	}
	return cfg
}

func hasOperation(plan *authz.ConfigApplyPlan, action, entityType, entityID string) bool {
	for _, op := range plan.Operations {
		if op.Action == action && op.EntityType == entityType && op.EntityID == entityID {
			return true
		}
	}
	return false
}
