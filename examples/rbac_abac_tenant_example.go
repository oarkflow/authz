package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func mai3n() {
	ctx := context.Background()

	// Initialize stores (in-memory for example)
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	rmStore := stores.NewMemoryRoleMembershipStore()

	// custom trace id generator used for example output
	tidGen := func() string { return fmt.Sprintf("example-%d", time.Now().UnixNano()) }

	engine := authz.NewEngine(
		policyStore,
		roleStore,
		aclStore,
		auditStore,
		authz.WithRoleMembershipStore(rmStore),
		authz.WithLogger(authz.NewSLogLogger(nil)),
		authz.WithTraceIDFunc(tidGen),
	)

	// Tenant hierarchy: team-a is a child of tenant-1
	tr := authz.NewMemoryTenantResolver()
	tr.AddParent("team-a", "tenant-1")
	engine.SetTenantResolver(tr)

	// 1) RBAC: define roles and inheritance
	editor := &authz.Role{
		ID:       "role-editor",
		TenantID: "tenant-1",
		Name:     "Editor",
		Permissions: []authz.Permission{
			{Action: "post.publish", Resource: "backend:post"},
			{Action: "post.edit", Resource: "backend:post"},
		},
	}
	admin := &authz.Role{
		ID:       "role-admin",
		TenantID: "tenant-1",
		Name:     "Admin",
		Permissions: []authz.Permission{
			{Action: "user.create", Resource: "backend:user"},
			{Action: "user.delete", Resource: "backend:user"},
		},
		// Admin inherits editor to get editor permissions as well
		Inherits: []string{"role-editor"},
	}

	_ = engine.CreateRole(ctx, editor)
	_ = engine.CreateRole(ctx, admin)

	// 2) Assign principal roles using RoleMembership store
	_ = engine.AssignRoleToUser(ctx, "user1", "role-admin") // user1 is an admin
	_ = engine.AssignRoleToUser(ctx, "user2", "role-editor")

	// 3) ABAC: Add a policy where resource owners can read their documents
	ownerPolicy := &authz.Policy{
		ID:        "policy-owner-read",
		TenantID:  "tenant-1",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"read"},
		Resources: []string{"document:*"},
		Condition: &authz.EqExpr{Field: "resource.owner_id", Value: "subject.id"},
		Priority:  100,
	}
	_ = engine.CreatePolicy(ctx, ownerPolicy)

	// 4) ABAC: time-based policy for working hours
	timePolicy := &authz.Policy{
		ID:        "policy-business-hours",
		TenantID:  "tenant-1",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"document.*"},
		Resources: []string{"document:*"},
		Condition: &authz.TimeBetweenExpr{Start: "09:00", End: "18:00"},
		Priority:  10,
	}
	_ = engine.CreatePolicy(ctx, timePolicy)

	// 5) ACL: grant user2 a temporary allow to write a specific document
	acl := &authz.ACL{
		ID:         "acl-allow-write",
		ResourceID: "document:99",
		SubjectID:  "user2",
		Actions:    []authz.Action{"write"},
		Effect:     authz.EffectAllow,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}
	_ = engine.GrantACL(ctx, acl)

	// Reload policies into compiled index
	_ = engine.ReloadPolicies(ctx, "tenant-1")

	// Build some subjects and resources
	subject1 := &authz.Subject{ID: "user1", TenantID: "tenant-1"} // admin
	subject2 := &authz.Subject{ID: "user2", TenantID: "tenant-1"} // editor
	subject3 := &authz.Subject{ID: "external", TenantID: "other"}

	docOwnedByUser2 := &authz.Resource{ID: "99", Type: "document", TenantID: "tenant-1", OwnerID: "user2"}
	docOther := &authz.Resource{ID: "123", Type: "document", TenantID: "tenant-1", OwnerID: "someone"}

	// Environment (current tenant)
	env := &authz.Environment{Time: time.Now(), TenantID: "tenant-1"}

	// Authorize examples
	requests := []struct {
		name       string
		sub        *authz.Subject
		a          authz.Action
		res        *authz.Resource
		env        *authz.Environment
		expAllowed bool
		expReason  string
	}{
		// Note: some resources intentionally do not set Resource.TenantID to demonstrate tenant-mismatch behavior
		{"Admin creates user", subject1, "user.create", &authz.Resource{Type: "backend", ID: "user"}, env, false, "resource tenant mismatch"},
		{"Editor publish post", subject2, "post.publish", &authz.Resource{Type: "backend", ID: "post"}, env, false, "resource tenant mismatch"},
		{"Editor write own doc (ACL)", subject2, "write", docOwnedByUser2, env, true, "acl allow"},
		{"Non-owner read doc (no matching)", subject2, "read", docOther, env, false, "default deny"},
		{"Owner read doc (ABAC)", subject2, "read", docOwnedByUser2, env, true, "abac policy allow"},
		{"External tenant request (denied)", subject3, "read", docOther, env, false, "subject tenant not authorized"},
	}

	for _, r := range requests {
		dec, _ := engine.Authorize(ctx, r.sub, r.a, r.res, r.env)
		fmt.Printf("%s -> Actual: allowed=%v reason=%s matched_by=%s\n", r.name, dec.Allowed, dec.Reason, dec.MatchedBy)
		fmt.Printf("           Expected: allowed=%v reason=%s\n", r.expAllowed, r.expReason)
		// print explanation trace when there's a mismatch
		if dec.Allowed != r.expAllowed || dec.Reason != r.expReason {
			ex, _ := engine.Explain(ctx, r.sub, r.a, r.res, r.env)
			fmt.Println("  Explanation trace:")
			for _, t := range ex.Trace {
				fmt.Println("   ", t)
			}
		}
	}

	// Demonstrate tenant ownership: owner role pattern
	ownerRole := &authz.Role{ID: "role-tenant-owner", TenantID: "tenant-1", Name: "tenant-owner", OwnerAllowedActions: []authz.Action{"document.*"}}
	_ = engine.CreateRole(ctx, ownerRole)
	// user1 becomes a tenant owner via attribute
	subject1.Attrs = map[string]any{"is_tenant_owner": true}

	// This should allow owner-like actions across descendant tenant (team-a)
	envDesc := &authz.Environment{Time: time.Now(), TenantID: "team-a"}
	docInTeam := &authz.Resource{ID: "abc", Type: "document", TenantID: "team-a", OwnerID: "other"}
	decOwner, _ := engine.Authorize(ctx, subject1, "document.read", docInTeam, envDesc)
	fmt.Printf("Tenant owner allowed across descendant tenant: %v (reason=%s)\n", decOwner.Allowed, decOwner.Reason)

	// Policy history example
	_ = engine.UpdatePolicy(ctx, ownerPolicy) // bump version and snapshot
	if h, err := policyStore.GetPolicyHistory(ctx, "policy-owner-read"); err == nil {
		fmt.Printf("policy-owner-read history snapshots: %d\n", len(h))
	}

	// Replay: get last audit log and replay decision (if any)
	logs, _ := auditStore.GetAccessLog(ctx, authz.AuditFilter{Limit: 5})
	if len(logs) > 0 {
		fmt.Println("Replaying last audit entry:")
		newDec, matched, _ := engine.ReplayDecision(ctx, logs[len(logs)-1])
		fmt.Printf("replay matched=%v new_allowed=%v\n", matched, newDec.Allowed)
	}

	// BatchAuthorize example
	batch := []authz.AuthRequest{
		{Subject: subject1, Action: "user.create", Resource: &authz.Resource{Type: "backend", ID: "user"}, Environment: env},
		{Subject: subject2, Action: "post.publish", Resource: &authz.Resource{Type: "backend", ID: "post"}, Environment: env},
	}
	resps, _ := engine.BatchAuthorize(ctx, batch)
	fmt.Println("Batch results:")
	for i, d := range resps {
		fmt.Printf("  %d: allowed=%v reason=%s\n", i+1, d.Allowed, d.Reason)
	}
}
