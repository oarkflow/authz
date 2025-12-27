package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
)

func mai1n() {
	ctx := context.Background()

	// Initialize stores
	policyStore := authz.NewMemoryPolicyStore()
	roleStore := authz.NewMemoryRoleStore()
	aclStore := authz.NewMemoryACLStore()
	auditStore := authz.NewMemoryAuditStore()

	// Create engine
	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore)

	// 1. Create a simple ABAC policy: Owners can read their own documents
	ownerPolicy := &authz.Policy{
		ID:        "policy-owner-read",
		TenantID:  "tenant-1",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"read"},
		Resources: []string{"document:*"},
		Condition: &authz.EqExpr{
			Field: "resource.owner_id",
			Value: "subject.id",
		},
		Priority: 100,
		Enabled:  true,
	}
	_ = engine.CreatePolicy(ctx, ownerPolicy)

	// 2. Create an admin role
	adminRole := &authz.Role{
		ID:       "role-admin",
		TenantID: "tenant-1",
		Name:     "Admin",
		Permissions: []authz.Permission{
			{Action: "*", Resource: "*"},
		},
	}
	_ = engine.CreateRole(ctx, adminRole)

	// Demonstrate owner role-level action patterns and subject attribute patterns
	tr := authz.NewMemoryTenantResolver()
	tr.AddParent("team-a", "tenant-1")
	engine.SetTenantResolver(tr)

	// Role-based owner that allows document.* actions across descendants
	ownerRole := &authz.Role{ID: "role-owner-pattern", TenantID: "tenant-1", Name: "tenant-owner", OwnerAllowedActions: []authz.Action{"document.*"}}
	_ = engine.CreateRole(ctx, ownerRole)

	ownerUser := &authz.Subject{ID: "owner-user", TenantID: "tenant-1", Roles: []string{"role-owner-pattern"}}
	docTeam := &authz.Resource{ID: "doc-team", Type: "document", TenantID: "team-a"}
	// local environment for descendant tenant
	envLocal := &authz.Environment{Time: time.Now(), TenantID: "team-a"}

	decA, _ := engine.Authorize(ctx, ownerUser, "document.read", docTeam, envLocal)
	fmt.Printf("Owner role pattern decision for document.read across descendant: allowed=%v\n", decA.Allowed)

	decB, _ := engine.Authorize(ctx, ownerUser, "delete", docTeam, envLocal)
	fmt.Printf("Owner role pattern decision for delete across descendant: allowed=%v\n", decB.Allowed)

	// Subject attribute based owner allowed actions
	subAttrOwner := &authz.Subject{ID: "owner-attr", TenantID: "tenant-1", Attrs: map[string]any{"is_tenant_owner": true, "owner_allowed_actions": []string{"document.*"}}}
	decC, _ := engine.Authorize(ctx, subAttrOwner, "document.read", docTeam, envLocal)
	fmt.Printf("Subject attribute owner decision for document.read across descendant: allowed=%v\n", decC.Allowed)

	// 3. Grant ACL to a specific user for a specific document
	acl := &authz.ACL{
		ID:         "acl-1",
		ResourceID: "document:123",
		SubjectID:  "user-bob",
		Actions:    []authz.Action{"read", "write"},
		Effect:     authz.EffectAllow,
	}
	_ = engine.GrantACL(ctx, acl)

	// Reload policies into index
	_ = engine.ReloadPolicies(ctx, "tenant-1")

	// 4. Test authorization
	alice := &authz.Subject{
		ID:       "user-alice",
		Type:     "user",
		TenantID: "tenant-1",
		Roles:    []string{"role-admin"},
		Attrs:    map[string]any{"clearance": 5},
	}

	document := &authz.Resource{
		ID:       "123",
		Type:     "document",
		TenantID: "tenant-1",
		OwnerID:  "user-alice",
		Attrs:    map[string]any{"classification": 3},
	}

	env := &authz.Environment{
		Time:     time.Now(),
		TenantID: "tenant-1",
		Region:   "us-west",
	}

	decision, _ := engine.Authorize(ctx, alice, "read", document, env)
	fmt.Printf("Decision: %+v\n", decision)

	// 5. Explain decision
	explanation, _ := engine.Explain(ctx, alice, "read", document, env)
	fmt.Println("\nExplanation:")
	for _, trace := range explanation.Trace {
		fmt.Println(trace)
	}

	// 6. Owner-index example: create owner policy and demonstrate O(1) lookup
	ownerPolicy = &authz.Policy{ID: "policy-owner-fast", TenantID: "tenant-1", Effect: authz.EffectAllow, Actions: []authz.Action{"read"}, Resources: []string{"document:*"}, Condition: &authz.EqExpr{Field: "resource.owner_id", Value: "subject.id"}, Priority: 100}
	_ = engine.CreatePolicy(ctx, ownerPolicy)
	_ = engine.ReloadPolicies(ctx, "tenant-1")

	// owner user can access without scanning unrelated policies
	ownerUser = &authz.Subject{ID: "user-alice", TenantID: "tenant-1"}
	decA, _ = engine.Authorize(ctx, ownerUser, "read", document, env)
	fmt.Printf("Owner index decision for owner read: allowed=%v\n", decA.Allowed)

	// non-owner denied if no policy allows
	nonOwner := &authz.Subject{ID: "bob", TenantID: "tenant-1"}
	decB, _ = engine.Authorize(ctx, nonOwner, "read", document, env)

	// Demonstrate policy versioning, history and replay
	// Update owner policy (bump version)
	ownerPolicy.Priority = 200
	_ = engine.UpdatePolicy(ctx, ownerPolicy)

	// Fetch history
	hist, err := policyStore.ListPolicies(ctx, "tenant-1")
	if err == nil {
		fmt.Printf("Policies count after update: %d\n", len(hist))
	}
	// Get history for a single policy (MemoryPolicyStore supports GetPolicyHistory)
	if versions, err := policyStore.GetPolicyHistory(ctx, "policy-owner-read"); err == nil {
		fmt.Printf("Policy history versions for policy-owner-read: %d\n", len(versions))
	}

	// Replay an audit entry (take last entry)
	logs, _ := auditStore.GetAccessLog(ctx, authz.AuditFilter{SubjectID: alice.ID, Limit: 1})
	if len(logs) > 0 {
		fmt.Println("Replaying decision for last audit entry...")
		newDec, matched, _ := engine.ReplayDecision(ctx, logs[len(logs)-1])
		fmt.Printf("Replay matched: %v, New decision allowed=%v\n", matched, newDec.Allowed)
	}

}
