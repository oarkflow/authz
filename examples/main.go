package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
)

func main() {
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
}
