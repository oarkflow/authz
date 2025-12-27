package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

// This example demonstrates modelling tenant namespaces and scoped roles using
// a combination of RBAC (roles + role membership) and ABAC (policies that check
// subject attributes and environment metadata).
func mai2n() {
	ctx := context.Background()

	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	rmStore := stores.NewMemoryRoleMembershipStore()

	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore, authz.WithRoleMembershipStore(rmStore), authz.WithLogger(authz.NewNullLogger()))

	// Roles
	editor := &authz.Role{ID: "role-editor", TenantID: "tenant-a", Name: "Editor", Permissions: []authz.Permission{{Action: "post.edit", Resource: "backend:post"}}}
	admin := &authz.Role{ID: "role-admin", TenantID: "tenant-a", Name: "Admin", Permissions: []authz.Permission{{Action: "user.create", Resource: "backend:user"}}}
	// admin inherits editor
	admin.Inherits = []string{"role-editor"}

	_ = engine.CreateRole(ctx, editor)
	_ = engine.CreateRole(ctx, admin)

	// ABAC policy: allow editors to publish in a specific tenant namespace and scope
	// Condition: subject.roles contains role-editor AND subject.attrs.namespace == env.extra.namespace AND subject.attrs.scope == env.extra.scope
	publishPolicy := &authz.Policy{
		ID:        "policy-editor-publish-scoped",
		TenantID:  "tenant-a",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"post.publish"},
		Resources: []string{"backend:post"},
		Condition: &authz.AndExpr{
			Left: &authz.InExpr{Field: "subject.roles", Values: []any{"role-editor"}},
			Right: &authz.AndExpr{
				Left:  &authz.EqExpr{Field: "subject.attrs.namespace", Value: "env.extra.namespace"},
				Right: &authz.EqExpr{Field: "subject.attrs.scope", Value: "env.extra.scope"},
			},
		},
		Priority: 100,
	}
	_ = engine.CreatePolicy(ctx, publishPolicy)
	_ = engine.ReloadPolicies(ctx, "tenant-a")

	// Assign roles to principals
	_ = engine.AssignRoleToUser(ctx, "user1", "role-admin")
	_ = engine.AssignRoleToUser(ctx, "user2", "role-editor")
	// note: user3 is not assigned role-editor (scoped user for engineering should be denied)

	// Subjects
	sub1 := &authz.Subject{ID: "user1", TenantID: "tenant-a"} // admin
	sub2 := &authz.Subject{ID: "user2", TenantID: "tenant-a", Attrs: map[string]any{"namespace": "marketing", "scope": "campaign-management"}}
	sub3 := &authz.Subject{ID: "user3", TenantID: "tenant-a", Attrs: map[string]any{"namespace": "engineering", "scope": "engineering-scope"}}

	// Requests (mirroring example semantics)
	req1 := struct {
		name     string
		subject  *authz.Subject
		tenant   string
		resource *authz.Resource
		action   authz.Action
		env      *authz.Environment
		exp      bool
	}{
		"user1 create user in tenant-a (admin)", sub1, "tenant-a", &authz.Resource{Type: "backend", ID: "user/1", TenantID: "tenant-a"}, "user.create", &authz.Environment{Time: time.Now(), TenantID: "tenant-a"}, true,
	}

	req2 := struct {
		name     string
		subject  *authz.Subject
		tenant   string
		resource *authz.Resource
		action   authz.Action
		env      *authz.Environment
		exp      bool
	}{
		"user2 publish in marketing/campaign-management (editor scoped)", sub2, "tenant-a", &authz.Resource{Type: "backend", ID: "post", TenantID: "tenant-a"}, "post.publish", &authz.Environment{Time: time.Now(), TenantID: "tenant-a", Extra: map[string]any{"namespace": "marketing", "scope": "campaign-management"}}, true,
	}

	req3 := struct {
		name     string
		subject  *authz.Subject
		tenant   string
		resource *authz.Resource
		action   authz.Action
		env      *authz.Environment
		exp      bool
	}{
		"user2 publish in engineering (should be denied)", sub3, "tenant-a", &authz.Resource{Type: "backend", ID: "post", TenantID: "tenant-a"}, "post.publish", &authz.Environment{Time: time.Now(), TenantID: "tenant-a", Extra: map[string]any{"namespace": "engineering", "scope": "engineering-scope"}}, false,
	}

	requests := []interface{}{req1, req2, req3}

	for _, r := range requests {
		switch v := r.(type) {
		case struct {
			name     string
			subject  *authz.Subject
			tenant   string
			resource *authz.Resource
			action   authz.Action
			env      *authz.Environment
			exp      bool
		}:
			dec, _ := engine.Authorize(ctx, v.subject, v.action, v.resource, v.env)
			fmt.Printf("%s -> actual allowed=%v expected=%v reason=%s\n", v.name, dec.Allowed, v.exp, dec.Reason)
			if dec.Allowed != v.exp {
				ex, _ := engine.Explain(ctx, v.subject, v.action, v.resource, v.env)
				fmt.Println(" Explanation:")
				for _, t := range ex.Trace {
					fmt.Println("  ", t)
				}
			}
		}
	}
}
