package authz

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	sub := &Subject{ID: "u1", TenantID: "t1"}
	res := &Resource{ID: "r1", TenantID: "t2", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "t1"}

	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if dec.Allowed {
		t.Fatalf("expected deny due to tenant mismatch")
	}
}

func TestACLPrecedenceAndGroup(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	// Grant an explicit deny via ACL
	aclDeny := &ACL{ID: "acl-deny", ResourceID: "document:123", SubjectID: "user-john", Actions: []Action{"read"}, Effect: EffectDeny}
	_ = eng.GrantACL(ctx, aclDeny)

	// Grant group allow
	aclGroup := &ACL{ID: "acl-group", ResourceID: "document:123", SubjectID: "group:eng", Actions: []Action{"read"}, Effect: EffectAllow}
	_ = eng.GrantACL(ctx, aclGroup)

	sub := &Subject{ID: "user-john", TenantID: "tenant-1", Groups: []string{"eng"}}
	res := &Resource{ID: "123", TenantID: "tenant-1", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "tenant-1"}

	// Deny should win
	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if dec.Allowed {
		t.Fatalf("expected deny due to explicit ACL deny")
	}

	// Revoke deny and allow via group should succeed
	_ = eng.RevokeACL(ctx, "acl-deny")
	dec2, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec2.Allowed {
		t.Fatalf("expected allow via group ACL")
	}
}

func TestRBACDerivedAsABAC(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	// Create role with permission
	role := &Role{ID: "role-reader", TenantID: "tenant-1", Permissions: []Permission{{Action: "read", Resource: "document:*"}}}
	_ = eng.CreateRole(ctx, role)

	sub := &Subject{ID: "alice", TenantID: "tenant-1", Roles: []string{"role-reader"}}
	res := &Resource{ID: "999", TenantID: "tenant-1", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "tenant-1"}

	allowed, roleID, trace := eng.checkRBAC(ctx, sub, "read", res)
	if !allowed {
		t.Fatalf("expected RBAC-derived allow, trace=%v", trace)
	}
	if roleID != "role-reader" {
		t.Fatalf("expected matching role id role-reader, got %s", roleID)
	}

	// Authorize should also allow
	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec.Allowed {
		t.Fatalf("expected final allow via RBAC")
	}
}

func TestExprTimeBetweenAndCIDR(t *testing.T) {
	ctx := context.Background()
	tm := time.Date(2025, 12, 26, 10, 30, 0, 0, time.UTC)
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	// Policy: allow read if time between 09:00 and 18:00 and ip in 10.0.0.0/8
	p := &Policy{ID: "p-time-ip", TenantID: "tenant-1", Effect: EffectAllow, Actions: []Action{"read"}, Resources: []string{"document:*"}, Condition: &AndExpr{Left: &TimeBetweenExpr{Start: "09:00", End: "18:00"}, Right: &CIDRExpr{CIDR: "10.0.0.0/8"}}, Priority: 10}
	_ = eng.CreatePolicy(ctx, p)
	_ = eng.ReloadPolicies(ctx, "tenant-1")

	sub := &Subject{ID: "svc", TenantID: "tenant-1"}
	res := &Resource{ID: "1", TenantID: "tenant-1", Type: "document"}
	env := &Environment{Time: tm, TenantID: "tenant-1", IP: net.ParseIP("10.1.2.3")}

	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec.Allowed {
		t.Fatalf("expected allow for time+ip condition, trace=%v", dec.Trace)
	}
}

func TestRouteAuthorizationViaMiddleware(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	// admin role permission for admin routes
	role := &Role{ID: "role-admin", TenantID: "t", Name: "admin", Permissions: []Permission{{Action: "GET", Resource: "route:GET:/admin/*"}}}
	_ = eng.CreateRole(ctx, role)
	// owner route policy
	p := &Policy{ID: "p-owner-route", TenantID: "t", Effect: EffectAllow, Actions: []Action{"GET"}, Resources: []string{"route:GET:/users/*"}, Condition: &EqExpr{Field: "resource.owner_id", Value: "subject.id"}, Priority: 10}
	_ = eng.CreatePolicy(ctx, p)
	_ = eng.ReloadPolicies(ctx, "t")

	// admin should access
	subAdmin := &Subject{ID: "sysadmin", TenantID: "t", Roles: []string{"role-admin"}}
	resAdmin := &Resource{Type: "route", ID: "GET:/admin/dashboard", TenantID: "t"}
	env := &Environment{Time: time.Now(), TenantID: "t"}
	dec, _ := eng.Authorize(ctx, subAdmin, "GET", resAdmin, env)
	if !dec.Allowed {
		t.Fatalf("expected admin to be allowed")
	}

	// owner should access their user route
	subOwner := &Subject{ID: "alice", TenantID: "t"}
	resOwner := &Resource{Type: "route", ID: "GET:/users/alice", TenantID: "t", OwnerID: "alice"}
	dec2, _ := eng.Authorize(ctx, subOwner, "GET", resOwner, env)
	if !dec2.Allowed {
		t.Fatalf("expected owner to be allowed")
	}

	// other user denied
	subOther := &Subject{ID: "bob", TenantID: "t"}
	dec3, _ := eng.Authorize(ctx, subOther, "GET", resOwner, env)
	if dec3.Allowed {
		t.Fatalf("expected non-owner to be denied")
	}
}

func TestExplainIncludesPolicyTraces(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	p := &Policy{ID: "p-owner", TenantID: "tenant-1", Effect: EffectAllow, Actions: []Action{"read"}, Resources: []string{"document:*"}, Condition: &EqExpr{Field: "resource.owner_id", Value: "subject.id"}, Priority: 5}
	_ = eng.CreatePolicy(ctx, p)
	_ = eng.ReloadPolicies(ctx, "tenant-1")

	sub := &Subject{ID: "user-alice", TenantID: "tenant-1"}
	res := &Resource{ID: "doc1", TenantID: "tenant-1", Type: "document", OwnerID: "user-alice"}
	env := &Environment{Time: time.Now(), TenantID: "tenant-1"}

	// ensure owner index has the policy
	ops := eng.policyIndex.GetOwnerPolicies("document")
	if len(ops) == 0 {
		t.Fatalf("expected owner index to contain policies for document, got none")
	}

	// Explain should include trace
	dec, _ := eng.Explain(ctx, sub, "read", res, env)
	t.Logf("Explain trace: %v", dec.Trace)
	found := false
	for _, tr := range dec.Trace {
		if strings.Contains(tr, "policy=p-owner MATCH") || strings.Contains(tr, "policy=p-owner cond=resource.owner_id == subject.id result=true") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected trace to include policy match details, trace=%v", dec.Trace)
	}
}

func TestRegexAndRangeExpr(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	p1 := &Policy{ID: "p-regex", TenantID: "tenant-1", Effect: EffectAllow, Actions: []Action{"read"}, Resources: []string{"document:*"}, Condition: &RegexExpr{Field: "resource.attrs.name", Regex: "^confidential"}, Priority: 5}
	p2 := &Policy{ID: "p-range", TenantID: "tenant-1", Effect: EffectAllow, Actions: []Action{"read"}, Resources: []string{"document:*"}, Condition: &RangeExpr{Field: "resource.attrs.size", Min: 10, Max: 100}, Priority: 5}
	_ = eng.CreatePolicy(ctx, p1)
	_ = eng.CreatePolicy(ctx, p2)
	_ = eng.ReloadPolicies(ctx, "tenant-1")

	sub := &Subject{ID: "svc", TenantID: "tenant-1"}
	res1 := &Resource{ID: "1", TenantID: "tenant-1", Type: "document", Attrs: map[string]any{"name": "confidential-123"}}
	res2 := &Resource{ID: "2", TenantID: "tenant-1", Type: "document", Attrs: map[string]any{"size": 50}}
	env := &Environment{Time: time.Now(), TenantID: "tenant-1"}

	dec1, _ := eng.Authorize(ctx, sub, "read", res1, env)
	if !dec1.Allowed {
		t.Fatalf("expected regex policy to allow")
	}

	dec2, _ := eng.Authorize(ctx, sub, "read", res2, env)
	if !dec2.Allowed {
		t.Fatalf("expected range policy to allow")
	}
}

func TestAttributeProviderAndDecisionCache(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	// attribute provider
	m := NewMemoryAttributeProvider()
	m.SetAttributes("user-attr", map[string]any{"clearance": 7})
	eng.RegisterAttributeProvider(m)

	// policy: subject.attr.clearance >= resource.attrs.classification
	p := &Policy{ID: "p-clearance", TenantID: "tenant-1", Effect: EffectAllow, Actions: []Action{"read"}, Resources: []string{"document:*"}, Condition: &GteExpr{Field: "subject.attrs.clearance", Value: 5}, Priority: 10}
	_ = eng.CreatePolicy(ctx, p)
	_ = eng.ReloadPolicies(ctx, "tenant-1")

	sub := &Subject{ID: "user-attr", TenantID: "tenant-1"}
	res := &Resource{ID: "9", TenantID: "tenant-1", Type: "document", Attrs: map[string]any{"classification": 3}}
	env := &Environment{Time: time.Now(), TenantID: "tenant-1"}

	// First call caches
	dec1, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec1.Allowed {
		t.Fatalf("expected allow via attribute provider")
	}

	// second call should be cached
	dec2, _ := eng.Authorize(ctx, sub, "read", res, env)
	if len(dec2.Trace) == 0 || dec2.Trace[0] != "(cached)" {
		t.Fatalf("expected cached decision, got trace=%v", dec2.Trace)
	}

	// update policy to deny and ensure cache invalidation
	p.Effect = EffectDeny
	_ = eng.UpdatePolicy(ctx, p)
	_ = eng.ReloadPolicies(ctx, "tenant-1")
	dec3, _ := eng.Authorize(ctx, sub, "read", res, env)
	if dec3.Allowed {
		t.Fatalf("expected deny after policy update, got allow")
	}
}

func TestPolicySigningAndBundle(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	// create policies
	p1 := &Policy{ID: "sig-p1", TenantID: "tenant-1", Effect: EffectAllow, Actions: []Action{"read"}, Resources: []string{"document:*"}, Condition: &TrueExpr{}, Priority: 1}
	p2 := &Policy{ID: "sig-p2", TenantID: "tenant-1", Effect: EffectDeny, Actions: []Action{"delete"}, Resources: []string{"document:*"}, Condition: &TrueExpr{}, Priority: 2}

	// generate keypair
	pub, priv, _ := ed25519.GenerateKey(nil)

	bundle, err := SignBundle(priv, []*Policy{p1, p2})
	if err != nil {
		t.Fatalf("failed to sign bundle: %v", err)
	}

	ok, err := VerifyBundle(pub, bundle)
	if err != nil || !ok {
		t.Fatalf("bundle verification failed: %v", err)
	}

	// apply bundle
	if err := eng.ApplySignedBundle(ctx, pub, bundle); err != nil {
		t.Fatalf("apply signed bundle failed: %v", err)
	}

	// reload and check policies present
	_ = eng.ReloadPolicies(ctx, "tenant-1")
	if _, err := ps.GetPolicy(ctx, "sig-p1"); err != nil {
		t.Fatalf("policy not found after apply: %v", err)
	}

	// authorization should reflect policies
	sub := &Subject{ID: "u1", TenantID: "tenant-1"}
	res := &Resource{ID: "r1", TenantID: "tenant-1", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "tenant-1"}

	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec.Allowed {
		t.Fatalf("expected allow via signed policy p1")
	}

	dec2, _ := eng.Authorize(ctx, sub, "delete", res, env)
	if dec2.Allowed {
		t.Fatalf("expected deny via signed policy p2")
	}
}

func BenchmarkAuthorize(b *testing.B) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	p := &Policy{ID: "bench-p", TenantID: "t", Effect: EffectAllow, Actions: []Action{"read"}, Resources: []string{"document:*"}, Condition: &TrueExpr{}, Priority: 1}
	_ = eng.CreatePolicy(ctx, p)
	_ = eng.ReloadPolicies(ctx, "t")

	sub := &Subject{ID: "bench-user", TenantID: "t"}
	res := &Resource{ID: "1", Type: "document", TenantID: "t"}
	env := &Environment{Time: time.Now(), TenantID: "t"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eng.Authorize(ctx, sub, "read", res, env)
	}
}

func BenchmarkReloadPolicies(b *testing.B) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	policies := make([]*Policy, 0, 1000)
	for i := 0; i < 1000; i++ {
		p := &Policy{ID: fmt.Sprintf("p-%d", i), TenantID: "t", Effect: EffectAllow, Actions: []Action{"read"}, Resources: []string{"document:*"}, Condition: &TrueExpr{}, Priority: 1}
		policies = append(policies, p)
		_ = ps.CreatePolicy(ctx, p)
	}
	re := NewEngine(ps, NewMemoryRoleStore(), NewMemoryACLStore(), NewMemoryAuditStore())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = re.ReloadPolicies(ctx, "t")
	}
}

// BenchmarkCompiledPredicateEval measures the cost of calling the fast compiled predicate
func BenchmarkCompiledPredicateEval(b *testing.B) {
	// construct a moderately complex expression
	expr := &AndExpr{
		Left: &AndExpr{
			Left:  &EqExpr{Field: "resource.owner_id", Value: "subject.id"},
			Right: &RegexExpr{Field: "resource.attrs.name", Regex: "^confidential"},
		},
		Right: &RangeExpr{Field: "resource.attrs.size", Min: 10, Max: 100},
	}

	pred := compilePredicate(expr)
	sub := &Subject{ID: "alice", TenantID: "t", Attrs: map[string]any{"clearance": 5}}
	res := &Resource{ID: "1", Type: "document", TenantID: "t", OwnerID: "alice", Attrs: map[string]any{"name": "confidential-1", "size": 50}}
	env := &Environment{Time: time.Now(), TenantID: "t"}
	evalCtx := &EvalContext{Subject: sub, Resource: res, Action: "read", Environment: env}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pred(evalCtx)
	}
}

// BenchmarkBytecodeEval measures the cost of running equivalent bytecode
func BenchmarkBytecodeEval(b *testing.B) {
	expr := &AndExpr{
		Left: &AndExpr{
			Left:  &EqExpr{Field: "resource.owner_id", Value: "subject.id"},
			Right: &RegexExpr{Field: "resource.attrs.name", Regex: "^confidential"},
		},
		Right: &RangeExpr{Field: "resource.attrs.size", Min: 10, Max: 100},
	}

	bc := compileToBytecode(expr)
	sub := &Subject{ID: "alice", TenantID: "t", Attrs: map[string]any{"clearance": 5}}
	res := &Resource{ID: "1", Type: "document", TenantID: "t", OwnerID: "alice", Attrs: map[string]any{"name": "confidential-1", "size": 50}}
	env := &Environment{Time: time.Now(), TenantID: "t"}
	evalCtx := &EvalContext{Subject: sub, Resource: res, Action: "read", Environment: env}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bc.Eval(evalCtx)
	}
}

func benchAuthorizeWithPolicies(b *testing.B, n int) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	for i := 0; i < n; i++ {
		p := &Policy{
			ID:        fmt.Sprintf("p-%d", i),
			TenantID:  "t",
			Effect:    EffectAllow,
			Actions:   []Action{"read"},
			Resources: []string{"document:*"},
			Condition: &GteExpr{Field: "subject.attrs.clearance", Value: i + 1000},
			Priority:  100,
		}
		_ = ps.CreatePolicy(ctx, p)
	}
	// add a low-priority matching policy to force scanning all prior policies
	last := &Policy{ID: "p-match", TenantID: "t", Effect: EffectAllow, Actions: []Action{"read"}, Resources: []string{"document:*"}, Condition: &TrueExpr{}, Priority: 1}
	_ = ps.CreatePolicy(ctx, last)

	eng := NewEngine(ps, NewMemoryRoleStore(), NewMemoryACLStore(), NewMemoryAuditStore())
	// ensure compiled index is built
	_ = eng.ReloadPolicies(ctx, "t")
	// disable decision cache by setting negative TTL so entries expire immediately
	eng.decisionCacheTTL = -time.Second
	eng.InvalidateDecisionCache()

	sub := &Subject{ID: "bench-user", TenantID: "t", Attrs: map[string]any{"clearance": 50}}
	res := &Resource{ID: "1", Type: "document", TenantID: "t", OwnerID: "alice"}
	env := &Environment{Time: time.Now(), TenantID: "t"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eng.Authorize(ctx, sub, "read", res, env)
	}
}

func BenchmarkAuthorize_1kPolicies(b *testing.B) {
	benchAuthorizeWithPolicies(b, 1000)
}

func BenchmarkAuthorize_10kPolicies(b *testing.B) {
	benchAuthorizeWithPolicies(b, 10000)
}
func TestHierarchicalTenantOwnerAccess(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	tr := NewMemoryTenantResolver()
	tr.AddParent("team-a", "org-1")
	eng.SetTenantResolver(tr)

	sub := &Subject{ID: "owner1", TenantID: "org-1", Attrs: map[string]any{"is_tenant_owner": true}}
	res := &Resource{ID: "res1", TenantID: "team-a", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "team-a"}

	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec.Allowed {
		t.Fatalf("expected tenant owner to have access, got deny, trace=%v", dec.Trace)
	}
}

func TestCrossTenantAdminAccess(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	tr := NewMemoryTenantResolver()
	tr.AddParent("team-a", "org-1")
	eng.SetTenantResolver(tr)

	// create an admin role in org-1
	role := &Role{ID: "role-admin", TenantID: "org-1", Name: "admin", Permissions: []Permission{{Action: "*", Resource: "*"}}}
	_ = eng.CreateRole(ctx, role)

	sub := &Subject{ID: "admin1", TenantID: "org-1", Roles: []string{"role-admin"}}
	res := &Resource{ID: "res2", TenantID: "team-a", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "team-a"}

	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec.Allowed {
		t.Fatalf("expected cross-tenant admin to have access, got deny, trace=%v", dec.Trace)
	}
}

func TestTenantOwnerActionScoped(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	tr := NewMemoryTenantResolver()
	tr.AddParent("team-a", "org-1")
	eng.SetTenantResolver(tr)

	// subject marked as owner but only allowed 'read'
	sub := &Subject{ID: "owner1", TenantID: "org-1", Attrs: map[string]any{"is_tenant_owner": true, "owner_allowed_actions": []string{"read"}}}
	res := &Resource{ID: "res1", TenantID: "team-a", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "team-a"}

	// read should be allowed
	dec1, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec1.Allowed {
		t.Fatalf("expected owner read to be allowed, got deny, trace=%v", dec1.Trace)
	}

	// delete should be denied
	dec2, _ := eng.Authorize(ctx, sub, "delete", res, env)
	if dec2.Allowed {
		t.Fatalf("expected owner delete to be denied, got allow, trace=%v", dec2.Trace)
	}
}

func TestRoleOwnerActionScoped(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	tr := NewMemoryTenantResolver()
	tr.AddParent("team-a", "org-1")
	eng.SetTenantResolver(tr)

	// create an owner role that only permits read via Permissions (legacy style)
	role := &Role{ID: "role-owner", TenantID: "org-1", Name: "tenant-owner", Permissions: []Permission{{Action: "read", Resource: "document:*"}}}
	_ = eng.CreateRole(ctx, role)

	sub := &Subject{ID: "ownerRoleUser", TenantID: "org-1", Roles: []string{"role-owner"}}
	res := &Resource{ID: "res3", TenantID: "team-a", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "team-a"}

	// read allowed
	dec1, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec1.Allowed {
		t.Fatalf("expected role owner read to be allowed, got deny, trace=%v", dec1.Trace)
	}

	// delete denied
	dec2, _ := eng.Authorize(ctx, sub, "delete", res, env)
	if dec2.Allowed {
		t.Fatalf("expected role owner delete to be denied, got allow, trace=%v", dec2.Trace)
	}
}

func TestRoleOwnerRoleLevelAllowedActions(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	tr := NewMemoryTenantResolver()
	tr.AddParent("team-a", "org-1")
	eng.SetTenantResolver(tr)

	// create an owner role that defines owner-scoped allowed actions
	role := &Role{ID: "role-owner-actions", TenantID: "org-1", Name: "tenant-owner", OwnerAllowedActions: []Action{"read"}}
	_ = eng.CreateRole(ctx, role)

	sub := &Subject{ID: "ownerRoleUser2", TenantID: "org-1", Roles: []string{"role-owner-actions"}}
	res := &Resource{ID: "res4", TenantID: "team-a", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "team-a"}

	// read allowed via OwnerAllowedActions
	dec1, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec1.Allowed {
		t.Fatalf("expected role-level owner read to be allowed, got deny, trace=%v", dec1.Trace)
	}

	// delete denied
	dec2, _ := eng.Authorize(ctx, sub, "delete", res, env)
	if dec2.Allowed {
		t.Fatalf("expected role-level owner delete to be denied, got allow, trace=%v", dec2.Trace)
	}
}

func TestCrossTenantAdminViaInheritance(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	tr := NewMemoryTenantResolver()
	tr.AddParent("team-a", "org-1")
	eng.SetTenantResolver(tr)

	// parent role is admin and has wildcard permissions
	admin := &Role{ID: "role-admin-parent", TenantID: "org-1", Name: "admin", Permissions: []Permission{{Action: "*", Resource: "*"}}}
	_ = eng.CreateRole(ctx, admin)

	// child role inherits admin
	child := &Role{ID: "role-manager", TenantID: "org-1", Name: "manager", Inherits: []string{"role-admin-parent"}}
	_ = eng.CreateRole(ctx, child)

	// subject with child role
	sub := &Subject{ID: "mgrUser", TenantID: "org-1", Roles: []string{"role-manager"}}
	res := &Resource{ID: "resX", TenantID: "team-a", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "team-a"}

	// subject tenant is ancestor, and child role inherits admin wildcard, so allow
	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec.Allowed {
		t.Fatalf("expected inherited admin role to allow cross-tenant access, got deny, trace=%v", dec.Trace)
	}
}

func TestRoleInheritanceCycleDoesNotInfiniteLoop(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	// Role A inherits B, B inherits A, B defines a wildcard permission
	a := &Role{ID: "role-a", TenantID: "t", Name: "role-a", Inherits: []string{"role-b"}}
	b := &Role{ID: "role-b", TenantID: "t", Name: "role-b", Inherits: []string{"role-a"}, Permissions: []Permission{{Action: "*", Resource: "*"}}}
	_ = eng.CreateRole(ctx, a)
	_ = eng.CreateRole(ctx, b)

	sub := &Subject{ID: "u1", TenantID: "t", Roles: []string{"role-a"}}
	res := &Resource{ID: "resC", TenantID: "t", Type: "doc"}
	env := &Environment{Time: time.Now(), TenantID: "t"}

	// should allow via inherited wildcard and must not hang or recurse infinitely
	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec.Allowed {
		t.Fatalf("expected allowed via cyclic inheritance and wildcard, got deny, trace=%v", dec.Trace)
	}
}

func TestRoleInheritanceCycleDeniesIfNoPermission(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	// Roles with mutual inheritance but no permissions
	a := &Role{ID: "role-x", TenantID: "t", Name: "role-x", Inherits: []string{"role-y"}}
	b := &Role{ID: "role-y", TenantID: "t", Name: "role-y", Inherits: []string{"role-x"}}
	_ = eng.CreateRole(ctx, a)
	_ = eng.CreateRole(ctx, b)

	sub := &Subject{ID: "u2", TenantID: "t", Roles: []string{"role-x"}}
	res := &Resource{ID: "resD", TenantID: "t", Type: "doc"}
	env := &Environment{Time: time.Now(), TenantID: "t"}

	// should be denied and must not hang
	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if dec.Allowed {
		t.Fatalf("expected deny when cyclic roles have no permissions, got allow, trace=%v", dec.Trace)
	}
}

func TestImplicitRolesFromAttributeProvider(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	// install attribute provider and attach roles for a subject
	mapProv := NewMemoryAttributeProvider()
	mapProv.SetAttributes("sysattr", map[string]any{"roles": []string{"role-admin"}})
	eng.RegisterAttributeProvider(mapProv)

	// create admin role with wildcard access
	admin := &Role{ID: "role-admin", TenantID: "t", Name: "admin", Permissions: []Permission{{Action: "*", Resource: "*"}}}
	_ = eng.CreateRole(ctx, admin)

	sub := &Subject{ID: "sysattr", TenantID: "t"} // no explicit Roles
	res := &Resource{ID: "resZ", TenantID: "t", Type: "any"}
	env := &Environment{Time: time.Now(), TenantID: "t"}

	// should be allowed via roles from attribute provider
	dec, _ := eng.Authorize(ctx, sub, "read", res, env)
	if !dec.Allowed {
		t.Fatalf("expected allowed via roles provided by attribute provider, got deny, trace=%v", dec.Trace)
	}
}

func TestRoleOwnerActionPatternSupportsPrefix(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	tr := NewMemoryTenantResolver()
	tr.AddParent("team-a", "org-1")
	eng.SetTenantResolver(tr)

	// role with OwnerAllowedActions pattern
	role := &Role{ID: "role-owner-pattern", TenantID: "org-1", Name: "tenant-owner", OwnerAllowedActions: []Action{"document.*"}}
	_ = eng.CreateRole(ctx, role)

	sub := &Subject{ID: "ownerPatternUser", TenantID: "org-1", Roles: []string{"role-owner-pattern"}}
	res := &Resource{ID: "res5", TenantID: "team-a", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "team-a"}

	// action with prefix should be allowed
	dec1, _ := eng.Authorize(ctx, sub, "document.read", res, env)
	if !dec1.Allowed {
		t.Fatalf("expected role-level owner pattern read to be allowed, got deny, trace=%v", dec1.Trace)
	}

	// other action denied
	dec2, _ := eng.Authorize(ctx, sub, "delete", res, env)
	if dec2.Allowed {
		t.Fatalf("expected role-level owner pattern delete to be denied, got allow, trace=%v", dec2.Trace)
	}
}

func TestSubjectOwnerActionPatternSupportsPrefix(t *testing.T) {
	ctx := context.Background()
	ps := NewMemoryPolicyStore()
	rs := NewMemoryRoleStore()
	as := NewMemoryACLStore()
	tau := NewMemoryAuditStore()
	eng := NewEngine(ps, rs, as, tau)

	tr := NewMemoryTenantResolver()
	tr.AddParent("team-a", "org-1")
	eng.SetTenantResolver(tr)

	// subject marked as owner with allowed action pattern
	sub := &Subject{ID: "ownerAttrUser", TenantID: "org-1", Attrs: map[string]any{"is_tenant_owner": true, "owner_allowed_actions": []string{"document.*"}}}
	res := &Resource{ID: "res6", TenantID: "team-a", Type: "document"}
	env := &Environment{Time: time.Now(), TenantID: "team-a"}

	// debug: verify subject attributes types
	if v, ok := sub.Attrs["is_tenant_owner"]; !ok {
		t.Fatalf("missing is_tenant_owner attr")
	} else {
		t.Logf("is_tenant_owner type=%T value=%v", v, v)
	}
	if v, ok := sub.Attrs["owner_allowed_actions"]; !ok {
		t.Fatalf("missing owner_allowed_actions attr")
	} else {
		t.Logf("owner_allowed_actions type=%T value=%v", v, v)
	}

	// ensure the direct owner-for-action check returns true
	if !eng.isTenantOwnerForAction(ctx, sub, "team-a", "document.read", res) {
		t.Fatalf("expected isTenantOwnerForAction to return true for pattern, got false")
	}

	// pattern action allowed via engine
	dec1, _ := eng.Authorize(ctx, sub, "document.read", res, env)
	if !dec1.Allowed {
		t.Fatalf("expected subject owner pattern read to be allowed, got deny, trace=%v", dec1.Trace)
	}

	// non-matching action denied
	dec2, _ := eng.Authorize(ctx, sub, "delete", res, env)
	if dec2.Allowed {
		t.Fatalf("expected subject owner pattern delete to be denied, got allow, trace=%v", dec2.Trace)
	}
}
