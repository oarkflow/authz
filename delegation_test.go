package authz_test

import (
	"context"
	"testing"
	"time"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func newDelegationEngine(t *testing.T) (*authz.Engine, *stores.MemoryDelegationStore, *stores.MemoryAuditStore) {
	t.Helper()
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	delegationStore := stores.NewMemoryDelegationStore()

	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore,
		authz.WithDelegationStore(delegationStore),
	)
	return engine, delegationStore, auditStore
}

func delegationTestResource() *authz.Resource {
	return &authz.Resource{ID: "123", Type: "document", TenantID: "tenant-a"}
}

func delegationTestEnv(at time.Time) *authz.Environment {
	return &authz.Environment{Time: at, TenantID: "tenant-a"}
}

func TestDelegationAllowsWithinScopeAndWindow(t *testing.T) {
	engine, _, _ := newDelegationEngine(t)
	ctx := context.Background()

	delegator := &authz.Subject{ID: "alice", TenantID: "tenant-a"}
	delegate := &authz.Subject{ID: "bob", TenantID: "tenant-a"}
	resource := delegationTestResource()

	// Grant the delegator direct ACL authority over the resource first, since
	// delegation cannot forward a capability the delegator does not have.
	if err := engine.GrantACL(ctx, &authz.ACL{
		ID:         "acl-alice-doc123",
		TenantID:   "tenant-a",
		ResourceID: "document:123",
		SubjectID:  "alice",
		Actions:    []authz.Action{"read"},
		Effect:     authz.EffectAllow,
	}); err != nil {
		t.Fatalf("grant acl: %v", err)
	}

	now := time.Now()
	grant, err := engine.CreateDelegation(ctx, delegator, delegate, []authz.Action{"read"}, "document:123",
		now.Add(-time.Minute), now.Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("create delegation: %v", err)
	}
	if grant.ID == "" {
		t.Fatalf("expected grant id to be set")
	}

	decision, err := engine.Authorize(ctx, delegate, "read", resource, delegationTestEnv(now))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected delegated access to be allowed, got reason=%s", decision.Reason)
	}
	if decision.Reason != "delegation allow" {
		t.Fatalf("expected reason 'delegation allow', got %q", decision.Reason)
	}
}

func TestDelegationDeniesOutsideTimeWindow(t *testing.T) {
	engine, _, _ := newDelegationEngine(t)
	ctx := context.Background()

	delegator := &authz.Subject{ID: "alice", TenantID: "tenant-a"}
	delegate := &authz.Subject{ID: "bob", TenantID: "tenant-a"}
	resource := delegationTestResource()

	if err := engine.GrantACL(ctx, &authz.ACL{
		ID:         "acl-alice-doc123",
		TenantID:   "tenant-a",
		ResourceID: "document:123",
		SubjectID:  "alice",
		Actions:    []authz.Action{"read"},
		Effect:     authz.EffectAllow,
	}); err != nil {
		t.Fatalf("grant acl: %v", err)
	}

	now := time.Now()

	// Not yet started.
	_, err := engine.CreateDelegation(ctx, delegator, delegate, []authz.Action{"read"}, "document:123",
		now.Add(time.Hour), now.Add(2*time.Hour), 0)
	if err != nil {
		t.Fatalf("create delegation: %v", err)
	}
	decision, err := engine.Authorize(ctx, delegate, "read", resource, delegationTestEnv(now))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected access to be denied before delegation start time")
	}

	// Already expired.
	engine2, _, _ := newDelegationEngine(t)
	if err := engine2.GrantACL(ctx, &authz.ACL{
		ID:         "acl-alice-doc123",
		TenantID:   "tenant-a",
		ResourceID: "document:123",
		SubjectID:  "alice",
		Actions:    []authz.Action{"read"},
		Effect:     authz.EffectAllow,
	}); err != nil {
		t.Fatalf("grant acl: %v", err)
	}
	_, err = engine2.CreateDelegation(ctx, delegator, delegate, []authz.Action{"read"}, "document:123",
		now.Add(-2*time.Hour), now.Add(-time.Hour), 0)
	if err != nil {
		t.Fatalf("create delegation: %v", err)
	}
	decision2, err := engine2.Authorize(ctx, delegate, "read", resource, delegationTestEnv(now))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision2.Allowed {
		t.Fatalf("expected access to be denied after delegation expiry")
	}
}

func TestDelegationDeniedWhenDelegatorLacksPermission(t *testing.T) {
	engine, _, _ := newDelegationEngine(t)
	ctx := context.Background()

	delegator := &authz.Subject{ID: "alice", TenantID: "tenant-a"}
	delegate := &authz.Subject{ID: "bob", TenantID: "tenant-a"}
	now := time.Now()

	// Alice has no ACL, role, or policy granting her "read" on document:123 -
	// CreateDelegation must refuse to let her delegate what she does not have.
	_, err := engine.CreateDelegation(ctx, delegator, delegate, []authz.Action{"read"}, "document:123",
		now.Add(-time.Minute), now.Add(time.Hour), 0)
	if err == nil {
		t.Fatalf("expected CreateDelegation to fail when delegator lacks the underlying permission")
	}
}

func TestDelegationRevocationStopsAccessImmediately(t *testing.T) {
	engine, _, _ := newDelegationEngine(t)
	ctx := context.Background()

	delegator := &authz.Subject{ID: "alice", TenantID: "tenant-a"}
	delegate := &authz.Subject{ID: "bob", TenantID: "tenant-a"}
	resource := delegationTestResource()

	if err := engine.GrantACL(ctx, &authz.ACL{
		ID:         "acl-alice-doc123",
		TenantID:   "tenant-a",
		ResourceID: "document:123",
		SubjectID:  "alice",
		Actions:    []authz.Action{"read"},
		Effect:     authz.EffectAllow,
	}); err != nil {
		t.Fatalf("grant acl: %v", err)
	}

	now := time.Now()
	grant, err := engine.CreateDelegation(ctx, delegator, delegate, []authz.Action{"read"}, "document:123",
		now.Add(-time.Minute), now.Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("create delegation: %v", err)
	}

	decision, err := engine.Authorize(ctx, delegate, "read", resource, delegationTestEnv(now))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected delegated access to be allowed before revocation")
	}

	if err := engine.RevokeDelegation(ctx, delegator, grant.ID); err != nil {
		t.Fatalf("revoke delegation: %v", err)
	}

	decision2, err := engine.Authorize(ctx, delegate, "read", resource, delegationTestEnv(now))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision2.Allowed {
		t.Fatalf("expected access to be denied immediately after revocation")
	}
}

func TestBreakGlassAlwaysAllowsAndRecordsFlaggedAudit(t *testing.T) {
	engine, _, auditStore := newDelegationEngine(t)
	ctx := context.Background()

	subject := &authz.Subject{ID: "oncall-eng", TenantID: "tenant-a"}
	resource := delegationTestResource()
	env := delegationTestEnv(time.Now())

	// Confirm normal Authorize denies this request (no grants configured).
	normalDecision, err := engine.Authorize(ctx, subject, "delete", resource, env)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if normalDecision.Allowed {
		t.Fatalf("expected normal authorize to deny access")
	}

	justification := "production incident INC-4821, need emergency delete to unblock rollback"
	decision, err := engine.AuthorizeBreakGlass(ctx, subject, "delete", resource, env, justification)
	if err != nil {
		t.Fatalf("authorize break glass: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected break-glass access to always be allowed")
	}

	found := false
	logs, err := auditStore.GetAccessLog(ctx, authz.AuditFilter{SubjectID: subject.ID})
	if err != nil {
		t.Fatalf("get access log: %v", err)
	}
	for _, entry := range logs {
		if entry.Action != authz.BreakGlassAction {
			continue
		}
		flag, ok := entry.Metadata["break_glass"].(bool)
		if !ok || !flag {
			t.Fatalf("expected break_glass metadata flag to be true")
		}
		if entry.Metadata["justification"] != justification {
			t.Fatalf("expected justification to be recorded in audit metadata, got %v", entry.Metadata["justification"])
		}
		found = true
	}
	if !found {
		t.Fatalf("expected a flagged break-glass audit entry to be recorded")
	}
}

func TestAuthorizeBreakGlassRequiresJustification(t *testing.T) {
	engine, _, _ := newDelegationEngine(t)
	ctx := context.Background()
	subject := &authz.Subject{ID: "oncall-eng", TenantID: "tenant-a"}
	resource := delegationTestResource()
	env := delegationTestEnv(time.Now())

	if _, err := engine.AuthorizeBreakGlass(ctx, subject, "delete", resource, env, ""); err == nil {
		t.Fatalf("expected error when justification is empty")
	}
}
