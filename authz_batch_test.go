package authz_test

import (
	"context"
	"testing"
	"time"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func newTestEngine(t *testing.T) *authz.Engine {
	t.Helper()
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore)
	policy := &authz.Policy{
		ID:        "policy-allow-read",
		TenantID:  "tenant-1",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"document.read"},
		Resources: []string{"document:*"},
		Condition: &authz.TrueExpr{},
		Priority:  1,
	}
	if err := engine.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := engine.ReloadPolicies(context.Background(), "tenant-1"); err != nil {
		t.Fatalf("reload policies: %v", err)
	}
	return engine
}

func TestBatchAuthorizeMultipleRequests(t *testing.T) {
	engine := newTestEngine(t)
	subject := &authz.Subject{ID: "user", TenantID: "tenant-1"}
	resource := &authz.Resource{ID: "123", Type: "document", TenantID: "tenant-1"}
	env := &authz.Environment{Time: time.Now(), TenantID: "tenant-1"}
	reqs := []authz.AuthRequest{
		{Subject: subject, Action: "document.read", Resource: resource, Environment: env},
		{Subject: subject, Action: "document.read", Resource: resource, Environment: env},
		{Subject: subject, Action: "document.read", Resource: resource, Environment: env},
	}
	decisions, err := engine.BatchAuthorize(context.Background(), reqs)
	if err != nil {
		t.Fatalf("batch authorize: %v", err)
	}
	if len(decisions) != len(reqs) {
		t.Fatalf("expected %d decisions, got %d", len(reqs), len(decisions))
	}
	for i, dec := range decisions {
		if dec == nil {
			t.Fatalf("decision %d is nil", i)
		}
		if !dec.Allowed {
			t.Fatalf("expected decision %d to allow", i)
		}
	}
}

func TestBatchAuthorizeValidatesRequests(t *testing.T) {
	engine := newTestEngine(t)
	env := &authz.Environment{Time: time.Now(), TenantID: "tenant-1"}
	reqs := []authz.AuthRequest{{Action: "document.read", Environment: env}}
	if _, err := engine.BatchAuthorize(context.Background(), reqs); err == nil {
		t.Fatalf("expected error for missing subject/resource")
	}
}

func TestBatchAuthorizeHonorsContextCancellation(t *testing.T) {
	engine := newTestEngine(t)
	subject := &authz.Subject{ID: "user", TenantID: "tenant-1"}
	resource := &authz.Resource{ID: "123", Type: "document", TenantID: "tenant-1"}
	env := &authz.Environment{Time: time.Now(), TenantID: "tenant-1"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reqs := []authz.AuthRequest{{Subject: subject, Action: "document.read", Resource: resource, Environment: env}}
	if _, err := engine.BatchAuthorize(ctx, reqs); err == nil {
		t.Fatalf("expected context cancellation error")
	}
}
