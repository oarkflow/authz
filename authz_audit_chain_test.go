package authz_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func waitForAuditLog(t *testing.T, engine *authz.Engine, tenantID string, want int) []*authz.AuditEntry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := engine.GetAccessLog(context.Background(), authz.AuditFilter{TenantID: tenantID, Limit: 1000})
		if err != nil {
			t.Fatalf("get access log: %v", err)
		}
		if len(entries) >= want {
			return entries
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d audit entries", want)
	return nil
}

func TestAuditChainComputedAndVerified(t *testing.T) {
	engine := newTestEngine(t)
	subject := &authz.Subject{ID: "user", TenantID: "tenant-1"}
	env := &authz.Environment{Time: time.Now(), TenantID: "tenant-1"}

	for i := 0; i < 5; i++ {
		resource := &authz.Resource{ID: fmt.Sprintf("doc-%d", i), Type: "document", TenantID: "tenant-1"}
		if _, err := engine.Authorize(context.Background(), subject, "document.read", resource, env); err != nil {
			t.Fatalf("authorize: %v", err)
		}
	}

	entries := waitForAuditLog(t, engine, "tenant-1", 5)

	for i, e := range entries {
		if e.Hash == "" {
			t.Fatalf("entry %d missing hash", i)
		}
		if i == 0 {
			if e.PrevHash != "" {
				t.Fatalf("first entry should have empty prev hash, got %q", e.PrevHash)
			}
			continue
		}
		if e.PrevHash != entries[i-1].Hash {
			t.Fatalf("entry %d prev_hash %q does not match previous entry hash %q", i, e.PrevHash, entries[i-1].Hash)
		}
	}

	brk, err := engine.VerifyAuditChain(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if brk != nil {
		t.Fatalf("expected intact chain, got break: %+v", brk)
	}
}

func TestAuditChainDetectsTamperedEntry(t *testing.T) {
	engine := newTestEngine(t)
	subject := &authz.Subject{ID: "user", TenantID: "tenant-1"}
	env := &authz.Environment{Time: time.Now(), TenantID: "tenant-1"}

	for i := 0; i < 3; i++ {
		resource := &authz.Resource{ID: fmt.Sprintf("doc-%d", i), Type: "document", TenantID: "tenant-1"}
		if _, err := engine.Authorize(context.Background(), subject, "document.read", resource, env); err != nil {
			t.Fatalf("authorize: %v", err)
		}
	}

	entries := waitForAuditLog(t, engine, "tenant-1", 3)
	entries[1].Decision.Reason = "tampered"

	brk, err := engine.VerifyAuditChain(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if brk == nil {
		t.Fatalf("expected chain break after tampering, got none")
	}
	if brk.Index != 1 {
		t.Fatalf("expected break at index 1, got %d", brk.Index)
	}
}

func TestAuditChainDetectsDeletedEntry(t *testing.T) {
	auditStore := stores.NewMemoryAuditStore()
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
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

	subject := &authz.Subject{ID: "user", TenantID: "tenant-1"}
	env := &authz.Environment{Time: time.Now(), TenantID: "tenant-1"}
	for i := 0; i < 3; i++ {
		resource := &authz.Resource{ID: fmt.Sprintf("doc-%d", i), Type: "document", TenantID: "tenant-1"}
		if _, err := engine.Authorize(context.Background(), subject, "document.read", resource, env); err != nil {
			t.Fatalf("authorize: %v", err)
		}
	}
	waitForAuditLog(t, engine, "tenant-1", 3)

	all, err := auditStore.GetAccessLog(context.Background(), authz.AuditFilter{TenantID: "tenant-1", Limit: 1000})
	if err != nil {
		t.Fatalf("get access log: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}

	if err := auditStore.DeleteEntry(all[1].ID); err != nil {
		t.Fatalf("delete entry: %v", err)
	}

	brk, err := engine.VerifyAuditChain(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if brk == nil {
		t.Fatalf("expected chain break after deletion, got none")
	}
	if brk.Index != 1 {
		t.Fatalf("expected break at index 1, got %d", brk.Index)
	}
}
