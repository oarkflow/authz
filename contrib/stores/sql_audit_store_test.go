package stores

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/contrib/sqldriver"
	"github.com/oarkflow/squealx/drivers/sqlite"
)

func TestSQLAuditStoreTraceIDRoundtrip(t *testing.T) {
	db, err := sqlite.Open(":memory:", "sqlite")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := sqldriver.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	store, err := sqldriver.NewSQLAuditStore(db)
	if err != nil {
		t.Fatalf("new audit store: %v", err)
	}

	entry := &authz.AuditEntry{
		ID:        "evt-1",
		Timestamp: time.Now(),
		Subject:   &authz.Subject{ID: "user-x"},
		Action:    authz.Action("read"),
		Resource:  &authz.Resource{ID: "doc-1", TenantID: "tenant-1"},
		Decision:  &authz.Decision{Allowed: true, Reason: "ok", MatchedBy: "policy-1", Timestamp: time.Now()},
		TraceID:   "trace-abc-123",
		Metadata:  map[string]any{"trace_id": "trace-abc-123"},
	}

	if err := store.LogDecision(context.Background(), entry); err != nil {
		t.Fatalf("log decision: %v", err)
	}

	logs, err := store.GetAccessLog(context.Background(), authz.AuditFilter{SubjectID: "user-x", Limit: 10})
	if err != nil {
		t.Fatalf("get access log: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	got := logs[0]
	if got.GetTraceID() != "trace-abc-123" {
		t.Fatalf("expected trace_id=%s got=%s", "trace-abc-123", got.GetTraceID())
	}
}

func TestSQLAuditStoreHashChain(t *testing.T) {
	db, err := sqlite.Open(":memory:", "sqlite")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := sqldriver.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	store, err := sqldriver.NewSQLAuditStore(db)
	if err != nil {
		t.Fatalf("new audit store: %v", err)
	}

	prevHash := ""
	base := time.Now()
	for i := 0; i < 4; i++ {
		entry := &authz.AuditEntry{
			ID:        fmt.Sprintf("evt-%d", i),
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Subject:   &authz.Subject{ID: "user-x", TenantID: "tenant-chain"},
			Action:    authz.Action("read"),
			Resource:  &authz.Resource{ID: fmt.Sprintf("doc-%d", i), TenantID: "tenant-chain"},
			Decision:  &authz.Decision{Allowed: true, Reason: "ok", MatchedBy: "policy-1"},
		}
		entry.PrevHash = prevHash
		hash, err := authz.ComputeAuditEntryHash(entry, prevHash)
		if err != nil {
			t.Fatalf("compute hash: %v", err)
		}
		entry.Hash = hash
		prevHash = hash

		if err := store.LogDecision(context.Background(), entry); err != nil {
			t.Fatalf("log decision: %v", err)
		}
	}

	brk, err := authz.VerifyAuditChain(context.Background(), store, "tenant-chain")
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if brk != nil {
		t.Fatalf("expected intact chain, got break: %+v", brk)
	}

	entries, err := store.GetAccessLog(context.Background(), authz.AuditFilter{TenantID: "tenant-chain", Limit: 100})
	if err != nil {
		t.Fatalf("get access log: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	entries[2].Decision.Reason = "tampered"
	if brk := authz.VerifyAuditEntryChain(entries); brk == nil {
		t.Fatalf("expected chain break after tampering entry 2")
	} else if brk.Index != 2 {
		t.Fatalf("expected break at index 2, got %d", brk.Index)
	}
}
