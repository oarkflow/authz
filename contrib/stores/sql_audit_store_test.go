package stores

import (
	"context"
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
