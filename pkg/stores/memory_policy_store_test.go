package stores

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/authz"
)

// TestMemoryPolicyStore_History verifies that the in-memory policy store
// tracks a version history per policy, mirroring the SQL policy store's
// insertPolicyHistory/GetPolicyHistory contract: each UpdatePolicy call
// appends a snapshot of the pre-update state, and GetPolicyHistory returns
// those snapshots in chronological order.
func TestMemoryPolicyStore_History(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPolicyStore()

	policy := &authz.Policy{
		ID:       "history-policy-1",
		TenantID: "tenant-1",
		Effect:   authz.EffectAllow,
		Actions:  []authz.Action{"read"},
		Version:  1,
		Enabled:  true,
	}

	if err := store.CreatePolicy(ctx, policy); err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	// No history should exist yet since the policy was only just created.
	if _, err := store.GetPolicyHistory(ctx, policy.ID); err == nil {
		t.Fatalf("expected no history immediately after creation")
	}

	// First update: bump version like Engine.UpdatePolicy does, then persist.
	policy.Version = 2
	policy.Actions = []authz.Action{"read", "write"}
	if err := store.UpdatePolicy(ctx, policy); err != nil {
		t.Fatalf("first UpdatePolicy failed: %v", err)
	}

	time.Sleep(time.Millisecond) // ensure distinguishable timestamps

	// Second update.
	policy.Version = 3
	policy.Actions = []authz.Action{"read", "write", "delete"}
	if err := store.UpdatePolicy(ctx, policy); err != nil {
		t.Fatalf("second UpdatePolicy failed: %v", err)
	}

	history, err := store.GetPolicyHistory(ctx, policy.ID)
	if err != nil {
		t.Fatalf("GetPolicyHistory failed: %v", err)
	}

	if len(history) != 2 {
		t.Fatalf("expected 2 history entries after 2 updates, got %d", len(history))
	}

	// Entries are pre-update snapshots, recorded in chronological order.
	if history[0].Version != 1 {
		t.Errorf("expected first history entry version 1, got %d", history[0].Version)
	}
	if history[1].Version != 2 {
		t.Errorf("expected second history entry version 2, got %d", history[1].Version)
	}

	if history[0].CreatedAt.IsZero() {
		t.Errorf("expected first history entry to carry a non-zero CreatedAt")
	}
	if history[1].UpdatedAt.Before(history[0].UpdatedAt) {
		t.Errorf("expected history entries' UpdatedAt to be non-decreasing: got %v then %v", history[0].UpdatedAt, history[1].UpdatedAt)
	}

	// The live policy itself should reflect the latest version, unaffected
	// by the history bookkeeping.
	current, err := store.GetPolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if current.Version != 3 {
		t.Errorf("expected current policy version 3, got %d", current.Version)
	}
}

// TestMemoryPolicyStore_UpdateDoesNotDoubleIncrementVersion guards against a
// regression where the store itself bumped Version in addition to the
// caller (Engine.UpdatePolicy), which would cause versions to skip.
func TestMemoryPolicyStore_UpdateDoesNotDoubleIncrementVersion(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPolicyStore()

	policy := &authz.Policy{ID: "history-policy-2", Effect: authz.EffectAllow, Version: 1}
	if err := store.CreatePolicy(ctx, policy); err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}

	policy.Version = 2 // simulate the single increment Engine.UpdatePolicy performs
	if err := store.UpdatePolicy(ctx, policy); err != nil {
		t.Fatalf("UpdatePolicy failed: %v", err)
	}

	got, err := store.GetPolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	if got.Version != 2 {
		t.Fatalf("expected version 2 after a single caller-driven increment, got %d", got.Version)
	}
}

// TestMemoryPolicyStore_HistoryUnknownPolicy verifies the error contract for
// an id that has never been updated.
func TestMemoryPolicyStore_HistoryUnknownPolicy(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPolicyStore()
	if _, err := store.GetPolicyHistory(ctx, "does-not-exist"); err == nil {
		t.Fatalf("expected an error for a policy id with no history")
	}
}
