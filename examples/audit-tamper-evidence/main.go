// Command audit-tamper-evidence demonstrates the tamper-evident (hash-chained)
// audit trail built into the authz engine.
//
// Every AuditEntry the engine writes carries a PrevHash and a Hash field that
// together form a per-tenant SHA-256 hash chain: each entry's Hash covers its
// own content plus the previous entry's Hash. That means any out-of-band
// mutation or deletion of an audit row - for example a raw SQL UPDATE/DELETE
// run directly against the audit table, bypassing the engine entirely - will
// break the chain from that point forward, and VerifyAuditChain will detect
// exactly where.
//
// This example:
//  1. Makes several real Authorize calls against different resources so the
//     engine writes multiple chained audit entries.
//  2. Verifies the chain is intact.
//  3. Tampers with a fetched entry's Decision.Reason in place and re-verifies,
//     showing the break that is detected.
//  4. Deletes a middle entry directly from the store (simulating an
//     out-of-band DB delete) and re-verifies, showing the resulting gap.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

const tenantID = "tenant-1"

func main() {
	ctx := context.Background()

	fmt.Println("=== Tamper-Evident Audit Trail Example ===")
	fmt.Println()

	// --- 1. Set up an engine backed entirely by in-memory stores ---
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()

	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore)

	policy := &authz.Policy{
		ID:        "policy-allow-read",
		TenantID:  tenantID,
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"document.read"},
		Resources: []string{"document:*"},
		Condition: &authz.TrueExpr{},
		Priority:  1,
		Enabled:   true,
	}
	if err := engine.CreatePolicy(ctx, policy); err != nil {
		panic(fmt.Sprintf("create policy: %v", err))
	}
	if err := engine.ReloadPolicies(ctx, tenantID); err != nil {
		panic(fmt.Sprintf("reload policies: %v", err))
	}

	subject := &authz.Subject{ID: "user-alice", TenantID: tenantID}
	env := &authz.Environment{Time: time.Now(), TenantID: tenantID}

	// --- Make several real Authorize calls against DIFFERENT resources. ---
	// The decision cache would skip audit logging for repeated identical
	// requests, so each call below targets a distinct resource ID to ensure
	// a fresh audit entry - and a fresh link in the hash chain - is written
	// each time.
	const numRequests = 5
	fmt.Printf("Making %d authorize calls against distinct resources...\n", numRequests)
	for i := 0; i < numRequests; i++ {
		resource := &authz.Resource{ID: fmt.Sprintf("doc-%d", i), Type: "document", TenantID: tenantID}
		decision, err := engine.Authorize(ctx, subject, "document.read", resource, env)
		if err != nil {
			panic(fmt.Sprintf("authorize: %v", err))
		}
		fmt.Printf("  - document.read on doc-%d: allowed=%v\n", i, decision.Allowed)
	}

	// Audit entries are flushed to the store asynchronously by a background
	// batch worker, so poll briefly until they show up.
	entries := waitForAuditEntries(ctx, engine, numRequests)
	fmt.Printf("Audit store now holds %d chained entries.\n", len(entries))
	fmt.Println()

	// --- 2. Verify the chain is intact. ---
	fmt.Println("--- Step 1: Verify the freshly written chain ---")
	verifyAndReport(ctx, engine)
	fmt.Println()

	// --- 3. Tamper with an entry in place and re-verify. ---
	fmt.Println("--- Step 2: Tamper with a stored entry's Decision.Reason in place ---")
	entries = fetchEntries(ctx, engine)
	tamperedIndex := 1
	original := entries[tamperedIndex].Decision.Reason
	entries[tamperedIndex].Decision.Reason = "tampered"
	fmt.Printf("Mutated entry index %d (id=%s): Decision.Reason %q -> %q\n",
		tamperedIndex, entries[tamperedIndex].ID, original, entries[tamperedIndex].Decision.Reason)
	verifyAndReport(ctx, engine)
	fmt.Println()

	// Restart clean for the deletion scenario so the break we report next is
	// solely due to deletion, not the mutation above (both mutate the entry
	// stored in the in-memory slice since MemoryAuditStore returns pointers
	// to its underlying entries).
	entries[tamperedIndex].Decision.Reason = original

	// --- 4. Delete a middle entry directly from the store (simulating an
	// out-of-band DB DELETE) and re-verify. ---
	fmt.Println("--- Step 3: Delete a middle entry directly from the audit store ---")
	deletedEntry := entries[2]
	fmt.Printf("Deleting entry index 2 (id=%s) directly via MemoryAuditStore.DeleteEntry, bypassing the engine.\n", deletedEntry.ID)
	if err := auditStore.DeleteEntry(deletedEntry.ID); err != nil {
		panic(fmt.Sprintf("delete entry: %v", err))
	}
	verifyAndReport(ctx, engine)
	fmt.Println()

	// --- 5. Compliance takeaway. ---
	fmt.Println("=== Compliance point ===")
	fmt.Println("Because each entry's Hash covers its own content plus the previous")
	fmt.Println("entry's Hash, any out-of-band mutation or deletion of audit rows -")
	fmt.Println("whether from a rogue admin, a buggy migration, or a direct SQL")
	fmt.Println("statement against the audit table - is detectable by re-running")
	fmt.Println("VerifyAuditChain. The audit trail cannot be silently altered without")
	fmt.Println("leaving cryptographic evidence of exactly where the break occurred.")
}

// waitForAuditEntries polls the engine's audit log until at least `want`
// entries are visible, since the engine batches audit writes asynchronously.
func waitForAuditEntries(ctx context.Context, engine *authz.Engine, want int) []*authz.AuditEntry {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := engine.GetAccessLog(ctx, authz.AuditFilter{TenantID: tenantID, Limit: 1000})
		if err != nil {
			panic(fmt.Sprintf("get access log: %v", err))
		}
		if len(entries) >= want {
			return entries
		}
		time.Sleep(5 * time.Millisecond)
	}
	panic("timed out waiting for audit entries to flush")
}

// fetchEntries returns the tenant's audit entries in the order they were
// originally written (oldest first), matching what VerifyAuditChain expects.
func fetchEntries(ctx context.Context, engine *authz.Engine) []*authz.AuditEntry {
	entries, err := engine.GetAccessLog(ctx, authz.AuditFilter{TenantID: tenantID, Limit: 1000})
	if err != nil {
		panic(fmt.Sprintf("get access log: %v", err))
	}
	return entries
}

// verifyAndReport calls Engine.VerifyAuditChain and prints a human-readable
// summary of the result.
func verifyAndReport(ctx context.Context, engine *authz.Engine) {
	brk, err := engine.VerifyAuditChain(ctx, tenantID)
	if err != nil {
		panic(fmt.Sprintf("verify audit chain: %v", err))
	}
	if brk == nil {
		fmt.Println("VerifyAuditChain: chain is intact - no tampering detected.")
		return
	}
	fmt.Printf("VerifyAuditChain: BROKEN CHAIN DETECTED at index %d (entry id=%s)\n", brk.Index, brk.EntryID)
	fmt.Printf("  reason:   %s\n", brk.Reason)
	fmt.Printf("  expected: %s\n", brk.Expected)
	fmt.Printf("  actual:   %s\n", brk.Actual)
}
