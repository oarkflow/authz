// Command delegation-breakglass demonstrates two enterprise IAM primitives
// added on top of the normal Authorize decision tree:
//
//  1. Delegation: one subject (the delegator) hands a bounded, time-boxed set
//     of actions on a resource pattern to another subject (the delegate),
//     with a hard guarantee that a subject can never delegate a permission
//     it does not itself hold.
//  2. Break-glass / emergency access: a deliberately separate, always-allow
//     method that requires a justification and writes a high-visibility,
//     synchronously-recorded audit entry.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func main() {
	ctx := context.Background()

	// ------------------------------------------------------------------
	// 1. Set up an Engine with a DelegationStore, plus a real ABAC policy
	//    so "alice" genuinely has read/approve access to a document before
	//    she tries to delegate any of it.
	// ------------------------------------------------------------------
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	delegationStore := stores.NewMemoryDelegationStore()

	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore,
		authz.WithDelegationStore(delegationStore),
	)

	tenant := "tenant-a"
	alice := &authz.Subject{ID: "alice", TenantID: tenant}
	bob := &authz.Subject{ID: "bob", TenantID: tenant}
	mallory := &authz.Subject{ID: "mallory", TenantID: tenant}

	document := &authz.Resource{ID: "123", Type: "document", TenantID: tenant}
	now := time.Now()
	env := &authz.Environment{Time: now, TenantID: tenant}

	// Give alice real, direct authority over document:123 via an ACL grant
	// (a normal RBAC role or ABAC policy would work just as well).
	if err := engine.GrantACL(ctx, &authz.ACL{
		ID:         "acl-alice-doc123",
		TenantID:   tenant,
		ResourceID: "document:123",
		SubjectID:  alice.ID,
		Actions:    []authz.Action{"read", "approve"},
		Effect:     authz.EffectAllow,
	}); err != nil {
		fmt.Printf("unexpected error granting ACL to alice: %v\n", err)
		return
	}

	aliceDecision, err := engine.Authorize(ctx, alice, "read", document, env)
	if err != nil {
		fmt.Printf("unexpected error authorizing alice: %v\n", err)
		return
	}
	fmt.Printf("Step 1: alice has direct 'read' access on document:123 via ACL -> allowed=%v (reason=%q)\n\n",
		aliceDecision.Allowed, aliceDecision.Reason)

	// ------------------------------------------------------------------
	// 2. alice delegates "read" on document:123 to bob for the next 24
	//    hours. CreateDelegation checks alice's own authority for every
	//    delegated action before persisting the grant. ("approve" is left
	//    out of this grant deliberately so step 4 below can demonstrate a
	//    separate, already-expired grant for it without the still-active
	//    "read" grant masking the result.)
	// ------------------------------------------------------------------
	grant, err := engine.CreateDelegation(ctx, alice, bob,
		[]authz.Action{"read"},
		"document:123",
		now.Add(-time.Minute), // already started
		now.Add(24*time.Hour), // expires in 24h
		0,                     // unlimited uses
	)
	if err != nil {
		fmt.Printf("unexpected error creating delegation: %v\n", err)
		return
	}
	fmt.Printf("Step 2: alice delegated [read] on document:123 to bob (grant id=%s)\n", grant.ID)

	bobDecision, err := engine.Authorize(ctx, bob, "read", document, env)
	if err != nil {
		fmt.Printf("unexpected error authorizing bob: %v\n", err)
		return
	}
	fmt.Printf("bob authorized to 'read' document:123 via delegation -> allowed=%v (reason=%q)\n\n",
		bobDecision.Allowed, bobDecision.Reason)

	// ------------------------------------------------------------------
	// 3. Capability-amplification guard: mallory has no permission on
	//    document:123 at all, so alice (or anyone) trying to have mallory
	//    delegate something she doesn't have must be refused. Here we show
	//    the guard from the delegator's side: mallory herself cannot
	//    delegate a permission she was never granted.
	// ------------------------------------------------------------------
	_, err = engine.CreateDelegation(ctx, mallory, bob,
		[]authz.Action{"read"},
		"document:123",
		now,
		now.Add(24*time.Hour),
		0,
	)
	if err == nil {
		fmt.Println("Step 3: UNEXPECTED - mallory was allowed to delegate a permission she does not have")
	} else {
		fmt.Printf("Step 3: mallory (no permission on document:123) tried to delegate 'read' -> refused as expected: %v\n\n", err)
	}

	// ------------------------------------------------------------------
	// 4. Time-boxed grant: create a delegation that has already expired,
	//    and show Authorize denies it despite it existing.
	// ------------------------------------------------------------------
	expiredGrant, err := engine.CreateDelegation(ctx, alice, bob,
		[]authz.Action{"approve"},
		"document:123",
		now.Add(-2*time.Hour),
		now.Add(-time.Hour), // expired one hour ago
		0,
	)
	if err != nil {
		fmt.Printf("unexpected error creating expired delegation: %v\n", err)
		return
	}
	expiredDecision, err := engine.Authorize(ctx, bob, "approve", document, env)
	if err != nil {
		fmt.Printf("unexpected error authorizing bob for approve: %v\n", err)
		return
	}
	fmt.Printf("Step 4: expired delegation (id=%s, expired 1h ago) for 'approve' -> allowed=%v (reason=%q)\n\n",
		expiredGrant.ID, expiredDecision.Allowed, expiredDecision.Reason)

	// ------------------------------------------------------------------
	// 5. RevokeDelegation cuts off access immediately, even mid-window.
	// ------------------------------------------------------------------
	beforeRevoke, err := engine.Authorize(ctx, bob, "read", document, env)
	if err != nil {
		fmt.Printf("unexpected error authorizing bob: %v\n", err)
		return
	}
	fmt.Printf("Step 5: bob's 'read' access before revocation -> allowed=%v\n", beforeRevoke.Allowed)

	if err := engine.RevokeDelegation(ctx, alice, grant.ID); err != nil {
		fmt.Printf("unexpected error revoking delegation: %v\n", err)
		return
	}
	afterRevoke, err := engine.Authorize(ctx, bob, "read", document, env)
	if err != nil {
		fmt.Printf("unexpected error authorizing bob: %v\n", err)
		return
	}
	fmt.Printf("bob's 'read' access after alice revokes the grant -> allowed=%v (reason=%q)\n\n",
		afterRevoke.Allowed, afterRevoke.Reason)

	// ------------------------------------------------------------------
	// 6. Break-glass / emergency access.
	// ------------------------------------------------------------------
	oncall := &authz.Subject{ID: "oncall-eng", TenantID: tenant}

	// First, confirm normal Authorize denies this: oncall-eng has no role,
	// ACL, policy, or delegation granting "delete" on document:123.
	normalDecision, err := engine.Authorize(ctx, oncall, "delete", document, env)
	if err != nil {
		fmt.Printf("unexpected error authorizing oncall-eng: %v\n", err)
		return
	}
	fmt.Printf("Step 6: normal Authorize for oncall-eng 'delete' on document:123 -> allowed=%v (would be denied without break-glass)\n",
		normalDecision.Allowed)

	// Empty justification is rejected outright.
	if _, err := engine.AuthorizeBreakGlass(ctx, oncall, "delete", document, env, ""); err != nil {
		fmt.Printf("AuthorizeBreakGlass with empty justification -> refused as expected: %v\n", err)
	} else {
		fmt.Println("UNEXPECTED - break-glass access was granted without a justification")
	}

	// With a justification, break-glass access is always granted (fail-open
	// by design) and produces a flagged, synchronously-written audit entry.
	justification := "production incident INC-4821, need emergency delete to unblock rollback"
	bgDecision, err := engine.AuthorizeBreakGlass(ctx, oncall, "delete", document, env, justification)
	if err != nil {
		fmt.Printf("unexpected error on break-glass access: %v\n", err)
		return
	}
	fmt.Printf("AuthorizeBreakGlass for oncall-eng 'delete' on document:123 -> allowed=%v (reason=%q)\n\n",
		bgDecision.Allowed, bgDecision.Reason)

	// Show the flagged audit entry that was written for the break-glass
	// invocation: the action is recorded as authz.BreakGlassAction, not
	// "delete", and carries break_glass/justification metadata.
	logs, err := auditStore.GetAccessLog(ctx, authz.AuditFilter{SubjectID: oncall.ID})
	if err != nil {
		fmt.Printf("unexpected error reading audit log: %v\n", err)
		return
	}
	for _, entry := range logs {
		if entry.Action != authz.BreakGlassAction {
			continue
		}
		fmt.Printf("Flagged audit entry found: action=%s break_glass=%v flagged=%v justification=%q original_action=%v\n",
			entry.Action, entry.Metadata["break_glass"], entry.Metadata["flagged"],
			entry.Metadata["justification"], entry.Metadata["original_action"])
	}
}
