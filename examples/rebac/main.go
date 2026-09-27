// Command rebac demonstrates Relationship-Based Access Control (ReBAC) --
// a Zanzibar/SpiceDB-inspired relationship-tuple model that plugs into
// Engine.Authorize as one more allow-path, alongside the existing ABAC
// policies, ACLs and RBAC roles.
//
// It shows:
//  1. Wiring a RelationshipStore + RelationConfig into an Engine.
//  2. A direct relationship tuple ("document:123#viewer@user:alice")
//     granting access -- denied before the tuple exists, allowed after.
//  3. Subject-set (group) indirection -- a tuple granting a group "viewer"
//     access, plus a membership tuple, giving a group member transitive
//     access while a non-member stays denied.
//  4. Revocation via DeleteTuple, immediately removing access.
//  5. Inspecting Decision.Reason / Decision.Trace to see "relationship
//     allow" show up explicitly.
package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func main() {
	ctx := context.Background()

	fmt.Println("=== ReBAC (Relationship-Based Access Control) Example ===")

	// ------------------------------------------------------------------
	// 1. Set up an Engine with a RelationshipStore and RelationConfig,
	//    in addition to the usual policy/role/ACL/audit stores.
	// ------------------------------------------------------------------
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	relStore := stores.NewMemoryRelationshipStore()

	// RelationConfig maps (action, resourceType) -> the relation(s) that
	// satisfy it. Reading a document is granted to viewers, editors or
	// owners of that document (directly, or transitively via a group).
	relConfig := authz.NewRelationConfig().
		Require("read", "document", "viewer", "editor", "owner")

	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore,
		authz.WithRelationshipStore(relStore, relConfig),
	)

	alice := &authz.Subject{ID: "alice", Type: "user", TenantID: "t1"}
	carol := &authz.Subject{ID: "carol", Type: "user", TenantID: "t1"}
	dave := &authz.Subject{ID: "dave", Type: "user", TenantID: "t1"}
	doc123 := &authz.Resource{ID: "123", Type: "document", TenantID: "t1"}
	env := &authz.Environment{TenantID: "t1"}

	// ------------------------------------------------------------------
	// 2. Direct relationship tuple.
	// ------------------------------------------------------------------
	fmt.Println("\n--- Step 1: Direct relationship tuple ---")
	fmt.Println("Checking whether alice can read document:123 BEFORE any tuple exists...")

	decision, err := engine.Authorize(ctx, alice, "read", doc123, env)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Allowed: %v (reason: %q)\n", decision.Allowed, decision.Reason)

	fmt.Println("\nWriting tuple: document:123#viewer@user:alice ...")
	tuple := authz.RelationTuple{
		ObjectType: "document", ObjectID: "123",
		Relation:    "viewer",
		SubjectType: "user", SubjectID: "alice",
	}
	if err := relStore.WriteTuple(ctx, tuple); err != nil {
		panic(err)
	}
	fmt.Printf("Tuple written: %s\n", tuple.String())
	// The engine caches decisions with a short TTL keyed on
	// subject/action/resource/env, so invalidate the cache to make sure we
	// observe the newly-written tuple immediately rather than the stale
	// cached "deny" from the check above.
	engine.InvalidateDecisionCache()

	fmt.Println("Checking again whether alice can read document:123 AFTER the tuple exists...")
	decision, err = engine.Authorize(ctx, alice, "read", doc123, env)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Allowed: %v (reason: %q, matched by: %q)\n", decision.Allowed, decision.Reason, decision.MatchedBy)

	// ------------------------------------------------------------------
	// 3. Subject-set (group) indirection.
	// ------------------------------------------------------------------
	fmt.Println("\n--- Step 2: Subject-set (group) indirection ---")
	fmt.Println("Writing tuple: document:123#viewer@group:eng#member")
	fmt.Println("  (\"anyone who has relation 'member' on group:eng is a viewer of document:123\")")
	groupTuple := authz.RelationTuple{
		ObjectType: "document", ObjectID: "123",
		Relation:    "viewer",
		SubjectType: "group", SubjectID: "eng", SubjectRelation: "member",
	}
	if err := relStore.WriteTuple(ctx, groupTuple); err != nil {
		panic(err)
	}
	fmt.Printf("Tuple written: %s\n", groupTuple.String())

	fmt.Println("Writing tuple: group:eng#member@user:carol (carol joins group:eng)")
	membershipTuple := authz.RelationTuple{
		ObjectType: "group", ObjectID: "eng",
		Relation:    "member",
		SubjectType: "user", SubjectID: "carol",
	}
	if err := relStore.WriteTuple(ctx, membershipTuple); err != nil {
		panic(err)
	}
	fmt.Printf("Tuple written: %s\n", membershipTuple.String())

	fmt.Println("\nChecking whether carol (a group:eng member) can read document:123...")
	decision, err = engine.Authorize(ctx, carol, "read", doc123, env)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Allowed: %v (reason: %q) -- transitive access via group membership\n", decision.Allowed, decision.Reason)

	fmt.Println("\nChecking whether dave (NOT a group:eng member) can read document:123...")
	decision, err = engine.Authorize(ctx, dave, "read", doc123, env)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Allowed: %v (reason: %q) -- correctly denied, dave has no path to viewer\n", decision.Allowed, decision.Reason)

	// ------------------------------------------------------------------
	// 4. Revocation.
	// ------------------------------------------------------------------
	fmt.Println("\n--- Step 3: Revocation ---")
	fmt.Println("Deleting tuple: document:123#viewer@user:alice ...")
	if err := relStore.DeleteTuple(ctx, tuple); err != nil {
		panic(err)
	}
	// The engine caches decisions with a short TTL keyed on
	// subject/action/resource/env, so invalidate the cache to observe the
	// revocation immediately (same pattern used in relationships_test.go).
	engine.InvalidateDecisionCache()

	fmt.Println("Checking whether alice can still read document:123 after revocation...")
	decision, err = engine.Authorize(ctx, alice, "read", doc123, env)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Allowed: %v (reason: %q) -- alice's direct viewer grant was revoked\n", decision.Allowed, decision.Reason)

	// ------------------------------------------------------------------
	// 5. Inspect the decision trace for a still-allowed request (carol,
	//    via group indirection) to see "relationship allow" appear.
	// ------------------------------------------------------------------
	fmt.Println("\n--- Step 4: Decision trace ---")
	explanation, err := engine.Explain(ctx, carol, "read", doc123, env)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Final decision for carol: allowed=%v reason=%q matchedBy=%q\n",
		explanation.Allowed, explanation.Reason, explanation.MatchedBy)
	fmt.Println("Trace:")
	for _, line := range explanation.Trace {
		fmt.Printf("  - %s\n", line)
	}

	fmt.Println("\n=== Done ===")
}
