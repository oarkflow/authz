package authz_test

import (
	"context"
	"testing"
	"time"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func newRelEngine(t *testing.T, relStore authz.RelationshipStore, cfg *authz.RelationConfig) *authz.Engine {
	t.Helper()
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()

	return authz.NewEngine(policyStore, roleStore, aclStore, auditStore,
		authz.WithRelationshipStore(relStore, cfg),
	)
}

func relSubject(id string) *authz.Subject {
	return &authz.Subject{ID: id, Type: "user", TenantID: "t1"}
}

func relResource(id string) *authz.Resource {
	return &authz.Resource{ID: id, Type: "document", TenantID: "t1"}
}

func relEnv() *authz.Environment {
	return &authz.Environment{TenantID: "t1"}
}

func TestRelationships_DirectTupleGrantsAccess(t *testing.T) {
	store := stores.NewMemoryRelationshipStore()
	cfg := authz.NewRelationConfig().Require("read", "document", "viewer", "owner")
	engine := newRelEngine(t, store, cfg)

	if err := store.WriteTuple(context.Background(), authz.RelationTuple{
		ObjectType: "document", ObjectID: "doc1", Relation: "viewer",
		SubjectType: "user", SubjectID: "alice",
	}); err != nil {
		t.Fatalf("write tuple: %v", err)
	}

	decision, err := engine.Authorize(context.Background(), relSubject("alice"), authz.Action("read"), relResource("doc1"), relEnv())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow, got deny: %+v", decision)
	}
	if decision.Reason != "relationship allow" {
		t.Fatalf("expected relationship allow reason, got %q", decision.Reason)
	}
}

func TestRelationships_MissingTupleDenies(t *testing.T) {
	store := stores.NewMemoryRelationshipStore()
	cfg := authz.NewRelationConfig().Require("read", "document", "viewer", "owner")
	engine := newRelEngine(t, store, cfg)

	decision, err := engine.Authorize(context.Background(), relSubject("bob"), authz.Action("read"), relResource("doc1"), relEnv())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected deny, got allow: %+v", decision)
	}
}

func TestRelationships_SubjectSetIndirectionGrantsAccess(t *testing.T) {
	store := stores.NewMemoryRelationshipStore()
	cfg := authz.NewRelationConfig().Require("read", "document", "viewer", "owner")
	engine := newRelEngine(t, store, cfg)
	ctx := context.Background()

	// document:doc1#viewer@group:eng#member -- members of group:eng can view doc1
	if err := store.WriteTuple(ctx, authz.RelationTuple{
		ObjectType: "document", ObjectID: "doc1", Relation: "viewer",
		SubjectType: "group", SubjectID: "eng", SubjectRelation: "member",
	}); err != nil {
		t.Fatalf("write tuple: %v", err)
	}
	// group:eng#member@user:carol -- carol is a member of group:eng
	if err := store.WriteTuple(ctx, authz.RelationTuple{
		ObjectType: "group", ObjectID: "eng", Relation: "member",
		SubjectType: "user", SubjectID: "carol",
	}); err != nil {
		t.Fatalf("write tuple: %v", err)
	}

	decision, err := engine.Authorize(ctx, relSubject("carol"), authz.Action("read"), relResource("doc1"), relEnv())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow via group indirection, got deny: %+v", decision)
	}

	// someone not in the group should still be denied
	decision, err = engine.Authorize(ctx, relSubject("dave"), authz.Action("read"), relResource("doc1"), relEnv())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected deny for non-member, got allow: %+v", decision)
	}
}

func TestRelationships_CycleProtectionDoesNotHang(t *testing.T) {
	store := stores.NewMemoryRelationshipStore()
	ctx := context.Background()

	// group:a#member@group:b#member and group:b#member@group:a#member form a cycle
	if err := store.WriteTuple(ctx, authz.RelationTuple{
		ObjectType: "group", ObjectID: "a", Relation: "member",
		SubjectType: "group", SubjectID: "b", SubjectRelation: "member",
	}); err != nil {
		t.Fatalf("write tuple: %v", err)
	}
	if err := store.WriteTuple(ctx, authz.RelationTuple{
		ObjectType: "group", ObjectID: "b", Relation: "member",
		SubjectType: "group", SubjectID: "a", SubjectRelation: "member",
	}); err != nil {
		t.Fatalf("write tuple: %v", err)
	}

	done := make(chan bool, 1)
	go func() {
		allowed, err := store.Check(ctx, "group", "a", "member", "user", "zoe")
		if err != nil {
			t.Errorf("check: %v", err)
		}
		done <- allowed
	}()

	select {
	case allowed := <-done:
		if allowed {
			t.Fatalf("expected no path to resolve for unrelated subject in a cycle")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Check did not return, likely stuck in a cycle")
	}
}

func TestRelationships_TupleDeletionRevokesAccess(t *testing.T) {
	store := stores.NewMemoryRelationshipStore()
	cfg := authz.NewRelationConfig().Require("read", "document", "viewer", "owner")
	engine := newRelEngine(t, store, cfg)
	ctx := context.Background()

	tuple := authz.RelationTuple{
		ObjectType: "document", ObjectID: "doc1", Relation: "viewer",
		SubjectType: "user", SubjectID: "alice",
	}
	if err := store.WriteTuple(ctx, tuple); err != nil {
		t.Fatalf("write tuple: %v", err)
	}

	decision, err := engine.Authorize(ctx, relSubject("alice"), authz.Action("read"), relResource("doc1"), relEnv())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow before deletion: %+v", decision)
	}

	if err := store.DeleteTuple(ctx, tuple); err != nil {
		t.Fatalf("delete tuple: %v", err)
	}
	// decision cache has a short TTL and keys on subject/action/resource/env;
	// invalidate to make sure we observe the deletion immediately in this test.
	engine.InvalidateDecisionCache()

	decision, err = engine.Authorize(ctx, relSubject("alice"), authz.Action("read"), relResource("doc1"), relEnv())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected deny after tuple deletion: %+v", decision)
	}
}
