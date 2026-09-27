package authz

// ============================================================================
// RELATIONSHIP-BASED ACCESS CONTROL (ReBAC) — MINIMAL, ADDITIVE MODULE
// ============================================================================
//
// This file adds an optional, Zanzibar/SpiceDB-inspired relationship-tuple
// model that plugs into Engine.Authorize as one more allow-path, alongside
// the existing ABAC policies, ACLs and RBAC roles. It does NOT replace or
// modify any of that logic; when no RelationshipStore/RelationConfig is
// configured on the Engine, behavior is completely unchanged.
//
// WHAT THIS DOES:
//   - Stores relationship tuples of the form:
//       object_type:object_id#relation@subject_type:subject_id
//       object_type:object_id#relation@subject_type:subject_id#subject_relation
//     e.g. "document:123#viewer@user:alice"
//          "document:123#viewer@group:eng#member"  (subject-set / group indirection)
//   - Resolves a Check(object, relation, subject) query via direct tuple
//     match plus a bounded-depth traversal through subject-set indirection
//     (e.g. "viewer of document:123 includes members of group:eng", and
//     "alice is a member of group:eng" => alice can view document:123).
//   - Lets callers map (action, resourceType) -> required relation(s) via
//     RelationConfig, so Engine.Authorize can decide which relation to check
//     without changing its (ctx, subject, action, resource, env) signature.
//
// WHAT THIS EXPLICITLY DOES NOT DO (yet):
//   - No distributed, consistent, or persistent tuple storage — only an
//     in-memory reference implementation is provided (pkg/stores). A
//     production deployment would need a real backing store (SQL/KV) with
//     transactional writes and a consistency/zookie model like Zanzibar's.
//   - No advanced set-algebra: no intersection, exclusion/subtraction, or
//     "computed userset" rewrite rules like SpiceDB's schema language.
//     Only union of direct tuples and subject-set indirection is supported.
//   - No caching/indexing beyond whatever the RelationshipStore implementation
//     chooses to do internally; large graphs may be slow to traverse.
//   - No wildcard/public subjects (e.g. "user:*") and no negation.
//
// This is intended as a first, extensible step so relationship-based checks
// can be introduced incrementally without disturbing the existing engine.

import (
	"context"
	"fmt"
)

// RelationTuple is a single ReBAC relationship fact:
// "SubjectType:SubjectID[#SubjectRelation] has relation Relation to ObjectType:ObjectID".
//
// When SubjectRelation is empty, the tuple is a direct subject tuple, e.g.
// document:123#viewer@user:alice.
//
// When SubjectRelation is set, the tuple denotes a subject set (group-based
// indirection), e.g. document:123#viewer@group:eng#member means "everyone
// who has relation 'member' on group:eng is a viewer of document:123".
type RelationTuple struct {
	ObjectType      string
	ObjectID        string
	Relation        string
	SubjectType     string
	SubjectID       string
	SubjectRelation string
}

// String renders the tuple in Zanzibar-style notation, mainly for logging/debugging.
func (t RelationTuple) String() string {
	subj := fmt.Sprintf("%s:%s", t.SubjectType, t.SubjectID)
	if t.SubjectRelation != "" {
		subj = fmt.Sprintf("%s#%s", subj, t.SubjectRelation)
	}
	return fmt.Sprintf("%s:%s#%s@%s", t.ObjectType, t.ObjectID, t.Relation, subj)
}

// objectKey/subjectKey are convenience helpers used by store implementations.
func (t RelationTuple) objectKey() string {
	return t.ObjectType + ":" + t.ObjectID
}

func (t RelationTuple) subjectKey() string {
	return t.SubjectType + ":" + t.SubjectID
}

// maxRelationDepth bounds the subject-set traversal to prevent cycles and
// runaway graph walks (e.g. group A -> group B -> group A).
const maxRelationDepth = 10

// RelationshipStore persists and queries relationship tuples.
//
// Check performs graph resolution: it returns true if there is a direct
// tuple matching (object, relation, subject), or if the subject is reachable
// through subject-set indirection (e.g. group membership) within
// maxRelationDepth hops.
type RelationshipStore interface {
	WriteTuple(ctx context.Context, tuple RelationTuple) error
	DeleteTuple(ctx context.Context, tuple RelationTuple) error

	// ReadTuples returns tuples matching the given non-empty filter fields.
	// Any of objectType/objectID/relation/subjectType/subjectID may be left
	// empty ("") to mean "any".
	ReadTuples(ctx context.Context, objectType, objectID, relation, subjectType, subjectID string) ([]RelationTuple, error)

	Check(ctx context.Context, objectType, objectID, relation, subjectType, subjectID string) (bool, error)
}

// RelationConfig maps a (action, resourceType) pair to the set of relations
// that satisfy it. If a subject has ANY of the configured relations to the
// resource, the action is allowed.
//
// Example: RelationConfig{{"read", "document"}: {"viewer", "editor", "owner"}}
// means reading a document requires the subject to be a viewer, editor, or
// owner of it (directly or via subject-set indirection).
type RelationConfig struct {
	rules map[relationRuleKey][]string
}

type relationRuleKey struct {
	action       string
	resourceType string
}

// NewRelationConfig creates an empty relation configuration.
func NewRelationConfig() *RelationConfig {
	return &RelationConfig{rules: make(map[relationRuleKey][]string)}
}

// Require registers that performing `action` on resources of `resourceType`
// is granted if the subject holds any of `relations` to the resource.
func (c *RelationConfig) Require(action Action, resourceType string, relations ...string) *RelationConfig {
	if c.rules == nil {
		c.rules = make(map[relationRuleKey][]string)
	}
	c.rules[relationRuleKey{action: string(action), resourceType: resourceType}] = relations
	return c
}

// relationsFor returns the relations required for (action, resourceType),
// and whether a rule was configured at all.
func (c *RelationConfig) relationsFor(action Action, resourceType string) ([]string, bool) {
	if c == nil || c.rules == nil {
		return nil, false
	}
	rels, ok := c.rules[relationRuleKey{action: string(action), resourceType: resourceType}]
	return rels, ok
}

// WithRelationshipStore wires an optional ReBAC allow-path into the Engine.
// When both store and config are non-nil, Engine.Authorize will, as one more
// allow source (checked alongside ACL/ABAC/RBAC), look up which relation(s)
// are required for the requested (action, resource.Type) via config and ask
// the store whether the subject holds one of those relations to the
// resource. It does not affect any deny path or any other allow path.
func WithRelationshipStore(store RelationshipStore, config *RelationConfig) EngineOption {
	return func(e *Engine) error {
		e.relationshipStore = store
		e.relationConfig = config
		return nil
	}
}

// checkRelationships is the ReBAC allow-path check used by Engine.Authorize.
// It returns (allowed, matchedRelation).
func (e *Engine) checkRelationships(ctx context.Context, subject *Subject, action Action, resource *Resource) (bool, string) {
	if e.relationshipStore == nil || e.relationConfig == nil || subject == nil || resource == nil {
		return false, ""
	}
	relations, ok := e.relationConfig.relationsFor(action, resource.Type)
	if !ok || len(relations) == 0 {
		return false, ""
	}
	subjectType := subject.Type
	if subjectType == "" {
		subjectType = "user"
	}
	for _, relation := range relations {
		allowed, err := e.relationshipStore.Check(ctx, resource.Type, resource.ID, relation, subjectType, subject.ID)
		if err == nil && allowed {
			return true, relation
		}
	}
	return false, ""
}
