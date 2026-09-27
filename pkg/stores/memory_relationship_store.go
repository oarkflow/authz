package stores

import (
	"context"
	"sync"

	"github.com/oarkflow/authz"
)

// MemoryRelationshipStore is an in-memory implementation of
// authz.RelationshipStore, intended for tests, examples and small
// deployments. It is not distributed and holds no persistence guarantees.
type MemoryRelationshipStore struct {
	mu     sync.RWMutex
	tuples map[string]authz.RelationTuple // tupleKey -> tuple
}

// NewMemoryRelationshipStore creates an empty in-memory relationship store.
func NewMemoryRelationshipStore() *MemoryRelationshipStore {
	return &MemoryRelationshipStore{tuples: make(map[string]authz.RelationTuple)}
}

func tupleKey(t authz.RelationTuple) string {
	return t.ObjectType + "\x00" + t.ObjectID + "\x00" + t.Relation + "\x00" +
		t.SubjectType + "\x00" + t.SubjectID + "\x00" + t.SubjectRelation
}

func (s *MemoryRelationshipStore) WriteTuple(ctx context.Context, tuple authz.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tuples[tupleKey(tuple)] = tuple
	return nil
}

func (s *MemoryRelationshipStore) DeleteTuple(ctx context.Context, tuple authz.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tuples, tupleKey(tuple))
	return nil
}

func matches(t authz.RelationTuple, objectType, objectID, relation, subjectType, subjectID string) bool {
	if objectType != "" && t.ObjectType != objectType {
		return false
	}
	if objectID != "" && t.ObjectID != objectID {
		return false
	}
	if relation != "" && t.Relation != relation {
		return false
	}
	if subjectType != "" && t.SubjectType != subjectType {
		return false
	}
	if subjectID != "" && t.SubjectID != subjectID {
		return false
	}
	return true
}

func (s *MemoryRelationshipStore) ReadTuples(ctx context.Context, objectType, objectID, relation, subjectType, subjectID string) ([]authz.RelationTuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]authz.RelationTuple, 0)
	for _, t := range s.tuples {
		if matches(t, objectType, objectID, relation, subjectType, subjectID) {
			result = append(result, t)
		}
	}
	return result, nil
}

// Check resolves whether subjectType:subjectID has `relation` to
// objectType:objectID, via direct tuples plus bounded-depth subject-set
// (group) indirection. Depth is capped to guard against cycles.
func (s *MemoryRelationshipStore) Check(ctx context.Context, objectType, objectID, relation, subjectType, subjectID string) (bool, error) {
	visited := make(map[string]bool)
	return s.check(objectType, objectID, relation, subjectType, subjectID, 0, visited), nil
}

func (s *MemoryRelationshipStore) check(objectType, objectID, relation, subjectType, subjectID string, depth int, visited map[string]bool) bool {
	const maxDepth = 10
	if depth > maxDepth {
		return false
	}
	key := objectType + "\x00" + objectID + "\x00" + relation + "\x00" + subjectType + "\x00" + subjectID
	if visited[key] {
		return false
	}
	visited[key] = true

	s.mu.RLock()
	candidates := make([]authz.RelationTuple, 0)
	for _, t := range s.tuples {
		if t.ObjectType == objectType && t.ObjectID == objectID && t.Relation == relation {
			candidates = append(candidates, t)
		}
	}
	s.mu.RUnlock()

	for _, t := range candidates {
		if t.SubjectRelation == "" {
			// direct subject tuple
			if t.SubjectType == subjectType && t.SubjectID == subjectID {
				return true
			}
			continue
		}
		// subject-set indirection: subject must hold t.SubjectRelation on
		// t.SubjectType:t.SubjectID (e.g. be a "member" of "group:eng")
		if s.check(t.SubjectType, t.SubjectID, t.SubjectRelation, subjectType, subjectID, depth+1, visited) {
			return true
		}
	}
	return false
}
