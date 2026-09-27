package stores

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemoryDelegationStore implements authz.DelegationStore in-memory for
// testing/demo purposes, following the same patterns as the other memory
// stores in this package.
type MemoryDelegationStore struct {
	mu     sync.RWMutex
	grants map[string]*authz.DelegationGrant
}

func NewMemoryDelegationStore() *MemoryDelegationStore {
	return &MemoryDelegationStore{grants: make(map[string]*authz.DelegationGrant)}
}

func cloneDelegationGrant(g *authz.DelegationGrant) *authz.DelegationGrant {
	cp := *g
	cp.Actions = append([]authz.Action{}, g.Actions...)
	return &cp
}

func (s *MemoryDelegationStore) Create(ctx context.Context, grant *authz.DelegationGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if grant.ID == "" {
		return fmt.Errorf("delegation grant id is required")
	}
	if _, exists := s.grants[grant.ID]; exists {
		return fmt.Errorf("delegation grant already exists: %s", grant.ID)
	}
	if grant.CreatedAt.IsZero() {
		grant.CreatedAt = time.Now()
	}
	s.grants[grant.ID] = cloneDelegationGrant(grant)
	return nil
}

func (s *MemoryDelegationStore) Get(ctx context.Context, id string) (*authz.DelegationGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[id]
	if !ok {
		return nil, fmt.Errorf("delegation grant not found: %s", id)
	}
	return cloneDelegationGrant(g), nil
}

func (s *MemoryDelegationStore) List(ctx context.Context, tenantID string) ([]*authz.DelegationGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.DelegationGrant, 0)
	for _, g := range s.grants {
		if tenantID == "" || g.TenantID == tenantID || g.TenantID == "" {
			result = append(result, cloneDelegationGrant(g))
		}
	}
	return result, nil
}

func (s *MemoryDelegationStore) ListByDelegate(ctx context.Context, delegateID string) ([]*authz.DelegationGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.DelegationGrant, 0)
	for _, g := range s.grants {
		if g.DelegateID == delegateID {
			result = append(result, cloneDelegationGrant(g))
		}
	}
	return result, nil
}

func (s *MemoryDelegationStore) Revoke(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return fmt.Errorf("delegation grant not found: %s", id)
	}
	g.Revoked = true
	g.RevokedAt = time.Now()
	return nil
}

func (s *MemoryDelegationStore) IncrementUse(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return fmt.Errorf("delegation grant not found: %s", id)
	}
	g.UseCount++
	return nil
}
