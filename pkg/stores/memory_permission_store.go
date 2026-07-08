package stores

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemoryPermissionBoundaryStore implements PermissionBoundaryStore in-memory.
type MemoryPermissionBoundaryStore struct {
	mu         sync.RWMutex
	boundaries map[string]*authz.PermissionBoundary
}

func NewMemoryPermissionBoundaryStore() *MemoryPermissionBoundaryStore {
	return &MemoryPermissionBoundaryStore{boundaries: make(map[string]*authz.PermissionBoundary)}
}

func (s *MemoryPermissionBoundaryStore) CreateBoundary(ctx context.Context, boundary *authz.PermissionBoundary) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if boundary.CreatedAt.IsZero() {
		boundary.CreatedAt = time.Now()
	}
	s.boundaries[boundary.ID] = boundary
	return nil
}

func (s *MemoryPermissionBoundaryStore) UpdateBoundary(ctx context.Context, boundary *authz.PermissionBoundary) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.boundaries[boundary.ID]; !ok {
		return fmt.Errorf("boundary not found: %s", boundary.ID)
	}
	s.boundaries[boundary.ID] = boundary
	return nil
}

func (s *MemoryPermissionBoundaryStore) DeleteBoundary(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.boundaries, id)
	return nil
}

func (s *MemoryPermissionBoundaryStore) GetBoundary(ctx context.Context, id string) (*authz.PermissionBoundary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.boundaries[id]
	if !ok {
		return nil, fmt.Errorf("boundary not found: %s", id)
	}
	return b, nil
}

func (s *MemoryPermissionBoundaryStore) ListBoundaries(ctx context.Context, tenantID string) ([]*authz.PermissionBoundary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.PermissionBoundary, 0)
	for _, b := range s.boundaries {
		if tenantID == "" || b.TenantID == tenantID {
			result = append(result, b)
		}
	}
	return result, nil
}

// MemoryUserBoundaryStore implements UserBoundaryStore in-memory.
type MemoryUserBoundaryStore struct {
	mu         sync.RWMutex
	boundaries map[string]string // userID -> boundaryID
}

func NewMemoryUserBoundaryStore() *MemoryUserBoundaryStore {
	return &MemoryUserBoundaryStore{boundaries: make(map[string]string)}
}

func (s *MemoryUserBoundaryStore) SetBoundary(ctx context.Context, userID, boundaryID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.boundaries[userID] = boundaryID
	return nil
}

func (s *MemoryUserBoundaryStore) RemoveBoundary(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.boundaries, userID)
	return nil
}

func (s *MemoryUserBoundaryStore) GetBoundary(ctx context.Context, userID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.boundaries[userID]
	if !ok {
		return "", nil
	}
	return id, nil
}
