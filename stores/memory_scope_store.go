package stores

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemoryScopeStore implements in-memory scope persistence
type MemoryScopeStore struct {
	mu     sync.RWMutex
	scopes map[string]*authz.Scope
}

func NewMemoryScopeStore() *MemoryScopeStore {
	return &MemoryScopeStore{scopes: make(map[string]*authz.Scope)}
}

func (s *MemoryScopeStore) CreateScope(ctx context.Context, scope *authz.Scope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.scopes[scope.ID]; exists {
		return fmt.Errorf("scope already exists: %s", scope.ID)
	}
	scope.CreatedAt = time.Now()
	s.scopes[scope.ID] = scope
	return nil
}

func (s *MemoryScopeStore) UpdateScope(ctx context.Context, scope *authz.Scope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.scopes[scope.ID]; !ok {
		return fmt.Errorf("scope not found: %s", scope.ID)
	}
	s.scopes[scope.ID] = scope
	return nil
}

func (s *MemoryScopeStore) DeleteScope(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.scopes, id)
	return nil
}

func (s *MemoryScopeStore) GetScope(ctx context.Context, id string) (*authz.Scope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scope, ok := s.scopes[id]
	if !ok {
		return nil, fmt.Errorf("scope not found: %s", id)
	}
	cp := *scope
	return &cp, nil
}

func (s *MemoryScopeStore) ListScopes(ctx context.Context, tenantID string) ([]*authz.Scope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Scope, 0)
	for _, scope := range s.scopes {
		if tenantID == "" || scope.TenantID == tenantID {
			cp := *scope
			result = append(result, &cp)
		}
	}
	return result, nil
}

// MemoryRoleScopeStore implements in-memory role-to-scope mapping persistence
type MemoryRoleScopeStore struct {
	mu           sync.RWMutex
	roleToScopes map[string]map[string]bool // roleID -> set of scopeIDs
	scopeToRoles map[string]map[string]bool // scopeID -> set of roleIDs
}

func NewMemoryRoleScopeStore() *MemoryRoleScopeStore {
	return &MemoryRoleScopeStore{
		roleToScopes: make(map[string]map[string]bool),
		scopeToRoles: make(map[string]map[string]bool),
	}
}

func (s *MemoryRoleScopeStore) AssignScope(ctx context.Context, roleID, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roleToScopes[roleID]; !ok {
		s.roleToScopes[roleID] = make(map[string]bool)
	}
	s.roleToScopes[roleID][scopeID] = true

	if _, ok := s.scopeToRoles[scopeID]; !ok {
		s.scopeToRoles[scopeID] = make(map[string]bool)
	}
	s.scopeToRoles[scopeID][roleID] = true
	return nil
}

func (s *MemoryRoleScopeStore) RevokeScope(ctx context.Context, roleID, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set, ok := s.roleToScopes[roleID]; ok {
		delete(set, scopeID)
	}
	if set, ok := s.scopeToRoles[scopeID]; ok {
		delete(set, roleID)
	}
	return nil
}

func (s *MemoryRoleScopeStore) ListScopesByRole(ctx context.Context, roleID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0)
	if set, ok := s.roleToScopes[roleID]; ok {
		for scopeID := range set {
			result = append(result, scopeID)
		}
	}
	return result, nil
}

func (s *MemoryRoleScopeStore) ListRolesByScope(ctx context.Context, scopeID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0)
	if set, ok := s.scopeToRoles[scopeID]; ok {
		for roleID := range set {
			result = append(result, roleID)
		}
	}
	return result, nil
}
