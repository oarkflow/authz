package authz

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// SCOPES SYSTEM
// ============================================================================

// Scope represents a named permission scope (OAuth2-style)
type Scope struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`                  // e.g., "read:documents", "admin:users"
	Description string    `json:"description"`
	ParentID    string    `json:"parent_id,omitempty"` // for hierarchical scopes
	CreatedAt   time.Time `json:"created_at"`
}

// ScopeStore manages scope persistence
type ScopeStore interface {
	CreateScope(ctx context.Context, scope *Scope) error
	UpdateScope(ctx context.Context, scope *Scope) error
	DeleteScope(ctx context.Context, id string) error
	GetScope(ctx context.Context, id string) (*Scope, error)
	ListScopes(ctx context.Context, tenantID string) ([]*Scope, error)
}

// RoleScopeMapping maps roles to scopes
type RoleScopeMapping struct {
	RoleID  string `json:"role_id"`
	ScopeID string `json:"scope_id"`
}

// RoleScopeStore manages role-to-scope mappings
type RoleScopeStore interface {
	AssignScope(ctx context.Context, roleID, scopeID string) error
	RevokeScope(ctx context.Context, roleID, scopeID string) error
	ListScopesByRole(ctx context.Context, roleID string) ([]string, error)
	ListRolesByScope(ctx context.Context, scopeID string) ([]string, error)
}

// ScopeRegistry provides scope resolution and hierarchy
type ScopeRegistry struct {
	store     ScopeStore
	roleScope RoleScopeStore
	mu        sync.RWMutex
	cache     map[string]*Scope   // id -> scope
	children  map[string][]string // parentID -> childIDs
}

// NewScopeRegistry creates a new ScopeRegistry backed by the given stores.
func NewScopeRegistry(store ScopeStore, roleScope RoleScopeStore) *ScopeRegistry {
	return &ScopeRegistry{
		store:     store,
		roleScope: roleScope,
		cache:     make(map[string]*Scope),
		children:  make(map[string][]string),
	}
}

// ResolveScopes returns all scopes for a set of roles (including inherited scopes from parent hierarchy).
func (sr *ScopeRegistry) ResolveScopes(ctx context.Context, roleIDs []string) ([]string, error) {
	seen := make(map[string]bool)
	var result []string

	for _, roleID := range roleIDs {
		scopeIDs, err := sr.roleScope.ListScopesByRole(ctx, roleID)
		if err != nil {
			return nil, fmt.Errorf("list scopes for role %s: %w", roleID, err)
		}
		for _, scopeID := range scopeIDs {
			if seen[scopeID] {
				continue
			}
			seen[scopeID] = true
			result = append(result, scopeID)

			// Walk up the parent hierarchy to inherit ancestor scopes
			inherited, err := sr.collectAncestorScopes(ctx, scopeID)
			if err != nil {
				return nil, err
			}
			for _, id := range inherited {
				if !seen[id] {
					seen[id] = true
					result = append(result, id)
				}
			}
		}
	}

	return result, nil
}

// collectAncestorScopes walks parent_id links upward and returns all ancestor scope IDs.
func (sr *ScopeRegistry) collectAncestorScopes(ctx context.Context, scopeID string) ([]string, error) {
	var ancestors []string
	visited := map[string]bool{scopeID: true}

	currentID := scopeID
	for {
		scope, err := sr.getCachedScope(ctx, currentID)
		if err != nil || scope == nil {
			break
		}
		if scope.ParentID == "" {
			break
		}
		if visited[scope.ParentID] {
			break // prevent cycles
		}
		visited[scope.ParentID] = true
		ancestors = append(ancestors, scope.ParentID)
		currentID = scope.ParentID
	}

	return ancestors, nil
}

// getCachedScope returns a scope from cache or fetches it from the store.
func (sr *ScopeRegistry) getCachedScope(ctx context.Context, id string) (*Scope, error) {
	sr.mu.RLock()
	if s, ok := sr.cache[id]; ok {
		sr.mu.RUnlock()
		return s, nil
	}
	sr.mu.RUnlock()

	s, err := sr.store.GetScope(ctx, id)
	if err != nil {
		return nil, err
	}

	sr.mu.Lock()
	sr.cache[id] = s
	sr.mu.Unlock()

	return s, nil
}

// HasScope checks if the given scopes contain the required scope (with hierarchy support).
// Supports wildcard matching: having "admin:*" satisfies "admin:read".
func (sr *ScopeRegistry) HasScope(ctx context.Context, userScopes []string, required string) bool {
	for _, scope := range userScopes {
		if scope == required {
			return true
		}
		// Wildcard matching: "admin:*" matches "admin:read", "admin:write", etc.
		if strings.HasSuffix(scope, ":*") {
			prefix := strings.TrimSuffix(scope, "*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
		// Full wildcard
		if scope == "*" {
			return true
		}
	}

	// Check hierarchy: if a user has a parent scope, they implicitly have child scopes
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	for _, scope := range userScopes {
		if sr.scopeContainsChild(scope, required) {
			return true
		}
	}

	return false
}

// scopeContainsChild checks if parentScopeID has required as a descendant in the children map.
// Must be called with sr.mu held (at least RLock).
func (sr *ScopeRegistry) scopeContainsChild(parentScopeID, required string) bool {
	children, ok := sr.children[parentScopeID]
	if !ok {
		return false
	}
	for _, childID := range children {
		if childID == required {
			return true
		}
		if sr.scopeContainsChild(childID, required) {
			return true
		}
	}
	return false
}

// ValidateScopes checks if all requested scopes are valid in the tenant.
func (sr *ScopeRegistry) ValidateScopes(ctx context.Context, tenantID string, scopes []string) error {
	allScopes, err := sr.store.ListScopes(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("list scopes for tenant %s: %w", tenantID, err)
	}

	validNames := make(map[string]bool, len(allScopes))
	validIDs := make(map[string]bool, len(allScopes))
	for _, s := range allScopes {
		validNames[s.Name] = true
		validIDs[s.ID] = true
	}

	var invalid []string
	for _, scope := range scopes {
		if !validNames[scope] && !validIDs[scope] {
			invalid = append(invalid, scope)
		}
	}

	if len(invalid) > 0 {
		return fmt.Errorf("invalid scopes for tenant %s: %s", tenantID, strings.Join(invalid, ", "))
	}
	return nil
}

// RefreshCache rebuilds the in-memory scope cache for the given tenant.
func (sr *ScopeRegistry) RefreshCache(ctx context.Context, tenantID string) error {
	allScopes, err := sr.store.ListScopes(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("list scopes for tenant %s: %w", tenantID, err)
	}

	sr.mu.Lock()
	defer sr.mu.Unlock()

	// Clear existing cache entries for this tenant
	for id, s := range sr.cache {
		if s.TenantID == tenantID {
			delete(sr.cache, id)
		}
	}
	// Clear children map for this tenant's scopes
	for parentID := range sr.children {
		if s, ok := sr.cache[parentID]; ok && s.TenantID == tenantID {
			delete(sr.children, parentID)
		}
	}

	// Rebuild
	sr.children = make(map[string][]string)
	for _, s := range allScopes {
		sr.cache[s.ID] = s
	}
	for _, s := range allScopes {
		if s.ParentID != "" {
			sr.children[s.ParentID] = append(sr.children[s.ParentID], s.ID)
		}
	}

	return nil
}
