package stores

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemoryPolicyStore implements policy persistence in-memory for testing/demo
type MemoryPolicyStore struct {
	mu        sync.RWMutex
	policies  map[string]*authz.Policy
	histories map[string][]*authz.Policy
}

func NewMemoryPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{policies: make(map[string]*authz.Policy), histories: make(map[string][]*authz.Policy)}
}

func (s *MemoryPolicyStore) CreatePolicy(ctx context.Context, p *authz.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt
	s.policies[p.ID] = p
	return nil
}

func (s *MemoryPolicyStore) UpdatePolicy(ctx context.Context, p *authz.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.policies[p.ID]
	if ok {
		cop := *old
		s.histories[p.ID] = append(s.histories[p.ID], &cop)
	}
	p.UpdatedAt = time.Now()
	p.Version++
	s.policies[p.ID] = p
	return nil
}

func (s *MemoryPolicyStore) GetPolicyHistory(ctx context.Context, id string) ([]*authz.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.histories[id]
	if !ok {
		return nil, fmt.Errorf("no history for policy %s", id)
	}
	return h, nil
}

func (s *MemoryPolicyStore) DeletePolicy(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, id)
	return nil
}

func (s *MemoryPolicyStore) GetPolicy(ctx context.Context, id string) (*authz.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	return p, nil
}

func (s *MemoryPolicyStore) ListPolicies(ctx context.Context, tenantID string) ([]*authz.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Policy, 0)
	for _, p := range s.policies {
		if p.TenantID == tenantID || p.TenantID == "" {
			result = append(result, p)
		}
	}
	return result, nil
}

// MemoryRoleStore implements in-memory role persistence
type MemoryRoleStore struct {
	mu    sync.RWMutex
	roles map[string]*authz.Role
}

func NewMemoryRoleStore() *MemoryRoleStore {
	return &MemoryRoleStore{roles: make(map[string]*authz.Role)}
}

func (s *MemoryRoleStore) CreateRole(ctx context.Context, r *authz.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.CreatedAt = time.Now()
	s.roles[r.ID] = r
	return nil
}

func (s *MemoryRoleStore) UpdateRole(ctx context.Context, r *authz.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[r.ID] = r
	return nil
}

func (s *MemoryRoleStore) DeleteRole(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roles, id)
	return nil
}

func (s *MemoryRoleStore) GetRole(ctx context.Context, id string) (*authz.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[id]
	if !ok {
		return nil, fmt.Errorf("role not found: %s", id)
	}
	return r, nil
}

func (s *MemoryRoleStore) ListRoles(ctx context.Context, tenantID string) ([]*authz.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Role, 0)
	for _, r := range s.roles {
		if r.TenantID == tenantID || r.TenantID == "" {
			result = append(result, r)
		}
	}
	return result, nil
}

// MemoryACLStore implements in-memory ACL persistence
type MemoryACLStore struct {
	mu   sync.RWMutex
	acls map[string]*authz.ACL
}

func NewMemoryACLStore() *MemoryACLStore {
	return &MemoryACLStore{acls: make(map[string]*authz.ACL)}
}

func (s *MemoryACLStore) GrantACL(ctx context.Context, acl *authz.ACL) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acl.CreatedAt = time.Now()
	s.acls[acl.ID] = acl
	return nil
}

func (s *MemoryACLStore) RevokeACL(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.acls, id)
	return nil
}

func (s *MemoryACLStore) ListACLsByResource(ctx context.Context, resourceID string) ([]*authz.ACL, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.ACL, 0)
	for _, acl := range s.acls {
		if acl.IsExpired() {
			continue
		}
		if acl.ResourceID == resourceID {
			result = append(result, acl)
			continue
		}
		for i, ch := range acl.ResourceID {
			if ch == '*' {
				prefix := acl.ResourceID[:i]
				if len(resourceID) >= len(prefix) && resourceID[:len(prefix)] == prefix {
					result = append(result, acl)
				}
				break
			}
		}
	}
	return result, nil
}

func (s *MemoryACLStore) ListACLsBySubject(ctx context.Context, subjectID string) ([]*authz.ACL, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.ACL, 0)
	for _, acl := range s.acls {
		if acl.SubjectID == subjectID && !acl.IsExpired() {
			result = append(result, acl)
		}
	}
	return result, nil
}

// MemoryAuditStore implements in-memory audit logging
type MemoryAuditStore struct {
	mu      sync.RWMutex
	entries []*authz.AuditEntry
}

func NewMemoryAuditStore() *MemoryAuditStore {
	return &MemoryAuditStore{entries: make([]*authz.AuditEntry, 0)}
}

func (s *MemoryAuditStore) LogDecision(ctx context.Context, entry *authz.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	return nil
}

func (s *MemoryAuditStore) GetAccessLog(ctx context.Context, filter authz.AuditFilter) ([]*authz.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.AuditEntry, 0)
	for _, entry := range s.entries {
		if filter.SubjectID != "" && entry.Subject.ID != filter.SubjectID {
			continue
		}
		if filter.ResourceID != "" && entry.Resource.ID != filter.ResourceID {
			continue
		}
		if filter.Action != "" && entry.Action != filter.Action {
			continue
		}
		if !filter.StartTime.IsZero() && entry.Timestamp.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && entry.Timestamp.After(filter.EndTime) {
			continue
		}
		result = append(result, entry)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, nil
}

// MemoryRoleMembershipStore implements role membership in memory
type MemoryRoleMembershipStore struct {
	mu    sync.RWMutex
	store map[string]map[string]bool
}

func NewMemoryRoleMembershipStore() *MemoryRoleMembershipStore {
	return &MemoryRoleMembershipStore{store: make(map[string]map[string]bool)}
}

func (m *MemoryRoleMembershipStore) AssignRole(ctx context.Context, subjectID, roleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.store[subjectID]; !ok {
		m.store[subjectID] = make(map[string]bool)
	}
	m.store[subjectID][roleID] = true
	return nil
}

func (m *MemoryRoleMembershipStore) RevokeRole(ctx context.Context, subjectID, roleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.store[subjectID]; !ok {
		return nil
	}
	delete(m.store[subjectID], roleID)
	return nil
}

func (m *MemoryRoleMembershipStore) ListRoles(ctx context.Context, subjectID string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0)
	if set, ok := m.store[subjectID]; ok {
		for r := range set {
			out = append(out, r)
		}
	}
	return out, nil
}
