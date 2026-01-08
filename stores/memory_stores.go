package stores

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
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
		if tenantID == "" || p.TenantID == tenantID || p.TenantID == "" {
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
	mu              sync.RWMutex
	acls            map[string]*authz.ACL
	snapshot        atomic.Value
	refreshInterval time.Duration
	stopCh          chan struct{}
}

func NewMemoryACLStore() *MemoryACLStore {
	store := &MemoryACLStore{
		acls:            make(map[string]*authz.ACL),
		refreshInterval: 250 * time.Millisecond,
		stopCh:          make(chan struct{}),
	}
	store.snapshot.Store([]*authz.ACL{})
	go store.snapshotWorker()
	return store
}

func (s *MemoryACLStore) snapshotWorker() {
	ticker := time.NewTicker(s.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.rebuildACLSnapshot()
		case <-s.stopCh:
			return
		}
	}
}

func (s *MemoryACLStore) rebuildACLSnapshot() {
	s.mu.RLock()
	copyList := make([]*authz.ACL, 0, len(s.acls))
	for _, acl := range s.acls {
		if acl.IsExpired() {
			continue
		}
		dup := *acl
		copyList = append(copyList, &dup)
	}
	s.mu.RUnlock()
	s.snapshot.Store(copyList)
}

func (s *MemoryACLStore) GrantACL(ctx context.Context, acl *authz.ACL) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acl.CreatedAt = time.Now()
	s.acls[acl.ID] = acl
	go s.rebuildACLSnapshot()
	return nil
}

func (s *MemoryACLStore) RevokeACL(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.acls, id)
	go s.rebuildACLSnapshot()
	return nil
}

func (s *MemoryACLStore) GetACL(ctx context.Context, id string) (*authz.ACL, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	acl, ok := s.acls[id]
	if !ok {
		return nil, fmt.Errorf("acl not found: %s", id)
	}
	return cloneACL(acl), nil
}

func (s *MemoryACLStore) UpdateACL(ctx context.Context, acl *authz.ACL) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.acls[acl.ID]; !ok {
		return fmt.Errorf("acl not found: %s", acl.ID)
	}
	s.acls[acl.ID] = acl
	go s.rebuildACLSnapshot()
	return nil
}

func (s *MemoryACLStore) ListACLs(ctx context.Context, tenantID string) ([]*authz.ACL, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.ACL, 0)
	for _, acl := range s.acls {
		if acl.IsExpired() {
			continue
		}
		// If tenantID is empty, return all ACLs; otherwise filter by tenantID
		if tenantID == "" || acl.TenantID == tenantID {
			result = append(result, cloneACL(acl))
		}
	}
	return result, nil
}

func (s *MemoryACLStore) Close() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
}

func (s *MemoryACLStore) ListACLsByResource(ctx context.Context, resourceID string) ([]*authz.ACL, error) {
	if snapshot, ok := s.snapshot.Load().([]*authz.ACL); ok && len(snapshot) > 0 {
		return filterACLsSnapshot(snapshot, resourceID), nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.ACL, 0)
	for _, acl := range s.acls {
		if acl.IsExpired() {
			continue
		}
		if aclMatchesResource(acl.ResourceID, resourceID) {
			result = append(result, cloneACL(acl))
		}
	}
	return result, nil
}

func (s *MemoryACLStore) ListACLsBySubject(ctx context.Context, subjectID string) ([]*authz.ACL, error) {
	if snapshot, ok := s.snapshot.Load().([]*authz.ACL); ok && len(snapshot) > 0 {
		return filterACLsBySubject(snapshot, subjectID), nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.ACL, 0)
	for _, acl := range s.acls {
		if acl.SubjectID == subjectID && !acl.IsExpired() {
			result = append(result, cloneACL(acl))
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
	mu              sync.RWMutex
	store           map[string]map[string]bool
	snapshot        atomic.Value
	refreshInterval time.Duration
	stopCh          chan struct{}
}

func NewMemoryRoleMembershipStore() *MemoryRoleMembershipStore {
	store := &MemoryRoleMembershipStore{
		store:           make(map[string]map[string]bool),
		refreshInterval: 250 * time.Millisecond,
		stopCh:          make(chan struct{}),
	}
	store.snapshot.Store(map[string][]string{})
	go store.snapshotWorker()
	return store
}

func (m *MemoryRoleMembershipStore) snapshotWorker() {
	ticker := time.NewTicker(m.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.rebuildMembershipSnapshot()
		case <-m.stopCh:
			return
		}
	}
}

func (m *MemoryRoleMembershipStore) rebuildMembershipSnapshot() {
	m.mu.RLock()
	copyMap := make(map[string][]string, len(m.store))
	for subj, roles := range m.store {
		arr := make([]string, 0, len(roles))
		for roleID := range roles {
			arr = append(arr, roleID)
		}
		copyMap[subj] = arr
	}
	m.mu.RUnlock()
	m.snapshot.Store(copyMap)
}

func (m *MemoryRoleMembershipStore) AssignRole(ctx context.Context, subjectID, roleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.store[subjectID]; !ok {
		m.store[subjectID] = make(map[string]bool)
	}
	m.store[subjectID][roleID] = true
	go m.rebuildMembershipSnapshot()
	return nil
}

func (m *MemoryRoleMembershipStore) RevokeRole(ctx context.Context, subjectID, roleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.store[subjectID]; !ok {
		return nil
	}
	delete(m.store[subjectID], roleID)
	go m.rebuildMembershipSnapshot()
	return nil
}

func (m *MemoryRoleMembershipStore) Close() {
	select {
	case <-m.stopCh:
		return
	default:
		close(m.stopCh)
	}
}

func (m *MemoryRoleMembershipStore) ListRoles(ctx context.Context, subjectID string) ([]string, error) {
	if snap, ok := m.snapshot.Load().(map[string][]string); ok {
		if roles, ok2 := snap[subjectID]; ok2 {
			copyRoles := make([]string, len(roles))
			copy(copyRoles, roles)
			return copyRoles, nil
		}
	}
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

// MemoryTenantStore implements in-memory tenant persistence
type MemoryTenantStore struct {
	mu      sync.RWMutex
	tenants map[string]*authz.Tenant
}

func NewMemoryTenantStore() *MemoryTenantStore {
	return &MemoryTenantStore{tenants: make(map[string]*authz.Tenant)}
}

func (s *MemoryTenantStore) CreateTenant(ctx context.Context, tenant *authz.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tenants[tenant.ID]; exists {
		return fmt.Errorf("tenant already exists: %s", tenant.ID)
	}
	tenant.CreatedAt = time.Now()
	tenant.UpdatedAt = tenant.CreatedAt
	s.tenants[tenant.ID] = tenant
	return nil
}

func (s *MemoryTenantStore) UpdateTenant(ctx context.Context, tenant *authz.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenant.ID]; !ok {
		return fmt.Errorf("tenant not found: %s", tenant.ID)
	}
	tenant.UpdatedAt = time.Now()
	s.tenants[tenant.ID] = tenant
	return nil
}

func (s *MemoryTenantStore) DeleteTenant(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tenants, id)
	return nil
}

func (s *MemoryTenantStore) GetTenant(ctx context.Context, id string) (*authz.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenant, ok := s.tenants[id]
	if !ok {
		return nil, fmt.Errorf("tenant not found: %s", id)
	}
	// Return a copy to avoid mutation
	copy := *tenant
	return &copy, nil
}

func (s *MemoryTenantStore) ListTenants(ctx context.Context) ([]*authz.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		copy := *t
		result = append(result, &copy)
	}
	return result, nil
}
