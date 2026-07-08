package stores

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/authz"
)

// MemoryGroupStore implements in-memory group persistence
type MemoryGroupStore struct {
	mu     sync.RWMutex
	groups map[string]*authz.Group
}

func NewMemoryGroupStore() *MemoryGroupStore {
	return &MemoryGroupStore{groups: make(map[string]*authz.Group)}
}

func (s *MemoryGroupStore) CreateGroup(ctx context.Context, group *authz.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.groups[group.ID]; exists {
		return fmt.Errorf("group already exists: %s", group.ID)
	}
	group.CreatedAt = time.Now()
	group.UpdatedAt = group.CreatedAt
	s.groups[group.ID] = group
	return nil
}

func (s *MemoryGroupStore) UpdateGroup(ctx context.Context, group *authz.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[group.ID]; !ok {
		return fmt.Errorf("group not found: %s", group.ID)
	}
	group.UpdatedAt = time.Now()
	s.groups[group.ID] = group
	return nil
}

func (s *MemoryGroupStore) DeleteGroup(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.groups, id)
	return nil
}

func (s *MemoryGroupStore) GetGroup(ctx context.Context, id string) (*authz.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	if !ok {
		return nil, fmt.Errorf("group not found: %s", id)
	}
	cp := *g
	return &cp, nil
}

func (s *MemoryGroupStore) ListGroups(ctx context.Context, tenantID string) ([]*authz.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*authz.Group, 0, len(s.groups))
	for _, g := range s.groups {
		if tenantID == "" || g.TenantID == tenantID {
			cp := *g
			result = append(result, &cp)
		}
	}
	return result, nil
}

// MemoryGroupMembershipStore implements in-memory group membership
type MemoryGroupMembershipStore struct {
	mu      sync.RWMutex
	members map[string]map[string]bool // groupID -> set of userIDs
	groups  map[string]map[string]bool // userID  -> set of groupIDs
}

func NewMemoryGroupMembershipStore() *MemoryGroupMembershipStore {
	return &MemoryGroupMembershipStore{
		members: make(map[string]map[string]bool),
		groups:  make(map[string]map[string]bool),
	}
}

func (s *MemoryGroupMembershipStore) AddMember(ctx context.Context, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.members[groupID]; !ok {
		s.members[groupID] = make(map[string]bool)
	}
	s.members[groupID][userID] = true
	if _, ok := s.groups[userID]; !ok {
		s.groups[userID] = make(map[string]bool)
	}
	s.groups[userID][groupID] = true
	return nil
}

func (s *MemoryGroupMembershipStore) RemoveMember(ctx context.Context, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.members[groupID]; ok {
		delete(m, userID)
	}
	if g, ok := s.groups[userID]; ok {
		delete(g, groupID)
	}
	return nil
}

func (s *MemoryGroupMembershipStore) ListMembers(ctx context.Context, groupID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0)
	if m, ok := s.members[groupID]; ok {
		for userID := range m {
			result = append(result, userID)
		}
	}
	return result, nil
}

func (s *MemoryGroupMembershipStore) ListGroups(ctx context.Context, userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0)
	if g, ok := s.groups[userID]; ok {
		for groupID := range g {
			result = append(result, groupID)
		}
	}
	return result, nil
}

func (s *MemoryGroupMembershipStore) IsMember(ctx context.Context, groupID, userID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.members[groupID]; ok {
		return m[userID], nil
	}
	return false, nil
}

// MemoryGroupRoleStore implements in-memory group-to-role assignments
type MemoryGroupRoleStore struct {
	mu             sync.RWMutex
	rolesByGroup   map[string]map[string]bool // groupID -> set of roleIDs
	groupsByRole   map[string]map[string]bool // roleID  -> set of groupIDs
}

func NewMemoryGroupRoleStore() *MemoryGroupRoleStore {
	return &MemoryGroupRoleStore{
		rolesByGroup: make(map[string]map[string]bool),
		groupsByRole: make(map[string]map[string]bool),
	}
}

func (s *MemoryGroupRoleStore) AssignRole(ctx context.Context, groupID, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rolesByGroup[groupID]; !ok {
		s.rolesByGroup[groupID] = make(map[string]bool)
	}
	s.rolesByGroup[groupID][roleID] = true
	if _, ok := s.groupsByRole[roleID]; !ok {
		s.groupsByRole[roleID] = make(map[string]bool)
	}
	s.groupsByRole[roleID][groupID] = true
	return nil
}

func (s *MemoryGroupRoleStore) RevokeRole(ctx context.Context, groupID, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.rolesByGroup[groupID]; ok {
		delete(m, roleID)
	}
	if m, ok := s.groupsByRole[roleID]; ok {
		delete(m, groupID)
	}
	return nil
}

func (s *MemoryGroupRoleStore) ListRolesByGroup(ctx context.Context, groupID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0)
	if m, ok := s.rolesByGroup[groupID]; ok {
		for roleID := range m {
			result = append(result, roleID)
		}
	}
	return result, nil
}

func (s *MemoryGroupRoleStore) ListGroupsByRole(ctx context.Context, roleID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0)
	if m, ok := s.groupsByRole[roleID]; ok {
		for groupID := range m {
			result = append(result, groupID)
		}
	}
	return result, nil
}
