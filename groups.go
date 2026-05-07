package authz

import (
	"context"
	"sync"
	"time"
)

// ============================================================================
// GROUP DOMAIN OBJECTS & STORES
// ============================================================================

// Group represents a collection of users
type Group struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	ParentID    string    `json:"parent_id,omitempty"` // for nested groups
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GroupStore manages group persistence
type GroupStore interface {
	CreateGroup(ctx context.Context, group *Group) error
	UpdateGroup(ctx context.Context, group *Group) error
	DeleteGroup(ctx context.Context, id string) error
	GetGroup(ctx context.Context, id string) (*Group, error)
	ListGroups(ctx context.Context, tenantID string) ([]*Group, error)
}

// GroupMembershipStore manages group membership
type GroupMembershipStore interface {
	AddMember(ctx context.Context, groupID, userID string) error
	RemoveMember(ctx context.Context, groupID, userID string) error
	ListMembers(ctx context.Context, groupID string) ([]string, error) // returns userIDs
	ListGroups(ctx context.Context, userID string) ([]string, error)   // returns groupIDs
	IsMember(ctx context.Context, groupID, userID string) (bool, error)
}

// GroupRoleStore manages group-to-role assignments
type GroupRoleStore interface {
	AssignRole(ctx context.Context, groupID, roleID string) error
	RevokeRole(ctx context.Context, groupID, roleID string) error
	ListRolesByGroup(ctx context.Context, groupID string) ([]string, error)
	ListGroupsByRole(ctx context.Context, roleID string) ([]string, error)
}

// ============================================================================
// GROUP RESOLVER
// ============================================================================

// GroupResolver resolves group memberships including nested groups
type GroupResolver struct {
	groupStore  GroupStore
	memberStore GroupMembershipStore
	roleStore   GroupRoleStore
	mu          sync.RWMutex
	parentCache map[string]string // groupID -> parentID
}

// NewGroupResolver creates a new GroupResolver with the given stores.
func NewGroupResolver(gs GroupStore, ms GroupMembershipStore, rs GroupRoleStore) *GroupResolver {
	return &GroupResolver{
		groupStore:  gs,
		memberStore: ms,
		roleStore:   rs,
		parentCache: make(map[string]string),
	}
}

// ResolveAllGroups returns all group IDs a user belongs to (including parent groups transitively).
func (gr *GroupResolver) ResolveAllGroups(ctx context.Context, userID string) ([]string, error) {
	directGroups, err := gr.memberStore.ListGroups(ctx, userID)
	if err != nil {
		return nil, err
	}

	gr.mu.RLock()
	defer gr.mu.RUnlock()

	seen := make(map[string]bool, len(directGroups))
	result := make([]string, 0, len(directGroups))

	for _, gid := range directGroups {
		if seen[gid] {
			continue
		}
		seen[gid] = true
		result = append(result, gid)

		// Walk up parent chain
		current := gid
		for {
			parentID, ok := gr.parentCache[current]
			if !ok || parentID == "" {
				break
			}
			if seen[parentID] {
				break // avoid cycles
			}
			seen[parentID] = true
			result = append(result, parentID)
			current = parentID
		}
	}

	return result, nil
}

// ResolveGroupRoles returns all role IDs inherited through groups.
func (gr *GroupResolver) ResolveGroupRoles(ctx context.Context, userID string) ([]string, error) {
	allGroups, err := gr.ResolveAllGroups(ctx, userID)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, gid := range allGroups {
		roles, err := gr.roleStore.ListRolesByGroup(ctx, gid)
		if err != nil {
			return nil, err
		}
		for _, roleID := range roles {
			if !seen[roleID] {
				seen[roleID] = true
				result = append(result, roleID)
			}
		}
	}

	return result, nil
}

// RefreshCache rebuilds the parent cache for the given tenant.
func (gr *GroupResolver) RefreshCache(ctx context.Context, tenantID string) error {
	groups, err := gr.groupStore.ListGroups(ctx, tenantID)
	if err != nil {
		return err
	}

	gr.mu.Lock()
	defer gr.mu.Unlock()

	for _, g := range groups {
		if g.ParentID != "" {
			gr.parentCache[g.ID] = g.ParentID
		} else {
			delete(gr.parentCache, g.ID)
		}
	}

	return nil
}
