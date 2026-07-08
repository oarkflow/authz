package authz

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/authz/pkg/utils"
)

// EffectivePermission represents a resolved permission with its source
type EffectivePermission struct {
	Action   Action `json:"action"`
	Resource string `json:"resource"`
	Effect   Effect `json:"effect"` // allow or deny
	Source   string `json:"source"` // "role:admin", "acl:acl-123", "policy:pol-456", "group:eng"
}

// PermissionBoundary restricts the maximum permissions a user can have
type PermissionBoundary struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Name         string    `json:"name"`
	MaxActions   []Action  `json:"max_actions"`   // maximum allowed actions
	MaxResources []string  `json:"max_resources"` // maximum allowed resource patterns
	CreatedAt    time.Time `json:"created_at"`
}

// PermissionBoundaryStore manages permission boundaries
type PermissionBoundaryStore interface {
	CreateBoundary(ctx context.Context, boundary *PermissionBoundary) error
	UpdateBoundary(ctx context.Context, boundary *PermissionBoundary) error
	DeleteBoundary(ctx context.Context, id string) error
	GetBoundary(ctx context.Context, id string) (*PermissionBoundary, error)
	ListBoundaries(ctx context.Context, tenantID string) ([]*PermissionBoundary, error)
}

// UserBoundaryStore maps users to permission boundaries
type UserBoundaryStore interface {
	SetBoundary(ctx context.Context, userID, boundaryID string) error
	RemoveBoundary(ctx context.Context, userID string) error
	GetBoundary(ctx context.Context, userID string) (string, error) // returns boundaryID
}

// PermissionResolver resolves effective permissions from all sources
type PermissionResolver struct {
	roleStore           RoleStore
	aclStore            ACLStore
	policyStore         PolicyStore
	roleMembershipStore RoleMembershipStore
	boundaryStore       PermissionBoundaryStore
	userBoundaryStore   UserBoundaryStore
}

// NewPermissionResolver creates a new PermissionResolver.
func NewPermissionResolver(
	roleStore RoleStore,
	aclStore ACLStore,
	policyStore PolicyStore,
	roleMembershipStore RoleMembershipStore,
	boundaryStore PermissionBoundaryStore,
	userBoundaryStore UserBoundaryStore,
) *PermissionResolver {
	return &PermissionResolver{
		roleStore:           roleStore,
		aclStore:            aclStore,
		policyStore:         policyStore,
		roleMembershipStore: roleMembershipStore,
		boundaryStore:       boundaryStore,
		userBoundaryStore:   userBoundaryStore,
	}
}

// GetEffectivePermissions resolves ALL permissions for a user from roles, ACLs, and policies.
func (pr *PermissionResolver) GetEffectivePermissions(ctx context.Context, userID, tenantID string) ([]EffectivePermission, error) {
	var perms []EffectivePermission

	// 1. Collect permissions from roles via role membership
	roleIDs, err := pr.roleMembershipStore.ListRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list roles for user %s: %w", userID, err)
	}
	for _, roleID := range roleIDs {
		rolePerms, err := pr.resolveRolePermissions(ctx, roleID, tenantID, make(map[string]bool))
		if err != nil {
			return nil, err
		}
		perms = append(perms, rolePerms...)
	}

	// 2. Collect permissions from ACLs
	acls, err := pr.aclStore.ListACLsBySubject(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list ACLs for user %s: %w", userID, err)
	}
	for _, acl := range acls {
		if acl.IsExpired() {
			continue
		}
		if tenantID != "" && acl.TenantID != "" && acl.TenantID != tenantID {
			continue
		}
		for _, action := range acl.Actions {
			perms = append(perms, EffectivePermission{
				Action:   action,
				Resource: acl.ResourceID,
				Effect:   acl.Effect,
				Source:   "acl:" + acl.ID,
			})
		}
	}

	// 3. Collect permissions from policies
	policies, err := pr.policyStore.ListPolicies(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list policies for tenant %s: %w", tenantID, err)
	}
	for _, pol := range policies {
		if !pol.Enabled {
			continue
		}
		for _, action := range pol.Actions {
			for _, resource := range pol.Resources {
				perms = append(perms, EffectivePermission{
					Action:   action,
					Resource: resource,
					Effect:   pol.Effect,
					Source:   "policy:" + pol.ID,
				})
			}
		}
	}

	return perms, nil
}

// resolveRolePermissions recursively resolves permissions from a role and its inherited roles.
func (pr *PermissionResolver) resolveRolePermissions(ctx context.Context, roleID, tenantID string, visited map[string]bool) ([]EffectivePermission, error) {
	if visited[roleID] {
		return nil, nil // prevent cycles
	}
	visited[roleID] = true

	role, err := pr.roleStore.GetRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("get role %s: %w", roleID, err)
	}
	if tenantID != "" && role.TenantID != "" && role.TenantID != tenantID {
		return nil, nil
	}

	var perms []EffectivePermission
	for _, p := range role.Permissions {
		perms = append(perms, EffectivePermission{
			Action:   p.Action,
			Resource: p.Resource,
			Effect:   EffectAllow,
			Source:   "role:" + role.Name,
		})
	}

	// Resolve inherited roles
	for _, parentID := range role.Inherits {
		inherited, err := pr.resolveRolePermissions(ctx, parentID, tenantID, visited)
		if err != nil {
			return nil, err
		}
		perms = append(perms, inherited...)
	}

	return perms, nil
}

// GetEffectivePermissionsWithBoundary applies permission boundary filtering
// on top of the resolved effective permissions.
func (pr *PermissionResolver) GetEffectivePermissionsWithBoundary(ctx context.Context, userID, tenantID string) ([]EffectivePermission, error) {
	perms, err := pr.GetEffectivePermissions(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	if pr.userBoundaryStore == nil || pr.boundaryStore == nil {
		return perms, nil
	}

	boundaryID, err := pr.userBoundaryStore.GetBoundary(ctx, userID)
	if err != nil || boundaryID == "" {
		// No boundary assigned; return all permissions unfiltered
		return perms, nil
	}

	boundary, err := pr.boundaryStore.GetBoundary(ctx, boundaryID)
	if err != nil {
		return nil, fmt.Errorf("get boundary %s: %w", boundaryID, err)
	}

	var filtered []EffectivePermission
	for _, perm := range perms {
		if pr.withinBoundary(perm, boundary) {
			filtered = append(filtered, perm)
		}
	}
	return filtered, nil
}

// withinBoundary checks if a permission falls within the boundary's maximum allowed scope.
func (pr *PermissionResolver) withinBoundary(perm EffectivePermission, boundary *PermissionBoundary) bool {
	// Deny permissions always pass through boundaries
	if perm.Effect == EffectDeny {
		return true
	}

	// Check action is within boundary
	actionAllowed := false
	for _, maxAction := range boundary.MaxActions {
		if string(maxAction) == "*" || maxAction == perm.Action {
			actionAllowed = true
			break
		}
	}
	if !actionAllowed {
		return false
	}

	// Check resource is within boundary
	if len(boundary.MaxResources) == 0 {
		return true
	}
	for _, pattern := range boundary.MaxResources {
		if utils.MatchResource(perm.Resource, pattern) {
			return true
		}
	}
	return false
}

// HasPermission checks if a user effectively has a specific action on a resource.
// Deny permissions take precedence over allow.
func (pr *PermissionResolver) HasPermission(ctx context.Context, userID, tenantID string, action Action, resource string) (bool, error) {
	perms, err := pr.GetEffectivePermissionsWithBoundary(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}

	hasAllow := false
	for _, perm := range perms {
		// Check if this permission matches the requested action/resource
		actionMatch := string(perm.Action) == "*" || perm.Action == action
		resourceMatch := utils.MatchResource(resource, perm.Resource)

		if actionMatch && resourceMatch {
			if perm.Effect == EffectDeny {
				return false, nil // explicit deny wins
			}
			if perm.Effect == EffectAllow {
				hasAllow = true
			}
		}
	}
	return hasAllow, nil
}

// ComparePermissions shows the diff between two users' effective permissions.
func (pr *PermissionResolver) ComparePermissions(ctx context.Context, userID1, userID2, tenantID string) (onlyUser1, onlyUser2, shared []EffectivePermission, err error) {
	perms1, err := pr.GetEffectivePermissions(ctx, userID1, tenantID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve permissions for user %s: %w", userID1, err)
	}
	perms2, err := pr.GetEffectivePermissions(ctx, userID2, tenantID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve permissions for user %s: %w", userID2, err)
	}

	set1 := make(map[string]EffectivePermission)
	for _, p := range perms1 {
		key := permKey(p)
		set1[key] = p
	}

	set2 := make(map[string]EffectivePermission)
	for _, p := range perms2 {
		key := permKey(p)
		set2[key] = p
	}

	for key, p := range set1 {
		if _, ok := set2[key]; ok {
			shared = append(shared, p)
		} else {
			onlyUser1 = append(onlyUser1, p)
		}
	}
	for key, p := range set2 {
		if _, ok := set1[key]; !ok {
			onlyUser2 = append(onlyUser2, p)
		}
	}
	return onlyUser1, onlyUser2, shared, nil
}

// permKey produces a stable key for deduplication / comparison.
func permKey(p EffectivePermission) string {
	return string(p.Action) + "|" + p.Resource + "|" + string(p.Effect)
}
