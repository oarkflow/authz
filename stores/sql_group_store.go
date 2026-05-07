package stores

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// ============================================================================
// SQLGroupStore
// ============================================================================

// SQLGroupStore persists groups in SQL (squealx).
type SQLGroupStore struct {
	db *squealx.DB
}

// NewSQLGroupStore creates a new SQL-backed group store.
func NewSQLGroupStore(db *squealx.DB) *SQLGroupStore {
	return &SQLGroupStore{db: db}
}

func (s *SQLGroupStore) CreateGroup(ctx context.Context, group *authz.Group) error {
	if group.CreatedAt.IsZero() {
		group.CreatedAt = time.Now()
	}
	if group.UpdatedAt.IsZero() {
		group.UpdatedAt = group.CreatedAt
	}

	q := `INSERT INTO groups_ (id, tenant_id, name, description, parent_id, created_at, updated_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, q, group.ID, group.TenantID, group.Name, group.Description, group.ParentID, group.CreatedAt, group.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert group: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for group %s", group.ID)
	}
	return nil
}

func (s *SQLGroupStore) UpdateGroup(ctx context.Context, group *authz.Group) error {
	group.UpdatedAt = time.Now()

	q := `UPDATE groups_ SET tenant_id = :tenant_id, name = :name, description = :description, parent_id = :parent_id, updated_at = :updated_at WHERE id = :id`
	result, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":          group.ID,
		"tenant_id":   group.TenantID,
		"name":        group.Name,
		"description": group.Description,
		"parent_id":   group.ParentID,
		"updated_at":  group.UpdatedAt,
	})
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("group not found: %s", group.ID)
	}
	return nil
}

func (s *SQLGroupStore) DeleteGroup(ctx context.Context, id string) error {
	q := `DELETE FROM groups_ WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("group not found: %s", id)
	}
	return nil
}

func (s *SQLGroupStore) GetGroup(ctx context.Context, id string) (*authz.Group, error) {
	q := `SELECT id, tenant_id, name, description, parent_id, created_at, updated_at FROM groups_ WHERE id = ?`

	row := s.db.QueryRowxContext(ctx, q, id)

	var group authz.Group
	var description, parentID sql.NullString
	var createdAt, updatedAt sql.NullString

	err := row.Scan(&group.ID, &group.TenantID, &group.Name, &description, &parentID, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("group not found: %s", id)
	}

	if description.Valid {
		group.Description = description.String
	}
	if parentID.Valid {
		group.ParentID = parentID.String
	}
	if createdAt.Valid {
		if t, err := parseFlexibleTime(createdAt.String); err == nil {
			group.CreatedAt = t
		}
	}
	if updatedAt.Valid {
		if t, err := parseFlexibleTime(updatedAt.String); err == nil {
			group.UpdatedAt = t
		}
	}

	return &group, nil
}

func (s *SQLGroupStore) ListGroups(ctx context.Context, tenantID string) ([]*authz.Group, error) {
	q := `SELECT id, tenant_id, name, description, parent_id, created_at, updated_at FROM groups_ WHERE tenant_id = ?`

	rows, err := s.db.QueryxContext(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*authz.Group
	for rows.Next() {
		var group authz.Group
		var description, parentID sql.NullString
		var createdAt, updatedAt sql.NullString

		err := rows.Scan(&group.ID, &group.TenantID, &group.Name, &description, &parentID, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		if description.Valid {
			group.Description = description.String
		}
		if parentID.Valid {
			group.ParentID = parentID.String
		}
		if createdAt.Valid {
			if t, err := parseFlexibleTime(createdAt.String); err == nil {
				group.CreatedAt = t
			}
		}
		if updatedAt.Valid {
			if t, err := parseFlexibleTime(updatedAt.String); err == nil {
				group.UpdatedAt = t
			}
		}

		groups = append(groups, &group)
	}

	return groups, nil
}

// ============================================================================
// SQLGroupMembershipStore
// ============================================================================

// SQLGroupMembershipStore manages group membership in SQL.
type SQLGroupMembershipStore struct {
	db *squealx.DB
}

// NewSQLGroupMembershipStore creates a new SQL-backed group membership store.
func NewSQLGroupMembershipStore(db *squealx.DB) *SQLGroupMembershipStore {
	return &SQLGroupMembershipStore{db: db}
}

func (s *SQLGroupMembershipStore) AddMember(ctx context.Context, groupID, userID string) error {
	q := `INSERT OR IGNORE INTO group_members(group_id, user_id) VALUES(:group_id, :user_id)`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"group_id": groupID, "user_id": userID})
	return err
}

func (s *SQLGroupMembershipStore) RemoveMember(ctx context.Context, groupID, userID string) error {
	q := `DELETE FROM group_members WHERE group_id = :group_id AND user_id = :user_id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"group_id": groupID, "user_id": userID})
	return err
}

func (s *SQLGroupMembershipStore) ListMembers(ctx context.Context, groupID string) ([]string, error) {
	out := make([]string, 0)
	q := `SELECT user_id FROM group_members WHERE group_id = :group_id`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"group_id": groupID})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for r.Next() {
		var userID string
		if err := r.Scan(&userID); err != nil {
			return nil, err
		}
		out = append(out, userID)
	}
	return out, nil
}

func (s *SQLGroupMembershipStore) ListGroups(ctx context.Context, userID string) ([]string, error) {
	out := make([]string, 0)
	q := `SELECT group_id FROM group_members WHERE user_id = :user_id`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for r.Next() {
		var groupID string
		if err := r.Scan(&groupID); err != nil {
			return nil, err
		}
		out = append(out, groupID)
	}
	return out, nil
}

func (s *SQLGroupMembershipStore) IsMember(ctx context.Context, groupID, userID string) (bool, error) {
	q := `SELECT COUNT(*) FROM group_members WHERE group_id = :group_id AND user_id = :user_id`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"group_id": groupID, "user_id": userID})
	if err != nil {
		return false, err
	}
	defer r.Close()
	if r.Next() {
		var count int
		if err := r.Scan(&count); err != nil {
			return false, err
		}
		return count > 0, nil
	}
	return false, nil
}

// ============================================================================
// SQLGroupRoleStore
// ============================================================================

// SQLGroupRoleStore manages group-to-role assignments in SQL.
type SQLGroupRoleStore struct {
	db *squealx.DB
}

// NewSQLGroupRoleStore creates a new SQL-backed group role store.
func NewSQLGroupRoleStore(db *squealx.DB) *SQLGroupRoleStore {
	return &SQLGroupRoleStore{db: db}
}

func (s *SQLGroupRoleStore) AssignRole(ctx context.Context, groupID, roleID string) error {
	q := `INSERT OR IGNORE INTO group_roles(group_id, role_id) VALUES(:group_id, :role_id)`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"group_id": groupID, "role_id": roleID})
	return err
}

func (s *SQLGroupRoleStore) RevokeRole(ctx context.Context, groupID, roleID string) error {
	q := `DELETE FROM group_roles WHERE group_id = :group_id AND role_id = :role_id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"group_id": groupID, "role_id": roleID})
	return err
}

func (s *SQLGroupRoleStore) ListRolesByGroup(ctx context.Context, groupID string) ([]string, error) {
	out := make([]string, 0)
	q := `SELECT role_id FROM group_roles WHERE group_id = :group_id`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"group_id": groupID})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for r.Next() {
		var roleID string
		if err := r.Scan(&roleID); err != nil {
			return nil, err
		}
		out = append(out, roleID)
	}
	return out, nil
}

func (s *SQLGroupRoleStore) ListGroupsByRole(ctx context.Context, roleID string) ([]string, error) {
	out := make([]string, 0)
	q := `SELECT group_id FROM group_roles WHERE role_id = :role_id`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"role_id": roleID})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for r.Next() {
		var groupID string
		if err := r.Scan(&groupID); err != nil {
			return nil, err
		}
		out = append(out, groupID)
	}
	return out, nil
}
