package sqldriver

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLScopeStore persists scopes in SQL (squealx).
type SQLScopeStore struct {
	db *squealx.DB
}

// NewSQLScopeStore creates a new SQL-backed scope store.
func NewSQLScopeStore(db *squealx.DB) *SQLScopeStore {
	return &SQLScopeStore{db: db}
}

func (s *SQLScopeStore) CreateScope(ctx context.Context, scope *authz.Scope) error {
	if scope.CreatedAt.IsZero() {
		scope.CreatedAt = time.Now()
	}

	q := `INSERT INTO scopes (id, tenant_id, name, description, parent_id, created_at)
	      VALUES (?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, q, scope.ID, scope.TenantID, scope.Name, scope.Description, scope.ParentID, scope.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert scope: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for scope %s", scope.ID)
	}
	return nil
}

func (s *SQLScopeStore) UpdateScope(ctx context.Context, scope *authz.Scope) error {
	q := `UPDATE scopes SET tenant_id = ?, name = ?, description = ?, parent_id = ? WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, scope.TenantID, scope.Name, scope.Description, scope.ParentID, scope.ID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("scope not found: %s", scope.ID)
	}
	return nil
}

func (s *SQLScopeStore) DeleteScope(ctx context.Context, id string) error {
	q := `DELETE FROM scopes WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("scope not found: %s", id)
	}
	return nil
}

func (s *SQLScopeStore) GetScope(ctx context.Context, id string) (*authz.Scope, error) {
	q := `SELECT id, tenant_id, name, description, parent_id, created_at FROM scopes WHERE id = ?`

	row := s.db.QueryRowxContext(ctx, q, id)

	var scope authz.Scope
	var description, parentID sql.NullString
	var createdAt sql.NullString

	err := row.Scan(&scope.ID, &scope.TenantID, &scope.Name, &description, &parentID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("scope not found: %s", id)
	}

	if description.Valid {
		scope.Description = description.String
	}
	if parentID.Valid {
		scope.ParentID = parentID.String
	}
	if createdAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
			scope.CreatedAt = t
		}
	}

	return &scope, nil
}

func (s *SQLScopeStore) ListScopes(ctx context.Context, tenantID string) ([]*authz.Scope, error) {
	q := `SELECT id, tenant_id, name, description, parent_id, created_at FROM scopes WHERE tenant_id = ?`

	rows, err := s.db.QueryxContext(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scopes []*authz.Scope
	for rows.Next() {
		var scope authz.Scope
		var description, parentID *string
		var createdAt *time.Time

		err := rows.Scan(&scope.ID, &scope.TenantID, &scope.Name, &description, &parentID, &createdAt)
		if err != nil {
			return nil, err
		}

		if description != nil {
			scope.Description = *description
		}
		if parentID != nil {
			scope.ParentID = *parentID
		}
		if createdAt != nil {
			scope.CreatedAt = *createdAt
		}

		scopes = append(scopes, &scope)
	}

	return scopes, nil
}

// SQLRoleScopeStore persists role-scope mappings in SQL (squealx).
type SQLRoleScopeStore struct {
	db *squealx.DB
}

// NewSQLRoleScopeStore creates a new SQL-backed role-scope store.
func NewSQLRoleScopeStore(db *squealx.DB) *SQLRoleScopeStore {
	return &SQLRoleScopeStore{db: db}
}

func (s *SQLRoleScopeStore) AssignScope(ctx context.Context, roleID, scopeID string) error {
	q := `INSERT INTO role_scopes (role_id, scope_id) VALUES (?, ?)`
	_, err := s.db.ExecContext(ctx, q, roleID, scopeID)
	if err != nil {
		return fmt.Errorf("failed to assign scope %s to role %s: %w", scopeID, roleID, err)
	}
	return nil
}

func (s *SQLRoleScopeStore) RevokeScope(ctx context.Context, roleID, scopeID string) error {
	q := `DELETE FROM role_scopes WHERE role_id = ? AND scope_id = ?`
	result, err := s.db.ExecContext(ctx, q, roleID, scopeID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("role-scope mapping not found: role=%s scope=%s", roleID, scopeID)
	}
	return nil
}

func (s *SQLRoleScopeStore) ListScopesByRole(ctx context.Context, roleID string) ([]string, error) {
	q := `SELECT scope_id FROM role_scopes WHERE role_id = ?`
	rows, err := s.db.QueryxContext(ctx, q, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var scopeID string
		if err := rows.Scan(&scopeID); err != nil {
			return nil, err
		}
		result = append(result, scopeID)
	}
	return result, nil
}

func (s *SQLRoleScopeStore) ListRolesByScope(ctx context.Context, scopeID string) ([]string, error) {
	q := `SELECT role_id FROM role_scopes WHERE scope_id = ?`
	rows, err := s.db.QueryxContext(ctx, q, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var roleID string
		if err := rows.Scan(&roleID); err != nil {
			return nil, err
		}
		result = append(result, roleID)
	}
	return result, nil
}
