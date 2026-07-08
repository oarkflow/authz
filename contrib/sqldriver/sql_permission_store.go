package sqldriver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLPermissionBoundaryStore persists permission boundaries in SQL (squealx).
type SQLPermissionBoundaryStore struct {
	db *squealx.DB
}

// NewSQLPermissionBoundaryStore creates a new SQL-backed permission boundary store.
func NewSQLPermissionBoundaryStore(db *squealx.DB) *SQLPermissionBoundaryStore {
	return &SQLPermissionBoundaryStore{db: db}
}

func (s *SQLPermissionBoundaryStore) CreateBoundary(ctx context.Context, boundary *authz.PermissionBoundary) error {
	if boundary.CreatedAt.IsZero() {
		boundary.CreatedAt = time.Now()
	}

	actionsJSON, err := json.Marshal(boundary.MaxActions)
	if err != nil {
		return fmt.Errorf("failed to marshal max_actions: %w", err)
	}
	resourcesJSON, err := json.Marshal(boundary.MaxResources)
	if err != nil {
		return fmt.Errorf("failed to marshal max_resources: %w", err)
	}

	q := `INSERT INTO permission_boundaries (id, tenant_id, name, max_actions_json, max_resources_json, created_at)
	      VALUES (?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, q, boundary.ID, boundary.TenantID, boundary.Name, string(actionsJSON), string(resourcesJSON), boundary.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert permission boundary: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for boundary %s", boundary.ID)
	}
	return nil
}

func (s *SQLPermissionBoundaryStore) UpdateBoundary(ctx context.Context, boundary *authz.PermissionBoundary) error {
	actionsJSON, err := json.Marshal(boundary.MaxActions)
	if err != nil {
		return fmt.Errorf("failed to marshal max_actions: %w", err)
	}
	resourcesJSON, err := json.Marshal(boundary.MaxResources)
	if err != nil {
		return fmt.Errorf("failed to marshal max_resources: %w", err)
	}

	q := `UPDATE permission_boundaries SET tenant_id = :tenant_id, name = :name, max_actions_json = :max_actions_json, max_resources_json = :max_resources_json WHERE id = :id`
	result, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":                 boundary.ID,
		"tenant_id":          boundary.TenantID,
		"name":               boundary.Name,
		"max_actions_json":   string(actionsJSON),
		"max_resources_json": string(resourcesJSON),
	})
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("boundary not found: %s", boundary.ID)
	}
	return nil
}

func (s *SQLPermissionBoundaryStore) DeleteBoundary(ctx context.Context, id string) error {
	q := `DELETE FROM permission_boundaries WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("boundary not found: %s", id)
	}
	return nil
}

func (s *SQLPermissionBoundaryStore) GetBoundary(ctx context.Context, id string) (*authz.PermissionBoundary, error) {
	q := `SELECT id, tenant_id, name, max_actions_json, max_resources_json, created_at FROM permission_boundaries WHERE id = ?`

	row := s.db.QueryRowxContext(ctx, q, id)

	var boundary authz.PermissionBoundary
	var actionsJSON, resourcesJSON sql.NullString
	var createdAt sql.NullString

	err := row.Scan(&boundary.ID, &boundary.TenantID, &boundary.Name, &actionsJSON, &resourcesJSON, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("boundary not found: %s", id)
	}

	if actionsJSON.Valid && actionsJSON.String != "" {
		_ = json.Unmarshal([]byte(actionsJSON.String), &boundary.MaxActions)
	}
	if resourcesJSON.Valid && resourcesJSON.String != "" {
		_ = json.Unmarshal([]byte(resourcesJSON.String), &boundary.MaxResources)
	}
	if createdAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
			boundary.CreatedAt = t
		}
	}

	return &boundary, nil
}

func (s *SQLPermissionBoundaryStore) ListBoundaries(ctx context.Context, tenantID string) ([]*authz.PermissionBoundary, error) {
	q := `SELECT id, tenant_id, name, max_actions_json, max_resources_json, created_at FROM permission_boundaries`
	args := []any{}
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}

	rows, err := s.db.QueryxContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var boundaries []*authz.PermissionBoundary
	for rows.Next() {
		var boundary authz.PermissionBoundary
		var actionsJSON, resourcesJSON *string
		var createdAt *time.Time

		err := rows.Scan(&boundary.ID, &boundary.TenantID, &boundary.Name, &actionsJSON, &resourcesJSON, &createdAt)
		if err != nil {
			return nil, err
		}

		if actionsJSON != nil && *actionsJSON != "" {
			_ = json.Unmarshal([]byte(*actionsJSON), &boundary.MaxActions)
		}
		if resourcesJSON != nil && *resourcesJSON != "" {
			_ = json.Unmarshal([]byte(*resourcesJSON), &boundary.MaxResources)
		}
		if createdAt != nil {
			boundary.CreatedAt = *createdAt
		}

		boundaries = append(boundaries, &boundary)
	}

	return boundaries, nil
}

// SQLUserBoundaryStore persists user-to-boundary mappings in SQL (squealx).
type SQLUserBoundaryStore struct {
	db *squealx.DB
}

// NewSQLUserBoundaryStore creates a new SQL-backed user boundary store.
func NewSQLUserBoundaryStore(db *squealx.DB) *SQLUserBoundaryStore {
	return &SQLUserBoundaryStore{db: db}
}

func (s *SQLUserBoundaryStore) SetBoundary(ctx context.Context, userID, boundaryID string) error {
	q := `INSERT INTO user_boundaries (user_id, boundary_id) VALUES (?, ?)
	      ON CONFLICT(user_id) DO UPDATE SET boundary_id = ?`
	_, err := s.db.ExecContext(ctx, q, userID, boundaryID, boundaryID)
	return err
}

func (s *SQLUserBoundaryStore) RemoveBoundary(ctx context.Context, userID string) error {
	q := `DELETE FROM user_boundaries WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, q, userID)
	return err
}

func (s *SQLUserBoundaryStore) GetBoundary(ctx context.Context, userID string) (string, error) {
	q := `SELECT boundary_id FROM user_boundaries WHERE user_id = ?`
	row := s.db.QueryRowxContext(ctx, q, userID)

	var boundaryID string
	err := row.Scan(&boundaryID)
	if err != nil {
		return "", nil // no boundary assigned
	}
	return boundaryID, nil
}
