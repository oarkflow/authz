package stores

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLTenantStore persists tenants in SQL (squealx).
type SQLTenantStore struct {
	db *squealx.DB
}

// NewSQLTenantStore creates a new SQL-backed tenant store.
func NewSQLTenantStore(db *squealx.DB) *SQLTenantStore {
	return &SQLTenantStore{db: db}
}

func (s *SQLTenantStore) CreateTenant(ctx context.Context, tenant *authz.Tenant) error {
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = time.Now()
	}
	if tenant.UpdatedAt.IsZero() {
		tenant.UpdatedAt = tenant.CreatedAt
	}

	attrsJSON := "{}"
	if tenant.Attrs != nil {
		b, err := json.Marshal(tenant.Attrs)
		if err != nil {
			return fmt.Errorf("failed to marshal attrs: %w", err)
		}
		attrsJSON = string(b)
	}

	q := `INSERT INTO tenants (id, name, parent_id, attrs_json, created_at, updated_at)
	      VALUES (?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, q, tenant.ID, tenant.Name, tenant.ParentID, attrsJSON, tenant.CreatedAt, tenant.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert tenant: %w", err)
	}

	// Check if a row was actually inserted
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for tenant %s", tenant.ID)
	}
	return err
}

func (s *SQLTenantStore) UpdateTenant(ctx context.Context, tenant *authz.Tenant) error {
	tenant.UpdatedAt = time.Now()

	attrsJSON := "{}"
	if tenant.Attrs != nil {
		b, err := json.Marshal(tenant.Attrs)
		if err != nil {
			return fmt.Errorf("failed to marshal attrs: %w", err)
		}
		attrsJSON = string(b)
	}

	q := `UPDATE tenants SET name = :name, parent_id = :parent_id, attrs_json = :attrs_json, updated_at = :updated_at WHERE id = :id`
	result, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":         tenant.ID,
		"name":       tenant.Name,
		"parent_id":  tenant.ParentID,
		"attrs_json": attrsJSON,
		"updated_at": tenant.UpdatedAt,
	})
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("tenant not found: %s", tenant.ID)
	}
	return nil
}

func (s *SQLTenantStore) DeleteTenant(ctx context.Context, id string) error {
	q := `DELETE FROM tenants WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("tenant not found: %s", id)
	}
	return nil
}

func (s *SQLTenantStore) GetTenant(ctx context.Context, id string) (*authz.Tenant, error) {
	q := `SELECT id, name, parent_id, attrs_json, created_at, updated_at FROM tenants WHERE id = ?`

	row := s.db.QueryRowxContext(ctx, q, id)

	var tenant authz.Tenant
	var parentID, attrsJSON sql.NullString
	var createdAt, updatedAt sql.NullString

	err := row.Scan(&tenant.ID, &tenant.Name, &parentID, &attrsJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %s", id)
	}

	if parentID.Valid {
		tenant.ParentID = parentID.String
	}
	if attrsJSON.Valid && attrsJSON.String != "" {
		_ = json.Unmarshal([]byte(attrsJSON.String), &tenant.Attrs)
	}
	if createdAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
			tenant.CreatedAt = t
		}
	}
	if updatedAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", updatedAt.String); err == nil {
			tenant.UpdatedAt = t
		}
	}

	return &tenant, nil
}

func (s *SQLTenantStore) ListTenants(ctx context.Context) ([]*authz.Tenant, error) {
	q := `SELECT id, name, parent_id, attrs_json, created_at, updated_at FROM tenants`

	rows, err := s.db.QueryxContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []*authz.Tenant
	for rows.Next() {
		var tenant authz.Tenant
		var parentID, attrsJSON *string
		var createdAt, updatedAt *time.Time

		err := rows.Scan(&tenant.ID, &tenant.Name, &parentID, &attrsJSON, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		if parentID != nil {
			tenant.ParentID = *parentID
		}
		if attrsJSON != nil && *attrsJSON != "" {
			_ = json.Unmarshal([]byte(*attrsJSON), &tenant.Attrs)
		}
		if createdAt != nil {
			tenant.CreatedAt = *createdAt
		}
		if updatedAt != nil {
			tenant.UpdatedAt = *updatedAt
		}

		tenants = append(tenants, &tenant)
	}

	return tenants, nil
}
