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

// SQLServiceAccountStore persists service accounts in SQL (squealx).
type SQLServiceAccountStore struct {
	db *squealx.DB
}

// NewSQLServiceAccountStore creates a new SQL-backed service account store.
func NewSQLServiceAccountStore(db *squealx.DB) *SQLServiceAccountStore {
	return &SQLServiceAccountStore{db: db}
}

func (s *SQLServiceAccountStore) CreateServiceAccount(ctx context.Context, sa *authz.ServiceAccount) error {
	if sa.CreatedAt.IsZero() {
		sa.CreatedAt = time.Now()
	}
	if sa.UpdatedAt.IsZero() {
		sa.UpdatedAt = sa.CreatedAt
	}
	if sa.Status == "" {
		sa.Status = authz.UserStatusActive
	}

	rolesJSON, err := json.Marshal(sa.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}
	scopesJSON, err := json.Marshal(sa.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	q := `INSERT INTO service_accounts (id, tenant_id, name, description, client_id, client_secret, status, roles_json, scopes_json, created_by, last_used_at, expires_at, created_at, updated_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, q,
		sa.ID, sa.TenantID, sa.Name, sa.Description,
		sa.ClientID, sa.ClientSecret, string(sa.Status),
		string(rolesJSON), string(scopesJSON),
		sa.CreatedBy, nullTime(sa.LastUsedAt), nullTime(sa.ExpiresAt),
		sa.CreatedAt, sa.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert service account: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for service account %s", sa.ID)
	}
	return nil
}

func (s *SQLServiceAccountStore) UpdateServiceAccount(ctx context.Context, sa *authz.ServiceAccount) error {
	sa.UpdatedAt = time.Now()

	rolesJSON, err := json.Marshal(sa.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}
	scopesJSON, err := json.Marshal(sa.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	q := `UPDATE service_accounts SET tenant_id = :tenant_id, name = :name, description = :description,
	      client_id = :client_id, client_secret = :client_secret, status = :status,
	      roles_json = :roles_json, scopes_json = :scopes_json, created_by = :created_by,
	      last_used_at = :last_used_at, expires_at = :expires_at, updated_at = :updated_at
	      WHERE id = :id`

	result, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":            sa.ID,
		"tenant_id":     sa.TenantID,
		"name":          sa.Name,
		"description":   sa.Description,
		"client_id":     sa.ClientID,
		"client_secret": sa.ClientSecret,
		"status":        string(sa.Status),
		"roles_json":    string(rolesJSON),
		"scopes_json":   string(scopesJSON),
		"created_by":    sa.CreatedBy,
		"last_used_at":  nullTime(sa.LastUsedAt),
		"expires_at":    nullTime(sa.ExpiresAt),
		"updated_at":    sa.UpdatedAt,
	})
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("service account not found: %s", sa.ID)
	}
	return nil
}

func (s *SQLServiceAccountStore) DeleteServiceAccount(ctx context.Context, id string) error {
	q := `DELETE FROM service_accounts WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("service account not found: %s", id)
	}
	return nil
}

func (s *SQLServiceAccountStore) GetServiceAccount(ctx context.Context, id string) (*authz.ServiceAccount, error) {
	q := `SELECT id, tenant_id, name, description, client_id, client_secret, status,
	      roles_json, scopes_json, created_by, last_used_at, expires_at, created_at, updated_at
	      FROM service_accounts WHERE id = ?`
	return s.scanServiceAccount(s.db.QueryRowxContext(ctx, q, id), id)
}

func (s *SQLServiceAccountStore) GetServiceAccountByClientID(ctx context.Context, clientID string) (*authz.ServiceAccount, error) {
	q := `SELECT id, tenant_id, name, description, client_id, client_secret, status,
	      roles_json, scopes_json, created_by, last_used_at, expires_at, created_at, updated_at
	      FROM service_accounts WHERE client_id = ?`
	return s.scanServiceAccount(s.db.QueryRowxContext(ctx, q, clientID), clientID)
}

func (s *SQLServiceAccountStore) ListServiceAccounts(ctx context.Context, tenantID string) ([]*authz.ServiceAccount, error) {
	q := `SELECT id, tenant_id, name, description, client_id, client_secret, status,
	      roles_json, scopes_json, created_by, last_used_at, expires_at, created_at, updated_at
	      FROM service_accounts`
	args := make([]any, 0)
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}

	rows, err := s.db.QueryxContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*authz.ServiceAccount
	for rows.Next() {
		var sa authz.ServiceAccount
		var description, status, rolesJSON, scopesJSON, createdBy sql.NullString
		var lastUsedAt, expiresAt, createdAt, updatedAt sql.NullString

		err := rows.Scan(&sa.ID, &sa.TenantID, &sa.Name, &description,
			&sa.ClientID, &sa.ClientSecret, &status,
			&rolesJSON, &scopesJSON, &createdBy,
			&lastUsedAt, &expiresAt, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		if description.Valid {
			sa.Description = description.String
		}
		if status.Valid {
			sa.Status = authz.UserStatus(status.String)
		}
		if rolesJSON.Valid && rolesJSON.String != "" {
			_ = json.Unmarshal([]byte(rolesJSON.String), &sa.Roles)
		}
		if scopesJSON.Valid && scopesJSON.String != "" {
			_ = json.Unmarshal([]byte(scopesJSON.String), &sa.Scopes)
		}
		if createdBy.Valid {
			sa.CreatedBy = createdBy.String
		}
		parseNullTime(lastUsedAt, &sa.LastUsedAt)
		parseNullTime(expiresAt, &sa.ExpiresAt)
		parseNullTime(createdAt, &sa.CreatedAt)
		parseNullTime(updatedAt, &sa.UpdatedAt)

		result = append(result, &sa)
	}

	return result, nil
}

func (s *SQLServiceAccountStore) UpdateLastUsed(ctx context.Context, id string) error {
	q := `UPDATE service_accounts SET last_used_at = ? WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, time.Now(), id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("service account not found: %s", id)
	}
	return nil
}

// scanServiceAccount scans a single row into a ServiceAccount.
func (s *SQLServiceAccountStore) scanServiceAccount(row *squealx.Row, identifier string) (*authz.ServiceAccount, error) {
	var sa authz.ServiceAccount
	var description, status, rolesJSON, scopesJSON, createdBy sql.NullString
	var lastUsedAt, expiresAt, createdAt, updatedAt sql.NullString

	err := row.Scan(&sa.ID, &sa.TenantID, &sa.Name, &description,
		&sa.ClientID, &sa.ClientSecret, &status,
		&rolesJSON, &scopesJSON, &createdBy,
		&lastUsedAt, &expiresAt, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("service account not found: %s", identifier)
	}

	if description.Valid {
		sa.Description = description.String
	}
	if status.Valid {
		sa.Status = authz.UserStatus(status.String)
	}
	if rolesJSON.Valid && rolesJSON.String != "" {
		_ = json.Unmarshal([]byte(rolesJSON.String), &sa.Roles)
	}
	if scopesJSON.Valid && scopesJSON.String != "" {
		_ = json.Unmarshal([]byte(scopesJSON.String), &sa.Scopes)
	}
	if createdBy.Valid {
		sa.CreatedBy = createdBy.String
	}
	parseNullTime(lastUsedAt, &sa.LastUsedAt)
	parseNullTime(expiresAt, &sa.ExpiresAt)
	parseNullTime(createdAt, &sa.CreatedAt)
	parseNullTime(updatedAt, &sa.UpdatedAt)

	return &sa, nil
}

// nullTime returns nil for zero time values for SQL insertion.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// parseNullTime parses a sql.NullString into a *time.Time field.
func parseNullTime(ns sql.NullString, dest *time.Time) {
	if ns.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", ns.String); err == nil {
			*dest = t
		}
	}
}
