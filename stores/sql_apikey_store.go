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

// SQLAPIKeyStore persists API keys in SQL (squealx).
type SQLAPIKeyStore struct {
	db *squealx.DB
}

// NewSQLAPIKeyStore creates a new SQL-backed API key store.
func NewSQLAPIKeyStore(db *squealx.DB) *SQLAPIKeyStore {
	return &SQLAPIKeyStore{db: db}
}

func (s *SQLAPIKeyStore) CreateAPIKey(ctx context.Context, key *authz.APIKey) error {
	if key.CreatedAt.IsZero() {
		key.CreatedAt = time.Now()
	}

	scopesJSON := "[]"
	if key.Scopes != nil {
		b, err := json.Marshal(key.Scopes)
		if err != nil {
			return fmt.Errorf("failed to marshal scopes: %w", err)
		}
		scopesJSON = string(b)
	}

	q := `INSERT INTO api_keys (id, name, prefix, key_hash, user_id, tenant_id, scopes_json, expires_at, last_used, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, q, key.ID, key.Name, key.Prefix, key.KeyHash,
		key.UserID, key.TenantID, scopesJSON, key.ExpiresAt, key.LastUsed, key.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert api key: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for api key %s", key.ID)
	}
	return nil
}

func (s *SQLAPIKeyStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*authz.APIKey, error) {
	q := `SELECT id, name, prefix, key_hash, user_id, tenant_id, scopes_json, expires_at, last_used, created_at
	      FROM api_keys WHERE prefix = ?`

	row := s.db.QueryRowxContext(ctx, q, prefix)

	var key authz.APIKey
	var name, scopesJSON sql.NullString
	var expiresAt, lastUsed, createdAt sql.NullString

	err := row.Scan(&key.ID, &name, &key.Prefix, &key.KeyHash,
		&key.UserID, &key.TenantID, &scopesJSON, &expiresAt, &lastUsed, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("api key not found for prefix: %s", prefix)
	}

	if name.Valid {
		key.Name = name.String
	}
	if scopesJSON.Valid && scopesJSON.String != "" {
		_ = json.Unmarshal([]byte(scopesJSON.String), &key.Scopes)
	}
	if expiresAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", expiresAt.String); err == nil {
			key.ExpiresAt = t
		}
	}
	if lastUsed.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", lastUsed.String); err == nil {
			key.LastUsed = t
		}
	}
	if createdAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
			key.CreatedAt = t
		}
	}

	return &key, nil
}

func (s *SQLAPIKeyStore) ListAPIKeys(ctx context.Context, userID string) ([]*authz.APIKey, error) {
	q := `SELECT id, name, prefix, key_hash, user_id, tenant_id, scopes_json, expires_at, last_used, created_at
	      FROM api_keys WHERE user_id = ?`

	rows, err := s.db.QueryxContext(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*authz.APIKey
	for rows.Next() {
		var key authz.APIKey
		var name, scopesJSON *string
		var expiresAt, lastUsed, createdAt *time.Time

		err := rows.Scan(&key.ID, &name, &key.Prefix, &key.KeyHash,
			&key.UserID, &key.TenantID, &scopesJSON, &expiresAt, &lastUsed, &createdAt)
		if err != nil {
			return nil, err
		}

		if name != nil {
			key.Name = *name
		}
		if scopesJSON != nil && *scopesJSON != "" {
			_ = json.Unmarshal([]byte(*scopesJSON), &key.Scopes)
		}
		if expiresAt != nil {
			key.ExpiresAt = *expiresAt
		}
		if lastUsed != nil {
			key.LastUsed = *lastUsed
		}
		if createdAt != nil {
			key.CreatedAt = *createdAt
		}

		keys = append(keys, &key)
	}

	return keys, nil
}

func (s *SQLAPIKeyStore) DeleteAPIKey(ctx context.Context, id string) error {
	q := `DELETE FROM api_keys WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("api key not found: %s", id)
	}
	return nil
}

func (s *SQLAPIKeyStore) UpdateLastUsed(ctx context.Context, id string) error {
	q := `UPDATE api_keys SET last_used = ? WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, time.Now(), id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("api key not found: %s", id)
	}
	return nil
}
