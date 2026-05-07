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

// SQLUserStore persists users in SQL (squealx).
type SQLUserStore struct {
	db *squealx.DB
}

// NewSQLUserStore creates a new SQL-backed user store.
func NewSQLUserStore(db *squealx.DB) *SQLUserStore {
	return &SQLUserStore{db: db}
}

func (s *SQLUserStore) CreateUser(ctx context.Context, user *authz.User) error {
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = user.CreatedAt
	}
	if user.Status == "" {
		user.Status = authz.UserStatusActive
	}

	attrsJSON := "{}"
	if user.Attrs != nil {
		b, err := json.Marshal(user.Attrs)
		if err != nil {
			return fmt.Errorf("failed to marshal attrs: %w", err)
		}
		attrsJSON = string(b)
	}

	q := `INSERT INTO users (id, tenant_id, email, name, password_hash, status, email_verified, mfa_enabled, mfa_secret, attrs_json, last_login_at, created_at, updated_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	emailVerified := 0
	if user.EmailVerified {
		emailVerified = 1
	}
	mfaEnabled := 0
	if user.MFAEnabled {
		mfaEnabled = 1
	}

	var lastLoginAt *time.Time
	if !user.LastLoginAt.IsZero() {
		lastLoginAt = &user.LastLoginAt
	}

	result, err := s.db.ExecContext(ctx, q, user.ID, user.TenantID, user.Email, user.Name, user.PasswordHash, string(user.Status), emailVerified, mfaEnabled, user.MFASecret, attrsJSON, lastLoginAt, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for user %s", user.ID)
	}
	return nil
}

func (s *SQLUserStore) UpdateUser(ctx context.Context, user *authz.User) error {
	user.UpdatedAt = time.Now()

	attrsJSON := "{}"
	if user.Attrs != nil {
		b, err := json.Marshal(user.Attrs)
		if err != nil {
			return fmt.Errorf("failed to marshal attrs: %w", err)
		}
		attrsJSON = string(b)
	}

	emailVerified := 0
	if user.EmailVerified {
		emailVerified = 1
	}
	mfaEnabled := 0
	if user.MFAEnabled {
		mfaEnabled = 1
	}

	var lastLoginAt *time.Time
	if !user.LastLoginAt.IsZero() {
		lastLoginAt = &user.LastLoginAt
	}

	q := `UPDATE users SET tenant_id = :tenant_id, email = :email, name = :name, password_hash = :password_hash, status = :status, email_verified = :email_verified, mfa_enabled = :mfa_enabled, mfa_secret = :mfa_secret, attrs_json = :attrs_json, last_login_at = :last_login_at, updated_at = :updated_at WHERE id = :id`
	result, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":             user.ID,
		"tenant_id":      user.TenantID,
		"email":          user.Email,
		"name":           user.Name,
		"password_hash":  user.PasswordHash,
		"status":         string(user.Status),
		"email_verified": emailVerified,
		"mfa_enabled":    mfaEnabled,
		"mfa_secret":     user.MFASecret,
		"attrs_json":     attrsJSON,
		"last_login_at":  lastLoginAt,
		"updated_at":     user.UpdatedAt,
	})
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("user not found: %s", user.ID)
	}
	return nil
}

func (s *SQLUserStore) DeleteUser(ctx context.Context, id string) error {
	q := `DELETE FROM users WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("user not found: %s", id)
	}
	return nil
}

func (s *SQLUserStore) GetUser(ctx context.Context, id string) (*authz.User, error) {
	q := `SELECT id, tenant_id, email, name, password_hash, status, email_verified, mfa_enabled, mfa_secret, attrs_json, last_login_at, created_at, updated_at FROM users WHERE id = ?`
	row := s.db.QueryRowxContext(ctx, q, id)
	return s.scanUser(row)
}

func (s *SQLUserStore) GetUserByEmail(ctx context.Context, tenantID, email string) (*authz.User, error) {
	q := `SELECT id, tenant_id, email, name, password_hash, status, email_verified, mfa_enabled, mfa_secret, attrs_json, last_login_at, created_at, updated_at FROM users WHERE tenant_id = ? AND email = ?`
	row := s.db.QueryRowxContext(ctx, q, tenantID, email)
	return s.scanUser(row)
}

func (s *SQLUserStore) scanUser(row *squealx.Row) (*authz.User, error) {
	var user authz.User
	var passwordHash, mfaSecret, attrsJSON, status sql.NullString
	var name sql.NullString
	var emailVerified, mfaEnabled int
	var lastLoginAt, createdAt, updatedAt sql.NullString

	err := row.Scan(&user.ID, &user.TenantID, &user.Email, &name, &passwordHash, &status, &emailVerified, &mfaEnabled, &mfaSecret, &attrsJSON, &lastLoginAt, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	if name.Valid {
		user.Name = name.String
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if status.Valid {
		user.Status = authz.UserStatus(status.String)
	}
	user.EmailVerified = emailVerified != 0
	user.MFAEnabled = mfaEnabled != 0
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
	}
	if attrsJSON.Valid && attrsJSON.String != "" {
		_ = json.Unmarshal([]byte(attrsJSON.String), &user.Attrs)
	}
	if lastLoginAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", lastLoginAt.String); err == nil {
			user.LastLoginAt = t
		}
	}
	if createdAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
			user.CreatedAt = t
		}
	}
	if updatedAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", updatedAt.String); err == nil {
			user.UpdatedAt = t
		}
	}

	return &user, nil
}

func (s *SQLUserStore) ListUsers(ctx context.Context, filter authz.UserFilter) ([]*authz.User, error) {
	q := `SELECT id, tenant_id, email, name, password_hash, status, email_verified, mfa_enabled, mfa_secret, attrs_json, last_login_at, created_at, updated_at FROM users WHERE 1=1`
	args := make([]any, 0)

	if filter.TenantID != "" {
		q += ` AND tenant_id = ?`
		args = append(args, filter.TenantID)
	}
	if filter.Email != "" {
		q += ` AND email = ?`
		args = append(args, filter.Email)
	}
	if filter.Status != "" {
		q += ` AND status = ?`
		args = append(args, string(filter.Status))
	}
	if filter.Query != "" {
		q += ` AND (LOWER(name) LIKE ? OR LOWER(email) LIKE ?)`
		like := "%" + filter.Query + "%"
		args = append(args, like, like)
	}

	q += ` ORDER BY created_at DESC`

	if filter.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		q += ` OFFSET ?`
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryxContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*authz.User
	for rows.Next() {
		var user authz.User
		var passwordHash, mfaSecret, attrsJSON, status, name sql.NullString
		var emailVerified, mfaEnabled int
		var lastLoginAt, createdAt, updatedAt sql.NullString

		err := rows.Scan(&user.ID, &user.TenantID, &user.Email, &name, &passwordHash, &status, &emailVerified, &mfaEnabled, &mfaSecret, &attrsJSON, &lastLoginAt, &createdAt, &updatedAt)
		if err != nil {
			return nil, err
		}

		if name.Valid {
			user.Name = name.String
		}
		if passwordHash.Valid {
			user.PasswordHash = passwordHash.String
		}
		if status.Valid {
			user.Status = authz.UserStatus(status.String)
		}
		user.EmailVerified = emailVerified != 0
		user.MFAEnabled = mfaEnabled != 0
		if mfaSecret.Valid {
			user.MFASecret = mfaSecret.String
		}
		if attrsJSON.Valid && attrsJSON.String != "" {
			_ = json.Unmarshal([]byte(attrsJSON.String), &user.Attrs)
		}
		if lastLoginAt.Valid {
			if t, err := time.Parse("2006-01-02 15:04:05", lastLoginAt.String); err == nil {
				user.LastLoginAt = t
			}
		}
		if createdAt.Valid {
			if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
				user.CreatedAt = t
			}
		}
		if updatedAt.Valid {
			if t, err := time.Parse("2006-01-02 15:04:05", updatedAt.String); err == nil {
				user.UpdatedAt = t
			}
		}

		users = append(users, &user)
	}

	return users, nil
}

func (s *SQLUserStore) CountUsers(ctx context.Context, filter authz.UserFilter) (int64, error) {
	q := `SELECT COUNT(*) FROM users WHERE 1=1`
	args := make([]any, 0)

	if filter.TenantID != "" {
		q += ` AND tenant_id = ?`
		args = append(args, filter.TenantID)
	}
	if filter.Email != "" {
		q += ` AND email = ?`
		args = append(args, filter.Email)
	}
	if filter.Status != "" {
		q += ` AND status = ?`
		args = append(args, string(filter.Status))
	}
	if filter.Query != "" {
		q += ` AND (LOWER(name) LIKE ? OR LOWER(email) LIKE ?)`
		like := "%" + filter.Query + "%"
		args = append(args, like, like)
	}

	var count int64
	err := s.db.QueryRowxContext(ctx, q, args...).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
