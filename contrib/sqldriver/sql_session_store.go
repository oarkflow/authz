package sqldriver

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLSessionStore persists sessions in SQL (squealx).
type SQLSessionStore struct {
	db *squealx.DB
}

// NewSQLSessionStore creates a new SQL-backed session store.
func NewSQLSessionStore(db *squealx.DB) *SQLSessionStore {
	return &SQLSessionStore{db: db}
}

func (s *SQLSessionStore) CreateSession(ctx context.Context, session *authz.Session) error {
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now()
	}

	q := `INSERT INTO sessions (id, user_id, tenant_id, refresh_token, ip_address, user_agent, expires_at, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, q, session.ID, session.UserID, session.TenantID,
		session.RefreshToken, session.IPAddress, session.UserAgent, session.ExpiresAt, session.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert session: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for session %s", session.ID)
	}
	return nil
}

func (s *SQLSessionStore) GetSession(ctx context.Context, id string) (*authz.Session, error) {
	q := `SELECT id, user_id, tenant_id, refresh_token, ip_address, user_agent, expires_at, created_at
	      FROM sessions WHERE id = ?`

	row := s.db.QueryRowxContext(ctx, q, id)

	var session authz.Session
	var refreshToken, ipAddress, userAgent sql.NullString
	var expiresAt, createdAt sql.NullString

	err := row.Scan(&session.ID, &session.UserID, &session.TenantID,
		&refreshToken, &ipAddress, &userAgent, &expiresAt, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	if refreshToken.Valid {
		session.RefreshToken = refreshToken.String
	}
	if ipAddress.Valid {
		session.IPAddress = ipAddress.String
	}
	if userAgent.Valid {
		session.UserAgent = userAgent.String
	}
	if expiresAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", expiresAt.String); err == nil {
			session.ExpiresAt = t
		}
	}
	if createdAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
			session.CreatedAt = t
		}
	}

	return &session, nil
}

func (s *SQLSessionStore) DeleteSession(ctx context.Context, id string) error {
	q := `DELETE FROM sessions WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("session not found: %s", id)
	}
	return nil
}

func (s *SQLSessionStore) DeleteUserSessions(ctx context.Context, userID string) error {
	q := `DELETE FROM sessions WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, q, userID)
	return err
}

func (s *SQLSessionStore) ListUserSessions(ctx context.Context, userID string) ([]*authz.Session, error) {
	q := `SELECT id, user_id, tenant_id, refresh_token, ip_address, user_agent, expires_at, created_at
	      FROM sessions WHERE user_id = ?`

	rows, err := s.db.QueryxContext(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*authz.Session
	for rows.Next() {
		var session authz.Session
		var refreshToken, ipAddress, userAgent *string
		var expiresAt, createdAt *time.Time

		err := rows.Scan(&session.ID, &session.UserID, &session.TenantID,
			&refreshToken, &ipAddress, &userAgent, &expiresAt, &createdAt)
		if err != nil {
			return nil, err
		}

		if refreshToken != nil {
			session.RefreshToken = *refreshToken
		}
		if ipAddress != nil {
			session.IPAddress = *ipAddress
		}
		if userAgent != nil {
			session.UserAgent = *userAgent
		}
		if expiresAt != nil {
			session.ExpiresAt = *expiresAt
		}
		if createdAt != nil {
			session.CreatedAt = *createdAt
		}

		sessions = append(sessions, &session)
	}

	return sessions, nil
}
