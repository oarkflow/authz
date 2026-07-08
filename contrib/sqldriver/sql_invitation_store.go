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

// SQLInvitationStore persists invitations in SQL (squealx).
type SQLInvitationStore struct {
	db *squealx.DB
}

// NewSQLInvitationStore creates a new SQL-backed invitation store.
func NewSQLInvitationStore(db *squealx.DB) *SQLInvitationStore {
	return &SQLInvitationStore{db: db}
}

func (s *SQLInvitationStore) CreateInvitation(ctx context.Context, invite *authz.Invitation) error {
	if invite.CreatedAt.IsZero() {
		invite.CreatedAt = time.Now()
	}

	roleIDsJSON := "[]"
	if invite.RoleIDs != nil {
		b, err := json.Marshal(invite.RoleIDs)
		if err != nil {
			return fmt.Errorf("failed to marshal role_ids: %w", err)
		}
		roleIDsJSON = string(b)
	}

	groupIDsJSON := "[]"
	if invite.GroupIDs != nil {
		b, err := json.Marshal(invite.GroupIDs)
		if err != nil {
			return fmt.Errorf("failed to marshal group_ids: %w", err)
		}
		groupIDsJSON = string(b)
	}

	q := `INSERT INTO invitations (id, tenant_id, email, role_ids_json, group_ids_json, token_hash, status, invited_by, message, expires_at, created_at, accepted_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var acceptedAt *time.Time
	if !invite.AcceptedAt.IsZero() {
		acceptedAt = &invite.AcceptedAt
	}

	result, err := s.db.ExecContext(ctx, q,
		invite.ID, invite.TenantID, invite.Email, roleIDsJSON, groupIDsJSON,
		invite.TokenHash, string(invite.Status), invite.InvitedBy, invite.Message,
		invite.ExpiresAt, invite.CreatedAt, acceptedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert invitation: %w", err)
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("no rows inserted for invitation %s", invite.ID)
	}
	return nil
}

func (s *SQLInvitationStore) UpdateInvitation(ctx context.Context, invite *authz.Invitation) error {
	roleIDsJSON := "[]"
	if invite.RoleIDs != nil {
		b, err := json.Marshal(invite.RoleIDs)
		if err != nil {
			return fmt.Errorf("failed to marshal role_ids: %w", err)
		}
		roleIDsJSON = string(b)
	}

	groupIDsJSON := "[]"
	if invite.GroupIDs != nil {
		b, err := json.Marshal(invite.GroupIDs)
		if err != nil {
			return fmt.Errorf("failed to marshal group_ids: %w", err)
		}
		groupIDsJSON = string(b)
	}

	var acceptedAt *time.Time
	if !invite.AcceptedAt.IsZero() {
		acceptedAt = &invite.AcceptedAt
	}

	q := `UPDATE invitations SET tenant_id = :tenant_id, email = :email, role_ids_json = :role_ids_json, group_ids_json = :group_ids_json, token_hash = :token_hash, status = :status, invited_by = :invited_by, message = :message, expires_at = :expires_at, accepted_at = :accepted_at WHERE id = :id`
	result, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":             invite.ID,
		"tenant_id":      invite.TenantID,
		"email":          invite.Email,
		"role_ids_json":  roleIDsJSON,
		"group_ids_json": groupIDsJSON,
		"token_hash":     invite.TokenHash,
		"status":         string(invite.Status),
		"invited_by":     invite.InvitedBy,
		"message":        invite.Message,
		"expires_at":     invite.ExpiresAt,
		"accepted_at":    acceptedAt,
	})
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("invitation not found: %s", invite.ID)
	}
	return nil
}

func (s *SQLInvitationStore) DeleteInvitation(ctx context.Context, id string) error {
	q := `DELETE FROM invitations WHERE id = ?`
	result, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("invitation not found: %s", id)
	}
	return nil
}

func (s *SQLInvitationStore) GetInvitation(ctx context.Context, id string) (*authz.Invitation, error) {
	q := `SELECT id, tenant_id, email, role_ids_json, group_ids_json, token_hash, status, invited_by, message, expires_at, created_at, accepted_at FROM invitations WHERE id = ?`
	row := s.db.QueryRowxContext(ctx, q, id)
	return scanInvitation(row)
}

func (s *SQLInvitationStore) GetInvitationByToken(ctx context.Context, tokenHash string) (*authz.Invitation, error) {
	q := `SELECT id, tenant_id, email, role_ids_json, group_ids_json, token_hash, status, invited_by, message, expires_at, created_at, accepted_at FROM invitations WHERE token_hash = ?`
	row := s.db.QueryRowxContext(ctx, q, tokenHash)
	return scanInvitation(row)
}

func (s *SQLInvitationStore) ListInvitations(ctx context.Context, tenantID string) ([]*authz.Invitation, error) {
	q := `SELECT id, tenant_id, email, role_ids_json, group_ids_json, token_hash, status, invited_by, message, expires_at, created_at, accepted_at FROM invitations WHERE tenant_id = ?`
	rows, err := s.db.QueryxContext(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInvitations(rows)
}

func (s *SQLInvitationStore) ListPendingByEmail(ctx context.Context, email string) ([]*authz.Invitation, error) {
	q := `SELECT id, tenant_id, email, role_ids_json, group_ids_json, token_hash, status, invited_by, message, expires_at, created_at, accepted_at FROM invitations WHERE email = ? AND status = 'pending'`
	rows, err := s.db.QueryxContext(ctx, q, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInvitations(rows)
}

// scanInvitation scans a single invitation row.
func scanInvitation(row *squealx.Row) (*authz.Invitation, error) {
	var inv authz.Invitation
	var roleIDsJSON, groupIDsJSON, tokenHash, status, invitedBy, message sql.NullString
	var expiresAt, createdAt sql.NullString
	var acceptedAt sql.NullString

	err := row.Scan(&inv.ID, &inv.TenantID, &inv.Email, &roleIDsJSON, &groupIDsJSON, &tokenHash, &status, &invitedBy, &message, &expiresAt, &createdAt, &acceptedAt)
	if err != nil {
		return nil, fmt.Errorf("invitation not found")
	}

	if roleIDsJSON.Valid && roleIDsJSON.String != "" {
		_ = json.Unmarshal([]byte(roleIDsJSON.String), &inv.RoleIDs)
	}
	if groupIDsJSON.Valid && groupIDsJSON.String != "" {
		_ = json.Unmarshal([]byte(groupIDsJSON.String), &inv.GroupIDs)
	}
	if tokenHash.Valid {
		inv.TokenHash = tokenHash.String
	}
	if status.Valid {
		inv.Status = authz.InviteStatus(status.String)
	}
	if invitedBy.Valid {
		inv.InvitedBy = invitedBy.String
	}
	if message.Valid {
		inv.Message = message.String
	}
	if expiresAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", expiresAt.String); err == nil {
			inv.ExpiresAt = t
		}
	}
	if createdAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", createdAt.String); err == nil {
			inv.CreatedAt = t
		}
	}
	if acceptedAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", acceptedAt.String); err == nil {
			inv.AcceptedAt = t
		}
	}

	return &inv, nil
}

// scanInvitations scans multiple invitation rows.
func scanInvitations(rows *squealx.Rows) ([]*authz.Invitation, error) {
	var invitations []*authz.Invitation
	for rows.Next() {
		var inv authz.Invitation
		var roleIDsJSON, groupIDsJSON, tokenHash, status, invitedBy, message *string
		var expiresAt, createdAt, acceptedAt *time.Time

		err := rows.Scan(&inv.ID, &inv.TenantID, &inv.Email, &roleIDsJSON, &groupIDsJSON, &tokenHash, &status, &invitedBy, &message, &expiresAt, &createdAt, &acceptedAt)
		if err != nil {
			return nil, err
		}

		if roleIDsJSON != nil && *roleIDsJSON != "" {
			_ = json.Unmarshal([]byte(*roleIDsJSON), &inv.RoleIDs)
		}
		if groupIDsJSON != nil && *groupIDsJSON != "" {
			_ = json.Unmarshal([]byte(*groupIDsJSON), &inv.GroupIDs)
		}
		if tokenHash != nil {
			inv.TokenHash = *tokenHash
		}
		if status != nil {
			inv.Status = authz.InviteStatus(*status)
		}
		if invitedBy != nil {
			inv.InvitedBy = *invitedBy
		}
		if message != nil {
			inv.Message = *message
		}
		if expiresAt != nil {
			inv.ExpiresAt = *expiresAt
		}
		if createdAt != nil {
			inv.CreatedAt = *createdAt
		}
		if acceptedAt != nil {
			inv.AcceptedAt = *acceptedAt
		}

		invitations = append(invitations, &inv)
	}
	return invitations, nil
}
