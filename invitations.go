package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// InviteStatus represents the state of an invitation
type InviteStatus string

const (
	InviteStatusPending  InviteStatus = "pending"
	InviteStatusAccepted InviteStatus = "accepted"
	InviteStatusExpired  InviteStatus = "expired"
	InviteStatusRevoked  InviteStatus = "revoked"
)

// Invitation represents a pending user invite
type Invitation struct {
	ID         string       `json:"id"`
	TenantID   string       `json:"tenant_id"`
	Email      string       `json:"email"`
	RoleIDs    []string     `json:"role_ids"`
	GroupIDs   []string     `json:"group_ids,omitempty"`
	Token      string       `json:"-"` // secure random token
	TokenHash  string       `json:"-"` // stored hash of token
	Status     InviteStatus `json:"status"`
	InvitedBy  string       `json:"invited_by"` // user ID of inviter
	Message    string       `json:"message,omitempty"`
	ExpiresAt  time.Time    `json:"expires_at"`
	CreatedAt  time.Time    `json:"created_at"`
	AcceptedAt time.Time    `json:"accepted_at,omitempty"`
}

// InvitationStore manages invitation persistence
type InvitationStore interface {
	CreateInvitation(ctx context.Context, invite *Invitation) error
	GetInvitation(ctx context.Context, id string) (*Invitation, error)
	GetInvitationByToken(ctx context.Context, tokenHash string) (*Invitation, error)
	UpdateInvitation(ctx context.Context, invite *Invitation) error
	DeleteInvitation(ctx context.Context, id string) error
	ListInvitations(ctx context.Context, tenantID string) ([]*Invitation, error)
	ListPendingByEmail(ctx context.Context, email string) ([]*Invitation, error)
}

// GenerateInviteToken generates a secure random token and its hash
func GenerateInviteToken() (token, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(b)
	tokenHash = HashInviteToken(token)
	return token, tokenHash, nil
}

// HashInviteToken hashes a token for storage
func HashInviteToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// IsExpired checks if the invitation has expired
func (inv *Invitation) IsExpired() bool {
	return !inv.ExpiresAt.IsZero() && time.Now().After(inv.ExpiresAt)
}
