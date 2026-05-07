package authz

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ServiceAccount represents a non-human identity
type ServiceAccount struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	ClientID     string     `json:"client_id"`
	ClientSecret string     `json:"-"` // hashed, never serialized
	Status       UserStatus `json:"status"`
	Roles        []string   `json:"roles"`
	Scopes       []string   `json:"scopes"`
	CreatedBy    string     `json:"created_by"`
	LastUsedAt   time.Time  `json:"last_used_at,omitempty"`
	ExpiresAt    time.Time  `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// ServiceAccountStore manages service account persistence
type ServiceAccountStore interface {
	CreateServiceAccount(ctx context.Context, sa *ServiceAccount) error
	UpdateServiceAccount(ctx context.Context, sa *ServiceAccount) error
	DeleteServiceAccount(ctx context.Context, id string) error
	GetServiceAccount(ctx context.Context, id string) (*ServiceAccount, error)
	GetServiceAccountByClientID(ctx context.Context, clientID string) (*ServiceAccount, error)
	ListServiceAccounts(ctx context.Context, tenantID string) ([]*ServiceAccount, error)
	UpdateLastUsed(ctx context.Context, id string) error
}

// GenerateClientCredentials creates a new client_id and hashed client_secret pair.
func GenerateClientCredentials() (clientID, plainSecret, hashedSecret string, err error) {
	idBytes := make([]byte, 16)
	if _, err = rand.Read(idBytes); err != nil {
		return "", "", "", fmt.Errorf("generate client_id: %w", err)
	}
	clientID = "sa_" + hex.EncodeToString(idBytes)

	secretBytes := make([]byte, 32)
	if _, err = rand.Read(secretBytes); err != nil {
		return "", "", "", fmt.Errorf("generate client_secret: %w", err)
	}
	plainSecret = hex.EncodeToString(secretBytes)

	hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", fmt.Errorf("hash client_secret: %w", err)
	}
	hashedSecret = string(hash)

	return clientID, plainSecret, hashedSecret, nil
}

// ValidateClientSecret checks plain secret against hash.
func ValidateClientSecret(plainSecret, hashedSecret string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(plainSecret)) == nil
}

// ToSubject converts a ServiceAccount to a Subject for authorization checks.
func (sa *ServiceAccount) ToSubject() *Subject {
	return &Subject{
		ID:       sa.ID,
		Type:     "service",
		TenantID: sa.TenantID,
		Roles:    sa.Roles,
		Attrs: map[string]any{
			"client_id":  sa.ClientID,
			"scopes":     sa.Scopes,
			"created_by": sa.CreatedBy,
		},
	}
}
