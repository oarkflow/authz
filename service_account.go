package authz

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	saArgonTime    = 3
	saArgonMemory  = 64 * 1024
	saArgonThreads = 4
	saArgonKeyLen  = 32
	saArgonSaltLen = 16
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

	salt := make([]byte, saArgonSaltLen)
	if _, err = rand.Read(salt); err != nil {
		return "", "", "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(plainSecret), salt, saArgonTime, saArgonMemory, saArgonThreads, saArgonKeyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	hashedSecret = fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", saArgonMemory, saArgonTime, saArgonThreads, b64Salt, b64Hash)

	return clientID, plainSecret, hashedSecret, nil
}

func decodeArgon2id(encoded string) (salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, errors.New("invalid argon2id hash format")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid salt encoding: %w", err)
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid hash encoding: %w", err)
	}
	return salt, hash, nil
}

// ValidateClientSecret checks plain secret against argon2id hash.
func ValidateClientSecret(plainSecret, hashedSecret string) bool {
	salt, expected, err := decodeArgon2id(hashedSecret)
	if err != nil {
		return false
	}
	computed := argon2.IDKey([]byte(plainSecret), salt, saArgonTime, saArgonMemory, saArgonThreads, saArgonKeyLen)
	return hmac.Equal(computed, expected)
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
