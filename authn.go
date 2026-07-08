package authz

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword hashes a plaintext password using argon2id.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("authn: failed to generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, b64Salt, b64Hash), nil
}

// CheckPassword compares an argon2id hash with a plaintext password.
func CheckPassword(encoded, password string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("authn: invalid argon2id hash format")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("authn: invalid salt encoding: %w", err)
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("authn: invalid hash encoding: %w", err)
	}
	computed := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	if !hmac.Equal(computed, expected) {
		return errors.New("authn: password mismatch")
	}
	return nil
}

// ============================================================================
// JWT TOKEN SYSTEM
// ============================================================================

// TokenClaims represents the payload of a JWT token.
type TokenClaims struct {
	UserID    string   `json:"uid"`
	TenantID  string   `json:"tid"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	Scopes    []string `json:"scopes,omitempty"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	TokenType string   `json:"typ"` // "access" or "refresh"
	Issuer    string   `json:"iss,omitempty"`
}

// TokenPair holds both access and refresh tokens.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"` // always "Bearer"
}

// TokenConfig holds configuration for token generation and validation.
type TokenConfig struct {
	Secret          []byte
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Issuer          string
}

// jwtHeader is the static header for HMAC-SHA256 JWTs.
var jwtHeader = base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))

// NewTokenConfig creates a new TokenConfig with sensible defaults.
func NewTokenConfig(secret []byte) *TokenConfig {
	return &TokenConfig{
		Secret:          secret,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "",
	}
}

// GenerateTokenPair creates a new access/refresh token pair from the given claims.
func (tc *TokenConfig) GenerateTokenPair(claims *TokenClaims) (*TokenPair, error) {
	now := time.Now().Unix()

	// Build access token claims
	accessClaims := *claims
	accessClaims.IssuedAt = now
	accessClaims.ExpiresAt = now + int64(tc.AccessTokenTTL.Seconds())
	accessClaims.TokenType = "access"
	accessClaims.Issuer = tc.Issuer

	accessToken, err := tc.signToken(&accessClaims)
	if err != nil {
		return nil, fmt.Errorf("authn: failed to generate access token: %w", err)
	}

	// Build refresh token claims
	refreshClaims := *claims
	refreshClaims.IssuedAt = now
	refreshClaims.ExpiresAt = now + int64(tc.RefreshTokenTTL.Seconds())
	refreshClaims.TokenType = "refresh"
	refreshClaims.Issuer = tc.Issuer

	refreshToken, err := tc.signToken(&refreshClaims)
	if err != nil {
		return nil, fmt.Errorf("authn: failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(tc.AccessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// ValidateToken parses and validates a JWT token string, returning the claims.
func (tc *TokenConfig) ValidateToken(tokenStr string) (*TokenClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("authn: invalid token format")
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	expectedSig := tc.computeHMAC([]byte(signingInput))
	actualSig, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, errors.New("authn: invalid token signature encoding")
	}
	if !hmac.Equal(expectedSig, actualSig) {
		return nil, errors.New("authn: invalid token signature")
	}

	// Decode payload
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, errors.New("authn: invalid token payload encoding")
	}

	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("authn: failed to decode token claims: %w", err)
	}

	// Check expiration
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("authn: token has expired")
	}

	return &claims, nil
}

// RefreshTokenPair takes a valid refresh token and issues a new token pair.
func (tc *TokenConfig) RefreshTokenPair(refreshToken string) (*TokenPair, error) {
	claims, err := tc.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("authn: invalid refresh token: %w", err)
	}
	if claims.TokenType != "refresh" {
		return nil, errors.New("authn: token is not a refresh token")
	}
	return tc.GenerateTokenPair(claims)
}

// signToken encodes and signs claims into a JWT string.
func (tc *TokenConfig) signToken(claims *TokenClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encodedPayload := base64URLEncode(payload)
	signingInput := jwtHeader + "." + encodedPayload
	signature := tc.computeHMAC([]byte(signingInput))
	return signingInput + "." + base64URLEncode(signature), nil
}

// computeHMAC calculates HMAC-SHA256 for the given data.
func (tc *TokenConfig) computeHMAC(data []byte) []byte {
	h := hmac.New(sha256.New, tc.Secret)
	h.Write(data)
	return h.Sum(nil)
}

// base64URLEncode encodes data using base64 URL encoding without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes a base64 URL encoded string without padding.
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

// Session represents an authenticated user session.
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	TenantID     string    `json:"tenant_id"`
	RefreshToken string    `json:"-"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// SessionStore defines the interface for session persistence.
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	ListUserSessions(ctx context.Context, userID string) ([]*Session, error)
}

// ============================================================================
// MFA / TOTP (RFC 6238)
// ============================================================================

// TOTPConfig holds configuration for TOTP code generation and validation.
type TOTPConfig struct {
	Issuer    string
	Period    uint
	Digits    int
	SecretLen int
}

// NewTOTPConfig creates a new TOTPConfig with sensible defaults.
func NewTOTPConfig(issuer string) *TOTPConfig {
	return &TOTPConfig{
		Issuer:    issuer,
		Period:    30,
		Digits:    6,
		SecretLen: 20,
	}
}

// GenerateSecret generates a random base32-encoded secret for TOTP.
func (tc *TOTPConfig) GenerateSecret() (string, error) {
	secret := make([]byte, tc.SecretLen)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("authn: failed to generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateCode generates a TOTP code for the given secret and time.
func (tc *TOTPConfig) GenerateCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("authn: invalid TOTP secret: %w", err)
	}

	counter := uint64(t.Unix()) / uint64(tc.Period)
	return tc.generateHOTP(key, counter), nil
}

// ValidateCode validates a TOTP code against the current time window (+/- 1 period).
func (tc *TOTPConfig) ValidateCode(secret, code string) bool {
	now := time.Now()
	for _, offset := range []int{-1, 0, 1} {
		t := now.Add(time.Duration(offset) * time.Duration(tc.Period) * time.Second)
		expected, err := tc.GenerateCode(secret, t)
		if err != nil {
			continue
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

// generateHOTP computes an HOTP value per RFC 4226.
func (tc *TOTPConfig) generateHOTP(key []byte, counter uint64) string {
	// Convert counter to big-endian 8-byte buffer
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	// HMAC-SHA1 is the standard for TOTP/HOTP per RFC 6238/4226
	mac := hmac.New(sha512.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Dynamic truncation
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)

	code := binCode % uint32(math.Pow10(tc.Digits))
	return fmt.Sprintf("%0*d", tc.Digits, code)
}

// ============================================================================
// API KEY MANAGEMENT
// ============================================================================

// APIKey represents an API key with metadata.
type APIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"` // e.g., "sk_live_"
	KeyHash   string    `json:"-"`
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	LastUsed  time.Time `json:"last_used,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// APIKeyStore defines the interface for API key persistence.
type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, key *APIKey) error
	GetAPIKeyByPrefix(ctx context.Context, prefix string) (*APIKey, error)
	ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error)
	DeleteAPIKey(ctx context.Context, id string) error
	UpdateLastUsed(ctx context.Context, id string) error
}

// GenerateAPIKey generates a new API key with the given prefix.
// It returns the plaintext key (to show to the user once) and the SHA-256 hash (for storage).
func GenerateAPIKey(prefix string) (plainKey string, keyHash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("authn: failed to generate API key: %w", err)
	}
	plain := prefix + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(plain))
	return plain, fmt.Sprintf("%x", hash), nil
}

// ValidateAPIKey checks whether a plaintext API key matches its stored hash.
func ValidateAPIKey(plainKey, keyHash string) bool {
	hash := sha256.Sum256([]byte(plainKey))
	return fmt.Sprintf("%x", hash) == keyHash
}

// ============================================================================
// LOGIN TRACKER (BRUTE FORCE PROTECTION)
// ============================================================================

// LoginAttempt records a single login attempt.
type LoginAttempt struct {
	Email     string
	IP        string
	Success   bool
	Timestamp time.Time
}

// LoginTracker provides in-memory brute force protection by tracking login attempts.
type LoginTracker struct {
	mu              sync.RWMutex
	attempts        map[string][]LoginAttempt
	maxAttempts     int
	lockoutDuration time.Duration
}

// NewLoginTracker creates a new LoginTracker with the given thresholds.
func NewLoginTracker(maxAttempts int, lockoutDuration time.Duration) *LoginTracker {
	return &LoginTracker{
		attempts:        make(map[string][]LoginAttempt),
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
	}
}

// RecordAttempt records a login attempt for both the email and IP address.
func (lt *LoginTracker) RecordAttempt(attempt LoginAttempt) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	attempt.Timestamp = time.Now()

	if attempt.Email != "" {
		lt.attempts[attempt.Email] = append(lt.attempts[attempt.Email], attempt)
	}
	if attempt.IP != "" {
		lt.attempts[attempt.IP] = append(lt.attempts[attempt.IP], attempt)
	}
}

// IsLocked checks whether the given key (email or IP) is currently locked out.
func (lt *LoginTracker) IsLocked(key string) bool {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	attempts, ok := lt.attempts[key]
	if !ok {
		return false
	}

	cutoff := time.Now().Add(-lt.lockoutDuration)
	failures := 0
	for i := len(attempts) - 1; i >= 0; i-- {
		a := attempts[i]
		if a.Timestamp.Before(cutoff) {
			break
		}
		if a.Success {
			// A successful login resets the failure count
			break
		}
		failures++
	}
	return failures >= lt.maxAttempts
}

// Reset clears all recorded attempts for the given key.
func (lt *LoginTracker) Reset(key string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.attempts, key)
}
