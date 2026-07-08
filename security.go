package authz

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// SECURITY HEADERS MIDDLEWARE
// ============================================================================

// SecurityHeadersConfig defines HTTP security headers for the admin API.
type SecurityHeadersConfig struct {
	// ContentSecurityPolicy sets Content-Security-Policy header.
	// Default: "default-src 'self'"
	ContentSecurityPolicy string

	// StrictTransportSecurity sets Strict-Transport-Security header.
	// Default: "max-age=31536000; includeSubDomains"
	StrictTransportSecurity string

	// XFrameOptions sets X-Frame-Options header.
	// Default: "DENY"
	XFrameOptions string

	// XContentTypeOptions sets X-Content-Type-Options header.
	// Default: "nosniff"
	XContentTypeOptions string

	// XXSSProtection sets X-XSS-Protection header.
	// Default: "0" (disables deprecated feature)
	XXSSProtection string

	// ReferrerPolicy sets Referrer-Policy header.
	// Default: "strict-origin-when-cross-origin"
	ReferrerPolicy string

	// PermissionsPolicy sets Permissions-Policy header.
	// Default: "camera=(), microphone=(), geolocation=(), interest-cohort=()"
	PermissionsPolicy string

	// CrossOriginOpenerPolicy sets Cross-Origin-Opener-Policy header.
	// Default: "same-origin"
	CrossOriginOpenerPolicy string

	// CrossOriginResourcePolicy sets Cross-Origin-Resource-Policy header.
	// Default: "same-origin"
	CrossOriginResourcePolicy string

	// CrossOriginEmbedderPolicy sets Cross-Origin-Embedder-Policy header.
	// Default: "require-corp"
	CrossOriginEmbedderPolicy string

	// CacheControl sets Cache-Control header for sensitive responses.
	// Default: "no-store, max-age=0"
	CacheControl string

	// Pragma sets Pragma header.
	// Default: "no-cache"
	Pragma string
}

// DefaultSecurityHeadersConfig returns sensible security header defaults.
func DefaultSecurityHeadersConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		ContentSecurityPolicy:     "default-src 'self'",
		StrictTransportSecurity:  "max-age=31536000; includeSubDomains",
		XFrameOptions:            "DENY",
		XContentTypeOptions:      "nosniff",
		XXSSProtection:           "0",
		ReferrerPolicy:           "strict-origin-when-cross-origin",
		PermissionsPolicy:        "camera=(), microphone=(), geolocation=(), interest-cohort=()",
		CrossOriginOpenerPolicy:  "same-origin",
		CrossOriginResourcePolicy: "same-origin",
		CrossOriginEmbedderPolicy: "require-corp",
		CacheControl:             "no-store, max-age=0",
		Pragma:                   "no-cache",
	}
}

// SecurityHeadersMiddleware returns an HTTP middleware that sets security headers.
func SecurityHeadersMiddleware(cfg *SecurityHeadersConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultSecurityHeadersConfig()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
			w.Header().Set("X-Frame-Options", cfg.XFrameOptions)
			w.Header().Set("X-Content-Type-Options", cfg.XContentTypeOptions)
			w.Header().Set("X-XSS-Protection", cfg.XXSSProtection)
			w.Header().Set("Referrer-Policy", cfg.ReferrerPolicy)
			w.Header().Set("Permissions-Policy", cfg.PermissionsPolicy)
			w.Header().Set("Cross-Origin-Opener-Policy", cfg.CrossOriginOpenerPolicy)
			w.Header().Set("Cross-Origin-Resource-Policy", cfg.CrossOriginResourcePolicy)
			w.Header().Set("Cross-Origin-Embedder-Policy", cfg.CrossOriginEmbedderPolicy)
			w.Header().Set("Cache-Control", cfg.CacheControl)
			w.Header().Set("Pragma", cfg.Pragma)

			if r.TLS != nil {
				w.Header().Set("Strict-Transport-Security", cfg.StrictTransportSecurity)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// CORS CONFIGURATION
// ============================================================================

// CORSConfig defines CORS policy for the admin API.
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

// DefaultCORSConfig returns a restrictive CORS configuration.
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins:   []string{},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-CSRF-Token", "X-Tenant-ID", "X-Subject-ID"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}
}

// CORSOriginMatches checks if the given origin is allowed.
func (c *CORSConfig) CORSOriginMatches(origin string) bool {
	if len(c.AllowedOrigins) == 0 {
		return false
	}
	for _, allowed := range c.AllowedOrigins {
		if allowed == "*" {
			return true
		}
		if allowed == origin {
			return true
		}
	}
	return false
}

// CORSMiddleware returns an HTTP middleware that sets CORS headers.
func CORSMiddleware(cfg *CORSConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultCORSConfig()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && cfg.CORSOriginMatches(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				if cfg.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
				if len(cfg.ExposedHeaders) > 0 {
					w.Header().Set("Access-Control-Expose-Headers", strings.Join(cfg.ExposedHeaders, ", "))
				}
				if cfg.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.MaxAge))
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// CSRF PROTECTION
// ============================================================================

// CSRFConfig holds CSRF protection configuration.
type CSRFConfig struct {
	// Secret is the HMAC key used to sign CSRF tokens.
	Secret []byte
	// TokenLength is the length of the random token in bytes.
	TokenLength int
	// MaxAge is the token validity duration.
	MaxAge time.Duration
	// CookieName is the name of the CSRF cookie.
	CookieName string
	// HeaderName is the header name for the CSRF token.
	HeaderName string
	// Secure restricts cookie to HTTPS.
	Secure bool
	// SameSite specifies the SameSite mode for the cookie.
	SameSite http.SameSite
	// SafeMethods lists HTTP methods that do not require CSRF protection.
	SafeMethods []string
}

// DefaultCSRFConfig returns sensible CSRF protection defaults.
func DefaultCSRFConfig(secret []byte) *CSRFConfig {
	if len(secret) == 0 {
		key := make([]byte, 32)
		rand.Read(key)
		secret = key
	}
	return &CSRFConfig{
		Secret:      secret,
		TokenLength: 32,
		MaxAge:      2 * time.Hour,
		CookieName:  "_csrf_token",
		HeaderName:  "X-CSRF-Token",
		Secure:      true,
		SameSite:    http.SameSiteStrictMode,
		SafeMethods: []string{"GET", "HEAD", "OPTIONS", "TRACE"},
	}
}

// GenerateCSRFToken creates a signed CSRF token.
func (c *CSRFConfig) GenerateCSRFToken() (string, error) {
	token := make([]byte, c.TokenLength)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("csrf: failed to generate token: %w", err)
	}
	now := time.Now().Unix()
	payload := fmt.Sprintf("%s:%d", hex.EncodeToString(token), now)
	mac := hmacSHA256(c.Secret, []byte(payload))
	return hex.EncodeToString(mac) + "." + payload, nil
}

// ValidateCSRFToken validates a signed CSRF token.
func (c *CSRFConfig) ValidateCSRFToken(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	expectedMAC, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload := parts[1]

	mac := hmacSHA256(c.Secret, []byte(payload))
	if !hmacEqual(expectedMAC, mac) {
		return false
	}

	var ts int64
	if _, err := fmt.Sscanf(payload, "%*s:%d", &ts); err != nil {
		return false
	}
	if time.Now().Unix()-ts > int64(c.MaxAge.Seconds()) {
		return false
	}
	return true
}

// CSRFMiddleware returns HTTP middleware that protects against CSRF attacks.
func CSRFMiddleware(cfg *CSRFConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultCSRFConfig(nil)
	}
	safeMethods := make(map[string]bool, len(cfg.SafeMethods))
	for _, m := range cfg.SafeMethods {
		safeMethods[m] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if safeMethods[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			token := r.Header.Get(cfg.HeaderName)
			if token == "" {
				if c, err := r.Cookie(cfg.CookieName); err == nil {
					token = c.Value
				}
			}
			if token == "" || !cfg.ValidateCSRFToken(token) {
				respondJSON(w, http.StatusForbidden, map[string]string{"error": "invalid or missing CSRF token"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hmacSHA256(secret, data []byte) []byte {
	h := sha256.New()
	h.Write(secret)
	h.Write(data)
	return h.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ============================================================================
// RATE LIMITING
// ============================================================================

// RateLimiterConfig holds rate limiter configuration.
type RateLimiterConfig struct {
	// RequestsPerSecond is the maximum number of requests per second per client.
	RequestsPerSecond float64
	// Burst is the maximum burst size.
	Burst int
	// KeyFunc extracts the client identifier from the request.
	KeyFunc func(r *http.Request) string
	// OnLimit is called when rate limit is exceeded.
	OnLimit func(w http.ResponseWriter, r *http.Request)
}

// DefaultRateLimiterConfig returns sensible rate limiting defaults.
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		RequestsPerSecond: 10,
		Burst:             20,
		KeyFunc: func(r *http.Request) string {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			return fmt.Sprintf("rate:%s", ip)
		},
		OnLimit: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "1")
			respondJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "rate limit exceeded",
				"retry": "1",
			})
		},
	}
}

// TokenBucket implements a token bucket rate limiter.
type TokenBucket struct {
	mu        sync.Mutex
	tokens    float64
	rate      float64
	burst     float64
	lastCheck time.Time
}

func newTokenBucket(rate float64, burst int) *TokenBucket {
	return &TokenBucket{
		tokens:    float64(burst),
		rate:      rate,
		burst:     float64(burst),
		lastCheck: time.Now(),
	}
}

func (tb *TokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastCheck).Seconds()
	tb.lastCheck = now
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// RateLimiter is a per-client rate limiter using token buckets.
type RateLimiter struct {
	mu     sync.Mutex
	buckets map[string]*TokenBucket
	config *RateLimiterConfig
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter(cfg *RateLimiterConfig) *RateLimiter {
	if cfg == nil {
		cfg = DefaultRateLimiterConfig()
	}
	return &RateLimiter{
		buckets: make(map[string]*TokenBucket),
		config:  cfg,
	}
}

// Allow checks if a request is allowed by the rate limiter.
func (rl *RateLimiter) Allow(r *http.Request) bool {
	key := rl.config.KeyFunc(r)
	rl.mu.Lock()
	bucket, ok := rl.buckets[key]
	if !ok {
		bucket = newTokenBucket(rl.config.RequestsPerSecond, rl.config.Burst)
		rl.buckets[key] = bucket
	}
	rl.mu.Unlock()
	return bucket.allow()
}

// RateLimitMiddleware returns HTTP middleware for rate limiting.
func RateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.Allow(r) {
				rl.config.OnLimit(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// CONTENT-TYPE ENFORCEMENT
// ============================================================================

// ContentTypeConfig enforces Content-Type headers on API requests.
type ContentTypeConfig struct {
	// EnforcedMethods lists HTTP methods that require Content-Type check.
	EnforcedMethods []string
	// AllowedContentTypes lists accepted Content-Type values.
	AllowedContentTypes []string
}

// DefaultContentTypeConfig returns default content-type enforcement.
func DefaultContentTypeConfig() *ContentTypeConfig {
	return &ContentTypeConfig{
		EnforcedMethods:     []string{"POST", "PUT", "PATCH"},
		AllowedContentTypes: []string{"application/json"},
	}
}

// ContentTypeMiddleware enforces Content-Type headers.
func ContentTypeMiddleware(cfg *ContentTypeConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = DefaultContentTypeConfig()
	}
	methodsSet := make(map[string]bool, len(cfg.EnforcedMethods))
	for _, m := range cfg.EnforcedMethods {
		methodsSet[m] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if methodsSet[r.Method] {
				ct := r.Header.Get("Content-Type")
				valid := false
				for _, allowed := range cfg.AllowedContentTypes {
					if strings.HasPrefix(ct, allowed) {
						valid = true
						break
					}
				}
				if !valid {
					respondJSON(w, http.StatusUnsupportedMediaType, map[string]string{
						"error": fmt.Sprintf("unsupported Content-Type: %s", ct),
					})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// REQUEST BODY SIZE LIMITER
// ============================================================================

// MaxBodySize returns middleware that limits request body size.
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// SECURE ID GENERATION
// ============================================================================

// GenerateSecureID creates a cryptographically random identifier with the given prefix.
func GenerateSecureID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

// GenerateSecureToken creates a cryptographically random hex token of the given byte length.
func GenerateSecureToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ============================================================================
// WEBHOOK URL VALIDATION
// ============================================================================

var privateCIDRs = []*net.IPNet{
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("169.254.0.0/16"),
	mustParseCIDR("::1/128"),
	mustParseCIDR("fc00::/7"),
	mustParseCIDR("fe80::/10"),
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// ValidateWebhookURL checks that the webhook URL uses HTTPS and does not point to a private IP.
func ValidateWebhookURL(rawURL string) error {
	if !strings.HasPrefix(rawURL, "https://") {
		return errors.New("webhook URL must use HTTPS")
	}

	host := rawURL
	if strings.HasPrefix(rawURL, "https://") {
		host = rawURL[8:]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("webhook URL host lookup failed: %w", err)
	}

	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		for _, cidr := range privateCIDRs {
			if cidr.Contains(parsed) {
				return errors.New("webhook URL must not point to a private IP address")
			}
		}
	}
	return nil
}

// ============================================================================
// ENCRYPTION UTILITY FOR SENSITIVE DATA AT REST
// ============================================================================

// Encryptor provides AES-256-GCM encryption for sensitive fields (e.g. MFA secrets).
type Encryptor struct {
	key []byte
}

// NewEncryptor creates an Encryptor with the given 32-byte key.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	return &Encryptor{key: key}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM. Returns hex-encoded ciphertext.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	block, err := aesNewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	aesGCM, err := cipherNewGCM(block)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts hex-encoded ciphertext produced by Encrypt.
func (e *Encryptor) Decrypt(encoded string) (string, error) {
	ciphertext, err := hex.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	block, err := aesNewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	aesGCM, err := cipherNewGCM(block)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("decrypt: ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}

// ============================================================================
// REQUEST ID MIDDLEWARE
// ============================================================================

// RequestIDMiddleware injects a unique request ID into each request/response.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = GenerateSecureID("req")
		}
		w.Header().Set("X-Request-ID", id)
		r = r.WithContext(contextWithRequestID(r.Context(), id))
		next.ServeHTTP(w, r)
	})
}
