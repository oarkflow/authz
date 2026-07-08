# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

We take the security of `authz` seriously. If you believe you have found a security
vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **security@oarkflow.com** with the subject
line "authz vulnerability report".

You should receive a response within 48 hours. If for some reason you do not,
please follow up via email to ensure we received your original message.

### What to include

Try to include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Posture

This project implements the following security controls aligned with OWASP ASVS (Application Security Verification Standard):

### Authentication (OWASP ASVS V2)

- [x] Password hashing using bcrypt with configurable cost
- [x] JWT-based access tokens (HMAC-SHA256) with short TTLs (default 15 min)
- [x] Refresh token rotation with configurable TTL (default 7 days)
- [x] TOTP multi-factor authentication (RFC 6238 compliant)
- [x] API key authentication with SHA-256 hashed storage
- [x] Service account authentication with client credentials
- [x] Brute-force login protection with configurable lockout thresholds
- [x] Session management with secure session IDs

### Access Control (OWASP ASVS V4)

- [x] Attribute-Based Access Control (ABAC) with condition expressions
- [x] Role-Based Access Control (RBAC) with role inheritance
- [x] Access Control Lists (ACLs) for fine-grained overrides
- [x] Multi-tenant isolation enforced at the engine level
- [x] Owner-scoped permissions for resource ownership
- [x] Cross-tenant admin role support
- [x] Permission boundaries for delegated administration
- [x] Deny-by-default authorization model
- [x] Explicit deny taking precedence over allow
- [x] Policy evaluation caching with configurable TTL

### Secure Configuration (OWASP ASVS V14)

- [x] Security headers middleware (CSP, HSTS, XFO, X-Content-Type-Options)
- [x] CORS configuration with restrictive defaults
- [x] CSRF protection for state-changing endpoints
- [x] Rate limiting with token bucket algorithm
- [x] Request body size limits
- [x] Content-Type enforcement
- [x] TLS configuration for HTTP server
- [x] Configurable request body size limits
- [x] Config ID/checksum signing via Ed25519

### Data Protection (OWASP ASVS V8)

- [x] Encryption at rest for MFA secrets via AES-256-GCM
- [x] Encrypted webhook payload signing (HMAC-SHA256)
- [x] Secure audit logging of all authorization decisions
- [x] PII redaction option for OpenTelemetry telemetry
- [x] Parameterized SQL queries preventing SQL injection
- [x] Constant-time comparison for HMAC verification

### Input Validation (OWASP ASVS V5)

- [x] JSON body decoding with `DisallowUnknownFields`
- [x] Config validation (duplicate IDs, missing fields, invalid effects)
- [x] DSL parser running in strict mode (fail-closed)
- [x] Webhook URL validation (HTTPS-only, private IP blocking)

### Security Testing

- [ ] SAST scanning via `gosec` (run manually: `make security-scan`)
- [ ] Dependency scanning via `govulncheck` (run manually: `make vulncheck`)
- [x] Unit tests covering authorization engine
- [x] Integration tests for admin HTTP API

## Security Checklist for Integrators

When using `authz` in your application, ensure:

1. **Admin API authentication**: Use `WithAdminAuth()` to secure admin endpoints
2. **TLS**: Use `WithAdminTLS()` or wrap the server in a TLS-enabled listener
3. **JWT secrets**: Use cryptographically random secrets of at least 32 bytes
4. **Security headers**: Use `WithAdminSecurityHeaders()` to enable security headers
5. **Rate limiting**: Use `WithAdminRateLimiter()` to protect against abuse
6. **CSRF protection**: Use `WithAdminCSRF()` for cookie-based auth deployments
7. **Content-Type enforcement**: Use `WithAdminContentTypeEnforcement()` to restrict media types
8. **MFA secrets**: Configure `Encryptor` with a 32-byte key stored in a secrets manager
9. **Dependency scanning**: Run `govulncheck` and `gosec` regularly
10. **PII redaction**: Enable `RedactPII` in `OTelConfig` for production deployments

## OWASP Top 10 (2021) Coverage

| A1: Broken Access Control       | A2: Cryptographic Failures     | A3: Injection                  |
|--------------------------------|--------------------------------|--------------------------------|
| ✅ ABAC/RBAC/ACL engine        | ✅ bcrypt password hashing     | ✅ Parameterized SQL queries   |
| ✅ Multi-tenant isolation       | ✅ AES-256-GCM for MFA secrets | ✅ DSL parser fail-closed      |
| ✅ Deny-by-default model        | ✅ Ed25519 policy signing      | ✅ JSON DisallowUnknownFields  |

| A4: Insecure Design             | A5: Security Misconfiguration  | A6: Vulnerable Components      |
|--------------------------------|--------------------------------|--------------------------------|
| ✅ Audit logging                | ✅ Security headers middleware | ⚠️ Run `govulncheck` regularly |
| ✅ Rate limiting                | ✅ CORS with restrictive       | ⚠️ Run `gosec` for SAST        |
| ✅ CSRF protection              | ✅ TLS support                 |                                |

| A7: Identification & Auth Failures | A8: Software & Data Integrity  | A9: Security Logging & Monitoring |
|-----------------------------------|--------------------------------|-----------------------------------|
| ✅ bcrypt + JWT + TOTP MFA        | ✅ Ed25519 policy bundle signing| ✅ Audit log all decisions        |
| ✅ Brute-force protection          | ✅ Webhook HMAC signing         | ✅ OTel observability integration |
| ✅ Session management              | ✅ Config validation            |                                   |

| A10: Server-Side Request Forgery        |
|----------------------------------------|
| ✅ Webhook URL validation (private IPs) |
| ✅ Configurable HTTP client timeout     |
