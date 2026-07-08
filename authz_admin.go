package authz

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// ExplainRequest is a minimal request for Explain API used by admin server
type ExplainRequest struct {
	Tenant    string   `json:"tenant"`
	SubjectID string   `json:"subject_id"`
	Roles     []string `json:"roles,omitempty"`
	Action    string   `json:"action"`
	Resource  string   `json:"resource"` // format: type:id or route:GET:/users/1
	OwnerID   string   `json:"owner_id,omitempty"`
}

func (e *Engine) ExplainRequest(ctx context.Context, req *ExplainRequest) (*Decision, error) {
	sub := &Subject{ID: req.SubjectID, TenantID: req.Tenant}
	if len(req.Roles) > 0 {
		sub.Roles = append(sub.Roles, req.Roles...)
	}
	rType := ""
	rID := req.Resource
	if idx := strings.Index(req.Resource, ":"); idx != -1 {
		rType = req.Resource[:idx]
		rID = req.Resource[idx+1:]
	}
	res := &Resource{Type: rType, ID: rID, TenantID: req.Tenant}
	if req.OwnerID != "" {
		res.OwnerID = req.OwnerID
	}
	env := &Environment{Time: time.Now(), TenantID: req.Tenant}
	return e.Explain(ctx, sub, Action(req.Action), res, env)
}

// AdminHTTPServer exposes tenant-scoped management APIs over HTTP with security hardening.
type AdminHTTPServer struct {
	engine             *Engine
	mux                *http.ServeMux
	authFn             AdminAuthFunc
	server             *http.Server
	handler            http.Handler
	tlsConfig          *tls.Config
	tlsCertFile        string
	tlsKeyFile         string
	securityHeadersCfg *SecurityHeadersConfig
	corsCfg            *CORSConfig
	csrfCfg            *CSRFConfig
	rateLimiter        *RateLimiter
	contentTypeCfg     *ContentTypeConfig
	maxBodySize        int64
}

// AdminAuthFunc allows callers to enforce authentication/authorization on admin endpoints.
type AdminAuthFunc func(r *http.Request) error

// AdminHTTPOption configures the admin HTTP server.
type AdminHTTPOption func(*AdminHTTPServer)

// WithAdminAuth installs a custom authentication callback.
// If not provided, the server will warn and require auth by default.
func WithAdminAuth(fn AdminAuthFunc) AdminHTTPOption {
	return func(s *AdminHTTPServer) {
		s.authFn = fn
	}
}

// WithAdminTLS configures TLS for the admin HTTP server.
func WithAdminTLS(certFile, keyFile string) AdminHTTPOption {
	return func(s *AdminHTTPServer) {
		s.tlsCertFile = certFile
		s.tlsKeyFile = keyFile
	}
}

// WithAdminTLSConfig configures a custom TLS configuration.
func WithAdminTLSConfig(cfg *tls.Config) AdminHTTPOption {
	return func(s *AdminHTTPServer) {
		s.tlsConfig = cfg
	}
}

// WithAdminSecurityHeaders configures security headers for the admin server.
// If nil, defaults are used.
func WithAdminSecurityHeaders(cfg *SecurityHeadersConfig) AdminHTTPOption {
	return func(s *AdminHTTPServer) {
		s.securityHeadersCfg = cfg
	}
}

// WithAdminCORS configures CORS for the admin server.
// If nil, CORS is not enabled.
func WithAdminCORS(cfg *CORSConfig) AdminHTTPOption {
	return func(s *AdminHTTPServer) {
		s.corsCfg = cfg
	}
}

// WithAdminCSRF configures CSRF protection for the admin server.
// If nil, defaults are used.
func WithAdminCSRF(cfg *CSRFConfig) AdminHTTPOption {
	return func(s *AdminHTTPServer) {
		s.csrfCfg = cfg
	}
}

// WithAdminRateLimiter configures rate limiting for the admin server.
// If nil, defaults are used.
func WithAdminRateLimiter(cfg *RateLimiterConfig) AdminHTTPOption {
	return func(s *AdminHTTPServer) {
		s.rateLimiter = NewRateLimiter(cfg)
	}
}

// WithAdminContentTypeEnforcement configures content-type enforcement.
// If nil, defaults are used.
func WithAdminContentTypeEnforcement(cfg *ContentTypeConfig) AdminHTTPOption {
	return func(s *AdminHTTPServer) {
		s.contentTypeCfg = cfg
	}
}

// WithAdminMaxBodySize sets the maximum request body size in bytes for admin endpoints.
// Default: 1MB (1048576 bytes)
func WithAdminMaxBodySize(maxBytes int64) AdminHTTPOption {
	return func(s *AdminHTTPServer) {
		s.maxBodySize = maxBytes
	}
}

// NewAdminHTTPServer wires handlers for managing policies, roles, batch decisions, and explanations.
// Security middleware is automatically applied. Admin authentication is required by default;
// a warning is logged if no auth function is provided.
func NewAdminHTTPServer(engine *Engine, opts ...AdminHTTPOption) *AdminHTTPServer {
	if engine == nil {
		panic("engine is required")
	}
	server := &AdminHTTPServer{
		engine:      engine,
		mux:         http.NewServeMux(),
		maxBodySize: 1 << 20, // 1MB default
	}
	for _, opt := range opts {
		opt(server)
	}

	// Warn if no auth function is provided
	if server.authFn == nil {
		log.Println("[WARN] AdminHTTPServer: no authentication configured via WithAdminAuth(). " +
			"This is a security risk. Consider adding authentication for production use.")
	}

	server.routes()
	server.buildHandler()
	return server
}

func (s *AdminHTTPServer) buildHandler() {
	var h http.Handler = s.mux

	// Request ID (innermost, first applied)
	h = RequestIDMiddleware(h)

	// Max body size
	if s.maxBodySize > 0 {
		h = MaxBodySize(s.maxBodySize)(h)
	}

	// Content-Type enforcement (opt-in via WithAdminContentTypeEnforcement)
	if s.contentTypeCfg != nil {
		h = ContentTypeMiddleware(s.contentTypeCfg)(h)
	}

	// Rate limiting (opt-in via WithAdminRateLimiter)
	if s.rateLimiter != nil {
		h = RateLimitMiddleware(s.rateLimiter)(h)
	}

	// CSRF protection (opt-in via WithAdminCSRF)
	if s.csrfCfg != nil {
		h = CSRFMiddleware(s.csrfCfg)(h)
	}

	// CORS (opt-in via WithAdminCORS)
	if s.corsCfg != nil {
		h = CORSMiddleware(s.corsCfg)(h)
	}

	// Security headers (opt-in via WithAdminSecurityHeaders)
	if s.securityHeadersCfg != nil {
		h = SecurityHeadersMiddleware(s.securityHeadersCfg)(h)
	}

	s.handler = h
}

func (s *AdminHTTPServer) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/tenants", s.handleTenantsRoot)
	s.mux.HandleFunc("/tenants/", s.handleTenants)
}

// Handler returns the underlying HTTP handler with all security middleware applied.
func (s *AdminHTTPServer) Handler() http.Handler {
	return s.handler
}

// ServeHTTP satisfies http.Handler with all security middleware applied.
func (s *AdminHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// Start begins serving on the provided address with optional TLS.
func (s *AdminHTTPServer) Start(addr string) error {
	s.server = &http.Server{
		Addr:    addr,
		Handler: s.handler,
		TLSConfig: func() *tls.Config {
			if s.tlsConfig != nil {
				return s.tlsConfig
			}
			// Return minimal secure defaults
			return &tls.Config{
				MinVersion:               tls.VersionTLS12,
				PreferServerCipherSuites: true,
			}
		}(),
	}

	if s.tlsCertFile != "" && s.tlsKeyFile != "" {
		log.Printf("[INFO] AdminHTTPServer starting with TLS on %s", addr)
		return s.server.ListenAndServeTLS(s.tlsCertFile, s.tlsKeyFile)
	}
	log.Printf("[INFO] AdminHTTPServer starting without TLS on %s (recommend using WithAdminTLS for production)", addr)
	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *AdminHTTPServer) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func (s *AdminHTTPServer) authorize(r *http.Request) error {
	if s.authFn == nil {
		return nil
	}
	return s.authFn(r)
}

func (s *AdminHTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *AdminHTTPServer) handleTenantsRoot(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		respondError(w, http.StatusUnauthorized, err)
		return
	}
	if r.URL.Path != "/tenants" && r.URL.Path != "/tenants/" {
		s.handleTenants(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		tenants, err := s.engine.ListTenants(r.Context())
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
	case http.MethodPost:
		defer r.Body.Close()
		var t Tenant
		if err := decodeJSON(r, &t); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		if t.ID == "" {
			respondError(w, http.StatusBadRequest, errors.New("tenant id required"))
			return
		}
		if err := s.engine.CreateTenant(r.Context(), &t); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusCreated, t)
	default:
		w.Header().Set("Allow", "GET,POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *AdminHTTPServer) handleTenants(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r); err != nil {
		respondError(w, http.StatusUnauthorized, err)
		return
	}
	tenantID, remainder, err := parseTenantPath(r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if len(remainder) == 0 {
		// Operations on the tenant itself
		switch r.Method {
		case http.MethodGet:
			t, err := s.engine.GetTenant(r.Context(), tenantID)
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, t)
		case http.MethodPut:
			defer r.Body.Close()
			var t Tenant
			if err := decodeJSON(r, &t); err != nil {
				respondError(w, http.StatusBadRequest, err)
				return
			}
			t.ID = tenantID
			if err := s.engine.UpdateTenant(r.Context(), &t); err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, t)
		case http.MethodDelete:
			if err := s.engine.DeleteTenant(r.Context(), tenantID); err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET,PUT,DELETE")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	switch remainder[0] {
	case "policies":
		s.handlePolicies(w, r, tenantID, remainder[1:])
	case "roles":
		s.handleRoles(w, r, tenantID, remainder[1:])
	case "acls":
		s.handleACLs(w, r, tenantID, remainder[1:])
	case "members":
		s.handleMembers(w, r, tenantID, remainder[1:])
	case "explain":
		s.handleExplain(w, r, tenantID)
	case "batch":
		s.handleBatch(w, r, tenantID)
	default:
		http.NotFound(w, r)
	}
}

func (s *AdminHTTPServer) handlePolicies(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	switch r.Method {
	case http.MethodGet:
		if len(parts) != 0 {
			respondError(w, http.StatusNotFound, errors.New("policy id required"))
			return
		}
		policies, err := s.engine.ListPolicies(r.Context(), tenantID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		response := make([]policyDTO, 0, len(policies))
		for _, p := range policies {
			response = append(response, newPolicyDTO(p))
		}
		respondJSON(w, http.StatusOK, map[string]any{"policies": response})
	case http.MethodPost:
		if len(parts) != 0 {
			respondError(w, http.StatusNotFound, errors.New("policy id should not be in path for create"))
			return
		}
		defer r.Body.Close()
		var payload policyPayload
		if err := decodeJSON(r, &payload); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		policy, err := payload.toPolicy(tenantID)
		if err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		if policy.ID == "" {
			policy.ID = GenerateSecureID("policy")
		}
		if err := s.engine.CreatePolicy(r.Context(), policy); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusCreated, newPolicyDTO(policy))
	case http.MethodPut:
		if len(parts) == 0 {
			respondError(w, http.StatusNotFound, errors.New("policy id required"))
			return
		}
		policyID := parts[0]
		existing, err := s.engine.policyStore.GetPolicy(r.Context(), policyID)
		if err != nil {
			respondError(w, http.StatusNotFound, err)
			return
		}
		defer r.Body.Close()
		var payload policyPayload
		if err := decodeJSON(r, &payload); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		policy, err := payload.toPolicy(tenantID)
		if err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		policy.ID = policyID
		policy.CreatedAt = existing.CreatedAt
		policy.Version = existing.Version
		if err := s.engine.UpdatePolicy(r.Context(), policy); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, newPolicyDTO(policy))
	case http.MethodDelete:
		if len(parts) == 0 {
			respondError(w, http.StatusNotFound, errors.New("policy id required"))
			return
		}
		if err := s.engine.DeletePolicy(r.Context(), parts[0]); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,POST,PUT,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *AdminHTTPServer) handleRoles(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	switch r.Method {
	case http.MethodGet:
		if len(parts) != 0 {
			respondError(w, http.StatusNotFound, errors.New("role id required for detail requests"))
			return
		}
		roles, err := s.engine.ListRoles(r.Context(), tenantID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		resp := make([]roleDTO, 0, len(roles))
		for _, role := range roles {
			resp = append(resp, newRoleDTO(role))
		}
		respondJSON(w, http.StatusOK, map[string]any{"roles": resp})
	case http.MethodPost:
		if len(parts) != 0 {
			respondError(w, http.StatusNotFound, errors.New("role id should not be in path for create"))
			return
		}
		defer r.Body.Close()
		var payload rolePayload
		if err := decodeJSON(r, &payload); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		role := payload.toRole(tenantID)
		if role.ID == "" {
			role.ID = GenerateSecureID("role")
		}
		if err := s.engine.CreateRole(r.Context(), role); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusCreated, newRoleDTO(role))
	case http.MethodPut:
		if len(parts) == 0 {
			respondError(w, http.StatusNotFound, errors.New("role id required"))
			return
		}
		roleID := parts[0]
		defer r.Body.Close()
		var payload rolePayload
		if err := decodeJSON(r, &payload); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		role := payload.toRole(tenantID)
		role.ID = roleID
		if err := s.engine.UpdateRole(r.Context(), role); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, newRoleDTO(role))
	case http.MethodDelete:
		if len(parts) == 0 {
			respondError(w, http.StatusNotFound, errors.New("role id required"))
			return
		}
		if err := s.engine.DeleteRole(r.Context(), parts[0]); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,POST,PUT,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *AdminHTTPServer) handleExplain(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var payload ExplainRequest
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	if payload.Tenant == "" {
		payload.Tenant = tenantID
	}
	decision, err := s.engine.ExplainRequest(r.Context(), &payload)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, decision)
}

func (s *AdminHTTPServer) handleBatch(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var payload batchAuthorizePayload
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	if len(payload.Requests) == 0 {
		respondError(w, http.StatusBadRequest, errors.New("requests cannot be empty"))
		return
	}
	for i := range payload.Requests {
		req := &payload.Requests[i]
		if req.Subject == nil || req.Resource == nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("request %d missing subject or resource", i))
			return
		}
		if req.Subject.TenantID == "" {
			req.Subject.TenantID = tenantID
		}
		if req.Resource.TenantID == "" {
			req.Resource.TenantID = tenantID
		}
		if req.Environment == nil {
			req.Environment = &Environment{Time: time.Now(), TenantID: tenantID}
		} else if req.Environment.TenantID == "" {
			req.Environment.TenantID = tenantID
		}
	}
	decisions, err := s.engine.BatchAuthorize(r.Context(), payload.Requests)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, batchAuthorizeResponse{Decisions: decisions})
}

type policyPayload struct {
	ID        string   `json:"id"`
	Effect    Effect   `json:"effect"`
	Actions   []Action `json:"actions"`
	Resources []string `json:"resources"`
	Condition string   `json:"condition"`
	Priority  int      `json:"priority"`
	Enabled   *bool    `json:"enabled,omitempty"`
}

func (p *policyPayload) toPolicy(tenantID string) (*Policy, error) {
	if len(p.Actions) == 0 {
		return nil, errors.New("actions are required")
	}
	if len(p.Resources) == 0 {
		return nil, errors.New("resources are required")
	}
	expr, err := ParseCondition(p.Condition)
	if err != nil {
		return nil, err
	}
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	return &Policy{
		ID:        p.ID,
		TenantID:  tenantID,
		Effect:    p.Effect,
		Actions:   append([]Action{}, p.Actions...),
		Resources: append([]string{}, p.Resources...),
		Condition: expr,
		Priority:  p.Priority,
		Enabled:   enabled,
	}, nil
}

type policyDTO struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Effect    Effect    `json:"effect"`
	Actions   []Action  `json:"actions"`
	Resources []string  `json:"resources"`
	Condition string    `json:"condition"`
	Priority  int       `json:"priority"`
	Enabled   bool      `json:"enabled"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

func newPolicyDTO(p *Policy) policyDTO {
	cond := ""
	if p.Condition != nil {
		cond = p.Condition.String()
	}
	return policyDTO{
		ID:        p.ID,
		TenantID:  p.TenantID,
		Effect:    p.Effect,
		Actions:   append([]Action{}, p.Actions...),
		Resources: append([]string{}, p.Resources...),
		Condition: cond,
		Priority:  p.Priority,
		Enabled:   p.Enabled,
		Version:   p.Version,
		UpdatedAt: p.UpdatedAt,
	}
}

type rolePayload struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	Permissions         []permissionPayload `json:"permissions"`
	Inherits            []string            `json:"inherits"`
	OwnerAllowedActions []Action            `json:"owner_allowed_actions"`
}

func (s *AdminHTTPServer) handleACLs(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	switch r.Method {
	case http.MethodGet:
		if len(parts) == 0 {
			// List
			acls, err := s.engine.ListACLs(r.Context(), tenantID)
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, map[string]any{"acls": acls})
		} else {
			// Get
			acl, err := s.engine.GetACL(r.Context(), parts[0])
			if err != nil {
				respondError(w, http.StatusNotFound, err)
				return
			}
			if acl.TenantID != "" && acl.TenantID != tenantID {
				respondError(w, http.StatusNotFound, errors.New("acl not found in tenant"))
				return
			}
			respondJSON(w, http.StatusOK, acl)
		}
	case http.MethodPost:
		if len(parts) != 0 {
			respondError(w, http.StatusNotFound, errors.New("acl id should not be in path for create"))
			return
		}
		defer r.Body.Close()
		var acl ACL
		if err := decodeJSON(r, &acl); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		if acl.ID == "" {
			acl.ID = GenerateSecureID("acl")
		}
		acl.TenantID = tenantID
		if err := s.engine.GrantACL(r.Context(), &acl); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusCreated, acl)
	case http.MethodPut:
		if len(parts) == 0 {
			respondError(w, http.StatusNotFound, errors.New("acl id required"))
			return
		}
		defer r.Body.Close()
		var acl ACL
		if err := decodeJSON(r, &acl); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		acl.ID = parts[0]
		acl.TenantID = tenantID
		if err := s.engine.UpdateACL(r.Context(), &acl); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, acl)
	case http.MethodDelete:
		if len(parts) == 0 {
			respondError(w, http.StatusNotFound, errors.New("acl id required"))
			return
		}
		// Optional: check tenant ownership if needed, but ID is unique
		if err := s.engine.RevokeACL(r.Context(), parts[0]); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,POST,PUT,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *AdminHTTPServer) handleMembers(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	// Pattern: /tenants/{tid}/members/{subjectID}/roles [POST, GET]
	//          /tenants/{tid}/members/{subjectID}/roles/{roleID} [DELETE]
	if len(parts) < 2 || parts[1] != "roles" {
		http.NotFound(w, r)
		return
	}
	subjectID := parts[0]

	switch r.Method {
	case http.MethodGet:
		roles, err := s.engine.ListRolesForUser(r.Context(), subjectID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"roles": roles})
	case http.MethodPost:
		defer r.Body.Close()
		var payload struct {
			RoleID string `json:"role_id"`
		}
		if err := decodeJSON(r, &payload); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		if payload.RoleID == "" {
			respondError(w, http.StatusBadRequest, errors.New("role_id required"))
			return
		}
		if err := s.engine.AssignRoleToUser(r.Context(), subjectID, payload.RoleID); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if len(parts) < 3 {
			respondError(w, http.StatusNotFound, errors.New("role id required"))
			return
		}
		roleID := parts[2]
		if err := s.engine.RevokeRoleFromUser(r.Context(), subjectID, roleID); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,POST,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type permissionPayload struct {
	Action   Action `json:"action"`
	Resource string `json:"resource"`
}

func (r *rolePayload) toRole(tenantID string) *Role {
	perms := make([]Permission, 0, len(r.Permissions))
	for _, p := range r.Permissions {
		perms = append(perms, Permission{Action: p.Action, Resource: p.Resource})
	}
	return &Role{
		ID:                  r.ID,
		TenantID:            tenantID,
		Name:                r.Name,
		Permissions:         perms,
		Inherits:            append([]string{}, r.Inherits...),
		OwnerAllowedActions: append([]Action{}, r.OwnerAllowedActions...),
	}
}

type roleDTO struct {
	ID                  string       `json:"id"`
	TenantID            string       `json:"tenant_id"`
	Name                string       `json:"name"`
	Permissions         []Permission `json:"permissions"`
	Inherits            []string     `json:"inherits"`
	OwnerAllowedActions []Action     `json:"owner_allowed_actions"`
}

func newRoleDTO(r *Role) roleDTO {
	return roleDTO{
		ID:                  r.ID,
		TenantID:            r.TenantID,
		Name:                r.Name,
		Permissions:         append([]Permission{}, r.Permissions...),
		Inherits:            append([]string{}, r.Inherits...),
		OwnerAllowedActions: append([]Action{}, r.OwnerAllowedActions...),
	}
}

type batchAuthorizePayload struct {
	Requests []AuthRequest `json:"requests"`
}

type batchAuthorizeResponse struct {
	Decisions []*Decision `json:"decisions"`
}

func parseTenantPath(path string) (string, []string, error) {
	trimmed := strings.Trim(path, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 || parts[0] != "tenants" {
		return "", nil, fmt.Errorf("invalid tenant path")
	}
	return parts[1], parts[2:], nil
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func respondError(w http.ResponseWriter, status int, err error) {
	if err == nil {
		err = errors.New("unknown error")
	}
	respondJSON(w, status, map[string]string{"error": err.Error()})
}
