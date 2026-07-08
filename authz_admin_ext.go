package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ExtendedAdminServer extends AdminHTTPServer with IAM management endpoints.
type ExtendedAdminServer struct {
	*AdminHTTPServer

	userStore           UserStore
	groupStore          GroupStore
	groupMemberStore    GroupMembershipStore
	groupRoleStore      GroupRoleStore
	scopeStore          ScopeStore
	roleScopeStore      RoleScopeStore
	serviceAccountStore ServiceAccountStore
	invitationStore     InvitationStore
	eventStore          EventStore
	webhookStore        WebhookStore
	eventDispatcher     *EventDispatcher
	tokenConfig         *TokenConfig
	sessionStore        SessionStore
	loginTracker        *LoginTracker
	permissionResolver  *PermissionResolver
}

// ExtendedAdminOption configures the ExtendedAdminServer.
type ExtendedAdminOption func(*ExtendedAdminServer)

func WithUserStore(s UserStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.userStore = s }
}

func WithGroupStore(s GroupStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.groupStore = s }
}

func WithGroupMembershipStore(s GroupMembershipStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.groupMemberStore = s }
}

func WithGroupRoleStore(s GroupRoleStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.groupRoleStore = s }
}

func WithScopeStore(s ScopeStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.scopeStore = s }
}

func WithRoleScopeStore(s RoleScopeStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.roleScopeStore = s }
}

func WithServiceAccountStore(s ServiceAccountStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.serviceAccountStore = s }
}

func WithInvitationStore(s InvitationStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.invitationStore = s }
}

func WithEventStore(s EventStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.eventStore = s }
}

func WithWebhookStore(s WebhookStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.webhookStore = s }
}

func WithEventDispatcher(d *EventDispatcher) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.eventDispatcher = d }
}

func WithTokenConfig(tc *TokenConfig) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.tokenConfig = tc }
}

func WithSessionStore(s SessionStore) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.sessionStore = s }
}

func WithLoginTracker(lt *LoginTracker) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.loginTracker = lt }
}

func WithPermissionResolver(pr *PermissionResolver) ExtendedAdminOption {
	return func(e *ExtendedAdminServer) { e.permissionResolver = pr }
}

// NewExtendedAdminServer creates an ExtendedAdminServer wrapping the given AdminHTTPServer.
func NewExtendedAdminServer(base *AdminHTTPServer, opts ...ExtendedAdminOption) *ExtendedAdminServer {
	srv := &ExtendedAdminServer{AdminHTTPServer: base}
	for _, opt := range opts {
		opt(srv)
	}
	srv.extendedRoutes()
	return srv
}

func (s *ExtendedAdminServer) extendedRoutes() {
	// Override the tenant sub-resource handler to add new routes
	s.mux.HandleFunc("/tenants/", s.handleExtendedTenants)
	// Auth endpoints (not tenant-scoped)
	s.mux.HandleFunc("/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("/auth/refresh", s.handleAuthRefresh)
	s.mux.HandleFunc("/auth/logout", s.handleAuthLogout)
}

func (s *ExtendedAdminServer) handleExtendedTenants(w http.ResponseWriter, r *http.Request) {
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
		// Delegate tenant-level ops to base
		s.AdminHTTPServer.handleTenants(w, r)
		return
	}
	switch remainder[0] {
	// Original routes — delegate to base server
	case "policies", "roles", "acls", "members", "explain", "batch":
		s.AdminHTTPServer.handleTenants(w, r)
	// Extended routes
	case "users":
		s.handleUsers(w, r, tenantID, remainder[1:])
	case "groups":
		s.handleGroups(w, r, tenantID, remainder[1:])
	case "scopes":
		s.handleScopes(w, r, tenantID, remainder[1:])
	case "service-accounts":
		s.handleServiceAccounts(w, r, tenantID, remainder[1:])
	case "invitations":
		s.handleInvitations(w, r, tenantID, remainder[1:])
	case "webhooks":
		s.handleWebhooks(w, r, tenantID, remainder[1:])
	case "events":
		s.handleEvents(w, r, tenantID)
	case "effective-permissions":
		s.handleEffectivePermissions(w, r, tenantID)
	default:
		http.NotFound(w, r)
	}
}

// ============================================================================
// USERS
// ============================================================================

func (s *ExtendedAdminServer) handleUsers(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	if s.userStore == nil {
		respondError(w, http.StatusNotImplemented, errors.New("user store not configured"))
		return
	}
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			users, err := s.userStore.ListUsers(r.Context(), UserFilter{TenantID: tenantID})
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, map[string]any{"users": users})
		case http.MethodPost:
			defer r.Body.Close()
			var u User
			if err := decodeJSON(r, &u); err != nil {
				respondError(w, http.StatusBadRequest, err)
				return
			}
			u.TenantID = tenantID
			if u.Email == "" {
				respondError(w, http.StatusBadRequest, errors.New("email required"))
				return
			}
			if u.Status == "" {
				u.Status = UserStatusActive
			}
			now := time.Now()
			u.CreatedAt = now
			u.UpdatedAt = now
			if err := s.userStore.CreateUser(r.Context(), &u); err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusCreated, u)
		default:
			w.Header().Set("Allow", "GET,POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	userID := parts[0]
	switch r.Method {
	case http.MethodGet:
		u, err := s.userStore.GetUser(r.Context(), userID)
		if err != nil {
			respondError(w, http.StatusNotFound, err)
			return
		}
		respondJSON(w, http.StatusOK, u)
	case http.MethodPut:
		defer r.Body.Close()
		var u User
		if err := decodeJSON(r, &u); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		u.ID = userID
		u.TenantID = tenantID
		u.UpdatedAt = time.Now()
		if err := s.userStore.UpdateUser(r.Context(), &u); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, u)
	case http.MethodDelete:
		if err := s.userStore.DeleteUser(r.Context(), userID); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,PUT,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ============================================================================
// GROUPS
// ============================================================================

func (s *ExtendedAdminServer) handleGroups(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	if s.groupStore == nil {
		respondError(w, http.StatusNotImplemented, errors.New("group store not configured"))
		return
	}
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			groups, err := s.groupStore.ListGroups(r.Context(), tenantID)
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, map[string]any{"groups": groups})
		case http.MethodPost:
			defer r.Body.Close()
			var g Group
			if err := decodeJSON(r, &g); err != nil {
				respondError(w, http.StatusBadRequest, err)
				return
			}
			g.TenantID = tenantID
			now := time.Now()
			g.CreatedAt = now
			g.UpdatedAt = now
			if err := s.groupStore.CreateGroup(r.Context(), &g); err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusCreated, g)
		default:
			w.Header().Set("Allow", "GET,POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	groupID := parts[0]
	// /tenants/{tid}/groups/{gid}/members or /tenants/{tid}/groups/{gid}/roles
	if len(parts) >= 2 {
		switch parts[1] {
		case "members":
			s.handleGroupMembers(w, r, groupID, parts[2:])
		case "roles":
			s.handleGroupRoles(w, r, groupID, parts[2:])
		default:
			http.NotFound(w, r)
		}
		return
	}
	switch r.Method {
	case http.MethodGet:
		g, err := s.groupStore.GetGroup(r.Context(), groupID)
		if err != nil {
			respondError(w, http.StatusNotFound, err)
			return
		}
		respondJSON(w, http.StatusOK, g)
	case http.MethodPut:
		defer r.Body.Close()
		var g Group
		if err := decodeJSON(r, &g); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		g.ID = groupID
		g.TenantID = tenantID
		g.UpdatedAt = time.Now()
		if err := s.groupStore.UpdateGroup(r.Context(), &g); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, g)
	case http.MethodDelete:
		if err := s.groupStore.DeleteGroup(r.Context(), groupID); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,PUT,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *ExtendedAdminServer) handleGroupMembers(w http.ResponseWriter, r *http.Request, groupID string, parts []string) {
	if s.groupMemberStore == nil {
		respondError(w, http.StatusNotImplemented, errors.New("group membership store not configured"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		members, err := s.groupMemberStore.ListMembers(r.Context(), groupID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"members": members})
	case http.MethodPost:
		defer r.Body.Close()
		var payload struct {
			UserID string `json:"user_id"`
		}
		if err := decodeJSON(r, &payload); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		if payload.UserID == "" {
			respondError(w, http.StatusBadRequest, errors.New("user_id required"))
			return
		}
		if err := s.groupMemberStore.AddMember(r.Context(), groupID, payload.UserID); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if len(parts) == 0 {
			respondError(w, http.StatusBadRequest, errors.New("user_id required in path"))
			return
		}
		if err := s.groupMemberStore.RemoveMember(r.Context(), groupID, parts[0]); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,POST,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *ExtendedAdminServer) handleGroupRoles(w http.ResponseWriter, r *http.Request, groupID string, parts []string) {
	if s.groupRoleStore == nil {
		respondError(w, http.StatusNotImplemented, errors.New("group role store not configured"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		roles, err := s.groupRoleStore.ListRolesByGroup(r.Context(), groupID)
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
		if err := s.groupRoleStore.AssignRole(r.Context(), groupID, payload.RoleID); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		if len(parts) == 0 {
			respondError(w, http.StatusBadRequest, errors.New("role_id required in path"))
			return
		}
		if err := s.groupRoleStore.RevokeRole(r.Context(), groupID, parts[0]); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,POST,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ============================================================================
// SCOPES
// ============================================================================

func (s *ExtendedAdminServer) handleScopes(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	if s.scopeStore == nil {
		respondError(w, http.StatusNotImplemented, errors.New("scope store not configured"))
		return
	}
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			scopes, err := s.scopeStore.ListScopes(r.Context(), tenantID)
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, map[string]any{"scopes": scopes})
		case http.MethodPost:
			defer r.Body.Close()
			var sc Scope
			if err := decodeJSON(r, &sc); err != nil {
				respondError(w, http.StatusBadRequest, err)
				return
			}
			sc.TenantID = tenantID
			sc.CreatedAt = time.Now()
			if err := s.scopeStore.CreateScope(r.Context(), &sc); err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusCreated, sc)
		default:
			w.Header().Set("Allow", "GET,POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	scopeID := parts[0]
	switch r.Method {
	case http.MethodGet:
		sc, err := s.scopeStore.GetScope(r.Context(), scopeID)
		if err != nil {
			respondError(w, http.StatusNotFound, err)
			return
		}
		respondJSON(w, http.StatusOK, sc)
	case http.MethodPut:
		defer r.Body.Close()
		var sc Scope
		if err := decodeJSON(r, &sc); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		sc.ID = scopeID
		sc.TenantID = tenantID
		if err := s.scopeStore.UpdateScope(r.Context(), &sc); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, sc)
	case http.MethodDelete:
		if err := s.scopeStore.DeleteScope(r.Context(), scopeID); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,PUT,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ============================================================================
// SERVICE ACCOUNTS
// ============================================================================

func (s *ExtendedAdminServer) handleServiceAccounts(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	if s.serviceAccountStore == nil {
		respondError(w, http.StatusNotImplemented, errors.New("service account store not configured"))
		return
	}
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			accounts, err := s.serviceAccountStore.ListServiceAccounts(r.Context(), tenantID)
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, map[string]any{"service_accounts": accounts})
		case http.MethodPost:
			defer r.Body.Close()
			var sa ServiceAccount
			if err := decodeJSON(r, &sa); err != nil {
				respondError(w, http.StatusBadRequest, err)
				return
			}
			sa.TenantID = tenantID
			// Generate credentials
			clientID, plainSecret, hashedSecret, err := GenerateClientCredentials()
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			sa.ClientID = clientID
			sa.ClientSecret = hashedSecret
			sa.Status = UserStatusActive
			now := time.Now()
			sa.CreatedAt = now
			sa.UpdatedAt = now
			if err := s.serviceAccountStore.CreateServiceAccount(r.Context(), &sa); err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			// Return the plain secret once — it cannot be retrieved later
			respondJSON(w, http.StatusCreated, map[string]any{
				"service_account": sa,
				"client_id":       clientID,
				"client_secret":   plainSecret,
			})
		default:
			w.Header().Set("Allow", "GET,POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	saID := parts[0]
	switch r.Method {
	case http.MethodGet:
		sa, err := s.serviceAccountStore.GetServiceAccount(r.Context(), saID)
		if err != nil {
			respondError(w, http.StatusNotFound, err)
			return
		}
		respondJSON(w, http.StatusOK, sa)
	case http.MethodPut:
		defer r.Body.Close()
		var sa ServiceAccount
		if err := decodeJSON(r, &sa); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		sa.ID = saID
		sa.TenantID = tenantID
		sa.UpdatedAt = time.Now()
		if err := s.serviceAccountStore.UpdateServiceAccount(r.Context(), &sa); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, sa)
	case http.MethodDelete:
		if err := s.serviceAccountStore.DeleteServiceAccount(r.Context(), saID); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,PUT,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ============================================================================
// INVITATIONS
// ============================================================================

func (s *ExtendedAdminServer) handleInvitations(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	if s.invitationStore == nil {
		respondError(w, http.StatusNotImplemented, errors.New("invitation store not configured"))
		return
	}
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			invites, err := s.invitationStore.ListInvitations(r.Context(), tenantID)
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, map[string]any{"invitations": invites})
		case http.MethodPost:
			defer r.Body.Close()
			var inv Invitation
			if err := decodeJSON(r, &inv); err != nil {
				respondError(w, http.StatusBadRequest, err)
				return
			}
			inv.TenantID = tenantID
			if inv.Email == "" {
				respondError(w, http.StatusBadRequest, errors.New("email required"))
				return
			}
			token, tokenHash, err := GenerateInviteToken()
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			inv.Token = tokenHash // store hash
			inv.TokenHash = tokenHash
			inv.Status = InviteStatusPending
			inv.CreatedAt = time.Now()
			if inv.ExpiresAt.IsZero() {
				inv.ExpiresAt = time.Now().Add(72 * time.Hour)
			}
			if err := s.invitationStore.CreateInvitation(r.Context(), &inv); err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusCreated, map[string]any{
				"invitation": inv,
				"token":      token, // return plain token once
			})
		default:
			w.Header().Set("Allow", "GET,POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	// /tenants/{tid}/invitations/{id}/accept
	if len(parts) == 2 && parts[1] == "accept" {
		s.handleAcceptInvitation(w, r, parts[0])
		return
	}
	invID := parts[0]
	switch r.Method {
	case http.MethodGet:
		inv, err := s.invitationStore.GetInvitation(r.Context(), invID)
		if err != nil {
			respondError(w, http.StatusNotFound, err)
			return
		}
		respondJSON(w, http.StatusOK, inv)
	case http.MethodDelete:
		// Revoke
		inv, err := s.invitationStore.GetInvitation(r.Context(), invID)
		if err != nil {
			respondError(w, http.StatusNotFound, err)
			return
		}
		inv.Status = InviteStatusRevoked
		if err := s.invitationStore.UpdateInvitation(r.Context(), inv); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *ExtendedAdminServer) handleAcceptInvitation(w http.ResponseWriter, r *http.Request, invID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var payload struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	if payload.Token == "" {
		respondError(w, http.StatusBadRequest, errors.New("token required"))
		return
	}
	tokenHash := HashInviteToken(payload.Token)
	inv, err := s.invitationStore.GetInvitationByToken(r.Context(), tokenHash)
	if err != nil {
		respondError(w, http.StatusNotFound, errors.New("invalid or expired invitation"))
		return
	}
	if inv.ID != invID {
		respondError(w, http.StatusBadRequest, errors.New("token does not match invitation"))
		return
	}
	if inv.Status != InviteStatusPending {
		respondError(w, http.StatusConflict, fmt.Errorf("invitation status is %s", inv.Status))
		return
	}
	if inv.IsExpired() {
		inv.Status = InviteStatusExpired
		_ = s.invitationStore.UpdateInvitation(r.Context(), inv)
		respondError(w, http.StatusGone, errors.New("invitation has expired"))
		return
	}
	inv.Status = InviteStatusAccepted
	inv.AcceptedAt = time.Now()
	if err := s.invitationStore.UpdateInvitation(r.Context(), inv); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, inv)
}

// ============================================================================
// WEBHOOKS
// ============================================================================

func (s *ExtendedAdminServer) handleWebhooks(w http.ResponseWriter, r *http.Request, tenantID string, parts []string) {
	if s.webhookStore == nil {
		respondError(w, http.StatusNotImplemented, errors.New("webhook store not configured"))
		return
	}
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			webhooks, err := s.webhookStore.ListWebhooks(r.Context(), tenantID)
			if err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusOK, map[string]any{"webhooks": webhooks})
		case http.MethodPost:
			defer r.Body.Close()
			var wh Webhook
			if err := decodeJSON(r, &wh); err != nil {
				respondError(w, http.StatusBadRequest, err)
				return
			}
			wh.TenantID = tenantID
			if wh.URL == "" {
				respondError(w, http.StatusBadRequest, errors.New("url required"))
				return
			}
			if err := ValidateWebhookURL(wh.URL); err != nil {
				respondError(w, http.StatusBadRequest, err)
				return
			}
			wh.Enabled = true
			now := time.Now()
			wh.CreatedAt = now
			wh.UpdatedAt = now
			if err := s.webhookStore.CreateWebhook(r.Context(), &wh); err != nil {
				respondError(w, http.StatusInternalServerError, err)
				return
			}
			respondJSON(w, http.StatusCreated, wh)
		default:
			w.Header().Set("Allow", "GET,POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	whID := parts[0]
	switch r.Method {
	case http.MethodGet:
		wh, err := s.webhookStore.GetWebhook(r.Context(), whID)
		if err != nil {
			respondError(w, http.StatusNotFound, err)
			return
		}
		respondJSON(w, http.StatusOK, wh)
	case http.MethodPut:
		defer r.Body.Close()
		var wh Webhook
		if err := decodeJSON(r, &wh); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		wh.ID = whID
		wh.TenantID = tenantID
		wh.UpdatedAt = time.Now()
		if wh.URL != "" {
			if err := ValidateWebhookURL(wh.URL); err != nil {
				respondError(w, http.StatusBadRequest, err)
				return
			}
		}
		if err := s.webhookStore.UpdateWebhook(r.Context(), &wh); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, wh)
	case http.MethodDelete:
		if err := s.webhookStore.DeleteWebhook(r.Context(), whID); err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET,PUT,DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ============================================================================
// EVENTS
// ============================================================================

func (s *ExtendedAdminServer) handleEvents(w http.ResponseWriter, r *http.Request, tenantID string) {
	if s.eventStore == nil {
		respondError(w, http.StatusNotImplemented, errors.New("event store not configured"))
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	filter := EventFilter{
		TenantID: tenantID,
		Type:     EventType(q.Get("type")),
		ActorID:  q.Get("actor_id"),
		TargetID: q.Get("target_id"),
		Limit:    100,
	}
	events, err := s.eventStore.ListEvents(r.Context(), filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"events": events})
}

// ============================================================================
// EFFECTIVE PERMISSIONS
// ============================================================================

func (s *ExtendedAdminServer) handleEffectivePermissions(w http.ResponseWriter, r *http.Request, tenantID string) {
	if s.permissionResolver == nil {
		respondError(w, http.StatusNotImplemented, errors.New("permission resolver not configured"))
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		respondError(w, http.StatusBadRequest, errors.New("user_id query parameter required"))
		return
	}
	perms, err := s.permissionResolver.GetEffectivePermissions(r.Context(), userID, tenantID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"permissions": perms})
}

// ============================================================================
// AUTH ENDPOINTS
// ============================================================================

func (s *ExtendedAdminServer) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.userStore == nil || s.tokenConfig == nil {
		respondError(w, http.StatusNotImplemented, errors.New("auth not configured"))
		return
	}
	defer r.Body.Close()
	var payload struct {
		TenantID string `json:"tenant_id"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	if payload.TenantID == "" || payload.Email == "" || payload.Password == "" {
		respondError(w, http.StatusBadRequest, errors.New("tenant_id, email and password required"))
		return
	}

	// Check brute force lockout
	if s.loginTracker != nil && s.loginTracker.IsLocked(payload.Email) {
		respondError(w, http.StatusTooManyRequests, errors.New("account temporarily locked"))
		return
	}

	user, err := s.userStore.GetUserByEmail(r.Context(), payload.TenantID, payload.Email)
	if err != nil {
		s.recordLoginFailure(payload.Email, r)
		respondError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}
	if user.Status != UserStatusActive {
		respondError(w, http.StatusForbidden, fmt.Errorf("account is %s", user.Status))
		return
	}
	if err := CheckPassword(user.PasswordHash, payload.Password); err != nil {
		s.recordLoginFailure(payload.Email, r)
		respondError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}

	// Successful login — reset tracker
	if s.loginTracker != nil {
		s.loginTracker.RecordAttempt(LoginAttempt{Email: payload.Email, Success: true})
	}

	// Get user roles
	var roles []string
	if s.AdminHTTPServer.engine != nil {
		roles, _ = s.engine.roleMembershipStore.ListRoles(r.Context(), user.ID)
	}

	claims := &TokenClaims{
		UserID:   user.ID,
		TenantID: user.TenantID,
		Email:    user.Email,
		Roles:    roles,
	}
	pair, err := s.tokenConfig.GenerateTokenPair(claims)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}

	// Create session if store available
	if s.sessionStore != nil {
		sess := &Session{
			ID:           GenerateSecureID("sess"),
			UserID:       user.ID,
			TenantID:     user.TenantID,
			RefreshToken: pair.RefreshToken,
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			ExpiresAt:    time.Now().Add(s.tokenConfig.RefreshTokenTTL),
			CreatedAt:    time.Now(),
		}
		_ = s.sessionStore.CreateSession(r.Context(), sess)
	}

	// Dispatch login event
	if s.eventDispatcher != nil {
		_ = s.eventDispatcher.Dispatch(r.Context(), &Event{
			ID:       GenerateSecureID("evt"),
			TenantID: user.TenantID,
			Type:     EventUserLogin,
			ActorID:  user.ID,
			Data:     map[string]any{"ip": r.RemoteAddr},
		})
	}

	respondJSON(w, http.StatusOK, pair)
}

func (s *ExtendedAdminServer) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.tokenConfig == nil {
		respondError(w, http.StatusNotImplemented, errors.New("auth not configured"))
		return
	}
	defer r.Body.Close()
	var payload struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	if payload.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, errors.New("refresh_token required"))
		return
	}
	pair, err := s.tokenConfig.RefreshTokenPair(payload.RefreshToken)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err)
		return
	}
	respondJSON(w, http.StatusOK, pair)
}

func (s *ExtendedAdminServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var payload struct {
		SessionID string `json:"session_id"`
		UserID    string `json:"user_id"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	if s.sessionStore != nil {
		if payload.SessionID != "" {
			_ = s.sessionStore.DeleteSession(r.Context(), payload.SessionID)
		} else if payload.UserID != "" {
			_ = s.sessionStore.DeleteUserSessions(r.Context(), payload.UserID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *ExtendedAdminServer) recordLoginFailure(email string, r *http.Request) {
	if s.loginTracker == nil {
		return
	}
	s.loginTracker.RecordAttempt(LoginAttempt{
		Email: email,
		IP:    r.RemoteAddr,
	})
}

// decodeJSONBody is a helper that decodes JSON from request body.
// It is intentionally not exported and shadows the package-level decodeJSON for clarity.
func decodeJSONBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
