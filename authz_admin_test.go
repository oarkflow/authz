package authz_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func newEmptyEngine(t *testing.T) *authz.Engine {
	t.Helper()
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	tenantStore := stores.NewMemoryTenantStore()
	roleMemberStore := stores.NewMemoryRoleMembershipStore()

	// Use the new options
	return authz.NewEngine(policyStore, roleStore, aclStore, auditStore,
		authz.WithTenantStore(tenantStore),
		authz.WithRoleMembershipStore(roleMemberStore),
	)
}

func newTestAdminServer(t *testing.T, engine *authz.Engine, opts ...authz.AdminHTTPOption) *authz.AdminHTTPServer {
	t.Helper()
	opts = append(opts, authz.WithAdminAuthDisabled())
	server, err := authz.NewAdminHTTPServer(engine, opts...)
	if err != nil {
		t.Fatalf("new admin server: %v", err)
	}
	return server
}

func TestAdminHTTPServerRefusesToStartWithoutAuth(t *testing.T) {
	engine := newEmptyEngine(t)
	server, err := authz.NewAdminHTTPServer(engine)
	if err == nil {
		t.Fatal("expected error when no auth is configured, got nil")
	}
	if !errors.Is(err, authz.ErrAdminAuthNotConfigured) {
		t.Fatalf("expected ErrAdminAuthNotConfigured, got %v", err)
	}
	if server != nil {
		t.Fatal("expected nil server on failure")
	}
}

func TestAdminHTTPServerStartsWithAdminAuth(t *testing.T) {
	engine := newEmptyEngine(t)
	server, err := authz.NewAdminHTTPServer(engine, authz.WithAdminAuth(func(r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if server == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestAdminHTTPServerStartsWithAuthExplicitlyDisabled(t *testing.T) {
	engine := newEmptyEngine(t)
	server, err := authz.NewAdminHTTPServer(engine, authz.WithAdminAuthDisabled())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if server == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestAdminHTTPServerDefaultRateLimiterApplied(t *testing.T) {
	engine := newEmptyEngine(t)
	server := newTestAdminServer(t, engine)

	// The default limiter is conservative (burst 20); hammering the same
	// client beyond that should eventually trip a 429 even though no
	// WithAdminRateLimiter option was provided.
	var lastCode int
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "203.0.113.5:1234"
		resp := httptest.NewRecorder()
		server.ServeHTTP(resp, req)
		lastCode = resp.Code
		if lastCode == http.StatusTooManyRequests {
			break
		}
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected default rate limiter to eventually return 429, last status was %d", lastCode)
	}
}

func TestAdminHTTPServerPolicyCreate(t *testing.T) {
	engine := newEmptyEngine(t)
	server := newTestAdminServer(t, engine)
	body := `{"id":"admin-policy","effect":"allow","actions":["read"],"resources":["document:*"],"condition":"","priority":1}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/tenant-admin/policies", strings.NewReader(body))
	resp := httptest.NewRecorder()
	server.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", resp.Code)
	}
	policies, err := engine.ListPolicies(context.Background(), "tenant-admin")
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
}

func TestAdminHTTPServerExplainEndpoint(t *testing.T) {
	engine := newEmptyEngine(t)
	policy := &authz.Policy{
		ID:        "doc-read",
		TenantID:  "tenant-admin",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"read"},
		Resources: []string{"document:*"},
		Condition: &authz.TrueExpr{},
		Priority:  1,
	}
	if err := engine.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := engine.ReloadPolicies(context.Background(), "tenant-admin"); err != nil {
		t.Fatalf("reload policies: %v", err)
	}
	server := newTestAdminServer(t, engine)
	body := `{"subject_id":"alice","action":"read","resource":"document:42"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/tenant-admin/explain", strings.NewReader(body))
	resp := httptest.NewRecorder()
	server.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.Code)
	}
}

func TestAdminHTTPServerTenantCreate(t *testing.T) {
	engine := newEmptyEngine(t)
	server := newTestAdminServer(t, engine)
	body := `{"id":"new-tenant","name":"New Tenant"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(body))
	resp := httptest.NewRecorder()
	server.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", resp.Code)
	}

	// Verify tenant created
	tenant, err := engine.GetTenant(context.Background(), "new-tenant")
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if tenant.Name != "New Tenant" {
		t.Fatalf("expected name 'New Tenant', got %s", tenant.Name)
	}
}

func TestAdminHTTPServerACLCreate(t *testing.T) {
	engine := newEmptyEngine(t)
	server := newTestAdminServer(t, engine)

	body := `{"id":"acl-1","resource_id":"doc:1","subject_id":"user:1","actions":["read"],"effect":"allow"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/acls", strings.NewReader(body))
	resp := httptest.NewRecorder()
	server.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", resp.Code)
	}

	// Verify ACL created
	acl, err := engine.GetACL(context.Background(), "acl-1")
	if err != nil {
		t.Fatalf("get acl: %v", err)
	}
	if acl.TenantID != "t1" {
		t.Fatalf("expected tenant t1, got %s", acl.TenantID)
	}
}

func TestAdminHTTPServerMemberAssign(t *testing.T) {
	engine := newEmptyEngine(t)
	server := newTestAdminServer(t, engine)

	// Assign role
	body := `{"role_id":"role-1"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/t1/members/user:1/roles", strings.NewReader(body))
	resp := httptest.NewRecorder()
	server.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", resp.Code)
	}

	// Verify role assigned
	roles, err := engine.ListRolesForUser(context.Background(), "user:1")
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) != 1 || roles[0] != "role-1" {
		t.Fatalf("expected role-1, got %v", roles)
	}
}
