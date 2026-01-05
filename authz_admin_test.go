package authz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func newEmptyEngine(t *testing.T) *authz.Engine {
	t.Helper()
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	return authz.NewEngine(policyStore, roleStore, aclStore, auditStore)
}

func TestAdminHTTPServerPolicyCreate(t *testing.T) {
	engine := newEmptyEngine(t)
	server := authz.NewAdminHTTPServer(engine)
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
	server := authz.NewAdminHTTPServer(engine)
	body := `{"subject_id":"alice","action":"read","resource":"document:42"}`
	req := httptest.NewRequest(http.MethodPost, "/tenants/tenant-admin/explain", strings.NewReader(body))
	resp := httptest.NewRecorder()
	server.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.Code)
	}
}
