package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func main() {
	ctx := context.Background()

	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	rmStore := stores.NewMemoryRoleMembershipStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()

	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore, authz.WithRoleMembershipStore(rmStore), authz.WithLogger(authz.NewNullLogger()))

	// RBAC: admin role for tenant "t"
	adminRole := &authz.Role{ID: "role-admin", TenantID: "t", Name: "admin", Permissions: []authz.Permission{{Action: "GET", Resource: "route:GET:/admin/*"}}}
	_ = engine.CreateRole(ctx, adminRole)
	_ = rmStore.AssignRole(ctx, "sysadmin", "role-admin")

	// Policy: owners can GET their user route
	p := &authz.Policy{ID: "p-owner-route", TenantID: "t", Effect: authz.EffectAllow, Actions: []authz.Action{"GET"}, Resources: []string{"route:GET:/users/*"}, Condition: &authz.EqExpr{Field: "resource.owner_id", Value: "subject.id"}, Priority: 10}
	_ = engine.CreatePolicy(ctx, p)
	_ = engine.ReloadPolicies(ctx, "t")

	// ACL: guest can GET /public/info
	_ = aclStore.GrantACL(ctx, &authz.ACL{ID: "acl-guest-public", ResourceID: "route:GET:/public/info", SubjectID: "guest", Actions: []authz.Action{"GET"}, Effect: authz.EffectAllow})

	// HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("admin dashboard"))
	})
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		// last segment
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		id := ""
		if len(parts) >= 2 && parts[0] == "users" {
			id = parts[len(parts)-1]
		}
		w.Write([]byte(fmt.Sprintf("user %s profile", id)))
	})
	mux.HandleFunc("/public/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("public info"))
	})

	// Extractor functions for example
	subjectFn := func(r *http.Request) string { return r.Header.Get("X-Subject-ID") }
	tenantFn := func(r *http.Request) string { return r.Header.Get("X-Tenant-ID") }
	resourceFn := func(r *http.Request) *authz.Resource {
		res := &authz.Resource{Type: "route", ID: r.Method + ":" + r.URL.Path, TenantID: tenantFn(r)}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 2 && parts[0] == "users" {
			res.OwnerID = parts[len(parts)-1]
		}
		return res
	}

	opts := &HTTPAuthOptions{
		Engine:   engine,
		Subject:  subjectFn,
		Tenant:   tenantFn,
		Resource: resourceFn,
		OnDenied: func(w http.ResponseWriter, r *http.Request, dec *authz.Decision) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("custom forbidden"))
		},
		OnError: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal error"))
		},
	}

	h := NewHTTPAuthMiddleware(opts)(mux)

	// start server
	srv := &http.Server{Addr: ":3001", Handler: h}
	go func() {
		_ = srv.ListenAndServe()
	}()
	// allow server to start
	time.Sleep(100 * time.Millisecond)

	tests := []struct {
		name   string
		method string
		path   string
		header map[string]string
	}{
		{"Admin", "GET", "/admin/dashboard", map[string]string{"X-Subject-ID": "sysadmin", "X-Tenant-ID": "t"}},
		{"Owner", "GET", "/users/alice", map[string]string{"X-Subject-ID": "alice", "X-Tenant-ID": "t"}},
		{"NonOwner", "GET", "/users/alice", map[string]string{"X-Subject-ID": "bob", "X-Tenant-ID": "t"}},
		{"Guest", "GET", "/public/info", map[string]string{"X-Subject-ID": "guest", "X-Tenant-ID": "t"}},
	}

	for _, tc := range tests {
		req, _ := http.NewRequest(tc.method, "http://localhost:3001"+tc.path, nil)
		for k, v := range tc.header {
			req.Header.Set(k, v)
		}
		resp, _ := http.DefaultClient.Do(req)
		b := make([]byte, 1024)
		n, _ := resp.Body.Read(b)
		resp.Body.Close()
		fmt.Printf("%s %s %s -> %d %s\n", tc.name, tc.method, tc.path, resp.StatusCode, strings.TrimSpace(string(b[:n])))
	}

	_ = srv.Close()
}
