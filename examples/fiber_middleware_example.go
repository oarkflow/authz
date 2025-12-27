package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/authz"
)

func main() {
	ctx := context.Background()

	policyStore := authz.NewMemoryPolicyStore()
	roleStore := authz.NewMemoryRoleStore()
	aclStore := authz.NewMemoryACLStore()
	auditStore := authz.NewMemoryAuditStore()

	eng := authz.NewEngine(policyStore, roleStore, aclStore, auditStore)

	// Role and policy: admin role can access any admin route
	adminRole := &authz.Role{ID: "role-admin", TenantID: "t", Name: "admin", Permissions: []authz.Permission{{Action: "GET", Resource: "route:GET:/admin/*"}}}
	_ = eng.CreateRole(ctx, adminRole)

	// child role inherits admin (demonstrates role inheritance)
	managerRole := &authz.Role{ID: "role-manager", TenantID: "t", Name: "manager", Inherits: []string{"role-admin"}}
	_ = eng.CreateRole(ctx, managerRole)

	// Policy: owners can read their own resource routes: route:GET:/users/:id
	p := &authz.Policy{ID: "p-owner-route", TenantID: "t", Effect: authz.EffectAllow, Actions: []authz.Action{"GET"}, Resources: []string{"route:GET:/users/*"}, Condition: &authz.EqExpr{Field: "resource.owner_id", Value: "subject.id"}, Priority: 10}
	_ = eng.CreatePolicy(ctx, p)
	_ = eng.ReloadPolicies(ctx, "t")

	// ACL demo: allow guest to GET /public/info
	_ = aclStore.GrantACL(ctx, &authz.ACL{ID: "acl-guest-public", ResourceID: "route:GET:/public/info", SubjectID: "guest", Actions: []authz.Action{"GET"}, Effect: authz.EffectAllow})

	// If run with CLI args: <tenant> <userID> <URI Path> <URI Method> [ownerID] [roles]
	// Example: ./fiber_middleware_example t alice /users/alice GET alice role-admin
	if len(os.Args) >= 5 {
		tenant := os.Args[1]
		userID := os.Args[2]
		path := os.Args[3]
		method := os.Args[4]
		owner := ""
		roles := []string{}
		if len(os.Args) >= 6 {
			owner = os.Args[5]
		}
		if len(os.Args) >= 7 {
			roles = strings.Split(os.Args[6], ",")
		}
		doCheck(ctx, eng, tenant, userID, path, method, owner, roles)
		return
	}

	// Fiber app with authorization middleware
	app := fiber.New()

	// In-example roster for subjects -> roles (fallback when header not provided)
	roleAssignments := map[string][]string{"sysadmin": {"role-admin"}, "mgr": {"role-manager"}}

	app.Use(func(c *fiber.Ctx) error {
		// Build subject from headers (X-Subject-ID, X-Subject-Roles, X-Tenant-ID)
		subID := c.Get("X-Subject-ID")
		tenantID := c.Get("X-Tenant-ID")
		if tenantID == "" {
			tenantID = "t"
		}
		rolesStr := c.Get("X-Subject-Roles")
		roles := []string{}
		if rolesStr != "" {
			roles = strings.Split(rolesStr, ",")
		} else if asgn, ok := roleAssignments[subID]; ok {
			// fallback mapping in this example
			roles = append(roles, asgn...)
		}
		sub := &authz.Subject{ID: subID, TenantID: tenantID, Roles: roles}

		// Resource: encode method:path into resource.ID and set OwnerID when possible
		path := c.Path()
		res := &authz.Resource{Type: "route", ID: c.Method() + ":" + path, TenantID: tenantID}
		// If path is like /users/:id, set OwnerID so owner-based policies can match
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) > 1 && parts[0] == "users" {
			res.OwnerID = parts[len(parts)-1]
		}
		env := &authz.Environment{Time: time.Now(), TenantID: tenantID}

		decision, _ := eng.Authorize(context.Background(), sub, authz.Action(c.Method()), res, env)
		if decision.Allowed {
			return c.Next()
		}
		return c.Status(http.StatusForbidden).SendString("forbidden")
	})

	app.Get("/admin/dashboard", func(c *fiber.Ctx) error {
		return c.SendString("admin dashboard")
	})

	app.Get("/users/:id", func(c *fiber.Ctx) error {
		return c.SendString(fmt.Sprintf("user %s profile", c.Params("id")))
	})

	app.Get("/public/info", func(c *fiber.Ctx) error {
		return c.SendString("public info")
	})

	// Start the server in the background and exercise it with real HTTP requests
	go func() {
		if err := app.Listen(":3000"); err != nil {
			log.Printf("server error: %v", err)
		}
	}()
	// give server a moment to start
	time.Sleep(100 * time.Millisecond)

	b := make([]byte, 1024)

	// Admin access
	req, _ := http.NewRequest("GET", "http://localhost:3000/admin/dashboard", nil)
	req.Header.Set("X-Subject-ID", "sysadmin")
	req.Header.Set("X-Subject-Roles", "role-admin")
	resp, _ := http.DefaultClient.Do(req)
	n, _ := resp.Body.Read(b)
	resp.Body.Close()
	fmt.Printf("Admin GET /admin/dashboard -> %d %s\n", resp.StatusCode, strings.TrimSpace(string(b[:n])))

	// Owner access to their profile
	req2, _ := http.NewRequest("GET", "http://localhost:3000/users/alice", nil)
	req2.Header.Set("X-Subject-ID", "alice")
	resp2, _ := http.DefaultClient.Do(req2)
	n2, _ := resp2.Body.Read(b)
	resp2.Body.Close()
	fmt.Printf("Owner GET /users/alice -> %d %s\n", resp2.StatusCode, strings.TrimSpace(string(b[:n2])))

	// Non-owner denied (bob)
	req3, _ := http.NewRequest("GET", "http://localhost:3000/users/alice", nil)
	req3.Header.Set("X-Subject-ID", "bob")
	resp3, _ := http.DefaultClient.Do(req3)
	n3, _ := resp3.Body.Read(b)
	resp3.Body.Close()
	fmt.Printf("Non-owner GET /users/alice -> %d %s\n", resp3.StatusCode, strings.TrimSpace(string(b[:n3])))

	// Sysadmin implicit role (no X-Subject-Roles header) should be allowed via roleAssignments fallback
	reqSys, _ := http.NewRequest("GET", "http://localhost:3000/admin/dashboard", nil)
	reqSys.Header.Set("X-Subject-ID", "sysadmin")
	respSys, _ := http.DefaultClient.Do(reqSys)
	nSys, _ := respSys.Body.Read(b)
	respSys.Body.Close()
	fmt.Printf("Sysadmin (implicit) GET /admin/dashboard -> %d %s\n", respSys.StatusCode, strings.TrimSpace(string(b[:nSys])))

	// Manager (inherits admin) access to admin dashboard
	reqMgr, _ := http.NewRequest("GET", "http://localhost:3000/admin/dashboard", nil)
	reqMgr.Header.Set("X-Subject-ID", "mgr")
	reqMgr.Header.Set("X-Subject-Roles", "role-manager")
	respMgr, _ := http.DefaultClient.Do(reqMgr)
	n4, _ := respMgr.Body.Read(b)
	respMgr.Body.Close()
	fmt.Printf("Manager GET /admin/dashboard -> %d %s\n", respMgr.StatusCode, strings.TrimSpace(string(b[:n4])))

	// Guest public (ACL allowed)
	reqGuest, _ := http.NewRequest("GET", "http://localhost:3000/public/info", nil)
	reqGuest.Header.Set("X-Subject-ID", "guest")
	respGuest, _ := http.DefaultClient.Do(reqGuest)
	n5, _ := respGuest.Body.Read(b)
	respGuest.Body.Close()
	fmt.Printf("Guest GET /public/info -> %d %s\n", respGuest.StatusCode, strings.TrimSpace(string(b[:n5])))

	// Shutdown server
	_ = app.Shutdown()

}
func doCheck(ctx context.Context, eng *authz.Engine, tenant, userID, path, method, owner string, roles []string) {
	// Build subject and resource
	sub := &authz.Subject{ID: userID, TenantID: tenant, Roles: roles}
	res := &authz.Resource{Type: "route", ID: method + ":" + path, TenantID: tenant}
	if owner != "" {
		res.OwnerID = owner
	} else {
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) > 1 && parts[0] == "users" {
			res.OwnerID = parts[len(parts)-1]
		}
	}
	env := &authz.Environment{Time: time.Now(), TenantID: tenant}
	decision, _ := eng.Authorize(ctx, sub, authz.Action(method), res, env)
	fmt.Printf("CLI check: tenant=%s user=%s path=%s method=%s owner=%s roles=%v -> allowed=%v reason=%s\n", tenant, userID, path, method, res.OwnerID, roles, decision.Allowed, decision.Reason)
}
