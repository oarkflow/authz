package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func main() {
	// 1. Initialize Engine with in-memory stores, including TenantStore
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	tenantStore := stores.NewMemoryTenantStore()
	roleMemberStore := stores.NewMemoryRoleMembershipStore()

	engine := authz.NewEngine(policyStore, roleStore, aclStore, auditStore,
		authz.WithTenantStore(tenantStore),
		authz.WithRoleMembershipStore(roleMemberStore),
	)

	// 2. Start Admin HTTP Server
	server := authz.NewAdminHTTPServer(engine)
	addr := ":8081"
	go func() {
		log.Printf("Starting admin server on %s", addr)
		if err := server.Start(addr); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// 3. Demonstrate Dynamic Operations via HTTP

	// 3a. Create a Tenant
	log.Println("Creating Tenant 'engineering'...")
	createTenant(addr, authz.Tenant{
		ID:   "engineering",
		Name: "Engineering Department",
	})

	// 3b. Create a Policy
	log.Println("Creating Policy in 'engineering'...")
	createPolicy(addr, "engineering", authz.Policy{
		ID:        "allow-read-docs",
		Effect:    authz.EffectAllow,
		Actions:   []authz.Action{"read"},
		Resources: []string{"doc:*"},
		Condition: &authz.TrueExpr{}, // Always true
		Priority:  10,
	})

	// 3c. Grant an ACL
	log.Println("Granting ACL in 'engineering'...")
	createACL(addr, "engineering", authz.ACL{
		ID:         "acl-alice-doc1",
		ResourceID: "doc:1",
		SubjectID:  "user:alice",
		Actions:    []authz.Action{"write"},
		Effect:     authz.EffectAllow,
	})

	// 3d. Assign a Role
	// First create the role
	log.Println("Creating Role 'admin' in 'engineering'...")
	createRole(addr, "engineering", authz.Role{
		ID:   "admin",
		Name: "Administrator",
		Permissions: []authz.Permission{
			{Action: "*", Resource: "*"},
		},
	})
	// Then assign it
	log.Println("Assigning 'admin' role to 'user:bob'...")
	assignRole(addr, "engineering", "user:bob", "admin")

	// 4. Verify Access via Engine
	log.Println("Verifying Access...")
	verifyAccess(engine, "engineering", "user:alice", "read", "doc:1", true)   // allowed by Policy
	verifyAccess(engine, "engineering", "user:alice", "write", "doc:1", true)  // allowed by ACL
	verifyAccess(engine, "engineering", "user:bob", "delete", "doc:any", true) // allowed by Role

	fmt.Println("\nExample completed successfully.")
}

func createTenant(addr string, t authz.Tenant) {
	data, _ := json.Marshal(t)
	resp, err := http.Post("http://localhost"+addr+"/tenants", "application/json", bytes.NewReader(data))
	if err != nil {
		log.Fatalf("Failed to create tenant: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("Expected 201 Created, got %d", resp.StatusCode)
	}
}

func createPolicy(addr, tenantID string, p authz.Policy) {
	// Payload slightly different from struct to match API expectations if needed,
	// but Engine's Policy struct maps well to JSON.
	// Admin API expects specific structure. Using a map for simplicity to match API DTO.
	payload := map[string]any{
		"id":        p.ID,
		"effect":    p.Effect,
		"actions":   p.Actions,
		"resources": p.Resources,
		"condition": "", // simplification for example
		"priority":  p.Priority,
	}
	if p.Condition != nil {
		cond := p.Condition.String()
		// ParseCondition treats empty string as TrueExpr, but might not handle "true" literal
		if cond == "true" {
			cond = ""
		}
		payload["condition"] = cond
	}

	data, _ := json.Marshal(payload)
	resp, err := http.Post("http://localhost"+addr+"/tenants/"+tenantID+"/policies", "application/json", bytes.NewReader(data))
	if err != nil {
		log.Fatalf("Failed to create policy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		log.Fatalf("Expected 201 Created, got %d. Body: %s", resp.StatusCode, buf.String())
	}
}

func createACL(addr, tenantID string, acl authz.ACL) {
	data, _ := json.Marshal(acl)
	resp, err := http.Post("http://localhost"+addr+"/tenants/"+tenantID+"/acls", "application/json", bytes.NewReader(data))
	if err != nil {
		log.Fatalf("Failed to create ACL: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("Expected 201 Created, got %d", resp.StatusCode)
	}
}

func createRole(addr, tenantID string, role authz.Role) {
	// Map to API payload
	permissions := make([]map[string]any, len(role.Permissions))
	for i, p := range role.Permissions {
		permissions[i] = map[string]any{"action": p.Action, "resource": p.Resource}
	}
	payload := map[string]any{
		"id":          role.ID,
		"name":        role.Name,
		"permissions": permissions,
	}
	data, _ := json.Marshal(payload)
	resp, err := http.Post("http://localhost"+addr+"/tenants/"+tenantID+"/roles", "application/json", bytes.NewReader(data))
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("Expected 201 Created, got %d", resp.StatusCode)
	}
}

func assignRole(addr, tenantID, subjectID, roleID string) {
	payload := map[string]string{"role_id": roleID}
	data, _ := json.Marshal(payload)
	url := fmt.Sprintf("http://localhost%s/tenants/%s/members/%s/roles", addr, tenantID, subjectID)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Fatalf("Failed to assign role: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("Expected 201 Created, got %d", resp.StatusCode)
	}
}

func verifyAccess(e *authz.Engine, tenantID, sub, act, res string, expected bool) {
	subject := &authz.Subject{ID: sub, TenantID: tenantID}
	// Need to fetch roles for subject if we want role-based access to work in Authorize call
	// The Engine's Authorize doesn't auto-fetch roles from store by default unless we implement that logic
	// or pre-populate the subject.
	// HOWEVER, Engine implementation SHOULD use RoleMembershipStore if available?
	// Checking Engine.authorizeInternal... it relies on subject.Roles being populated.
	// Wait, Engine.AssignRoleToUser persists to store, but does Authorize read it?
	// Let's check Engine.Authorize -> authorizeInternal.
	// It does NOT seem to fetch roles from RoleMembershipStore automatically.
	// Users are expected to provide roles in Subject, OR we need a middleware/method to enrich subject.
	// But let's check `ListRolesForUser`.

	// Implementation Detail: The provided `Engine` code does not automatically lookup roles from MembershipStore during Authorize.
	// So we must fetch them manually for this example validation to succeed for role-based checks.

	roles, _ := e.ListRolesForUser(context.Background(), sub)
	subject.Roles = roles

	resType := ""
	resID := res
	if idx := strings.Index(res, ":"); idx != -1 {
		resType = res[:idx]
		resID = res[idx+1:]
	}
	resource := &authz.Resource{ID: resID, Type: resType, TenantID: tenantID}
	action := authz.Action(act)
	env := &authz.Environment{Time: time.Now(), TenantID: tenantID}

	decision, err := e.Authorize(context.Background(), subject, action, resource, env)
	if err != nil {
		log.Fatalf("Authorize error: %v", err)
	}

	if decision.Allowed != expected {
		log.Fatalf("Validation failed for %s %s %s: expected %v, got %v (reason: %s)", sub, act, res, expected, decision.Allowed, decision.Reason)
	}
	log.Printf("CHECK: %s can %s %s? %v (Reason: %s)", sub, act, res, decision.Allowed, decision.Reason)
}
