package stores

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/authz"
)

// ConformanceTestSuite provides a reusable test suite that can be run against
// any store implementation (memory or SQL) to ensure consistent behavior.
type ConformanceTestSuite struct {
	PolicyStore         authz.PolicyStore
	RoleStore           authz.RoleStore
	ACLStore            authz.ACLStore
	AuditStore          authz.AuditStore
	RoleMembershipStore authz.RoleMembershipStore
	TenantStore         authz.TenantStore
	Cleanup             func()
}

// NewMemoryTestSuite creates a test suite using memory stores.
func NewMemoryTestSuite() *ConformanceTestSuite {
	return &ConformanceTestSuite{
		PolicyStore:         NewMemoryPolicyStore(),
		RoleStore:           NewMemoryRoleStore(),
		ACLStore:            NewMemoryACLStore(),
		AuditStore:          NewMemoryAuditStore(),
		RoleMembershipStore: NewMemoryRoleMembershipStore(),
		TenantStore:         NewMemoryTenantStore(),
		Cleanup:             func() {},
	}
}

// RunAllTests runs all conformance tests against the test suite.
func (s *ConformanceTestSuite) RunAllTests(t *testing.T) {
	t.Run("PolicyStore", s.TestPolicyStore)
	t.Run("RoleStore", s.TestRoleStore)
	t.Run("ACLStore", s.TestACLStore)
	t.Run("AuditStore", s.TestAuditStore)
	t.Run("RoleMembershipStore", s.TestRoleMembershipStore)
	t.Run("TenantStore", s.TestTenantStore)
}

// TestPolicyStore tests policy store operations.
func (s *ConformanceTestSuite) TestPolicyStore(t *testing.T) {
	if s.PolicyStore == nil {
		t.Skip("PolicyStore not configured")
	}

	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		policy := &authz.Policy{
			ID:        "test-policy-1",
			TenantID:  "tenant-1",
			Effect:    authz.EffectAllow,
			Actions:   []authz.Action{"read", "write"},
			Resources: []string{"document:*"},
			Priority:  10,
			Enabled:   true,
		}

		err := s.PolicyStore.CreatePolicy(ctx, policy)
		if err != nil {
			t.Fatalf("CreatePolicy failed: %v", err)
		}

		got, err := s.PolicyStore.GetPolicy(ctx, "test-policy-1")
		if err != nil {
			t.Fatalf("GetPolicy failed: %v", err)
		}

		if got.ID != policy.ID {
			t.Errorf("ID mismatch: got %s, want %s", got.ID, policy.ID)
		}
		if got.TenantID != policy.TenantID {
			t.Errorf("TenantID mismatch: got %s, want %s", got.TenantID, policy.TenantID)
		}
		if got.Effect != policy.Effect {
			t.Errorf("Effect mismatch: got %s, want %s", got.Effect, policy.Effect)
		}
		if len(got.Actions) != len(policy.Actions) {
			t.Errorf("Actions length mismatch: got %d, want %d", len(got.Actions), len(policy.Actions))
		}
	})

	t.Run("Update", func(t *testing.T) {
		policy := &authz.Policy{
			ID:        "test-policy-2",
			TenantID:  "tenant-1",
			Effect:    authz.EffectAllow,
			Actions:   []authz.Action{"read"},
			Resources: []string{"file:*"},
			Priority:  5,
			Enabled:   true,
		}

		err := s.PolicyStore.CreatePolicy(ctx, policy)
		if err != nil {
			t.Fatalf("CreatePolicy failed: %v", err)
		}

		policy.Priority = 20
		policy.Actions = []authz.Action{"read", "write", "delete"}

		err = s.PolicyStore.UpdatePolicy(ctx, policy)
		if err != nil {
			t.Fatalf("UpdatePolicy failed: %v", err)
		}

		got, err := s.PolicyStore.GetPolicy(ctx, "test-policy-2")
		if err != nil {
			t.Fatalf("GetPolicy failed: %v", err)
		}

		if got.Priority != 20 {
			t.Errorf("Priority mismatch: got %d, want 20", got.Priority)
		}
		if len(got.Actions) != 3 {
			t.Errorf("Actions length mismatch: got %d, want 3", len(got.Actions))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		policy := &authz.Policy{
			ID:       "test-policy-3",
			TenantID: "tenant-1",
			Effect:   authz.EffectDeny,
			Actions:  []authz.Action{"delete"},
			Enabled:  true,
		}

		err := s.PolicyStore.CreatePolicy(ctx, policy)
		if err != nil {
			t.Fatalf("CreatePolicy failed: %v", err)
		}

		err = s.PolicyStore.DeletePolicy(ctx, "test-policy-3")
		if err != nil {
			t.Fatalf("DeletePolicy failed: %v", err)
		}

		_, err = s.PolicyStore.GetPolicy(ctx, "test-policy-3")
		if err == nil {
			t.Error("Expected error when getting deleted policy")
		}
	})

	t.Run("ListByTenant", func(t *testing.T) {
		// Create policies for different tenants
		p1 := &authz.Policy{ID: "list-p1", TenantID: "list-tenant-1", Effect: authz.EffectAllow, Enabled: true}
		p2 := &authz.Policy{ID: "list-p2", TenantID: "list-tenant-1", Effect: authz.EffectAllow, Enabled: true}
		p3 := &authz.Policy{ID: "list-p3", TenantID: "list-tenant-2", Effect: authz.EffectAllow, Enabled: true}

		_ = s.PolicyStore.CreatePolicy(ctx, p1)
		_ = s.PolicyStore.CreatePolicy(ctx, p2)
		_ = s.PolicyStore.CreatePolicy(ctx, p3)

		policies, err := s.PolicyStore.ListPolicies(ctx, "list-tenant-1")
		if err != nil {
			t.Fatalf("ListPolicies failed: %v", err)
		}

		count := 0
		for _, p := range policies {
			if p.TenantID == "list-tenant-1" {
				count++
			}
		}
		if count < 2 {
			t.Errorf("Expected at least 2 policies for list-tenant-1, got %d", count)
		}
	})
}

// TestRoleStore tests role store operations.
func (s *ConformanceTestSuite) TestRoleStore(t *testing.T) {
	if s.RoleStore == nil {
		t.Skip("RoleStore not configured")
	}

	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		role := &authz.Role{
			ID:       "test-role-1",
			TenantID: "tenant-1",
			Name:     "Admin",
			Permissions: []authz.Permission{
				{Action: "read", Resource: "document:*"},
				{Action: "write", Resource: "document:*"},
			},
		}

		err := s.RoleStore.CreateRole(ctx, role)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}

		got, err := s.RoleStore.GetRole(ctx, "test-role-1")
		if err != nil {
			t.Fatalf("GetRole failed: %v", err)
		}

		if got.ID != role.ID {
			t.Errorf("ID mismatch: got %s, want %s", got.ID, role.ID)
		}
		if got.Name != role.Name {
			t.Errorf("Name mismatch: got %s, want %s", got.Name, role.Name)
		}
		if len(got.Permissions) != len(role.Permissions) {
			t.Errorf("Permissions length mismatch: got %d, want %d", len(got.Permissions), len(role.Permissions))
		}
	})

	t.Run("Inheritance", func(t *testing.T) {
		parentRole := &authz.Role{
			ID:       "parent-role",
			TenantID: "tenant-1",
			Name:     "Parent",
			Permissions: []authz.Permission{
				{Action: "read", Resource: "file:*"},
			},
		}

		childRole := &authz.Role{
			ID:       "child-role",
			TenantID: "tenant-1",
			Name:     "Child",
			Inherits: []string{"parent-role"},
			Permissions: []authz.Permission{
				{Action: "write", Resource: "file:*"},
			},
		}

		_ = s.RoleStore.CreateRole(ctx, parentRole)
		err := s.RoleStore.CreateRole(ctx, childRole)
		if err != nil {
			t.Fatalf("CreateRole for child failed: %v", err)
		}

		got, err := s.RoleStore.GetRole(ctx, "child-role")
		if err != nil {
			t.Fatalf("GetRole failed: %v", err)
		}

		if len(got.Inherits) != 1 || got.Inherits[0] != "parent-role" {
			t.Errorf("Inherits mismatch: got %v, want [parent-role]", got.Inherits)
		}
	})

	t.Run("Update", func(t *testing.T) {
		role := &authz.Role{
			ID:       "test-role-2",
			TenantID: "tenant-1",
			Name:     "Viewer",
		}

		err := s.RoleStore.CreateRole(ctx, role)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}

		role.Name = "Super Viewer"
		role.Permissions = []authz.Permission{{Action: "view", Resource: "*"}}

		err = s.RoleStore.UpdateRole(ctx, role)
		if err != nil {
			t.Fatalf("UpdateRole failed: %v", err)
		}

		got, err := s.RoleStore.GetRole(ctx, "test-role-2")
		if err != nil {
			t.Fatalf("GetRole failed: %v", err)
		}

		if got.Name != "Super Viewer" {
			t.Errorf("Name mismatch: got %s, want Super Viewer", got.Name)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		role := &authz.Role{ID: "test-role-3", TenantID: "tenant-1", Name: "Temp"}

		err := s.RoleStore.CreateRole(ctx, role)
		if err != nil {
			t.Fatalf("CreateRole failed: %v", err)
		}

		err = s.RoleStore.DeleteRole(ctx, "test-role-3")
		if err != nil {
			t.Fatalf("DeleteRole failed: %v", err)
		}

		_, err = s.RoleStore.GetRole(ctx, "test-role-3")
		if err == nil {
			t.Error("Expected error when getting deleted role")
		}
	})
}

// TestACLStore tests ACL store operations.
func (s *ConformanceTestSuite) TestACLStore(t *testing.T) {
	if s.ACLStore == nil {
		t.Skip("ACLStore not configured")
	}

	ctx := context.Background()

	t.Run("GrantAndGet", func(t *testing.T) {
		acl := &authz.ACL{
			ID:         "test-acl-1",
			TenantID:   "tenant-1",
			SubjectID:  "user-1",
			ResourceID: "document:123",
			Actions:    []authz.Action{"read", "write"},
			Effect:     authz.EffectAllow,
		}

		err := s.ACLStore.GrantACL(ctx, acl)
		if err != nil {
			t.Fatalf("GrantACL failed: %v", err)
		}

		got, err := s.ACLStore.GetACL(ctx, "test-acl-1")
		if err != nil {
			t.Fatalf("GetACL failed: %v", err)
		}

		if got.ID != acl.ID {
			t.Errorf("ID mismatch: got %s, want %s", got.ID, acl.ID)
		}
		if got.SubjectID != acl.SubjectID {
			t.Errorf("SubjectID mismatch: got %s, want %s", got.SubjectID, acl.SubjectID)
		}
	})

	t.Run("ListByResource", func(t *testing.T) {
		acl1 := &authz.ACL{ID: "res-acl-1", SubjectID: "user-1", ResourceID: "file:abc", Actions: []authz.Action{"read"}, Effect: authz.EffectAllow}
		acl2 := &authz.ACL{ID: "res-acl-2", SubjectID: "user-2", ResourceID: "file:abc", Actions: []authz.Action{"write"}, Effect: authz.EffectAllow}

		_ = s.ACLStore.GrantACL(ctx, acl1)
		_ = s.ACLStore.GrantACL(ctx, acl2)

		// Allow background snapshot to update
		time.Sleep(50 * time.Millisecond)

		acls, err := s.ACLStore.ListACLsByResource(ctx, "file:abc")
		if err != nil {
			t.Fatalf("ListACLsByResource failed: %v", err)
		}

		if len(acls) < 2 {
			t.Errorf("Expected at least 2 ACLs for file:abc, got %d", len(acls))
		}
	})

	t.Run("ListBySubject", func(t *testing.T) {
		acl := &authz.ACL{ID: "subj-acl-1", SubjectID: "special-user", ResourceID: "doc:xyz", Actions: []authz.Action{"read"}, Effect: authz.EffectAllow}
		_ = s.ACLStore.GrantACL(ctx, acl)

		// Allow background snapshot to update
		time.Sleep(50 * time.Millisecond)

		acls, err := s.ACLStore.ListACLsBySubject(ctx, "special-user")
		if err != nil {
			t.Fatalf("ListACLsBySubject failed: %v", err)
		}

		found := false
		for _, a := range acls {
			if a.ID == "subj-acl-1" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to find subj-acl-1 in subject's ACLs")
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		acl := &authz.ACL{ID: "test-acl-2", SubjectID: "user-1", ResourceID: "temp", Effect: authz.EffectAllow}

		err := s.ACLStore.GrantACL(ctx, acl)
		if err != nil {
			t.Fatalf("GrantACL failed: %v", err)
		}

		err = s.ACLStore.RevokeACL(ctx, "test-acl-2")
		if err != nil {
			t.Fatalf("RevokeACL failed: %v", err)
		}

		_, err = s.ACLStore.GetACL(ctx, "test-acl-2")
		if err == nil {
			t.Error("Expected error when getting revoked ACL")
		}
	})

	t.Run("Expiration", func(t *testing.T) {
		expiredACL := &authz.ACL{
			ID:         "expired-acl",
			SubjectID:  "user-1",
			ResourceID: "temp-resource",
			Actions:    []authz.Action{"read"},
			Effect:     authz.EffectAllow,
			ExpiresAt:  time.Now().Add(-1 * time.Hour), // Already expired
		}

		err := s.ACLStore.GrantACL(ctx, expiredACL)
		if err != nil {
			t.Fatalf("GrantACL failed: %v", err)
		}

		// Wait for snapshot rebuild
		time.Sleep(300 * time.Millisecond)

		acls, err := s.ACLStore.ListACLs(ctx, "")
		if err != nil {
			t.Fatalf("ListACLs failed: %v", err)
		}

		for _, a := range acls {
			if a.ID == "expired-acl" {
				t.Error("Expired ACL should not be returned in list")
			}
		}
	})
}

// TestAuditStore tests audit store operations.
func (s *ConformanceTestSuite) TestAuditStore(t *testing.T) {
	if s.AuditStore == nil {
		t.Skip("AuditStore not configured")
	}

	ctx := context.Background()

	t.Run("LogAndRetrieve", func(t *testing.T) {
		entry := &authz.AuditEntry{
			ID:        "audit-1",
			Timestamp: time.Now(),
			Subject: &authz.Subject{
				ID:       "user-1",
				TenantID: "tenant-1",
			},
			Action: "read",
			Resource: &authz.Resource{
				ID:       "document:123",
				TenantID: "tenant-1",
			},
			Decision: &authz.Decision{
				Allowed: true,
				Reason:  "policy match",
			},
		}

		err := s.AuditStore.LogDecision(ctx, entry)
		if err != nil {
			t.Fatalf("LogDecision failed: %v", err)
		}

		filter := authz.AuditFilter{
			SubjectID: "user-1",
		}

		entries, err := s.AuditStore.GetAccessLog(ctx, filter)
		if err != nil {
			t.Fatalf("GetAccessLog failed: %v", err)
		}

		found := false
		for _, e := range entries {
			if e.Subject != nil && e.Subject.ID == "user-1" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to find logged audit entry")
		}
	})

	t.Run("FilterBySubject", func(t *testing.T) {
		entry := &authz.AuditEntry{
			ID:        "audit-2",
			Timestamp: time.Now(),
			Subject: &authz.Subject{
				ID:       "filter-user",
				TenantID: "tenant-1",
			},
			Action: "write",
			Resource: &authz.Resource{
				ID:       "file:456",
				TenantID: "tenant-1",
			},
			Decision: &authz.Decision{
				Allowed: false,
				Reason:  "denied",
			},
		}

		err := s.AuditStore.LogDecision(ctx, entry)
		if err != nil {
			t.Fatalf("LogDecision failed: %v", err)
		}

		filter := authz.AuditFilter{
			SubjectID: "filter-user",
		}

		entries, err := s.AuditStore.GetAccessLog(ctx, filter)
		if err != nil {
			t.Fatalf("GetAccessLog failed: %v", err)
		}

		for _, e := range entries {
			if e.Subject == nil || e.Subject.ID != "filter-user" {
				t.Errorf("Expected only entries for filter-user, got %v", e.Subject)
			}
		}
	})
}

// TestRoleMembershipStore tests role membership operations.
func (s *ConformanceTestSuite) TestRoleMembershipStore(t *testing.T) {
	if s.RoleMembershipStore == nil {
		t.Skip("RoleMembershipStore not configured")
	}

	ctx := context.Background()

	t.Run("AssignAndList", func(t *testing.T) {
		err := s.RoleMembershipStore.AssignRole(ctx, "member-user-1", "admin-role")
		if err != nil {
			t.Fatalf("AssignRole failed: %v", err)
		}

		err = s.RoleMembershipStore.AssignRole(ctx, "member-user-1", "viewer-role")
		if err != nil {
			t.Fatalf("AssignRole failed: %v", err)
		}

		// Allow time for async snapshot updates
		time.Sleep(10 * time.Millisecond)

		roles, err := s.RoleMembershipStore.ListRoles(ctx, "member-user-1")
		if err != nil {
			t.Fatalf("ListRoles failed: %v", err)
		}

		if len(roles) < 2 {
			t.Errorf("Expected at least 2 roles, got %d", len(roles))
		}
	})

	t.Run("Unassign", func(t *testing.T) {
		_ = s.RoleMembershipStore.AssignRole(ctx, "member-user-2", "temp-role")

		err := s.RoleMembershipStore.RevokeRole(ctx, "member-user-2", "temp-role")
		if err != nil {
			t.Fatalf("RevokeRole failed: %v", err)
		}

		// Allow time for snapshot to rebuild
		time.Sleep(10 * time.Millisecond)

		roles, err := s.RoleMembershipStore.ListRoles(ctx, "member-user-2")
		if err != nil {
			t.Fatalf("ListRoles failed: %v", err)
		}

		for _, r := range roles {
			if r == "temp-role" {
				t.Error("temp-role should have been unassigned")
			}
		}
	})
}

// TestTenantStore tests tenant store operations.
func (s *ConformanceTestSuite) TestTenantStore(t *testing.T) {
	if s.TenantStore == nil {
		t.Skip("TenantStore not configured")
	}

	ctx := context.Background()

	t.Run("CreateAndGet", func(t *testing.T) {
		tenant := &authz.Tenant{
			ID:   "test-tenant-1",
			Name: "Test Tenant",
		}

		err := s.TenantStore.CreateTenant(ctx, tenant)
		if err != nil {
			t.Fatalf("CreateTenant failed: %v", err)
		}

		got, err := s.TenantStore.GetTenant(ctx, "test-tenant-1")
		if err != nil {
			t.Fatalf("GetTenant failed: %v", err)
		}

		if got.ID != tenant.ID {
			t.Errorf("ID mismatch: got %s, want %s", got.ID, tenant.ID)
		}
		if got.Name != tenant.Name {
			t.Errorf("Name mismatch: got %s, want %s", got.Name, tenant.Name)
		}
	})

	t.Run("Hierarchy", func(t *testing.T) {
		parent := &authz.Tenant{ID: "parent-tenant", Name: "Parent"}
		child := &authz.Tenant{ID: "child-tenant", Name: "Child", ParentID: "parent-tenant"}

		_ = s.TenantStore.CreateTenant(ctx, parent)
		err := s.TenantStore.CreateTenant(ctx, child)
		if err != nil {
			t.Fatalf("CreateTenant for child failed: %v", err)
		}

		got, err := s.TenantStore.GetTenant(ctx, "child-tenant")
		if err != nil {
			t.Fatalf("GetTenant failed: %v", err)
		}

		if got.ParentID != "parent-tenant" {
			t.Errorf("ParentID mismatch: got %s, want parent-tenant", got.ParentID)
		}
	})
}

// TestMemoryStoresConformance runs conformance tests against memory stores.
func TestMemoryStoresConformance(t *testing.T) {
	suite := NewMemoryTestSuite()
	defer suite.Cleanup()
	suite.RunAllTests(t)
}


