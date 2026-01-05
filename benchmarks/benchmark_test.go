package benchmark

import (
	"context"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	authz "github.com/oarkflow/authz"
	"github.com/oarkflow/authz/logger"
	"github.com/oarkflow/authz/stores"
)

// NoOpAuditStore implements AuditStore but does nothing
type NoOpAuditStore struct{}

func (s *NoOpAuditStore) LogDecision(ctx context.Context, entry *authz.AuditEntry) error {
	return nil
}

func (s *NoOpAuditStore) GetAccessLog(ctx context.Context, filter authz.AuditFilter) ([]*authz.AuditEntry, error) {
	return nil, nil
}

func BenchmarkAuthzAuthorize(b *testing.B) {
	// Setup authz engine
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := &NoOpAuditStore{}
	rmStore := stores.NewMemoryRoleMembershipStore()

	eng := authz.NewEngine(
		policyStore,
		roleStore,
		aclStore,
		auditStore,
		authz.WithRoleMembershipStore(rmStore),
		authz.WithLogger(logger.NewNullLogger()),
	)

	// Add ACL for alice to read book
	acl := &authz.ACL{
		ID:         "acl1",
		ResourceID: "book",
		SubjectID:  "alice",
		Actions:    []authz.Action{"read"},
		Effect:     authz.EffectAllow,
	}
	_ = aclStore.GrantACL(context.Background(), acl)

	subject := &authz.Subject{
		ID:       "alice",
		Type:     "user",
		TenantID: "",
	}
	resource := &authz.Resource{
		ID:       "book",
		Type:     "book",
		TenantID: "",
	}
	action := authz.Action("read")
	env := &authz.Environment{}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = eng.Authorize(context.Background(), subject, action, resource, env)
	}
}

func BenchmarkAuthzRBAC(b *testing.B) {
	// Setup authz engine with RBAC
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := &NoOpAuditStore{}
	rmStore := stores.NewMemoryRoleMembershipStore()

	eng := authz.NewEngine(
		policyStore,
		roleStore,
		aclStore,
		auditStore,
		authz.WithRoleMembershipStore(rmStore),
		authz.WithLogger(logger.NewNullLogger()),
	)

	// Create role
	role := &authz.Role{
		ID:   "reader",
		Name: "Reader",
		Permissions: []authz.Permission{
			{Action: "read", Resource: "book"},
		},
	}
	_ = eng.CreateRole(context.Background(), role)

	// Assign role to user
	_ = eng.AssignRoleToUser(context.Background(), "alice", "reader")

	subject := &authz.Subject{
		ID:    "alice",
		Type:  "user",
		Roles: []string{"reader"},
	}
	resource := &authz.Resource{
		ID:   "book1",
		Type: "book",
	}
	action := authz.Action("read")
	env := &authz.Environment{}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = eng.Authorize(context.Background(), subject, action, resource, env)
	}
}

func BenchmarkCasbinRBAC(b *testing.B) {
	// Setup Casbin with RBAC
	modelText := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

	m, _ := model.NewModelFromString(modelText)
	e, _ := casbin.NewEnforcer(m)
	_, _ = e.AddPolicy("reader", "book", "read")
	_, _ = e.AddGroupingPolicy("alice", "reader")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("alice", "book", "read")
	}
}
