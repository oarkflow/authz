package authz_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func TestDSLParser(t *testing.T) {
	dsl := `
# Test configuration
tenant org1 "Organization 1"
tenant team1 "Team 1" parent:"org1:dept1"
tenant team2 "Team 2" parent:'org1:dept2'
tenant team3 "Team 3" parent:` + "`" + `org1:dept3` + "`" + `

policy p1 org1 allow read document:* subject.type=user priority:10
policy p2 org1 deny delete document:* subject.roles@guest priority:20

role admin org1 Admin *:*
role viewer org1 Viewer read:*

acl acl1 document:123 user:alice read,write allow

member user:alice admin
member user:bob viewer

engine cache_ttl=5000 batch_size=100
`

	parser := authz.NewDSLParser()
	cfg, err := parser.Parse([]byte(dsl))
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Tenants) != 4 {
		t.Errorf("expected 4 tenants, got %d", len(cfg.Tenants))
	}
	if len(cfg.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(cfg.Policies))
	}
	if len(cfg.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(cfg.Roles))
	}
	if len(cfg.ACLs) != 1 {
		t.Errorf("expected 1 ACL, got %d", len(cfg.ACLs))
	}
	if len(cfg.Memberships) != 2 {
		t.Errorf("expected 2 memberships, got %d", len(cfg.Memberships))
	}
	if cfg.Hierarchy["team1"] != "org1:dept1" {
		t.Errorf("expected hierarchy team1=org1:dept1, got %s", cfg.Hierarchy["team1"])
	}
	if cfg.Hierarchy["team2"] != "org1:dept2" {
		t.Errorf("expected hierarchy team2=org1:dept2, got %s", cfg.Hierarchy["team2"])
	}
	if cfg.Hierarchy["team3"] != "org1:dept3" {
		t.Errorf("expected hierarchy team3=org1:dept3, got %s", cfg.Hierarchy["team3"])
	}
	if cfg.Engine.DecisionCacheTTL != 5000 {
		t.Errorf("expected cache_ttl=5000, got %d", cfg.Engine.DecisionCacheTTL)
	}
}

func TestBinaryProtocol(t *testing.T) {
	cfg := &authz.Config{
		Version: 1,
		Tenants: []authz.TenantConfig{
			{ID: "org1", Name: "Org 1", Parent: ""},
		},
		Policies: []*authz.Policy{
			{
				ID:        "p1",
				TenantID:  "org1",
				Effect:    authz.EffectAllow,
				Actions:   []authz.Action{"read"},
				Resources: []string{"*"},
				Condition: &authz.TrueExpr{},
				Priority:  10,
				Enabled:   true,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
		Roles: []*authz.Role{
			{
				ID:          "admin",
				TenantID:    "org1",
				Name:        "Admin",
				Permissions: []authz.Permission{{Action: "*", Resource: "*"}},
				CreatedAt:   time.Now(),
			},
		},
		ACLs:        []*authz.ACL{},
		Memberships: []authz.RoleMembership{{SubjectID: "user:1", RoleID: "admin"}},
		Hierarchy:   map[string]string{},
		Engine:      authz.EngineConfig{DecisionCacheTTL: 1000, AuditBatchSize: 64},
	}

	encoder := authz.NewBinaryEncoder()
	data, err := encoder.Encode(cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Binary size: %d bytes", len(data))

	decoder := authz.NewBinaryDecoder(data)
	decoded, err := decoder.Decode()
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Version != cfg.Version {
		t.Errorf("version mismatch")
	}
	if len(decoded.Tenants) != len(cfg.Tenants) {
		t.Errorf("tenant count mismatch")
	}
	if len(decoded.Policies) != len(cfg.Policies) {
		t.Errorf("policy count mismatch")
	}
	if len(decoded.Roles) != len(cfg.Roles) {
		t.Errorf("role count mismatch")
	}
}

func TestDSLWithEngine(t *testing.T) {
	dsl := `
tenant myapp "My Application"

policy allow-read myapp allow read document:* subject.type=user
role admin myapp Admin *:*
role viewer myapp Viewer read:*

member user:alice admin
member user:bob viewer

engine cache_ttl=3000
`

	parser := authz.NewDSLParser()
	cfg, err := parser.Parse([]byte(dsl))
	if err != nil {
		t.Fatal(err)
	}

	engine := authz.NewEngine(
		stores.NewMemoryPolicyStore(),
		stores.NewMemoryRoleStore(),
		stores.NewMemoryACLStore(),
		stores.NewMemoryAuditStore(),
		authz.WithRoleMembershipStore(stores.NewMemoryRoleMembershipStore()),
	)

	ctx := context.Background()
	if err := engine.ApplyConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	alice := &authz.Subject{ID: "user:alice", Type: "user", TenantID: "myapp", Roles: []string{"admin"}}
	doc := &authz.Resource{ID: "doc1", Type: "document", TenantID: "myapp"}
	env := &authz.Environment{Time: time.Now(), TenantID: "myapp"}

	decision, err := engine.Authorize(ctx, alice, "delete", doc, env)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Error("expected alice (admin) to be allowed")
	}

	bob := &authz.Subject{ID: "user:bob", Type: "user", TenantID: "myapp", Roles: []string{"viewer"}}
	decision, err = engine.Authorize(ctx, bob, "delete", doc, env)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Error("expected bob (viewer) to be denied")
	}
}

func TestDSLFromFile(t *testing.T) {
	data, err := os.ReadFile("examples/config.authz")
	if err != nil {
		t.Skip("config.authz not found")
	}

	parser := authz.NewDSLParser()
	cfg, err := parser.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Loaded config: %d tenants, %d policies, %d roles",
		len(cfg.Tenants), len(cfg.Policies), len(cfg.Roles))
}

func TestDenySensitivePolicy(t *testing.T) {
	dsl := `
tenant company "ACME Corp"

policy allow-users company allow read,write document:* subject.type=user priority:10
policy deny-sensitive company deny read,write,delete document:sensitive:* subject.attrs.clearance!=high priority:50

role admin company Administrator *:*
role viewer company Viewer read:*

member user:alice admin
member user:bob viewer

engine cache_ttl=3000
`

	parser := authz.NewDSLParser()
	cfg, err := parser.Parse([]byte(dsl))
	if err != nil {
		t.Fatal(err)
	}

	engine := authz.NewEngine(
		stores.NewMemoryPolicyStore(),
		stores.NewMemoryRoleStore(),
		stores.NewMemoryACLStore(),
		stores.NewMemoryAuditStore(),
		authz.WithRoleMembershipStore(stores.NewMemoryRoleMembershipStore()),
	)

	ctx := context.Background()
	if err := engine.ApplyConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	sensitiveDoc := &authz.Resource{
		ID:       "doc-sensitive",
		Type:     "document:sensitive",
		TenantID: "company",
	}

	env := &authz.Environment{Time: time.Now(), TenantID: "company"}

	tests := []struct {
		name     string
		subject  *authz.Subject
		action   authz.Action
		expected bool
	}{
		{
			name:     "high-clearance",
			subject:  &authz.Subject{ID: "user:alice", Type: "user", TenantID: "company", Roles: []string{"admin"}, Attrs: map[string]any{"clearance": "high"}},
			action:   authz.Action("read"),
			expected: true,
		},
		{
			name:     "low-clearance",
			subject:  &authz.Subject{ID: "user:bob", Type: "user", TenantID: "company", Roles: []string{"viewer"}, Attrs: map[string]any{"clearance": "low"}},
			action:   authz.Action("read"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Authorize(ctx, tt.subject, tt.action, sensitiveDoc, env)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed != tt.expected {
				t.Fatalf("expected allowed=%t for %s, got %t (reason=%s)", tt.expected, tt.name, decision.Allowed, decision.Reason)
			}
		})
	}
}

func ExampleDSLParser() {
	dsl := `
tenant myapp "My App"
policy allow-read myapp allow read * subject.type=user
role admin myapp Admin *:*
member user:alice admin
engine cache_ttl=5000
`

	parser := authz.NewDSLParser()
	cfg, err := parser.Parse([]byte(dsl))
	if err != nil {
		panic(err)
	}

	fmt.Println("Tenants:", len(cfg.Tenants))
	fmt.Println("Policies:", len(cfg.Policies))
	// Output:
	// Tenants: 1
	// Policies: 1
}
