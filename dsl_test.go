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

func TestDSLHTTPRoutePermissions(t *testing.T) {
	dsl := `
tenant org1 "Organization 1"

policy owner-route org1 allow GET route:GET:/users/* resource.owner_id=subject.id priority:60
policy admin-routes org1 allow GET,POST route:* subject.roles@admin priority:90

role route-admin org1 "Route Administrator" GET:route:GET:/admin/*,POST:route:POST:/admin/*
acl public-info route:GET:/public/info guest GET allow

member user:erin route-admin
`

	parser := authz.NewDSLParser()
	cfg, err := parser.Parse([]byte(dsl))
	if err != nil {
		t.Fatal(err)
	}

	if got := cfg.Policies[0].Resources[0]; got != "route:GET:/users/*" {
		t.Fatalf("route policy resource mismatch: got %q", got)
	}
	if got := cfg.Roles[0].Permissions[0].Resource; got != "route:GET:/admin/*" {
		t.Fatalf("route role resource mismatch: got %q", got)
	}
	if got := cfg.ACLs[0].ResourceID; got != "route:GET:/public/info" {
		t.Fatalf("route ACL resource mismatch: got %q", got)
	}
}

func TestDSLBlockSyntax(t *testing.T) {
	dsl := `
tenant org1 {
  name "Engineering Org"
}
tenant team1 {
  name "Backend Team"
  parent org1
}

policy allow-admin {
  tenant org1
  effect allow
  actions [
    read
    write
    delete
    share
  ]
  resources [
    document:*
    project:*
    route:*
  ]
  when {
    subject.roles contains any [
      admin
      superadmin
    ]
  }
  priority 100
}

policy owner-access {
  tenant org1
  effect allow
  actions [read, write, delete]
  resources [document:*]
  when {
    resource.owner_id == subject.id
  }
  priority 50
}

role editor {
  tenant org1
  name "Editor"
  permissions [
    read:document:*
    write:document:*
    delete:document:*
  ]
}

role owner {
  tenant org1
  name "Owner"
  permissions {
    read:*
  }
  owner_actions [
    read
    write
    delete
    share
  ]
}

acl acl-route-public {
  resource route:GET:/public/info
  subject guest
  actions [GET]
  effect allow
}

member user:alice {
  roles [
    editor
    owner
  ]
}

members {
  user:bob [editor]
  user:charlie [owner]
}

engine {
  cache_ttl 5000
  attr_ttl 10000
  batch_size 128
  flush_interval 50
  workers 8
}
`
	cfg, err := authz.NewDSLParser().Parse([]byte(dsl))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tenants) != 2 || cfg.Hierarchy["team1"] != "org1" {
		t.Fatalf("tenant blocks did not parse hierarchy: %#v", cfg.Tenants)
	}
	if len(cfg.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(cfg.Policies))
	}
	if got := len(cfg.Policies[0].Actions); got != 4 {
		t.Fatalf("expected 4 policy actions, got %d", got)
	}
	if _, ok := cfg.Policies[0].Condition.(*authz.InExpr); !ok {
		t.Fatalf("expected contains any condition to parse as InExpr, got %T", cfg.Policies[0].Condition)
	}
	if _, ok := cfg.Policies[1].Condition.(*authz.EqExpr); !ok {
		t.Fatalf("expected equality condition, got %T", cfg.Policies[1].Condition)
	}
	if len(cfg.Roles) != 2 || len(cfg.Roles[1].OwnerAllowedActions) != 4 {
		t.Fatalf("role blocks did not parse owner actions: %#v", cfg.Roles)
	}
	if len(cfg.ACLs) != 1 || cfg.ACLs[0].ResourceID != "route:GET:/public/info" {
		t.Fatalf("acl block did not parse route resource: %#v", cfg.ACLs)
	}
	if len(cfg.Memberships) != 4 {
		t.Fatalf("expected 4 memberships, got %d", len(cfg.Memberships))
	}
	if cfg.Engine.DecisionCacheTTL != 5000 || cfg.Engine.AttributeCacheTTL != 10000 || cfg.Engine.AuditBatchSize != 128 || cfg.Engine.AuditFlushInterval != 50 || cfg.Engine.BatchWorkerCount != 8 {
		t.Fatalf("engine block did not parse: %#v", cfg.Engine)
	}
}

func TestDSLStrictParserRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		dsl  string
	}{
		{"invalid condition", `tenant org "Org"
policy p org allow read document:* subject.type~user`},
		{"invalid effect", `tenant org "Org"
policy p org maybe read document:* true`},
		{"invalid priority", `tenant org "Org"
policy p org allow read document:* true priority:nope`},
		{"invalid expires", `tenant org "Org"
acl a document:1 user:alice read allow expires:nope`},
		{"unknown option", `tenant org "Org"
role r org Role read:* unknown:value`},
		{"malformed list", `tenant org "Org"
policy p org allow read, document:* true`},
		{"malformed permission", `tenant org "Org"
role r org Role read`},
		{"unterminated quote", `tenant org "Org`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := authz.NewDSLParser().Parse([]byte(tt.dsl))
			if err == nil {
				t.Fatal("expected strict parser error")
			}
			if got := err.Error(); got == "" || got[:4] != "line" {
				t.Fatalf("expected line-numbered error, got %q", got)
			}
		})
	}
}

func TestDSLInlineComments(t *testing.T) {
	dsl := `
tenant org "Org # quoted" # outside comment
policy p org allow read document:* true # outside comment
`
	cfg, err := authz.NewDSLParser().Parse([]byte(dsl))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tenants[0].Name != "Org # quoted" {
		t.Fatalf("quoted comment marker was not preserved: %q", cfg.Tenants[0].Name)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("expected policy to parse with inline comment, got %d", len(cfg.Policies))
	}
}

func TestDSLPermissiveParserCompatibility(t *testing.T) {
	dsl := `tenant org "Org"
policy p org maybe read document:* subject.type~user priority:nope`
	cfg, err := authz.NewPermissiveDSLParser().Parse([]byte(dsl))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("expected permissive parser to keep policy, got %d", len(cfg.Policies))
	}
	if _, ok := cfg.Policies[0].Condition.(*authz.TrueExpr); !ok {
		t.Fatalf("expected unsupported permissive condition to fall back to true")
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
