package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func main() {
	// Example 1: Build configuration programmatically
	buildConfigExample()

	// Example 2: Load from YAML file
	loadYAMLExample()

	// Example 3: Binary protocol for high performance
	binaryProtocolExample()

	// Example 4: Complete engine setup from config
	completeEngineExample()
}

func buildConfigExample() {
	fmt.Println("=== Building Configuration Programmatically ===")

	cfg := authz.NewConfigBuilder().
		Version(1).
		AddTenant("acme", "ACME Corporation", "").
		AddTenant("engineering", "Engineering Department", "acme").
		AddPolicy(
			authz.NewPolicyConfig("allow-engineers-read", "acme").
				Effect(authz.EffectAllow).
				Actions("read", "list").
				Resources("document:*", "file:*").
				Condition(
					authz.NewCondition().
						Eq("subject.attrs.department", "engineering").
						Build(),
				).
				Priority(10).
				Build(),
		).
		AddRole(
			authz.NewRoleConfig("admin", "acme", "Administrator").
				AddPermission("*", "*").
				Build(),
		).
		AddRole(
			authz.NewRoleConfig("document-owner", "acme", "Document Owner").
				OwnerActions("read", "write", "delete", "share").
				AddPermission("read", "document:*").
				Build(),
		).
		AddACL(
			authz.NewACLConfig("temp-access", "document:secret-123", "user:bob").
				Actions("read").
				Effect(authz.EffectAllow).
				ExpiresAt(time.Now().Add(24 * time.Hour)).
				Build(),
		).
		AddMembership("user:alice", "admin").
		AddMembership("user:bob", "document-owner").
		EngineSettings(func(e *authz.EngineConfig) {
			e.DecisionCacheTTL = 5000
			e.AttributeCacheTTL = 10000
			e.AuditBatchSize = 128
			e.RistrettoNumCounter = 1 << 16
			e.RistrettoMaxCost = 1 << 22
		}).
		Build()

	// Export to YAML
	yamlData, err := cfg.ToYAML()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated YAML config (%d bytes):\n%s\n\n", len(yamlData), string(yamlData))
}

func loadYAMLExample() {
	fmt.Println("=== Loading Configuration from YAML ===")

	yamlConfig := `
version: 1
tenants:
  - id: company1
    name: Company 1
    parent: ""
policies:
  - id: allow-read-all
    tenant_id: company1
    effect: allow
    actions: [read]
    resources: ["*"]
    condition:
      op: eq
      field: subject.type
      value: user
    priority: 1
    enabled: true
roles:
  - id: viewer
    tenant_id: company1
    name: Viewer
    permissions:
      - action: read
        resource: "*"
engine:
  decision_cache_ttl_ms: 3000
  audit_batch_size: 64
`

	loader := authz.NewConfigLoader()
	cfg, err := loader.LoadYAML([]byte(yamlConfig))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Loaded config version: %d\n", cfg.Version)
	fmt.Printf("Tenants: %d\n", len(cfg.Tenants))
	fmt.Printf("Policies: %d\n", len(cfg.Policies))
	fmt.Printf("Roles: %d\n", len(cfg.Roles))
	fmt.Println()
}

func binaryProtocolExample() {
	fmt.Println("=== Binary Protocol Performance ===")

	// Create a large configuration
	cfg := authz.NewConfigBuilder().Version(1)

	// Add 100 policies
	for i := 0; i < 100; i++ {
		cfg.AddPolicy(
			authz.NewPolicyConfig(fmt.Sprintf("policy-%d", i), "tenant1").
				Actions("read", "write").
				Resources(fmt.Sprintf("resource:%d:*", i)).
				Condition(&authz.TrueExpr{}).
				Build(),
		)
	}

	// Add 50 roles
	for i := 0; i < 50; i++ {
		cfg.AddRole(
			authz.NewRoleConfig(fmt.Sprintf("role-%d", i), "tenant1", fmt.Sprintf("Role %d", i)).
				AddPermission("read", "*").
				Build(),
		)
	}

	config := cfg.Build()

	// Measure YAML encoding
	start := time.Now()
	yamlData, _ := config.ToYAML()
	yamlTime := time.Since(start)

	// Measure JSON encoding
	start = time.Now()
	jsonData, _ := config.ToJSON()
	jsonTime := time.Since(start)

	// Measure binary encoding
	start = time.Now()
	binaryData, _ := authz.EncodeBinaryConfig(config)
	binaryTime := time.Since(start)

	fmt.Printf("YAML:   %d bytes, encoded in %v\n", len(yamlData), yamlTime)
	fmt.Printf("JSON:   %d bytes, encoded in %v\n", len(jsonData), jsonTime)
	fmt.Printf("Binary: %d bytes, encoded in %v\n", len(binaryData), binaryTime)
	fmt.Printf("Binary is %.1f%% smaller than YAML\n", (1-float64(len(binaryData))/float64(len(yamlData)))*100)
	fmt.Printf("Binary is %.2fx faster than YAML\n", float64(yamlTime)/float64(binaryTime))
	fmt.Println()
}

func completeEngineExample() {
	fmt.Println("=== Complete Engine Setup from Config ===")

	// Create stores
	policyStore := stores.NewMemoryPolicyStore()
	roleStore := stores.NewMemoryRoleStore()
	aclStore := stores.NewMemoryACLStore()
	auditStore := stores.NewMemoryAuditStore()
	membershipStore := stores.NewMemoryRoleMembershipStore()

	// Create engine
	engine := authz.NewEngine(
		policyStore,
		roleStore,
		aclStore,
		auditStore,
		authz.WithRoleMembershipStore(membershipStore),
	)

	// Build comprehensive configuration
	cfg := authz.NewConfigBuilder().
		AddTenant("org", "Organization", "").
		AddPolicy(
			authz.NewPolicyConfig("allow-document-access", "org").
				Actions("read", "write").
				Resources("document:*").
				Condition(
					authz.NewCondition().
						In("subject.roles", "editor", "admin").
						Build(),
				).
				Priority(10).
				Build(),
		).
		AddRole(
			authz.NewRoleConfig("editor", "org", "Editor").
				AddPermission("read", "document:*").
				AddPermission("write", "document:*").
				Build(),
		).
		AddRole(
			authz.NewRoleConfig("admin", "org", "Admin").
				AddPermission("*", "*").
				Build(),
		).
		AddMembership("user:alice", "admin").
		AddMembership("user:bob", "editor").
		EngineSettings(func(e *authz.EngineConfig) {
			e.DecisionCacheTTL = 5000
			e.AuditBatchSize = 100
		}).
		Build()

	// Apply configuration to engine
	ctx := context.Background()
	if err := engine.ApplyConfig(ctx, cfg); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Configuration applied successfully!")

	// Test authorization
	testAuthorization(ctx, engine)
}

func testAuthorization(ctx context.Context, engine *authz.Engine) {
	fmt.Println("\n--- Testing Authorization ---")

	// Test 1: Admin user
	alice := &authz.Subject{
		ID:       "user:alice",
		Type:     "user",
		TenantID: "org",
		Roles:    []string{"admin"},
	}

	doc := &authz.Resource{
		ID:       "doc-123",
		Type:     "document",
		TenantID: "org",
	}

	env := &authz.Environment{
		Time:     time.Now(),
		TenantID: "org",
	}

	decision, err := engine.Authorize(ctx, alice, "write", doc, env)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Alice (admin) write document: %v (reason: %s)\n", decision.Allowed, decision.Reason)

	// Test 2: Editor user
	bob := &authz.Subject{
		ID:       "user:bob",
		Type:     "user",
		TenantID: "org",
		Roles:    []string{"editor"},
	}

	decision, err = engine.Authorize(ctx, bob, "write", doc, env)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bob (editor) write document: %v (reason: %s)\n", decision.Allowed, decision.Reason)

	// Test 3: Unauthorized action
	decision, err = engine.Authorize(ctx, bob, "delete", doc, env)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bob (editor) delete document: %v (reason: %s)\n", decision.Allowed, decision.Reason)
}

// Example: Load config from file
func loadConfigFromFile(filename string) (*authz.Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	loader := authz.NewConfigLoader()

	// Detect format by extension
	switch {
	case len(filename) > 5 && filename[len(filename)-5:] == ".yaml":
		return loader.LoadYAML(data)
	case len(filename) > 4 && filename[len(filename)-4:] == ".yml":
		return loader.LoadYAML(data)
	case len(filename) > 5 && filename[len(filename)-5:] == ".json":
		return loader.LoadJSON(data)
	case len(filename) > 4 && filename[len(filename)-4:] == ".bin":
		return loader.LoadBinary(data)
	default:
		return nil, fmt.Errorf("unsupported file format")
	}
}
