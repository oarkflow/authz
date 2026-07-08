package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/pkg/stores"
)

func mai3n() {
	// Example 1: Build configuration programmatically
	buildConfigExample()

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
		}).
		Build()

	// Export to JSON
	jsonData, err := cfg.ToJSON()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated JSON config (%d bytes):\n%s\n\n", len(jsonData), string(jsonData))
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
	// Measure JSON encoding
	start = time.Now()
	jsonData, _ := config.ToJSON()
	jsonTime := time.Since(start)

	// Measure binary encoding
	start = time.Now()
	binaryData, _ := authz.EncodeBinaryConfig(config)
	binaryTime := time.Since(start)

	fmt.Printf("JSON:   %d bytes, encoded in %v\n", len(jsonData), jsonTime)
	fmt.Printf("Binary: %d bytes, encoded in %v\n", len(binaryData), binaryTime)
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
	case len(filename) > 5 && filename[len(filename)-5:] == ".json":
		return loader.LoadJSON(data)
	case len(filename) > 4 && filename[len(filename)-4:] == ".bin":
		return loader.LoadBinary(data)
	default:
		return nil, fmt.Errorf("unsupported file format")
	}
}
