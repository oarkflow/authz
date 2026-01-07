package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
	"gopkg.in/yaml.v3"
)

func main() {
	fmt.Println("=== AuthZ Custom DSL Demo ===\n")

	// Example 1: Parse DSL
	dslExample()

	// Example 2: Binary Protocol
	binaryExample()

	// Example 3: Complete Engine Setup
	engineExample()

	// Example 4: Performance Comparison
	performanceExample()
}

func dslExample() {
	fmt.Println("1. Parsing Custom DSL")
	fmt.Println("---------------------")

	dsl := `
# Simple application config
tenant myapp "My Application"

policy allow-read myapp allow read document:* subject.type=user priority:10
policy allow-admin myapp allow * * subject.roles@admin priority:100

role admin myapp Administrator *:*
role viewer myapp Viewer read:*

member user:alice admin
member user:bob viewer

engine cache_ttl=5000 batch_size=128
`

	parser := authz.NewDSLParser()
	cfg, err := parser.Parse([]byte(dsl))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed: %d tenants, %d policies, %d roles\n",
		len(cfg.Tenants), len(cfg.Policies), len(cfg.Roles))
	fmt.Printf("Engine cache TTL: %dms\n\n", cfg.Engine.DecisionCacheTTL)
}

func binaryExample() {
	fmt.Println("2. Binary Protocol")
	fmt.Println("------------------")

	// Create config
	cfg := &authz.Config{
		Version: 1,
		Tenants: []authz.TenantConfig{
			{ID: "app1", Name: "Application 1"},
		},
		Policies: []*authz.Policy{
			{
				ID:        "p1",
				TenantID:  "app1",
				Effect:    authz.EffectAllow,
				Actions:   []authz.Action{"read", "write"},
				Resources: []string{"document:*"},
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
				TenantID:    "app1",
				Name:        "Admin",
				Permissions: []authz.Permission{{Action: "*", Resource: "*"}},
				CreatedAt:   time.Now(),
			},
		},
		ACLs:        []*authz.ACL{},
		Memberships: []authz.RoleMembership{{SubjectID: "user:1", RoleID: "admin"}},
		Hierarchy:   map[string]string{},
		Engine:      authz.EngineConfig{DecisionCacheTTL: 5000, AuditBatchSize: 128},
	}

	// Encode to binary
	encoder := authz.NewBinaryEncoder()
	binary, err := encoder.Encode(cfg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Binary size: %d bytes\n", len(binary))

	// Decode from binary
	decoder := authz.NewBinaryDecoder(binary)
	decoded, err := decoder.Decode()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decoded: %d tenants, %d policies, %d roles\n\n",
		len(decoded.Tenants), len(decoded.Policies), len(decoded.Roles))
}

func engineExample() {
	fmt.Println("3. Complete Engine Setup")
	fmt.Println("------------------------")

	dsl := `
tenant company "ACME Corp"

# ABAC Policies with attribute-based conditions
policy allow-users company allow read,write document:* subject.type=user priority:10
policy allow-admins company allow * * subject.roles@admin priority:100
policy deny-sensitive company deny read,write,delete document:sensitive:* subject.attrs.clearance!=high priority:50
policy owner-access company allow read,write,delete * resource.owner_id=subject.id priority:20

role admin company Administrator *:*
role editor company Editor read:document:*,write:document:*
role viewer company Viewer read:*

acl temp-access document:secret user:bob read allow

member user:alice admin
member user:bob editor
member user:charlie viewer

engine cache_ttl=3000 batch_size=100 workers=4
`

	// Parse DSL
	parser := authz.NewDSLParser()
	cfg, err := parser.Parse([]byte(dsl))
	if err != nil {
		log.Fatal(err)
	}

	// Create engine
	engine := authz.NewEngine(
		stores.NewMemoryPolicyStore(),
		stores.NewMemoryRoleStore(),
		stores.NewMemoryACLStore(),
		stores.NewMemoryAuditStore(),
		authz.WithRoleMembershipStore(stores.NewMemoryRoleMembershipStore()),
	)

	// Apply configuration
	ctx := context.Background()
	if err := engine.ApplyConfig(ctx, cfg); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Configuration applied successfully!")

	// Test authorization
	testAuth(ctx, engine)
}

func testAuth(ctx context.Context, engine *authz.Engine) {
	fmt.Println("\nTesting Authorization (RBAC + ABAC):")

	alice := &authz.Subject{
		ID:       "user:alice",
		Type:     "user",
		TenantID: "company",
		Roles:    []string{"admin"},
		Attrs:    map[string]any{"clearance": "high"},
	}

	bob := &authz.Subject{
		ID:       "user:bob",
		Type:     "user",
		TenantID: "company",
		Roles:    []string{"editor"},
		Attrs:    map[string]any{"clearance": "low"},
	}

	charlie := &authz.Subject{
		ID:       "user:charlie",
		Type:     "user",
		TenantID: "company",
		Roles:    []string{"viewer"},
		Attrs:    map[string]any{"clearance": "high"},
	}

	doc := &authz.Resource{
		ID:       "doc-123",
		Type:     "document",
		TenantID: "company",
		Attrs:    map[string]any{"owner_id": "user:alice"},
	}

	sensitiveDoc := &authz.Resource{
		ID:       "sensitive-456",
		Type:     "document:sensitive",
		TenantID: "company",
		Attrs:    map[string]any{"owner_id": "user:bob"},
	}

	env := &authz.Environment{
		Time:     time.Now(),
		TenantID: "company",
	}

	fmt.Println("RBAC Tests:")
	// Alice (admin) can delete any document
	decision, _ := engine.Authorize(ctx, alice, "delete", doc, env)
	fmt.Printf("  Alice (admin) delete regular doc: %v (%s)\n", decision.Allowed, decision.Reason)

	// Bob (editor) can write to regular documents
	decision, _ = engine.Authorize(ctx, bob, "write", doc, env)
	fmt.Printf("  Bob (editor) write regular doc: %v (%s)\n", decision.Allowed, decision.Reason)

	// Bob (editor) cannot delete
	decision, _ = engine.Authorize(ctx, bob, "delete", doc, env)
	fmt.Printf("  Bob (editor) delete regular doc: %v (%s)\n", decision.Allowed, decision.Reason)

	fmt.Println("\nABAC Tests:")
	// Alice (high clearance) can read sensitive documents
	decision, _ = engine.Authorize(ctx, alice, "read", sensitiveDoc, env)
	fmt.Printf("  Alice (high clearance) read sensitive: %v (%s)\n", decision.Allowed, decision.Reason)

	// Bob (low clearance) cannot read sensitive documents
	decision, _ = engine.Authorize(ctx, bob, "read", sensitiveDoc, env)
	fmt.Printf("  Bob (low clearance) read sensitive: %v (%s)\n", decision.Allowed, decision.Reason)

	// Charlie (high clearance) can read sensitive
	decision, _ = engine.Authorize(ctx, charlie, "read", sensitiveDoc, env)
	fmt.Printf("  Charlie (high clearance) read sensitive: %v (%s)\n", decision.Allowed, decision.Reason)

	// Alice can delete her own document (owner access)
	decision, _ = engine.Authorize(ctx, alice, "delete", doc, env)
	fmt.Printf("  Alice delete own document: %v (%s)\n", decision.Allowed, decision.Reason)

	// Bob cannot delete Alice's document
	decision, _ = engine.Authorize(ctx, bob, "delete", doc, env)
	fmt.Printf("  Bob delete Alice's document: %v (%s)\n\n", decision.Allowed, decision.Reason)
}

func performanceExample() {
	fmt.Println("4. DSL Parsing and Encoding Comparison")
	fmt.Println("--------------------------------------")

	// Create test config
	dsl := `
tenant test "Test"
policy p1 test allow read * subject.type=user
role admin test Admin *:*
member user:1 admin
engine cache_ttl=1000
`

	// Measure DSL parsing
	start := time.Now()
	parser := authz.NewDSLParser()
	cfg, _ := parser.Parse([]byte(dsl))
	dslTime := time.Since(start)

	// Measure JSON encoding
	start = time.Now()
	jsonData, _ := json.Marshal(cfg)
	jsonEncodeTime := time.Since(start)

	// Measure JSON decoding
	start = time.Now()
	var cfgJSON authz.Config
	json.Unmarshal(jsonData, &cfgJSON)
	jsonDecodeTime := time.Since(start)

	// Measure YAML encoding
	start = time.Now()
	yamlData, _ := yaml.Marshal(cfg)
	yamlEncodeTime := time.Since(start)

	// Measure YAML decoding
	start = time.Now()
	var cfgYAML authz.Config
	yaml.Unmarshal(yamlData, &cfgYAML)
	yamlDecodeTime := time.Since(start)

	// Measure binary encoding
	start = time.Now()
	encoder := authz.NewBinaryEncoder()
	binary, _ := encoder.Encode(cfg)
	binaryEncodeTime := time.Since(start)

	// Measure binary decoding
	start = time.Now()
	decoder := authz.NewBinaryDecoder(binary)
	decoder.Decode()
	binaryDecodeTime := time.Since(start)

	fmt.Printf("Sizes:\n")
	fmt.Printf("  DSL:     %d bytes\n", len(dsl))
	fmt.Printf("  JSON:    %d bytes (%.1fx DSL)\n", len(jsonData), float64(len(jsonData))/float64(len(dsl)))
	fmt.Printf("  YAML:    %d bytes (%.1fx DSL)\n", len(yamlData), float64(len(yamlData))/float64(len(dsl)))
	fmt.Printf("  Binary:  %d bytes (%.1fx DSL)\n", len(binary), float64(len(binary))/float64(len(dsl)))

	fmt.Printf("\nEncoding times:\n")
	fmt.Printf("  DSL parse:     %v\n", dslTime)
	fmt.Printf("  JSON encode:   %v\n", jsonEncodeTime)
	fmt.Printf("  YAML encode:   %v\n", yamlEncodeTime)
	fmt.Printf("  Binary encode: %v\n", binaryEncodeTime)

	fmt.Printf("\nDecoding times:\n")
	fmt.Printf("  DSL parse:     %v\n", dslTime)
	fmt.Printf("  JSON decode:   %v\n", jsonDecodeTime)
	fmt.Printf("  YAML decode:   %v\n", yamlDecodeTime)
	fmt.Printf("  Binary decode: %v\n", binaryDecodeTime)

	fmt.Printf("\nSpeed comparisons (lower is better):\n")
	fmt.Printf("  JSON decode vs DSL parse:   %.1fx\n", float64(jsonDecodeTime)/float64(dslTime))
	fmt.Printf("  YAML decode vs DSL parse:   %.1fx\n", float64(yamlDecodeTime)/float64(dslTime))
	fmt.Printf("  Binary decode vs DSL parse: %.1fx\n", float64(binaryDecodeTime)/float64(dslTime))
}

// Example: Load from file
func loadFromFile() {
	data, err := os.ReadFile("config.authz")
	if err != nil {
		log.Fatal(err)
	}

	parser := authz.NewDSLParser()
	cfg, err := parser.Parse(data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Loaded: %d policies\n", len(cfg.Policies))
}

// Example: Convert DSL to Binary
func convertToBinary() {
	// Read DSL
	dslData, _ := os.ReadFile("config.authz")
	parser := authz.NewDSLParser()
	cfg, _ := parser.Parse(dslData)

	// Encode to binary
	encoder := authz.NewBinaryEncoder()
	binary, _ := encoder.Encode(cfg)

	// Save binary
	os.WriteFile("config.bin", binary, 0644)

	fmt.Printf("Converted: %d bytes DSL -> %d bytes binary\n",
		len(dslData), len(binary))
}

// Example: Load binary in production
func loadBinary() {
	data, _ := os.ReadFile("config.bin")
	decoder := authz.NewBinaryDecoder(data)
	cfg, _ := decoder.Decode()

	// Use config
	fmt.Printf("Loaded binary: %d policies\n", len(cfg.Policies))
}

// Adding a test for the updated deny-sensitive policy
func testDenySensitivePolicy(ctx context.Context, engine *authz.Engine) {
	fmt.Println("\nTesting Updated deny-sensitive Policy:")

	alice := &authz.Subject{
		ID:       "user:alice",
		Type:     "user",
		TenantID: "company",
		Roles:    []string{"admin"},
		Attrs:    map[string]any{"clearance": "high"},
	}

	bob := &authz.Subject{
		ID:       "user:bob",
		Type:     "user",
		TenantID: "company",
		Roles:    []string{"editor"},
		Attrs:    map[string]any{"clearance": "low"},
	}

	sensitiveDoc := &authz.Resource{
		ID:       "sensitive-456",
		Type:     "document:sensitive",
		TenantID: "company",
		Attrs:    map[string]any{"owner_id": "user:bob"},
	}

	env := &authz.Environment{
		Time:     time.Now(),
		TenantID: "company",
	}

	// Alice (high clearance) can read sensitive documents
	decision, _ := engine.Authorize(ctx, alice, "read", sensitiveDoc, env)
	fmt.Printf("  Alice (high clearance) read sensitive: %v (%s)\n", decision.Allowed, decision.Reason)

	// Bob (low clearance) cannot read sensitive documents
	decision, _ = engine.Authorize(ctx, bob, "read", sensitiveDoc, env)
	fmt.Printf("  Bob (low clearance) read sensitive: %v (%s)\n", decision.Allowed, decision.Reason)

	// Bob (low clearance) cannot delete sensitive documents
	decision, _ = engine.Authorize(ctx, bob, "delete", sensitiveDoc, env)
	fmt.Printf("  Bob (low clearance) delete sensitive: %v (%s)\n", decision.Allowed, decision.Reason)
}
