package authz_test

import (
	"testing"

	"github.com/oarkflow/authz"
	"gopkg.in/yaml.v3"
)

// Generate test config with N policies and roles
func generateTestConfig(numPolicies, numRoles int) *authz.Config {
	cfg := &authz.Config{
		Version:     1,
		Tenants:     []authz.TenantConfig{{ID: "test", Name: "Test Tenant"}},
		Policies:    make([]*authz.Policy, numPolicies),
		Roles:       make([]*authz.Role, numRoles),
		ACLs:        []*authz.ACL{},
		Memberships: []authz.RoleMembership{},
		Hierarchy:   map[string]string{},
		Engine:      authz.EngineConfig{DecisionCacheTTL: 5000, AuditBatchSize: 128},
	}

	for i := 0; i < numPolicies; i++ {
		cfg.Policies[i] = &authz.Policy{
			ID:        "policy-" + string(rune(i)),
			TenantID:  "test",
			Effect:    authz.EffectAllow,
			Actions:   []authz.Action{"read", "write"},
			Resources: []string{"document:*", "file:*"},
			Condition: &authz.TrueExpr{},
			Priority:  i,
			Enabled:   true,
		}
	}

	for i := 0; i < numRoles; i++ {
		cfg.Roles[i] = &authz.Role{
			ID:       "role-" + string(rune(i)),
			TenantID: "test",
			Name:     "Role " + string(rune(i)),
			Permissions: []authz.Permission{
				{Action: "read", Resource: "*"},
				{Action: "write", Resource: "document:*"},
			},
		}
	}

	return cfg
}

// Benchmark DSL Parsing
func BenchmarkDSLParse(b *testing.B) {
	dsl := []byte(`
tenant test "Test"
policy p1 test allow read document:* subject.type=user
policy p2 test allow write document:* subject.roles@editor
role admin test Admin *:*
role viewer test Viewer read:*
member user:1 admin
engine cache_ttl=5000
`)

	parser := authz.NewDSLParser()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(dsl)
	}
}

// Benchmark DSL Encoding
func BenchmarkDSLEncode(b *testing.B) {
	cfg := generateTestConfig(10, 5)
	encoder := authz.NewDSLEncoder()
	
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.Encode(cfg)
	}
}

// Benchmark Binary Encoding
func BenchmarkBinaryEncode(b *testing.B) {
	cfg := generateTestConfig(10, 5)
	encoder := authz.NewBinaryEncoder()
	
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.Encode(cfg)
	}
}

// Benchmark Binary Decoding
func BenchmarkBinaryDecode(b *testing.B) {
	cfg := generateTestConfig(10, 5)
	encoder := authz.NewBinaryEncoder()
	data, _ := encoder.Encode(cfg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decoder := authz.NewBinaryDecoder(data)
		_, _ = decoder.Decode()
	}
}

// Benchmark YAML Encoding
func BenchmarkYAMLEncode(b *testing.B) {
	cfg := generateTestConfig(10, 5)
	
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = yaml.Marshal(cfg)
	}
}

// Benchmark YAML Decoding
func BenchmarkYAMLDecode(b *testing.B) {
	b.Skip("YAML decode has issues with Expr interface")
	cfg := generateTestConfig(10, 5)
	data, _ := yaml.Marshal(cfg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var decoded authz.Config
		_ = yaml.Unmarshal(data, &decoded)
	}
}

// Benchmark JSON Encoding
func BenchmarkJSONEncode(b *testing.B) {
	cfg := generateTestConfig(10, 5)
	
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = cfg.ToJSON()
	}
}

// Benchmark JSON Decoding
func BenchmarkJSONDecode(b *testing.B) {
	cfg := generateTestConfig(10, 5)
	data, _ := cfg.ToJSON()
	loader := authz.NewConfigLoader()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = loader.LoadJSON(data)
	}
}

// Benchmark with larger configs
func BenchmarkDSLParseLarge(b *testing.B) {
	// Generate DSL with 100 policies
	dsl := []byte("tenant test \"Test\"\n")
	for i := 0; i < 100; i++ {
		dsl = append(dsl, []byte("policy p"+string(rune(i))+" test allow read document:* subject.type=user\n")...)
	}
	for i := 0; i < 50; i++ {
		dsl = append(dsl, []byte("role r"+string(rune(i))+" test Role"+string(rune(i))+" read:*\n")...)
	}

	parser := authz.NewDSLParser()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(dsl)
	}
}

func BenchmarkBinaryEncodeLarge(b *testing.B) {
	cfg := generateTestConfig(100, 50)
	encoder := authz.NewBinaryEncoder()
	
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.Encode(cfg)
	}
}

func BenchmarkBinaryDecodeLarge(b *testing.B) {
	cfg := generateTestConfig(100, 50)
	encoder := authz.NewBinaryEncoder()
	data, _ := encoder.Encode(cfg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decoder := authz.NewBinaryDecoder(data)
		_, _ = decoder.Decode()
	}
}

func BenchmarkYAMLEncodeLarge(b *testing.B) {
	cfg := generateTestConfig(100, 50)
	
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = yaml.Marshal(cfg)
	}
}

func BenchmarkYAMLDecodeLarge(b *testing.B) {
	b.Skip("YAML decode has issues with Expr interface")
	cfg := generateTestConfig(100, 50)
	data, _ := yaml.Marshal(cfg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var decoded authz.Config
		_ = yaml.Unmarshal(data, &decoded)
	}
}

// Size comparison test
func TestSizeComparison(t *testing.T) {
	cfg := generateTestConfig(100, 50)

	// Binary
	encoder := authz.NewBinaryEncoder()
	binaryData, _ := encoder.Encode(cfg)

	// YAML
	yamlData, _ := yaml.Marshal(cfg)

	// JSON
	jsonData, _ := cfg.ToJSON()

	t.Logf("Size Comparison (100 policies, 50 roles):")
	t.Logf("  Binary: %d bytes (100%%)", len(binaryData))
	t.Logf("  YAML:   %d bytes (%.0f%%)", len(yamlData), float64(len(yamlData))/float64(len(binaryData))*100)
	t.Logf("  JSON:   %d bytes (%.0f%%)", len(jsonData), float64(len(jsonData))/float64(len(binaryData))*100)
}
