package authz_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/oarkflow/authz"
	"gopkg.in/yaml.v3"
)

type benchmarkWireConfig struct {
	Version     uint16                 `json:"version" yaml:"version"`
	Tenants     []authz.TenantConfig   `json:"tenants" yaml:"tenants"`
	Policies    []benchmarkWirePolicy  `json:"policies" yaml:"policies"`
	Roles       []benchmarkWireRole    `json:"roles" yaml:"roles"`
	ACLs        []benchmarkWireACL     `json:"acls" yaml:"acls"`
	Memberships []authz.RoleMembership `json:"memberships" yaml:"memberships"`
	Hierarchy   map[string]string      `json:"hierarchy" yaml:"hierarchy"`
	Engine      authz.EngineConfig     `json:"engine" yaml:"engine"`
}

type benchmarkWirePolicy struct {
	ID        string   `json:"id" yaml:"id"`
	TenantID  string   `json:"tenant_id" yaml:"tenant_id"`
	Effect    string   `json:"effect" yaml:"effect"`
	Actions   []string `json:"actions" yaml:"actions"`
	Resources []string `json:"resources" yaml:"resources"`
	Condition string   `json:"condition" yaml:"condition"`
	Priority  int      `json:"priority" yaml:"priority"`
	Enabled   bool     `json:"enabled" yaml:"enabled"`
}

type benchmarkWireRole struct {
	ID          string             `json:"id" yaml:"id"`
	TenantID    string             `json:"tenant_id" yaml:"tenant_id"`
	Name        string             `json:"name" yaml:"name"`
	Permissions []authz.Permission `json:"permissions" yaml:"permissions"`
	Inherits    []string           `json:"inherits,omitempty" yaml:"inherits,omitempty"`
	Owner       []authz.Action     `json:"owner,omitempty" yaml:"owner,omitempty"`
}

type benchmarkWireACL struct {
	ID         string   `json:"id" yaml:"id"`
	ResourceID string   `json:"resource_id" yaml:"resource_id"`
	SubjectID  string   `json:"subject_id" yaml:"subject_id"`
	Actions    []string `json:"actions" yaml:"actions"`
	Effect     string   `json:"effect" yaml:"effect"`
}

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

func generateBenchmarkWireConfig(numPolicies, numRoles int) benchmarkWireConfig {
	cfg := benchmarkWireConfig{
		Version:     1,
		Tenants:     []authz.TenantConfig{{ID: "test", Name: "Test Tenant"}},
		Policies:    make([]benchmarkWirePolicy, numPolicies),
		Roles:       make([]benchmarkWireRole, numRoles),
		ACLs:        []benchmarkWireACL{{ID: "acl-public", ResourceID: "document:public", SubjectID: "guest", Actions: []string{"read"}, Effect: "allow"}},
		Memberships: []authz.RoleMembership{{SubjectID: "user:1", RoleID: "role-0"}},
		Hierarchy:   map[string]string{},
		Engine:      authz.EngineConfig{DecisionCacheTTL: 5000, AuditBatchSize: 128},
	}
	for i := 0; i < numPolicies; i++ {
		cfg.Policies[i] = benchmarkWirePolicy{
			ID:        fmt.Sprintf("policy-%d", i),
			TenantID:  "test",
			Effect:    "allow",
			Actions:   []string{"read", "write"},
			Resources: []string{"document:*", "file:*"},
			Condition: "subject.type=user",
			Priority:  i,
			Enabled:   true,
		}
	}
	for i := 0; i < numRoles; i++ {
		cfg.Roles[i] = benchmarkWireRole{
			ID:       fmt.Sprintf("role-%d", i),
			TenantID: "test",
			Name:     fmt.Sprintf("Role %d", i),
			Permissions: []authz.Permission{
				{Action: "read", Resource: "*"},
				{Action: "write", Resource: "document:*"},
			},
		}
	}
	return cfg
}

func generateBenchmarkDSL(numPolicies, numRoles int) []byte {
	var b strings.Builder
	b.Grow(64 + numPolicies*90 + numRoles*45)
	b.WriteString("tenant test \"Test Tenant\"\n")
	for i := 0; i < numPolicies; i++ {
		fmt.Fprintf(&b, "policy policy-%d test allow read,write document:*,file:* subject.type=user priority:%d\n", i, i)
	}
	for i := 0; i < numRoles; i++ {
		fmt.Fprintf(&b, "role role-%d test \"Role %d\" read:*,write:document:*\n", i, i)
	}
	b.WriteString("acl acl-public document:public guest read allow\n")
	b.WriteString("member user:1 role-0\n")
	b.WriteString("engine cache_ttl=5000 batch_size=128\n")
	return []byte(b.String())
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

func BenchmarkConfigFormatDecodeSmall(b *testing.B) {
	wire := generateBenchmarkWireConfig(10, 5)
	dsl := generateBenchmarkDSL(10, 5)
	jsonData, _ := json.Marshal(wire)
	yamlData, _ := yaml.Marshal(wire)

	b.Run("DSL", func(b *testing.B) {
		parser := authz.NewDSLParser()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := parser.Parse(dsl); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("JSON", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var decoded benchmarkWireConfig
			if err := json.Unmarshal(jsonData, &decoded); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("YAML", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var decoded benchmarkWireConfig
			if err := yaml.Unmarshal(yamlData, &decoded); err != nil {
				b.Fatal(err)
			}
		}
	})
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

func BenchmarkConfigFormatDecodeLarge(b *testing.B) {
	wire := generateBenchmarkWireConfig(100, 50)
	dsl := generateBenchmarkDSL(100, 50)
	jsonData, _ := json.Marshal(wire)
	yamlData, _ := yaml.Marshal(wire)

	b.Run("DSL", func(b *testing.B) {
		parser := authz.NewDSLParser()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := parser.Parse(dsl); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("JSON", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var decoded benchmarkWireConfig
			if err := json.Unmarshal(jsonData, &decoded); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("YAML", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var decoded benchmarkWireConfig
			if err := yaml.Unmarshal(yamlData, &decoded); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkConfigSignatureVerify(b *testing.B) {
	pub, priv, err := authz.GenerateConfigSigningKey()
	if err != nil {
		b.Fatal(err)
	}
	data := generateBenchmarkDSL(100, 50)
	sig, err := authz.SignConfig(data, priv)
	if err != nil {
		b.Fatal(err)
	}
	signed := authz.AppendConfigSignature(data, sig)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := authz.VerifyConfigSignature(signed, pub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConfigSignatureVerifyWithKey(b *testing.B) {
	pub, priv, err := authz.GenerateConfigSigningKey()
	if err != nil {
		b.Fatal(err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		b.Fatal(err)
	}
	data := generateBenchmarkDSL(100, 50)
	sig, err := authz.SignConfig(data, priv)
	if err != nil {
		b.Fatal(err)
	}
	signed := authz.AppendConfigSignature(data, sig)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := authz.VerifyConfigSignatureWithKey(signed, pubBytes); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateConfigLarge(b *testing.B) {
	cfg, err := authz.NewDSLParser().Parse(generateBenchmarkDSL(100, 50))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := authz.ValidateConfig(cfg); err != nil {
			b.Fatal(err)
		}
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
