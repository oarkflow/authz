package authz

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete authz configuration
type Config struct {
	Version     uint16            `json:"version" yaml:"version"`
	Tenants     []TenantConfig    `json:"tenants" yaml:"tenants"`
	Policies    []*Policy         `json:"policies" yaml:"policies"`
	Roles       []*Role           `json:"roles" yaml:"roles"`
	ACLs        []*ACL            `json:"acls" yaml:"acls"`
	Memberships []RoleMembership  `json:"memberships" yaml:"memberships"`
	Engine      EngineConfig      `json:"engine" yaml:"engine"`
	Hierarchy   map[string]string `json:"hierarchy" yaml:"hierarchy"` // child -> parent
}

type TenantConfig struct {
	ID     string         `json:"id" yaml:"id"`
	Name   string         `json:"name" yaml:"name"`
	Parent string         `json:"parent,omitempty" yaml:"parent,omitempty"`
	Attrs  map[string]any `json:"attrs,omitempty" yaml:"attrs,omitempty"`
}

type RoleMembership struct {
	SubjectID string `json:"subject_id" yaml:"subject_id"`
	RoleID    string `json:"role_id" yaml:"role_id"`
}

type EngineConfig struct {
	DecisionCacheTTL    int64 `json:"decision_cache_ttl_ms" yaml:"decision_cache_ttl_ms"`
	AttributeCacheTTL   int64 `json:"attribute_cache_ttl_ms" yaml:"attribute_cache_ttl_ms"`
	AuditBatchSize      int   `json:"audit_batch_size" yaml:"audit_batch_size"`
	AuditFlushInterval  int64 `json:"audit_flush_interval_ms" yaml:"audit_flush_interval_ms"`
	BatchWorkerCount    int   `json:"batch_worker_count" yaml:"batch_worker_count"`
	RistrettoNumCounter int64 `json:"ristretto_num_counter" yaml:"ristretto_num_counter"`
	RistrettoMaxCost    int64 `json:"ristretto_max_cost" yaml:"ristretto_max_cost"`
	RistrettoBuffer     int64 `json:"ristretto_buffer" yaml:"ristretto_buffer"`
}

// ConfigLoader loads configuration from various formats
type ConfigLoader struct{}

func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{}
}

func (l *ConfigLoader) LoadYAML(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (l *ConfigLoader) LoadJSON(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadBinary loads from custom binary protocol
func (l *ConfigLoader) LoadBinary(data []byte) (*Config, error) {
	r := bytes.NewReader(data)
	return decodeBinaryConfig(r)
}

// EncodeBinaryConfig encodes config to binary format
func EncodeBinaryConfig(cfg *Config) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := encodeBinaryConfig(cfg, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ToYAML exports config to YAML
func (c *Config) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// ToJSON exports config to JSON
func (c *Config) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// ApplyConfig applies configuration to engine and stores
func (e *Engine) ApplyConfig(ctx context.Context, cfg *Config) error {
	// Apply engine settings
	if cfg.Engine.DecisionCacheTTL > 0 {
		e.decisionCacheTTL = time.Duration(cfg.Engine.DecisionCacheTTL) * time.Millisecond
	}
	if cfg.Engine.AttributeCacheTTL > 0 {
		e.SetAttributeCacheTTL(time.Duration(cfg.Engine.AttributeCacheTTL) * time.Millisecond)
	}
	if cfg.Engine.AuditBatchSize > 0 {
		e.auditBatchSize = cfg.Engine.AuditBatchSize
	}
	if cfg.Engine.AuditFlushInterval > 0 {
		e.auditFlushInterval = time.Duration(cfg.Engine.AuditFlushInterval) * time.Millisecond
	}
	if cfg.Engine.BatchWorkerCount > 0 {
		e.batchWorkerCount = cfg.Engine.BatchWorkerCount
	}
	if cfg.Engine.RistrettoNumCounter > 0 {
		_ = e.ConfigureRistrettoDecisionCache(cfg.Engine.RistrettoNumCounter, cfg.Engine.RistrettoMaxCost, cfg.Engine.RistrettoBuffer)
	}

	// Apply tenant hierarchy
	if len(cfg.Hierarchy) > 0 && e.tenantResolver == nil {
		resolver := NewMemoryTenantResolver()
		for child, parent := range cfg.Hierarchy {
			resolver.AddParent(child, parent)
		}
		e.SetTenantResolver(resolver)
	}

	// Apply policies
	for _, p := range cfg.Policies {
		if _, err := e.policyStore.GetPolicy(ctx, p.ID); err != nil {
			if err := e.CreatePolicy(ctx, p); err != nil {
				return fmt.Errorf("create policy %s: %w", p.ID, err)
			}
		} else {
			if err := e.UpdatePolicy(ctx, p); err != nil {
				return fmt.Errorf("update policy %s: %w", p.ID, err)
			}
		}
	}

	// Apply roles
	for _, r := range cfg.Roles {
		if _, err := e.roleStore.GetRole(ctx, r.ID); err != nil {
			if err := e.CreateRole(ctx, r); err != nil {
				return fmt.Errorf("create role %s: %w", r.ID, err)
			}
		} else {
			if err := e.UpdateRole(ctx, r); err != nil {
				return fmt.Errorf("update role %s: %w", r.ID, err)
			}
		}
	}

	// Apply ACLs
	for _, acl := range cfg.ACLs {
		if err := e.GrantACL(ctx, acl); err != nil {
			return fmt.Errorf("grant acl %s: %w", acl.ID, err)
		}
	}

	// Apply role memberships
	if e.roleMembershipStore != nil {
		for _, m := range cfg.Memberships {
			if err := e.roleMembershipStore.AssignRole(ctx, m.SubjectID, m.RoleID); err != nil {
				return fmt.Errorf("assign role %s to %s: %w", m.RoleID, m.SubjectID, err)
			}
		}
	}

	// Reload policies for all tenants
	tenants := make(map[string]bool)
	for _, p := range cfg.Policies {
		tenants[p.TenantID] = true
	}
	for t := range tenants {
		_ = e.ReloadPolicies(ctx, t)
	}

	return nil
}

// Binary protocol encoding/decoding
const (
	binaryMagic   = 0x415A // "AZ" for authz
	binaryVersion = 1
)

func encodeBinaryConfig(cfg *Config, w io.Writer) error {
	buf := &bytes.Buffer{}

	// Header: magic(2) + version(2) + config_version(2)
	binary.Write(buf, binary.LittleEndian, uint16(binaryMagic))
	binary.Write(buf, binary.LittleEndian, uint16(binaryVersion))
	binary.Write(buf, binary.LittleEndian, cfg.Version)

	// Encode sections with type tags
	writeSection(buf, 0x01, func(b *bytes.Buffer) { encodeTenants(b, cfg.Tenants) })
	writeSection(buf, 0x02, func(b *bytes.Buffer) { encodePolicies(b, cfg.Policies) })
	writeSection(buf, 0x03, func(b *bytes.Buffer) { encodeRoles(b, cfg.Roles) })
	writeSection(buf, 0x04, func(b *bytes.Buffer) { encodeACLs(b, cfg.ACLs) })
	writeSection(buf, 0x05, func(b *bytes.Buffer) { encodeMemberships(b, cfg.Memberships) })
	writeSection(buf, 0x06, func(b *bytes.Buffer) { encodeEngineConfig(b, &cfg.Engine) })
	writeSection(buf, 0x07, func(b *bytes.Buffer) { encodeHierarchy(b, cfg.Hierarchy) })

	_, err := w.Write(buf.Bytes())
	return err
}

func decodeBinaryConfig(r io.Reader) (*Config, error) {
	cfg := &Config{}

	var magic, ver, cfgVer uint16
	binary.Read(r, binary.LittleEndian, &magic)
	binary.Read(r, binary.LittleEndian, &ver)
	binary.Read(r, binary.LittleEndian, &cfgVer)

	if magic != binaryMagic {
		return nil, fmt.Errorf("invalid magic: %x", magic)
	}
	if ver != binaryVersion {
		return nil, fmt.Errorf("unsupported version: %d", ver)
	}
	cfg.Version = cfgVer

	for {
		var tag uint8
		if err := binary.Read(r, binary.LittleEndian, &tag); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		var size uint32
		binary.Read(r, binary.LittleEndian, &size)
		data := make([]byte, size)
		io.ReadFull(r, data)

		switch tag {
		case 0x01:
			cfg.Tenants = decodeTenants(data)
		case 0x02:
			cfg.Policies = decodePolicies(data)
		case 0x03:
			cfg.Roles = decodeRoles(data)
		case 0x04:
			cfg.ACLs = decodeACLs(data)
		case 0x05:
			cfg.Memberships = decodeMemberships(data)
		case 0x06:
			cfg.Engine = decodeEngineConfig(data)
		case 0x07:
			cfg.Hierarchy = decodeHierarchy(data)
		}
	}

	return cfg, nil
}

func writeSection(buf *bytes.Buffer, tag uint8, fn func(*bytes.Buffer)) {
	tmp := &bytes.Buffer{}
	fn(tmp)
	binary.Write(buf, binary.LittleEndian, tag)
	binary.Write(buf, binary.LittleEndian, uint32(tmp.Len()))
	buf.Write(tmp.Bytes())
}

func writeString(buf *bytes.Buffer, s string) {
	binary.Write(buf, binary.LittleEndian, uint16(len(s)))
	buf.WriteString(s)
}

func readString(r *bytes.Reader) string {
	var l uint16
	binary.Read(r, binary.LittleEndian, &l)
	b := make([]byte, l)
	r.Read(b)
	return string(b)
}

func encodeTenants(buf *bytes.Buffer, tenants []TenantConfig) {
	binary.Write(buf, binary.LittleEndian, uint16(len(tenants)))
	for _, t := range tenants {
		writeString(buf, t.ID)
		writeString(buf, t.Name)
		writeString(buf, t.Parent)
	}
}

func decodeTenants(data []byte) []TenantConfig {
	r := bytes.NewReader(data)
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	tenants := make([]TenantConfig, count)
	for i := range tenants {
		tenants[i].ID = readString(r)
		tenants[i].Name = readString(r)
		tenants[i].Parent = readString(r)
	}
	return tenants
}

func encodePolicies(buf *bytes.Buffer, policies []*Policy) {
	binary.Write(buf, binary.LittleEndian, uint16(len(policies)))
	for _, p := range policies {
		writeString(buf, p.ID)
		writeString(buf, p.TenantID)
		buf.WriteByte(byte(map[Effect]uint8{EffectAllow: 1, EffectDeny: 2}[p.Effect]))
		binary.Write(buf, binary.LittleEndian, uint16(len(p.Actions)))
		for _, a := range p.Actions {
			writeString(buf, string(a))
		}
		binary.Write(buf, binary.LittleEndian, uint16(len(p.Resources)))
		for _, res := range p.Resources {
			writeString(buf, res)
		}
		condJSON, _ := json.Marshal(p.Condition)
		writeString(buf, string(condJSON))
		binary.Write(buf, binary.LittleEndian, int32(p.Priority))
		buf.WriteByte(map[bool]byte{true: 1, false: 0}[p.Enabled])
	}
}

func decodePolicies(data []byte) []*Policy {
	r := bytes.NewReader(data)
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	policies := make([]*Policy, count)
	for i := range policies {
		p := &Policy{}
		p.ID = readString(r)
		p.TenantID = readString(r)
		var eff byte
		r.ReadByte()
		eff, _ = r.ReadByte()
		p.Effect = map[uint8]Effect{1: EffectAllow, 2: EffectDeny}[eff]
		var actCount uint16
		binary.Read(r, binary.LittleEndian, &actCount)
		p.Actions = make([]Action, actCount)
		for j := range p.Actions {
			p.Actions[j] = Action(readString(r))
		}
		var resCount uint16
		binary.Read(r, binary.LittleEndian, &resCount)
		p.Resources = make([]string, resCount)
		for j := range p.Resources {
			p.Resources[j] = readString(r)
		}
		condStr := readString(r)
		p.Condition = parseConditionJSON(condStr)
		var pri int32
		binary.Read(r, binary.LittleEndian, &pri)
		p.Priority = int(pri)
		enb, _ := r.ReadByte()
		p.Enabled = enb == 1
		p.CreatedAt = time.Now()
		p.UpdatedAt = time.Now()
		policies[i] = p
	}
	return policies
}

func encodeRoles(buf *bytes.Buffer, roles []*Role) {
	binary.Write(buf, binary.LittleEndian, uint16(len(roles)))
	for _, role := range roles {
		writeString(buf, role.ID)
		writeString(buf, role.TenantID)
		writeString(buf, role.Name)
		binary.Write(buf, binary.LittleEndian, uint16(len(role.Permissions)))
		for _, perm := range role.Permissions {
			writeString(buf, string(perm.Action))
			writeString(buf, perm.Resource)
		}
		binary.Write(buf, binary.LittleEndian, uint16(len(role.OwnerAllowedActions)))
		for _, a := range role.OwnerAllowedActions {
			writeString(buf, string(a))
		}
		binary.Write(buf, binary.LittleEndian, uint16(len(role.Inherits)))
		for _, inh := range role.Inherits {
			writeString(buf, inh)
		}
	}
}

func decodeRoles(data []byte) []*Role {
	r := bytes.NewReader(data)
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	roles := make([]*Role, count)
	for i := range roles {
		role := &Role{}
		role.ID = readString(r)
		role.TenantID = readString(r)
		role.Name = readString(r)
		var permCount uint16
		binary.Read(r, binary.LittleEndian, &permCount)
		role.Permissions = make([]Permission, permCount)
		for j := range role.Permissions {
			role.Permissions[j].Action = Action(readString(r))
			role.Permissions[j].Resource = readString(r)
		}
		var oaaCount uint16
		binary.Read(r, binary.LittleEndian, &oaaCount)
		role.OwnerAllowedActions = make([]Action, oaaCount)
		for j := range role.OwnerAllowedActions {
			role.OwnerAllowedActions[j] = Action(readString(r))
		}
		var inhCount uint16
		binary.Read(r, binary.LittleEndian, &inhCount)
		role.Inherits = make([]string, inhCount)
		for j := range role.Inherits {
			role.Inherits[j] = readString(r)
		}
		role.CreatedAt = time.Now()
		roles[i] = role
	}
	return roles
}

func encodeACLs(buf *bytes.Buffer, acls []*ACL) {
	binary.Write(buf, binary.LittleEndian, uint16(len(acls)))
	for _, acl := range acls {
		writeString(buf, acl.ID)
		writeString(buf, acl.ResourceID)
		writeString(buf, acl.SubjectID)
		binary.Write(buf, binary.LittleEndian, uint16(len(acl.Actions)))
		for _, a := range acl.Actions {
			writeString(buf, string(a))
		}
		buf.WriteByte(map[Effect]byte{EffectAllow: 1, EffectDeny: 2}[acl.Effect])
		binary.Write(buf, binary.LittleEndian, acl.ExpiresAt.Unix())
	}
}

func decodeACLs(data []byte) []*ACL {
	r := bytes.NewReader(data)
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	acls := make([]*ACL, count)
	for i := range acls {
		acl := &ACL{}
		acl.ID = readString(r)
		acl.ResourceID = readString(r)
		acl.SubjectID = readString(r)
		var actCount uint16
		binary.Read(r, binary.LittleEndian, &actCount)
		acl.Actions = make([]Action, actCount)
		for j := range acl.Actions {
			acl.Actions[j] = Action(readString(r))
		}
		eff, _ := r.ReadByte()
		acl.Effect = map[byte]Effect{1: EffectAllow, 2: EffectDeny}[eff]
		var exp int64
		binary.Read(r, binary.LittleEndian, &exp)
		if exp > 0 {
			acl.ExpiresAt = time.Unix(exp, 0)
		}
		acl.CreatedAt = time.Now()
		acls[i] = acl
	}
	return acls
}

func encodeMemberships(buf *bytes.Buffer, memberships []RoleMembership) {
	binary.Write(buf, binary.LittleEndian, uint16(len(memberships)))
	for _, m := range memberships {
		writeString(buf, m.SubjectID)
		writeString(buf, m.RoleID)
	}
}

func decodeMemberships(data []byte) []RoleMembership {
	r := bytes.NewReader(data)
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	memberships := make([]RoleMembership, count)
	for i := range memberships {
		memberships[i].SubjectID = readString(r)
		memberships[i].RoleID = readString(r)
	}
	return memberships
}

func encodeEngineConfig(buf *bytes.Buffer, cfg *EngineConfig) {
	binary.Write(buf, binary.LittleEndian, cfg.DecisionCacheTTL)
	binary.Write(buf, binary.LittleEndian, cfg.AttributeCacheTTL)
	binary.Write(buf, binary.LittleEndian, int32(cfg.AuditBatchSize))
	binary.Write(buf, binary.LittleEndian, cfg.AuditFlushInterval)
	binary.Write(buf, binary.LittleEndian, int32(cfg.BatchWorkerCount))
	binary.Write(buf, binary.LittleEndian, cfg.RistrettoNumCounter)
	binary.Write(buf, binary.LittleEndian, cfg.RistrettoMaxCost)
	binary.Write(buf, binary.LittleEndian, cfg.RistrettoBuffer)
}

func decodeEngineConfig(data []byte) EngineConfig {
	r := bytes.NewReader(data)
	cfg := EngineConfig{}
	binary.Read(r, binary.LittleEndian, &cfg.DecisionCacheTTL)
	binary.Read(r, binary.LittleEndian, &cfg.AttributeCacheTTL)
	var bs int32
	binary.Read(r, binary.LittleEndian, &bs)
	cfg.AuditBatchSize = int(bs)
	binary.Read(r, binary.LittleEndian, &cfg.AuditFlushInterval)
	var wc int32
	binary.Read(r, binary.LittleEndian, &wc)
	cfg.BatchWorkerCount = int(wc)
	binary.Read(r, binary.LittleEndian, &cfg.RistrettoNumCounter)
	binary.Read(r, binary.LittleEndian, &cfg.RistrettoMaxCost)
	binary.Read(r, binary.LittleEndian, &cfg.RistrettoBuffer)
	return cfg
}

func encodeHierarchy(buf *bytes.Buffer, hierarchy map[string]string) {
	binary.Write(buf, binary.LittleEndian, uint16(len(hierarchy)))
	for child, parent := range hierarchy {
		writeString(buf, child)
		writeString(buf, parent)
	}
}

func decodeHierarchy(data []byte) map[string]string {
	r := bytes.NewReader(data)
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	hierarchy := make(map[string]string, count)
	for i := 0; i < int(count); i++ {
		child := readString(r)
		parent := readString(r)
		hierarchy[child] = parent
	}
	return hierarchy
}

func parseConditionJSON(s string) Expr {
	if s == "" || s == "null" {
		return &TrueExpr{}
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return &TrueExpr{}
	}
	return parseExprMap(raw)
}

func parseExprMap(m map[string]any) Expr {
	if op, ok := m["op"].(string); ok {
		switch op {
		case "eq":
			return &EqExpr{Field: m["field"].(string), Value: m["value"]}
		case "in":
			vals := m["values"].([]any)
			return &InExpr{Field: m["field"].(string), Values: vals}
		case "gte":
			return &GteExpr{Field: m["field"].(string), Value: m["value"]}
		case "and":
			return &AndExpr{Left: parseExprMap(m["left"].(map[string]any)), Right: parseExprMap(m["right"].(map[string]any))}
		case "or":
			return &OrExpr{Left: parseExprMap(m["left"].(map[string]any)), Right: parseExprMap(m["right"].(map[string]any))}
		}
	}
	return &TrueExpr{}
}
