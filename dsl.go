package authz

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// DSL Syntax:
// tenant <id> <name> [parent:<parent_id>]
// policy <id> <tenant> <effect> <actions> <resources> <condition> [priority:<n>]
// role <id> <tenant> <name> <perms> [inherits:<roles>] [owner:<actions>]
// acl <id> <resource> <subject> <actions> <effect> [expires:<time>]
// member <subject> <role>
// engine <key>=<value>...

type DSLParser struct {
	line int
}

func NewDSLParser() *DSLParser {
	return &DSLParser{}
}

type DSLEncoder struct {
	buf []byte
}

func NewDSLEncoder() *DSLEncoder {
	return &DSLEncoder{buf: make([]byte, 0, 4096)}
}

func (e *DSLEncoder) Encode(cfg *Config) ([]byte, error) {
	e.buf = e.buf[:0]
	var tmp [20]byte

	for _, t := range cfg.Tenants {
		e.buf = append(e.buf, "tenant "...)
		e.buf = append(e.buf, t.ID...)
		e.buf = append(e.buf, " \""...)
		e.buf = append(e.buf, t.Name...)
		e.buf = append(e.buf, '"')
		if t.Parent != "" {
			e.buf = append(e.buf, " parent:"...)
			e.buf = append(e.buf, t.Parent...)
		}
		e.buf = append(e.buf, '\n')
	}

	for _, p := range cfg.Policies {
		e.buf = append(e.buf, "policy "...)
		e.buf = append(e.buf, p.ID...)
		e.buf = append(e.buf, ' ')
		e.buf = append(e.buf, p.TenantID...)
		e.buf = append(e.buf, ' ')
		e.buf = append(e.buf, p.Effect...)
		e.buf = append(e.buf, ' ')
		for i, a := range p.Actions {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			e.buf = append(e.buf, a...)
		}
		e.buf = append(e.buf, ' ')
		for i, r := range p.Resources {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			e.buf = append(e.buf, r...)
		}
		e.buf = append(e.buf, ' ')
		e.buf = append(e.buf, p.Condition.String()...)
		if p.Priority != 0 {
			e.buf = append(e.buf, " priority:"...)
			n := strconv.AppendInt(tmp[:0], int64(p.Priority), 10)
			e.buf = append(e.buf, n...)
		}
		e.buf = append(e.buf, '\n')
	}

	for _, r := range cfg.Roles {
		e.buf = append(e.buf, "role "...)
		e.buf = append(e.buf, r.ID...)
		e.buf = append(e.buf, ' ')
		e.buf = append(e.buf, r.TenantID...)
		e.buf = append(e.buf, ' ')
		if strings.Contains(r.Name, " ") {
			e.buf = append(e.buf, '"')
			e.buf = append(e.buf, r.Name...)
			e.buf = append(e.buf, '"')
		} else {
			e.buf = append(e.buf, r.Name...)
		}
		e.buf = append(e.buf, ' ')
		for i, p := range r.Permissions {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			e.buf = append(e.buf, p.Action...)
			e.buf = append(e.buf, ':')
			e.buf = append(e.buf, p.Resource...)
		}
		if len(r.Inherits) > 0 {
			e.buf = append(e.buf, " inherits:"...)
			for i, inh := range r.Inherits {
				if i > 0 {
					e.buf = append(e.buf, ',')
				}
				e.buf = append(e.buf, inh...)
			}
		}
		if len(r.OwnerAllowedActions) > 0 {
			e.buf = append(e.buf, " owner:"...)
			for i, a := range r.OwnerAllowedActions {
				if i > 0 {
					e.buf = append(e.buf, ',')
				}
				e.buf = append(e.buf, a...)
			}
		}
		e.buf = append(e.buf, '\n')
	}

	for _, acl := range cfg.ACLs {
		e.buf = append(e.buf, "acl "...)
		e.buf = append(e.buf, acl.ID...)
		e.buf = append(e.buf, ' ')
		e.buf = append(e.buf, acl.ResourceID...)
		e.buf = append(e.buf, ' ')
		e.buf = append(e.buf, acl.SubjectID...)
		e.buf = append(e.buf, ' ')
		for i, a := range acl.Actions {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			e.buf = append(e.buf, a...)
		}
		e.buf = append(e.buf, ' ')
		e.buf = append(e.buf, acl.Effect...)
		if !acl.ExpiresAt.IsZero() {
			e.buf = append(e.buf, " expires:"...)
			e.buf = append(e.buf, acl.ExpiresAt.Format(time.RFC3339)...)
		}
		e.buf = append(e.buf, '\n')
	}

	for _, m := range cfg.Memberships {
		e.buf = append(e.buf, "member "...)
		e.buf = append(e.buf, m.SubjectID...)
		e.buf = append(e.buf, ' ')
		e.buf = append(e.buf, m.RoleID...)
		e.buf = append(e.buf, '\n')
	}

	if cfg.Engine.DecisionCacheTTL > 0 || cfg.Engine.AuditBatchSize > 0 {
		e.buf = append(e.buf, "engine"...)
		if cfg.Engine.DecisionCacheTTL > 0 {
			e.buf = append(e.buf, " cache_ttl="...)
			n := strconv.AppendInt(tmp[:0], cfg.Engine.DecisionCacheTTL, 10)
			e.buf = append(e.buf, n...)
		}
		if cfg.Engine.AttributeCacheTTL > 0 {
			e.buf = append(e.buf, " attr_ttl="...)
			n := strconv.AppendInt(tmp[:0], cfg.Engine.AttributeCacheTTL, 10)
			e.buf = append(e.buf, n...)
		}
		if cfg.Engine.AuditBatchSize > 0 {
			e.buf = append(e.buf, " batch_size="...)
			n := strconv.AppendInt(tmp[:0], int64(cfg.Engine.AuditBatchSize), 10)
			e.buf = append(e.buf, n...)
		}
		if cfg.Engine.AuditFlushInterval > 0 {
			e.buf = append(e.buf, " flush_interval="...)
			n := strconv.AppendInt(tmp[:0], cfg.Engine.AuditFlushInterval, 10)
			e.buf = append(e.buf, n...)
		}
		if cfg.Engine.BatchWorkerCount > 0 {
			e.buf = append(e.buf, " workers="...)
			n := strconv.AppendInt(tmp[:0], int64(cfg.Engine.BatchWorkerCount), 10)
			e.buf = append(e.buf, n...)
		}
		e.buf = append(e.buf, '\n')
	}

	return e.buf, nil
}

func (p *DSLParser) Parse(data []byte) (*Config, error) {
	cfg := &Config{
		Version:     1,
		Tenants:     make([]TenantConfig, 0, 8),
		Policies:    make([]*Policy, 0, 16),
		Roles:       make([]*Role, 0, 8),
		ACLs:        make([]*ACL, 0, 8),
		Memberships: make([]RoleMembership, 0, 8),
		Hierarchy:   make(map[string]string, 8),
		Engine:      EngineConfig{DecisionCacheTTL: 1000, AuditBatchSize: 64},
	}

	p.line = 0
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '\n' {
			p.line++
			line := data[start:i]
			start = i + 1

			for len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				line = line[1:]
			}
			for len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t' || line[len(line)-1] == '\r') {
				line = line[:len(line)-1]
			}

			if len(line) == 0 || line[0] == '#' {
				continue
			}

			parts := splitLineBytes(line)
			if len(parts) == 0 {
				continue
			}

			switch parts[0] {
			case "tenant":
				if err := p.parseTenant(cfg, parts[1:]); err != nil {
					return nil, fmt.Errorf("line %d: %w", p.line, err)
				}
			case "policy":
				if err := p.parsePolicy(cfg, parts[1:]); err != nil {
					return nil, fmt.Errorf("line %d: %w", p.line, err)
				}
			case "role":
				if err := p.parseRole(cfg, parts[1:]); err != nil {
					return nil, fmt.Errorf("line %d: %w", p.line, err)
				}
			case "acl":
				if err := p.parseACL(cfg, parts[1:]); err != nil {
					return nil, fmt.Errorf("line %d: %w", p.line, err)
				}
			case "member":
				if err := p.parseMember(cfg, parts[1:]); err != nil {
					return nil, fmt.Errorf("line %d: %w", p.line, err)
				}
			case "engine":
				if err := p.parseEngine(cfg, parts[1:]); err != nil {
					return nil, fmt.Errorf("line %d: %w", p.line, err)
				}
			default:
				return nil, fmt.Errorf("line %d: unknown directive: %s", p.line, parts[0])
			}
		}
	}

	return cfg, nil
}

func splitLineBytes(line []byte) []string {
	parts := make([]string, 0, 8)
	var start int
	inQuote := false
	i := 0

	for i < len(line) {
		ch := line[i]
		if ch == '"' {
			if inQuote {
				parts = append(parts, string(line[start:i]))
				start = i + 1
				inQuote = false
			} else {
				start = i + 1
				inQuote = true
			}
		} else if (ch == ' ' || ch == '\t') && !inQuote {
			if i > start {
				parts = append(parts, string(line[start:i]))
			}
			start = i + 1
		}
		i++
	}

	if start < len(line) {
		parts = append(parts, string(line[start:]))
	}

	return parts
}

func (p *DSLParser) parseTenant(cfg *Config, parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("tenant requires: <id> <name> [parent:<id>]")
	}
	t := TenantConfig{ID: parts[0], Name: parts[1]}
	for _, opt := range parts[2:] {
		if strings.HasPrefix(opt, "parent:") {
			t.Parent = opt[7:]
			cfg.Hierarchy[t.ID] = t.Parent
		}
	}
	cfg.Tenants = append(cfg.Tenants, t)
	return nil
}

func (p *DSLParser) parsePolicy(cfg *Config, parts []string) error {
	if len(parts) < 6 {
		return fmt.Errorf("policy requires: <id> <tenant> <effect> <actions> <resources> <condition> [priority:<n>]")
	}

	pol := &Policy{
		ID:        parts[0],
		TenantID:  parts[1],
		Effect:    Effect(parts[2]),
		Actions:   parseList(parts[3]),
		Resources: strings.Split(parts[4], ","),
		Condition: parseCondition(parts[5]),
		Priority:  0,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	for _, opt := range parts[6:] {
		if strings.HasPrefix(opt, "priority:") {
			pol.Priority, _ = strconv.Atoi(opt[9:])
		}
	}

	cfg.Policies = append(cfg.Policies, pol)
	return nil
}

func (p *DSLParser) parseRole(cfg *Config, parts []string) error {
	if len(parts) < 4 {
		return fmt.Errorf("role requires: <id> <tenant> <name> <perms> [inherits:<roles>] [owner:<actions>]")
	}

	role := &Role{
		ID:                  parts[0],
		TenantID:            parts[1],
		Name:                parts[2],
		Permissions:         parsePermissions(parts[3]),
		OwnerAllowedActions: []Action{},
		Inherits:            []string{},
		CreatedAt:           time.Now(),
	}

	for _, opt := range parts[4:] {
		if strings.HasPrefix(opt, "inherits:") {
			role.Inherits = strings.Split(opt[9:], ",")
		} else if strings.HasPrefix(opt, "owner:") {
			for _, a := range strings.Split(opt[6:], ",") {
				role.OwnerAllowedActions = append(role.OwnerAllowedActions, Action(a))
			}
		}
	}

	cfg.Roles = append(cfg.Roles, role)
	return nil
}

func (p *DSLParser) parseACL(cfg *Config, parts []string) error {
	if len(parts) < 5 {
		return fmt.Errorf("acl requires: <id> <resource> <subject> <actions> <effect> [expires:<time>]")
	}

	acl := &ACL{
		ID:         parts[0],
		ResourceID: parts[1],
		SubjectID:  parts[2],
		Actions:    parseList(parts[3]),
		Effect:     Effect(parts[4]),
		CreatedAt:  time.Now(),
	}

	for _, opt := range parts[5:] {
		if strings.HasPrefix(opt, "expires:") {
			acl.ExpiresAt, _ = time.Parse(time.RFC3339, opt[8:])
		}
	}

	cfg.ACLs = append(cfg.ACLs, acl)
	return nil
}

func (p *DSLParser) parseMember(cfg *Config, parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("member requires: <subject> <role>")
	}
	cfg.Memberships = append(cfg.Memberships, RoleMembership{
		SubjectID: parts[0],
		RoleID:    parts[1],
	})
	return nil
}

func (p *DSLParser) parseEngine(cfg *Config, parts []string) error {
	for _, kv := range parts {
		idx := strings.Index(kv, "=")
		if idx == -1 {
			continue
		}
		key, val := kv[:idx], kv[idx+1:]
		switch key {
		case "cache_ttl":
			cfg.Engine.DecisionCacheTTL, _ = strconv.ParseInt(val, 10, 64)
		case "attr_ttl":
			cfg.Engine.AttributeCacheTTL, _ = strconv.ParseInt(val, 10, 64)
		case "batch_size":
			cfg.Engine.AuditBatchSize, _ = strconv.Atoi(val)
		case "flush_interval":
			cfg.Engine.AuditFlushInterval, _ = strconv.ParseInt(val, 10, 64)
		case "workers":
			cfg.Engine.BatchWorkerCount, _ = strconv.Atoi(val)
		}
	}
	return nil
}


func parseList(s string) []Action {
	if s == "" {
		return nil
	}
	if s == "*" {
		return []Action{"*"}
	}
	count := 1
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			count++
		}
	}
	actions := make([]Action, 0, count)
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				actions = append(actions, Action(s[start:i]))
			}
			start = i + 1
		}
	}
	return actions
}

func parsePermissions(s string) []Permission {
	if s == "" {
		return nil
	}
	count := 1
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			count++
		}
	}
	perms := make([]Permission, 0, count)
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				part := s[start:i]
				for j := 0; j < len(part); j++ {
					if part[j] == ':' {
						perms = append(perms, Permission{
							Action:   Action(part[:j]),
							Resource: part[j+1:],
						})
						break
					}
				}
			}
			start = i + 1
		}
	}
	return perms
}

func parseCondition(s string) Expr {
	if s == "" || s == "true" {
		return &TrueExpr{}
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return &EqExpr{Field: s[:i], Value: s[i+1:]}
		}
		if s[i] == '@' {
			count := 1
			for j := i + 1; j < len(s); j++ {
				if s[j] == ',' {
					count++
				}
			}
			values := make([]any, 0, count)
			start := i + 1
			for j := i + 1; j <= len(s); j++ {
				if j == len(s) || s[j] == ',' {
					if j > start {
						values = append(values, s[start:j])
					}
					start = j + 1
				}
			}
			return &InExpr{Field: s[:i], Values: values}
		}
	}
	return &TrueExpr{}
}

// Binary Protocol V2 - Compact format
const (
	protoMagic   = 0x415A4332 // "AZC2"
	protoVersion = 2
)

type BinaryEncoder struct {
	buf *bytes.Buffer
}

func NewBinaryEncoder() *BinaryEncoder {
	return &BinaryEncoder{buf: &bytes.Buffer{}}
}

func (e *BinaryEncoder) Encode(cfg *Config) ([]byte, error) {
	binary.Write(e.buf, binary.LittleEndian, uint32(protoMagic))
	binary.Write(e.buf, binary.LittleEndian, uint16(protoVersion))
	binary.Write(e.buf, binary.LittleEndian, cfg.Version)

	e.writeSection(1, func() { e.encodeTenants(cfg.Tenants) })
	e.writeSection(2, func() { e.encodePolicies(cfg.Policies) })
	e.writeSection(3, func() { e.encodeRoles(cfg.Roles) })
	e.writeSection(4, func() { e.encodeACLs(cfg.ACLs) })
	e.writeSection(5, func() { e.encodeMemberships(cfg.Memberships) })
	e.writeSection(6, func() { e.encodeEngine(&cfg.Engine) })
	e.writeSection(7, func() { e.encodeHierarchy(cfg.Hierarchy) })

	return e.buf.Bytes(), nil
}

func (e *BinaryEncoder) writeSection(tag byte, fn func()) {
	tmp := &bytes.Buffer{}
	oldBuf := e.buf
	e.buf = tmp
	fn()
	e.buf = oldBuf
	e.buf.WriteByte(tag)
	binary.Write(e.buf, binary.LittleEndian, uint32(tmp.Len()))
	e.buf.Write(tmp.Bytes())
}

func (e *BinaryEncoder) writeStr(s string) {
	binary.Write(e.buf, binary.LittleEndian, uint16(len(s)))
	e.buf.WriteString(s)
}

func (e *BinaryEncoder) encodeTenants(tenants []TenantConfig) {
	binary.Write(e.buf, binary.LittleEndian, uint16(len(tenants)))
	for _, t := range tenants {
		e.writeStr(t.ID)
		e.writeStr(t.Name)
		e.writeStr(t.Parent)
	}
}

func (e *BinaryEncoder) encodePolicies(policies []*Policy) {
	binary.Write(e.buf, binary.LittleEndian, uint16(len(policies)))
	for _, p := range policies {
		e.writeStr(p.ID)
		e.writeStr(p.TenantID)
		e.buf.WriteByte(map[Effect]byte{EffectAllow: 1, EffectDeny: 2}[p.Effect])
		binary.Write(e.buf, binary.LittleEndian, uint8(len(p.Actions)))
		for _, a := range p.Actions {
			e.writeStr(string(a))
		}
		binary.Write(e.buf, binary.LittleEndian, uint8(len(p.Resources)))
		for _, r := range p.Resources {
			e.writeStr(r)
		}
		e.writeStr(p.Condition.String())
		binary.Write(e.buf, binary.LittleEndian, int16(p.Priority))
		if p.Enabled {
			e.buf.WriteByte(1)
		} else {
			e.buf.WriteByte(0)
		}
	}
}

func (e *BinaryEncoder) encodeRoles(roles []*Role) {
	binary.Write(e.buf, binary.LittleEndian, uint16(len(roles)))
	for _, r := range roles {
		e.writeStr(r.ID)
		e.writeStr(r.TenantID)
		e.writeStr(r.Name)
		binary.Write(e.buf, binary.LittleEndian, uint8(len(r.Permissions)))
		for _, p := range r.Permissions {
			e.writeStr(string(p.Action))
			e.writeStr(p.Resource)
		}
		binary.Write(e.buf, binary.LittleEndian, uint8(len(r.OwnerAllowedActions)))
		for _, a := range r.OwnerAllowedActions {
			e.writeStr(string(a))
		}
		binary.Write(e.buf, binary.LittleEndian, uint8(len(r.Inherits)))
		for _, i := range r.Inherits {
			e.writeStr(i)
		}
	}
}

func (e *BinaryEncoder) encodeACLs(acls []*ACL) {
	binary.Write(e.buf, binary.LittleEndian, uint16(len(acls)))
	for _, a := range acls {
		e.writeStr(a.ID)
		e.writeStr(a.ResourceID)
		e.writeStr(a.SubjectID)
		binary.Write(e.buf, binary.LittleEndian, uint8(len(a.Actions)))
		for _, act := range a.Actions {
			e.writeStr(string(act))
		}
		e.buf.WriteByte(map[Effect]byte{EffectAllow: 1, EffectDeny: 2}[a.Effect])
		binary.Write(e.buf, binary.LittleEndian, a.ExpiresAt.Unix())
	}
}

func (e *BinaryEncoder) encodeMemberships(memberships []RoleMembership) {
	binary.Write(e.buf, binary.LittleEndian, uint16(len(memberships)))
	for _, m := range memberships {
		e.writeStr(m.SubjectID)
		e.writeStr(m.RoleID)
	}
}

func (e *BinaryEncoder) encodeEngine(cfg *EngineConfig) {
	binary.Write(e.buf, binary.LittleEndian, cfg.DecisionCacheTTL)
	binary.Write(e.buf, binary.LittleEndian, cfg.AttributeCacheTTL)
	binary.Write(e.buf, binary.LittleEndian, int32(cfg.AuditBatchSize))
	binary.Write(e.buf, binary.LittleEndian, cfg.AuditFlushInterval)
	binary.Write(e.buf, binary.LittleEndian, int32(cfg.BatchWorkerCount))
}

func (e *BinaryEncoder) encodeHierarchy(hierarchy map[string]string) {
	binary.Write(e.buf, binary.LittleEndian, uint16(len(hierarchy)))
	for child, parent := range hierarchy {
		e.writeStr(child)
		e.writeStr(parent)
	}
}

type BinaryDecoder struct {
	r *bytes.Reader
}

func NewBinaryDecoder(data []byte) *BinaryDecoder {
	return &BinaryDecoder{r: bytes.NewReader(data)}
}

func (d *BinaryDecoder) Decode() (*Config, error) {
	var magic uint32
	var ver, cfgVer uint16
	binary.Read(d.r, binary.LittleEndian, &magic)
	binary.Read(d.r, binary.LittleEndian, &ver)
	binary.Read(d.r, binary.LittleEndian, &cfgVer)

	if magic != protoMagic {
		return nil, fmt.Errorf("invalid magic: %x", magic)
	}

	cfg := &Config{Version: cfgVer, Hierarchy: make(map[string]string)}

	for {
		var tag byte
		if err := binary.Read(d.r, binary.LittleEndian, &tag); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		var size uint32
		binary.Read(d.r, binary.LittleEndian, &size)
		data := make([]byte, size)
		io.ReadFull(d.r, data)
		dr := bytes.NewReader(data)

		switch tag {
		case 1:
			cfg.Tenants = d.decodeTenants(dr)
		case 2:
			cfg.Policies = d.decodePolicies(dr)
		case 3:
			cfg.Roles = d.decodeRoles(dr)
		case 4:
			cfg.ACLs = d.decodeACLs(dr)
		case 5:
			cfg.Memberships = d.decodeMemberships(dr)
		case 6:
			cfg.Engine = d.decodeEngine(dr)
		case 7:
			cfg.Hierarchy = d.decodeHierarchy(dr)
		}
	}

	return cfg, nil
}

func (d *BinaryDecoder) readStr(r *bytes.Reader) string {
	var l uint16
	binary.Read(r, binary.LittleEndian, &l)
	b := make([]byte, l)
	r.Read(b)
	return string(b)
}

func (d *BinaryDecoder) decodeTenants(r *bytes.Reader) []TenantConfig {
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	tenants := make([]TenantConfig, count)
	for i := range tenants {
		tenants[i].ID = d.readStr(r)
		tenants[i].Name = d.readStr(r)
		tenants[i].Parent = d.readStr(r)
	}
	return tenants
}

func (d *BinaryDecoder) decodePolicies(r *bytes.Reader) []*Policy {
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	policies := make([]*Policy, count)
	for i := range policies {
		p := &Policy{}
		p.ID = d.readStr(r)
		p.TenantID = d.readStr(r)
		eff, _ := r.ReadByte()
		p.Effect = map[byte]Effect{1: EffectAllow, 2: EffectDeny}[eff]
		var actCount uint8
		binary.Read(r, binary.LittleEndian, &actCount)
		p.Actions = make([]Action, actCount)
		for j := range p.Actions {
			p.Actions[j] = Action(d.readStr(r))
		}
		var resCount uint8
		binary.Read(r, binary.LittleEndian, &resCount)
		p.Resources = make([]string, resCount)
		for j := range p.Resources {
			p.Resources[j] = d.readStr(r)
		}
		p.Condition = parseCondition(d.readStr(r))
		var pri int16
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

func (d *BinaryDecoder) decodeRoles(r *bytes.Reader) []*Role {
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	roles := make([]*Role, count)
	for i := range roles {
		role := &Role{}
		role.ID = d.readStr(r)
		role.TenantID = d.readStr(r)
		role.Name = d.readStr(r)
		var permCount uint8
		binary.Read(r, binary.LittleEndian, &permCount)
		role.Permissions = make([]Permission, permCount)
		for j := range role.Permissions {
			role.Permissions[j].Action = Action(d.readStr(r))
			role.Permissions[j].Resource = d.readStr(r)
		}
		var oaaCount uint8
		binary.Read(r, binary.LittleEndian, &oaaCount)
		role.OwnerAllowedActions = make([]Action, oaaCount)
		for j := range role.OwnerAllowedActions {
			role.OwnerAllowedActions[j] = Action(d.readStr(r))
		}
		var inhCount uint8
		binary.Read(r, binary.LittleEndian, &inhCount)
		role.Inherits = make([]string, inhCount)
		for j := range role.Inherits {
			role.Inherits[j] = d.readStr(r)
		}
		role.CreatedAt = time.Now()
		roles[i] = role
	}
	return roles
}

func (d *BinaryDecoder) decodeACLs(r *bytes.Reader) []*ACL {
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	acls := make([]*ACL, count)
	for i := range acls {
		acl := &ACL{}
		acl.ID = d.readStr(r)
		acl.ResourceID = d.readStr(r)
		acl.SubjectID = d.readStr(r)
		var actCount uint8
		binary.Read(r, binary.LittleEndian, &actCount)
		acl.Actions = make([]Action, actCount)
		for j := range acl.Actions {
			acl.Actions[j] = Action(d.readStr(r))
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

func (d *BinaryDecoder) decodeMemberships(r *bytes.Reader) []RoleMembership {
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	memberships := make([]RoleMembership, count)
	for i := range memberships {
		memberships[i].SubjectID = d.readStr(r)
		memberships[i].RoleID = d.readStr(r)
	}
	return memberships
}

func (d *BinaryDecoder) decodeEngine(r *bytes.Reader) EngineConfig {
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
	return cfg
}

func (d *BinaryDecoder) decodeHierarchy(r *bytes.Reader) map[string]string {
	var count uint16
	binary.Read(r, binary.LittleEndian, &count)
	hierarchy := make(map[string]string, count)
	for i := 0; i < int(count); i++ {
		child := d.readStr(r)
		parent := d.readStr(r)
		hierarchy[child] = parent
	}
	return hierarchy
}
