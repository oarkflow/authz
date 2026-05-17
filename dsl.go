package authz

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// DSL Syntax:
// tenant <id> <name> [parent:<parent_id>]
// policy <id> <tenant> <effect> <actions> <resources> <condition> [priority:<n>]
// role <id> <tenant> <name> <perms> [inherits:<roles>] [owner:<actions>]
// acl <id> <resource> <subject> <actions> <effect> [expires:<time>]
// member <subject> <role>
// engine <key>=<value>...

type DSLParser struct {
	line         int
	strict       bool
	zeroCopy     bool
	baseDir      string
	includeSet   map[string]bool
	now          time.Time
	partsScratch []string
	lastCondText string
	lastCondExpr Expr
	policyValues []Policy
	roleValues   []Role
	aclValues    []ACL
	actionValues []Action
	stringValues []string
	permValues   []Permission
	policyIndex  int
	roleIndex    int
	aclIndex     int
	actionIndex  int
	stringIndex  int
	permIndex    int
}

func NewDSLParser() *DSLParser {
	return &DSLParser{strict: true, zeroCopy: true}
}

func NewPermissiveDSLParser() *DSLParser {
	return &DSLParser{strict: false, zeroCopy: true}
}

func (p *DSLParser) SetStrict(strict bool) *DSLParser {
	p.strict = strict
	return p
}

func (p *DSLParser) SetZeroCopy(zeroCopy bool) *DSLParser {
	p.zeroCopy = zeroCopy
	return p
}

func (p *DSLParser) ParseCopy(data []byte) (*Config, error) {
	copied := append([]byte(nil), data...)
	oldZeroCopy := p.zeroCopy
	p.zeroCopy = true
	cfg, err := p.Parse(copied)
	p.zeroCopy = oldZeroCopy
	return cfg, err
}

func (p *DSLParser) ParseFile(filename string) (*Config, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	p.includeSet = make(map[string]bool)
	return p.parseFile(abs)
}

func (p *DSLParser) parseFile(filename string) (*Config, error) {
	if p.includeSet[filename] {
		return nil, fmt.Errorf("include cycle detected at %s", filename)
	}
	p.includeSet[filename] = true
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	oldState := p.saveState()
	p.baseDir = filepath.Dir(filename)
	cfg, err := p.Parse(data)
	p.restoreState(oldState)
	delete(p.includeSet, filename)
	return cfg, err
}

type dslParserState struct {
	line         int
	baseDir      string
	now          time.Time
	partsScratch []string
	lastCondText string
	lastCondExpr Expr
	policyValues []Policy
	roleValues   []Role
	aclValues    []ACL
	actionValues []Action
	stringValues []string
	permValues   []Permission
	policyIndex  int
	roleIndex    int
	aclIndex     int
	actionIndex  int
	stringIndex  int
	permIndex    int
}

func (p *DSLParser) saveState() dslParserState {
	return dslParserState{
		line:         p.line,
		baseDir:      p.baseDir,
		now:          p.now,
		partsScratch: p.partsScratch,
		lastCondText: p.lastCondText,
		lastCondExpr: p.lastCondExpr,
		policyValues: p.policyValues,
		roleValues:   p.roleValues,
		aclValues:    p.aclValues,
		actionValues: p.actionValues,
		stringValues: p.stringValues,
		permValues:   p.permValues,
		policyIndex:  p.policyIndex,
		roleIndex:    p.roleIndex,
		aclIndex:     p.aclIndex,
		actionIndex:  p.actionIndex,
		stringIndex:  p.stringIndex,
		permIndex:    p.permIndex,
	}
}

func (p *DSLParser) restoreState(s dslParserState) {
	p.line = s.line
	p.baseDir = s.baseDir
	p.now = s.now
	p.partsScratch = s.partsScratch
	p.lastCondText = s.lastCondText
	p.lastCondExpr = s.lastCondExpr
	p.policyValues = s.policyValues
	p.roleValues = s.roleValues
	p.aclValues = s.aclValues
	p.actionValues = s.actionValues
	p.stringValues = s.stringValues
	p.permValues = s.permValues
	p.policyIndex = s.policyIndex
	p.roleIndex = s.roleIndex
	p.aclIndex = s.aclIndex
	p.actionIndex = s.actionIndex
	p.stringIndex = s.stringIndex
	p.permIndex = s.permIndex
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
		e.buf = append(e.buf, '"')
		e.buf = append(e.buf, t.ID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, t.Name...)
		e.buf = append(e.buf, '"')
		if t.Parent != "" {
			e.buf = append(e.buf, " parent:\""...)
			e.buf = append(e.buf, t.Parent...)
			e.buf = append(e.buf, '"')
		}
		e.buf = append(e.buf, '\n')
	}

	for _, p := range cfg.Policies {
		e.buf = append(e.buf, "policy "...)
		e.buf = append(e.buf, '"')
		e.buf = append(e.buf, p.ID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, p.TenantID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, string(p.Effect)...)
		e.buf = append(e.buf, `" "`...)
		actionsStr := ""
		for i, a := range p.Actions {
			if i > 0 {
				actionsStr += ","
			}
			actionsStr += string(a)
		}
		e.buf = append(e.buf, actionsStr...)
		e.buf = append(e.buf, `" "`...)
		resourcesStr := ""
		for i, r := range p.Resources {
			if i > 0 {
				resourcesStr += ","
			}
			resourcesStr += r
		}
		e.buf = append(e.buf, resourcesStr...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, conditionToDSL(p.Condition)...)
		e.buf = append(e.buf, '"')
		if p.Priority != 0 {
			e.buf = append(e.buf, " priority:"...)
			n := strconv.AppendInt(tmp[:0], int64(p.Priority), 10)
			e.buf = append(e.buf, n...)
		}
		e.buf = append(e.buf, '\n')
	}

	for _, r := range cfg.Roles {
		e.buf = append(e.buf, "role "...)
		e.buf = append(e.buf, '"')
		e.buf = append(e.buf, r.ID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, r.TenantID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, r.Name...)
		e.buf = append(e.buf, `" "`...)
		permsStr := ""
		for i, p := range r.Permissions {
			if i > 0 {
				permsStr += ","
			}
			permsStr += string(p.Action) + ":" + p.Resource
		}
		e.buf = append(e.buf, permsStr...)
		e.buf = append(e.buf, '"')
		if len(r.Inherits) > 0 {
			e.buf = append(e.buf, " inherits:\""...)
			for i, inh := range r.Inherits {
				if i > 0 {
					e.buf = append(e.buf, ',')
				}
				e.buf = append(e.buf, inh...)
			}
			e.buf = append(e.buf, '"')
		}
		if len(r.OwnerAllowedActions) > 0 {
			e.buf = append(e.buf, " owner:\""...)
			for i, a := range r.OwnerAllowedActions {
				if i > 0 {
					e.buf = append(e.buf, ',')
				}
				e.buf = append(e.buf, string(a)...)
			}
			e.buf = append(e.buf, '"')
		}
		e.buf = append(e.buf, '\n')
	}

	for _, acl := range cfg.ACLs {
		e.buf = append(e.buf, "acl "...)
		e.buf = append(e.buf, '"')
		e.buf = append(e.buf, acl.ID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, acl.ResourceID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, acl.SubjectID...)
		e.buf = append(e.buf, `" "`...)
		actionsStr := ""
		for i, a := range acl.Actions {
			if i > 0 {
				actionsStr += ","
			}
			actionsStr += string(a)
		}
		e.buf = append(e.buf, actionsStr...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, string(acl.Effect)...)
		e.buf = append(e.buf, '"')
		if !acl.ExpiresAt.IsZero() {
			e.buf = append(e.buf, " expires:\""...)
			e.buf = append(e.buf, acl.ExpiresAt.Format(time.RFC3339)...)
			e.buf = append(e.buf, '"')
		}
		e.buf = append(e.buf, '\n')
	}

	for _, m := range cfg.Memberships {
		e.buf = append(e.buf, "member "...)
		e.buf = append(e.buf, '"')
		e.buf = append(e.buf, m.SubjectID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, m.RoleID...)
		e.buf = append(e.buf, "\"\n"...)
	}

	for _, u := range cfg.Users {
		e.buf = append(e.buf, "user \""...)
		e.buf = append(e.buf, u.ID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, u.TenantID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, u.Email...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, u.Name...)
		e.buf = append(e.buf, '"')
		if u.Status != "" && u.Status != UserStatusActive {
			e.buf = append(e.buf, " status:"...)
			e.buf = append(e.buf, string(u.Status)...)
		}
		e.buf = append(e.buf, '\n')
	}
	for _, g := range cfg.Groups {
		e.buf = append(e.buf, "group \""...)
		e.buf = append(e.buf, g.ID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, g.TenantID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, g.Name...)
		e.buf = append(e.buf, '"')
		if g.ParentID != "" {
			e.buf = append(e.buf, " parent:"...)
			e.buf = append(e.buf, g.ParentID...)
		}
		e.buf = append(e.buf, '\n')
	}
	for _, s := range cfg.Scopes {
		e.buf = append(e.buf, "scope \""...)
		e.buf = append(e.buf, s.ID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, s.TenantID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, s.Name...)
		e.buf = append(e.buf, '"')
		if s.ParentID != "" {
			e.buf = append(e.buf, " parent:"...)
			e.buf = append(e.buf, s.ParentID...)
		}
		e.buf = append(e.buf, '\n')
	}
	for _, b := range cfg.PermissionBoundaries {
		e.buf = append(e.buf, "boundary \""...)
		e.buf = append(e.buf, b.ID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, b.TenantID...)
		e.buf = append(e.buf, `" "`...)
		e.buf = append(e.buf, b.Name...)
		e.buf = append(e.buf, `" "`...)
		for i, a := range b.MaxActions {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			e.buf = append(e.buf, string(a)...)
		}
		e.buf = append(e.buf, `" "`...)
		for i, r := range b.MaxResources {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			e.buf = append(e.buf, r...)
		}
		e.buf = append(e.buf, "\"\n"...)
	}

	if cfg.Engine.DecisionCacheTTL > 0 || cfg.Engine.AttributeCacheTTL > 0 || cfg.Engine.AuditBatchSize > 0 || cfg.Engine.AuditFlushInterval > 0 || cfg.Engine.BatchWorkerCount > 0 {
		e.buf = append(e.buf, "engine"...)
		if cfg.Engine.DecisionCacheTTL > 0 {
			e.buf = append(e.buf, " cache_ttl=\""...)
			n := strconv.AppendInt(tmp[:0], cfg.Engine.DecisionCacheTTL, 10)
			e.buf = append(e.buf, n...)
			e.buf = append(e.buf, '"')
		}
		if cfg.Engine.AttributeCacheTTL > 0 {
			e.buf = append(e.buf, " attr_ttl=\""...)
			n := strconv.AppendInt(tmp[:0], cfg.Engine.AttributeCacheTTL, 10)
			e.buf = append(e.buf, n...)
			e.buf = append(e.buf, '"')
		}
		if cfg.Engine.AuditBatchSize > 0 {
			e.buf = append(e.buf, " batch_size=\""...)
			n := strconv.AppendInt(tmp[:0], int64(cfg.Engine.AuditBatchSize), 10)
			e.buf = append(e.buf, n...)
			e.buf = append(e.buf, '"')
		}
		if cfg.Engine.AuditFlushInterval > 0 {
			e.buf = append(e.buf, " flush_interval=\""...)
			n := strconv.AppendInt(tmp[:0], cfg.Engine.AuditFlushInterval, 10)
			e.buf = append(e.buf, n...)
			e.buf = append(e.buf, '"')
		}
		if cfg.Engine.BatchWorkerCount > 0 {
			e.buf = append(e.buf, " workers=\""...)
			n := strconv.AppendInt(tmp[:0], int64(cfg.Engine.BatchWorkerCount), 10)
			e.buf = append(e.buf, n...)
			e.buf = append(e.buf, '"')
		}
		e.buf = append(e.buf, '\n')
	}

	return e.buf, nil
}

func (p *DSLParser) Parse(data []byte) (*Config, error) {
	counts := countDSLDirectives(data)
	cfg := &Config{
		Version:     1,
		Tenants:     make([]TenantConfig, 0, counts.tenants),
		Policies:    make([]*Policy, 0, counts.policies),
		Roles:       make([]*Role, 0, counts.roles),
		ACLs:        make([]*ACL, 0, counts.acls),
		Memberships: make([]RoleMembership, 0, counts.members),
		Engine:      EngineConfig{DecisionCacheTTL: 1000, AuditBatchSize: 64},
	}

	p.line = 0
	p.now = time.Now()
	p.lastCondText = ""
	p.lastCondExpr = nil
	p.policyValues = make([]Policy, counts.policies)
	p.roleValues = make([]Role, counts.roles)
	p.aclValues = make([]ACL, counts.acls)
	p.actionValues = make([]Action, counts.actionItems)
	p.stringValues = make([]string, counts.stringItems)
	p.permValues = make([]Permission, counts.permissionItems)
	p.policyIndex = 0
	p.roleIndex = 0
	p.aclIndex = 0
	p.actionIndex = 0
	p.stringIndex = 0
	p.permIndex = 0
	lines := bytes.Split(data, []byte{'\n'})
	for i := 0; i < len(lines); i++ {
		p.line = i + 1
		line := trimDSLLine(lines[i])
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		parts, err := p.splitLineBytes(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", p.line, err)
		}
		if len(parts) == 0 {
			continue
		}

		if isTopLevelBlockStart(parts) {
			header := append([]string(nil), parts[:len(parts)-1]...)
			body, next, err := p.collectBlock(lines, i)
			if err != nil {
				return nil, err
			}
			if err := p.parseDirectiveBlock(cfg, header, body); err != nil {
				return nil, fmt.Errorf("line %d: %w", p.line, err)
			}
			i = next
			continue
		}

		if err := p.parseDirective(cfg, parts); err != nil {
			return nil, fmt.Errorf("line %d: %w", p.line, err)
		}
	}

	return cfg, nil
}

func trimDSLLine(line []byte) []byte {
	for len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
		line = line[1:]
	}
	for len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}

func isTopLevelBlockStart(parts []string) bool {
	return len(parts) >= 2 && parts[len(parts)-1] == "{"
}

func (p *DSLParser) parseDirective(cfg *Config, parts []string) error {
	switch parts[0] {
	case "include":
		return p.parseInclude(cfg, parts[1:])
	case "tenant":
		return p.parseTenant(cfg, parts[1:])
	case "policy":
		return p.parsePolicy(cfg, parts[1:])
	case "role":
		return p.parseRole(cfg, parts[1:])
	case "acl":
		return p.parseACL(cfg, parts[1:])
	case "member":
		return p.parseMember(cfg, parts[1:])
	case "engine":
		return p.parseEngine(cfg, parts[1:])
	case "user":
		return p.parseUser(cfg, parts[1:])
	case "group":
		return p.parseGroup(cfg, parts[1:])
	case "scope":
		return p.parseScope(cfg, parts[1:])
	case "service_account":
		return p.parseServiceAccount(cfg, parts[1:])
	case "invitation":
		return p.parseInvitation(cfg, parts[1:])
	case "api_key":
		return p.parseAPIKey(cfg, parts[1:])
	case "boundary":
		return p.parseBoundary(cfg, parts[1:])
	default:
		return fmt.Errorf("unknown directive: %s", parts[0])
	}
}

type dslBlockLine struct {
	line int
	text []byte
}

func (p *DSLParser) collectBlock(lines [][]byte, start int) ([]dslBlockLine, int, error) {
	depth := dslBraceDelta(lines[start])
	if depth <= 0 {
		return nil, start, fmt.Errorf("line %d: malformed block start", start+1)
	}
	body := make([]dslBlockLine, 0, 8)
	for i := start + 1; i < len(lines); i++ {
		line := trimDSLLine(lines[i])
		oldDepth := depth
		depth += dslBraceDelta(line)
		if oldDepth == 1 && depth == 0 && isDSLClosingBraceLine(line) {
			return body, i, nil
		}
		body = append(body, dslBlockLine{line: i + 1, text: line})
		if depth < 0 {
			return nil, i, fmt.Errorf("line %d: unexpected block close", i+1)
		}
	}
	return nil, start, fmt.Errorf("line %d: unterminated block", start+1)
}

func dslBraceDelta(line []byte) int {
	var quote byte
	delta := 0
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '#' && quote == 0 {
			break
		}
		if (ch == '"' || ch == '\'' || ch == '`') && quote == 0 {
			quote = ch
			continue
		}
		if ch == quote {
			quote = 0
			continue
		}
		if quote != 0 {
			continue
		}
		switch ch {
		case '{':
			delta++
		case '}':
			delta--
		}
	}
	return delta
}

func isDSLClosingBraceLine(line []byte) bool {
	parts, err := splitLineBytes(line)
	return err == nil && len(parts) == 1 && parts[0] == "}"
}

func (p *DSLParser) parseDirectiveBlock(cfg *Config, header []string, body []dslBlockLine) error {
	if len(header) == 0 {
		return fmt.Errorf("missing block directive")
	}
	switch header[0] {
	case "tenant":
		return p.parseTenantBlock(cfg, header[1:], body)
	case "policy":
		return p.parsePolicyBlock(cfg, header[1:], body)
	case "role":
		return p.parseRoleBlock(cfg, header[1:], body)
	case "acl":
		return p.parseACLBlock(cfg, header[1:], body)
	case "member":
		return p.parseMemberBlock(cfg, header[1:], body)
	case "members":
		if len(header) != 1 {
			return fmt.Errorf("members block does not take an id")
		}
		return p.parseMembersBlock(cfg, body)
	case "engine":
		if len(header) != 1 {
			return fmt.Errorf("engine block does not take an id")
		}
		return p.parseEngineBlock(cfg, body)
	default:
		return fmt.Errorf("unknown block directive: %s", header[0])
	}
}

func (p *DSLParser) parseTenantBlock(cfg *Config, header []string, body []dslBlockLine) error {
	if len(header) != 1 {
		return fmt.Errorf("tenant block requires: tenant <id> { ... }")
	}
	fields, err := p.parseBlockFields(body)
	if err != nil {
		return err
	}
	t := TenantConfig{ID: parseQuotedString(header[0]), Name: fields.one("name")}
	if t.Name == "" {
		t.Name = t.ID
	}
	t.Parent = fields.one("parent")
	if t.Parent != "" {
		if cfg.Hierarchy == nil {
			cfg.Hierarchy = make(map[string]string, 4)
		}
		cfg.Hierarchy[t.ID] = t.Parent
	}
	cfg.Tenants = append(cfg.Tenants, t)
	return nil
}

func (p *DSLParser) parsePolicyBlock(cfg *Config, header []string, body []dslBlockLine) error {
	if len(header) != 1 {
		return fmt.Errorf("policy block requires: policy <id> { ... }")
	}
	fields, err := p.parseBlockFields(body)
	if err != nil {
		return err
	}
	effect := Effect(fields.one("effect"))
	if p.strict && !validEffect(effect) {
		return fmt.Errorf("invalid policy effect: %s", effect)
	}
	actions, err := p.actionsFromValues(fields.list("actions"))
	if err != nil {
		return fmt.Errorf("invalid policy actions: %w", err)
	}
	resources := fields.list("resources")
	if p.strict && len(resources) == 0 {
		return fmt.Errorf("invalid policy resources: empty list")
	}
	conditionText := fields.blockText("when")
	if conditionText == "" {
		conditionText = fields.one("condition")
	}
	condition, err := p.parseCondition(conditionText)
	if err != nil {
		return fmt.Errorf("invalid policy condition: %w", err)
	}

	pol := p.nextPolicy()
	*pol = Policy{
		ID:        parseQuotedString(header[0]),
		TenantID:  fields.one("tenant"),
		Effect:    effect,
		Actions:   actions,
		Resources: resources,
		Condition: condition,
		Enabled:   true,
		CreatedAt: p.now,
		UpdatedAt: p.now,
	}
	if priority := fields.one("priority"); priority != "" {
		n, err := strconv.Atoi(priority)
		if err != nil {
			if p.strict {
				return fmt.Errorf("invalid priority: %s", priority)
			}
		} else {
			pol.Priority = n
		}
	}
	cfg.Policies = append(cfg.Policies, pol)
	return nil
}

func (p *DSLParser) parseRoleBlock(cfg *Config, header []string, body []dslBlockLine) error {
	if len(header) != 1 {
		return fmt.Errorf("role block requires: role <id> { ... }")
	}
	fields, err := p.parseBlockFields(body)
	if err != nil {
		return err
	}
	perms, err := p.permissionsFromValues(fields.list("permissions"))
	if err != nil {
		return fmt.Errorf("invalid role permissions: %w", err)
	}
	role := p.nextRole()
	*role = Role{
		ID:                  parseQuotedString(header[0]),
		TenantID:            fields.one("tenant"),
		Name:                fields.one("name"),
		Permissions:         perms,
		OwnerAllowedActions: []Action{},
		Inherits:            fields.list("inherits"),
		CreatedAt:           p.now,
	}
	if role.Name == "" {
		role.Name = role.ID
	}
	if fields.has("owner_actions") {
		ownerActions, err := p.actionsFromValues(fields.list("owner_actions"))
		if err != nil {
			return fmt.Errorf("invalid owner_actions: %w", err)
		}
		role.OwnerAllowedActions = ownerActions
	}
	cfg.Roles = append(cfg.Roles, role)
	return nil
}

func (p *DSLParser) parseACLBlock(cfg *Config, header []string, body []dslBlockLine) error {
	if len(header) != 1 {
		return fmt.Errorf("acl block requires: acl <id> { ... }")
	}
	fields, err := p.parseBlockFields(body)
	if err != nil {
		return err
	}
	effect := Effect(fields.one("effect"))
	if p.strict && !validEffect(effect) {
		return fmt.Errorf("invalid acl effect: %s", effect)
	}
	actions, err := p.actionsFromValues(fields.list("actions"))
	if err != nil {
		return fmt.Errorf("invalid acl actions: %w", err)
	}
	acl := p.nextACL()
	*acl = ACL{
		ID:         parseQuotedString(header[0]),
		ResourceID: fields.one("resource"),
		SubjectID:  fields.one("subject"),
		TenantID:   fields.one("tenant"),
		Actions:    actions,
		Effect:     effect,
		CreatedAt:  p.now,
	}
	if expiresText := fields.one("expires"); expiresText != "" {
		expires, err := time.Parse(time.RFC3339, expiresText)
		if err != nil {
			if p.strict {
				return fmt.Errorf("invalid expires timestamp: %s", expiresText)
			}
		} else {
			acl.ExpiresAt = expires
		}
	}
	cfg.ACLs = append(cfg.ACLs, acl)
	return nil
}

func (p *DSLParser) parseMemberBlock(cfg *Config, header []string, body []dslBlockLine) error {
	if len(header) != 1 {
		return fmt.Errorf("member block requires: member <subject> { ... }")
	}
	fields, err := p.parseBlockFields(body)
	if err != nil {
		return err
	}
	for _, role := range fields.list("roles") {
		cfg.Memberships = append(cfg.Memberships, RoleMembership{SubjectID: parseQuotedString(header[0]), RoleID: role})
	}
	return nil
}

func (p *DSLParser) parseMembersBlock(cfg *Config, body []dslBlockLine) error {
	for _, line := range body {
		text := trimDSLLine(line.text)
		if len(text) == 0 || text[0] == '#' {
			continue
		}
		parts, err := p.splitLineBytes(text)
		if err != nil {
			return fmt.Errorf("line %d: %w", line.line, err)
		}
		if len(parts) < 2 {
			return fmt.Errorf("line %d: member row requires: <subject> [roles]", line.line)
		}
		subjectID := parseQuotedString(parts[0])
		roles, err := p.parseBlockListTokens(parts[1:])
		if err != nil {
			return fmt.Errorf("line %d: invalid member roles: %w", line.line, err)
		}
		for _, role := range roles {
			cfg.Memberships = append(cfg.Memberships, RoleMembership{SubjectID: subjectID, RoleID: role})
		}
	}
	return nil
}

func (p *DSLParser) parseEngineBlock(cfg *Config, body []dslBlockLine) error {
	fields, err := p.parseBlockFields(body)
	if err != nil {
		return err
	}
	for _, key := range []string{"cache_ttl", "attr_ttl", "batch_size", "flush_interval", "workers"} {
		val := fields.one(key)
		if val == "" {
			continue
		}
		var parseErr error
		switch key {
		case "cache_ttl":
			cfg.Engine.DecisionCacheTTL, parseErr = strconv.ParseInt(val, 10, 64)
		case "attr_ttl":
			cfg.Engine.AttributeCacheTTL, parseErr = strconv.ParseInt(val, 10, 64)
		case "batch_size":
			cfg.Engine.AuditBatchSize, parseErr = strconv.Atoi(val)
		case "flush_interval":
			cfg.Engine.AuditFlushInterval, parseErr = strconv.ParseInt(val, 10, 64)
		case "workers":
			cfg.Engine.BatchWorkerCount, parseErr = strconv.Atoi(val)
		}
		if parseErr != nil && p.strict {
			return fmt.Errorf("invalid engine value for %s: %s", key, val)
		}
	}
	return nil
}

type dslDirectiveCounts struct {
	tenants, policies, roles, acls, members   int
	actionItems, stringItems, permissionItems int
}

func countDSLDirectives(data []byte) dslDirectiveCounts {
	var counts dslDirectiveCounts
	start := 0
	for i := 0; i <= len(data); i++ {
		if i != len(data) && data[i] != '\n' {
			continue
		}
		line := data[start:i]
		start = i + 1
		for len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			line = line[1:]
		}
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		switch {
		case bytes.HasPrefix(line, []byte("tenant ")):
			counts.tenants++
		case bytes.HasPrefix(line, []byte("policy ")):
			counts.policies++
			counts.actionItems += countTokenListItems(line, 4)
			counts.stringItems += countTokenListItems(line, 5)
		case bytes.HasPrefix(line, []byte("role ")):
			counts.roles++
			counts.permissionItems += countTokenListItems(line, 4)
		case bytes.HasPrefix(line, []byte("acl ")):
			counts.acls++
			counts.actionItems += countTokenListItems(line, 4)
		case bytes.HasPrefix(line, []byte("member ")):
			counts.members++
		}
	}
	return counts
}

func countTokenListItems(line []byte, tokenIndex int) int {
	token := tokenAt(line, tokenIndex)
	if len(token) == 0 {
		return 0
	}
	count := 1
	for _, ch := range token {
		if ch == ',' {
			count++
		}
	}
	return count
}

func countListItems(s string) int {
	if s == "" {
		return 0
	}
	count := 1
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			count++
		}
	}
	return count
}

func tokenAt(line []byte, tokenIndex int) []byte {
	var start int
	var quoteChar byte
	index := 0
	for i := 0; i <= len(line); i++ {
		if i == len(line) || ((line[i] == ' ' || line[i] == '\t') && quoteChar == 0) {
			if i > start {
				token := line[start:i]
				if len(token) >= 2 {
					first, last := token[0], token[len(token)-1]
					if (first == '"' && last == '"') || (first == '\'' && last == '\'') || (first == '`' && last == '`') {
						token = token[1 : len(token)-1]
					}
				}
				if index == tokenIndex {
					return token
				}
				index++
			}
			start = i + 1
			continue
		}
		if i < len(line) {
			ch := line[i]
			if (ch == '"' || ch == '\'' || ch == '`') && quoteChar == 0 && (i == start || line[i-1] == ' ' || line[i-1] == '\t') {
				quoteChar = ch
			} else if ch == quoteChar {
				quoteChar = 0
			}
		}
	}
	return nil
}

func (p *DSLParser) splitLineBytes(line []byte) ([]string, error) {
	parts := p.partsScratch[:0]
	var start int
	var quoteChar byte
	i := 0

	for i < len(line) {
		ch := line[i]
		if ch == '#' && quoteChar == 0 {
			if i > start {
				parts = append(parts, p.tokenString(line[start:i]))
			}
			return parts, nil
		}
		if (ch == '"' || ch == '\'' || ch == '`') && quoteChar == 0 && (i == start || line[i-1] == ' ' || line[i-1] == '\t') {
			quoteChar = ch
			start = i + 1
		} else if ch == quoteChar {
			parts = append(parts, p.tokenString(line[start:i]))
			start = i + 1
			quoteChar = 0
		} else if (ch == ' ' || ch == '\t') && quoteChar == 0 {
			if i > start {
				parts = append(parts, p.tokenString(line[start:i]))
			}
			start = i + 1
		}
		i++
	}

	if quoteChar != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	if start < len(line) {
		parts = append(parts, p.tokenString(line[start:]))
	}

	p.partsScratch = parts
	return parts, nil
}

func splitLineBytes(line []byte) ([]string, error) {
	parser := &DSLParser{}
	return parser.splitLineBytes(line)
}

func parseQuotedString(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') ||
			(s[0] == '`' && s[len(s)-1] == '`') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func (p *DSLParser) tokenString(b []byte) string {
	if !p.zeroCopy {
		return string(b)
	}
	return bytesToString(b)
}

func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// Zero-copy token strings keep parser allocations low; callers should treat Parse input as immutable.
	return unsafe.String(&b[0], len(b))
}

func (p *DSLParser) nextPolicy() *Policy {
	if p.policyIndex < len(p.policyValues) {
		pol := &p.policyValues[p.policyIndex]
		p.policyIndex++
		return pol
	}
	return &Policy{}
}

func (p *DSLParser) nextRole() *Role {
	if p.roleIndex < len(p.roleValues) {
		role := &p.roleValues[p.roleIndex]
		p.roleIndex++
		return role
	}
	return &Role{}
}

func (p *DSLParser) nextACL() *ACL {
	if p.aclIndex < len(p.aclValues) {
		acl := &p.aclValues[p.aclIndex]
		p.aclIndex++
		return acl
	}
	return &ACL{}
}

func (p *DSLParser) nextActionSlice(n int) []Action {
	if n <= 0 {
		return nil
	}
	if p.actionIndex+n <= len(p.actionValues) {
		start := p.actionIndex
		p.actionIndex += n
		return p.actionValues[start:start]
	}
	return make([]Action, 0, n)
}

func (p *DSLParser) nextStringSlice(n int) []string {
	if n <= 0 {
		return nil
	}
	if p.stringIndex+n <= len(p.stringValues) {
		start := p.stringIndex
		p.stringIndex += n
		return p.stringValues[start:start]
	}
	return make([]string, 0, n)
}

func (p *DSLParser) nextPermissionSlice(n int) []Permission {
	if n <= 0 {
		return nil
	}
	if p.permIndex+n <= len(p.permValues) {
		start := p.permIndex
		p.permIndex += n
		return p.permValues[start:start]
	}
	return make([]Permission, 0, n)
}

func (p *DSLParser) parseInclude(cfg *Config, parts []string) error {
	if len(parts) != 1 {
		return fmt.Errorf("include requires: <file>")
	}
	name := parseQuotedString(parts[0])
	if name == "" {
		return fmt.Errorf("include path is required")
	}
	base := p.baseDir
	if base == "" {
		base = "."
	}
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if p.includeSet == nil {
		p.includeSet = make(map[string]bool)
	}
	included, err := p.parseFile(abs)
	if err != nil {
		return err
	}
	mergeConfig(cfg, included)
	return nil
}

func mergeConfig(dst, src *Config) {
	dst.Tenants = append(dst.Tenants, src.Tenants...)
	dst.Policies = append(dst.Policies, src.Policies...)
	dst.Roles = append(dst.Roles, src.Roles...)
	dst.ACLs = append(dst.ACLs, src.ACLs...)
	dst.Memberships = append(dst.Memberships, src.Memberships...)
	dst.Users = append(dst.Users, src.Users...)
	dst.Groups = append(dst.Groups, src.Groups...)
	dst.Scopes = append(dst.Scopes, src.Scopes...)
	dst.ServiceAccounts = append(dst.ServiceAccounts, src.ServiceAccounts...)
	dst.Invitations = append(dst.Invitations, src.Invitations...)
	dst.APIKeys = append(dst.APIKeys, src.APIKeys...)
	dst.PermissionBoundaries = append(dst.PermissionBoundaries, src.PermissionBoundaries...)
	if len(src.Hierarchy) > 0 {
		if dst.Hierarchy == nil {
			dst.Hierarchy = make(map[string]string, len(src.Hierarchy))
		}
		for child, parent := range src.Hierarchy {
			dst.Hierarchy[child] = parent
		}
	}
}

func (p *DSLParser) parseTenant(cfg *Config, parts []string) error {
	if len(parts) < 2 {
		return fmt.Errorf("tenant requires: <id> <name> [parent:<id>]")
	}
	t := TenantConfig{ID: parseQuotedString(parts[0]), Name: parseQuotedString(parts[1])}
	for _, opt := range parts[2:] {
		if strings.HasPrefix(opt, "parent:") {
			t.Parent = parseQuotedString(opt[7:])
			if cfg.Hierarchy == nil {
				cfg.Hierarchy = make(map[string]string, 4)
			}
			cfg.Hierarchy[t.ID] = t.Parent
		} else if p.strict {
			return fmt.Errorf("unknown tenant option: %s", opt)
		}
	}
	cfg.Tenants = append(cfg.Tenants, t)
	return nil
}

func (p *DSLParser) parsePolicy(cfg *Config, parts []string) error {
	if len(parts) < 6 {
		return fmt.Errorf("policy requires: <id> <tenant> <effect> <actions> <resources> <condition> [priority:<n>]")
	}

	effect := Effect(parseQuotedString(parts[2]))
	if p.strict && !validEffect(effect) {
		return fmt.Errorf("invalid policy effect: %s", effect)
	}
	actions, err := p.parseList(parseQuotedString(parts[3]))
	if err != nil {
		return fmt.Errorf("invalid policy actions: %w", err)
	}
	resources, err := p.parseStringList(parseQuotedString(parts[4]))
	if err != nil {
		return fmt.Errorf("invalid policy resources: %w", err)
	}
	condition, err := p.parseCondition(parseQuotedString(parts[5]))
	if err != nil {
		return fmt.Errorf("invalid policy condition: %w", err)
	}

	pol := p.nextPolicy()
	*pol = Policy{
		ID:        parseQuotedString(parts[0]),
		TenantID:  parseQuotedString(parts[1]),
		Effect:    effect,
		Actions:   actions,
		Resources: resources,
		Condition: condition,
		Priority:  0,
		Enabled:   true,
		CreatedAt: p.now,
		UpdatedAt: p.now,
	}

	for _, opt := range parts[6:] {
		if strings.HasPrefix(opt, "priority:") {
			priority, err := strconv.Atoi(parseQuotedString(opt[9:]))
			if err != nil {
				if p.strict {
					return fmt.Errorf("invalid priority: %s", opt[9:])
				}
			} else {
				pol.Priority = priority
			}
		} else if p.strict {
			return fmt.Errorf("unknown policy option: %s", opt)
		}
	}

	cfg.Policies = append(cfg.Policies, pol)
	return nil
}

func (p *DSLParser) parseRole(cfg *Config, parts []string) error {
	if len(parts) < 4 {
		return fmt.Errorf("role requires: <id> <tenant> <name> <perms> [inherits:<roles>] [owner:<actions>]")
	}

	perms, err := p.parsePermissions(parseQuotedString(parts[3]))
	if err != nil {
		return fmt.Errorf("invalid role permissions: %w", err)
	}

	role := p.nextRole()
	*role = Role{
		ID:                  parseQuotedString(parts[0]),
		TenantID:            parseQuotedString(parts[1]),
		Name:                parseQuotedString(parts[2]),
		Permissions:         perms,
		OwnerAllowedActions: []Action{},
		Inherits:            []string{},
		CreatedAt:           p.now,
	}

	for _, opt := range parts[4:] {
		if strings.HasPrefix(opt, "inherits:") {
			inherits, err := p.parseStringList(parseQuotedString(opt[9:]))
			if err != nil {
				return fmt.Errorf("invalid inherits option: %w", err)
			}
			role.Inherits = inherits
		} else if strings.HasPrefix(opt, "owner:") {
			actions, err := p.parseList(parseQuotedString(opt[6:]))
			if err != nil {
				return fmt.Errorf("invalid owner option: %w", err)
			}
			for _, a := range actions {
				role.OwnerAllowedActions = append(role.OwnerAllowedActions, Action(a))
			}
		} else if p.strict {
			return fmt.Errorf("unknown role option: %s", opt)
		}
	}

	cfg.Roles = append(cfg.Roles, role)
	return nil
}

func (p *DSLParser) parseACL(cfg *Config, parts []string) error {
	if len(parts) < 5 {
		return fmt.Errorf("acl requires: <id> <resource> <subject> <actions> <effect> [expires:<time>]")
	}

	effect := Effect(parseQuotedString(parts[4]))
	if p.strict && !validEffect(effect) {
		return fmt.Errorf("invalid acl effect: %s", effect)
	}
	actions, err := p.parseList(parseQuotedString(parts[3]))
	if err != nil {
		return fmt.Errorf("invalid acl actions: %w", err)
	}

	acl := p.nextACL()
	*acl = ACL{
		ID:         parseQuotedString(parts[0]),
		ResourceID: parseQuotedString(parts[1]),
		SubjectID:  parseQuotedString(parts[2]),
		Actions:    actions,
		Effect:     effect,
		CreatedAt:  p.now,
	}

	for _, opt := range parts[5:] {
		if strings.HasPrefix(opt, "expires:") {
			expires, err := time.Parse(time.RFC3339, parseQuotedString(opt[8:]))
			if err != nil {
				if p.strict {
					return fmt.Errorf("invalid expires timestamp: %s", opt[8:])
				}
			} else {
				acl.ExpiresAt = expires
			}
		} else if p.strict {
			return fmt.Errorf("unknown acl option: %s", opt)
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
		SubjectID: parseQuotedString(parts[0]),
		RoleID:    parseQuotedString(parts[1]),
	})
	return nil
}

func (p *DSLParser) parseEngine(cfg *Config, parts []string) error {
	for _, kv := range parts {
		idx := strings.Index(kv, "=")
		if idx == -1 {
			if p.strict {
				return fmt.Errorf("invalid engine option: %s", kv)
			}
			continue
		}
		key, val := kv[:idx], parseQuotedString(kv[idx+1:])
		var err error
		switch key {
		case "cache_ttl":
			cfg.Engine.DecisionCacheTTL, err = strconv.ParseInt(val, 10, 64)
		case "attr_ttl":
			cfg.Engine.AttributeCacheTTL, err = strconv.ParseInt(val, 10, 64)
		case "batch_size":
			cfg.Engine.AuditBatchSize, err = strconv.Atoi(val)
		case "flush_interval":
			cfg.Engine.AuditFlushInterval, err = strconv.ParseInt(val, 10, 64)
		case "workers":
			cfg.Engine.BatchWorkerCount, err = strconv.Atoi(val)
		default:
			if p.strict {
				return fmt.Errorf("unknown engine option: %s", key)
			}
		}
		if err != nil && p.strict {
			return fmt.Errorf("invalid engine value for %s: %s", key, val)
		}
	}
	return nil
}

func (p *DSLParser) parseUser(cfg *Config, parts []string) error {
	if len(parts) < 4 {
		return fmt.Errorf("user requires: <id> <tenant> <email> <name> [status:<status>]")
	}
	u := &User{ID: parseQuotedString(parts[0]), TenantID: parseQuotedString(parts[1]), Email: parseQuotedString(parts[2]), Name: parseQuotedString(parts[3]), Status: UserStatusActive}
	for _, opt := range parts[4:] {
		if strings.HasPrefix(opt, "status:") {
			u.Status = UserStatus(parseQuotedString(opt[7:]))
		} else if p.strict {
			return fmt.Errorf("unknown user option: %s", opt)
		}
	}
	cfg.Users = append(cfg.Users, u)
	return nil
}

func (p *DSLParser) parseGroup(cfg *Config, parts []string) error {
	if len(parts) < 3 {
		return fmt.Errorf("group requires: <id> <tenant> <name> [parent:<group>] [desc:<text>]")
	}
	g := &Group{ID: parseQuotedString(parts[0]), TenantID: parseQuotedString(parts[1]), Name: parseQuotedString(parts[2])}
	for _, opt := range parts[3:] {
		switch {
		case strings.HasPrefix(opt, "parent:"):
			g.ParentID = parseQuotedString(opt[7:])
		case strings.HasPrefix(opt, "desc:"):
			g.Description = parseQuotedString(opt[5:])
		default:
			if p.strict {
				return fmt.Errorf("unknown group option: %s", opt)
			}
		}
	}
	cfg.Groups = append(cfg.Groups, g)
	return nil
}

func (p *DSLParser) parseScope(cfg *Config, parts []string) error {
	if len(parts) < 3 {
		return fmt.Errorf("scope requires: <id> <tenant> <name> [parent:<scope>] [desc:<text>]")
	}
	s := &Scope{ID: parseQuotedString(parts[0]), TenantID: parseQuotedString(parts[1]), Name: parseQuotedString(parts[2])}
	for _, opt := range parts[3:] {
		switch {
		case strings.HasPrefix(opt, "parent:"):
			s.ParentID = parseQuotedString(opt[7:])
		case strings.HasPrefix(opt, "desc:"):
			s.Description = parseQuotedString(opt[5:])
		default:
			if p.strict {
				return fmt.Errorf("unknown scope option: %s", opt)
			}
		}
	}
	cfg.Scopes = append(cfg.Scopes, s)
	return nil
}

func (p *DSLParser) parseServiceAccount(cfg *Config, parts []string) error {
	if len(parts) < 3 {
		return fmt.Errorf("service_account requires: <id> <tenant> <name> [client:<id>] [roles:<roles>] [scopes:<scopes>] [status:<status>]")
	}
	sa := &ServiceAccount{ID: parseQuotedString(parts[0]), TenantID: parseQuotedString(parts[1]), Name: parseQuotedString(parts[2]), Status: UserStatusActive}
	for _, opt := range parts[3:] {
		switch {
		case strings.HasPrefix(opt, "client:"):
			sa.ClientID = parseQuotedString(opt[7:])
		case strings.HasPrefix(opt, "roles:"):
			v, err := p.parseStringList(parseQuotedString(opt[6:]))
			if err != nil {
				return fmt.Errorf("invalid roles option: %w", err)
			}
			sa.Roles = v
		case strings.HasPrefix(opt, "scopes:"):
			v, err := p.parseStringList(parseQuotedString(opt[7:]))
			if err != nil {
				return fmt.Errorf("invalid scopes option: %w", err)
			}
			sa.Scopes = v
		case strings.HasPrefix(opt, "status:"):
			sa.Status = UserStatus(parseQuotedString(opt[7:]))
		default:
			if p.strict {
				return fmt.Errorf("unknown service_account option: %s", opt)
			}
		}
	}
	cfg.ServiceAccounts = append(cfg.ServiceAccounts, sa)
	return nil
}

func (p *DSLParser) parseInvitation(cfg *Config, parts []string) error {
	if len(parts) < 4 {
		return fmt.Errorf("invitation requires: <id> <tenant> <email> <roles> [groups:<groups>] [status:<status>] [invited_by:<user>] [expires:<time>]")
	}
	roles, err := p.parseStringList(parseQuotedString(parts[3]))
	if err != nil {
		return fmt.Errorf("invalid invitation roles: %w", err)
	}
	inv := &Invitation{ID: parseQuotedString(parts[0]), TenantID: parseQuotedString(parts[1]), Email: parseQuotedString(parts[2]), RoleIDs: roles, Status: InviteStatusPending}
	for _, opt := range parts[4:] {
		switch {
		case strings.HasPrefix(opt, "groups:"):
			v, err := p.parseStringList(parseQuotedString(opt[7:]))
			if err != nil {
				return fmt.Errorf("invalid groups option: %w", err)
			}
			inv.GroupIDs = v
		case strings.HasPrefix(opt, "status:"):
			inv.Status = InviteStatus(parseQuotedString(opt[7:]))
		case strings.HasPrefix(opt, "invited_by:"):
			inv.InvitedBy = parseQuotedString(opt[11:])
		case strings.HasPrefix(opt, "expires:"):
			t, err := time.Parse(time.RFC3339, parseQuotedString(opt[8:]))
			if err != nil {
				if p.strict {
					return fmt.Errorf("invalid expires timestamp: %s", opt[8:])
				}
			} else {
				inv.ExpiresAt = t
			}
		default:
			if p.strict {
				return fmt.Errorf("unknown invitation option: %s", opt)
			}
		}
	}
	cfg.Invitations = append(cfg.Invitations, inv)
	return nil
}

func (p *DSLParser) parseAPIKey(cfg *Config, parts []string) error {
	if len(parts) < 5 {
		return fmt.Errorf("api_key requires: <id> <tenant> <user> <prefix> <name> [scopes:<scopes>] [expires:<time>]")
	}
	key := &APIKey{ID: parseQuotedString(parts[0]), TenantID: parseQuotedString(parts[1]), UserID: parseQuotedString(parts[2]), Prefix: parseQuotedString(parts[3]), Name: parseQuotedString(parts[4])}
	for _, opt := range parts[5:] {
		switch {
		case strings.HasPrefix(opt, "scopes:"):
			v, err := p.parseStringList(parseQuotedString(opt[7:]))
			if err != nil {
				return fmt.Errorf("invalid scopes option: %w", err)
			}
			key.Scopes = v
		case strings.HasPrefix(opt, "expires:"):
			t, err := time.Parse(time.RFC3339, parseQuotedString(opt[8:]))
			if err != nil {
				if p.strict {
					return fmt.Errorf("invalid expires timestamp: %s", opt[8:])
				}
			} else {
				key.ExpiresAt = t
			}
		default:
			if p.strict {
				return fmt.Errorf("unknown api_key option: %s", opt)
			}
		}
	}
	cfg.APIKeys = append(cfg.APIKeys, key)
	return nil
}

func (p *DSLParser) parseBoundary(cfg *Config, parts []string) error {
	if len(parts) < 5 {
		return fmt.Errorf("boundary requires: <id> <tenant> <name> <actions> <resources>")
	}
	actions, err := p.parseList(parseQuotedString(parts[3]))
	if err != nil {
		return fmt.Errorf("invalid boundary actions: %w", err)
	}
	resources, err := p.parseStringList(parseQuotedString(parts[4]))
	if err != nil {
		return fmt.Errorf("invalid boundary resources: %w", err)
	}
	if len(parts) > 5 && p.strict {
		return fmt.Errorf("unknown boundary option: %s", parts[5])
	}
	cfg.PermissionBoundaries = append(cfg.PermissionBoundaries, &PermissionBoundary{ID: parseQuotedString(parts[0]), TenantID: parseQuotedString(parts[1]), Name: parseQuotedString(parts[2]), MaxActions: actions, MaxResources: resources})
	return nil
}

type dslBlockFields struct {
	values map[string][]string
	blocks map[string]string
}

func (f dslBlockFields) one(key string) string {
	values := f.values[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (f dslBlockFields) has(key string) bool {
	_, ok := f.values[key]
	return ok
}

func (f dslBlockFields) list(key string) []string {
	values := f.values[key]
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (f dslBlockFields) blockText(key string) string {
	return f.blocks[key]
}

func (p *DSLParser) parseBlockFields(body []dslBlockLine) (dslBlockFields, error) {
	fields := dslBlockFields{
		values: make(map[string][]string),
		blocks: make(map[string]string),
	}
	for i := 0; i < len(body); i++ {
		line := body[i]
		text := trimDSLLine(line.text)
		if len(text) == 0 || text[0] == '#' {
			continue
		}
		parts, err := p.splitLineBytes(text)
		if err != nil {
			return fields, fmt.Errorf("line %d: %w", line.line, err)
		}
		if len(parts) == 0 || parts[0] == "}" {
			continue
		}
		key := parts[0]
		if len(parts) >= 2 && parts[1] == "{" {
			collected, next, err := p.collectNestedBlock(body, i)
			if err != nil {
				return fields, err
			}
			if key == "when" || key == "condition" {
				fields.blocks[key] = strings.Join(collected, " ")
			} else {
				fields.values[key] = append(fields.values[key], collected...)
			}
			i = next
			continue
		}
		if len(parts) >= 2 && parts[1] == "[" {
			collected, next, err := p.collectNestedList(body, i)
			if err != nil {
				return fields, err
			}
			fields.values[key] = append(fields.values[key], collected...)
			i = next
			continue
		}
		vals, err := p.parseBlockListTokens(parts[1:])
		if err != nil {
			return fields, fmt.Errorf("line %d: invalid %s value: %w", line.line, key, err)
		}
		fields.values[key] = append(fields.values[key], vals...)
	}
	return fields, nil
}

func (p *DSLParser) collectNestedBlock(body []dslBlockLine, start int) ([]string, int, error) {
	depth := dslBraceDelta(body[start].text)
	if depth <= 0 {
		return nil, start, fmt.Errorf("line %d: malformed nested block", body[start].line)
	}
	values := make([]string, 0, 4)
	for i := start + 1; i < len(body); i++ {
		text := trimDSLLine(body[i].text)
		oldDepth := depth
		depth += dslBraceDelta(text)
		if oldDepth == 1 && depth == 0 && isDSLClosingBraceLine(text) {
			return values, i, nil
		}
		if len(text) != 0 && text[0] != '#' {
			parts, err := p.splitLineBytes(text)
			if err != nil {
				return nil, i, fmt.Errorf("line %d: %w", body[i].line, err)
			}
			values = append(values, parts...)
		}
		if depth < 0 {
			return nil, i, fmt.Errorf("line %d: unexpected block close", body[i].line)
		}
	}
	return nil, start, fmt.Errorf("line %d: unterminated nested block", body[start].line)
}

func (p *DSLParser) collectNestedList(body []dslBlockLine, start int) ([]string, int, error) {
	values := make([]string, 0, 4)
	for i := start + 1; i < len(body); i++ {
		text := trimDSLLine(body[i].text)
		if len(text) == 0 || text[0] == '#' {
			continue
		}
		parts, err := p.splitLineBytes(text)
		if err != nil {
			return nil, i, fmt.Errorf("line %d: %w", body[i].line, err)
		}
		if len(parts) == 1 && parts[0] == "]" {
			return values, i, nil
		}
		for _, part := range parts {
			part = strings.TrimSuffix(strings.TrimPrefix(part, "["), "]")
			part = strings.TrimSuffix(part, ",")
			part = strings.TrimSpace(parseQuotedString(part))
			if part != "" {
				values = append(values, part)
			}
		}
	}
	return nil, start, fmt.Errorf("line %d: unterminated list", body[start].line)
}

func (p *DSLParser) parseBlockListTokens(tokens []string) ([]string, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	if len(tokens) == 1 && !strings.HasPrefix(tokens[0], "[") && !strings.HasPrefix(tokens[0], "{") {
		value := strings.TrimSpace(parseQuotedString(tokens[0]))
		if value == "" {
			return nil, nil
		}
		return []string{value}, nil
	}
	joined := strings.Join(tokens, " ")
	joined = strings.TrimSpace(joined)
	if strings.HasPrefix(joined, "[") {
		if !strings.HasSuffix(joined, "]") {
			return nil, fmt.Errorf("missing closing ]")
		}
		joined = strings.TrimSpace(joined[1 : len(joined)-1])
	} else if strings.HasPrefix(joined, "{") {
		if !strings.HasSuffix(joined, "}") {
			return nil, fmt.Errorf("missing closing }")
		}
		joined = strings.TrimSpace(joined[1 : len(joined)-1])
	}
	if joined == "" {
		return nil, nil
	}
	joined = strings.ReplaceAll(joined, ",", " ")
	parts, err := p.splitLineBytes([]byte(joined))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(parseQuotedString(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out, nil
}

func (p *DSLParser) actionsFromValues(values []string) ([]Action, error) {
	if len(values) == 0 {
		if p.strict {
			return nil, fmt.Errorf("empty list")
		}
		return nil, nil
	}
	out := p.nextActionSlice(len(values))
	for _, value := range values {
		if strings.Contains(value, ",") {
			actions, err := p.parseList(value)
			if err != nil {
				return nil, err
			}
			out = append(out, actions...)
			continue
		}
		out = append(out, Action(value))
	}
	return out, nil
}

func (p *DSLParser) permissionsFromValues(values []string) ([]Permission, error) {
	if len(values) == 0 {
		if p.strict {
			return nil, fmt.Errorf("empty permissions")
		}
		return nil, nil
	}
	out := p.nextPermissionSlice(len(values))
	for _, value := range values {
		if strings.Contains(value, ",") {
			perms, err := p.parsePermissions(value)
			if err != nil {
				return nil, err
			}
			out = append(out, perms...)
			continue
		}
		idx := strings.Index(value, ":")
		if idx <= 0 || idx == len(value)-1 {
			if p.strict {
				return nil, fmt.Errorf("malformed permission %q", value)
			}
			continue
		}
		out = append(out, Permission{Action: Action(value[:idx]), Resource: value[idx+1:]})
	}
	return out, nil
}

func parseList(s string) []Action {
	actions, _ := parseListStrict(s, false)
	return actions
}

func (p *DSLParser) parseList(s string) ([]Action, error) {
	if s == "" {
		if p.strict {
			return nil, fmt.Errorf("empty list")
		}
		return nil, nil
	}
	count := countListItems(s)
	actions := p.nextActionSlice(count)
	if s == "*" {
		return append(actions, Action("*")), nil
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				actions = append(actions, Action(s[start:i]))
			} else if p.strict {
				return nil, fmt.Errorf("empty item in %q", s)
			}
			start = i + 1
		}
	}
	if p.strict && len(actions) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	return actions, nil
}

func parseListStrict(s string, strict bool) ([]Action, error) {
	if s == "" {
		if strict {
			return nil, fmt.Errorf("empty list")
		}
		return nil, nil
	}
	if s == "*" {
		return []Action{"*"}, nil
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
			} else if strict {
				return nil, fmt.Errorf("empty item in %q", s)
			}
			start = i + 1
		}
	}
	if strict && len(actions) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	return actions, nil
}

func (p *DSLParser) parseStringList(s string) ([]string, error) {
	if s == "" {
		if p.strict {
			return nil, fmt.Errorf("empty list")
		}
		return nil, nil
	}
	out := p.nextStringSlice(countListItems(s))
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			} else if p.strict {
				return nil, fmt.Errorf("empty item in %q", s)
			}
			start = i + 1
		}
	}
	return out, nil
}

func parseStringListStrict(s string, strict bool) ([]string, error) {
	if s == "" {
		if strict {
			return nil, fmt.Errorf("empty list")
		}
		return nil, nil
	}
	count := 1
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			count++
		}
	}
	out := make([]string, 0, count)
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			} else {
				if strict {
					return nil, fmt.Errorf("empty item in %q", s)
				}
			}
			start = i + 1
		}
	}
	return out, nil
}

func parsePermissions(s string) []Permission {
	perms, _ := parsePermissionsStrict(s, false)
	return perms
}

func (p *DSLParser) parsePermissions(s string) ([]Permission, error) {
	if s == "" {
		if p.strict {
			return nil, fmt.Errorf("empty permissions")
		}
		return nil, nil
	}
	perms := p.nextPermissionSlice(countListItems(s))
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				part := s[start:i]
				found := false
				for j := 0; j < len(part); j++ {
					if part[j] == ':' {
						if p.strict && (j == 0 || j == len(part)-1) {
							return nil, fmt.Errorf("malformed permission %q", part)
						}
						perms = append(perms, Permission{Action: Action(part[:j]), Resource: part[j+1:]})
						found = true
						break
					}
				}
				if p.strict && !found {
					return nil, fmt.Errorf("malformed permission %q", part)
				}
			} else if p.strict {
				return nil, fmt.Errorf("empty permission in %q", s)
			}
			start = i + 1
		}
	}
	if p.strict && len(perms) == 0 {
		return nil, fmt.Errorf("empty permissions")
	}
	return perms, nil
}

func parsePermissionsStrict(s string, strict bool) ([]Permission, error) {
	if s == "" {
		if strict {
			return nil, fmt.Errorf("empty permissions")
		}
		return nil, nil
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
				found := false
				for j := 0; j < len(part); j++ {
					if part[j] == ':' {
						if strict && (j == 0 || j == len(part)-1) {
							return nil, fmt.Errorf("malformed permission %q", part)
						}
						perms = append(perms, Permission{
							Action:   Action(part[:j]),
							Resource: part[j+1:],
						})
						found = true
						break
					}
				}
				if strict && !found {
					return nil, fmt.Errorf("malformed permission %q", part)
				}
			} else if strict {
				return nil, fmt.Errorf("empty permission in %q", s)
			}
			start = i + 1
		}
	}
	if strict && len(perms) == 0 {
		return nil, fmt.Errorf("empty permissions")
	}
	return perms, nil
}

func parseCondition(s string) Expr {
	expr, _ := parseConditionStrict(s, false)
	return expr
}

func parseConditionStrict(s string, strict bool) (Expr, error) {
	if s == "" || s == "true" {
		return &TrueExpr{}, nil
	}
	expr, err := newConditionParser(s).parse()
	if err == nil {
		return expr, nil
	}
	if strict {
		return nil, err
	}
	return &TrueExpr{}, nil
}

func ParseCondition(s string) (Expr, error) {
	return parseConditionStrict(s, true)
}

func FormatCondition(expr Expr) string {
	return conditionToDSL(expr)
}

type conditionParser struct {
	input string
	pos   int
}

func newConditionParser(input string) *conditionParser {
	return &conditionParser{input: input}
}

func (p *conditionParser) parse() (Expr, error) {
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.input) {
		return nil, fmt.Errorf("unsupported condition near %q", p.input[p.pos:])
	}
	return expr, nil
}

func (p *conditionParser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.consume("||") && !p.consumeWordFold("or") {
			return left, nil
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &OrExpr{Left: left, Right: right}
	}
}

func (p *conditionParser) parseAnd() (Expr, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.consume("&&") && !p.consumeWordFold("and") {
			return left, nil
		}
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		left = &AndExpr{Left: left, Right: right}
	}
}

func (p *conditionParser) parsePrimary() (Expr, error) {
	p.skipSpace()
	if p.consume("(") {
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if !p.consume(")") {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		return expr, nil
	}
	return p.parseAtom()
}

func (p *conditionParser) parseAtom() (Expr, error) {
	field := p.readField()
	if field == "" {
		return nil, fmt.Errorf("expected condition")
	}
	p.skipSpace()
	if p.consume("(") {
		return p.parseFunction(field)
	}
	if p.consumeWordFold("in") {
		return p.parseMembershipList(field)
	}
	if p.consumeWordFold("contains") {
		p.consumeWordFold("any")
		return p.parseMembershipList(field)
	}
	if p.consumeWordFold("has_any") || p.consumeWordFold("has") {
		return p.parseMembershipList(field)
	}
	switch {
	case p.consume("!="):
		value := p.readValue(")&|")
		if value == "" {
			return nil, fmt.Errorf("malformed inequality")
		}
		return &NeExpr{Field: field, Value: value}, nil
	case p.consume(">="):
		value := p.readValue(")&|")
		if value == "" {
			return nil, fmt.Errorf("malformed comparison")
		}
		return &GteExpr{Field: field, Value: parseScalar(value)}, nil
	case p.consume("=="):
		value := p.readValue(")&|")
		if value == "" {
			return nil, fmt.Errorf("malformed equality")
		}
		return &EqExpr{Field: field, Value: value}, nil
	case p.consume("="):
		value := p.readValue(")&|")
		if value == "" {
			return nil, fmt.Errorf("malformed equality")
		}
		return &EqExpr{Field: field, Value: value}, nil
	case p.consume("@"):
		raw := p.readValue(")&|")
		if raw == "" {
			return nil, fmt.Errorf("malformed membership")
		}
		parts := strings.Split(raw, ",")
		values := make([]any, 0, len(parts))
		for _, part := range parts {
			if part == "" {
				return nil, fmt.Errorf("empty membership value")
			}
			values = append(values, part)
		}
		return &InExpr{Field: field, Values: values}, nil
	default:
		return nil, fmt.Errorf("unsupported condition %q", p.input)
	}
}

func (p *conditionParser) parseMembershipList(field string) (Expr, error) {
	p.skipSpace()
	if !p.consume("[") {
		return nil, fmt.Errorf("membership requires [values]")
	}
	raw := p.readValue("]")
	if !p.consume("]") {
		return nil, fmt.Errorf("membership requires closing ]")
	}
	raw = strings.ReplaceAll(raw, ",", " ")
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty membership values")
	}
	values := make([]any, 0, len(parts))
	for _, part := range parts {
		values = append(values, strings.Trim(part, `"'`))
	}
	return &InExpr{Field: field, Values: values}, nil
}

func (p *conditionParser) parseFunction(name string) (Expr, error) {
	args := make([]string, 0, 3)
	for {
		p.skipSpace()
		if p.consume(")") {
			break
		}
		arg := p.readValue(",)")
		if arg == "" {
			return nil, fmt.Errorf("empty argument in %s", name)
		}
		args = append(args, arg)
		p.skipSpace()
		if p.consume(")") {
			break
		}
		if !p.consume(",") {
			return nil, fmt.Errorf("expected comma in %s", name)
		}
	}
	switch name {
	case "regex":
		if len(args) != 2 {
			return nil, fmt.Errorf("regex requires field and pattern")
		}
		return &RegexExpr{Field: args[0], Regex: args[1]}, nil
	case "cidr", "ip_in_cidr":
		if len(args) != 1 {
			return nil, fmt.Errorf("cidr requires one CIDR argument")
		}
		return &CIDRExpr{CIDR: args[0]}, nil
	case "time_between":
		if len(args) != 2 {
			return nil, fmt.Errorf("time_between requires start and end")
		}
		return &TimeBetweenExpr{Start: args[0], End: args[1]}, nil
	case "range":
		if len(args) != 3 {
			return nil, fmt.Errorf("range requires field, min, max")
		}
		min, err := strconv.ParseFloat(args[1], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid range min")
		}
		max, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid range max")
		}
		return &RangeExpr{Field: args[0], Min: min, Max: max}, nil
	default:
		return nil, fmt.Errorf("unsupported condition function %s", name)
	}
}

func (p *conditionParser) skipSpace() {
	for p.pos < len(p.input) && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t') {
		p.pos++
	}
}

func (p *conditionParser) consume(s string) bool {
	p.skipSpace()
	if strings.HasPrefix(p.input[p.pos:], s) {
		p.pos += len(s)
		return true
	}
	return false
}

func (p *conditionParser) consumeWord(s string) bool {
	p.skipSpace()
	if !strings.HasPrefix(p.input[p.pos:], s) {
		return false
	}
	end := p.pos + len(s)
	if end < len(p.input) {
		ch := p.input[end]
		if ch != ' ' && ch != '\t' && ch != ')' {
			return false
		}
	}
	p.pos = end
	return true
}

func (p *conditionParser) consumeWordFold(s string) bool {
	p.skipSpace()
	end := p.pos + len(s)
	if end > len(p.input) || !strings.EqualFold(p.input[p.pos:end], s) {
		return false
	}
	if end < len(p.input) {
		ch := p.input[end]
		if ch != ' ' && ch != '\t' && ch != ')' && ch != '[' {
			return false
		}
	}
	p.pos = end
	return true
}

func (p *conditionParser) readValue(stoppers string) string {
	p.skipSpace()
	if p.pos >= len(p.input) {
		return ""
	}
	if p.input[p.pos] == '"' || p.input[p.pos] == '\'' || p.input[p.pos] == '`' {
		quote := p.input[p.pos]
		p.pos++
		start := p.pos
		for p.pos < len(p.input) && p.input[p.pos] != quote {
			p.pos++
		}
		if p.pos >= len(p.input) {
			return ""
		}
		out := p.input[start:p.pos]
		p.pos++
		return out
	}
	start := p.pos
	for p.pos < len(p.input) {
		if strings.HasPrefix(p.input[p.pos:], " AND ") || strings.HasPrefix(p.input[p.pos:], " OR ") {
			break
		}
		if strings.ContainsRune(stoppers, rune(p.input[p.pos])) {
			break
		}
		p.pos++
	}
	return strings.TrimSpace(p.input[start:p.pos])
}

func (p *conditionParser) readField() string {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if ch == ' ' || ch == '\t' || strings.ContainsRune("!=>@(),&|", rune(ch)) {
			break
		}
		p.pos++
	}
	return strings.TrimSpace(p.input[start:p.pos])
}

func (p *DSLParser) parseCondition(s string) (Expr, error) {
	// Expr values are immutable during evaluation; adjacent repeated conditions can share one parsed tree.
	if s == p.lastCondText && p.lastCondExpr != nil {
		return p.lastCondExpr, nil
	}
	expr, err := parseConditionStrict(s, p.strict)
	if err != nil {
		return nil, err
	}
	p.lastCondText = s
	p.lastCondExpr = expr
	return expr, nil
}

func parseScalar(s string) any {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

func conditionToDSL(expr Expr) string {
	switch e := expr.(type) {
	case nil:
		return "true"
	case *TrueExpr:
		return "true"
	case *EqExpr:
		return e.Field + "=" + fmt.Sprint(e.Value)
	case *NeExpr:
		return e.Field + "!=" + fmt.Sprint(e.Value)
	case *GteExpr:
		return e.Field + ">=" + fmt.Sprint(e.Value)
	case *InExpr:
		parts := make([]string, 0, len(e.Values))
		for _, v := range e.Values {
			parts = append(parts, fmt.Sprint(v))
		}
		return e.Field + "@" + strings.Join(parts, ",")
	case *AndExpr:
		return "(" + conditionToDSL(e.Left) + "&&" + conditionToDSL(e.Right) + ")"
	case *OrExpr:
		return "(" + conditionToDSL(e.Left) + "||" + conditionToDSL(e.Right) + ")"
	case *RegexExpr:
		return "regex(" + e.Field + "," + e.Regex + ")"
	case *CIDRExpr:
		return "cidr(" + e.CIDR + ")"
	case *TimeBetweenExpr:
		return "time_between(" + e.Start + "," + e.End + ")"
	case *RangeExpr:
		return "range(" + e.Field + "," + strconv.FormatFloat(e.Min, 'f', -1, 64) + "," + strconv.FormatFloat(e.Max, 'f', -1, 64) + ")"
	default:
		return expr.String()
	}
}

func validEffect(effect Effect) bool {
	return effect == EffectAllow || effect == EffectDeny
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
