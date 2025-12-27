package authz

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/authz/utils"

	phlog "github.com/phuslu/log"
)

// ============================================================================
// DOMAIN OBJECTS
// ============================================================================

// Subject represents who is requesting access
type Subject struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"` // user, service, device
	TenantID string         `json:"tenant_id"`
	Roles    []string       `json:"roles"`
	Groups   []string       `json:"groups"`
	Attrs    map[string]any `json:"attrs"`
}

// Resource represents what is being accessed
type Resource struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	TenantID string         `json:"tenant_id"`
	OwnerID  string         `json:"owner_id"`
	Attrs    map[string]any `json:"attrs"`
}

// Action represents how the resource is being accessed
type Action string

// Environment represents the context of the request
type Environment struct {
	Time     time.Time      `json:"time"`
	IP       net.IP         `json:"ip"`
	TenantID string         `json:"tenant_id"`
	Region   string         `json:"region"`
	Extra    map[string]any `json:"extra"`
}

// Effect represents the outcome of a policy evaluation
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Decision represents the authorization decision
type Decision struct {
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason"`
	MatchedBy string    `json:"matched_by"` // policy_id, acl, role, etc.
	Trace     []string  `json:"trace"`
	Timestamp time.Time `json:"timestamp"`
}

// TimestampAsEnv creates a minimal Environment using the decision timestamp for replay purposes
func (d *Decision) TimestampAsEnv() *Environment {
	return &Environment{Time: d.Timestamp}
}

// MemoryAttributeProvider is a simple in-memory attribute provider
type MemoryAttributeProvider struct {
	store map[string]map[string]any
}

func NewMemoryAttributeProvider() *MemoryAttributeProvider {
	return &MemoryAttributeProvider{store: make(map[string]map[string]any)}
}

func (m *MemoryAttributeProvider) ID() string { return "memory" }

func (m *MemoryAttributeProvider) GetAttributes(ctx context.Context, subject *Subject) (map[string]any, error) {
	if subject == nil {
		return nil, nil
	}
	if attrs, ok := m.store[subject.ID]; ok {
		return attrs, nil
	}
	return nil, nil
}

func (m *MemoryAttributeProvider) SetAttributes(subjectID string, attrs map[string]any) {
	m.store[subjectID] = attrs
}

// ============================================================================
// POLICY SYSTEM
// ============================================================================

// Policy represents an ABAC policy
type Policy struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Effect    Effect    `json:"effect"`
	Actions   []Action  `json:"actions"`
	Resources []string  `json:"resources"` // patterns: "document:*", "file:123"
	Condition Expr      `json:"condition"`
	Priority  int       `json:"priority"` // higher = evaluated first
	Version   int       `json:"version"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Checksum returns a deterministic hash of the policy
func (p *Policy) Checksum() string {
	data, _ := json.Marshal(struct {
		Effect    Effect
		Actions   []Action
		Resources []string
		Condition string
		Priority  int
	}{
		Effect:    p.Effect,
		Actions:   p.Actions,
		Resources: p.Resources,
		Condition: p.Condition.String(),
		Priority:  p.Priority,
	})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Signed policy bundle and signature utilities
type SignedPolicyBundle struct {
	Policies   []*Policy         `json:"policies"`
	Signatures map[string]string `json:"signatures"` // base64(pubkey+sig?) or just base64(sig)
	Meta       map[string]any    `json:"meta,omitempty"`
}

// SignPolicy returns an ed25519 signature (base64) for the policy using the private key
func SignPolicy(priv ed25519.PrivateKey, p *Policy) (string, error) {
	data, err := json.Marshal(struct {
		ID       string
		Checksum string
	}{
		ID:       p.ID,
		Checksum: p.Checksum(),
	})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyPolicySignature verifies that signature matches the policy checksum with a public key
func VerifyPolicySignature(pub ed25519.PublicKey, p *Policy, sigB64 string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, err
	}
	data, err := json.Marshal(struct {
		ID       string
		Checksum string
	}{
		ID:       p.ID,
		Checksum: p.Checksum(),
	})
	if err != nil {
		return false, err
	}
	ok := ed25519.Verify(pub, data, sig)
	return ok, nil
}

// SignBundle signs each policy with priv and returns a SignedPolicyBundle
func SignBundle(priv ed25519.PrivateKey, policies []*Policy) (*SignedPolicyBundle, error) {
	b := &SignedPolicyBundle{Policies: policies, Signatures: make(map[string]string)}
	for _, p := range policies {
		s, err := SignPolicy(priv, p)
		if err != nil {
			return nil, err
		}
		b.Signatures[p.ID] = s
	}
	return b, nil
}

// VerifyBundle verifies all signatures using given public key
func VerifyBundle(pub ed25519.PublicKey, b *SignedPolicyBundle) (bool, error) {
	for _, p := range b.Policies {
		sig, ok := b.Signatures[p.ID]
		if !ok {
			return false, fmt.Errorf("missing signature for policy %s", p.ID)
		}
		okv, err := VerifyPolicySignature(pub, p, sig)
		if err != nil || !okv {
			return false, fmt.Errorf("bad signature for policy %s: %v", p.ID, err)
		}
		// optional: verify checksum consistency (policy.Checksum already used in signature)
	}
	return true, nil
}

// ============================================================================
// EXPRESSION LANGUAGE (ABAC Conditions)
// ============================================================================

// Expr represents a compiled condition expression
type Expr interface {
	Evaluate(ctx *EvalContext) (bool, error)
	String() string
}

// EvalContext provides data for expression evaluation
type EvalContext struct {
	Subject     *Subject
	Resource    *Resource
	Action      Action
	Environment *Environment
}

// AndExpr represents logical AND
type AndExpr struct {
	Left  Expr
	Right Expr
}

func (e *AndExpr) Evaluate(ctx *EvalContext) (bool, error) {
	left, err := e.Left.Evaluate(ctx)
	if err != nil || !left {
		return false, err
	}
	return e.Right.Evaluate(ctx)
}

func (e *AndExpr) String() string {
	return fmt.Sprintf("(%s AND %s)", e.Left.String(), e.Right.String())
}

// OrExpr represents logical OR
type OrExpr struct {
	Left  Expr
	Right Expr
}

func (e *OrExpr) Evaluate(ctx *EvalContext) (bool, error) {
	left, err := e.Left.Evaluate(ctx)
	if err != nil {
		return false, err
	}
	if left {
		return true, nil
	}
	return e.Right.Evaluate(ctx)
}

func (e *OrExpr) String() string {
	return fmt.Sprintf("(%s OR %s)", e.Left.String(), e.Right.String())
}

// EqExpr represents equality check
type EqExpr struct {
	Field string
	Value any
}

func (e *EqExpr) Evaluate(ctx *EvalContext) (bool, error) {
	val := getField(ctx, e.Field)
	// Support value references like "subject.id" by resolving them
	switch v := e.Value.(type) {
	case string:
		if v == "action" || len(v) > 8 && (v[:8] == "subject." || v[:9] == "resource." || v[:4] == "env.") {
			res := getField(ctx, v)
			return compare(val, res) == 0, nil
		}
	}
	return compare(val, e.Value) == 0, nil
}

func (e *EqExpr) String() string {
	return fmt.Sprintf("%s == %v", e.Field, e.Value)
}

// InExpr represents membership check
type InExpr struct {
	Field  string
	Values []any
}

func (e *InExpr) Evaluate(ctx *EvalContext) (bool, error) {
	val := getField(ctx, e.Field)
	for _, v := range e.Values {
		// resolve potential field reference
		switch vv := v.(type) {
		case string:
			if vv == "action" || len(vv) > 8 && (vv[:8] == "subject." || vv[:9] == "resource." || vv[:4] == "env.") {
				rv := getField(ctx, vv)
				if compare(val, rv) == 0 {
					return true, nil
				}
				continue
			}
		}
		if compare(val, v) == 0 {
			return true, nil
		}
	}
	return false, nil
}

func (e *InExpr) String() string {
	return fmt.Sprintf("%s IN %v", e.Field, e.Values)
}

// GteExpr represents greater-than-or-equal check
type GteExpr struct {
	Field string
	Value any
}

func (e *GteExpr) Evaluate(ctx *EvalContext) (bool, error) {
	val := getField(ctx, e.Field)
	// resolve right-hand side if it's a field reference
	switch v := e.Value.(type) {
	case string:
		if v == "action" || len(v) > 8 && (v[:8] == "subject." || v[:9] == "resource." || v[:4] == "env.") {
			rv := getField(ctx, v)
			return compare(val, rv) >= 0, nil
		}
	}
	return compare(val, e.Value) >= 0, nil
}

func (e *GteExpr) String() string {
	return fmt.Sprintf("%s >= %v", e.Field, e.Value)
}

// TrueExpr always returns true (unconditional policy)
type TrueExpr struct{}

func (e *TrueExpr) Evaluate(ctx *EvalContext) (bool, error) {
	return true, nil
}

func (e *TrueExpr) String() string {
	return "true"
}

// Helper functions for field access and comparison
func getField(ctx *EvalContext, field string) any {
	switch {
	case len(field) > 8 && field[:8] == "subject.":
		return getSubjectField(ctx.Subject, field[8:])
	case len(field) > 9 && field[:9] == "resource.":
		return getResourceField(ctx.Resource, field[9:])
	case len(field) > 4 && field[:4] == "env.":
		return getEnvField(ctx.Environment, field[4:])
	case field == "action":
		return string(ctx.Action)
	}
	return nil
}

func getSubjectField(s *Subject, field string) any {
	switch field {
	case "id":
		return s.ID
	case "type":
		return s.Type
	case "tenant_id":
		return s.TenantID
	case "roles":
		return s.Roles
	case "groups":
		return s.Groups
	default:
		if len(field) > 6 && field[:6] == "attrs." {
			return s.Attrs[field[6:]]
		}
	}
	return nil
}

func getResourceField(r *Resource, field string) any {
	switch field {
	case "id":
		return r.ID
	case "type":
		return r.Type
	case "tenant_id":
		return r.TenantID
	case "owner_id":
		return r.OwnerID
	default:
		if len(field) > 6 && field[:6] == "attrs." {
			return r.Attrs[field[6:]]
		}
	}
	return nil
}

func getEnvField(e *Environment, field string) any {
	switch field {
	case "tenant_id":
		return e.TenantID
	case "region":
		return e.Region
	case "time":
		return e.Time
	case "ip":
		return e.IP.String()
	default:
		if len(field) > 6 && field[:6] == "extra." {
			return e.Extra[field[6:]]
		}
	}
	return nil
}

func compare(a, b any) int {
	switch av := a.(type) {

	case []string:
		if bs, ok := b.(string); ok {
			for _, v := range av {
				if v == bs {
					return 0
				}
			}
			return -1
		}

	case string:
		if bv, ok := b.(string); ok {
			switch {
			case av == bv:
				return 0
			case av < bv:
				return -1
			default:
				return 1
			}
		}

	case int:
		if bv, ok := b.(int); ok {
			return av - bv
		}

	case float64:
		if bv, ok := b.(float64); ok {
			switch {
			case av == bv:
				return 0
			case av < bv:
				return -1
			default:
				return 1
			}
		}
	}
	return -1
}

// ============================================================================
// RBAC (Derived from ABAC)
// ============================================================================

// Role represents a named collection of permissions
type Role struct {
	ID                  string       `json:"id"`
	TenantID            string       `json:"tenant_id"`
	Name                string       `json:"name"`
	Permissions         []Permission `json:"permissions"`
	OwnerAllowedActions []Action     `json:"owner_allowed_actions,omitempty"` // actions owner role can perform across descendants
	Inherits            []string     `json:"inherits"`                        // role IDs
	CreatedAt           time.Time    `json:"created_at"`
}

// Permission represents an action on a resource pattern
type Permission struct {
	Action   Action `json:"action"`
	Resource string `json:"resource"` // pattern: "document:*"
}

// ============================================================================
// ACL (Fine-Grained Overrides)
// ============================================================================

// ACL represents resource-specific access control
type ACL struct {
	ID         string    `json:"id"`
	ResourceID string    `json:"resource_id"`
	SubjectID  string    `json:"subject_id"`
	Actions    []Action  `json:"actions"`
	Effect     Effect    `json:"effect"`
	ExpiresAt  time.Time `json:"expires_at"` // zero = no expiry
	CreatedAt  time.Time `json:"created_at"`
}

// IsExpired checks if the ACL has expired
func (a *ACL) IsExpired() bool {
	return !a.ExpiresAt.IsZero() && time.Now().After(a.ExpiresAt)
}

// ============================================================================
// STORAGE INTERFACES
// ============================================================================

// PolicyStore manages policy persistence
type PolicyStore interface {
	CreatePolicy(ctx context.Context, p *Policy) error
	UpdatePolicy(ctx context.Context, p *Policy) error
	DeletePolicy(ctx context.Context, id string) error
	GetPolicy(ctx context.Context, id string) (*Policy, error)
	ListPolicies(ctx context.Context, tenantID string) ([]*Policy, error)
	GetPolicyHistory(ctx context.Context, id string) ([]*Policy, error)
}

// RoleStore manages role persistence
type RoleStore interface {
	CreateRole(ctx context.Context, r *Role) error
	UpdateRole(ctx context.Context, r *Role) error
	DeleteRole(ctx context.Context, id string) error
	GetRole(ctx context.Context, id string) (*Role, error)
	ListRoles(ctx context.Context, tenantID string) ([]*Role, error)
}

// ACLStore manages ACL persistence
type ACLStore interface {
	GrantACL(ctx context.Context, acl *ACL) error
	RevokeACL(ctx context.Context, id string) error
	ListACLsByResource(ctx context.Context, resourceID string) ([]*ACL, error)
	ListACLsBySubject(ctx context.Context, subjectID string) ([]*ACL, error)
}

// AuditStore manages audit logs
type AuditStore interface {
	LogDecision(ctx context.Context, entry *AuditEntry) error
	GetAccessLog(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error)
}

// AuditEntry represents an authorization decision log
type AuditEntry struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Subject   *Subject       `json:"subject"`
	Action    Action         `json:"action"`
	Resource  *Resource      `json:"resource"`
	Decision  *Decision      `json:"decision"`
	Metadata  map[string]any `json:"metadata"`
}

// AuditFilter for querying audit logs
type AuditFilter struct {
	SubjectID  string
	ResourceID string
	Action     Action
	StartTime  time.Time
	EndTime    time.Time
	Limit      int
}

// ============================================================================
// IN-MEMORY STORES (For demonstration)
// ============================================================================

type MemoryPolicyStore struct {
	mu        sync.RWMutex
	policies  map[string]*Policy
	histories map[string][]*Policy
}

func NewMemoryPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{
		policies:  make(map[string]*Policy),
		histories: make(map[string][]*Policy),
	}
}

func (s *MemoryPolicyStore) CreatePolicy(ctx context.Context, p *Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt
	s.policies[p.ID] = p
	return nil
}

func (s *MemoryPolicyStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.policies[p.ID]
	if ok {
		// store a copy in history
		cop := *old
		s.histories[p.ID] = append(s.histories[p.ID], &cop)
	}
	p.UpdatedAt = time.Now()
	p.Version++
	s.policies[p.ID] = p
	return nil
}

func (s *MemoryPolicyStore) GetPolicyHistory(ctx context.Context, id string) ([]*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.histories[id]
	if !ok {
		return nil, fmt.Errorf("no history for policy %s", id)
	}
	return h, nil
}

func (s *MemoryPolicyStore) DeletePolicy(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, id)
	return nil
}

func (s *MemoryPolicyStore) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	return p, nil
}

func (s *MemoryPolicyStore) ListPolicies(ctx context.Context, tenantID string) ([]*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Policy, 0)
	for _, p := range s.policies {
		if p.TenantID == tenantID || p.TenantID == "" {
			result = append(result, p)
		}
	}
	return result, nil
}

type MemoryRoleStore struct {
	mu    sync.RWMutex
	roles map[string]*Role
}

func NewMemoryRoleStore() *MemoryRoleStore {
	return &MemoryRoleStore{
		roles: make(map[string]*Role),
	}
}

func (s *MemoryRoleStore) CreateRole(ctx context.Context, r *Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.CreatedAt = time.Now()
	s.roles[r.ID] = r
	return nil
}

func (s *MemoryRoleStore) UpdateRole(ctx context.Context, r *Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[r.ID] = r
	return nil
}

func (s *MemoryRoleStore) DeleteRole(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roles, id)
	return nil
}

func (s *MemoryRoleStore) GetRole(ctx context.Context, id string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[id]
	if !ok {
		return nil, fmt.Errorf("role not found: %s", id)
	}
	return r, nil
}

func (s *MemoryRoleStore) ListRoles(ctx context.Context, tenantID string) ([]*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Role, 0)
	for _, r := range s.roles {
		if r.TenantID == tenantID || r.TenantID == "" {
			result = append(result, r)
		}
	}
	return result, nil
}

type MemoryACLStore struct {
	mu   sync.RWMutex
	acls map[string]*ACL
}

func NewMemoryACLStore() *MemoryACLStore {
	return &MemoryACLStore{
		acls: make(map[string]*ACL),
	}
}

func (s *MemoryACLStore) GrantACL(ctx context.Context, acl *ACL) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acl.CreatedAt = time.Now()
	s.acls[acl.ID] = acl
	return nil
}

func (s *MemoryACLStore) RevokeACL(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.acls, id)
	return nil
}

func (s *MemoryACLStore) ListACLsByResource(ctx context.Context, resourceID string) ([]*ACL, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*ACL, 0)
	for _, acl := range s.acls {
		if acl.IsExpired() {
			continue
		}
		// Support pattern-based ACL.ResourceID: exact match OR wildcard suffix: "document:*" OR prefix
		if acl.ResourceID == resourceID {
			result = append(result, acl)
			continue
		}
		// wildcard suffix
		for i, ch := range acl.ResourceID {
			if ch == '*' {
				prefix := acl.ResourceID[:i]
				if len(resourceID) >= len(prefix) && resourceID[:len(prefix)] == prefix {
					result = append(result, acl)
				}
				break
			}
		}
	}
	return result, nil
}

func (s *MemoryACLStore) ListACLsBySubject(ctx context.Context, subjectID string) ([]*ACL, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*ACL, 0)
	for _, acl := range s.acls {
		if acl.SubjectID == subjectID && !acl.IsExpired() {
			result = append(result, acl)
		}
	}
	return result, nil
}

type MemoryAuditStore struct {
	mu      sync.RWMutex
	entries []*AuditEntry
}

func NewMemoryAuditStore() *MemoryAuditStore {
	return &MemoryAuditStore{
		entries: make([]*AuditEntry, 0),
	}
}

func (s *MemoryAuditStore) LogDecision(ctx context.Context, entry *AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	return nil
}

func (s *MemoryAuditStore) GetAccessLog(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*AuditEntry, 0)
	for _, entry := range s.entries {
		if filter.SubjectID != "" && entry.Subject.ID != filter.SubjectID {
			continue
		}
		if filter.ResourceID != "" && entry.Resource.ID != filter.ResourceID {
			continue
		}
		if filter.Action != "" && entry.Action != filter.Action {
			continue
		}
		if !filter.StartTime.IsZero() && entry.Timestamp.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && entry.Timestamp.After(filter.EndTime) {
			continue
		}
		result = append(result, entry)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, nil
}

// ============================================================================
// POLICY INDEX (O(1) / O(log n) lookups)
// ============================================================================

// CompiledPredicate is a faster, precompiled predicate for a policy
type CompiledPredicate func(*EvalContext) (bool, error)

type OpCode uint8

const (
	OP_PUSH_FIELD OpCode = iota
	OP_PUSH_CONST
	OP_EQ
	OP_IN
	OP_GTE
	OP_AND
	OP_OR
	OP_TIME_BETWEEN
	OP_CIDR_CONTAINS
	OP_REGEX
	OP_RANGE
	OP_TRUE
)

// Bytecode is a simple stack-based instruction sequence
type Bytecode struct {
	ops   []OpCode
	args  []interface{}
	regex []*regexp.Regexp // precompiled regexes used by code
}

func (bc *Bytecode) Eval(ctx *EvalContext) (bool, error) {
	var stack [32]interface{}
	sp := 0
	push := func(v interface{}) {
		stack[sp] = v
		sp++
	}
	pop := func() interface{} {
		if sp == 0 {
			return nil
		}
		sp--
		v := stack[sp]
		stack[sp] = nil
		return v
	}

	argIdx := 0
	for _, op := range bc.ops {
		switch op {
		case OP_PUSH_FIELD:
			f := bc.args[argIdx].(string)
			argIdx++
			push(getField(ctx, f))
		case OP_PUSH_CONST:
			c := bc.args[argIdx]
			argIdx++
			push(c)
		case OP_EQ:
			b := pop()
			a := pop()
			push(compare(a, b) == 0)
		case OP_IN:
			set := pop()
			val := pop()
			found := false
			switch s := set.(type) {
			case []interface{}:
				for _, it := range s {
					// resolve field references in set items
					switch itv := it.(type) {
					case string:
						if itv == "action" || (len(itv) > 4 && (itv[:8] == "subject." || itv[:9] == "resource." || itv[:4] == "env.")) {
							rv := getField(ctx, itv)
							if compare(val, rv) == 0 {
								found = true
								break
							}
							continue
						}
					}
					if compare(val, it) == 0 {
						found = true
						break
					}
				}
			}
			push(found)
		case OP_GTE:
			b := pop()
			a := pop()
			push(compare(a, b) >= 0)
		case OP_AND:
			b := pop().(bool)
			a := pop().(bool)
			push(a && b)
		case OP_OR:
			b := pop().(bool)
			a := pop().(bool)
			push(a || b)
		case OP_TIME_BETWEEN:
			r := bc.args[argIdx].([2]int)
			argIdx++
			t := ctx.Environment.Time
			m := t.Hour()*60 + t.Minute()
			start := r[0]
			end := r[1]
			if start <= end {
				push(m >= start && m <= end)
			} else {
				push(m >= start || m <= end)
			}
		case OP_CIDR_CONTAINS:
			n := bc.args[argIdx].(*net.IPNet)
			argIdx++
			if ctx.Environment.IP == nil {
				push(false)
				break
			}
			push(n.Contains(ctx.Environment.IP))
		case OP_REGEX:
			rIdx := bc.args[argIdx].(int)
			argIdx++
			rg := bc.regex[rIdx]
			val := pop()
			vs, ok := val.(string)
			if !ok {
				push(false)
				break
			}
			push(rg.MatchString(vs))
		case OP_RANGE:
			rng := bc.args[argIdx].([2]float64)
			argIdx++
			val := pop()
			switch vv := val.(type) {
			case int:
				fv := float64(vv)
				push(fv >= rng[0] && fv <= rng[1])
			case float64:
				push(vv >= rng[0] && vv <= rng[1])
			default:
				push(false)
			}
		case OP_TRUE:
			push(true)
		default:
			return false, fmt.Errorf("unknown opcode %d", op)
		}
	}

	if sp == 0 {
		return false, nil
	}
	res, ok := pop().(bool)
	if !ok {
		return false, nil
	}
	return res, nil
}

// compileToBytecode - a simple compiler from Expr -> Bytecode
func compileToBytecode(e Expr) *Bytecode {
	if e == nil {
		return &Bytecode{ops: []OpCode{OP_TRUE}}
	}
	switch v := e.(type) {
	case *TrueExpr:
		return &Bytecode{ops: []OpCode{OP_TRUE}}
	case *EqExpr:
		// if RHS is a field reference (subject./resource./env.) treat as PUSH_FIELD
		if rv, ok := v.Value.(string); ok && (rv == "action" || (len(rv) > 4 && (rv[:8] == "subject." || rv[:9] == "resource." || rv[:4] == "env."))) {
			return &Bytecode{ops: []OpCode{OP_PUSH_FIELD, OP_PUSH_FIELD, OP_EQ}, args: []interface{}{v.Field, rv}}
		}
		return &Bytecode{ops: []OpCode{OP_PUSH_FIELD, OP_PUSH_CONST, OP_EQ}, args: []interface{}{v.Field, v.Value}}
	case *InExpr:
		vals := make([]interface{}, len(v.Values))
		for i := range v.Values {
			vals[i] = v.Values[i]
		}
		return &Bytecode{ops: []OpCode{OP_PUSH_FIELD, OP_PUSH_CONST, OP_IN}, args: []interface{}{v.Field, vals}}
	case *GteExpr:
		if rv, ok := v.Value.(string); ok && (rv == "action" || (len(rv) > 4 && (rv[:8] == "subject." || rv[:9] == "resource." || rv[:4] == "env."))) {
			return &Bytecode{ops: []OpCode{OP_PUSH_FIELD, OP_PUSH_FIELD, OP_GTE}, args: []interface{}{v.Field, rv}}
		}
		return &Bytecode{ops: []OpCode{OP_PUSH_FIELD, OP_PUSH_CONST, OP_GTE}, args: []interface{}{v.Field, v.Value}}
	case *AndExpr:
		l := compileToBytecode(v.Left)
		r := compileToBytecode(v.Right)
		ops := append(append([]OpCode{}, l.ops...), r.ops...)
		op := append(ops, OP_AND)
		args := append(append([]interface{}{}, l.args...), r.args...)
		regex := append(append([]*regexp.Regexp{}, l.regex...), r.regex...)
		return &Bytecode{ops: op, args: args, regex: regex}
	case *OrExpr:
		l := compileToBytecode(v.Left)
		r := compileToBytecode(v.Right)
		ops := append(append([]OpCode{}, l.ops...), r.ops...)
		op := append(ops, OP_OR)
		args := append(append([]interface{}{}, l.args...), r.args...)
		regex := append(append([]*regexp.Regexp{}, l.regex...), r.regex...)
		return &Bytecode{ops: op, args: args, regex: regex}
	case *TimeBetweenExpr:
		start, _ := time.Parse("15:04", v.Start)
		end, _ := time.Parse("15:04", v.End)
		return &Bytecode{ops: []OpCode{OP_TIME_BETWEEN}, args: []interface{}{[2]int{start.Hour()*60 + start.Minute(), end.Hour()*60 + end.Minute()}}}
	case *CIDRExpr:
		_, ipnet, _ := net.ParseCIDR(v.CIDR)
		return &Bytecode{ops: []OpCode{OP_CIDR_CONTAINS}, args: []interface{}{ipnet}}
	case *RegexExpr:
		rg := regexp.MustCompile(v.Regex)
		return &Bytecode{ops: []OpCode{OP_PUSH_FIELD, OP_REGEX}, args: []interface{}{v.Field, 0}, regex: []*regexp.Regexp{rg}}
	case *RangeExpr:
		return &Bytecode{ops: []OpCode{OP_PUSH_FIELD, OP_RANGE}, args: []interface{}{v.Field, [2]float64{v.Min, v.Max}}}
	default:
		// fallback to closure compile
		return &Bytecode{ops: []OpCode{OP_TRUE}}
	}
}

type CompiledPolicy struct {
	P         *Policy
	Predicate CompiledPredicate
	BC        *Bytecode
}

type PolicyIndex struct {
	mu             sync.RWMutex
	byAction       map[Action][]*CompiledPolicy
	byResourceType map[string][]*CompiledPolicy
	byTenant       map[string][]*CompiledPolicy
	ownerIndex     map[string][]*CompiledPolicy // resourceType -> compiled policies containing resource.owner_id == subject.id
	compiled       []*CompiledPolicy
	compiledCache  map[string]*CompiledPolicy // key: policyID:checksum
	lastCompiled   time.Time
}

func NewPolicyIndex() *PolicyIndex {
	return &PolicyIndex{
		byAction:       make(map[Action][]*CompiledPolicy),
		byResourceType: make(map[string][]*CompiledPolicy),
		byTenant:       make(map[string][]*CompiledPolicy),
		ownerIndex:     make(map[string][]*CompiledPolicy),
		compiled:       make([]*CompiledPolicy, 0),
		compiledCache:  make(map[string]*CompiledPolicy),
	}
}

func (idx *PolicyIndex) Rebuild(policies []*Policy) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// prepare maps with capacity hints to reduce per-append allocations
	actionCounts := make(map[Action]int)
	resCounts := make(map[string]int)
	tenantCounts := make(map[string]int)
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		for _, a := range p.Actions {
			actionCounts[a]++
		}
		for _, r := range p.Resources {
			resCounts[extractResourceType(r)]++
		}
		tenantCounts[p.TenantID]++
	}

	// Reuse existing maps & slices where possible to avoid allocations
	if idx.byAction == nil {
		idx.byAction = make(map[Action][]*CompiledPolicy, len(actionCounts))
		for a, c := range actionCounts {
			idx.byAction[a] = make([]*CompiledPolicy, 0, c)
		}
	} else {
		// shrink or reallocate existing slices to desired capacity
		for a, c := range actionCounts {
			if s, ok := idx.byAction[a]; ok {
				if cap(s) < c {
					idx.byAction[a] = make([]*CompiledPolicy, 0, c)
				} else {
					idx.byAction[a] = s[:0]
				}
			} else {
				idx.byAction[a] = make([]*CompiledPolicy, 0, c)
			}
		}
		// clear slices for keys not in actionCounts
		for existingKey := range idx.byAction {
			if _, ok := actionCounts[existingKey]; !ok {
				idx.byAction[existingKey] = idx.byAction[existingKey][:0]
			}
		}
	}

	if idx.byResourceType == nil {
		idx.byResourceType = make(map[string][]*CompiledPolicy, len(resCounts))
		for r, c := range resCounts {
			idx.byResourceType[r] = make([]*CompiledPolicy, 0, c)
		}
	} else {
		for r, c := range resCounts {
			if s, ok := idx.byResourceType[r]; ok {
				if cap(s) < c {
					idx.byResourceType[r] = make([]*CompiledPolicy, 0, c)
				} else {
					idx.byResourceType[r] = s[:0]
				}
			} else {
				idx.byResourceType[r] = make([]*CompiledPolicy, 0, c)
			}
		}
		for existingKey := range idx.byResourceType {
			if _, ok := resCounts[existingKey]; !ok {
				idx.byResourceType[existingKey] = idx.byResourceType[existingKey][:0]
			}
		}
	}

	if idx.byTenant == nil {
		idx.byTenant = make(map[string][]*CompiledPolicy, len(tenantCounts))
		for t, c := range tenantCounts {
			idx.byTenant[t] = make([]*CompiledPolicy, 0, c)
		}
	} else {
		for t, c := range tenantCounts {
			if s, ok := idx.byTenant[t]; ok {
				if cap(s) < c {
					idx.byTenant[t] = make([]*CompiledPolicy, 0, c)
				} else {
					idx.byTenant[t] = s[:0]
				}
			} else {
				idx.byTenant[t] = make([]*CompiledPolicy, 0, c)
			}
		}
		for existingKey := range idx.byTenant {
			if _, ok := tenantCounts[existingKey]; !ok {
				idx.byTenant[existingKey] = idx.byTenant[existingKey][:0]
			}
		}
	}

	// reuse compiled slice buffer if capacity sufficient
	if cap(idx.compiled) >= len(policies) {
		idx.compiled = idx.compiled[:0]
	} else {
		idx.compiled = make([]*CompiledPolicy, 0, len(policies))
	}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		// Use policy version if available to avoid expensive checksum computations
		var cacheKey string
		if p.Version > 0 {
			cacheKey = fmt.Sprintf("%s:%d", p.ID, p.Version)
		} else {
			cs := p.Checksum()
			cacheKey = p.ID + ":" + cs
		}
		var cp *CompiledPolicy
		if existing, ok := idx.compiledCache[cacheKey]; ok {
			cp = existing
		} else {
			// compile both predicate and bytecode where possible
			bc := compileToBytecode(p.Condition)
			pred := compilePredicate(p.Condition)
			cp = &CompiledPolicy{P: p, Predicate: pred, BC: bc}
			idx.compiledCache[cacheKey] = cp
		}
		idx.compiled = append(idx.compiled, cp)

		for _, action := range p.Actions {
			idx.byAction[action] = append(idx.byAction[action], cp)
		}

		for _, res := range p.Resources {
			resType := extractResourceType(res)
			idx.byResourceType[resType] = append(idx.byResourceType[resType], cp)
			// if policy contains owner equality condition, index for fast owner checks
			if hasOwnerEquality(p.Condition) {
				idx.ownerIndex[resType] = append(idx.ownerIndex[resType], cp)
			}
		}

		idx.byTenant[p.TenantID] = append(idx.byTenant[p.TenantID], cp)
	}

	// Sort by priority (descending)
	sort.Slice(idx.compiled, func(i, j int) bool { return idx.compiled[i].P.Priority > idx.compiled[j].P.Priority })
	// Sort owner index slices by priority as well
	for rt := range idx.ownerIndex {
		slice := idx.ownerIndex[rt]
		sort.Slice(slice, func(i, j int) bool { return slice[i].P.Priority > slice[j].P.Priority })
		idx.ownerIndex[rt] = slice
	}
	idx.lastCompiled = time.Now()
}

func (idx *PolicyIndex) GetRelevantPolicies(action Action, resourceType, tenantID string) []*CompiledPolicy {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	// Prefer action-indexed list, filter by tenant
	list := idx.byAction[action]
	if len(list) == 0 {
		// no action-specific policies: fallback to tenant list
		list = idx.byTenant[tenantID]
		if len(list) == 0 {
			list = idx.byTenant[""]
		}
	}

	res := make([]*CompiledPolicy, 0, len(list))
	for _, cp := range list {
		// tenant match or global
		if cp.P.TenantID == tenantID || cp.P.TenantID == "" {
			res = append(res, cp)
		}
	}
	return res
}

// GetOwnerPolicies returns owner-index policies for a resource type (may be empty)
func (idx *PolicyIndex) GetOwnerPolicies(resourceType string) []*CompiledPolicy {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.ownerIndex[resourceType]
}

func extractResourceType(pattern string) string {
	for i, ch := range pattern {
		if ch == ':' {
			return pattern[:i]
		}
	}
	return pattern
}

// ============================================================================
// AUTHORIZATION ENGINE
// ============================================================================

type DecisionCacheEntry struct {
	Decision  *Decision
	ExpiresAt time.Time
}

// DecisionKey is used as key for decisionCache to avoid string allocations
type DecisionKey struct {
	TenantID     string
	SubjectID    string
	ResourceType string
	ResourceID   string
	Action       Action
}

// TenantResolver defines ancestor/descendant relationships for tenants
type TenantResolver interface {
	IsAncestor(ancestor, tenant string) bool
}

// MemoryTenantResolver is a simple in-memory tenant parent map
type MemoryTenantResolver struct {
	mu     sync.RWMutex
	parent map[string]string // child -> parent
}

func NewMemoryTenantResolver() *MemoryTenantResolver {
	return &MemoryTenantResolver{parent: make(map[string]string)}
}

func (m *MemoryTenantResolver) AddParent(child, parent string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parent[child] = parent
}

func (m *MemoryTenantResolver) IsAncestor(ancestor, tenant string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ancestor == "" || tenant == "" {
		return ancestor == tenant
	}
	if ancestor == tenant {
		return true
	}
	cur := tenant
	for {
		p, ok := m.parent[cur]
		if !ok || p == "" {
			return false
		}
		if p == ancestor {
			return true
		}
		cur = p
	}
}

// AttributeProvider fetches external attributes for a subject
type AttributeProvider interface {
	ID() string
	GetAttributes(ctx context.Context, subject *Subject) (map[string]any, error)
}

type Engine struct {
	policyStore      PolicyStore
	roleStore        RoleStore
	aclStore         ACLStore
	auditStore       AuditStore
	policyIndex      *PolicyIndex
	roleCache        sync.Map
	decisionCache    map[DecisionKey]*DecisionCacheEntry
	decisionCacheTTL time.Duration
	attrProviders    []AttributeProvider
	decisionCacheMu  sync.RWMutex
	tenantResolver   TenantResolver
	// pools for hot-path objects
	evalCtxPool sync.Pool
	// asynchronous audit channel to avoid per-request allocations
	auditCh chan AuditEntry
}

func NewEngine(
	policyStore PolicyStore,
	roleStore RoleStore,
	aclStore ACLStore,
	auditStore AuditStore,
) *Engine {
	e := &Engine{
		policyStore:      policyStore,
		roleStore:        roleStore,
		aclStore:         aclStore,
		auditStore:       auditStore,
		policyIndex:      NewPolicyIndex(),
		decisionCache:    make(map[DecisionKey]*DecisionCacheEntry),
		decisionCacheTTL: time.Second, // default short TTL
		attrProviders:    []AttributeProvider{},
	}
	// init pools
	e.evalCtxPool.New = func() any { return &EvalContext{} }

	// init audit channel and worker
	e.auditCh = make(chan AuditEntry, 1024)
	go func() {
		bg := context.Background()
		for entry := range e.auditCh {
			_ = e.auditStore.LogDecision(bg, &entry)
		}
	}()
	return e
}

// ReloadPolicies rebuilds the policy index
func (e *Engine) ReloadPolicies(ctx context.Context, tenantID string) error {
	// Fetch all policies for tenant and global
	policies, err := e.policyStore.ListPolicies(ctx, tenantID)
	if err != nil {
		return err
	}
	// Rebuild index incrementally (replacing index for this tenant)
	e.policyIndex.Rebuild(policies)
	// Invalidate decision cache on policy reload
	e.InvalidateDecisionCache()
	return nil
}

// Authorize makes an authorization decision
func (e *Engine) Authorize(ctx context.Context, subject *Subject, action Action, resource *Resource, env *Environment) (*Decision, error) {
	return e.authorizeInternal(ctx, subject, action, resource, env, false)
}

// internal authorize with option to include trace (explain)
func (e *Engine) authorizeInternal(ctx context.Context, subject *Subject, action Action, resource *Resource, env *Environment, includeTrace bool) (*Decision, error) {
	start := time.Now()
	decision := &Decision{
		Allowed:   false,
		Trace:     make([]string, 0),
		Timestamp: start,
	}

	// Multi-tenancy enforcement
	// default behavior: subject and resource must be in same tenant
	if e.tenantResolver == nil {
		if subject.TenantID != env.TenantID || resource.TenantID != env.TenantID {
			if includeTrace {
				decision.Trace = append(decision.Trace, "DENY: tenant isolation violation")
			}
			decision.Reason = "tenant mismatch"
			e.auditLog(ctx, subject, action, resource, decision)
			return decision, nil
		}
	} else {
		// Resource tenant must match the environment tenant
		if resource.TenantID != env.TenantID {
			if includeTrace {
				decision.Trace = append(decision.Trace, "DENY: resource tenant != env tenant")
			}
			decision.Reason = "resource tenant mismatch"
			e.auditLog(ctx, subject, action, resource, decision)
			return decision, nil
		}
		// Subject may be the same tenant or an ancestor tenant. Additionally,
		// owners can have action-scoped privileges and cross-tenant admins have full rights.
		subjectOk := subject.TenantID == env.TenantID || e.tenantResolver.IsAncestor(subject.TenantID, env.TenantID) || e.isTenantOwnerForAction(ctx, subject, env.TenantID, action, resource) || e.isCrossTenantAdmin(ctx, subject)
		if !subjectOk {
			if includeTrace {
				decision.Trace = append(decision.Trace, "DENY: subject tenant not authorized for env tenant")
			}
			decision.Reason = "subject tenant not authorized"
			e.auditLog(ctx, subject, action, resource, decision)
			return decision, nil
		}
	}

	// Decision cache lookup first (fast path avoids attribute enrichment)
	ck := e.buildCacheKey(subject, action, resource, env)
	if !includeTrace {
		if cached, ok := e.getDecisionFromCache(ck); ok {
			return cached, nil
		}
	}

	// Enrich subject attributes from external providers (only on cache miss)
	for _, p := range e.attrProviders {
		if attrs, err := p.GetAttributes(ctx, subject); err == nil && attrs != nil {
			if subject.Attrs == nil {
				subject.Attrs = make(map[string]any)
			}
			for k, v := range attrs {
				// do not overwrite existing attributes
				if _, exists := subject.Attrs[k]; !exists {
					subject.Attrs[k] = v
				}
			}
		}
	}

	// If subject.Roles was not provided explicitly, allow attribute providers to supply roles
	if subject != nil && len(subject.Roles) == 0 && subject.Attrs != nil {
		if r, ok := subject.Attrs["roles"]; ok {
			switch v := r.(type) {
			case []string:
				subject.Roles = append(subject.Roles, v...)
			case []Action:
				for _, a := range v {
					subject.Roles = append(subject.Roles, string(a))
				}
			case []any:
				for _, item := range v {
					switch s := item.(type) {
					case string:
						subject.Roles = append(subject.Roles, s)
					}
				}
			case string:
				// comma-separated
				for _, s := range strings.Split(v, ",") {
					if s = strings.TrimSpace(s); s != "" {
						subject.Roles = append(subject.Roles, s)
					}
				}
			}
		}
	}
	// get pooled eval context to avoid per-request allocations
	evalCtx := e.getEvalCtx()
	evalCtx.Subject = subject
	evalCtx.Resource = resource
	evalCtx.Action = action
	evalCtx.Environment = env
	defer e.putEvalCtx(evalCtx)

	// 1. Explicit DENY (highest precedence) - include ACL denies
	if includeTrace {
		decision.Trace = append(decision.Trace, "1. Checking explicit DENY policies and ACLs...")
	}
	if denied, policyID := e.checkPoliciesFast(ctx, evalCtx, EffectDeny); denied {
		decision.Reason = "explicit deny policy"
		decision.MatchedBy = policyID
		if includeTrace {
			if polAllowed, pid, polTrace := e.checkPolicies(ctx, evalCtx, EffectDeny); polAllowed {
				for _, t := range polTrace {
					decision.Trace = append(decision.Trace, fmt.Sprintf("   %s", t))
				}
				decision.Trace = append(decision.Trace, fmt.Sprintf("   DENY by policy: %s", pid))
			}
		}
		ck := e.buildCacheKey(subject, action, resource, env)
		e.setDecisionInCache(ck, decision)
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}
	// Check ACL denies
	if denied, aclID := e.checkACLFast(ctx, subject, resource, action, EffectDeny); denied {
		decision.Reason = "explicit deny acl"
		decision.MatchedBy = aclID
		if includeTrace {
			if _, aid, aclTrace := e.checkACL(ctx, subject, resource, action, EffectDeny); aid != "" {
				for _, t := range aclTrace {
					decision.Trace = append(decision.Trace, fmt.Sprintf("   %s", t))
				}
				decision.Trace = append(decision.Trace, fmt.Sprintf("   DENY by ACL: %s", aid))
			}
		}
		ck := e.buildCacheKey(subject, action, resource, env)
		e.setDecisionInCache(ck, decision)
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}

	// 2. ACL Allow
	if includeTrace {
		decision.Trace = append(decision.Trace, "2. Checking ACL allow...")
	}
	if allowed, aclID := e.checkACLFast(ctx, subject, resource, action, EffectAllow); allowed {
		decision.Allowed = true
		decision.Reason = "acl allow"
		decision.MatchedBy = aclID
		if includeTrace {
			if _, aid, aclTrace := e.checkACL(ctx, subject, resource, action, EffectAllow); aid != "" {
				for _, t := range aclTrace {
					decision.Trace = append(decision.Trace, fmt.Sprintf("   %s", t))
				}
				decision.Trace = append(decision.Trace, fmt.Sprintf("   ALLOW by ACL: %s", aid))
			}
		}
		ck := e.buildCacheKey(subject, action, resource, env)
		e.setDecisionInCache(ck, decision)
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}

	// 3. ABAC Policy Allow
	if includeTrace {
		decision.Trace = append(decision.Trace, "3. Checking ABAC policy allow...")
		polAllowed, policyID, polTrace := e.checkPolicies(ctx, evalCtx, EffectAllow)
		for _, t := range polTrace {
			decision.Trace = append(decision.Trace, fmt.Sprintf("   %s", t))
		}
		if polAllowed {
			decision.Allowed = true
			decision.Reason = "abac policy allow"
			decision.MatchedBy = policyID
			decision.Trace = append(decision.Trace, fmt.Sprintf("   ALLOW by policy: %s", policyID))
			ck := e.buildCacheKey(subject, action, resource, env)
			e.setDecisionInCache(ck, decision)
			e.auditLog(ctx, subject, action, resource, decision)
			return decision, nil
		}
	} else {
		if ok, pid := e.checkPoliciesFast(ctx, evalCtx, EffectAllow); ok {
			decision.Allowed = true
			decision.Reason = "abac policy allow"
			decision.MatchedBy = pid
			ck := e.buildCacheKey(subject, action, resource, env)
			e.setDecisionInCache(ck, decision)
			e.auditLog(ctx, subject, action, resource, decision)
			return decision, nil
		}
	}

	// 4. RBAC-derived Allow
	if includeTrace {
		decision.Trace = append(decision.Trace, "4. Checking RBAC-derived allow...")
		rbAllowed, roleID, rbacTrace := e.checkRBAC(ctx, subject, action, resource)
		for _, t := range rbacTrace {
			decision.Trace = append(decision.Trace, fmt.Sprintf("   %s", t))
		}
		if rbAllowed {
			decision.Allowed = true
			decision.Reason = "rbac allow"
			decision.MatchedBy = roleID
			decision.Trace = append(decision.Trace, fmt.Sprintf("   ALLOW by role: %s", roleID))
			ck := e.buildCacheKey(subject, action, resource, env)
			e.setDecisionInCache(ck, decision)
			e.auditLog(ctx, subject, action, resource, decision)
			return decision, nil
		}
	} else {
		if ok, rid := e.checkRBACFast(ctx, subject, action, resource); ok {
			decision.Allowed = true
			decision.Reason = "rbac allow"
			decision.MatchedBy = rid
			ck := e.buildCacheKey(subject, action, resource, env)
			e.setDecisionInCache(ck, decision)
			e.auditLog(ctx, subject, action, resource, decision)
			return decision, nil
		}
	}

	// 4.5 Tenant owner or cross-tenant admin
	if includeTrace {
		decision.Trace = append(decision.Trace, "4.5 Checking tenant owner/admin privileges...")
	}
	if e.isTenantOwnerForAction(ctx, subject, env.TenantID, action, resource) {
		decision.Allowed = true
		decision.Reason = "tenant owner"
		if includeTrace {
			decision.Trace = append(decision.Trace, "   ALLOW by tenant owner privilege")
		}
		ck := e.buildCacheKey(subject, action, resource, env)
		e.setDecisionInCache(ck, decision)
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}
	if e.isCrossTenantAdmin(ctx, subject) {
		decision.Allowed = true
		decision.Reason = "cross-tenant admin"
		if includeTrace {
			decision.Trace = append(decision.Trace, "   ALLOW by cross-tenant admin privilege")
		}
		ck := e.buildCacheKey(subject, action, resource, env)
		e.setDecisionInCache(ck, decision)
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}

	// 5. Default DENY
	decision.Reason = "default deny"
	if includeTrace {
		decision.Trace = append(decision.Trace, "5. Default DENY (no matching allow rules)")
	}
	e.auditLog(ctx, subject, action, resource, decision)
	// Cache decision only if deterministic
	ck = e.buildCacheKey(subject, action, resource, env)
	e.setDecisionInCache(ck, decision)
	return decision, nil
}

// Explain returns a detailed trace of the authorization decision
func (e *Engine) Explain(ctx context.Context, subject *Subject, action Action, resource *Resource, env *Environment) (*Decision, error) {
	return e.authorizeInternal(ctx, subject, action, resource, env, true)
}

func (e *Engine) checkPolicies(_ context.Context, evalCtx *EvalContext, effect Effect) (bool, string, []string) {
	policies := e.policyIndex.GetRelevantPolicies(
		evalCtx.Action,
		evalCtx.Resource.Type,
		evalCtx.Environment.TenantID,
	)

	trace := make([]string, 0)

	for _, cp := range policies {
		p := cp.P
		if p.Effect != effect {
			trace = append(trace, fmt.Sprintf("policy=%s skip effect=%s", p.ID, p.Effect))
			continue
		}

		// Check if action matches
		actionMatches := false
		for _, a := range p.Actions {
			if matchAction(a, evalCtx.Action) {
				actionMatches = true
				break
			}
		}
		if !actionMatches {
			trace = append(trace, fmt.Sprintf("policy=%s action_no_match", p.ID))
			continue
		}

		// Check if resource matches
		resourceMatches := false
		for _, r := range p.Resources {
			if matchResource(r, evalCtx.Resource) {
				resourceMatches = true
				break
			}
		}
		if !resourceMatches {
			trace = append(trace, fmt.Sprintf("policy=%s resource_no_match", p.ID))
			continue
		}

		// Evaluate compiled predicate
		matched, err := cp.Predicate(evalCtx)
		if err != nil {
			trace = append(trace, fmt.Sprintf("policy=%s pred_error=%v", p.ID, err))
			continue
		}
		trace = append(trace, fmt.Sprintf("policy=%s cond=%s result=%v", p.ID, p.Condition.String(), matched))
		if matched {
			trace = append(trace, fmt.Sprintf("policy=%s MATCH", p.ID))
			return true, p.ID, trace
		}
	}
	return false, "", trace
}

// Fast policy check without trace allocations (using compiled bytecode where possible)
func (e *Engine) checkPoliciesFast(_ context.Context, evalCtx *EvalContext, effect Effect) (bool, string) {
	policies := e.policyIndex.GetRelevantPolicies(
		evalCtx.Action,
		evalCtx.Resource.Type,
		evalCtx.Environment.TenantID,
	)

	for _, cp := range policies {
		p := cp.P
		if p.Effect != effect {
			continue
		}

		// quick action/resource match
		actionMatch := false
		for _, a := range p.Actions {
			if matchAction(a, evalCtx.Action) {
				actionMatch = true
				break
			}
		}
		if !actionMatch {
			continue
		}
		resourceMatch := false
		for _, r := range p.Resources {
			if matchResource(r, evalCtx.Resource) {
				resourceMatch = true
				break
			}
		}
		if !resourceMatch {
			continue
		}

		// Prefer running bytecode if present
		if cp.BC != nil {
			ok, err := cp.BC.Eval(evalCtx)
			if err != nil {
				continue
			}
			if ok {
				return true, p.ID
			}
			continue
		}

		ok, err := cp.Predicate(evalCtx)
		if err != nil {
			continue
		}
		if ok {
			return true, p.ID
		}
	}
	return false, ""
}

func (e *Engine) checkACL(ctx context.Context, subject *Subject, resource *Resource, action Action, effect Effect) (bool, string, []string) {
	// Try both resource key and resource ID for ACL lookups
	// Query by resource ID first to avoid allocating the combined type:id string in the common case
	acls2, _ := e.aclStore.ListACLsByResource(ctx, resource.ID)
	acls1 := make([]*ACL, 0)
	if len(acls2) == 0 {
		resourceKey := resource.Type + ":" + resource.ID
		acls1, _ = e.aclStore.ListACLsByResource(ctx, resourceKey)
	}

	trace := make([]string, 0)

	proc := func(acl *ACL) (bool, string, bool) {
		if acl.Effect != effect {
			trace = append(trace, fmt.Sprintf("acl=%s skip_effect=%s", acl.ID, acl.Effect))
			return false, "", false
		}

		// Match subject: check exact, wildcard and group membership; use simple inlined loops
		subjectMatch := false
		subjID := subject.ID
		if acl.SubjectID == "*" || acl.SubjectID == subjID {
			subjectMatch = true
		} else {
			if len(acl.SubjectID) > 6 && acl.SubjectID[:6] == "group:" {
				g := acl.SubjectID[6:]
				for _, sg := range subject.Groups {
					if sg == g {
						subjectMatch = true
						break
					}
				}
			}
		}
		if !subjectMatch {
			trace = append(trace, fmt.Sprintf("acl=%s subject_no_match", acl.ID))
			return false, "", false
		}

		// Actions - inline compare
		for _, a := range acl.Actions {
			if a == action || a == "*" {
				trace = append(trace, fmt.Sprintf("acl=%s action_match=%s", acl.ID, a))
				// Check expiry
				if acl.IsExpired() {
					trace = append(trace, fmt.Sprintf("acl=%s expired", acl.ID))
					return false, "", false
				}
				return true, acl.ID, true
			}
		}
		return false, "", false
	}

	for _, a := range acls1 {
		if ok, id, done := proc(a); done {
			return ok, id, trace
		}
	}
	for _, a := range acls2 {
		if ok, id, done := proc(a); done {
			return ok, id, trace
		}
	}

	return false, "", trace
}

// Fast ACL check without allocation of traces
func (e *Engine) checkACLFast(ctx context.Context, subject *Subject, resource *Resource, action Action, effect Effect) (bool, string) {
	// Query by resource ID first to avoid allocating the combined type:id string in the common case
	acls2, _ := e.aclStore.ListACLsByResource(ctx, resource.ID)
	acls1 := make([]*ACL, 0)
	if len(acls2) == 0 {
		resourceKey := resource.Type + ":" + resource.ID
		acls1, _ = e.aclStore.ListACLsByResource(ctx, resourceKey)
	}
	proc := func(acl *ACL) (bool, string, bool) {
		if acl.Effect != effect {
			return false, "", false
		}
		// subject match
		if acl.SubjectID != "*" && acl.SubjectID != subject.ID {
			if len(acl.SubjectID) > 6 && acl.SubjectID[:6] == "group:" {
				g := acl.SubjectID[6:]
				found := false
				for _, sg := range subject.Groups {
					if sg == g {
						found = true
						break
					}
				}
				if !found {
					return false, "", false
				}
			} else {
				return false, "", false
			}
		}
		// action
		for _, a := range acl.Actions {
			if a == action || a == "*" {
				if acl.IsExpired() {
					return false, "", false
				}
				return true, acl.ID, true
			}
		}
		return false, "", false
	}

	for _, a := range acls1 {
		if ok, id, done := proc(a); done {
			return ok, id
		}
	}
	for _, a := range acls2 {
		if ok, id, done := proc(a); done {
			return ok, id
		}
	}
	return false, ""
}

func (e *Engine) checkRBAC(ctx context.Context, subject *Subject, action Action, resource *Resource) (bool, string, []string) {
	trace := make([]string, 0)
	for _, roleID := range subject.Roles {
		role, err := e.getRoleWithCache(ctx, roleID)
		if err != nil {
			trace = append(trace, fmt.Sprintf("role=%s not_found", roleID))
			continue
		}

		// Use roleHasPermission to check and collect traces
		if ok := e.roleHasPermission(ctx, role, action, resource); ok {
			trace = append(trace, fmt.Sprintf("role=%s matches via roleHasPermission", roleID))
			// ABAC projection: verify subject has role
			evalCtx := e.getEvalCtx()
			evalCtx.Subject = subject
			evalCtx.Resource = resource
			evalCtx.Action = action
			evalCtx.Environment = &Environment{Time: time.Now(), TenantID: subject.TenantID}
			cond := &InExpr{Field: "subject.roles", Values: []any{role.ID}}
			ok2, _ := cond.Evaluate(evalCtx)
			trace = append(trace, fmt.Sprintf("role=%s cond=%s result=%v", role.ID, cond.String(), ok2))
			e.putEvalCtx(evalCtx)
			if ok2 {
				return true, roleID, trace
			}
		}
	}
	return false, "", trace
}

// Fast RBAC check without trace allocations
func (e *Engine) checkRBACFast(ctx context.Context, subject *Subject, action Action, resource *Resource) (bool, string) {
	for _, roleID := range subject.Roles {
		role, err := e.getRoleWithCache(ctx, roleID)
		if err != nil {
			continue
		}
		if e.roleHasPermission(ctx, role, action, resource) {
			return true, roleID
		}
	}
	return false, ""
}

func (e *Engine) getRoleWithCache(ctx context.Context, roleID string) (*Role, error) {
	if cached, ok := e.roleCache.Load(roleID); ok {
		return cached.(*Role), nil
	}

	role, err := e.roleStore.GetRole(ctx, roleID)
	if err != nil {
		return nil, err
	}

	e.roleCache.Store(roleID, role)
	return role, nil
}

func (e *Engine) roleHasPermission(ctx context.Context, role *Role, action Action, resource *Resource) bool {
	visited := make(map[string]bool)
	return e.roleHasPermissionRecursive(ctx, role, action, resource, visited)
}

// roleHasPermissionRecursive checks whether a role or any of its ancestor roles grants the
// given action on the resource. It uses a visited map to avoid infinite recursion when
// role inheritance contains cycles.
func (e *Engine) roleHasPermissionRecursive(ctx context.Context, role *Role, action Action, resource *Resource, visited map[string]bool) bool {
	if role == nil {
		return false
	}
	if visited[role.ID] {
		return false
	}
	visited[role.ID] = true

	// Check direct permissions
	for _, perm := range role.Permissions {
		if matchAction(perm.Action, action) && matchResource(perm.Resource, resource) {
			return true
		}
	}

	// Check inherited roles
	for _, parentID := range role.Inherits {
		parent, err := e.getRoleWithCache(ctx, parentID)
		if err != nil {
			continue
		}
		if e.roleHasPermissionRecursive(ctx, parent, action, resource, visited) {
			return true
		}
	}

	return false
}

// isTenantOwner checks if a subject is owner of the given tenant (direct or ancestor)
func (e *Engine) isTenantOwner(ctx context.Context, subject *Subject, tenant string) bool {
	if subject == nil {
		return false
	}
	// attribute-based owner flag
	if subject.Attrs != nil {
		if v, ok := subject.Attrs["is_tenant_owner"]; ok {
			if b, ok2 := v.(bool); ok2 && b {
				if e.tenantResolver == nil {
					return subject.TenantID == tenant
				}
				return e.tenantResolver.IsAncestor(subject.TenantID, tenant)
			}
		}
	}

	// role name based owner (e.g., "tenant-owner")
	for _, rid := range subject.Roles {
		role, err := e.getRoleWithCache(ctx, rid)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(role.Name), "owner") {
			// allow if role tenant is ancestor of target tenant
			if e.tenantResolver == nil {
				if role.TenantID == tenant {
					return true
				}
			} else {
				if role.TenantID == tenant || e.tenantResolver.IsAncestor(role.TenantID, tenant) {
					return true
				}
			}
		}
	}

	return false
}

// isTenantOwnerForAction checks if a subject is owner of the given tenant (direct or ancestor)
// and whether the owner is allowed to perform the specific action (action-scoped owner privileges).
func (e *Engine) isTenantOwnerForAction(ctx context.Context, subject *Subject, tenant string, action Action, resource *Resource) bool {
	// Ensure subject is an owner (attribute or owner-role ancestor)
	if !e.isTenantOwner(ctx, subject, tenant) {
		return false
	}

	// If the ownership comes from subject attribute, enforce subject-level action list (if present)
	if subject != nil && subject.Attrs != nil {
		if v, ok := subject.Attrs["is_tenant_owner"]; ok {
			if b, ok2 := v.(bool); ok2 && b {
				if aa, ok := subject.Attrs["owner_allowed_actions"]; ok {
					switch list := aa.(type) {
					case []string:
						for _, s := range list {
							if matchAction(Action(s), action) {
								return true
							}
						}
						return false
					case []Action:
						for _, a := range list {
							if matchAction(a, action) {
								return true
							}
						}
						return false
					case []any:
						for _, item := range list {
							if s, ok := item.(string); ok && matchAction(Action(s), action) {
								return true
							}
						}
						return false
					default:
						return true
					}
				}
				// no explicit list on subject owner => allow all (backwards compat)
				return true
			}
		}
	}

	// Now check role-based owners: they must explicitly allow actions (via OwnerAllowedActions or permissions)
	foundOwnerRole := false
	for _, rid := range subject.Roles {
		role, err := e.getRoleWithCache(ctx, rid)
		if err != nil {
			continue
		}
		if !strings.Contains(strings.ToLower(role.Name), "owner") {
			continue
		}
		// ensure role tenant applies to target tenant
		if e.tenantResolver == nil {
			if role.TenantID != tenant {
				continue
			}
		} else {
			if !(role.TenantID == tenant || e.tenantResolver.IsAncestor(role.TenantID, tenant)) {
				continue
			}
		}
		foundOwnerRole = true

		// check role-level owner allowed actions (if defined)
		if len(role.OwnerAllowedActions) > 0 {
			for _, oa := range role.OwnerAllowedActions {
				if matchAction(oa, action) {
					return true
				}
			}
			// role defines allowed actions but none matched => continue to other roles
			continue
		}

		// check role permissions for the requested action & resource
		for _, p := range role.Permissions {
			if matchAction(p.Action, action) && matchResource(p.Resource, resource) {
				return true
			}
		}

		// if role has global wildcard permission allow
		for _, p := range role.Permissions {
			if p.Action == "*" && p.Resource == "*" {
				return true
			}
		}
	}

	// If role owner(s) existed but no role allowed the action explicitly, deny
	if foundOwnerRole {
		return false
	}

	// Otherwise, default permissive for historical subject-owner behavior
	return true
}

// isCrossTenantAdmin checks whether the subject has an admin role that can operate across tenants
func (e *Engine) isCrossTenantAdmin(ctx context.Context, subject *Subject) bool {
	if subject == nil {
		return false
	}
	for _, rid := range subject.Roles {
		role, err := e.getRoleWithCache(ctx, rid)
		if err != nil {
			continue
		}
		if e.roleOrAncestorsIsAdmin(ctx, role, map[string]bool{}) {
			return true
		}
	}
	return false
}

// roleOrAncestorsIsAdmin checks whether a role or any of its ancestor roles is an admin
// role (name == "admin") or has global wildcard permissions. It prevents cycles
// by tracking visited role IDs.
func (e *Engine) roleOrAncestorsIsAdmin(ctx context.Context, role *Role, visited map[string]bool) bool {
	if role == nil {
		return false
	}
	if visited[role.ID] {
		return false
	}
	visited[role.ID] = true
	if strings.EqualFold(role.Name, "admin") {
		return true
	}
	for _, p := range role.Permissions {
		if p.Action == "*" && p.Resource == "*" {
			return true
		}
	}
	for _, pid := range role.Inherits {
		parent, err := e.getRoleWithCache(ctx, pid)
		if err != nil {
			continue
		}
		if e.roleOrAncestorsIsAdmin(ctx, parent, visited) {
			return true
		}
	}
	return false
}

func matchAction(pattern, actual Action) bool {
	if pattern == "*" || pattern == actual {
		return true
	}
	// Support wildcard matching: "document.*" matches "document.read"
	patternStr := string(pattern)
	actualStr := string(actual)
	if len(patternStr) > 0 && patternStr[len(patternStr)-1] == '*' {
		prefix := patternStr[:len(patternStr)-1]
		return len(actualStr) >= len(prefix) && actualStr[:len(prefix)] == prefix
	}
	return false
}

func matchResource(pattern string, resource *Resource) bool {
	// Fast accept-all
	if pattern == "*" {
		return true
	}

	// If this is a route pattern (we use "route:..." syntax in policies), convert
	// both pattern and resource into the "METHOD PATH" form expected by utils.MatchResource.
	if strings.HasPrefix(pattern, "route:") && resource.Type == "route" {
		rest := pattern[len("route:"):]
		if rest == "*" || rest == "" {
			return true
		}
		patMethod := ""
		patPath := rest
		if idx := strings.Index(rest, ":"); idx != -1 {
			patMethod = rest[:idx]
			patPath = rest[idx+1:]
		}

		resID := resource.ID
		resMethod := ""
		resPath := resID
		if idx := strings.Index(resID, ":"); idx != -1 {
			resMethod = resID[:idx]
			resPath = resID[idx+1:]
		}

		val := strings.TrimSpace(resMethod + " " + resPath)
		var pat string
		if patMethod != "" {
			pat = strings.TrimSpace(patMethod + " " + patPath)
		} else {
			pat = patPath
		}
		return utils.MatchResource(val, pat)
	}

	// Generic patterns: compare against "type:id" value using MatchResource utilities
	val := resource.Type + ":" + resource.ID
	return utils.MatchResource(val, pattern)
}

func (e *Engine) auditLog(_ context.Context, subject *Subject, action Action, resource *Resource, decision *Decision) {
	// Send a value copy to the async audit channel (non-blocking) to avoid
	// allocating an AuditEntry on the hot path.
	entry := AuditEntry{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp: decision.Timestamp,
		Subject:   subject,
		Action:    action,
		Resource:  resource,
		Decision:  decision,
	}

	// Log using phuslu/log for observability (non-blocking/opinionated)
	resStr := ""
	if resource != nil {
		resStr = resource.Type + ":" + resource.ID
	}
	subID := ""
	if subject != nil {
		subID = subject.ID
	}
	phlog.Info().
		Str("tenant", e.buildAuditTenantID(subject, resource)).
		Str("subject", subID).
		Any("action", action).
		Str("resource", resStr).
		Bool("allowed", decision.Allowed).
		Str("matched_by", decision.MatchedBy).
		Str("reason", decision.Reason).
		Msg("audit decision")

	select {
	case e.auditCh <- entry:
		// queued
	default:
		// drop if channel is full to avoid blocking hot path
	}
}

// BatchAuthorize evaluates multiple authorization requests
func (e *Engine) BatchAuthorize(ctx context.Context, requests []AuthRequest) ([]*Decision, error) {
	decisions := make([]*Decision, len(requests))
	for i, req := range requests {
		decision, err := e.Authorize(ctx, req.Subject, req.Action, req.Resource, req.Environment)
		if err != nil {
			return nil, err
		}
		decisions[i] = decision
	}
	return decisions, nil
}

type AuthRequest struct {
	Subject     *Subject
	Action      Action
	Resource    *Resource
	Environment *Environment
}

// ============================================================================
// POLICY OPERATIONS
// ============================================================================

func (e *Engine) CreatePolicy(ctx context.Context, policy *Policy) error {
	if err := e.ValidatePolicy(policy); err != nil {
		return err
	}
	policy.Version = 1
	policy.Enabled = true
	err := e.policyStore.CreatePolicy(ctx, policy)
	if err == nil {
		e.InvalidateDecisionCache()
	}
	return err
}

func (e *Engine) UpdatePolicy(ctx context.Context, policy *Policy) error {
	if err := e.ValidatePolicy(policy); err != nil {
		return err
	}
	err := e.policyStore.UpdatePolicy(ctx, policy)
	if err == nil {
		e.InvalidateDecisionCache()
	}
	return err
}

func (e *Engine) DeletePolicy(ctx context.Context, id string) error {
	err := e.policyStore.DeletePolicy(ctx, id)
	if err == nil {
		e.InvalidateDecisionCache()
	}
	return err
}

func (e *Engine) EnablePolicy(ctx context.Context, id string) error {
	policy, err := e.policyStore.GetPolicy(ctx, id)
	if err != nil {
		return err
	}
	policy.Enabled = true
	return e.policyStore.UpdatePolicy(ctx, policy)
}

func (e *Engine) DisablePolicy(ctx context.Context, id string) error {
	policy, err := e.policyStore.GetPolicy(ctx, id)
	if err != nil {
		return err
	}
	policy.Enabled = false
	return e.policyStore.UpdatePolicy(ctx, policy)
}

func (e *Engine) ValidatePolicy(policy *Policy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID is required")
	}
	if len(policy.Actions) == 0 {
		return fmt.Errorf("policy must have at least one action")
	}
	if len(policy.Resources) == 0 {
		return fmt.Errorf("policy must have at least one resource")
	}
	if policy.Condition == nil {
		return fmt.Errorf("policy must have a condition")
	}
	return nil
}

func (e *Engine) SimulatePolicy(ctx context.Context, policy *Policy, subject *Subject, action Action, resource *Resource, env *Environment) (bool, error) {
	evalCtx := e.getEvalCtx()
	evalCtx.Subject = subject
	evalCtx.Resource = resource
	evalCtx.Action = action
	evalCtx.Environment = env
	defer e.putEvalCtx(evalCtx)
	return policy.Condition.Evaluate(evalCtx)
}

// SetTenantResolver installs a tenant resolver for hierarchical tenant checks
func (e *Engine) SetTenantResolver(tr TenantResolver) {
	e.tenantResolver = tr
}

// ApplySignedBundle verifies signatures and applies policies to the store
func (e *Engine) ApplySignedBundle(ctx context.Context, pub ed25519.PublicKey, bundle *SignedPolicyBundle) error {
	ok, err := VerifyBundle(pub, bundle)
	if err != nil || !ok {
		return fmt.Errorf("bundle verification failed: %v", err)
	}
	// apply policies
	tenants := make(map[string]bool)
	for _, p := range bundle.Policies {
		// Validate policy
		if err := e.ValidatePolicy(p); err != nil {
			return fmt.Errorf("invalid policy %s: %v", p.ID, err)
		}
		// upsert using engine methods to ensure version/enabled and hooks
		if _, err := e.policyStore.GetPolicy(ctx, p.ID); err != nil {
			if err := e.CreatePolicy(ctx, p); err != nil {
				return err
			}
		} else {
			p.Version++
			if err := e.UpdatePolicy(ctx, p); err != nil {
				return err
			}
		}
		tenants[p.TenantID] = true
	}
	// reload per tenant
	for t := range tenants {
		_ = e.ReloadPolicies(ctx, t)
	}
	return nil
}

// ReplayDecision re-evaluates an audit entry and returns whether it matches
func (e *Engine) ReplayDecision(ctx context.Context, entry *AuditEntry) (*Decision, bool, error) {
	if entry == nil {
		return nil, false, fmt.Errorf("entry is nil")
	}
	newEnv := &Environment{Time: entry.Decision.Timestamp, TenantID: entry.Subject.TenantID}
	newDec, err := e.Authorize(ctx, entry.Subject, entry.Action, entry.Resource, newEnv)
	if err != nil {
		return nil, false, err
	}
	match := newDec.Allowed == entry.Decision.Allowed && newDec.MatchedBy == entry.Decision.MatchedBy
	return newDec, match, nil
}

// Decision cache helpers
func (e *Engine) buildCacheKey(subject *Subject, action Action, resource *Resource, env *Environment) DecisionKey {
	// include environment tenant to ensure cache key reflects the effective tenant context
	tenantID := subject.TenantID
	if env != nil && env.TenantID != "" {
		tenantID = env.TenantID
	}
	return DecisionKey{TenantID: tenantID, SubjectID: subject.ID, ResourceType: resource.Type, ResourceID: resource.ID, Action: action}
}

// pooled eval context helpers
func (e *Engine) getEvalCtx() *EvalContext {
	v := e.evalCtxPool.Get()
	if v == nil {
		return &EvalContext{}
	}
	return v.(*EvalContext)
}

func (e *Engine) putEvalCtx(c *EvalContext) {
	// clear fields to avoid accidental retention
	c.Subject = nil
	c.Resource = nil
	c.Action = ""
	c.Environment = nil
	e.evalCtxPool.Put(c)
}

func (e *Engine) getDecisionFromCache(key DecisionKey) (*Decision, bool) {
	e.decisionCacheMu.RLock()
	entry, ok := e.decisionCache[key]
	e.decisionCacheMu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.ExpiresAt) {
		e.decisionCacheMu.Lock()
		delete(e.decisionCache, key)
		e.decisionCacheMu.Unlock()
		return nil, false
	}
	return entry.Decision, true
}

// buildAuditTenantID returns a best-effort tenant id for logging: prefer resource tenant then subject
func (e *Engine) buildAuditTenantID(subject *Subject, resource *Resource) string {
	if resource != nil && resource.TenantID != "" {
		return resource.TenantID
	}
	if subject != nil {
		return subject.TenantID
	}
	return ""
}

func (e *Engine) setDecisionInCache(key DecisionKey, dec *Decision) {
	// make a small copy for cache and set a tiny trace to avoid copying long traces
	copyDec := *dec
	copyDec.Trace = []string{"(cached)"}
	entry := &DecisionCacheEntry{Decision: &copyDec, ExpiresAt: time.Now().Add(e.decisionCacheTTL)}
	e.decisionCacheMu.Lock()
	e.decisionCache[key] = entry
	e.decisionCacheMu.Unlock()
}
func (e *Engine) InvalidateDecisionCache() {
	// Simple full flush for now
	e.decisionCacheMu.Lock()
	defer e.decisionCacheMu.Unlock()
	for k := range e.decisionCache {
		delete(e.decisionCache, k)
	}
}

// Attribute providers
func (e *Engine) RegisterAttributeProvider(p AttributeProvider) {
	e.attrProviders = append(e.attrProviders, p)
}

// GetPolicyHistory wrapper
func (e *Engine) GetPolicyHistory(ctx context.Context, id string) ([]*Policy, error) {
	return e.policyStore.GetPolicyHistory(ctx, id)
}

// GetAccessLog wrapper
func (e *Engine) GetAccessLog(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error) {
	return e.auditStore.GetAccessLog(ctx, filter)
}

// ============================================================================
// ROLE OPERATIONS
// ============================================================================

func (e *Engine) CreateRole(ctx context.Context, role *Role) error {
	e.roleCache.Delete(role.ID)
	err := e.roleStore.CreateRole(ctx, role)
	if err == nil {
		e.InvalidateDecisionCache()
	}
	return err
}

func (e *Engine) UpdateRole(ctx context.Context, role *Role) error {
	e.roleCache.Delete(role.ID)
	err := e.roleStore.UpdateRole(ctx, role)
	if err == nil {
		e.InvalidateDecisionCache()
	}
	return err
}

func (e *Engine) DeleteRole(ctx context.Context, id string) error {
	e.roleCache.Delete(id)
	err := e.roleStore.DeleteRole(ctx, id)
	if err == nil {
		e.InvalidateDecisionCache()
	}
	return err
}

func (e *Engine) AssignRole(ctx context.Context, subject *Subject, roleID string) error {
	for _, r := range subject.Roles {
		if r == roleID {
			return nil
		}
	}
	subject.Roles = append(subject.Roles, roleID)
	return nil
}

func (e *Engine) RevokeRole(ctx context.Context, subject *Subject, roleID string) error {
	roles := make([]string, 0)
	for _, r := range subject.Roles {
		if r != roleID {
			roles = append(roles, r)
		}
	}
	subject.Roles = roles
	return nil
}

// ============================================================================
// ACL OPERATIONS
// ============================================================================

func (e *Engine) GrantACL(ctx context.Context, acl *ACL) error {
	err := e.aclStore.GrantACL(ctx, acl)
	if err == nil {
		e.InvalidateDecisionCache()
	}
	return err
}

func (e *Engine) RevokeACL(ctx context.Context, id string) error {
	err := e.aclStore.RevokeACL(ctx, id)
	if err == nil {
		e.InvalidateDecisionCache()
	}
	return err
}

func (e *Engine) ExpireACL(ctx context.Context, id string, expiresAt time.Time) error {
	// Implementation depends on ACL store capabilities
	return nil
}

func (e *Engine) ListEffectivePermissions(ctx context.Context, subject *Subject, resource *Resource) ([]Action, error) {
	actions := make([]Action, 0)

	// Check common actions
	testActions := []Action{"read", "write", "delete", "admin"}
	env := &Environment{
		Time:     time.Now(),
		TenantID: subject.TenantID,
	}

	for _, action := range testActions {
		decision, err := e.Authorize(ctx, subject, action, resource, env)
		if err != nil {
			continue
		}
		if decision.Allowed {
			actions = append(actions, action)
		}
	}

	return actions, nil
}

// ============================================================================
// HELPER: Expression Builder
// ============================================================================

// Builder provides a fluent API for creating expressions
type ExprBuilder struct {
	expr Expr
}

func NewExprBuilder() *ExprBuilder {
	return &ExprBuilder{}
}

func (b *ExprBuilder) SubjectHasRole(role string) *ExprBuilder {
	b.expr = &InExpr{
		Field:  "subject.roles",
		Values: []any{role},
	}
	return b
}

func (b *ExprBuilder) ResourceOwnedBySubject() *ExprBuilder {
	b.expr = &EqExpr{
		Field: "resource.owner_id",
		Value: "subject.id",
	}
	return b
}

// TimeBetweenExpr checks if env.time is between start and end (local time in HH:MM)
type TimeBetweenExpr struct {
	Start string // "09:00"
	End   string // "18:00"
}

func (e *TimeBetweenExpr) Evaluate(ctx *EvalContext) (bool, error) {
	t := ctx.Environment.Time
	start, err := time.Parse("15:04", e.Start)
	if err != nil {
		return false, err
	}
	end, err := time.Parse("15:04", e.End)
	if err != nil {
		return false, err
	}
	// Compare only hour/minute
	tTime := time.Date(0, 1, 1, t.Hour(), t.Minute(), 0, 0, time.UTC)
	startTime := time.Date(0, 1, 1, start.Hour(), start.Minute(), 0, 0, time.UTC)
	endTime := time.Date(0, 1, 1, end.Hour(), end.Minute(), 0, 0, time.UTC)
	if startTime.Before(endTime) || startTime.Equal(endTime) {
		return !tTime.Before(startTime) && !tTime.After(endTime), nil
	}
	// Over midnight
	return !tTime.Before(startTime) || !tTime.After(endTime), nil
}

func (e *TimeBetweenExpr) String() string {
	return fmt.Sprintf("time_between(%s,%s)", e.Start, e.End)
}

// CIDRExpr checks if env.ip is in the provided CIDR
type CIDRExpr struct {
	CIDR string
}

func (e *CIDRExpr) Evaluate(ctx *EvalContext) (bool, error) {
	if ctx.Environment.IP == nil {
		return false, nil
	}
	_, ipnet, err := net.ParseCIDR(e.CIDR)
	if err != nil {
		return false, err
	}
	return ipnet.Contains(ctx.Environment.IP), nil
}

func (e *CIDRExpr) String() string {
	return fmt.Sprintf("ip_in_cidr(%s)", e.CIDR)
}

// RegexExpr matches a string field against a regular expression
type RegexExpr struct {
	Field string
	Regex string
}

func (e *RegexExpr) Evaluate(ctx *EvalContext) (bool, error) {
	val := getField(ctx, e.Field)
	vs, ok := val.(string)
	if !ok {
		return false, nil
	}
	r, err := regexp.Compile(e.Regex)
	if err != nil {
		return false, err
	}
	return r.MatchString(vs), nil
}

func (e *RegexExpr) String() string {
	return fmt.Sprintf("regex(%s,%s)", e.Field, e.Regex)
}

// RangeExpr checks numeric ranges: supports int/float (inclusive)
type RangeExpr struct {
	Field string
	Min   float64
	Max   float64
}

func (e *RangeExpr) Evaluate(ctx *EvalContext) (bool, error) {
	val := getField(ctx, e.Field)
	switch v := val.(type) {
	case int:
		fv := float64(v)
		return fv >= e.Min && fv <= e.Max, nil
	case float64:
		return v >= e.Min && v <= e.Max, nil
	default:
		return false, nil
	}
}

func (e *RangeExpr) String() string {
	return fmt.Sprintf("range(%s,%v,%v)", e.Field, e.Min, e.Max)
}

func (b *ExprBuilder) And(other Expr) *ExprBuilder {
	b.expr = &AndExpr{Left: b.expr, Right: other}
	return b
}

func (b *ExprBuilder) Or(other Expr) *ExprBuilder {
	b.expr = &OrExpr{Left: b.expr, Right: other}
	return b
}

func (b *ExprBuilder) Build() Expr {
	if b.expr == nil {
		return &TrueExpr{}
	}
	return b.expr
}

// compilePredicate converts an Expr into a fast compiled predicate function
func compilePredicate(e Expr) CompiledPredicate {
	if e == nil {
		return func(ctx *EvalContext) (bool, error) { return true, nil }
	}

	switch v := e.(type) {
	case *TrueExpr:
		return func(ctx *EvalContext) (bool, error) { return true, nil }
	case *EqExpr:
		expr := v
		return func(ctx *EvalContext) (bool, error) {
			val := getField(ctx, expr.Field)
			switch ve := expr.Value.(type) {
			case string:
				if ve == "action" || len(ve) > 8 && (ve[:8] == "subject." || ve[:9] == "resource." || ve[:4] == "env.") {
					rv := getField(ctx, ve)
					return compare(val, rv) == 0, nil
				}
			}
			return compare(val, expr.Value) == 0, nil
		}
	case *InExpr:
		expr := v
		return func(ctx *EvalContext) (bool, error) {
			val := getField(ctx, expr.Field)
			for _, vv := range expr.Values {
				switch vvs := vv.(type) {
				case string:
					if vvs == "action" || len(vvs) > 8 && (vvs[:8] == "subject." || vvs[:9] == "resource." || vvs[:4] == "env.") {
						rv := getField(ctx, vvs)
						if compare(val, rv) == 0 {
							return true, nil
						}
						continue
					}
				}
				if compare(val, vv) == 0 {
					return true, nil
				}
			}
			return false, nil
		}
	case *GteExpr:
		expr := v
		return func(ctx *EvalContext) (bool, error) {
			val := getField(ctx, expr.Field)
			switch ve := expr.Value.(type) {
			case string:
				if ve == "action" || len(ve) > 8 && (ve[:8] == "subject." || ve[:9] == "resource." || ve[:4] == "env.") {
					rv := getField(ctx, ve)
					return compare(val, rv) >= 0, nil
				}
			}
			return compare(val, expr.Value) >= 0, nil
		}
	case *AndExpr:
		left := compilePredicate(v.Left)
		right := compilePredicate(v.Right)
		return func(ctx *EvalContext) (bool, error) {
			l, err := left(ctx)
			if err != nil || !l {
				return false, err
			}
			return right(ctx)
		}
	case *OrExpr:
		left := compilePredicate(v.Left)
		right := compilePredicate(v.Right)
		return func(ctx *EvalContext) (bool, error) {
			l, err := left(ctx)
			if err != nil {
				return false, err
			}
			if l {
				return true, nil
			}
			return right(ctx)
		}
	case *TimeBetweenExpr:
		expr := v
		start, _ := time.Parse("15:04", expr.Start)
		end, _ := time.Parse("15:04", expr.End)
		return func(ctx *EvalContext) (bool, error) {
			t := ctx.Environment.Time
			// Compare only hour/minute
			tTime := time.Date(0, 1, 1, t.Hour(), t.Minute(), 0, 0, time.UTC)
			startTime := time.Date(0, 1, 1, start.Hour(), start.Minute(), 0, 0, time.UTC)
			endTime := time.Date(0, 1, 1, end.Hour(), end.Minute(), 0, 0, time.UTC)
			if startTime.Before(endTime) || startTime.Equal(endTime) {
				return !tTime.Before(startTime) && !tTime.After(endTime), nil
			}
			// Over midnight
			return !tTime.Before(startTime) || !tTime.After(endTime), nil
		}
	case *CIDRExpr:
		expr := v
		_, ipnet, _ := net.ParseCIDR(expr.CIDR)
		return func(ctx *EvalContext) (bool, error) {
			if ctx.Environment.IP == nil {
				return false, nil
			}
			return ipnet.Contains(ctx.Environment.IP), nil
		}
	case *RegexExpr:
		expr := v
		rg := regexp.MustCompile(expr.Regex)
		return func(ctx *EvalContext) (bool, error) {
			val := getField(ctx, expr.Field)
			vs, ok := val.(string)
			if !ok {
				return false, nil
			}
			return rg.MatchString(vs), nil
		}
	case *RangeExpr:
		expr := v
		return func(ctx *EvalContext) (bool, error) {
			val := getField(ctx, expr.Field)
			switch vv := val.(type) {
			case int:
				fv := float64(vv)
				return fv >= expr.Min && fv <= expr.Max, nil
			case float64:
				return vv >= expr.Min && vv <= expr.Max, nil
			default:
				return false, nil
			}
		}
	default:
		// fallback to dynamic evaluation
		return func(ctx *EvalContext) (bool, error) { return e.Evaluate(ctx) }
	}
}

// hasOwnerEquality returns true if expression contains EqExpr comparing resource.owner_id to subject.id
func hasOwnerEquality(e Expr) bool {
	if e == nil {
		return false
	}
	switch v := e.(type) {
	case *EqExpr:
		if v.Field == "resource.owner_id" {
			if s, ok := v.Value.(string); ok && s == "subject.id" {
				return true
			}
		}
		return false
	case *AndExpr:
		return hasOwnerEquality(v.Left) || hasOwnerEquality(v.Right)
	case *OrExpr:
		return hasOwnerEquality(v.Left) || hasOwnerEquality(v.Right)
	default:
		return false
	}
}
