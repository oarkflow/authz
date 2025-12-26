package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
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
	// Simple comparison logic - extend as needed
	switch av := a.(type) {
	case string:
		if bv, ok := b.(string); ok {
			if av == bv {
				return 0
			}
			if av < bv {
				return -1
			}
			return 1
		}
	case int:
		if bv, ok := b.(int); ok {
			return av - bv
		}
	case float64:
		if bv, ok := b.(float64); ok {
			if av == bv {
				return 0
			}
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ============================================================================
// RBAC (Derived from ABAC)
// ============================================================================

// Role represents a named collection of permissions
type Role struct {
	ID          string       `json:"id"`
	TenantID    string       `json:"tenant_id"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
	Inherits    []string     `json:"inherits"` // role IDs
	CreatedAt   time.Time    `json:"created_at"`
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
	mu       sync.RWMutex
	policies map[string]*Policy
}

func NewMemoryPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{
		policies: make(map[string]*Policy),
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
	p.UpdatedAt = time.Now()
	p.Version++
	s.policies[p.ID] = p
	return nil
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
		if acl.ResourceID == resourceID && !acl.IsExpired() {
			result = append(result, acl)
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

type PolicyIndex struct {
	mu             sync.RWMutex
	byAction       map[Action][]*Policy
	byResourceType map[string][]*Policy
	byTenant       map[string][]*Policy
	compiled       []*Policy
	lastCompiled   time.Time
}

func NewPolicyIndex() *PolicyIndex {
	return &PolicyIndex{
		byAction:       make(map[Action][]*Policy),
		byResourceType: make(map[string][]*Policy),
		byTenant:       make(map[string][]*Policy),
		compiled:       make([]*Policy, 0),
	}
}

func (idx *PolicyIndex) Rebuild(policies []*Policy) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.byAction = make(map[Action][]*Policy)
	idx.byResourceType = make(map[string][]*Policy)
	idx.byTenant = make(map[string][]*Policy)
	idx.compiled = make([]*Policy, 0, len(policies))

	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		idx.compiled = append(idx.compiled, p)

		for _, action := range p.Actions {
			idx.byAction[action] = append(idx.byAction[action], p)
		}

		for _, res := range p.Resources {
			resType := extractResourceType(res)
			idx.byResourceType[resType] = append(idx.byResourceType[resType], p)
		}

		idx.byTenant[p.TenantID] = append(idx.byTenant[p.TenantID], p)
	}

	// Sort by priority (descending)
	sort.Slice(idx.compiled, func(i, j int) bool {
		return idx.compiled[i].Priority > idx.compiled[j].Priority
	})

	idx.lastCompiled = time.Now()
}

func (idx *PolicyIndex) GetRelevantPolicies(action Action, resourceType, tenantID string) []*Policy {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	// Use intersection of all three indexes for optimal performance
	candidates := make(map[*Policy]bool)

	for _, p := range idx.byAction[action] {
		candidates[p] = true
	}

	result := make([]*Policy, 0)
	for _, p := range idx.byTenant[tenantID] {
		if candidates[p] {
			result = append(result, p)
		}
	}

	// If no tenant-specific policies, include global policies
	if len(result) == 0 {
		for _, p := range idx.byTenant[""] {
			if candidates[p] {
				result = append(result, p)
			}
		}
	}

	return result
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

type Engine struct {
	policyStore PolicyStore
	roleStore   RoleStore
	aclStore    ACLStore
	auditStore  AuditStore
	policyIndex *PolicyIndex
	roleCache   sync.Map
}

func NewEngine(
	policyStore PolicyStore,
	roleStore RoleStore,
	aclStore ACLStore,
	auditStore AuditStore,
) *Engine {
	return &Engine{
		policyStore: policyStore,
		roleStore:   roleStore,
		aclStore:    aclStore,
		auditStore:  auditStore,
		policyIndex: NewPolicyIndex(),
	}
}

// ReloadPolicies rebuilds the policy index
func (e *Engine) ReloadPolicies(ctx context.Context, tenantID string) error {
	policies, err := e.policyStore.ListPolicies(ctx, tenantID)
	if err != nil {
		return err
	}
	e.policyIndex.Rebuild(policies)
	return nil
}

// Authorize makes an authorization decision
func (e *Engine) Authorize(ctx context.Context, subject *Subject, action Action, resource *Resource, env *Environment) (*Decision, error) {
	start := time.Now()
	decision := &Decision{
		Allowed:   false,
		Trace:     make([]string, 0),
		Timestamp: start,
	}

	// Multi-tenancy enforcement
	if subject.TenantID != env.TenantID || resource.TenantID != env.TenantID {
		decision.Reason = "tenant mismatch"
		decision.Trace = append(decision.Trace, "DENY: tenant isolation violation")
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}

	evalCtx := &EvalContext{
		Subject:     subject,
		Resource:    resource,
		Action:      action,
		Environment: env,
	}

	// 1. Explicit DENY (highest precedence)
	decision.Trace = append(decision.Trace, "1. Checking explicit DENY policies...")
	if denied, policyID := e.checkPolicies(ctx, evalCtx, EffectDeny); denied {
		decision.Reason = "explicit deny policy"
		decision.MatchedBy = policyID
		decision.Trace = append(decision.Trace, fmt.Sprintf("   DENY by policy: %s", policyID))
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}

	// 2. ACL Allow
	decision.Trace = append(decision.Trace, "2. Checking ACL allow...")
	if allowed, aclID := e.checkACL(ctx, subject.ID, resource.ID, action, EffectAllow); allowed {
		decision.Allowed = true
		decision.Reason = "acl allow"
		decision.MatchedBy = aclID
		decision.Trace = append(decision.Trace, fmt.Sprintf("   ALLOW by ACL: %s", aclID))
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}

	// 3. ABAC Policy Allow
	decision.Trace = append(decision.Trace, "3. Checking ABAC policy allow...")
	if allowed, policyID := e.checkPolicies(ctx, evalCtx, EffectAllow); allowed {
		decision.Allowed = true
		decision.Reason = "abac policy allow"
		decision.MatchedBy = policyID
		decision.Trace = append(decision.Trace, fmt.Sprintf("   ALLOW by policy: %s", policyID))
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}

	// 4. RBAC-derived Allow
	decision.Trace = append(decision.Trace, "4. Checking RBAC-derived allow...")
	if allowed, roleID := e.checkRBAC(ctx, subject, action, resource); allowed {
		decision.Allowed = true
		decision.Reason = "rbac allow"
		decision.MatchedBy = roleID
		decision.Trace = append(decision.Trace, fmt.Sprintf("   ALLOW by role: %s", roleID))
		e.auditLog(ctx, subject, action, resource, decision)
		return decision, nil
	}

	// 5. Default DENY
	decision.Reason = "default deny"
	decision.Trace = append(decision.Trace, "5. Default DENY (no matching allow rules)")
	e.auditLog(ctx, subject, action, resource, decision)
	return decision, nil
}

// Explain returns a detailed trace of the authorization decision
func (e *Engine) Explain(ctx context.Context, subject *Subject, action Action, resource *Resource, env *Environment) (*Decision, error) {
	return e.Authorize(ctx, subject, action, resource, env)
}

func (e *Engine) checkPolicies(_ context.Context, evalCtx *EvalContext, effect Effect) (bool, string) {
	policies := e.policyIndex.GetRelevantPolicies(
		evalCtx.Action,
		evalCtx.Resource.Type,
		evalCtx.Environment.TenantID,
	)

	for _, policy := range policies {
		if policy.Effect != effect {
			continue
		}

		// Check if action matches
		actionMatches := false
		for _, a := range policy.Actions {
			if matchAction(a, evalCtx.Action) {
				actionMatches = true
				break
			}
		}
		if !actionMatches {
			continue
		}

		// Check if resource matches
		resourceMatches := false
		for _, r := range policy.Resources {
			if matchResource(r, evalCtx.Resource) {
				resourceMatches = true
				break
			}
		}
		if !resourceMatches {
			continue
		}

		// Evaluate condition
		matched, err := policy.Condition.Evaluate(evalCtx)
		if err != nil {
			continue
		}
		if matched {
			return true, policy.ID
		}
	}
	return false, ""
}

func (e *Engine) checkACL(ctx context.Context, subjectID, resourceID string, action Action, effect Effect) (bool, string) {
	acls, err := e.aclStore.ListACLsByResource(ctx, resourceID)
	if err != nil {
		return false, ""
	}

	for _, acl := range acls {
		if acl.SubjectID != subjectID || acl.Effect != effect {
			continue
		}
		for _, a := range acl.Actions {
			if a == action || a == "*" {
				return true, acl.ID
			}
		}
	}
	return false, ""
}

func (e *Engine) checkRBAC(ctx context.Context, subject *Subject, action Action, resource *Resource) (bool, string) {
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
		if e.roleHasPermission(ctx, parent, action, resource) {
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
	if pattern == "*" {
		return true
	}

	// Extract type and ID from pattern: "document:123" or "document:*"
	resourceStr := resource.Type + ":" + resource.ID

	if pattern == resourceStr {
		return true
	}

	// Wildcard matching: "document:*" matches any document
	for i, ch := range pattern {
		if ch == '*' {
			prefix := pattern[:i]
			return len(resourceStr) >= len(prefix) && resourceStr[:len(prefix)] == prefix
		}
	}

	return false
}

func (e *Engine) auditLog(ctx context.Context, subject *Subject, action Action, resource *Resource, decision *Decision) {
	entry := &AuditEntry{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp: decision.Timestamp,
		Subject:   subject,
		Action:    action,
		Resource:  resource,
		Decision:  decision,
	}
	_ = e.auditStore.LogDecision(ctx, entry)
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
	return e.policyStore.CreatePolicy(ctx, policy)
}

func (e *Engine) UpdatePolicy(ctx context.Context, policy *Policy) error {
	if err := e.ValidatePolicy(policy); err != nil {
		return err
	}
	return e.policyStore.UpdatePolicy(ctx, policy)
}

func (e *Engine) DeletePolicy(ctx context.Context, id string) error {
	return e.policyStore.DeletePolicy(ctx, id)
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
	evalCtx := &EvalContext{
		Subject:     subject,
		Resource:    resource,
		Action:      action,
		Environment: env,
	}
	return policy.Condition.Evaluate(evalCtx)
}

// ============================================================================
// ROLE OPERATIONS
// ============================================================================

func (e *Engine) CreateRole(ctx context.Context, role *Role) error {
	e.roleCache.Delete(role.ID)
	return e.roleStore.CreateRole(ctx, role)
}

func (e *Engine) UpdateRole(ctx context.Context, role *Role) error {
	e.roleCache.Delete(role.ID)
	return e.roleStore.UpdateRole(ctx, role)
}

func (e *Engine) DeleteRole(ctx context.Context, id string) error {
	e.roleCache.Delete(id)
	return e.roleStore.DeleteRole(ctx, id)
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
	return e.aclStore.GrantACL(ctx, acl)
}

func (e *Engine) RevokeACL(ctx context.Context, id string) error {
	return e.aclStore.RevokeACL(ctx, id)
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
