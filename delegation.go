package authz

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// DELEGATION
// ============================================================================

// DelegationGrant represents subject A (the delegator) handing off a bounded
// set of actions on a resource pattern to subject B (the delegate) for a
// time-boxed window, optionally capped by a maximum number of uses.
//
// Safety invariant: a delegation can never grant the delegate more than the
// delegator itself could do. Engine.CreateDelegation enforces this by running
// the delegator's own request through Engine.Authorize, for every action being
// delegated, before the grant is persisted. Delegation therefore only forwards
// authority the delegator already holds; it is not a capability-amplification
// path. This check is performed at grant-creation time only: if the
// delegator's underlying authorization is revoked afterwards, an already
// issued grant is not automatically invalidated — callers that need that
// guarantee should revoke the delegation explicitly via RevokeDelegation.
type DelegationGrant struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id,omitempty"`
	DelegatorID     string    `json:"delegator_id"`
	DelegateID      string    `json:"delegate_id"`
	Actions         []Action  `json:"actions"`
	ResourcePattern string    `json:"resource_pattern"` // e.g. "document:*" or "document:123"
	StartsAt        time.Time `json:"starts_at"`        // zero = active immediately
	ExpiresAt       time.Time `json:"expires_at"`       // zero = no expiry
	MaxUses         int       `json:"max_uses,omitempty"`
	UseCount        int       `json:"use_count"`
	Revoked         bool      `json:"revoked"`
	RevokedAt       time.Time `json:"revoked_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// activeAt reports whether the grant is usable at time t: not revoked, within
// its start/expiry window, and (if capped) has remaining uses.
func (g *DelegationGrant) activeAt(t time.Time) bool {
	if g == nil || g.Revoked {
		return false
	}
	if !g.StartsAt.IsZero() && t.Before(g.StartsAt) {
		return false
	}
	if !g.ExpiresAt.IsZero() && t.After(g.ExpiresAt) {
		return false
	}
	if g.MaxUses > 0 && g.UseCount >= g.MaxUses {
		return false
	}
	return true
}

func (g *DelegationGrant) allowsAction(action Action) bool {
	for _, a := range g.Actions {
		if a == action || a == "*" {
			return true
		}
	}
	return false
}

// DelegationStore manages delegation grant persistence.
type DelegationStore interface {
	Create(ctx context.Context, grant *DelegationGrant) error
	Get(ctx context.Context, id string) (*DelegationGrant, error)
	List(ctx context.Context, tenantID string) ([]*DelegationGrant, error)
	ListByDelegate(ctx context.Context, delegateID string) ([]*DelegationGrant, error)
	Revoke(ctx context.Context, id string) error
	// IncrementUse records one use of the grant; used to enforce MaxUses.
	IncrementUse(ctx context.Context, id string) error
}

// WithDelegationStore configures the engine's delegation grant store. Without
// this option, delegation checks and Engine.CreateDelegation/RevokeDelegation
// are no-ops/errors.
func WithDelegationStore(s DelegationStore) EngineOption {
	return func(e *Engine) error {
		e.delegationStore = s
		return nil
	}
}

// delegationProbeResource builds a synthetic resource from a delegation
// resource pattern ("type:id" or "type:*") so the delegator's own authority
// over that pattern can be checked via the normal Authorize path.
func delegationProbeResource(pattern, tenantID string) *Resource {
	resType := pattern
	resID := "*"
	if idx := strings.Index(pattern, ":"); idx != -1 {
		resType = pattern[:idx]
		resID = pattern[idx+1:]
	}
	return &Resource{Type: resType, ID: resID, TenantID: tenantID}
}

// checkDelegation looks for a non-revoked, currently-active delegation grant
// authorizing subject to perform action on resource. It is invoked from
// Engine.authorizeInternal as an additional allow path, analogous to the ACL
// allow check.
func (e *Engine) checkDelegation(ctx context.Context, subject *Subject, resource *Resource, action Action, at time.Time) (bool, string, []string) {
	trace := make([]string, 0)
	if e.delegationStore == nil || subject == nil || resource == nil {
		return false, "", trace
	}
	grants, err := e.delegationStore.ListByDelegate(ctx, subject.ID)
	if err != nil || len(grants) == 0 {
		return false, "", trace
	}
	if at.IsZero() {
		at = time.Now()
	}
	for _, g := range grants {
		if !g.activeAt(at) {
			trace = append(trace, fmt.Sprintf("delegation=%s inactive_or_expired", g.ID))
			continue
		}
		if !g.allowsAction(action) {
			continue
		}
		if !matchResource(g.ResourcePattern, resource) {
			continue
		}
		trace = append(trace, fmt.Sprintf("delegation=%s match delegator=%s", g.ID, g.DelegatorID))
		_ = e.delegationStore.IncrementUse(ctx, g.ID)
		return true, g.ID, trace
	}
	return false, "", trace
}

// CreateDelegation records a new delegation grant from delegator to delegate.
// It refuses to create the grant unless the delegator is itself authorized,
// right now, for every action being delegated over the given resource
// pattern — a subject cannot delegate a capability it does not hold.
func (e *Engine) CreateDelegation(ctx context.Context, delegator, delegate *Subject, actions []Action, resourcePattern string, startsAt, expiresAt time.Time, maxUses int) (*DelegationGrant, error) {
	if e.delegationStore == nil {
		return nil, fmt.Errorf("authz: no delegation store configured")
	}
	if delegator == nil || delegate == nil {
		return nil, fmt.Errorf("authz: delegator and delegate subjects are required")
	}
	if resourcePattern == "" {
		return nil, fmt.Errorf("authz: resource pattern is required")
	}
	if len(actions) == 0 {
		return nil, fmt.Errorf("authz: at least one action must be delegated")
	}
	if !expiresAt.IsZero() && !startsAt.IsZero() && expiresAt.Before(startsAt) {
		return nil, fmt.Errorf("authz: delegation expiry cannot be before its start time")
	}

	probe := delegationProbeResource(resourcePattern, delegator.TenantID)
	env := &Environment{Time: time.Now(), TenantID: delegator.TenantID}
	for _, action := range actions {
		decision, err := e.Authorize(ctx, delegator, action, probe, env)
		if err != nil {
			return nil, fmt.Errorf("authz: checking delegator authority for action %q: %w", action, err)
		}
		if !decision.Allowed {
			return nil, fmt.Errorf("authz: delegator %s is not authorized to perform %q on %q; a subject cannot delegate a permission it does not have", delegator.ID, action, resourcePattern)
		}
	}

	grant := &DelegationGrant{
		ID:              GenerateSecureID("delegation"),
		TenantID:        delegator.TenantID,
		DelegatorID:     delegator.ID,
		DelegateID:      delegate.ID,
		Actions:         actions,
		ResourcePattern: resourcePattern,
		StartsAt:        startsAt,
		ExpiresAt:       expiresAt,
		MaxUses:         maxUses,
		CreatedAt:       time.Now(),
	}
	if err := e.delegationStore.Create(ctx, grant); err != nil {
		return nil, err
	}
	e.InvalidateDecisionCache()
	return grant, nil
}

// RevokeDelegation revokes a delegation grant. Only the original delegator or
// a cross-tenant admin may revoke it; revocation takes effect immediately for
// subsequent Authorize calls (the decision cache is invalidated).
func (e *Engine) RevokeDelegation(ctx context.Context, revoker *Subject, delegationID string) error {
	if e.delegationStore == nil {
		return fmt.Errorf("authz: no delegation store configured")
	}
	grant, err := e.delegationStore.Get(ctx, delegationID)
	if err != nil {
		return err
	}
	if revoker != nil && grant.DelegatorID != revoker.ID && !e.isCrossTenantAdmin(ctx, revoker) {
		return fmt.Errorf("authz: subject %s is not authorized to revoke delegation %s", revoker.ID, delegationID)
	}
	if err := e.delegationStore.Revoke(ctx, delegationID); err != nil {
		return err
	}
	e.InvalidateDecisionCache()
	return nil
}

// ============================================================================
// BREAK-GLASS / EMERGENCY ACCESS
// ============================================================================

// BreakGlassAction marks the synthetic action recorded on the audit trail for
// every break-glass invocation, distinct from the action actually performed,
// so break-glass usage can be filtered and alerted on independently.
const BreakGlassAction Action = "breakglass.invoke"

// BreakGlassRequest captures the inputs of an emergency access invocation.
type BreakGlassRequest struct {
	Subject       *Subject
	Action        Action
	Resource      *Resource
	Environment   *Environment
	Justification string
}

// AuthorizeBreakGlass grants emergency access unconditionally (fail-open by
// design) so that a genuine emergency is never blocked by policy. It is a
// separate, explicitly-named method from Authorize so break-glass access can
// never be triggered accidentally by ordinary request handling.
//
// Every invocation, regardless of outcome, produces a high-visibility audit
// entry: the action is recorded as BreakGlassAction, Decision.Reason and
// Decision.Trace are flagged, and the AuditEntry.Metadata carries
// "break_glass": true and the caller-supplied justification. A non-empty
// justification is mandatory.
func (e *Engine) AuthorizeBreakGlass(ctx context.Context, subject *Subject, action Action, resource *Resource, env *Environment, justification string) (*Decision, error) {
	if subject == nil {
		return nil, fmt.Errorf("authz: subject is required for break-glass access")
	}
	if resource == nil {
		return nil, fmt.Errorf("authz: resource is required for break-glass access")
	}
	if strings.TrimSpace(justification) == "" {
		return nil, fmt.Errorf("authz: break-glass access requires a post-hoc justification")
	}

	now := time.Now()
	if env != nil && !env.Time.IsZero() {
		now = env.Time
	}

	decision := &Decision{
		Allowed:   true,
		Reason:    fmt.Sprintf("BREAK-GLASS EMERGENCY ACCESS GRANTED: %s", justification),
		MatchedBy: "breakglass",
		Timestamp: now,
		Trace: []string{
			fmt.Sprintf("BREAK-GLASS: fail-open emergency override for action=%s resource=%s:%s", action, resource.Type, resource.ID),
			fmt.Sprintf("justification=%q", justification),
		},
	}

	entry := &AuditEntry{
		ID:        GenerateSecureID("breakglass"),
		Timestamp: now,
		Subject:   subject,
		Action:    BreakGlassAction,
		Resource:  resource,
		Decision:  decision,
		TraceID:   GenerateSecureID("trace"),
		Metadata: map[string]any{
			"break_glass":     true,
			"flagged":         "HIGH_VISIBILITY_BREAK_GLASS",
			"justification":   justification,
			"original_action": string(action),
		},
	}
	e.recordBreakGlassAudit(ctx, entry)

	return decision, nil
}

// recordBreakGlassAudit writes the break-glass audit entry synchronously to
// the configured AuditStore (bypassing the best-effort async batch channel
// used by ordinary decisions) so a break-glass invocation is never silently
// dropped, plus a loud structured log line.
func (e *Engine) recordBreakGlassAudit(ctx context.Context, entry *AuditEntry) {
	if e.logger != nil {
		e.logger.Error("BREAK-GLASS emergency access invoked",
			"subject", entry.Subject.ID,
			"original_action", entry.Metadata["original_action"],
			"resource", entry.Resource.Type+":"+entry.Resource.ID,
			"justification", entry.Metadata["justification"],
			"trace_id", entry.TraceID,
		)
	}
	if e.auditStore != nil {
		_ = e.auditStore.LogDecision(ctx, entry)
	}
}
