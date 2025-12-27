package stores

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLPolicyStore persists policies in SQL (squealx)
type SQLPolicyStore struct {
	db *squealx.DB
}

func NewSQLPolicyStore(db *squealx.DB) *SQLPolicyStore {
	return &SQLPolicyStore{db: db}
}

func (s *SQLPolicyStore) CreatePolicy(ctx context.Context, p *authz.Policy) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	actions, _ := json.Marshal(p.Actions)
	resources, _ := json.Marshal(p.Resources)
	cond := ""
	if p.Condition != nil {
		cond = p.Condition.String()
	}
	q := `INSERT INTO policies(id, tenant_id, effect, actions_json, resources_json, condition_text, priority, enabled, version, created_at, updated_at) VALUES(:id, :tenant_id, :effect, :actions_json, :resources_json, :condition_text, :priority, :enabled, :version, :created_at, :updated_at)`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":             p.ID,
		"tenant_id":      p.TenantID,
		"effect":         string(p.Effect),
		"actions_json":   string(actions),
		"resources_json": string(resources),
		"condition_text": cond,
		"priority":       p.Priority,
		"enabled":        boolToInt(p.Enabled),
		"version":        p.Version,
		"created_at":     p.CreatedAt,
		"updated_at":     p.UpdatedAt,
	})
	if err != nil {
		return err
	}
	// insert initial snapshot into policy_history for immutability/audit
	if err := s.insertPolicyHistory(ctx, p); err != nil {
		return err
	}
	return nil
}

func (s *SQLPolicyStore) UpdatePolicy(ctx context.Context, p *authz.Policy) error {
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now()
	}
	// snapshot current policy to history (append-only)
	if err := s.snapshotExistingPolicy(ctx, p.ID); err != nil {
		return err
	}
	actions, _ := json.Marshal(p.Actions)
	resources, _ := json.Marshal(p.Resources)
	cond := ""
	if p.Condition != nil {
		cond = p.Condition.String()
	}
	q := `UPDATE policies SET tenant_id=:tenant_id, effect=:effect, actions_json=:actions_json, resources_json=:resources_json, condition_text=:condition_text, priority=:priority, enabled=:enabled, version=:version, updated_at=:updated_at WHERE id=:id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":             p.ID,
		"tenant_id":      p.TenantID,
		"effect":         string(p.Effect),
		"actions_json":   string(actions),
		"resources_json": string(resources),
		"condition_text": cond,
		"priority":       p.Priority,
		"enabled":        boolToInt(p.Enabled),
		"version":        p.Version,
		"updated_at":     p.UpdatedAt,
	})
	if err != nil {
		return err
	}
	// insert snapshot after successful update as an additional immutable record
	if err := s.insertPolicyHistory(ctx, p); err != nil {
		return err
	}
	return nil
}

func (s *SQLPolicyStore) DeletePolicy(ctx context.Context, id string) error {
	q := `DELETE FROM policies WHERE id = :id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"id": id})
	return err
}

func (s *SQLPolicyStore) GetPolicy(ctx context.Context, id string) (*authz.Policy, error) {
	q := `SELECT id, tenant_id, effect, actions_json, resources_json, condition_text, priority, enabled, version, created_at, updated_at FROM policies WHERE id = :id`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if !r.Next() {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	var idv, tenant, effect, actionsJSON, resourcesJSON, cond string
	var priority int
	var enabledInt int
	var version int
	var createdRaw interface{}
	var updatedRaw interface{}
	if err := r.Scan(&idv, &tenant, &effect, &actionsJSON, &resourcesJSON, &cond, &priority, &enabledInt, &version, &createdRaw, &updatedRaw); err != nil {
		return nil, err
	}
	p := &authz.Policy{ID: idv, TenantID: tenant, Effect: authz.Effect(effect), Priority: priority, Version: version, Enabled: enabledInt != 0}
	var acts []authz.Action
	_ = json.Unmarshal([]byte(actionsJSON), &acts)
	p.Actions = acts
	var ress []string
	_ = json.Unmarshal([]byte(resourcesJSON), &ress)
	p.Resources = ress
	if cond == "" {
		p.Condition = &authz.TrueExpr{}
	} else {
		if expr, err := authz.ParseCondition(cond); err == nil {
			p.Condition = expr
		} else {
			p.Condition = &authz.TrueExpr{}
		}
	}
	if createdRaw != nil {
		switch v := createdRaw.(type) {
		case time.Time:
			p.CreatedAt = v
		case string:
			if t, err := parseFlexibleTime(v); err == nil {
				p.CreatedAt = t
			}
		case []byte:
			if t, err := parseFlexibleTime(string(v)); err == nil {
				p.CreatedAt = t
			}
		}
	}
	if updatedRaw != nil {
		switch v := updatedRaw.(type) {
		case time.Time:
			p.UpdatedAt = v
		case string:
			if t, err := parseFlexibleTime(v); err == nil {
				p.UpdatedAt = t
			}
		case []byte:
			if t, err := parseFlexibleTime(string(v)); err == nil {
				p.UpdatedAt = t
			}
		}
	}
	return p, nil
}

func (s *SQLPolicyStore) ListPolicies(ctx context.Context, tenantID string) ([]*authz.Policy, error) {
	q := `SELECT id FROM policies WHERE tenant_id = :tenant_id OR tenant_id = ''`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"tenant_id": tenantID})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := make([]*authz.Policy, 0)
	for r.Next() {
		var id string
		_ = r.Scan(&id)
		if p, err := s.GetPolicy(ctx, id); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// snapshotExistingPolicy reads the current policy and inserts it into the history table
func (s *SQLPolicyStore) snapshotExistingPolicy(ctx context.Context, id string) error {
	p, err := s.GetPolicy(ctx, id)
	if err != nil {
		return err
	}
	return s.insertPolicyHistory(ctx, p)
}

// insertPolicyHistory inserts a JSON snapshot of the given policy into the policy_history table
func (s *SQLPolicyStore) insertPolicyHistory(ctx context.Context, p *authz.Policy) error {
	// create a lightweight snapshot with condition_text stringified
	snap := map[string]any{
		"id":             p.ID,
		"tenant_id":      p.TenantID,
		"effect":         string(p.Effect),
		"actions":        p.Actions,
		"resources":      p.Resources,
		"condition_text": "",
	}
	if p.Condition != nil {
		snap["condition_text"] = p.Condition.String()
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	q := `INSERT INTO policy_history(policy_id, snapshot_json) VALUES(:policy_id, :snapshot_json)`
	_, err = s.db.NamedExecContext(ctx, q, map[string]any{"policy_id": p.ID, "snapshot_json": string(b)})
	return err
}

func (s *SQLPolicyStore) GetPolicyHistory(ctx context.Context, id string) ([]*authz.Policy, error) {
	q := `SELECT snapshot_json FROM policy_history WHERE policy_id = :policy_id ORDER BY created_at ASC`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"policy_id": id})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := make([]*authz.Policy, 0)
	for r.Next() {
		var snap string
		if err := r.Scan(&snap); err != nil {
			return nil, err
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(snap), &raw); err != nil {
			return nil, err
		}
		p := &authz.Policy{}
		if idv, ok := raw["id"].(string); ok {
			p.ID = idv
		}
		if tenant, ok := raw["tenant_id"].(string); ok {
			p.TenantID = tenant
		}
		if eff, ok := raw["effect"].(string); ok {
			p.Effect = authz.Effect(eff)
		}
		if acts, ok := raw["actions"].([]any); ok {
			arr := make([]authz.Action, 0, len(acts))
			for _, it := range acts {
				if s, ok := it.(string); ok {
					arr = append(arr, authz.Action(s))
				}
			}
			p.Actions = arr
		}
		if ress, ok := raw["resources"].([]any); ok {
			arr := make([]string, 0, len(ress))
			for _, it := range ress {
				if s, ok := it.(string); ok {
					arr = append(arr, s)
				}
			}
			p.Resources = arr
		}
		if cond, ok := raw["condition_text"].(string); ok {
			if expr, err := authz.ParseCondition(cond); err == nil {
				p.Condition = expr
			} else {
				p.Condition = &authz.TrueExpr{}
			}
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no history for policy %s", id)
	}
	return out, nil
}
