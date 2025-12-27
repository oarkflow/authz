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
	return err
}

func (s *SQLPolicyStore) UpdatePolicy(ctx context.Context, p *authz.Policy) error {
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now()
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
	return err
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
		p.Condition = &authz.TrueExpr{}
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

func (s *SQLPolicyStore) GetPolicyHistory(ctx context.Context, id string) ([]*authz.Policy, error) {
	return nil, nil
}
