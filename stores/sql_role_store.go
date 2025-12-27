package stores

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLRoleStore persists roles in SQL (squealx)
type SQLRoleStore struct {
	db *squealx.DB
}

func NewSQLRoleStore(db *squealx.DB) *SQLRoleStore {
	return &SQLRoleStore{db: db}
}

func (s *SQLRoleStore) CreateRole(ctx context.Context, r *authz.Role) error {
	perms, _ := json.Marshal(r.Permissions)
	oas, _ := json.Marshal(r.OwnerAllowedActions)
	inherits, _ := json.Marshal(r.Inherits)
	q := `INSERT INTO roles(id, tenant_id, name, permissions_json, owner_allowed_actions_json, inherits_json, created_at) VALUES(:id, :tenant_id, :name, :permissions_json, :owner_allowed_actions_json, :inherits_json, :created_at)`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"id": r.ID, "tenant_id": r.TenantID, "name": r.Name, "permissions_json": string(perms), "owner_allowed_actions_json": string(oas), "inherits_json": string(inherits), "created_at": time.Now()})
	return err
}

func (s *SQLRoleStore) UpdateRole(ctx context.Context, r *authz.Role) error {
	perms, _ := json.Marshal(r.Permissions)
	oas, _ := json.Marshal(r.OwnerAllowedActions)
	inherits, _ := json.Marshal(r.Inherits)
	q := `UPDATE roles SET tenant_id=:tenant_id, name=:name, permissions_json=:permissions_json, owner_allowed_actions_json=:owner_allowed_actions_json, inherits_json=:inherits_json WHERE id=:id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"id": r.ID, "tenant_id": r.TenantID, "name": r.Name, "permissions_json": string(perms), "owner_allowed_actions_json": string(oas), "inherits_json": string(inherits)})
	return err
}

func (s *SQLRoleStore) DeleteRole(ctx context.Context, id string) error {
	q := `DELETE FROM roles WHERE id = :id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"id": id})
	return err
}

func (s *SQLRoleStore) GetRole(ctx context.Context, id string) (*authz.Role, error) {
	q := `SELECT id, tenant_id, name, permissions_json, owner_allowed_actions_json, inherits_json, created_at FROM roles WHERE id = :id`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if !r.Next() {
		return nil, fmt.Errorf("role not found: %s", id)
	}
	var idv, tenant, name, permsJSON, oasJSON, inheritsJSON string
	var createdRaw interface{}
	if err := r.Scan(&idv, &tenant, &name, &permsJSON, &oasJSON, &inheritsJSON, &createdRaw); err != nil {
		return nil, err
	}
	role := &authz.Role{ID: idv, TenantID: tenant, Name: name}
	var perms []authz.Permission
	_ = json.Unmarshal([]byte(permsJSON), &perms)
	role.Permissions = perms
	var oas []authz.Action
	_ = json.Unmarshal([]byte(oasJSON), &oas)
	role.OwnerAllowedActions = oas
	var inherits []string
	_ = json.Unmarshal([]byte(inheritsJSON), &inherits)
	role.Inherits = inherits
	if createdRaw != nil {
		switch v := createdRaw.(type) {
		case time.Time:
			role.CreatedAt = v
		case string:
			if t, err := parseFlexibleTime(v); err == nil {
				role.CreatedAt = t
			}
		case []byte:
			if t, err := parseFlexibleTime(string(v)); err == nil {
				role.CreatedAt = t
			}
		}
	}
	return role, nil
}

func (s *SQLRoleStore) ListRoles(ctx context.Context, tenantID string) ([]*authz.Role, error) {
	q := `SELECT id FROM roles WHERE tenant_id = :tenant_id OR tenant_id = ''`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"tenant_id": tenantID})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := make([]*authz.Role, 0)
	for r.Next() {
		var id string
		_ = r.Scan(&id)
		if rr, err := s.GetRole(ctx, id); err == nil {
			out = append(out, rr)
		}
	}
	return out, nil
}
