package stores

import (
	"context"
	"encoding/json"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLACLStore persists ACLs in SQL (squealx)
type SQLACLStore struct {
	db *squealx.DB
}

func NewSQLACLStore(db *squealx.DB) *SQLACLStore {
	return &SQLACLStore{db: db}
}

func (s *SQLACLStore) GrantACL(ctx context.Context, acl *authz.ACL) error {
	acts, _ := json.Marshal(acl.Actions)
	q := `INSERT INTO acls(id, resource_id, subject_id, actions_json, effect, expires_at, created_at) VALUES(:id, :resource_id, :subject_id, :actions_json, :effect, :expires_at, :created_at)`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":           acl.ID,
		"resource_id":  acl.ResourceID,
		"subject_id":   acl.SubjectID,
		"actions_json": string(acts),
		"effect":       string(acl.Effect),
		"expires_at":   sqlNullTimeOrNil(acl.ExpiresAt),
		"created_at":   acl.CreatedAt,
	})
	return err
}

func (s *SQLACLStore) RevokeACL(ctx context.Context, id string) error {
	q := `DELETE FROM acls WHERE id = :id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"id": id})
	return err
}

func (s *SQLACLStore) ListACLsByResource(ctx context.Context, resourceID string) ([]*authz.ACL, error) {
	q := `SELECT id, resource_id, subject_id, actions_json, effect, expires_at, created_at FROM acls WHERE (:resource_id = '' OR resource_id = :resource_id)`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"resource_id": resourceID})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := make([]*authz.ACL, 0)
	for r.Next() {
		var id, resource, subject, actionsJSON, effect string
		var expiresRaw interface{}
		var createdRaw interface{}
		if err := r.Scan(&id, &resource, &subject, &actionsJSON, &effect, &expiresRaw, &createdRaw); err != nil {
			return nil, err
		}
		a := &authz.ACL{ID: id, ResourceID: resource, SubjectID: subject, Effect: authz.Effect(effect)}
		var acts []authz.Action
		_ = json.Unmarshal([]byte(actionsJSON), &acts)
		a.Actions = acts
		if expiresRaw != nil {
			switch v := expiresRaw.(type) {
			case time.Time:
				a.ExpiresAt = v
			case string:
				if t, err := parseFlexibleTime(v); err == nil {
					a.ExpiresAt = t
				}
			case []byte:
				if t, err := parseFlexibleTime(string(v)); err == nil {
					a.ExpiresAt = t
				}
			}
		}
		if createdRaw != nil {
			switch v := createdRaw.(type) {
			case time.Time:
				a.CreatedAt = v
			case string:
				if t, err := parseFlexibleTime(v); err == nil {
					a.CreatedAt = t
				}
			case []byte:
				if t, err := parseFlexibleTime(string(v)); err == nil {
					a.CreatedAt = t
				}
			}
		}
		out = append(out, a)
	}
	return out, nil
}

func (s *SQLACLStore) ListACLsBySubject(ctx context.Context, subjectID string) ([]*authz.ACL, error) {
	q := `SELECT id, resource_id, subject_id, actions_json, effect, expires_at, created_at FROM acls WHERE subject_id = :subject_id`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"subject_id": subjectID})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := make([]*authz.ACL, 0)
	for r.Next() {
		var id, resource, subject, actionsJSON, effect string
		var expiresRaw interface{}
		var createdRaw interface{}
		if err := r.Scan(&id, &resource, &subject, &actionsJSON, &effect, &expiresRaw, &createdRaw); err != nil {
			return nil, err
		}
		a := &authz.ACL{ID: id, ResourceID: resource, SubjectID: subject, Effect: authz.Effect(effect)}
		var acts []authz.Action
		_ = json.Unmarshal([]byte(actionsJSON), &acts)
		a.Actions = acts
		if expiresRaw != nil {
			switch v := expiresRaw.(type) {
			case time.Time:
				a.ExpiresAt = v
			case string:
				if t, err := parseFlexibleTime(v); err == nil {
					a.ExpiresAt = t
				}
			case []byte:
				if t, err := parseFlexibleTime(string(v)); err == nil {
					a.ExpiresAt = t
				}
			}
		}
		if createdRaw != nil {
			switch v := createdRaw.(type) {
			case time.Time:
				a.CreatedAt = v
			case string:
				if t, err := parseFlexibleTime(v); err == nil {
					a.CreatedAt = t
				}
			case []byte:
				if t, err := parseFlexibleTime(string(v)); err == nil {
					a.CreatedAt = t
				}
			}
		}
		out = append(out, a)
	}
	return out, nil
}
