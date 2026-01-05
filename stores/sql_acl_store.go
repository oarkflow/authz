package stores

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/squealx"
)

// SQLACLStore persists ACLs in SQL (squealx)
type SQLACLStore struct {
	db              *squealx.DB
	snapshot        atomic.Value
	refreshInterval time.Duration
	once            sync.Once
	stopCh          chan struct{}
}

func NewSQLACLStore(db *squealx.DB) *SQLACLStore {
	store := &SQLACLStore{
		db:              db,
		refreshInterval: 30 * time.Second,
		stopCh:          make(chan struct{}),
	}
	store.snapshot.Store([]*authz.ACL{})
	store.startBackgroundRefresh()
	return store
}

func (s *SQLACLStore) startBackgroundRefresh() {
	s.once.Do(func() {
		go func() {
			if err := s.refreshSnapshot(); err != nil {
				log.Printf("sql acl warmup failed: %v", err)
			}
			ticker := time.NewTicker(s.refreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := s.refreshSnapshot(); err != nil {
						log.Printf("sql acl refresh error: %v", err)
					}
				case <-s.stopCh:
					return
				}
			}
		}()
	})
}

func (s *SQLACLStore) refreshSnapshot() error {
	q := `SELECT id, resource_id, subject_id, actions_json, effect, expires_at, created_at FROM acls`
	rows, err := s.db.NamedQueryContext(context.Background(), q, map[string]any{})
	if err != nil {
		return err
	}
	defer rows.Close()
	list := make([]*authz.ACL, 0)
	for rows.Next() {
		var id, resource, subject, actionsJSON, effect string
		var expiresRaw interface{}
		var createdRaw interface{}
		if err := rows.Scan(&id, &resource, &subject, &actionsJSON, &effect, &expiresRaw, &createdRaw); err != nil {
			return err
		}
		list = append(list, decodeACLRecord(id, resource, subject, actionsJSON, effect, expiresRaw, createdRaw))
	}
	s.snapshot.Store(list)
	return nil
}

func (s *SQLACLStore) Close() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
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
	if err == nil {
		go func() {
			if refreshErr := s.refreshSnapshot(); refreshErr != nil {
				log.Printf("sql acl refresh error after grant: %v", refreshErr)
			}
		}()
	}
	return err
}

func (s *SQLACLStore) RevokeACL(ctx context.Context, id string) error {
	q := `DELETE FROM acls WHERE id = :id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"id": id})
	if err == nil {
		go func() {
			if refreshErr := s.refreshSnapshot(); refreshErr != nil {
				log.Printf("sql acl refresh error after revoke: %v", refreshErr)
			}
		}()
	}
	return err
}

func (s *SQLACLStore) ListACLsByResource(ctx context.Context, resourceID string) ([]*authz.ACL, error) {
	if snapshot, ok := s.snapshot.Load().([]*authz.ACL); ok && len(snapshot) > 0 {
		return filterACLsSnapshot(snapshot, resourceID), nil
	}
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
		out = append(out, decodeACLRecord(id, resource, subject, actionsJSON, effect, expiresRaw, createdRaw))
	}
	return out, nil
}

func (s *SQLACLStore) ListACLsBySubject(ctx context.Context, subjectID string) ([]*authz.ACL, error) {
	if snapshot, ok := s.snapshot.Load().([]*authz.ACL); ok && len(snapshot) > 0 {
		return filterACLsBySubject(snapshot, subjectID), nil
	}
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
		out = append(out, decodeACLRecord(id, resource, subject, actionsJSON, effect, expiresRaw, createdRaw))
	}
	return out, nil
}

func decodeACLRecord(id, resource, subject, actionsJSON, effect string, expiresRaw, createdRaw interface{}) *authz.ACL {
	a := &authz.ACL{ID: id, ResourceID: resource, SubjectID: subject, Effect: authz.Effect(effect)}
	var acts []authz.Action
	_ = json.Unmarshal([]byte(actionsJSON), &acts)
	a.Actions = acts
	if t, ok := convertToTime(expiresRaw); ok {
		a.ExpiresAt = t
	}
	if t, ok := convertToTime(createdRaw); ok {
		a.CreatedAt = t
	}
	return a
}

func convertToTime(raw interface{}) (time.Time, bool) {
	if raw == nil {
		return time.Time{}, false
	}
	switch v := raw.(type) {
	case time.Time:
		return v, true
	case string:
		if t, err := parseFlexibleTime(v); err == nil {
			return t, true
		}
	case []byte:
		if t, err := parseFlexibleTime(string(v)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
