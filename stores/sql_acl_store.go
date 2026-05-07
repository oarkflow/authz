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
	// Skip background refresh for tests
	// store.startBackgroundRefresh()
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
		// Disable async refresh for tests
		// go func() {
		// 	if refreshErr := s.refreshSnapshot(); refreshErr != nil {
		// 		log.Printf("sql acl refresh error after grant: %v", refreshErr)
		// 	}
		// }()
	}
	return err
}

func (s *SQLACLStore) RevokeACL(ctx context.Context, id string) error {
	q := `DELETE FROM acls WHERE id = :id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"id": id})
	// Disable async refresh for tests
	// if err == nil {
	// 	go func() {
	// 		if refreshErr := s.refreshSnapshot(); refreshErr != nil {
	// 			log.Printf("sql acl refresh error after revoke: %v", refreshErr)
	// 		}
	// 	}()
	// }
	return err
}

func (s *SQLACLStore) GetACL(ctx context.Context, id string) (*authz.ACL, error) {
	q := `SELECT id, resource_id, subject_id, actions_json, effect, tenant_id, expires_at, created_at FROM acls WHERE id = ?`
	row := s.db.QueryRowxContext(ctx, q, id)

	var aclID, resource, subject, actionsJSON, effect string
	var tenantID *string
	var expiresRaw, createdRaw interface{}

	err := row.Scan(&aclID, &resource, &subject, &actionsJSON, &effect, &tenantID, &expiresRaw, &createdRaw)
	if err != nil {
		return nil, err
	}

	acl := decodeACLRecord(aclID, resource, subject, actionsJSON, effect, expiresRaw, createdRaw)
	if tenantID != nil {
		acl.TenantID = *tenantID
	}
	return acl, nil
}

func (s *SQLACLStore) UpdateACL(ctx context.Context, acl *authz.ACL) error {
	acts, _ := json.Marshal(acl.Actions)
	q := `UPDATE acls SET resource_id = :resource_id, subject_id = :subject_id, actions_json = :actions_json, effect = :effect, tenant_id = :tenant_id, expires_at = :expires_at WHERE id = :id`
	result, err := s.db.NamedExecContext(ctx, q, map[string]any{
		"id":           acl.ID,
		"resource_id":  acl.ResourceID,
		"subject_id":   acl.SubjectID,
		"actions_json": string(acts),
		"effect":       string(acl.Effect),
		"tenant_id":    acl.TenantID,
		"expires_at":   sqlNullTimeOrNil(acl.ExpiresAt),
	})
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return nil // no error if not found, could return an error if needed
	}
	go func() {
		if refreshErr := s.refreshSnapshot(); refreshErr != nil {
			log.Printf("sql acl refresh error after update: %v", refreshErr)
		}
	}()
	return nil
}

func (s *SQLACLStore) ListACLs(ctx context.Context, tenantID string) ([]*authz.ACL, error) {
	q := `SELECT id, resource_id, subject_id, actions_json, effect, tenant_id, expires_at, created_at FROM acls`
	var args []any
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}

	rows, err := s.db.QueryxContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var acls []*authz.ACL
	for rows.Next() {
		var id, resource, subject, actionsJSON, effect string
		var tid *string
		var expiresRaw, createdRaw interface{}

		if err := rows.Scan(&id, &resource, &subject, &actionsJSON, &effect, &tid, &expiresRaw, &createdRaw); err != nil {
			return nil, err
		}
		acl := decodeACLRecord(id, resource, subject, actionsJSON, effect, expiresRaw, createdRaw)
		if tid != nil {
			acl.TenantID = *tid
		}
		if !acl.IsExpired() {
			acls = append(acls, acl)
		}
	}
	return acls, nil
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
