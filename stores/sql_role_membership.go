package stores

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oarkflow/squealx"
)

// SQLRoleMembershipStore implements RoleMembershipStore backed by a SQL DB (squealx)
type SQLRoleMembershipStore struct {
	db              *squealx.DB
	snapshot        atomic.Value
	refreshInterval time.Duration
	once            sync.Once
	stopCh          chan struct{}
}

func NewSQLRoleMembershipStore(db *squealx.DB) *SQLRoleMembershipStore {
	store := &SQLRoleMembershipStore{
		db:              db,
		refreshInterval: 30 * time.Second,
		stopCh:          make(chan struct{}),
	}
	store.snapshot.Store(map[string][]string{})
	store.startBackgroundRefresh()
	return store
}

func (s *SQLRoleMembershipStore) startBackgroundRefresh() {
	s.once.Do(func() {
		go func() {
			if err := s.refreshSnapshot(); err != nil {
				log.Printf("sql role membership warmup failed: %v", err)
			}
			ticker := time.NewTicker(s.refreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := s.refreshSnapshot(); err != nil {
						log.Printf("sql role membership refresh error: %v", err)
					}
				case <-s.stopCh:
					return
				}
			}
		}()
	})
}

func (s *SQLRoleMembershipStore) refreshSnapshot() error {

	rows, err := s.db.NamedQueryContext(context.Background(), "SELECT subject_id, role_id FROM role_members", map[string]any{})
	if err != nil {
		return err
	}
	defer rows.Close()
	cache := make(map[string][]string)
	for rows.Next() {
		var subject, role string
		if err := rows.Scan(&subject, &role); err != nil {
			return err
		}
		cache[subject] = append(cache[subject], role)
	}
	s.snapshot.Store(cache)
	return nil
}

func (s *SQLRoleMembershipStore) AssignRole(ctx context.Context, subjectID, roleID string) error {
	q := `INSERT OR IGNORE INTO role_members(subject_id, role_id) VALUES(:subject_id, :role_id)`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"subject_id": subjectID, "role_id": roleID})
	if err == nil {
		go func() {
			if refreshErr := s.refreshSnapshot(); refreshErr != nil {
				log.Printf("sql role membership refresh error after assign: %v", refreshErr)
			}
		}()
	}
	return err
}

func (s *SQLRoleMembershipStore) RevokeRole(ctx context.Context, subjectID, roleID string) error {
	q := `DELETE FROM role_members WHERE subject_id = :subject_id AND role_id = :role_id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"subject_id": subjectID, "role_id": roleID})
	if err == nil {
		go func() {
			if refreshErr := s.refreshSnapshot(); refreshErr != nil {
				log.Printf("sql role membership refresh error after revoke: %v", refreshErr)
			}
		}()
	}
	return err
}

func (s *SQLRoleMembershipStore) ListRoles(ctx context.Context, subjectID string) ([]string, error) {
	if snap, ok := s.snapshot.Load().(map[string][]string); ok {
		if roles, ok2 := snap[subjectID]; ok2 {
			copyRoles := make([]string, len(roles))
			copy(copyRoles, roles)
			return copyRoles, nil
		}
	}
	out := make([]string, 0)
	q := `SELECT role_id FROM role_members WHERE subject_id = :subject_id`
	r, err := s.db.NamedQueryContext(ctx, q, map[string]any{"subject_id": subjectID})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for r.Next() {
		var role string
		if err := r.Scan(&role); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, nil
}

func (s *SQLRoleMembershipStore) Close() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
}
