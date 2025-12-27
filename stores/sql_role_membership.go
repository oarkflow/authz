package stores

import (
	"context"

	"github.com/oarkflow/squealx"
)

// SQLRoleMembershipStore implements RoleMembershipStore backed by a SQL DB (squealx)
type SQLRoleMembershipStore struct {
	db *squealx.DB
}

func NewSQLRoleMembershipStore(db *squealx.DB) *SQLRoleMembershipStore {
	return &SQLRoleMembershipStore{db: db}
}

func (s *SQLRoleMembershipStore) AssignRole(ctx context.Context, subjectID, roleID string) error {
	q := `INSERT OR IGNORE INTO role_members(subject_id, role_id) VALUES(:subject_id, :role_id)`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"subject_id": subjectID, "role_id": roleID})
	return err
}

func (s *SQLRoleMembershipStore) RevokeRole(ctx context.Context, subjectID, roleID string) error {
	q := `DELETE FROM role_members WHERE subject_id = :subject_id AND role_id = :role_id`
	_, err := s.db.NamedExecContext(ctx, q, map[string]any{"subject_id": subjectID, "role_id": roleID})
	return err
}

func (s *SQLRoleMembershipStore) ListRoles(ctx context.Context, subjectID string) ([]string, error) {
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
