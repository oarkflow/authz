package sqlitestore

import (
	"testing"

	"github.com/oarkflow/authz/contrib/sqldriver"
	"github.com/oarkflow/authz/pkg/stores"
)

// TestSQLiteStoresConformance runs the shared conformance suite against the
// SQL store implementations backed by an in-process SQLite database opened
// through this package's Open helper. It requires no external database, so
// it runs unconditionally in CI.
func TestSQLiteStoresConformance(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	defer db.Close()

	if err := sqldriver.Migrate(db); err != nil {
		t.Fatalf("migrate sqlite db: %v", err)
	}

	auditStore, err := sqldriver.NewSQLAuditStore(db)
	if err != nil {
		t.Fatalf("new sql audit store: %v", err)
	}

	suite := &stores.ConformanceTestSuite{
		PolicyStore:         sqldriver.NewSQLPolicyStore(db),
		RoleStore:           sqldriver.NewSQLRoleStore(db),
		ACLStore:            sqldriver.NewSQLACLStore(db),
		AuditStore:          auditStore,
		RoleMembershipStore: sqldriver.NewSQLRoleMembershipStore(db),
		TenantStore:         sqldriver.NewSQLTenantStore(db),
		Cleanup:             func() {},
	}

	suite.RunAllTests(t)
}
