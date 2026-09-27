package sqldriver

import (
	"os"
	"testing"

	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/drivers/sqlite"

	"github.com/oarkflow/authz/pkg/stores"
)

// TestSQLStoresConformance runs the shared conformance suite against the SQL
// store implementations in this package.
//
// By default it runs against an in-process SQLite database, which requires
// no external services and keeps this test lightweight enough to run in any
// CI environment.
//
// To exercise a different (e.g. production-like) database, set AUTHZ_TEST_DSN
// to its DSN and AUTHZ_TEST_DRIVER to the squealx driver name (currently only
// "sqlite" is wired here). Example:
//
//	AUTHZ_TEST_DSN="file:/tmp/authz-conformance.db" AUTHZ_TEST_DRIVER=sqlite go test ./...
func TestSQLStoresConformance(t *testing.T) {
	dsn := os.Getenv("AUTHZ_TEST_DSN")
	driver := os.Getenv("AUTHZ_TEST_DRIVER")
	if dsn == "" {
		dsn = ":memory:"
	}
	if driver == "" {
		driver = "sqlite"
	}

	var (
		db  *squealx.DB
		err error
	)
	switch driver {
	case "sqlite":
		db, err = sqlite.Open(dsn, "sqldriver-conformance")
	default:
		t.Skipf("AUTHZ_TEST_DRIVER=%q is not wired up for this conformance test yet", driver)
		return
	}
	if err != nil {
		t.Fatalf("open db (driver=%s dsn=%s): %v", driver, dsn, err)
	}
	defer db.Close()

	if err := Migrate(db); err != nil {
		t.Fatalf("migrate db: %v", err)
	}

	auditStore, err := NewSQLAuditStore(db)
	if err != nil {
		t.Fatalf("new sql audit store: %v", err)
	}

	suite := &stores.ConformanceTestSuite{
		PolicyStore:         NewSQLPolicyStore(db),
		RoleStore:           NewSQLRoleStore(db),
		ACLStore:            NewSQLACLStore(db),
		AuditStore:          auditStore,
		RoleMembershipStore: NewSQLRoleMembershipStore(db),
		TenantStore:         NewSQLTenantStore(db),
		Cleanup:             func() {},
	}

	suite.RunAllTests(t)
}
