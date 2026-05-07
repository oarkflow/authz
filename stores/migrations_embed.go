package stores

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/oarkflow/squealx"
)

//go:embed sql_migrations.sql
var migrationsSQL string

func Migrate(db *squealx.DB) error {
	// ensure migrations (the embedded migrations include ACL table)
	statements := strings.Split(strings.TrimSpace(migrationsSQL), ";")

	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			return fmt.Errorf("run migrations: %w", err)
		}
	}
	return nil
}
