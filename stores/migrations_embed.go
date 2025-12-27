package stores

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/oarkflow/squealx"
)

//go:embed sql_migrations.sql
var migrationsSQL string

func Migrate(db *squealx.DB) error {
	// ensure migrations (the embedded migrations include ACL table)
	if _, err := db.ExecContext(context.Background(), migrationsSQL); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}
