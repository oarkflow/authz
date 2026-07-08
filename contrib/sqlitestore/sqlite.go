package sqlitestore

import (
	"database/sql"

	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/drivers/sqlite"
)

func Open(dsn string) (*squealx.DB, error) {
	return sqlite.Open(dsn, "sqlite")
}

func OpenDB(dsn string) (*sql.DB, error) {
	db, err := sqlite.Open(dsn, "sqlite")
	if err != nil {
		return nil, err
	}
	return db.DB(), nil
}
