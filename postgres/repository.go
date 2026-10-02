// Package postgres stores authz's roles and grants in Postgres. It owns its schema, applied by
// Migrate, so wiring authz to a different backend runs none of this.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/Masterminds/squirrel"
	"github.com/applicaset/pkg/sqlmigrate"
)

//go:embed migrations/*.sql
var migrations embed.FS

func Migrate(ctx context.Context, db *sql.DB) error {
	runner := sqlmigrate.Runner{
		FileSystem: migrations,
		Directory:  "migrations",
		TableName:  "authz_schema_migrations",
		Dialect:    sqlmigrate.Postgres{},
	}

	if err := runner.Up(ctx, db); err != nil {
		return fmt.Errorf("migrate authz schema: %w", err)
	}

	return nil
}

// placeholders is this package's placeholder style, and the only place the dialect is named.
var placeholders squirrel.PlaceholderFormat = squirrel.Dollar

func builder() squirrel.StatementBuilderType {
	return squirrel.StatementBuilder.PlaceholderFormat(placeholders)
}
