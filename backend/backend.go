// Package backend is the one place that maps a storage driver to an authz repository.
package backend

import (
	"context"

	"github.com/buildset/buildset/authz"
	authzpostgres "github.com/buildset/buildset/authz/postgres"
	authzsqlite "github.com/buildset/buildset/authz/sqlite"
	"github.com/buildset/buildset/pkg/storage"
)

func New(ctx context.Context, driver string, handle *storage.Handle) (authz.Repository, error) {
	switch driver {
	case storage.DriverPostgres:
		return authzpostgres.NewRepository(ctx, handle.SQL)
	default:
		return authzsqlite.NewRepository(ctx, handle.SQL)
	}
}
