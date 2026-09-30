// Package backend is the one place that maps a storage driver to authz's repositories.
package backend

import (
	"context"

	"github.com/applicaset/buildset/authz"
	authzpostgres "github.com/applicaset/buildset/authz/postgres"
	authzsqlite "github.com/applicaset/buildset/authz/sqlite"
	"github.com/applicaset/buildset/pkg/storage"
)

type Repositories struct {
	Role        authz.RoleRepository
	SubjectRole authz.SubjectRoleRepository
	Grant       authz.GrantRepository
}

// New migrates the schema before returning repositories over it.
func New(ctx context.Context, driver string, handle *storage.Handle) (*Repositories, error) {
	db := handle.SQL

	switch driver {
	case storage.DriverPostgres:
		if err := authzpostgres.Migrate(ctx, db); err != nil {
			return nil, err
		}

		return &Repositories{
			Role:        authzpostgres.NewRoleRepository(db),
			SubjectRole: authzpostgres.NewSubjectRoleRepository(db),
			Grant:       authzpostgres.NewGrantRepository(db),
		}, nil
	default:
		if err := authzsqlite.Migrate(ctx, db); err != nil {
			return nil, err
		}

		return &Repositories{
			Role:        authzsqlite.NewRoleRepository(db),
			SubjectRole: authzsqlite.NewSubjectRoleRepository(db),
			Grant:       authzsqlite.NewGrantRepository(db),
		}, nil
	}
}
