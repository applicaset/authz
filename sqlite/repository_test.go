package sqlite_test

import (
	"database/sql"
	"testing"

	"github.com/applicaset/authz/repotest"
	"github.com/applicaset/authz/sqlite"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestRepository(t *testing.T) {
	repotest.Run(t, func(t *testing.T) repotest.Repositories {
		t.Helper()

		// Opened with foreign_keys on, like the application's database. SQLite defaults it to off,
		// and rejecting an unknown role depends on it.
		db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/test.db?_pragma=foreign_keys(ON)")
		require.NoError(t, err)

		db.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = db.Close() })

		require.NoError(t, sqlite.Migrate(t.Context(), db))

		return repotest.Repositories{
			Role:        sqlite.NewRoleRepository(db),
			SubjectRole: sqlite.NewSubjectRoleRepository(db),
			Grant:       sqlite.NewGrantRepository(db),
		}
	})
}
