// Package repotest is the contract every authz repository must satisfy. Both backends run it, so a
// behaviour that differs between SQLite and Postgres fails here rather than in production.
package repotest

import (
	"context"
	"testing"
	"time"

	"github.com/applicaset/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Repositories struct {
	Role        authz.RoleRepository
	SubjectRole authz.SubjectRoleRepository
	Grant       authz.GrantRepository
}

// New builds repositories over empty storage, already carrying the seeded roles.
type New func(t *testing.T) Repositories

const (
	alice = "urn:auth:user:alice"
	post  = "urn:content:post:1"
)

// Run exercises the whole contract.
func Run(t *testing.T, newRepositories New) {
	t.Helper()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	t.Run("Role.List returns the seeded roles", func(t *testing.T) {
		repos := newRepositories(t)

		roles, err := repos.Role.List(context.Background())
		require.NoError(t, err)

		names := make([]string, 0, len(roles))
		for _, role := range roles {
			names = append(names, role.Name)
		}

		assert.ElementsMatch(t, []string{"admin", "author", "reader"}, names)
	})

	t.Run("Role.Exists distinguishes seeded from unknown", func(t *testing.T) {
		repos := newRepositories(t)

		exists, err := repos.Role.Exists(context.Background(), "admin")
		require.NoError(t, err)
		assert.True(t, exists)

		exists, err = repos.Role.Exists(context.Background(), "wizard")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("SubjectRole.Insert rejects an unknown role", func(t *testing.T) {
		repos := newRepositories(t)

		err := repos.SubjectRole.Insert(context.Background(), alice, "wizard", now)
		require.ErrorIs(t, err, authz.ErrUnknownRole)
	})

	t.Run("SubjectRole.Insert is idempotent", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.SubjectRole.Insert(context.Background(), alice, "admin", now))
		require.NoError(
			t,
			repos.SubjectRole.Insert(context.Background(), alice, "admin", now.Add(time.Hour)),
		)

		roles, err := repos.SubjectRole.ListBySubject(context.Background(), alice)
		require.NoError(t, err)
		assert.Equal(t, []string{"admin"}, roles)
	})

	t.Run("SubjectRole.ListBySubject is empty for an unknown subject", func(t *testing.T) {
		repos := newRepositories(t)

		roles, err := repos.SubjectRole.ListBySubject(context.Background(), "urn:auth:user:nobody")
		require.NoError(t, err)
		assert.Empty(t, roles)
	})

	t.Run("SubjectRole.Delete removes one role", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.SubjectRole.Insert(context.Background(), alice, "admin", now))
		require.NoError(t, repos.SubjectRole.Insert(context.Background(), alice, "author", now))
		require.NoError(t, repos.SubjectRole.Delete(context.Background(), alice, "admin"))

		roles, err := repos.SubjectRole.ListBySubject(context.Background(), alice)
		require.NoError(t, err)
		assert.Equal(t, []string{"author"}, roles)
	})

	t.Run("Role.ListPermissions returns the permissions of the named roles", func(t *testing.T) {
		repos := newRepositories(t)

		patterns, err := repos.Role.ListPermissions(context.Background(), []string{"author"})
		require.NoError(t, err)
		assert.Equal(
			t,
			[]authz.Pattern{{Action: "post.create", Resource: "urn:content:post:*"}},
			patterns,
		)
	})

	t.Run("Role.ListPermissions is empty for no or unknown roles", func(t *testing.T) {
		repos := newRepositories(t)

		for _, roles := range [][]string{nil, {"wizard"}} {
			patterns, err := repos.Role.ListPermissions(context.Background(), roles)
			require.NoError(t, err)
			assert.Empty(t, patterns)
		}
	})

	t.Run("Grant.ListBySubject returns direct grants only", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.SubjectRole.Insert(context.Background(), alice, "author", now))
		require.NoError(
			t,
			repos.Grant.Insert(
				context.Background(),
				alice,
				[]string{"post.update", "post.delete"},
				post,
				now,
			),
		)

		patterns, err := repos.Grant.ListBySubject(context.Background(), alice)
		require.NoError(t, err)

		assert.ElementsMatch(t, []authz.Pattern{
			{Action: "post.update", Resource: post},
			{Action: "post.delete", Resource: post},
		}, patterns)
	})

	t.Run("Grant.ListBySubject is empty for an unknown subject", func(t *testing.T) {
		repos := newRepositories(t)

		patterns, err := repos.Grant.ListBySubject(context.Background(), "urn:auth:user:nobody")
		require.NoError(t, err)
		assert.Empty(t, patterns)
	})

	t.Run("Grant.Insert is idempotent", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(
			t,
			repos.Grant.Insert(
				context.Background(),
				alice,
				[]string{"post.update"},
				post,
				now,
			),
		)
		require.NoError(
			t,
			repos.Grant.Insert(
				context.Background(),
				alice,
				[]string{"post.update"},
				post,
				now.Add(time.Hour),
			),
		)

		patterns, err := repos.Grant.ListBySubject(context.Background(), alice)
		require.NoError(t, err)
		assert.Len(t, patterns, 1)
	})

	t.Run("Grant.Insert with no actions writes nothing", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.Grant.Insert(context.Background(), alice, nil, post, now))

		patterns, err := repos.Grant.ListBySubject(context.Background(), alice)
		require.NoError(t, err)
		assert.Empty(t, patterns)
	})

	t.Run("SubjectRole.DeleteBySubject removes roles and grants together", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.SubjectRole.Insert(context.Background(), alice, "author", now))
		require.NoError(
			t,
			repos.Grant.Insert(
				context.Background(),
				alice,
				[]string{"post.update"},
				post,
				now,
			),
		)

		require.NoError(t, repos.SubjectRole.DeleteBySubject(context.Background(), alice))

		roles, err := repos.SubjectRole.ListBySubject(context.Background(), alice)
		require.NoError(t, err)
		assert.Empty(t, roles)

		patterns, err := repos.Grant.ListBySubject(context.Background(), alice)
		require.NoError(t, err)
		assert.Empty(t, patterns)
	})

	t.Run("Grant.DeleteByResource removes grants and leaves roles", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(t, repos.SubjectRole.Insert(context.Background(), alice, "author", now))
		require.NoError(
			t,
			repos.Grant.Insert(
				context.Background(),
				alice,
				[]string{"post.update"},
				post,
				now,
			),
		)

		require.NoError(t, repos.Grant.DeleteByResource(context.Background(), post))

		roles, err := repos.SubjectRole.ListBySubject(context.Background(), alice)
		require.NoError(t, err)
		assert.Equal(t, []string{"author"}, roles)

		patterns, err := repos.Grant.ListBySubject(context.Background(), alice)
		require.NoError(t, err)
		assert.Empty(t, patterns)
	})

	t.Run("deleting an absent subject or resource is quiet", func(t *testing.T) {
		repos := newRepositories(t)

		require.NoError(
			t,
			repos.SubjectRole.DeleteBySubject(context.Background(), "urn:auth:user:nobody"),
		)
		require.NoError(
			t,
			repos.Grant.DeleteByResource(context.Background(), "urn:content:post:nothing"),
		)
		require.NoError(t, repos.SubjectRole.Delete(context.Background(), alice, "admin"))
	})

	t.Run("Role.Define creates a role, then replaces its permissions", func(t *testing.T) {
		repos := newRepositories(t)
		ctx := context.Background()

		role := authz.Role{Name: "billing.biller", Description: "May charge"}
		first := []authz.Pattern{
			{Action: "billing.charge", Resource: "urn:billing:charge:*"},
			{Action: "billing.post", Resource: "urn:billing:charge:*"},
		}
		require.NoError(t, repos.Role.Define(ctx, role, first))

		exists, err := repos.Role.Exists(ctx, role.Name)
		require.NoError(t, err)
		assert.True(t, exists)

		patterns, err := repos.Role.ListPermissions(ctx, []string{role.Name})
		require.NoError(t, err)
		assert.ElementsMatch(t, first, patterns)

		second := []authz.Pattern{{Action: "billing.charge", Resource: "urn:billing:charge:*"}}
		role.Description = "May charge others"
		require.NoError(t, repos.Role.Define(ctx, role, second))

		patterns, err = repos.Role.ListPermissions(ctx, []string{role.Name})
		require.NoError(t, err)
		assert.Equal(t, second, patterns)

		roles, err := repos.Role.List(ctx)
		require.NoError(t, err)
		assert.Contains(t, roles, role)
	})

	t.Run("Role.Define keeps the role's holders", func(t *testing.T) {
		repos := newRepositories(t)
		ctx := context.Background()

		role := authz.Role{Name: "billing.biller"}
		permissions := []authz.Pattern{{Action: "billing.charge", Resource: "urn:billing:charge:*"}}
		require.NoError(t, repos.Role.Define(ctx, role, permissions))
		require.NoError(t, repos.SubjectRole.Insert(ctx, alice, role.Name, now))
		require.NoError(t, repos.Role.Define(ctx, role, permissions))

		roles, err := repos.SubjectRole.ListBySubject(ctx, alice)
		require.NoError(t, err)
		assert.Equal(t, []string{role.Name}, roles)
	})
}
