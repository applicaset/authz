package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/applicaset/buildset/authz"
)

const tableGrants = "grants"

const (
	grantColumnSubjectRef  = "subject_ref"
	grantColumnAction      = "action"
	grantColumnResourceRef = "resource_ref"
	grantColumnGrantedAt   = "granted_at"
)

func grantColumns() []string {
	return []string{
		grantColumnSubjectRef,
		grantColumnAction,
		grantColumnResourceRef,
		grantColumnGrantedAt,
	}
}

type GrantRepository struct {
	db *sql.DB
}

var _ authz.GrantRepository = (*GrantRepository)(nil)

func NewGrantRepository(db *sql.DB) *GrantRepository {
	return &GrantRepository{db: db}
}

// Insert writes every action for one resource in a single transaction, so a caller granting
// ownership never ends up with half the actions.
func (r *GrantRepository) Insert(
	ctx context.Context,
	subject string,
	actions []string,
	resource string,
	grantedAt time.Time,
) error {
	if len(actions) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	insert := builder().RunWith(tx).
		Insert(tableGrants).
		Columns(grantColumns()...)

	for _, action := range actions {
		insert = insert.Values(subject, action, resource, grantedAt)
	}

	insert = insert.Suffix(fmt.Sprintf("ON CONFLICT (%s, %s, %s) DO NOTHING",
		grantColumnSubjectRef, grantColumnAction, grantColumnResourceRef))

	if _, err := insert.ExecContext(ctx); err != nil {
		return fmt.Errorf("insert grants: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func (r *GrantRepository) DeleteByResource(ctx context.Context, resource string) error {
	_, err := builder().RunWith(r.db).
		Delete(tableGrants).
		Where(squirrel.Eq{grantColumnResourceRef: resource}).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("delete grants of resource: %w", err)
	}

	return nil
}

func (r *GrantRepository) ListBySubject(
	ctx context.Context,
	subject string,
) ([]authz.Pattern, error) {
	rows, err := builder().RunWith(r.db).
		Select(grantColumnAction, grantColumnResourceRef).
		From(tableGrants).
		Where(squirrel.Eq{grantColumnSubjectRef: subject}).
		QueryContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("select subject grants: %w", err)
	}

	return scanPatterns(rows)
}

func scanPatterns(rows *sql.Rows) ([]authz.Pattern, error) {
	defer func() { _ = rows.Close() }()

	patterns := make([]authz.Pattern, 0)

	for rows.Next() {
		var pattern authz.Pattern

		if err := rows.Scan(&pattern.Action, &pattern.Resource); err != nil {
			return nil, fmt.Errorf("scan pattern: %w", err)
		}

		patterns = append(patterns, pattern)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate patterns: %w", err)
	}

	return patterns, nil
}
