package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/applicaset/buildset/authz"
)

const tableSubjectRoles = "subject_roles"

const (
	subjectRoleColumnSubjectRef = "subject_ref"
	subjectRoleColumnRole       = "role"
	subjectRoleColumnGrantedAt  = "granted_at"
)

func subjectRoleColumns() []string {
	return []string{subjectRoleColumnSubjectRef, subjectRoleColumnRole, subjectRoleColumnGrantedAt}
}

type SubjectRoleRepository struct {
	db *sql.DB
}

var _ authz.SubjectRoleRepository = (*SubjectRoleRepository)(nil)

func NewSubjectRoleRepository(db *sql.DB) *SubjectRoleRepository {
	return &SubjectRoleRepository{db: db}
}

func (r *SubjectRoleRepository) ListBySubject(
	ctx context.Context,
	subject string,
) ([]string, error) {
	rows, err := builder().RunWith(r.db).
		Select(subjectRoleColumnRole).
		From(tableSubjectRoles).
		Where(squirrel.Eq{subjectRoleColumnSubjectRef: subject}).
		OrderBy(subjectRoleColumnRole).
		QueryContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("select subject roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	roles := make([]string, 0)

	for rows.Next() {
		var role string

		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("scan subject role: %w", err)
		}

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subject roles: %w", err)
	}

	return roles, nil
}

// Insert is idempotent, so assigning a role twice is not an error.
func (r *SubjectRoleRepository) Insert(
	ctx context.Context,
	subject, role string,
	grantedAt time.Time,
) error {
	_, err := builder().RunWith(r.db).
		Insert(tableSubjectRoles).
		Columns(subjectRoleColumns()...).
		Values(subject, role, formatTime(grantedAt)).
		Suffix(fmt.Sprintf("ON CONFLICT (%s, %s) DO NOTHING", subjectRoleColumnSubjectRef, subjectRoleColumnRole)).
		ExecContext(ctx)
	if err != nil {
		if isForeignKeyViolation(err) {
			return fmt.Errorf("%w: %s", authz.ErrUnknownRole, role)
		}

		return fmt.Errorf("insert subject role: %w", err)
	}

	return nil
}

func (r *SubjectRoleRepository) Delete(ctx context.Context, subject, role string) error {
	_, err := builder().RunWith(r.db).
		Delete(tableSubjectRoles).
		Where(squirrel.Eq{subjectRoleColumnSubjectRef: subject, subjectRoleColumnRole: role}).
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("delete subject role: %w", err)
	}

	return nil
}

func (r *SubjectRoleRepository) DeleteBySubject(ctx context.Context, subject string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, table := range []struct {
		name   string
		column string
	}{
		{tableGrants, grantColumnSubjectRef},
		{tableSubjectRoles, subjectRoleColumnSubjectRef},
	} {
		_, err := builder().RunWith(tx).
			Delete(table.name).
			Where(squirrel.Eq{table.column: subject}).
			ExecContext(ctx)
		if err != nil {
			return fmt.Errorf("delete %s of subject: %w", table.name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}
