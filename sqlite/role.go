package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Masterminds/squirrel"
	"github.com/applicaset/buildset/authz"
)

const (
	tableRoles           = "roles"
	tableRolePermissions = "role_permissions"
)

const (
	roleColumnName        = "name"
	roleColumnDescription = "description"

	permissionColumnRole            = "role"
	permissionColumnAction          = "action"
	permissionColumnResourcePattern = "resource_pattern"
)

func roleColumns() []string {
	return []string{roleColumnName, roleColumnDescription}
}

type RoleRepository struct {
	db *sql.DB
}

var _ authz.RoleRepository = (*RoleRepository)(nil)

func NewRoleRepository(db *sql.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

func (r *RoleRepository) List(ctx context.Context) ([]authz.Role, error) {
	rows, err := builder().RunWith(r.db).
		Select(roleColumns()...).
		From(tableRoles).
		OrderBy(roleColumnName).
		QueryContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("select roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	roles := make([]authz.Role, 0)

	for rows.Next() {
		var role authz.Role

		if err := rows.Scan(&role.Name, &role.Description); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}

	return roles, nil
}

func (r *RoleRepository) Exists(ctx context.Context, role string) (bool, error) {
	var exists int

	err := builder().RunWith(r.db).
		Select("1").
		From(tableRoles).
		Where(squirrel.Eq{roleColumnName: role}).
		Limit(1).
		QueryRowContext(ctx).
		Scan(&exists)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}

		return false, fmt.Errorf("select role: %w", err)
	}

	return true, nil
}

func (r *RoleRepository) ListPermissions(
	ctx context.Context,
	roles []string,
) ([]authz.Pattern, error) {
	rows, err := builder().RunWith(r.db).
		Select(permissionColumnAction, permissionColumnResourcePattern).
		From(tableRolePermissions).
		Where(squirrel.Eq{permissionColumnRole: roles}).
		QueryContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("select role permissions: %w", err)
	}

	return scanPatterns(rows)
}
