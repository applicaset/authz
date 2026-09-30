package authz

import "context"

type Role struct {
	Name        string
	Description string
}

type RoleRepository interface {
	List(ctx context.Context) ([]Role, error)
	Exists(ctx context.Context, role string) (bool, error)
	// ListPermissions returns the permissions of every role named.
	ListPermissions(ctx context.Context, roles []string) ([]Pattern, error)
}
