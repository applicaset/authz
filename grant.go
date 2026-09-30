package authz

import (
	"context"
	"time"
)

// Grant is a permission held by one subject over one resource.
type Grant struct {
	Subject   string
	Action    string
	Resource  string
	GrantedAt time.Time
}

type GrantRepository interface {
	Insert(
		ctx context.Context,
		subject string,
		actions []string,
		resource string,
		grantedAt time.Time,
	) error
	ListBySubject(ctx context.Context, subject string) ([]Pattern, error)
	DeleteByResource(ctx context.Context, resource string) error
}
