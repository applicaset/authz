package authz

import (
	"context"
	"time"
)

type SubjectRoleRepository interface {
	ListBySubject(ctx context.Context, subject string) ([]string, error)
	Insert(ctx context.Context, subject, role string, grantedAt time.Time) error
	Delete(ctx context.Context, subject, role string) error
	// DeleteBySubject removes the subject's grants along with its roles.
	DeleteBySubject(ctx context.Context, subject string) error
}
