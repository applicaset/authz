package authz

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/applicaset/pkg/ref"
)

type Service struct {
	roleRepo        RoleRepository
	subjectRoleRepo SubjectRoleRepository
	grantRepo       GrantRepository
}

func NewService(
	roleRepo RoleRepository,
	subjectRoleRepo SubjectRoleRepository,
	grantRepo GrantRepository,
) *Service {
	return &Service{
		roleRepo:        roleRepo,
		subjectRoleRepo: subjectRoleRepo,
		grantRepo:       grantRepo,
	}
}

// Can reports whether the subject holds a permission covering this action on this resource.
func (svc *Service) Can(ctx context.Context, subject, action, resource string) (bool, error) {
	return svc.CanWithGroups(ctx, subject, nil, action, resource)
}

// CanWithGroups is Can for a subject that also holds what its groups hold. Membership is the
// caller's word: this service keeps no groups.
//
// TODO: every pattern a subject holds is loaded on each check. That is fine while a subject has
// tens of grants; push matching into the backend before one can hold thousands.
func (svc *Service) CanWithGroups(
	ctx context.Context,
	subject string,
	groups []string,
	action, resource string,
) (bool, error) {
	subjects := append([]string{subject}, groups...)

	for _, s := range subjects {
		if err := validateSubject(s); err != nil {
			return false, err
		}
	}

	if err := validateAction(action); err != nil {
		return false, err
	}

	// A query may name a class of resources, not one. That is how a caller asks "may this subject
	// create posts at all" before any post exists.
	if err := validateResourceQuery(resource); err != nil {
		return false, err
	}

	for _, s := range subjects {
		patterns, err := svc.subjectPatterns(ctx, s)
		if err != nil {
			return false, err
		}

		if allows(patterns, action, resource) {
			return true, nil
		}
	}

	return false, nil
}

// subjectPatterns returns every permission a subject holds, from roles and direct grants alike.
func (svc *Service) subjectPatterns(ctx context.Context, subject string) ([]Pattern, error) {
	roles, err := svc.subjectRoleRepo.ListBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("list subject roles: %w", err)
	}

	patterns, err := svc.grantRepo.ListBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("list subject grants: %w", err)
	}

	if len(roles) == 0 {
		return patterns, nil
	}

	permissions, err := svc.roleRepo.ListPermissions(ctx, roles)
	if err != nil {
		return nil, fmt.Errorf("list role permissions: %w", err)
	}

	return append(permissions, patterns...), nil
}

func (svc *Service) ListRoles(ctx context.Context) ([]Role, error) {
	roles, err := svc.roleRepo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}

	return roles, nil
}

func (svc *Service) SubjectRoles(ctx context.Context, subject string) ([]string, error) {
	if err := validateSubject(subject); err != nil {
		return nil, err
	}

	roles, err := svc.subjectRoleRepo.ListBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("list subject roles: %w", err)
	}

	return roles, nil
}

func (svc *Service) AssignRole(ctx context.Context, subject, role string) error {
	if err := validateSubject(subject); err != nil {
		return err
	}

	exists, err := svc.roleRepo.Exists(ctx, role)
	if err != nil {
		return fmt.Errorf("check role: %w", err)
	}

	if !exists {
		return fmt.Errorf("%w: %s", ErrUnknownRole, role)
	}

	if err := svc.subjectRoleRepo.Insert(
		ctx,
		subject,
		role,
		time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("assign role: %w", err)
	}

	return nil
}

func (svc *Service) RevokeRole(ctx context.Context, subject, role string) error {
	if err := validateSubject(subject); err != nil {
		return err
	}

	if err := svc.subjectRoleRepo.Delete(ctx, subject, role); err != nil {
		return fmt.Errorf("revoke role: %w", err)
	}

	return nil
}

// DefineRole creates a role, or replaces its description and permissions. A service defines the
// roles its own actions need when it starts. The name is "<service>.<role>", and every permission
// must name an action and resources of that service. A service then cannot widen another's role,
// nor touch the roles seeded here, whose names carry no service.
func (svc *Service) DefineRole(ctx context.Context, role Role, permissions []Pattern) error {
	service, name, found := strings.Cut(role.Name, ".")
	if !found || name == "" {
		return fmt.Errorf("%w: %q is not <service>.<role>", ErrInvalidRole, role.Name)
	}

	if err := validateAction(role.Name); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRole, err)
	}

	if len(permissions) == 0 {
		return fmt.Errorf("%w: %s has no permissions", ErrInvalidRole, role.Name)
	}

	unique := make([]Pattern, 0, len(permissions))

	for _, permission := range permissions {
		if !strings.HasPrefix(permission.Action, service+".") {
			return fmt.Errorf(
				"%w: action %q is not one of %s's",
				ErrInvalidRole,
				permission.Action,
				service,
			)
		}

		if err := validateAction(permission.Action); err != nil {
			return err
		}

		if !strings.HasPrefix(permission.Resource, "urn:"+service+":") {
			return fmt.Errorf(
				"%w: resource %q is not one of %s's",
				ErrInvalidRole,
				permission.Resource,
				service,
			)
		}

		if err := validateResourceQuery(permission.Resource); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidRole, err)
		}

		if !slices.Contains(unique, permission) {
			unique = append(unique, permission)
		}
	}

	if err := svc.roleRepo.Define(ctx, role, unique); err != nil {
		return fmt.Errorf("define role %s: %w", role.Name, err)
	}

	return nil
}

// Grant is how ownership is expressed: the service that creates a resource grants its creator the
// actions over it.
func (svc *Service) Grant(
	ctx context.Context,
	subject string,
	actions []string,
	resource string,
) error {
	if err := validateSubject(subject); err != nil {
		return err
	}

	if err := validateResource(resource); err != nil {
		return err
	}

	if len(actions) == 0 {
		return fmt.Errorf("%w: no actions given", ErrInvalidAction)
	}

	for _, action := range actions {
		if err := validateAction(action); err != nil {
			return err
		}
	}

	if err := svc.grantRepo.Insert(
		ctx,
		subject,
		actions,
		resource,
		time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("insert grants: %w", err)
	}

	return nil
}

// PurgeSubject removes everything held by a subject, for when whatever it references is deleted.
func (svc *Service) PurgeSubject(ctx context.Context, subject string) error {
	if err := validateSubject(subject); err != nil {
		return err
	}

	if err := svc.subjectRoleRepo.DeleteBySubject(ctx, subject); err != nil {
		return fmt.Errorf("purge subject: %w", err)
	}

	return nil
}

// PurgeResource removes every grant over a resource, for when that resource is deleted.
func (svc *Service) PurgeResource(ctx context.Context, resource string) error {
	if err := validateResource(resource); err != nil {
		return err
	}

	if err := svc.grantRepo.DeleteByResource(ctx, resource); err != nil {
		return fmt.Errorf("purge resource: %w", err)
	}

	return nil
}

// The shape is checked, never resolved. A malformed key would be stored and silently never match.
func validateSubject(subject string) error {
	if err := ref.Validate(subject); err != nil {
		return fmt.Errorf("subject: %w", err)
	}

	return nil
}

func validateResource(resource string) error {
	if err := ref.Validate(resource); err != nil {
		return fmt.Errorf("resource: %w", err)
	}

	return nil
}

// validateResourceQuery also accepts a wildcard covering a whole service, a whole resource type,
// or everything. A grant still requires one concrete resource, because a stored wildcard grant
// would be a policy rule and this service does not let callers write those.
func validateResourceQuery(resource string) error {
	if resource == wildcard {
		return nil
	}

	prefix, found := strings.CutSuffix(resource, wildcard)
	if !found {
		return validateResource(resource)
	}

	// Check the shape of what precedes the wildcard by standing a placeholder in its place.
	if err := ref.Validate(prefix + "x"); err != nil {
		return fmt.Errorf("resource pattern: %w", err)
	}

	return nil
}

// validateAction accepts the dotted lowercase names services use, such as "post.update".
func validateAction(action string) error {
	if action == "" || len(action) > 64 {
		return fmt.Errorf("%w: must be between 1 and 64 characters", ErrInvalidAction)
	}

	for _, c := range action {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return fmt.Errorf("%w: %q contains %q", ErrInvalidAction, action, c)
		}
	}

	return nil
}
