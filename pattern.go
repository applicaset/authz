package authz

// Pattern is one permission: an action, possibly a wildcard, over a resource, possibly a wildcard.
type Pattern struct {
	Action   string
	Resource string
}
