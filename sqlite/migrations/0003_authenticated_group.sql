-- Every signed-in user is in auth's authenticated group, and the group is a reader, so anyone
-- signed in may comment on a post. Membership comes with each check: nothing here lists members.
INSERT INTO role_permissions (role, action, resource_pattern) VALUES
    ('reader', 'comment.create', 'urn:content:post:*');

INSERT INTO subject_roles (subject_ref, role, granted_at) VALUES
    ('urn:auth:group:authenticated', 'reader', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
