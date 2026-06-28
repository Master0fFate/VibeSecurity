# Rails Notes

Prioritize controllers, filters, policies, parameters, SQL fragments, and storage.

Check:

- Sensitive actions use `before_action` authentication and policy authorization.
- Pundit/CanCan checks cover object access and collections.
- Strong parameters prevent mass assignment of sensitive fields.
- Raw SQL fragments and scopes avoid string interpolation.
- Active Storage access checks object ownership.
- Background jobs do not lose user or tenant context.
