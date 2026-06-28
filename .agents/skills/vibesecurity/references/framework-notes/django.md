# Django Notes

Prioritize views, decorators, middleware, forms, ORM usage, and storage.

Check:

- Sensitive views use auth decorators, permissions, or class-based mixins.
- Querysets are scoped to current user or tenant before object access.
- Raw SQL and `.extra()` are avoided or parameterized.
- Templates preserve escaping and safe-marking is justified.
- File storage, downloads, and admin actions enforce authorization.
- Debug mode and secret settings are not exposed.
