# Express Notes

Prioritize route registration, middleware order, and request-controlled sinks.

Check:

- Auth middleware is mounted before sensitive routes.
- Route parameters and loaded resources are checked against the current user or tenant.
- `fetch`, proxy, import, upload, and webhook endpoints cannot become SSRF paths.
- SQL construction uses parameterization.
- File upload/download code prevents traversal and unsafe content handling.
- Error handlers do not leak secrets or stack traces in production.
