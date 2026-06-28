# Web/API Checklist

Review public routes, route handlers, controllers, middleware order, auth/session boundaries, and object-level authorization.

Focus on:

- Missing auth checks on sensitive routes.
- Loading resources by ID before checking ownership or tenant.
- Input validation at trust boundaries.
- SSRF through URL fetches, webhooks, image proxies, importers, crawlers, or metadata fetchers.
- SQL, NoSQL, ORM, or search query construction from user input.
- File upload, download, path joining, archive extraction, and content type checks.
- XSS through HTML, markdown, rich text, template contexts, serialized props, or browser automation.
- CSRF for cookie-authenticated state changes.
- CORS/session settings that broaden trust unexpectedly.
- Rate limits for login, reset, invite, payment, export, and AI-cost endpoints.
- Webhook signature verification.
- Error handling and logging of sensitive data.

Confirm reachability and boundary crossing before reporting.
