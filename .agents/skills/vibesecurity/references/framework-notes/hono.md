# Hono Notes

Prioritize middleware composition, edge runtime secrets, and fetch boundaries.

Check:

- Sensitive routes compose auth middleware before handlers.
- Context variables for user and tenant are set from verified sessions or tokens.
- Edge `fetch` calls do not accept arbitrary user URLs.
- Environment bindings and secrets are not returned, logged, or included in client responses.
- Cache and CDN headers do not share tenant-specific data.
