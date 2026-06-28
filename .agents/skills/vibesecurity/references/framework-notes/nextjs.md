# Next.js Notes

Prioritize `app/api/**/route.ts`, `pages/api/**`, Server Actions, middleware, and cache/revalidation behavior.

Check:

- Sensitive handlers call auth and authorization directly; middleware alone is not enough.
- Object-level authorization happens after loading resources by ID.
- State-changing Server Actions validate user, role, tenant, and CSRF assumptions.
- User-controlled URLs in `fetch`, image proxy, import, OG image, or webhook code cannot reach internal networks.
- Cache keys, tags, and revalidation do not leak data across users or tenants.
- Secrets are not exposed through `NEXT_PUBLIC_*`, serialized props, logs, or client components.
