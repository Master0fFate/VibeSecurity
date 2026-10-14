# Next.js Notes

Prioritize `app/api/**/route.ts`, `pages/api/**`, Server Actions (`"use server"`), `middleware.ts`, environment variables, and cache/revalidation behavior.

Check:

- Sensitive handlers call auth and authorization directly; middleware alone is not enough (route handlers and server actions can be invoked without passing through a page).
- Object-level authorization happens after loading resources by ID.
- Server Actions are public HTTP endpoints: each validates its arguments with a schema and checks the session before mutating; `userId` must come from the session, never from an argument.
- Secrets are not exposed through `NEXT_PUBLIC_*`, serialized props, `getServerSideProps` return values, logs, or client components. A `NEXT_PUBLIC_` variable is inlined into the bundle at build time.
- Model-provider SDKs (OpenAI, Anthropic) are instantiated only in server code; `dangerouslyAllowBrowser: true` is a finding.
- Supabase: the `service_role` or `sb_secret_` key is used only in server-only modules; the browser client uses the public key and relies on RLS (see `supabase.md`).
- User-controlled URLs in `fetch`, image proxy, import, OG image, or webhook code cannot reach internal networks.
- Webhook routes (Stripe, Clerk, Svix) verify signatures over the raw body before acting.
- Cache keys, tags, `unstable_cache`, and revalidation do not leak data across users or tenants.
- The auth middleware matcher does not mark every route public (`createRouteMatcher(["/(.*)"])`).
- Error responses in production do not include stack traces or query text.
