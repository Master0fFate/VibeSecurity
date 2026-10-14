# Supabase Notes

Supabase exposes Postgres directly to browsers through PostgREST. The public key (legacy `anon` JWT or `sb_publishable_`) is meant to ship in the client; the only thing between a visitor and every row is Row Level Security. This is the boundary behind CVE-2025-48757 (170 of 1,645 Lovable apps) and the Moltbook exposure (January 2026).

Prioritize migrations, `supabase/` policies, client construction, and edge functions.

Check:

- Every table reachable by `anon` or `authenticated` has `enable row level security` and at least one policy; a table with RLS enabled and no policy is closed, a table without RLS is fully open through the public key.
- Policies scope rows to the caller: `auth.uid() = user_id`, membership joins, or tenant columns. `using (true)` or `with check (true)` on a non-public table is a finding, not a style issue.
- The `service_role` JWT or any `sb_secret_` key appears only in server-only code (route handlers, server actions, edge functions, cron) and never in `.tsx`, `components/`, `hooks/`, or anything imported by a client component. Check `NEXT_PUBLIC_`/`VITE_` prefixes.
- Storage buckets have policies too; a public bucket serves every object to anyone with the URL.
- Edge functions verify the caller's JWT (`verify_jwt`) or validate the `Authorization` header themselves before touching data with the service key.
- `supabase.auth.getUser()` (server-verified) is used for authorization decisions rather than `getSession()` from cookies alone.
- Database webhooks and pg_net calls send the secret key only to trusted destinations.
- Migrations that `grant all ... to anon` or `to public` are reviewed as privilege grants.

Verification: run the policy as the target role with `set role anon; select * from <table>;` in a disposable database, or use the Supabase dashboard RLS advisor; add a regression test that queries as a second user and expects zero rows.
