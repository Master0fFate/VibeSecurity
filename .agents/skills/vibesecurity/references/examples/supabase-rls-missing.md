# Supabase Table Without Row Level Security

Vulnerable pattern (migration):

```sql
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  total numeric,
  shipping_address text
);
```

The browser client holds the public key, so `supabase.from("orders").select("*")` from any visitor returns every order.

Safe pattern:

```sql
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  total numeric,
  shipping_address text
);
alter table public.orders enable row level security;
create policy "orders are visible to their owner" on public.orders
  for select using (auth.uid() = user_id);
create policy "orders are created by their owner" on public.orders
  for insert with check (auth.uid() = user_id);
```

Review lesson: with Supabase the database is the API. A table without RLS, or with a `using (true)` policy, is CWE-862 Missing Authorization (CWE Top 25 2025 rank 4) reachable by anyone holding the public key. Verification: query as a second authenticated user and as `anon` and expect zero rows.
