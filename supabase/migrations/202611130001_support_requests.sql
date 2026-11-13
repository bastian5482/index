-- Linkora support inbox: guest/account submissions, admin-only reads.
create table if not exists public.support_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  name text not null check (char_length(trim(name)) between 1 and 120),
  email text not null check (char_length(trim(email)) between 3 and 254 and email ~* '^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$'),
  message text not null check (char_length(trim(message)) between 10 and 5000),
  status text not null default 'new' check (status in ('new','in_progress','closed')),
  created_at timestamptz not null default now()
);

create index if not exists support_requests_created_at_idx
  on public.support_requests(created_at desc);
create index if not exists support_requests_user_id_idx
  on public.support_requests(user_id);

alter table public.support_requests enable row level security;
drop policy if exists "Public can submit support requests" on public.support_requests;
create policy "Public can submit support requests"
  on public.support_requests
  for insert to anon, authenticated
  with check (user_id is null or user_id = auth.uid());

drop policy if exists "Wallet admins can read support requests" on public.support_requests;
create policy "Wallet admins can read support requests"
  on public.support_requests
  for select to authenticated
  using (public.is_wallet_admin());

revoke all on public.support_requests from anon, authenticated;
grant insert on public.support_requests to anon, authenticated;
grant select on public.support_requests to authenticated;
