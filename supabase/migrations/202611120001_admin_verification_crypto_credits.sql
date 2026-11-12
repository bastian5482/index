-- LYNXORA: administrator ID verification and shared demo crypto credits
-- Run once in Supabase SQL Editor. Does not modify EUR/USD balances or wallet transactions.

create table if not exists public.admin_manual_verifications (
  user_id uuid primary key references auth.users(id) on delete cascade,
  verified_by uuid not null references auth.users(id),
  verified_at timestamptz not null default now(),
  note text
);

alter table public.admin_manual_verifications enable row level security;
drop policy if exists "Users read own manual verification" on public.admin_manual_verifications;
create policy "Users read own manual verification"
  on public.admin_manual_verifications for select to authenticated
  using (user_id = auth.uid());
revoke insert, update, delete on public.admin_manual_verifications from anon, authenticated;

create or replace function public.admin_lookup_user_by_id(p_user_id uuid)
returns table(user_id uuid, username text, full_name text, kyc_status text, submitted_at timestamptz, manually_verified boolean)
language plpgsql security definer set search_path = public, auth
as $$
begin
  if not public.is_wallet_admin() then raise exception 'Administrator access required'; end if;
  return query
    select p.id, p.username::text,
      coalesce(nullif(p.full_name,''), concat_ws(' ',p.first_name,p.last_name)),
      coalesce(v.status, case when mv.user_id is not null then 'approved' else 'not_submitted' end),
      v.submitted_at, (mv.user_id is not null)
    from public.profiles p
    left join public.kyc_requests v on v.user_id = p.id
    left join public.admin_manual_verifications mv on mv.user_id = p.id
    where p.id = p_user_id;
end;
$$;

create or replace function public.admin_verify_user_by_id(p_user_id uuid, p_note text default null)
returns jsonb
language plpgsql security definer set search_path = public, auth
as $$
begin
  if not public.is_wallet_admin() then raise exception 'Administrator access required'; end if;
  if not exists(select 1 from public.profiles where id = p_user_id) then
    raise exception 'User ID not found';
  end if;
  insert into public.admin_manual_verifications(user_id, verified_by, note)
  values (p_user_id, auth.uid(), nullif(left(trim(coalesce(p_note,'')),500),''))
  on conflict (user_id) do update
    set verified_by = excluded.verified_by, verified_at = now(), note = excluded.note;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.my_manual_verification()
returns table(verified boolean, verified_at timestamptz)
language sql stable security definer set search_path = public, auth
as $$
  select exists(select 1 from public.admin_manual_verifications where user_id = auth.uid()),
         (select v.verified_at from public.admin_manual_verifications v where v.user_id = auth.uid());
$$;

create table if not exists public.demo_crypto_credits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  asset_symbol text not null check (asset_symbol ~ '^[A-Z0-9]{2,15}$'),
  amount numeric(38,18) not null check (amount > 0),
  description text,
  granted_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);
create index if not exists demo_crypto_credits_user_idx
  on public.demo_crypto_credits(user_id, asset_symbol);
alter table public.demo_crypto_credits enable row level security;
drop policy if exists "Users read own demo crypto credits" on public.demo_crypto_credits;
create policy "Users read own demo crypto credits"
  on public.demo_crypto_credits for select to authenticated using (user_id = auth.uid());
revoke insert, update, delete on public.demo_crypto_credits from anon, authenticated;

create or replace function public.admin_credit_demo_crypto(
  p_user_id uuid, p_symbol text, p_amount numeric, p_description text default null
) returns jsonb
language plpgsql security definer set search_path = public, auth
as $$
declare v_id uuid;
begin
  if not public.is_wallet_admin() then raise exception 'Administrator access required'; end if;
  if not exists(select 1 from public.profiles where id = p_user_id) then raise exception 'User ID not found'; end if;
  if p_symbol is null or upper(trim(p_symbol)) !~ '^[A-Z0-9]{2,15}$' then raise exception 'Invalid asset symbol'; end if;
  if p_amount is null or p_amount <= 0 or p_amount > 1000000000000000 then raise exception 'Invalid amount'; end if;
  insert into public.demo_crypto_credits(user_id, asset_symbol, amount, description, granted_by)
  values(p_user_id, upper(trim(p_symbol)), p_amount, nullif(left(trim(coalesce(p_description,'')),160),''), auth.uid())
  returning id into v_id;
  return jsonb_build_object('ok',true,'credit_id',v_id);
end;
$$;

create or replace function public.my_demo_crypto_balances()
returns table(asset_symbol text, amount numeric)
language sql stable security definer set search_path = public, auth
as $$
  select c.asset_symbol, sum(c.amount)
  from public.demo_crypto_credits c
  where c.user_id = auth.uid()
  group by c.asset_symbol
  order by c.asset_symbol;
$$;

grant execute on function public.admin_lookup_user_by_id(uuid) to authenticated;
grant execute on function public.admin_verify_user_by_id(uuid,text) to authenticated;
grant execute on function public.my_manual_verification() to authenticated;
grant execute on function public.admin_credit_demo_crypto(uuid,text,numeric,text) to authenticated;
grant execute on function public.my_demo_crypto_balances() to authenticated;
