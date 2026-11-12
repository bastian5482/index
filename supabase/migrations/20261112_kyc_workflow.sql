-- LYNXORA KYC workflow
-- Run this migration in Supabase SQL Editor after the kyc_requests table,
-- is_wallet_admin(), and review_kyc_request() have been created.

begin;

create or replace function public.submit_kyc_request()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_request_id uuid;
  v_status text;
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  insert into public.kyc_requests (user_id, status, submitted_at, reviewed_at, reviewed_by, rejection_reason)
  values (v_user_id, 'pending', now(), null, null, null)
  on conflict (user_id) do update
    set status = 'pending',
        submitted_at = now(),
        reviewed_at = null,
        reviewed_by = null,
        rejection_reason = null
    where public.kyc_requests.status = 'rejected'
  returning id, status into v_request_id, v_status;

  if v_request_id is null then
    select id, status
      into v_request_id, v_status
      from public.kyc_requests
      where user_id = v_user_id;
  end if;

  if v_request_id is null then
    raise exception 'Could not create KYC request';
  end if;

  return jsonb_build_object('ok', true, 'request_id', v_request_id, 'status', v_status);
end;
$$;

revoke all on function public.submit_kyc_request() from public, anon;
grant execute on function public.submit_kyc_request() to authenticated;

create or replace function public.admin_list_kyc_requests()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_result jsonb;
begin
  if auth.uid() is null or not public.is_wallet_admin() then
    raise exception 'Administrator access required';
  end if;

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'id', k.id,
        'user_id', k.user_id,
        'status', k.status,
        'submitted_at', k.submitted_at,
        'reviewed_at', k.reviewed_at,
        'rejection_reason', k.rejection_reason,
        'username', p.username,
        'first_name', p.first_name,
        'last_name', p.last_name,
        'date_of_birth', p.date_of_birth,
        'country', p.country,
        'address_text', p.address_text
      )
      order by k.submitted_at desc
    ),
    '[]'::jsonb
  )
  into v_result
  from public.kyc_requests k
  left join public.profiles p on p.id = k.user_id;

  return v_result;
end;
$$;

revoke all on function public.admin_list_kyc_requests() from public, anon;
grant execute on function public.admin_list_kyc_requests() to authenticated;

commit;
