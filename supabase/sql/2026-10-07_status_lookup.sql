-- =====================================================================
-- DrayberFlex – update: "Tingnan ang application mo" (code + last 4 digits)
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================
create or replace function public.lookup_ticket(p_code text, p_last4 text) returns text
language sql stable security definer set search_path = public as $$
  select id from applicants
  where upper(code) = upper(trim(p_code))
    and length(p_last4) = 4
    and right(regexp_replace(coalesce(data->>'phone',''), '\D', '', 'g'), 4) = p_last4
  limit 1
$$;
grant execute on function public.lookup_ticket(text,text) to anon, authenticated;
