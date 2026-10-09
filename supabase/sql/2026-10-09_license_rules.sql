-- =====================================================================
-- DrayberFlex – update: one person = one driver's license number
-- * The license number is required and must look like a PH license (1 letter + 10 digits,
--   spaces and dashes ignored).
-- * One active application per license. After a "Failed" result the applicant waits the
--   months set in Rules & data (or is blocked for good for serious cases, Admin can override).
-- * A second no-show within 30 days means waiting 30 days.
-- * check_license(number) lets the application page check at step 2, before the applicant
--   fills in the rest. It only says ok / active / wait (date) / blocked, never who applied.
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================
create or replace function public.license_key(n text) returns text
language sql immutable as $$ select upper(regexp_replace(coalesce(n,''), '[^A-Za-z0-9]', '', 'g')) $$;

-- every application made with this license
create or replace function public.license_rows(v_key text) returns setof jsonb
language sql stable security definer set search_path = public as $$
  select data from applicants
   where coalesce(data->'docs'->'license'->>'key', public.license_key(data->'docs'->'license'->>'number')) = v_key $$;
revoke all on function public.license_rows(text) from public;

-- null = may apply; otherwise {error: active | wait (until) | blocked}
create or replace function public.license_check(v_key text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare
  v_now text := to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI');
  v_today text := to_char(now() at time zone 'Asia/Manila','YYYY-MM-DD');
  v_until text; v_ns int; v_last text;
begin
  if coalesce(v_key,'') = '' then return null; end if;
  -- blocked for good (red flag, NBI hit, fake document, repeated critical driving fail), unless an Admin allowed it
  if exists(select 1 from public.license_rows(v_key) d where (d->'released'->'fail'->>'permanent') = 'true') then
    return jsonb_build_object('error','blocked'); end if;
  -- an application still in progress, or already accredited
  if exists(select 1 from public.license_rows(v_key) d where
       coalesce(d->'booking'->>'status','') <> 'declined'
       and coalesce(d->>'calendlyCanceled','false') <> 'true'
       and coalesce(d->'checkin'->>'status','') <> 'noshow'
       and not (d->'checkin'->>'status' is null and coalesce(d->>'slot','') < v_now)
       and not coalesce(d->'released' ? 'fail', false)
       and coalesce(d->'training'->>'response','') <> 'declined') then
    return jsonb_build_object('error','active'); end if;
  -- waiting period after a "Failed" result
  select max(d->'released'->'fail'->>'waitUntil') into v_until from public.license_rows(v_key) d;
  if v_until is not null and v_until > v_today then return jsonb_build_object('error','wait','until',v_until); end if;
  -- two no-shows within 30 days: wait 30 days after the last one
  select count(*), max(left(d->>'slot',10)) into v_ns, v_last from public.license_rows(v_key) d
   where coalesce(d->'booking'->>'status','') <> 'declined' and coalesce(d->>'calendlyCanceled','false') <> 'true'
     and (d->'checkin'->>'status' = 'noshow' or (d->'checkin'->>'status' is null and coalesce(d->>'slot','') < v_now))
     and left(d->>'slot',10) >= to_char((now() at time zone 'Asia/Manila') - interval '30 days','YYYY-MM-DD');
  if v_ns >= 2 then
    v_until := to_char(v_last::date + 30, 'YYYY-MM-DD');
    if v_until > v_today then return jsonb_build_object('error','wait','until',v_until); end if;
  end if;
  return null;
end $$;
revoke all on function public.license_check(text) from public;

-- for the application page (step 2)
create or replace function public.check_license(p_number text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_key text := public.license_key(p_number);
begin
  if v_key !~ '^[A-Z][0-9]{10}$' then return jsonb_build_object('error','nolicense'); end if;
  return coalesce(public.license_check(v_key), jsonb_build_object('ok', true));
end $$;
revoke all on function public.check_license(text) from public;
grant execute on function public.check_license(text) to anon, authenticated;

create or replace function public.submit_application(p jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  s jsonb; c jsonb; seats int; taken int; v_id text; v_code text; ph text; dup record; v_today text; v_key text; v_chk jsonb;
begin
  if length(p::text) > 60000 then raise exception 'payload too large'; end if;
  v_id := p->>'id';
  if v_id is null or v_id !~ '^a[a-z0-9]{6,40}$' then raise exception 'bad id'; end if;
  if exists(select 1 from applicants where id = v_id) then raise exception 'exists'; end if;
  if jsonb_array_length(coalesce(p->'docs'->'license'->'photos','[]'::jsonb)) < 1 then return jsonb_build_object('error','nophoto'); end if;
  -- the driver's license number identifies the person: required, compared without spaces/dashes
  v_key := public.license_key(p->'docs'->'license'->>'number');
  if v_key !~ '^[A-Z][0-9]{10}$' then return jsonb_build_object('error','nolicense'); end if;
  v_chk := public.license_check(v_key);
  if v_chk is not null then return v_chk; end if;

  select data into s from app_config where key = 'settings';
  select x into c from jsonb_array_elements(coalesce(s->'camps','[]'::jsonb)) x where x->>'id' = p->>'campaignId';
  if c is null or coalesce(c->>'active','true') = 'false' then return jsonb_build_object('error','closed'); end if;
  -- campaign dates (Philippine time): not before the start date, not after the last day
  v_today := to_char(now() at time zone 'Asia/Manila', 'YYYY-MM-DD');
  if coalesce(c->>'startDate','') <> '' and v_today < (c->>'startDate') collate "C" then return jsonb_build_object('error','notyet'); end if;
  if coalesce(c->>'endDate','') <> '' and v_today > (c->>'endDate') collate "C" then return jsonb_build_object('error','closed'); end if;
  if (p->>'slot') is null or (p->>'slot') < to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI') then
    return jsonb_build_object('error','full'); end if;

  perform pg_advisory_xact_lock(hashtext(coalesce(p->>'campaignId','') || '|' || (p->>'slot')));
  seats := coalesce(nullif(c->>'seats','')::int, 1);
  select count(*) into taken from applicants
   where data->>'campaignId' = p->>'campaignId' and data->>'slot' = p->>'slot'
     and coalesce(data->'booking'->>'status','') <> 'declined';
  if taken >= seats then return jsonb_build_object('error','full'); end if;

  ph := regexp_replace(coalesce(p->>'phone',''), '[\s-]', '', 'g');
  select id, data->>'slot' as slot into dup from applicants
   where regexp_replace(coalesce(data->>'phone',''), '[\s-]', '', 'g') = ph
     and data ? 'code' and (data->'checkin'->>'status') is null
     and coalesce(data->'booking'->>'status','') <> 'declined'
     and data->>'slot' > to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI')
   limit 1;
  if found then return jsonb_build_object('error','dup','slot',dup.slot); end if;

  select jsonb_object_agg(k, v) into p from jsonb_each(p) e(k, v)
   where k = any(array['id','code','name','phone','email','slot','campaign','campaignId','position','hubName',
                       'location','refCode','application','booking','docs','createdAt','updatedAt','log']);
  p := p || jsonb_build_object('source','campaign');
  p := jsonb_set(p, '{docs,license,key}', to_jsonb(v_key));

  v_code := p->>'code';
  while v_code is null or v_code !~ '^MB-[A-Z0-9]{6}$' or exists(select 1 from applicants where code = v_code) loop
    v_code := 'MB-' || upper(substr(md5(random()::text), 1, 6));
  end loop;
  p := jsonb_set(p, '{code}', to_jsonb(v_code));

  insert into applicants(id, code, data) values (v_id, v_code, p);
  return jsonb_build_object('ok', true, 'id', v_id, 'code', v_code);
end $$;
revoke all on function public.submit_application(jsonb) from public;
grant execute on function public.submit_application(jsonb) to anon, authenticated;
