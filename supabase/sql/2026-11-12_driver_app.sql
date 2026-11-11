-- =====================================================================
-- DrayberFlex – update: Driver app (Phase 1) and Deployments
--  * Accredited applicants become drivers in the same app (#app). They set a 4-digit PIN,
--    then sign in with their code + PIN (no longer the last 4 digits of the mobile).
--  * Drivers tap the days they can work (driver_days), take jobs posted by Operations
--    (dep_jobs / dep_bookings) for the accounts they are trained for (applicants.data.accounts),
--    and show their QR at the hub, where Operations scans them in (dep_scan).
--  * Strikes (counts only): backing out after 8 PM the night before = 1 strike; no show = paused
--    30 days; 2 strikes in 60 days = paused 30 days; paused twice in 6 months = removed.
--    Staff can remove a strike with a reason (waived).
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================

-- ---------- tables ----------
create table if not exists public.driver_auth (
  applicant_id text primary key references public.applicants(id) on delete cascade,
  salt         text not null,
  pin_hash     text not null,
  set_at       timestamptz not null default now()
);
create table if not exists public.driver_days (
  applicant_id text not null references public.applicants(id) on delete cascade,
  day          date not null,
  primary key (applicant_id, day)
);
create table if not exists public.dep_jobs (
  id           uuid primary key default gen_random_uuid(),
  account      text not null check (length(account) between 1 and 60),
  role         text not null default 'Driver' check (length(role) between 1 and 60),
  hub          text not null default '' check (length(hub) <= 80),
  day          date not null,
  call_time    time not null,
  needed       int  not null check (needed between 1 and 200),
  note         text not null default '' check (length(note) <= 300),
  created_by   uuid,
  created_at   timestamptz not null default now(),
  cancelled_at timestamptz
);
create index if not exists dep_jobs_day on public.dep_jobs (day);
create table if not exists public.dep_bookings (
  id           uuid primary key default gen_random_uuid(),
  job_id       uuid not null references public.dep_jobs(id) on delete cascade,
  applicant_id text not null references public.applicants(id) on delete cascade,
  booked_at    timestamptz not null default now(),
  by_staff     uuid,
  cancelled_at timestamptz,
  cancel_late  boolean not null default false,
  cancel_by    text check (cancel_by in ('driver', 'staff')),
  time_in      timestamptz,
  outcome      text check (outcome in ('deployed', 'standby')),
  outcome_at   timestamptz,
  waived       boolean not null default false,
  waive_reason text,
  unique (job_id, applicant_id)
);
create index if not exists dep_bookings_app on public.dep_bookings (applicant_id);

alter table public.driver_auth  enable row level security;
alter table public.driver_days  enable row level security;
alter table public.dep_jobs     enable row level security;
alter table public.dep_bookings enable row level security;
revoke all on public.driver_auth  from anon, authenticated;   -- PINs: only the functions below
revoke all on public.driver_days  from anon, authenticated;
revoke all on public.dep_jobs     from anon, authenticated;
revoke all on public.dep_bookings from anon, authenticated;
grant select on public.driver_days to authenticated;
grant select, insert, update on public.dep_jobs     to authenticated;
grant select, insert, update on public.dep_bookings to authenticated;
drop policy if exists dd_sel on public.driver_days;
drop policy if exists dj_sel on public.dep_jobs;
drop policy if exists dj_ins on public.dep_jobs;
drop policy if exists dj_upd on public.dep_jobs;
drop policy if exists db_sel on public.dep_bookings;
drop policy if exists db_ins on public.dep_bookings;
drop policy if exists db_upd on public.dep_bookings;
create policy dd_sel on public.driver_days  for select to authenticated using (public.is_staff());
create policy dj_sel on public.dep_jobs     for select to authenticated using (public.is_staff());
create policy dj_ins on public.dep_jobs     for insert to authenticated with check (public.has_role('operations'));
create policy dj_upd on public.dep_jobs     for update to authenticated using (public.has_role('operations'));
create policy db_sel on public.dep_bookings for select to authenticated using (public.is_staff());
create policy db_ins on public.dep_bookings for insert to authenticated with check (public.has_role('operations'));
create policy db_upd on public.dep_bookings for update to authenticated using (public.has_role('operations'));

-- ---------- time rules (Manila) ----------
create or replace function public.dep_now() returns timestamp language sql stable as $$ select now() at time zone 'Asia/Manila' $$;
create or replace function public.dep_at(d date, t time) returns timestamptz language sql immutable as $$ select (d + t) at time zone 'Asia/Manila' $$;
-- a job is open until 6 PM the day before; one posted later stays open until 2 hours before call time
create or replace function public.dep_closes(j public.dep_jobs) returns timestamptz language sql stable as $$
  select case when j.created_at < public.dep_at(j.day - 1, '18:00') then public.dep_at(j.day - 1, '18:00')
              else public.dep_at(j.day, j.call_time) - interval '2 hours' end
$$;
-- backing out after 8 PM the night before is late (a strike)
create or replace function public.dep_late_from(d date) returns timestamptz language sql immutable as $$ select public.dep_at(d - 1, '20:00') $$;
-- a day of next week cannot be removed after Thursday 8 PM of this week; this week's days never
create or replace function public.dep_day_locked(d date) returns boolean language sql stable as $$
  select d <= (date_trunc('week', public.dep_now())::date + 6)
      or (d <= (date_trunc('week', public.dep_now())::date + 13) and public.dep_now() > date_trunc('week', public.dep_now()) + interval '3 days 20 hours')
$$;
revoke all on function public.dep_closes(public.dep_jobs) from public;

-- ---------- strikes and pauses ----------
-- {strikes (last 60 days), paused_until, removed, events[]}
create or replace function public.drv_standing(p_id text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare r record; ev jsonb := '[]'::jsonb; t timestamptz; pauses timestamptz[] := '{}'; pu timestamptz; n int; v_from timestamptz;
begin
  select nullif(data->>'depReinstatedAt','')::timestamptz into v_from from applicants where id = p_id;
  for r in
    select b.id, 'late_cancel' as kind, b.cancelled_at as at, j.day, j.account from dep_bookings b join dep_jobs j on j.id = b.job_id
     where b.applicant_id = p_id and b.cancel_late and not b.waived and b.cancelled_at is not null and j.cancelled_at is null
    union all
    select b.id, 'no_show', public.dep_at(j.day, j.call_time) + interval '2 hours', j.day, j.account from dep_bookings b join dep_jobs j on j.id = b.job_id
     where b.applicant_id = p_id and b.cancelled_at is null and b.time_in is null and not b.waived and j.cancelled_at is null
       and public.dep_at(j.day, j.call_time) + interval '2 hours' < now()
    order by 3
  loop
    if v_from is not null and r.at < v_from then continue; end if;
    ev := ev || jsonb_build_object('id', r.id, 'kind', r.kind, 'at', r.at, 'day', r.day, 'account', r.account);
    select count(*) into n from jsonb_array_elements(ev) e where (e->>'at')::timestamptz > r.at - interval '60 days';
    if r.kind = 'no_show' or n >= 2 then
      if array_length(pauses, 1) is null or pauses[array_length(pauses, 1)] + interval '30 days' < r.at then pauses := pauses || r.at; end if;
    end if;
  end loop;
  if array_length(pauses, 1) is not null then pu := pauses[array_length(pauses, 1)] + interval '30 days'; end if;
  select count(*) into n from jsonb_array_elements(ev) e where (e->>'at')::timestamptz > now() - interval '60 days';
  return jsonb_build_object('strikes', n,
    'paused_until', case when pu > now() then pu end,
    'removed', (select count(*) from unnest(pauses) p where p > now() - interval '6 months') >= 2,
    'events', ev);
end $$;
revoke all on function public.drv_standing(text) from public;
grant execute on function public.drv_standing(text) to authenticated;

-- ---------- signing in ----------
create or replace function public.drv_hash(p_salt text, p_pin text) returns text language sql immutable as $$
  select encode(sha256(convert_to(p_salt || ':' || p_pin, 'UTF8')), 'hex') $$;
revoke all on function public.drv_hash(text, text) from public;

-- applicants keep code + last 4 digits; once a driver has a PIN, the PIN is needed instead
create or replace function public.app_login(p_code text, p_last4 text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_code text := upper(regexp_replace(coalesce(p_code,''), '\s', '', 'g')); v_id text; v_tok text; v_fails int;
begin
  v_code := regexp_replace(v_code, '^MB-?', 'MB-');
  delete from app_login_fails where at < now() - interval '1 day';
  delete from applicant_sessions where expires_at < now();
  select count(*) into v_fails from app_login_fails where code = v_code and at > now() - interval '1 hour';
  if v_fails >= 5 then return jsonb_build_object('error','locked'); end if;
  if exists (select 1 from driver_auth da join applicants a on a.id = da.applicant_id where upper(a.code) = v_code) then
    return jsonb_build_object('error','pin');
  end if;
  select id into v_id from applicants
   where upper(code) = v_code and coalesce(p_last4,'') ~ '^[0-9]{4}$'
     and right(regexp_replace(coalesce(data->>'phone',''), '\D', '', 'g'), 4) = p_last4
   limit 1;
  if v_id is null then
    insert into app_login_fails(code) values (v_code);
    return jsonb_build_object('error', case when v_fails + 1 >= 5 then 'locked' else 'wrong' end);
  end if;
  delete from app_login_fails where code = v_code;
  v_tok := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
  insert into applicant_sessions(token_hash, applicant_id, expires_at)
  values (encode(sha256(convert_to(v_tok, 'UTF8')), 'hex'), v_id, now() + interval '30 days');
  return jsonb_build_object('ok', true, 'token', v_tok, 'id', v_id);
end $$;

create or replace function public.drv_login(p_code text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_code text := regexp_replace(upper(regexp_replace(coalesce(p_code,''), '\s', '', 'g')), '^MB-?', 'MB-'); v_id text; v_tok text; v_fails int; da record;
begin
  delete from app_login_fails where at < now() - interval '1 day';
  select count(*) into v_fails from app_login_fails where code = v_code and at > now() - interval '1 hour';
  if v_fails >= 5 then return jsonb_build_object('error','locked'); end if;
  select a.id, d.salt, d.pin_hash into da from applicants a join driver_auth d on d.applicant_id = a.id where upper(a.code) = v_code limit 1;
  if da.id is null or coalesce(p_pin,'') !~ '^[0-9]{4}$' or public.drv_hash(da.salt, p_pin) <> da.pin_hash then
    insert into app_login_fails(code) values (v_code);
    return jsonb_build_object('error', case when v_fails + 1 >= 5 then 'locked' else 'wrong' end);
  end if;
  delete from app_login_fails where code = v_code;
  v_tok := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
  insert into applicant_sessions(token_hash, applicant_id, expires_at)
  values (encode(sha256(convert_to(v_tok, 'UTF8')), 'hex'), da.id, now() + interval '30 days');
  return jsonb_build_object('ok', true, 'token', v_tok, 'id', da.id);
end $$;

-- set the PIN the first time (or change it with the old one)
create or replace function public.drv_set_pin(p_token text, p_pin text, p_old text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); d jsonb; da record; s text;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  select data into d from applicants where id = v_id;
  if d->'released'->'accredited' is null or d->'released'->'fail' is not null then return jsonb_build_object('error','notdriver'); end if;
  if coalesce(p_pin,'') !~ '^[0-9]{4}$' then return jsonb_build_object('error','format'); end if;
  select * into da from driver_auth where applicant_id = v_id;
  if da.applicant_id is not null and public.drv_hash(da.salt, coalesce(p_old,'')) <> da.pin_hash then return jsonb_build_object('error','old'); end if;
  s := replace(gen_random_uuid()::text, '-', '');
  insert into driver_auth(applicant_id, salt, pin_hash) values (v_id, s, public.drv_hash(s, p_pin))
  on conflict (applicant_id) do update set salt = excluded.salt, pin_hash = excluded.pin_hash, set_at = now();
  return jsonb_build_object('ok', true);
end $$;

-- staff: forgot PIN → the driver signs in with the last 4 digits again and sets a new PIN
create or replace function public.dep_reset_pin(p_id text) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not (public.has_role('operations') or public.has_role('trainer')) then return jsonb_build_object('error','role'); end if;
  delete from driver_auth where applicant_id = p_id;
  delete from applicant_sessions where applicant_id = p_id;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- what the driver sees ----------
create or replace function public.drv_me(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); d jsonb; st jsonb; accs jsonb; today date := public.dep_now()::date; v_days jsonb; v_books jsonb; v_offers jsonb; v_taken jsonb; ok boolean;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  select data into d from applicants where id = v_id;
  ok := d->'released'->'accredited' is not null and d->'released'->'fail' is null;
  if not ok then return jsonb_build_object('driver', false); end if;
  st := public.drv_standing(v_id);
  accs := coalesce(d->'accounts', '[]'::jsonb);
  select coalesce(jsonb_agg(day order by day), '[]'::jsonb) into v_days from driver_days where applicant_id = v_id and day >= today;
  select coalesce(jsonb_agg(jsonb_build_object('id', b.id, 'job', j.id, 'day', j.day, 'account', j.account, 'role', j.role, 'hub', j.hub,
      'call', to_char(j.call_time, 'HH24:MI'), 'note', j.note, 'cancelled', b.cancelled_at is not null or j.cancelled_at is not null,
      'byUs', j.cancelled_at is not null or b.cancel_by = 'staff', 'late', b.cancel_late, 'timeIn', b.time_in, 'outcome', b.outcome,
      'noShow', b.cancelled_at is null and j.cancelled_at is null and b.time_in is null and public.dep_at(j.day, j.call_time) + interval '2 hours' < now(),
      'lateFrom', public.dep_late_from(j.day),
      'queue', case when b.outcome = 'standby' or (b.time_in is not null and b.outcome is null) then
         (select count(*) from dep_bookings b2 join dep_jobs j2 on j2.id = b2.job_id where j2.day = j.day and j2.hub = j.hub and b2.time_in is not null and b2.outcome is distinct from 'deployed'
            and b2.cancelled_at is null and ((b2.time_in <= public.dep_at(j2.day, j2.call_time) - interval '15 minutes') > (b.time_in <= public.dep_at(j.day, j.call_time) - interval '15 minutes')
              or ((b2.time_in <= public.dep_at(j2.day, j2.call_time) - interval '15 minutes') = (b.time_in <= public.dep_at(j.day, j.call_time) - interval '15 minutes') and b2.time_in <= b.time_in))) end)
      order by j.day desc, j.call_time desc), '[]'::jsonb)
    into v_books from dep_bookings b join dep_jobs j on j.id = b.job_id where b.applicant_id = v_id and j.day >= today - 45;
  -- open jobs this driver may take
  select coalesce(jsonb_agg(jsonb_build_object('id', j.id, 'day', j.day, 'account', j.account, 'role', j.role, 'hub', j.hub, 'call', to_char(j.call_time, 'HH24:MI'),
      'note', j.note, 'closes', public.dep_closes(j)) order by j.day, j.call_time), '[]'::jsonb) into v_offers
    from dep_jobs j
   where j.cancelled_at is null and j.day >= today and now() < public.dep_closes(j)
     and accs ? j.account
     and exists (select 1 from driver_days dd where dd.applicant_id = v_id and dd.day = j.day)
     and not exists (select 1 from dep_bookings b join dep_jobs j2 on j2.id = b.job_id where b.applicant_id = v_id and j2.day = j.day and b.cancelled_at is null and j2.cancelled_at is null)
     and not exists (select 1 from dep_bookings b where b.applicant_id = v_id and b.job_id = j.id)
     and (select count(*) from dep_bookings b where b.job_id = j.id and b.cancelled_at is null) < j.needed
     and ((st->>'strikes')::int = 0 or now() > j.created_at + interval '15 minutes')
     and st->>'paused_until' is null and not (st->>'removed')::boolean;
  -- filled jobs they could have had ("Taken, thank you!")
  select coalesce(jsonb_agg(jsonb_build_object('day', j.day, 'account', j.account, 'role', j.role)), '[]'::jsonb) into v_taken from (
    select j.* from dep_jobs j where j.cancelled_at is null and j.day >= today and j.created_at > now() - interval '2 days' and accs ? j.account
      and exists (select 1 from driver_days dd where dd.applicant_id = v_id and dd.day = j.day)
      and not exists (select 1 from dep_bookings b where b.applicant_id = v_id and b.job_id = j.id)
      and (select count(*) from dep_bookings b where b.job_id = j.id and b.cancelled_at is null) >= j.needed
    order by j.created_at desc limit 2) j;
  return jsonb_build_object('driver', true, 'hasPin', exists (select 1 from driver_auth where applicant_id = v_id),
    'accounts', accs, 'standing', st - 'events', 'strikeList', st->'events', 'days', v_days, 'bookings', v_books, 'offers', v_offers, 'taken', v_taken,
    'today', today, 'now', now(), 'locked', (select coalesce(jsonb_agg(x), '[]'::jsonb) from generate_series(today, today + 21, '1 day') x where public.dep_day_locked(x::date)),
    'docs', jsonb_build_object('license', jsonb_build_object('expiry', d->'docs'->'license'->'expiry', 'codes', d->'docs'->'license'->'restrictions'),
      'nbi', jsonb_build_object('expiry', d->'docs'->'nbi'->'expiry'), 'medical', jsonb_build_object('date', d->'docs'->'medical'->'date')));
end $$;

-- the days the driver can work (today .. 3 weeks); locked days can be added, not removed
create or replace function public.drv_set_days(p_token text, p_days text[]) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); today date := public.dep_now()::date; want date[]; bad date[];
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  if not exists (select 1 from applicants where id = v_id and data->'released'->'accredited' is not null and data->'released'->'fail' is null) then return jsonb_build_object('error','notdriver'); end if;
  select coalesce(array_agg(distinct x::date), '{}') into want from unnest(coalesce(p_days, '{}')) x where x ~ '^\d{4}-\d{2}-\d{2}$' and x::date between today and today + 21;
  select coalesce(array_agg(day), '{}') into bad from driver_days where applicant_id = v_id and day >= today and not (day = any(want))
    and (public.dep_day_locked(day) or exists (select 1 from dep_bookings b join dep_jobs j on j.id = b.job_id where b.applicant_id = v_id and j.day = driver_days.day and b.cancelled_at is null and j.cancelled_at is null));
  if array_length(bad, 1) is not null then return jsonb_build_object('error','locked', 'days', to_jsonb(bad)); end if;
  delete from driver_days where applicant_id = v_id and day >= today and not (day = any(want));
  insert into driver_days(applicant_id, day) select v_id, x from unnest(want) x on conflict do nothing;
  return jsonb_build_object('ok', true);
end $$;

-- "I'll take it": first to tap gets it
create or replace function public.drv_take(p_token text, p_job uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); j dep_jobs; st jsonb; n int;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  perform pg_advisory_xact_lock(hashtext('dep:' || p_job::text));
  select * into j from dep_jobs where id = p_job;
  if j.id is null or j.cancelled_at is not null then return jsonb_build_object('error','gone'); end if;
  if now() >= public.dep_closes(j) then return jsonb_build_object('error','closed'); end if;
  if not exists (select 1 from applicants where id = v_id and data->'released'->'accredited' is not null and data->'released'->'fail' is null and coalesce(data->'accounts','[]'::jsonb) ? j.account) then
    return jsonb_build_object('error','account'); end if;
  st := public.drv_standing(v_id);
  if st->>'paused_until' is not null or (st->>'removed')::boolean then return jsonb_build_object('error','paused'); end if;
  if (st->>'strikes')::int > 0 and now() <= j.created_at + interval '15 minutes' then return jsonb_build_object('error','early'); end if;
  if exists (select 1 from dep_bookings b join dep_jobs j2 on j2.id = b.job_id where b.applicant_id = v_id and j2.day = j.day and b.cancelled_at is null and j2.cancelled_at is null) then
    return jsonb_build_object('error','sameday'); end if;
  select count(*) into n from dep_bookings where job_id = j.id and cancelled_at is null;
  if n >= j.needed then return jsonb_build_object('error','taken'); end if;
  insert into driver_days(applicant_id, day) values (v_id, j.day) on conflict do nothing;
  insert into dep_bookings(job_id, applicant_id) values (j.id, v_id)
  on conflict (job_id, applicant_id) do update set cancelled_at = null, cancel_late = false, cancel_by = null, booked_at = now();
  return jsonb_build_object('ok', true);
end $$;

-- "I can't make it": allowed until call time; after 8 PM the night before it counts as a strike
create or replace function public.drv_cancel(p_token text, p_booking uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); b dep_bookings; j dep_jobs; late boolean;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  select * into b from dep_bookings where id = p_booking and applicant_id = v_id for update;
  if b.id is null or b.cancelled_at is not null then return jsonb_build_object('error','gone'); end if;
  select * into j from dep_jobs where id = b.job_id;
  if b.time_in is not null or now() >= public.dep_at(j.day, j.call_time) then return jsonb_build_object('error','toolate'); end if;
  late := now() >= public.dep_late_from(j.day);
  update dep_bookings set cancelled_at = now(), cancel_late = late, cancel_by = 'driver' where id = b.id;
  return jsonb_build_object('ok', true, 'late', late);
end $$;

-- ---------- at the hub (staff) ----------
-- scan the driver's QR: time in for today's booking at this hub
create or replace function public.dep_scan(p_code text, p_hub text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_code text := regexp_replace(upper(regexp_replace(coalesce(p_code,''), '^(DF|MOBER):', '', 'i')), '\s', '', 'g'); a record; b record; today date := public.dep_now()::date;
begin
  if not public.has_role('operations') then return jsonb_build_object('error','role'); end if;
  v_code := regexp_replace(v_code, '^MB-?', 'MB-');
  select id, data into a from applicants where upper(code) = v_code limit 1;
  if a.id is null then return jsonb_build_object('error','unknown'); end if;
  select bk.*, j.account, j.role, j.hub, j.call_time, j.day into b from dep_bookings bk join dep_jobs j on j.id = bk.job_id
   where bk.applicant_id = a.id and j.day = today and bk.cancelled_at is null and j.cancelled_at is null
     and (coalesce(p_hub,'') = '' or j.hub = p_hub)
   order by j.call_time limit 1;
  if b.id is null then return jsonb_build_object('error','nobooking', 'id', a.id, 'name', a.data->>'name'); end if;
  if b.time_in is null then update dep_bookings set time_in = now() where id = b.id; b.time_in := now(); end if;
  return jsonb_build_object('ok', true, 'booking', b.id, 'id', a.id, 'name', a.data->>'name', 'code', a.data->>'code', 'account', b.account, 'role', b.role, 'hub', b.hub,
    'timeIn', b.time_in, 'due', public.dep_at(b.day, b.call_time) - interval '15 minutes', 'onTime', b.time_in <= public.dep_at(b.day, b.call_time) - interval '15 minutes', 'outcome', b.outcome);
end $$;

-- ---------- who may call what ----------
revoke all on function public.drv_login(text,text) from public;
revoke all on function public.drv_set_pin(text,text,text) from public;
revoke all on function public.drv_me(text) from public;
revoke all on function public.drv_set_days(text,text[]) from public;
revoke all on function public.drv_take(text,uuid) from public;
revoke all on function public.drv_cancel(text,uuid) from public;
revoke all on function public.dep_reset_pin(text) from public;
revoke all on function public.dep_scan(text,text) from public;
grant execute on function public.app_login(text,text)        to anon, authenticated;
grant execute on function public.drv_login(text,text)        to anon, authenticated;
grant execute on function public.drv_set_pin(text,text,text) to anon, authenticated;
grant execute on function public.drv_me(text)                to anon, authenticated;
grant execute on function public.drv_set_days(text,text[])   to anon, authenticated;
grant execute on function public.drv_take(text,uuid)         to anon, authenticated;
grant execute on function public.drv_cancel(text,uuid)       to anon, authenticated;
grant execute on function public.dep_reset_pin(text)         to authenticated;
grant execute on function public.dep_scan(text,text)         to authenticated;
