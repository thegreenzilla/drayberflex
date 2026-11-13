-- =====================================================================
-- DrayberFlex – update: Orders and automatic dispatch (needs 2026-11-12 driver app)
--  * Operations enters a client order once (e.g. 10 drivers a day, Mon–Sun, Nov 17–30). Dispatch makes one job per day.
--    Each week's jobs are offered on the Friday 8 AM before that week (after drivers' days lock on Thursday 8 PM),
--    or straight away when that time has passed or Operations taps "Send now".
--  * Offers go to every matching driver: trained for the account, marked the day available (or asked "Are you free?"),
--    not paused, no other job that day, under their weekly limit. Drivers accept several days at once or decline.
--  * First come, first served; when a day is full the driver goes on the waitlist and is moved up by themselves
--    when someone backs out.
--  * Declining days they had marked available asks for a reason and removes those days; 3 in 30 days = they see
--    new offers 1 hour after everyone else for 2 weeks.
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================

create table if not exists public.dep_orders (
  id           uuid primary key default gen_random_uuid(),
  client       text not null default '' check (length(client) <= 80),
  account      text not null check (length(account) between 1 and 60),
  role         text not null default 'Driver' check (length(role) between 1 and 60),
  hub          text not null default '' check (length(hub) <= 80),
  call_time    time not null,
  needed       int  not null check (needed between 1 and 200),
  days         int[] not null default '{1,2,3,4,5,6,7}',      -- 1 = Monday … 7 = Sunday
  start_day    date not null,
  end_day      date not null,
  note         text not null default '' check (length(note) <= 300),
  created_by   uuid,
  created_at   timestamptz not null default now(),
  dispatched_at timestamptz,
  cancelled_at timestamptz,
  check (end_day >= start_day and end_day <= start_day + 120)
);
alter table public.dep_jobs add column if not exists order_id uuid references public.dep_orders(id) on delete cascade;
alter table public.dep_jobs add column if not exists sent_at timestamptz;
alter table public.dep_jobs add column if not exists ask_all_at timestamptz;
update public.dep_jobs set sent_at = created_at where sent_at is null and order_id is null;
create unique index if not exists dep_jobs_order_day on public.dep_jobs (order_id, day) where order_id is not null;
alter table public.dep_bookings add column if not exists waitlist boolean not null default false;
create table if not exists public.driver_prefs (
  applicant_id text primary key references public.applicants(id) on delete cascade,
  max_week     int check (max_week between 1 and 7)
);
create table if not exists public.dep_declines (
  id           bigserial primary key,
  applicant_id text not null references public.applicants(id) on delete cascade,
  job_id       uuid not null references public.dep_jobs(id) on delete cascade,
  day          date not null,
  reason       text not null default '' check (length(reason) <= 60),
  was_available boolean not null default false,
  at           timestamptz not null default now(),
  unique (applicant_id, job_id)
);
alter table public.dep_orders   enable row level security;
alter table public.driver_prefs enable row level security;
alter table public.dep_declines enable row level security;
revoke all on public.dep_orders   from anon, authenticated;
revoke all on public.driver_prefs from anon, authenticated;
revoke all on public.dep_declines from anon, authenticated;
grant select, insert, update on public.dep_orders to authenticated;
grant select on public.driver_prefs, public.dep_declines to authenticated;
drop policy if exists do_sel on public.dep_orders;
drop policy if exists do_ins on public.dep_orders;
drop policy if exists do_upd on public.dep_orders;
drop policy if exists dp_sel on public.driver_prefs;
drop policy if exists dc_sel on public.dep_declines;
create policy do_sel on public.dep_orders   for select to authenticated using (public.is_staff());
create policy do_ins on public.dep_orders   for insert to authenticated with check (public.has_role('operations'));
create policy do_upd on public.dep_orders   for update to authenticated using (public.has_role('operations'));
create policy dp_sel on public.driver_prefs for select to authenticated using (public.is_staff());
create policy dc_sel on public.dep_declines for select to authenticated using (public.is_staff());

-- ---------- time rules ----------
-- when a day's job is offered: the Friday 8 AM before its week
create or replace function public.dep_send_time(d date) returns timestamptz language sql immutable as $$
  select public.dep_at(date_trunc('week', d)::date - 3, '08:00') $$;
-- open until 6 PM the day before; offered later = until 2 hours before call time
create or replace function public.dep_closes(j public.dep_jobs) returns timestamptz language sql stable as $$
  select case when coalesce(j.sent_at, j.created_at) < public.dep_at(j.day - 1, '18:00') then public.dep_at(j.day - 1, '18:00')
              else public.dep_at(j.day, j.call_time) - interval '2 hours' end
$$;
revoke all on function public.dep_closes(public.dep_jobs) from public;

-- ---------- reliability and standing ----------
create or replace function public.drv_stats(p_id text) returns jsonb
language sql stable security definer set search_path = public as $$
  with b as (
    select b.*, j.day, j.call_time from dep_bookings b join dep_jobs j on j.id = b.job_id
     where b.applicant_id = p_id and not b.waitlist and j.cancelled_at is null and coalesce(b.cancel_by, '') <> 'staff'
       and j.day > (now() at time zone 'Asia/Manila')::date - 60 and public.dep_at(j.day, j.call_time) < now() + interval '30 days')
  select jsonb_build_object(
    'accepted', count(*),
    'on_time', count(*) filter (where time_in is not null and time_in <= public.dep_at(day, call_time) - interval '15 minutes'),
    'late', count(*) filter (where time_in is not null and time_in > public.dep_at(day, call_time) - interval '15 minutes'),
    'backout_early', count(*) filter (where cancelled_at is not null and not cancel_late),
    'backout_late', count(*) filter (where cancelled_at is not null and cancel_late),
    'no_show', count(*) filter (where cancelled_at is null and time_in is null and public.dep_at(day, call_time) + interval '2 hours' < now()),
    'declined_available', (select count(*) from dep_declines where applicant_id = p_id and was_available and at > now() - interval '60 days'),
    'declined_available_30', (select count(*) from dep_declines where applicant_id = p_id and was_available and at > now() - interval '30 days'))
  from b
$$;
revoke all on function public.drv_stats(text) from public;
grant execute on function public.drv_stats(text) to authenticated;

-- {strikes, paused_until, removed, events, delay_until, stats}
create or replace function public.drv_standing(p_id text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare r record; ev jsonb := '[]'::jsonb; pauses timestamptz[] := '{}'; pu timestamptz; n int; v_from timestamptz; third timestamptz;
begin
  select nullif(data->>'depReinstatedAt','')::timestamptz into v_from from applicants where id = p_id;
  for r in
    select b.id, 'late_cancel' as kind, b.cancelled_at as at, j.day, j.account from dep_bookings b join dep_jobs j on j.id = b.job_id
     where b.applicant_id = p_id and b.cancel_late and not b.waived and not b.waitlist and b.cancelled_at is not null and j.cancelled_at is null
    union all
    select b.id, 'no_show', public.dep_at(j.day, j.call_time) + interval '2 hours', j.day, j.account from dep_bookings b join dep_jobs j on j.id = b.job_id
     where b.applicant_id = p_id and b.cancelled_at is null and b.time_in is null and not b.waived and not b.waitlist and j.cancelled_at is null
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
  -- 3 declines of available days in 30 days → offers 1 hour late for 2 weeks from the third
  select at into third from (select at from dep_declines where applicant_id = p_id and was_available and at > now() - interval '30 days'
     and (v_from is null or at > v_from) order by at desc offset 2 limit 1) x;
  return jsonb_build_object('strikes', n,
    'paused_until', case when pu > now() then pu end,
    'removed', (select count(*) from unnest(pauses) p where p > now() - interval '6 months') >= 2,
    'delay_until', case when third + interval '14 days' > now() then third + interval '14 days' end,
    'events', ev, 'stats', public.drv_stats(p_id));
end $$;
revoke all on function public.drv_standing(text) from public;
grant execute on function public.drv_standing(text) to authenticated;

-- may this driver see / take this job now? ('' = yes, else the reason)
create or replace function public.drv_can(p_id text, j public.dep_jobs, st jsonb) returns text
language plpgsql stable security definer set search_path = public as $$
declare lim int; used int; mon date := date_trunc('week', j.day)::date;
begin
  if j.cancelled_at is not null then return 'gone'; end if;
  if j.sent_at is null or now() < j.sent_at then return 'notyet'; end if;
  if now() >= public.dep_closes(j) then return 'closed'; end if;
  if not exists (select 1 from applicants where id = p_id and data->'released'->'accredited' is not null and data->'released'->'fail' is null and coalesce(data->'accounts','[]'::jsonb) ? j.account) then return 'account'; end if;
  if st->>'paused_until' is not null or (st->>'removed')::boolean then return 'paused'; end if;
  if (st->>'strikes')::int > 0 and now() <= j.sent_at + interval '15 minutes' then return 'early'; end if;
  if st->>'delay_until' is not null and now() <= j.sent_at + interval '1 hour' then return 'early'; end if;
  if not exists (select 1 from driver_days dd where dd.applicant_id = p_id and dd.day = j.day) and (j.ask_all_at is null or now() < j.ask_all_at) then return 'notavailable'; end if;
  if exists (select 1 from dep_bookings b join dep_jobs j2 on j2.id = b.job_id where b.applicant_id = p_id and j2.day = j.day and b.cancelled_at is null and j2.cancelled_at is null and b.job_id <> j.id) then return 'sameday'; end if;
  select max_week into lim from driver_prefs where applicant_id = p_id;
  if lim is not null then
    select count(*) into used from dep_bookings b join dep_jobs j2 on j2.id = b.job_id
     where b.applicant_id = p_id and b.cancelled_at is null and j2.cancelled_at is null and j2.day between mon and mon + 6 and b.job_id <> j.id;
    if used >= lim then return 'limit'; end if;
  end if;
  return '';
end $$;
revoke all on function public.drv_can(text, public.dep_jobs, jsonb) from public;

-- move the first person on the waitlist into a freed seat
create or replace function public.dep_promote(p_job uuid) returns void
language plpgsql security definer set search_path = public as $$
declare j dep_jobs; w record;
begin
  select * into j from dep_jobs where id = p_job;
  if j.id is null or j.cancelled_at is not null then return; end if;
  while (select count(*) from dep_bookings where job_id = p_job and cancelled_at is null and not waitlist) < j.needed loop
    select b.* into w from dep_bookings b where b.job_id = p_job and b.cancelled_at is null and b.waitlist order by b.booked_at limit 1;
    exit when w.id is null;
    if exists (select 1 from dep_bookings b join dep_jobs j2 on j2.id = b.job_id where b.applicant_id = w.applicant_id and j2.day = j.day and b.cancelled_at is null and not b.waitlist and j2.cancelled_at is null) then
      update dep_bookings set cancelled_at = now(), cancel_by = 'staff' where id = w.id;   -- they already have a job that day
    else
      update dep_bookings set waitlist = false, booked_at = now() where id = w.id;
    end if;
  end loop;
end $$;
revoke all on function public.dep_promote(uuid) from public;
create or replace function public.dep_after_cancel() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if old.cancelled_at is null and new.cancelled_at is not null and not new.waitlist then perform public.dep_promote(new.job_id); end if;
  return new;
end $$;
drop trigger if exists dep_bookings_promote on public.dep_bookings;
create trigger dep_bookings_promote after update of cancelled_at on public.dep_bookings for each row execute function public.dep_after_cancel();

-- ---------- what the driver sees ----------
create or replace function public.drv_me(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); d jsonb; st jsonb; accs jsonb; today date := public.dep_now()::date; v_days jsonb; v_books jsonb; v_offers jsonb; v_taken jsonb;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  select data into d from applicants where id = v_id;
  if not (d->'released'->'accredited' is not null and d->'released'->'fail' is null) then return jsonb_build_object('driver', false); end if;
  st := public.drv_standing(v_id);
  accs := coalesce(d->'accounts', '[]'::jsonb);
  select coalesce(jsonb_agg(day order by day), '[]'::jsonb) into v_days from driver_days where applicant_id = v_id and day >= today;
  select coalesce(jsonb_agg(jsonb_build_object('id', b.id, 'job', j.id, 'order', j.order_id, 'day', j.day, 'account', j.account, 'role', j.role, 'hub', j.hub,
      'call', to_char(j.call_time, 'HH24:MI'), 'note', j.note, 'cancelled', b.cancelled_at is not null or j.cancelled_at is not null,
      'byUs', j.cancelled_at is not null or b.cancel_by = 'staff', 'late', b.cancel_late, 'timeIn', b.time_in, 'outcome', b.outcome, 'waitlist', b.waitlist,
      'waitPos', case when b.waitlist and b.cancelled_at is null then (select count(*) from dep_bookings w where w.job_id = j.id and w.waitlist and w.cancelled_at is null and w.booked_at <= b.booked_at) end,
      'noShow', not b.waitlist and b.cancelled_at is null and j.cancelled_at is null and b.time_in is null and public.dep_at(j.day, j.call_time) + interval '2 hours' < now(),
      'lateFrom', public.dep_late_from(j.day),
      'queue', case when b.outcome = 'standby' or (b.time_in is not null and b.outcome is null) then
         (select count(*) from dep_bookings b2 join dep_jobs j2 on j2.id = b2.job_id where j2.day = j.day and j2.hub = j.hub and b2.time_in is not null and b2.outcome is distinct from 'deployed'
            and b2.cancelled_at is null and ((b2.time_in <= public.dep_at(j2.day, j2.call_time) - interval '15 minutes') > (b.time_in <= public.dep_at(j.day, j.call_time) - interval '15 minutes')
              or ((b2.time_in <= public.dep_at(j2.day, j2.call_time) - interval '15 minutes') = (b.time_in <= public.dep_at(j.day, j.call_time) - interval '15 minutes') and b2.time_in <= b.time_in))) end)
      order by j.day desc, j.call_time desc), '[]'::jsonb)
    into v_books from dep_bookings b join dep_jobs j on j.id = b.job_id where b.applicant_id = v_id and j.day >= today - 45;
  select coalesce(jsonb_agg(jsonb_build_object('id', j.id, 'order', j.order_id, 'day', j.day, 'account', j.account, 'role', j.role, 'hub', j.hub, 'call', to_char(j.call_time, 'HH24:MI'),
      'note', j.note, 'closes', public.dep_closes(j), 'available', exists (select 1 from driver_days dd where dd.applicant_id = v_id and dd.day = j.day),
      'full', (select count(*) from dep_bookings b where b.job_id = j.id and b.cancelled_at is null and not b.waitlist) >= j.needed) order by j.day, j.call_time), '[]'::jsonb) into v_offers
    from dep_jobs j
   where j.day >= today and accs ? j.account
     and not exists (select 1 from dep_bookings b where b.applicant_id = v_id and b.job_id = j.id and b.cancelled_at is null)
     and not exists (select 1 from dep_declines x where x.applicant_id = v_id and x.job_id = j.id)
     and public.drv_can(v_id, j, st) = '';
  select coalesce(jsonb_agg(jsonb_build_object('day', j.day, 'account', j.account, 'role', j.role)), '[]'::jsonb) into v_taken from (
    select j.* from dep_jobs j where j.cancelled_at is null and j.day >= today and coalesce(j.sent_at, j.created_at) > now() - interval '2 days' and now() >= coalesce(j.sent_at, j.created_at) and accs ? j.account
      and exists (select 1 from driver_days dd where dd.applicant_id = v_id and dd.day = j.day)
      and not exists (select 1 from dep_bookings b where b.applicant_id = v_id and b.job_id = j.id)
      and (select count(*) from dep_bookings b where b.job_id = j.id and b.cancelled_at is null and not b.waitlist) >= j.needed
      and now() >= public.dep_closes(j)
    order by j.created_at desc limit 2) j;
  return jsonb_build_object('driver', true, 'hasPin', exists (select 1 from driver_auth where applicant_id = v_id),
    'accounts', accs, 'standing', st - 'events' - 'stats', 'stats', st->'stats', 'strikeList', st->'events', 'days', v_days, 'bookings', v_books, 'offers', v_offers, 'taken', v_taken,
    'maxWeek', (select max_week from driver_prefs where applicant_id = v_id),
    'today', today, 'now', now(), 'locked', (select coalesce(jsonb_agg(x), '[]'::jsonb) from generate_series(today, today + 21, '1 day') x where public.dep_day_locked(x::date)),
    'docs', jsonb_build_object('license', jsonb_build_object('expiry', d->'docs'->'license'->'expiry', 'codes', d->'docs'->'license'->'restrictions'),
      'nbi', jsonb_build_object('expiry', d->'docs'->'nbi'->'expiry'), 'medical', jsonb_build_object('date', d->'docs'->'medical'->'date')));
end $$;

-- accept one or more days: a seat if one is left, else the waitlist
create or replace function public.drv_accept(p_token text, p_jobs uuid[]) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); jid uuid; j dep_jobs; st jsonb; why text; n int; res jsonb := '[]'::jsonb;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  st := public.drv_standing(v_id);
  foreach jid in array coalesce(p_jobs, '{}') loop
    perform pg_advisory_xact_lock(hashtext('dep:' || jid::text));
    select * into j from dep_jobs where id = jid;
    if j.id is null then res := res || jsonb_build_object('job', jid, 'result', 'gone'); continue; end if;
    why := public.drv_can(v_id, j, st);
    if why <> '' then res := res || jsonb_build_object('job', jid, 'day', j.day, 'result', why); continue; end if;
    select count(*) into n from dep_bookings where job_id = j.id and cancelled_at is null and not waitlist;
    insert into driver_days(applicant_id, day) values (v_id, j.day) on conflict do nothing;
    insert into dep_bookings(job_id, applicant_id, waitlist) values (j.id, v_id, n >= j.needed)
    on conflict (job_id, applicant_id) do update set cancelled_at = null, cancel_late = false, cancel_by = null, booked_at = now(), waitlist = excluded.waitlist, time_in = null, outcome = null;
    res := res || jsonb_build_object('job', jid, 'day', j.day, 'result', case when n >= j.needed then 'waitlist' else 'booked' end);
  end loop;
  return jsonb_build_object('ok', true, 'results', res);
end $$;

-- the old single "take" keeps working
create or replace function public.drv_take(p_token text, p_job uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r jsonb := public.drv_accept(p_token, array[p_job]); x text;
begin
  if r ? 'error' then return r; end if;
  x := r->'results'->0->>'result';
  return case when x in ('booked','waitlist') then jsonb_build_object('ok', true, 'result', x) else jsonb_build_object('error', x) end;
end $$;

-- decline days; days they had marked available are asked a reason and removed from My days
create or replace function public.drv_decline(p_token text, p_jobs uuid[], p_reason text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); jid uuid; j dep_jobs; av boolean; cnt int := 0;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  foreach jid in array coalesce(p_jobs, '{}') loop
    select * into j from dep_jobs where id = jid;
    continue when j.id is null;
    av := exists (select 1 from driver_days where applicant_id = v_id and day = j.day);
    insert into dep_declines(applicant_id, job_id, day, reason, was_available) values (v_id, j.id, j.day, left(coalesce(p_reason,''), 60), av)
    on conflict (applicant_id, job_id) do nothing;
    if av then delete from driver_days where applicant_id = v_id and day = j.day; cnt := cnt + 1; end if;
  end loop;
  return jsonb_build_object('ok', true, 'removedDays', cnt, 'count30', (select count(*) from dep_declines where applicant_id = v_id and was_available and at > now() - interval '30 days'));
end $$;

-- back out: waitlist = just leave it; else allowed until call time, after 8 PM the night before = a strike
create or replace function public.drv_cancel(p_token text, p_booking uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); b dep_bookings; j dep_jobs; late boolean;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  select * into b from dep_bookings where id = p_booking and applicant_id = v_id for update;
  if b.id is null or b.cancelled_at is not null then return jsonb_build_object('error','gone'); end if;
  select * into j from dep_jobs where id = b.job_id;
  if b.waitlist then update dep_bookings set cancelled_at = now(), cancel_by = 'driver' where id = b.id; return jsonb_build_object('ok', true, 'late', false); end if;
  if b.time_in is not null or now() >= public.dep_at(j.day, j.call_time) then return jsonb_build_object('error','toolate'); end if;
  late := now() >= public.dep_late_from(j.day);
  update dep_bookings set cancelled_at = now(), cancel_late = late, cancel_by = 'driver' where id = b.id;
  return jsonb_build_object('ok', true, 'late', late);
end $$;

-- most days a week the driver wants (null = no limit)
create or replace function public.drv_set_limit(p_token text, p_max int) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token);
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  if p_max is not null and (p_max < 1 or p_max > 7) then return jsonb_build_object('error','format'); end if;
  insert into driver_prefs(applicant_id, max_week) values (v_id, p_max) on conflict (applicant_id) do update set max_week = excluded.max_week;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- Operations ----------
-- make the order's daily jobs; each week is offered on the Friday 8 AM before it (or now if that has passed)
create or replace function public.dep_dispatch(p_order uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare o dep_orders; d date; n int := 0; today date := public.dep_now()::date;
begin
  if not public.has_role('operations') then return jsonb_build_object('error','role'); end if;
  select * into o from dep_orders where id = p_order for update;
  if o.id is null or o.cancelled_at is not null then return jsonb_build_object('error','gone'); end if;
  for d in select x::date from generate_series(greatest(o.start_day, today), o.end_day, '1 day') x loop
    continue when not (extract(isodow from d)::int = any(o.days));
    insert into dep_jobs(order_id, account, role, hub, day, call_time, needed, note, created_by, sent_at)
    values (o.id, o.account, o.role, o.hub, d, o.call_time, o.needed, o.note, auth.uid(), greatest(now(), public.dep_send_time(d)))
    on conflict (order_id, day) where order_id is not null do nothing;
    if found then n := n + 1; end if;
  end loop;
  update dep_orders set dispatched_at = coalesce(dispatched_at, now()) where id = o.id;
  return jsonb_build_object('ok', true, 'jobs', n);
end $$;
-- offer a week (or one day) now instead of on Friday
create or replace function public.dep_send_now(p_order uuid, p_from date, p_to date) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not public.has_role('operations') then return jsonb_build_object('error','role'); end if;
  update dep_jobs set sent_at = now() where order_id = p_order and day between p_from and p_to and cancelled_at is null and (sent_at is null or sent_at > now());
  get diagnostics n = row_count;
  return jsonb_build_object('ok', true, 'jobs', n);
end $$;
-- "Are you free?": also offer this day to trained drivers who didn't mark it
create or replace function public.dep_ask_all(p_job uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.has_role('operations') then return jsonb_build_object('error','role'); end if;
  update dep_jobs set ask_all_at = now(), sent_at = least(coalesce(sent_at, now()), now()) where id = p_job and cancelled_at is null;
  return jsonb_build_object('ok', true);
end $$;
-- cancel an order and its days still to come
create or replace function public.dep_cancel_order(p_order uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.has_role('operations') then return jsonb_build_object('error','role'); end if;
  update dep_orders set cancelled_at = now() where id = p_order and cancelled_at is null;
  update dep_jobs set cancelled_at = now() where order_id = p_order and cancelled_at is null and public.dep_at(day, call_time) > now();
  return jsonb_build_object('ok', true);
end $$;

-- scanning at the hub ignores waitlist places
create or replace function public.dep_scan(p_code text, p_hub text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_code text := regexp_replace(upper(regexp_replace(coalesce(p_code,''), '^(DF|MOBER):', '', 'i')), '\s', '', 'g'); a record; b record; today date := public.dep_now()::date;
begin
  if not public.has_role('operations') then return jsonb_build_object('error','role'); end if;
  v_code := regexp_replace(v_code, '^MB-?', 'MB-');
  select id, data into a from applicants where upper(code) = v_code limit 1;
  if a.id is null then return jsonb_build_object('error','unknown'); end if;
  select bk.*, j.account, j.role, j.hub, j.call_time, j.day into b from dep_bookings bk join dep_jobs j on j.id = bk.job_id
   where bk.applicant_id = a.id and j.day = today and bk.cancelled_at is null and not bk.waitlist and j.cancelled_at is null
     and (coalesce(p_hub,'') = '' or j.hub = p_hub)
   order by j.call_time limit 1;
  if b.id is null then return jsonb_build_object('error','nobooking', 'id', a.id, 'name', a.data->>'name'); end if;
  if b.time_in is null then update dep_bookings set time_in = now() where id = b.id; b.time_in := now(); end if;
  return jsonb_build_object('ok', true, 'booking', b.id, 'id', a.id, 'name', a.data->>'name', 'code', a.data->>'code', 'account', b.account, 'role', b.role, 'hub', b.hub,
    'timeIn', b.time_in, 'due', public.dep_at(b.day, b.call_time) - interval '15 minutes', 'onTime', b.time_in <= public.dep_at(b.day, b.call_time) - interval '15 minutes', 'outcome', b.outcome);
end $$;

revoke all on function public.drv_accept(text,uuid[]) from public;
revoke all on function public.drv_decline(text,uuid[],text) from public;
revoke all on function public.drv_set_limit(text,int) from public;
revoke all on function public.dep_dispatch(uuid) from public;
revoke all on function public.dep_send_now(uuid,date,date) from public;
revoke all on function public.dep_ask_all(uuid) from public;
revoke all on function public.dep_cancel_order(uuid) from public;
grant execute on function public.drv_me(text)                    to anon, authenticated;
grant execute on function public.drv_take(text,uuid)             to anon, authenticated;
grant execute on function public.drv_cancel(text,uuid)           to anon, authenticated;
grant execute on function public.drv_accept(text,uuid[])         to anon, authenticated;
grant execute on function public.drv_decline(text,uuid[],text)   to anon, authenticated;
grant execute on function public.drv_set_limit(text,int)         to anon, authenticated;
grant execute on function public.dep_dispatch(uuid)              to authenticated;
grant execute on function public.dep_send_now(uuid,date,date)    to authenticated;
grant execute on function public.dep_ask_all(uuid)               to authenticated;
grant execute on function public.dep_cancel_order(uuid)          to authenticated;
