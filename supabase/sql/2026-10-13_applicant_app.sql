-- =====================================================================
-- DrayberFlex – update: applicant app (Phase 1)
-- * Applicants sign in at #app with their reference code + last 4 digits of their mobile.
--   5 wrong tries for a code within an hour locks that code for the rest of the hour.
--   Sign-in lasts 30 days on that phone (only a hash of the sign-in key is stored).
-- * In the app they can: see their next step, reschedule the interview once (up to 12 hours
--   before), cancel it, and upload their NBI clearance / medical certificate later.
-- * A cancelled interview frees its seat (the booking check now skips cancelled bookings).
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================

create table if not exists public.applicant_sessions (
  token_hash   text primary key,
  applicant_id text not null references public.applicants(id) on delete cascade,
  created_at   timestamptz not null default now(),
  expires_at   timestamptz not null
);
create index if not exists applicant_sessions_app on public.applicant_sessions(applicant_id);
create table if not exists public.app_login_fails (
  code text not null,
  at   timestamptz not null default now()
);
create index if not exists app_login_fails_code on public.app_login_fails(code, at);
-- nobody reads these tables directly; only the functions below use them
alter table public.applicant_sessions enable row level security;
alter table public.app_login_fails    enable row level security;
revoke all on public.applicant_sessions from anon, authenticated;
revoke all on public.app_login_fails    from anon, authenticated;

-- sign-in key -> applicant id (null when unknown or expired)
create or replace function public.app_session(p_token text) returns text
language sql stable security definer set search_path = public as $$
  select applicant_id from applicant_sessions
   where token_hash = encode(sha256(convert_to(coalesce(p_token,''), 'UTF8')), 'hex')
     and expires_at > now()
$$;
revoke all on function public.app_session(text) from public;

-- code + last 4 digits of mobile -> {ok, token, id} | {error: wrong | locked}
create or replace function public.app_login(p_code text, p_last4 text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_code text := upper(regexp_replace(coalesce(p_code,''), '\s', '', 'g')); v_id text; v_tok text; v_fails int;
begin
  v_code := regexp_replace(v_code, '^MB-?', 'MB-');
  delete from app_login_fails where at < now() - interval '1 day';
  delete from applicant_sessions where expires_at < now();
  select count(*) into v_fails from app_login_fails where code = v_code and at > now() - interval '1 hour';
  if v_fails >= 5 then return jsonb_build_object('error','locked'); end if;
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

create or replace function public.app_logout(p_token text) returns jsonb
language sql security definer set search_path = public as $$
  delete from applicant_sessions where token_hash = encode(sha256(convert_to(coalesce(p_token,''), 'UTF8')), 'hex');
  select jsonb_build_object('ok', true)
$$;

-- everything the app shows: the ticket plus documents, reschedule/cancel state and updates.
-- Never returns staff notes, scores or interview / driving results.
create or replace function public.app_me(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); d jsonb; doc jsonb := '{}'::jsonb; k text; x jsonb;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  select data into d from applicants where id = v_id;
  foreach k in array array['license','nbi','medical'] loop
    x := coalesce(d->'docs'->k, '{}'::jsonb);
    doc := doc || jsonb_build_object(k, jsonb_build_object(
      'has', jsonb_array_length(coalesce(x->'photos','[]'::jsonb)) > 0 or coalesce(x->>'ref', x->>'date', x->>'number', '') <> '',
      'status', x->'status', 'older', coalesce((x->>'older')::boolean, false),
      'renew', x->'renew' is not null, 'uploadedAt', x->'uploadedAt'));
  end loop;
  return jsonb_build_object(
    'id', v_id, 'code', d->'code', 'name', d->'name', 'slot', d->'slot',
    'hubName', d->'hubName', 'location', d->'location', 'position', d->'position', 'campaignId', d->'campaignId',
    'email', regexp_replace(coalesce(d->>'email',''), '^(.{2})[^@]*', '\1***'),
    'phone4', right(regexp_replace(coalesce(d->>'phone',''), '\D', '', 'g'), 4),
    'createdAt', d->'createdAt',
    'booking', jsonb_build_object('status', d->'booking'->'status', 'note', d->'booking'->'note', 'at', d->'booking'->'at', 'auto', d->'booking'->'auto'),
    'released', coalesce(d->'released', '{}'::jsonb),
    'training', coalesce(d->'training', '{}'::jsonb),
    'checkin', jsonb_build_object('status', d->'checkin'->'status', 'at', d->'checkin'->'at'),
    'canceled', coalesce((d->>'calendlyCanceled')::boolean, false), 'canceledAt', d->'canceledAt', 'canceledBy', d->'canceledBy',
    'resched', coalesce(d->'resched', '{}'::jsonb),
    'docs', doc);
end $$;

-- is this a real interview time for the campaign? (day of week, opening hours, slot length, closed times, booking window)
create or replace function public.app_slot_ok(c jsonb, p_slot text) returns boolean
language plpgsql stable as $$
declare t timestamptz; l timestamp; m int; st int; en int; len int; win int;
begin
  begin t := p_slot::timestamptz; exception when others then return false; end;
  if to_char(t at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS".000Z"') <> p_slot then return false; end if;
  l := t at time zone 'Asia/Manila';
  if not (coalesce(c->'days','[1,2,3,4,5]'::jsonb) @> to_jsonb(extract(dow from l)::int)) then return false; end if;
  st := split_part(coalesce(c->>'start','09:00'), ':', 1)::int * 60 + split_part(coalesce(c->>'start','09:00'), ':', 2)::int;
  en := split_part(coalesce(c->>'end','16:00'), ':', 1)::int * 60 + split_part(coalesce(c->>'end','16:00'), ':', 2)::int;
  len := greatest(coalesce(nullif(c->>'len','')::int, 60), 5);
  m := extract(hour from l)::int * 60 + extract(minute from l)::int;
  if m < st or m + len > en or (m - st) % len <> 0 then return false; end if;
  if coalesce(c->'offTimes','[]'::jsonb) @> to_jsonb(to_char(l, 'HH24:MI')) then return false; end if;
  win := coalesce(nullif(c->>'window','')::int, 14);
  if t < now() + interval '1 hour' or l::date > (now() at time zone 'Asia/Manila')::date + win then return false; end if;
  if coalesce(c->>'endDate','') <> '' and to_char(l, 'YYYY-MM-DD') > c->>'endDate' then return false; end if;
  return true;
end $$;
revoke all on function public.app_slot_ok(jsonb,text) from public;

-- move the interview once, at least 12 hours before the current time
create or replace function public.app_reschedule(p_token text, p_slot text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); d jsonb; s jsonb; c jsonb; seats int; taken int; v_old text;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  select data into d from applicants where id = v_id for update;
  if coalesce((d->>'calendlyCanceled')::boolean, false) or d->'checkin'->>'status' is not null
     or coalesce(d->'booking'->>'status','') = 'declined' then return jsonb_build_object('error','notready'); end if;
  if coalesce((d->'resched'->>'count')::int, 0) >= 1 then return jsonb_build_object('error','nochange'); end if;
  v_old := d->>'slot';
  if v_old::timestamptz < now() + interval '12 hours' then return jsonb_build_object('error','toolate'); end if;
  if p_slot = v_old then return jsonb_build_object('ok', true); end if;

  select data into s from app_config where key = 'settings';
  select x into c from jsonb_array_elements(coalesce(s->'camps','[]'::jsonb)) x where x->>'id' = d->>'campaignId';
  if c is null or coalesce(c->>'active','true') = 'false' then return jsonb_build_object('error','closed'); end if;
  if not public.app_slot_ok(c, p_slot) then return jsonb_build_object('error','range'); end if;

  perform pg_advisory_xact_lock(hashtext(coalesce(d->>'campaignId','') || '|' || p_slot));
  seats := coalesce(nullif(c->>'seats','')::int, 1);
  select count(*) into taken from applicants
   where data->>'campaignId' = d->>'campaignId' and data->>'slot' = p_slot and id <> v_id
     and coalesce(data->'booking'->>'status','') <> 'declined'
     and coalesce(data->>'calendlyCanceled','false') <> 'true';
  if taken >= seats then return jsonb_build_object('error','full'); end if;

  d := jsonb_set(d, '{slot}', to_jsonb(p_slot));
  d := jsonb_set(d, '{resched}', jsonb_build_object('count', 1, 'from', v_old, 'at', now()));
  d := jsonb_set(d, '{log}', coalesce(d->'log','[]'::jsonb) || jsonb_build_array(jsonb_build_object(
         't', now(), 'by', 'applicant', 'msg', 'Applicant moved the interview from ' ||
         to_char(v_old::timestamptz at time zone 'Asia/Manila', 'Mon DD HH12:MI AM') || ' to ' ||
         to_char(p_slot::timestamptz at time zone 'Asia/Manila', 'Mon DD HH12:MI AM') || ' (applicant app)')));
  update applicants set data = d, updated_at = now() where id = v_id;
  return jsonb_build_object('ok', true);
end $$;

-- cancel the interview any time before it starts
create or replace function public.app_cancel(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); d jsonb;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  select data into d from applicants where id = v_id for update;
  if coalesce((d->>'calendlyCanceled')::boolean, false) then return jsonb_build_object('ok', true); end if;
  if d->'checkin'->>'status' is not null or (d->>'slot')::timestamptz <= now() then return jsonb_build_object('error','toolate'); end if;
  d := d || jsonb_build_object('calendlyCanceled', true, 'canceledBy', 'applicant', 'canceledAt', now());
  d := jsonb_set(d, '{log}', coalesce(d->'log','[]'::jsonb) || jsonb_build_array(jsonb_build_object(
         't', now(), 'by', 'applicant', 'msg', 'Applicant cancelled the interview (applicant app)')));
  update applicants set data = d, updated_at = now() where id = v_id;
  return jsonb_build_object('ok', true);
end $$;

-- upload the NBI clearance or medical certificate after applying.
-- Photos are uploaded to the docs bucket first; this saves the details.
-- A document staff already verified is not replaced: if it was an older one, the new one waits as "renew" for staff.
create or replace function public.app_add_doc(p_token text, p_kind text, p_doc jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_id text := public.app_session(p_token); d jsonb; cur jsonb; nd jsonb; ph jsonb;
begin
  if v_id is null then return jsonb_build_object('error','session'); end if;
  if p_kind not in ('nbi','medical') then return jsonb_build_object('error','bad'); end if;
  if length(coalesce(p_doc,'{}'::jsonb)::text) > 4000 then return jsonb_build_object('error','bad'); end if;
  select coalesce(jsonb_agg(v), '[]'::jsonb) into ph
    from jsonb_array_elements(case when jsonb_typeof(p_doc->'photos') = 'array' then p_doc->'photos' else '[]'::jsonb end) v
   where jsonb_typeof(v) = 'string' and v #>> '{}' ~ '^p[a-z0-9]{6,40}$';
  if jsonb_array_length(ph) < 1 or jsonb_array_length(ph) > 4 then return jsonb_build_object('error','nophoto'); end if;
  select data into d from applicants where id = v_id for update;
  if d->'released'->'fail' is not null or d->'released'->'accredited' is not null
     or coalesce((d->>'calendlyCanceled')::boolean, false) then return jsonb_build_object('error','notready'); end if;
  if p_kind = 'nbi' then
    nd := jsonb_build_object('ref', left(coalesce(p_doc->>'ref',''), 40),
            'expiry', case when coalesce(p_doc->>'expiry','') ~ '^\d{4}-\d{2}-\d{2}$' then p_doc->>'expiry' end);
  else
    nd := jsonb_build_object('date', case when coalesce(p_doc->>'date','') ~ '^\d{4}-\d{2}-\d{2}$' then p_doc->>'date' end,
            'clinic', left(coalesce(p_doc->>'clinic',''), 80));
  end if;
  nd := jsonb_strip_nulls(nd) || jsonb_build_object('photos', ph, 'fromApplicant', true, 'uploadedAt', now());
  cur := coalesce(d->'docs'->p_kind, '{}'::jsonb);
  if cur->>'status' = 'verified' then
    if not coalesce((cur->>'older')::boolean, false) then return jsonb_build_object('error','verified'); end if;
    d := jsonb_set(d, array['docs', p_kind, 'renew'], nd);
  else
    -- keep anything staff already noted (e.g. a hit), replace the applicant's own details
    d := jsonb_set(d, '{docs}', coalesce(d->'docs','{}'::jsonb));
    d := jsonb_set(d, array['docs', p_kind], (cur - 'status' - 'by' - 'at' - 'ref' - 'expiry' - 'date' - 'clinic' - 'photos') || nd);
  end if;
  d := jsonb_set(d, '{log}', coalesce(d->'log','[]'::jsonb) || jsonb_build_array(jsonb_build_object(
         't', now(), 'by', 'applicant', 'msg', case p_kind when 'nbi' then 'NBI clearance' else 'Medical certificate' end ||
         case when cur->>'status' = 'verified' then ' (newer copy for training)' else '' end || ' uploaded (applicant app)')));
  update applicants set data = d, updated_at = now() where id = v_id;
  return jsonb_build_object('ok', true);
end $$;

-- who may call what
revoke all on function public.app_login(text,text) from public;
revoke all on function public.app_logout(text) from public;
revoke all on function public.app_me(text) from public;
revoke all on function public.app_reschedule(text,text) from public;
revoke all on function public.app_cancel(text) from public;
revoke all on function public.app_add_doc(text,text,jsonb) from public;
grant execute on function public.app_login(text,text)          to anon, authenticated;
grant execute on function public.app_logout(text)              to anon, authenticated;
grant execute on function public.app_me(text)                  to anon, authenticated;
grant execute on function public.app_reschedule(text,text)     to anon, authenticated;
grant execute on function public.app_cancel(text)              to anon, authenticated;
grant execute on function public.app_add_doc(text,text,jsonb)  to anon, authenticated;

-- booking: a cancelled interview no longer takes a seat or counts as "already booked"
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
  v_key := public.license_key(p->'docs'->'license'->>'number');
  if v_key !~ '^[A-Z][0-9]{10}$' then return jsonb_build_object('error','nolicense'); end if;
  v_chk := public.license_check(v_key);
  if v_chk is not null then return v_chk; end if;

  select data into s from app_config where key = 'settings';
  select x into c from jsonb_array_elements(coalesce(s->'camps','[]'::jsonb)) x where x->>'id' = p->>'campaignId';
  if c is null or coalesce(c->>'active','true') = 'false' then return jsonb_build_object('error','closed'); end if;
  v_today := to_char(now() at time zone 'Asia/Manila', 'YYYY-MM-DD');
  if coalesce(c->>'startDate','') <> '' and v_today < (c->>'startDate') collate "C" then return jsonb_build_object('error','notyet'); end if;
  if coalesce(c->>'endDate','') <> '' and v_today > (c->>'endDate') collate "C" then return jsonb_build_object('error','closed'); end if;
  if (p->>'slot') is null or (p->>'slot') < to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI') then
    return jsonb_build_object('error','full'); end if;

  perform pg_advisory_xact_lock(hashtext(coalesce(p->>'campaignId','') || '|' || (p->>'slot')));
  seats := coalesce(nullif(c->>'seats','')::int, 1);
  select count(*) into taken from applicants
   where data->>'campaignId' = p->>'campaignId' and data->>'slot' = p->>'slot'
     and coalesce(data->'booking'->>'status','') <> 'declined'
     and coalesce(data->>'calendlyCanceled','false') <> 'true';
  if taken >= seats then return jsonb_build_object('error','full'); end if;

  ph := regexp_replace(coalesce(p->>'phone',''), '[\s-]', '', 'g');
  select id, data->>'slot' as slot into dup from applicants
   where regexp_replace(coalesce(data->>'phone',''), '[\s-]', '', 'g') = ph
     and data ? 'code' and (data->'checkin'->>'status') is null
     and coalesce(data->'booking'->>'status','') <> 'declined'
     and coalesce(data->>'calendlyCanceled','false') <> 'true'
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
