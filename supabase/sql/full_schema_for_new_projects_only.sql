-- =====================================================================
-- DrayberFlex – Supabase schema (run once in SQL Editor → New query → Run)
-- Safe to re-run.
-- =====================================================================

-- ---------- tables ----------
create table if not exists public.profiles (
  id          uuid primary key references auth.users on delete cascade,
  name        text not null default '',
  email       text not null default '',
  roles       text[] not null default '{}',
  active      boolean not null default false,
  pending     boolean not null default true,
  must_change boolean not null default false,
  last_login  timestamptz,
  approved_by uuid,
  approved_at timestamptz,
  created_at  timestamptz not null default now()
);

create table if not exists public.applicants (
  id          text primary key,
  code        text unique,
  data        jsonb not null,
  notified_at timestamptz,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists applicants_campaign_slot on public.applicants ((data->>'campaignId'), (data->>'slot'));

-- settings (campaigns, rules) and bank (interview question bank)
create table if not exists public.app_config (
  key        text primary key check (key in ('settings','bank','jobs')),
  data       jsonb not null default '{}',
  updated_at timestamptz not null default now()
);
insert into public.app_config(key) values ('settings'),('bank'),('jobs') on conflict do nothing;

-- ---------- role helpers ----------
create or replace function public.is_staff() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from profiles where id = auth.uid() and active and not pending)
$$;

create or replace function public.has_role(r text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from profiles where id = auth.uid() and active and not pending
                and (r = any(roles) or 'admin' = any(roles)))
$$;

-- ---------- new auth user -> profile (first user becomes Admin) ----------
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare first_user boolean;
begin
  perform pg_advisory_xact_lock(4242);
  select not exists(select 1 from profiles) into first_user;
  insert into profiles(id, name, email, roles, active, pending)
  values (new.id,
          coalesce(new.raw_user_meta_data->>'name', ''),
          lower(new.email),
          case when first_user then array['admin'] else '{}'::text[] end,
          first_user, not first_user);
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- non-admins can't change their own roles/status
create or replace function public.profiles_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or public.has_role('admin') then return new; end if;
  if new.roles is distinct from old.roles or new.active is distinct from old.active
     or new.pending is distinct from old.pending or new.email is distinct from old.email
     or new.approved_by is distinct from old.approved_by then
    raise exception 'Only an Admin can change roles or account status';
  end if;
  return new;
end $$;
drop trigger if exists profiles_guard on public.profiles;
create trigger profiles_guard before update on public.profiles
  for each row execute function public.profiles_guard();

-- ---------- Row Level Security ----------
alter table public.profiles   enable row level security;
alter table public.applicants enable row level security;
alter table public.app_config enable row level security;

drop policy if exists p_sel on public.profiles;
drop policy if exists p_upd on public.profiles;
drop policy if exists p_del on public.profiles;
create policy p_sel on public.profiles for select to authenticated using (public.is_staff() or id = auth.uid());
create policy p_upd on public.profiles for update to authenticated using (id = auth.uid() or public.has_role('admin'));
create policy p_del on public.profiles for delete to authenticated using (public.has_role('admin'));

drop policy if exists a_sel on public.applicants;
drop policy if exists a_ins on public.applicants;
drop policy if exists a_upd on public.applicants;
drop policy if exists a_del on public.applicants;
create policy a_sel on public.applicants for select to authenticated using (public.is_staff());
create policy a_ins on public.applicants for insert to authenticated with check (public.is_staff());
create policy a_upd on public.applicants for update to authenticated using (public.is_staff());
create policy a_del on public.applicants for delete to authenticated using (public.has_role('admin'));
-- applicants (anon) never touch this table directly: they use submit_application / get_ticket below

drop policy if exists c_sel on public.app_config;
drop policy if exists c_ins on public.app_config;
drop policy if exists c_upd on public.app_config;
create policy c_sel on public.app_config for select to anon, authenticated using (key = 'settings' or public.is_staff());
create policy c_ins on public.app_config for insert to authenticated with check (public.is_staff());
create policy c_upd on public.app_config for update to authenticated using (public.is_staff());

-- ---------- public booking API (anon) ----------
-- seats already taken, per campaign + slot (no personal data)
create or replace function public.slot_counts()
returns table(campaign text, slot text, n int)
language sql stable security definer set search_path = public as $$
  select data->>'campaignId', data->>'slot', count(*)::int
  from applicants
  where data->>'slot' >= to_char(now() at time zone 'utc', 'YYYY-MM-DD')
    and coalesce(data->'booking'->>'status','') <> 'declined'
    and coalesce(data->>'calendlyCanceled','false') in ('false','','0','null')
  group by 1, 2
$$;

-- applicant status page: only what the ticket shows
create or replace function public.get_ticket(p_id text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'id', id, 'code', data->'code', 'name', data->'name', 'slot', data->'slot',
    'hubName', data->'hubName', 'location', data->'location', 'position', data->'position',
    'email', regexp_replace(coalesce(data->>'email',''), '^(.{2})[^@]*', '\1***'),
    'booking', jsonb_build_object('status', data->'booking'->'status', 'note', data->'booking'->'note'))
  from applicants where id = p_id
$$;

-- submit a booking: checks campaign, seats, duplicate phone; strips staff-only fields
create or replace function public.submit_application(p jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  s jsonb; c jsonb; seats int; taken int; v_id text; v_code text; ph text; dup record;
begin
  if length(p::text) > 60000 then raise exception 'payload too large'; end if;
  v_id := p->>'id';
  if v_id is null or v_id !~ '^a[a-z0-9]{6,40}$' then raise exception 'bad id'; end if;
  if exists(select 1 from applicants where id = v_id) then raise exception 'exists'; end if;
  if jsonb_array_length(coalesce(p->'docs'->'license'->'photos','[]'::jsonb)) < 1 then return jsonb_build_object('error','nophoto'); end if;

  select data into s from app_config where key = 'settings';
  select x into c from jsonb_array_elements(coalesce(s->'camps','[]'::jsonb)) x where x->>'id' = p->>'campaignId';
  if c is null or coalesce(c->>'active','true') = 'false' then return jsonb_build_object('error','closed'); end if;
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
  if found then return jsonb_build_object('error','dup','id',dup.id,'slot',dup.slot); end if;

  select jsonb_object_agg(k, v) into p from jsonb_each(p) e(k, v)
   where k = any(array['id','code','name','phone','email','slot','campaign','campaignId','position','hubName',
                       'location','refCode','application','booking','docs','createdAt','updatedAt','log']);
  p := p || jsonb_build_object('source','campaign');

  v_code := p->>'code';
  while v_code is null or v_code !~ '^MB-[A-Z0-9]{6}$' or exists(select 1 from applicants where code = v_code) loop
    v_code := 'MB-' || upper(substr(md5(random()::text), 1, 6));
  end loop;
  p := jsonb_set(p, '{code}', to_jsonb(v_code));

  insert into applicants(id, code, data) values (v_id, v_code, p);
  return jsonb_build_object('ok', true, 'id', v_id, 'code', v_code);
end $$;

revoke all on function public.submit_application(jsonb) from public;
grant execute on function public.slot_counts()              to anon, authenticated;
grant execute on function public.get_ticket(text)           to anon, authenticated;
grant execute on function public.submit_application(jsonb)  to anon, authenticated;

-- ---------- document photos: private bucket ----------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('docs', 'docs', false, 5242880, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

drop policy if exists "docs upload" on storage.objects;
drop policy if exists "docs staff read" on storage.objects;
drop policy if exists "docs staff delete" on storage.objects;
create policy "docs upload"       on storage.objects for insert to anon, authenticated with check (bucket_id = 'docs');
create policy "docs staff read"   on storage.objects for select to authenticated using (bucket_id = 'docs' and public.is_staff());
create policy "docs staff delete" on storage.objects for delete to authenticated using (bucket_id = 'docs' and public.is_staff());

-- ---------- live updates (check-in tablet etc.) ----------
do $$ begin
  begin alter publication supabase_realtime add table public.applicants; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.app_config; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.profiles;   exception when duplicate_object then null; end;
end $$;
-- =====================================================================
-- DrayberFlex – update: results on the applicant's phone + training booking
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================

-- applicant status page: now also returns released results and training booking
create or replace function public.get_ticket(p_id text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'id', id, 'code', data->'code', 'name', data->'name', 'slot', data->'slot',
    'hubName', data->'hubName', 'location', data->'location', 'position', data->'position',
    'campaignId', data->'campaignId',
    'email', regexp_replace(coalesce(data->>'email',''), '^(.{2})[^@]*', '\1***'),
    'booking', jsonb_build_object('status', data->'booking'->'status', 'note', data->'booking'->'note'),
    'released', coalesce(data->'released', '{}'::jsonb),
    'training', coalesce(data->'training', '{}'::jsonb))
  from applicants where id = p_id
$$;

-- seats already taken per training day, all campaigns (no personal data)
create or replace function public.training_counts()
returns table(campaign text, day text, n int)
language sql stable security definer set search_path = public as $$
  select ''::text, data->'training'->>'slot', count(*)::int
  from applicants
  where data->'training'->>'slot' >= to_char((now() at time zone 'Asia/Manila')::date, 'YYYY-MM-DD')
    and data->'released'->'fail' is null
  group by 2
$$;

-- applicant accepts or declines the training invite (only after Check-in gave the "passed" result; once)
create or replace function public.training_respond(p_id text, p_resp text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare a jsonb;
begin
  if p_resp not in ('accepted','declined') then return jsonb_build_object('error','bad'); end if;
  select data into a from applicants where id = p_id for update;
  if a is null or a->'released'->'pass' is null or a->'released'->'fail' is not null then return jsonb_build_object('error','notready'); end if;
  if a->'training'->>'response' is not null then return jsonb_build_object('error','already'); end if;
  update applicants
     set data = jsonb_set(data, '{training}', coalesce(data->'training','{}'::jsonb) || jsonb_build_object('response', p_resp, 'respondedAt', now())),
         updated_at = now()
   where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

-- applicant books (or changes once, up to the day before) their training day
-- schedule = settings.training (set by the trainer in Training calendar); day overrides can close a day or set its seats
create or replace function public.book_training(p_id text, p_day text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  a jsonb; s jsonb; c jsonb; tr jsonb; ov jsonb; t jsonb; d date; cur text; ch int; seats int; taken int; win int;
  today date := (now() at time zone 'Asia/Manila')::date;
begin
  select data into a from applicants where id = p_id for update;
  if a is null then return jsonb_build_object('error','notready'); end if;
  if a->'released'->'pass' is null or a->'released'->'fail' is not null then return jsonb_build_object('error','notready'); end if;
  t := coalesce(a->'training','{}'::jsonb);
  if t->>'response' is distinct from 'accepted' then return jsonb_build_object('error','notready'); end if;
  begin d := p_day::date; exception when others then return jsonb_build_object('error','range'); end;

  select data into s from app_config where key = 'settings';
  select x into c from jsonb_array_elements(coalesce(s->'camps','[]'::jsonb)) x where x->>'id' = a->>'campaignId';
  tr := coalesce(c->'train','{}'::jsonb) || coalesce(s->'training','{}'::jsonb);
  ov := coalesce(tr->'overrides'->p_day, '{}'::jsonb);
  if coalesce((ov->>'closed')::boolean, false) then return jsonb_build_object('error','closedday'); end if;
  if nullif(ov->>'seats','') is not null then
    seats := (ov->>'seats')::int;
  elsif coalesce(tr->'days','[1,2,3,4,5,6]'::jsonb) @> to_jsonb(extract(dow from d)::int) then
    seats := coalesce(nullif(tr->>'seats','')::int, 10);
  else
    seats := 0;
  end if;
  if seats <= 0 then return jsonb_build_object('error','closedday'); end if;
  win := coalesce(nullif(tr->>'window','')::int, 14);
  if d <= today or d > today + win then return jsonb_build_object('error','range'); end if;

  cur := t->>'slot'; ch := coalesce((t->>'changes')::int, 0);
  if cur is not null then
    if cur = p_day then return jsonb_build_object('ok', true); end if;
    if ch >= 1 then return jsonb_build_object('error','nochange'); end if;
    if cur::date <= today then return jsonb_build_object('error','toolate'); end if;
  end if;

  perform pg_advisory_xact_lock(hashtext('train|' || p_day));
  select count(*) into taken from applicants
   where data->'training'->>'slot' = p_day and id <> p_id and data->'released'->'fail' is null;
  if taken >= seats then return jsonb_build_object('error','full'); end if;

  t := t || jsonb_build_object('slot', p_day, 'bookedAt', now(), 'changes', case when cur is null then 0 else ch + 1 end);
  update applicants set data = jsonb_set(data, '{training}', t), updated_at = now() where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

revoke all on function public.training_respond(text,text) from public;
revoke all on function public.book_training(text,text) from public;
grant execute on function public.get_ticket(text)               to anon, authenticated;
grant execute on function public.training_counts()              to anon, authenticated;
grant execute on function public.training_respond(text,text)    to anon, authenticated;
grant execute on function public.book_training(text,text)       to anon, authenticated;

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
-- DrayberFlex update: (1) allow PDF attachments up to 10 MB, (2) online applications must include a driver's license photo.
-- Run once in Supabase → SQL Editor. Safe to re-run.
update storage.buckets
   set allowed_mime_types = array['image/jpeg','image/png','image/webp','application/pdf'],
       file_size_limit    = 10485760
 where id = 'docs';

create or replace function public.submit_application(p jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  s jsonb; c jsonb; seats int; taken int; v_id text; v_code text; ph text; dup record;
begin
  if length(p::text) > 60000 then raise exception 'payload too large'; end if;
  v_id := p->>'id';
  if v_id is null or v_id !~ '^a[a-z0-9]{6,40}$' then raise exception 'bad id'; end if;
  if exists(select 1 from applicants where id = v_id) then raise exception 'exists'; end if;
  if jsonb_array_length(coalesce(p->'docs'->'license'->'photos','[]'::jsonb)) < 1 then return jsonb_build_object('error','nophoto'); end if;

  select data into s from app_config where key = 'settings';
  select x into c from jsonb_array_elements(coalesce(s->'camps','[]'::jsonb)) x where x->>'id' = p->>'campaignId';
  if c is null or coalesce(c->>'active','true') = 'false' then return jsonb_build_object('error','closed'); end if;
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
  if found then return jsonb_build_object('error','dup','id',dup.id,'slot',dup.slot); end if;

  select jsonb_object_agg(k, v) into p from jsonb_each(p) e(k, v)
   where k = any(array['id','code','name','phone','email','slot','campaign','campaignId','position','hubName',
                       'location','refCode','application','booking','docs','createdAt','updatedAt','log']);
  p := p || jsonb_build_object('source','campaign');

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

-- =====================================================================
-- DrayberFlex – update: campaign start and end dates are enforced by the database
-- Applications are refused before a campaign's start date or after its last day
-- (Philippine time), even if nobody has signed in to close the campaign.
-- Everything else in submit_application is unchanged.
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================
create or replace function public.submit_application(p jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  s jsonb; c jsonb; seats int; taken int; v_id text; v_code text; ph text; dup record; v_today text;
begin
  if length(p::text) > 60000 then raise exception 'payload too large'; end if;
  v_id := p->>'id';
  if v_id is null or v_id !~ '^a[a-z0-9]{6,40}$' then raise exception 'bad id'; end if;
  if exists(select 1 from applicants where id = v_id) then raise exception 'exists'; end if;
  if jsonb_array_length(coalesce(p->'docs'->'license'->'photos','[]'::jsonb)) < 1 then return jsonb_build_object('error','nophoto'); end if;

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
  if found then return jsonb_build_object('error','dup','id',dup.id,'slot',dup.slot); end if;

  select jsonb_object_agg(k, v) into p from jsonb_each(p) e(k, v)
   where k = any(array['id','code','name','phone','email','slot','campaign','campaignId','position','hubName',
                       'location','refCode','application','booking','docs','createdAt','updatedAt','log']);
  p := p || jsonb_build_object('source','campaign');

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

-- =====================================================================
-- Table permissions (explicit, so a new project works even if "Automatically expose new tables"
-- was switched off). Row level security above still decides which rows each person can see.
-- =====================================================================
grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on public.applicants, public.app_config, public.profiles to authenticated;
grant select on public.app_config to anon;


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
