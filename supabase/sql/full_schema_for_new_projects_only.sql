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


-- =====================================================================
-- DrayberFlex – update: test checklists on the What's new page
-- Stores the Pass / Fail / Skip result and note for each test, so everyone
-- testing sees the same results. Only signed-in staff can read or write them.
-- Meant for the TEST project; harmless on live (the live site doesn't show tests).
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================
create table if not exists public.test_results (
  id         text primary key,
  status     text not null default '' check (status in ('', 'pass', 'fail', 'skip')),
  note       text not null default '' check (length(note) <= 2000),
  by         uuid,
  by_name    text not null default '',
  at         timestamptz not null default now()
);
alter table public.test_results enable row level security;
drop policy if exists tr_sel on public.test_results;
drop policy if exists tr_ins on public.test_results;
drop policy if exists tr_upd on public.test_results;
create policy tr_sel on public.test_results for select to authenticated using (public.is_staff());
create policy tr_ins on public.test_results for insert to authenticated with check (public.is_staff());
create policy tr_upd on public.test_results for update to authenticated using (public.is_staff());
grant select, insert, update on public.test_results to authenticated;


-- =====================================================================
-- DrayberFlex – update: Hiring report, Unfinished applications, No-shows
--  * apply_events: which step of the online application each visit reached
--    (step numbers only, no names). Used by the Hiring report.
--  * apply_leads: name + mobile of people who agreed to be contacted on the
--    license step, so Marketing can call them if they stop before booking.
--    Deleted by themselves after 360 days.
-- The public page writes only through the two functions below.
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================

-- ---------- application steps (anonymous) ----------
create table if not exists public.apply_events (
  id        bigserial primary key,
  at        timestamptz not null default now(),
  visit     text not null check (length(visit) between 4 and 60),
  campaign  text not null check (length(campaign) <= 80),
  step      smallint not null check (step between 1 and 6),
  source    text not null default 'link' check (source in ('link', 'walkin')),
  note      text check (note in ('active', 'wait', 'blocked')),
  unique nulls not distinct (visit, step, note)
);
create index if not exists apply_events_at on public.apply_events (at);
alter table public.apply_events enable row level security;
revoke all on public.apply_events from anon, authenticated;
grant select on public.apply_events to authenticated;
drop policy if exists ae_sel on public.apply_events;
create policy ae_sel on public.apply_events for select to authenticated using (public.is_staff());

create or replace function public.track_apply_step(p_campaign text, p_visit text, p_step int, p_source text, p_note text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if p_step is null or p_step < 1 or p_step > 6 or coalesce(length(p_visit), 0) not between 4 and 60
     or coalesce(length(p_campaign), 0) not between 1 and 80 then return; end if;
  insert into apply_events (visit, campaign, step, source, note)
  values (p_visit, p_campaign, p_step,
          case when p_source = 'walkin' then 'walkin' else 'link' end,
          case when p_note in ('active', 'wait', 'blocked') then p_note end)
  on conflict do nothing;
end $$;
revoke all on function public.track_apply_step(text, text, int, text, text) from public;
grant execute on function public.track_apply_step(text, text, int, text, text) to anon, authenticated;

-- ---------- unfinished applications (only with the applicant's OK) ----------
create table if not exists public.apply_leads (
  visit       text primary key check (length(visit) between 4 and 60),
  campaign    text not null check (length(campaign) <= 80),
  name        text not null default '' check (length(name) <= 120),
  mobile      text not null check (length(mobile) between 7 and 20),
  step        smallint not null default 3 check (step between 1 and 6),
  status      text not null default 'new' check (status in ('new', 'will', 'noans', 'no', 'wrong', '')),
  note        text not null default '' check (length(note) <= 500),
  tries       int not null default 0,
  texted      timestamptz,
  called_at   timestamptz,
  called_by   uuid,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists apply_leads_created on public.apply_leads (created_at);
alter table public.apply_leads enable row level security;
revoke all on public.apply_leads from anon, authenticated;
grant select, update on public.apply_leads to authenticated;
drop policy if exists al_sel on public.apply_leads;
drop policy if exists al_upd on public.apply_leads;
create policy al_sel on public.apply_leads for select to authenticated using (public.has_role('marketing'));
create policy al_upd on public.apply_leads for update to authenticated using (public.has_role('marketing'));

create or replace function public.save_apply_lead(p_visit text, p_campaign text, p_name text, p_mobile text, p_step int)
returns void language plpgsql security definer set search_path = public as $$
declare m text := regexp_replace(coalesce(p_mobile, ''), '[^0-9+]', '', 'g');
begin
  if coalesce(length(p_visit), 0) not between 4 and 60 or coalesce(length(p_campaign), 0) not between 1 and 80
     or m !~ '^(\+?63|0)9[0-9]{9}$' then return; end if;
  insert into apply_leads (visit, campaign, name, mobile, step)
  values (p_visit, p_campaign, left(coalesce(trim(p_name), ''), 120), left(trim(p_mobile), 20), greatest(1, least(6, coalesce(p_step, 3))))
  on conflict (visit) do update set
    name = excluded.name, mobile = excluded.mobile, campaign = excluded.campaign,
    step = greatest(apply_leads.step, excluded.step), updated_at = now();
  -- keep them 360 days only
  delete from apply_leads where created_at < now() - interval '360 days';
end $$;
revoke all on function public.save_apply_lead(text, text, text, text, int) from public;
grant execute on function public.save_apply_lead(text, text, text, text, int) to anon, authenticated;


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
