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
