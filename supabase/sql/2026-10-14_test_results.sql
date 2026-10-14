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
