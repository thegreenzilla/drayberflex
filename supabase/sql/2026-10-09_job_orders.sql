-- =====================================================================
-- DrayberFlex – update: Job orders (Operations role)
-- Lets the app store job orders in their own app_config row ("jobs").
-- Only signed-in staff can read it: the public pages only read 'settings'.
-- Run once in Supabase → SQL Editor → New query → Run. Safe to re-run.
-- =====================================================================
alter table public.app_config drop constraint if exists app_config_key_check;
alter table public.app_config add constraint app_config_key_check check (key in ('settings','bank','jobs'));
insert into public.app_config(key) values ('jobs') on conflict do nothing;
