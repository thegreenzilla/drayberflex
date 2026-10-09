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
