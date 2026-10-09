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
