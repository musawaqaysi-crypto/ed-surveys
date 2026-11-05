-- ED surveys: doctors answer through RPCs only; the admin reads everything.

create table if not exists admins (user_id uuid primary key references auth.users on delete cascade);

create table if not exists surveys (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  title_ar text default '',
  intro text default '',
  intro_ar text default '',
  ask_emp boolean not null default false,   -- collect employee number (else anonymous)
  ask_role boolean not null default true,   -- ask position + experience
  show_score boolean not null default true, -- show the doctor his score after submitting
  is_open boolean not null default false,
  questions jsonb not null default '[]',    -- [{id,type:single|multi|scale|text,section,t,t_ar,options:[{en,ar}],correct}]
  created_at timestamptz not null default now()
);

create table if not exists responses (
  id bigint generated always as identity primary key,
  survey_id uuid not null references surveys on delete cascade,
  created_at timestamptz not null default now(),
  emp_no text,
  answers jsonb not null,
  score int,
  total int
);
create unique index if not exists responses_one_per_emp on responses (survey_id, emp_no) where emp_no is not null;

alter table admins enable row level security;
alter table surveys enable row level security;
alter table responses enable row level security;

create or replace function is_admin() returns boolean language sql stable security definer set search_path = public as
$$ select exists (select 1 from admins where user_id = auth.uid()) $$;

drop policy if exists admin_self on admins;
create policy admin_self on admins for select to authenticated using (user_id = auth.uid());
drop policy if exists admin_surveys on surveys;
create policy admin_surveys on surveys for all to authenticated using (is_admin()) with check (is_admin());
drop policy if exists admin_responses on responses;
create policy admin_responses on responses for all to authenticated using (is_admin()) with check (is_admin());

-- public: an open survey without the answer key
create or replace function get_survey(p_id uuid) returns json language sql stable security definer set search_path = public as $$
  select json_build_object('id', s.id, 'title', s.title, 'title_ar', s.title_ar, 'intro', s.intro, 'intro_ar', s.intro_ar,
    'ask_emp', s.ask_emp, 'ask_role', s.ask_role,
    'questions', coalesce((select json_agg(q - 'correct' order by o) from jsonb_array_elements(s.questions) with ordinality as x(q, o)), '[]'))
  from surveys s where s.id = p_id and s.is_open
$$;

-- public: submit answers; the score is computed here from the key
create or replace function submit_response(p_id uuid, p_answers jsonb, p_emp text default null) returns json
language plpgsql security definer set search_path = public as $$
declare s surveys; q jsonb; sc int := 0; tot int := 0; emp text := nullif(trim(coalesce(p_emp, '')), '');
begin
  select * into s from surveys where id = p_id and is_open;
  if not found then raise exception 'closed'; end if;
  if length(p_answers::text) > 20000 then raise exception 'too long'; end if;
  if s.ask_emp and (emp is null or emp !~ '^[0-9]{3,12}$') then raise exception 'emp'; end if;
  if not s.ask_emp then emp := null; end if;
  if emp is not null and exists (select 1 from responses where survey_id = p_id and emp_no = emp) then raise exception 'duplicate'; end if;
  for q in select * from jsonb_array_elements(s.questions) loop
    if q ? 'correct' and jsonb_typeof(q->'correct') = 'number' then
      tot := tot + 1;
      if p_answers->(q->>'id') = q->'correct' then sc := sc + 1; end if;
    end if;
  end loop;
  insert into responses (survey_id, emp_no, answers, score, total) values (p_id, emp, p_answers, sc, tot);
  return json_build_object('score', case when s.show_score then sc end, 'total', case when s.show_score then tot end);
end $$;

revoke all on function submit_response(uuid, jsonb, text) from public;
revoke all on function get_survey(uuid) from public;
grant execute on function submit_response(uuid, jsonb, text) to anon, authenticated;
grant execute on function get_survey(uuid) to anon, authenticated;
