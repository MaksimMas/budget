-- «Копилка» — схема базы для Supabase.
-- Как применить: Supabase → SQL Editor → New query → вставить весь файл → Run.
-- Скрипт можно запускать повторно: он ничего не удаляет.

-- ───────────────────────── Таблицы ─────────────────────────

create table if not exists public.budgets (
  id         uuid primary key default gen_random_uuid(),
  name       text not null check (char_length(name) between 1 and 80),
  currency   text not null default 'RUB' check (char_length(currency) = 3),
  owner_id   uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.budget_members (
  budget_id    uuid not null references public.budgets(id) on delete cascade,
  user_id      uuid not null references auth.users(id) on delete cascade,
  role         text not null check (role in ('owner','editor','viewer')),
  display_name text not null check (char_length(display_name) between 1 and 60),
  joined_at    timestamptz not null default now(),
  primary key (budget_id, user_id)
);

create table if not exists public.invites (
  code       text primary key,
  budget_id  uuid not null references public.budgets(id) on delete cascade,
  role       text not null check (role in ('editor','viewer')),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '7 days'
);

create table if not exists public.categories (
  id            uuid primary key default gen_random_uuid(),
  budget_id     uuid not null references public.budgets(id) on delete cascade,
  name          text not null check (char_length(name) between 1 and 60),
  kind          text not null check (kind in ('expense','income')),
  icon          text not null default '📦',
  color         smallint not null default 1 check (color between 1 and 8),
  monthly_limit numeric(14,2) check (monthly_limit is null or monthly_limit > 0),
  sort          integer not null default 0,
  archived      boolean not null default false,
  created_at    timestamptz not null default now(),
  unique (budget_id, id)
);

create table if not exists public.transactions (
  id          uuid primary key default gen_random_uuid(),
  budget_id   uuid not null references public.budgets(id) on delete cascade,
  category_id uuid,
  kind        text not null check (kind in ('expense','income')),
  amount      numeric(14,2) not null check (amount > 0),
  occurred_on date not null default current_date,
  note        text not null default '' check (char_length(note) <= 300),
  created_by  uuid default auth.uid() references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  -- категория обязана принадлежать тому же бюджету; при её удалении операция остаётся «без категории»
  foreign key (budget_id, category_id)
    references public.categories (budget_id, id) on delete set null (category_id)
);

create index if not exists transactions_budget_date on public.transactions (budget_id, occurred_on desc);
create index if not exists categories_budget on public.categories (budget_id);
create index if not exists members_user on public.budget_members (user_id);

-- ───────────────────── Вспомогательные функции ─────────────────────
-- security definer: выполняются с правами владельца и сами проверяют, кто вызывает.

create or replace function public.budget_role(p_budget uuid)
returns text language sql stable security definer set search_path = public as $$
  select role from budget_members where budget_id = p_budget and user_id = auth.uid()
$$;

create or replace function public.can_edit(p_budget uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce(budget_role(p_budget) in ('owner','editor'), false)
$$;

-- Создать бюджет: вызывающий становится владельцем.
create or replace function public.create_budget(p_name text, p_currency text, p_display_name text)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  if auth.uid() is null then raise exception 'Нужно войти в аккаунт'; end if;
  insert into budgets (name, currency, owner_id)
    values (trim(p_name), upper(p_currency), auth.uid()) returning id into v_id;
  insert into budget_members (budget_id, user_id, role, display_name)
    values (v_id, auth.uid(), 'owner', trim(p_display_name));
  return v_id;
end $$;

-- Создать приглашение (только владелец). Код действует 7 дней.
create or replace function public.create_invite(p_budget uuid, p_role text)
returns text language plpgsql security definer set search_path = public as $$
declare v_code text;
begin
  if budget_role(p_budget) is distinct from 'owner' then
    raise exception 'Приглашать участников может только владелец бюджета';
  end if;
  v_code := upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 12));
  insert into invites (code, budget_id, role, created_by) values (v_code, p_budget, p_role, auth.uid());
  return v_code;
end $$;

-- Вступить в бюджет по коду приглашения.
create or replace function public.join_budget(p_code text, p_display_name text)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_inv invites;
begin
  if auth.uid() is null then raise exception 'Нужно войти в аккаунт'; end if;
  select * into v_inv from invites where code = upper(trim(p_code)) and expires_at > now();
  if not found then raise exception 'Приглашение не найдено или его срок истёк'; end if;
  insert into budget_members (budget_id, user_id, role, display_name)
    values (v_inv.budget_id, auth.uid(), v_inv.role, trim(p_display_name))
    on conflict (budget_id, user_id) do nothing;
  return v_inv.budget_id;
end $$;

-- Сменить роль участника (только владелец; роль владельца не меняется).
create or replace function public.set_member_role(p_budget uuid, p_user uuid, p_role text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if budget_role(p_budget) is distinct from 'owner' then
    raise exception 'Менять роли может только владелец бюджета';
  end if;
  if p_role not in ('editor','viewer') then raise exception 'Неизвестная роль'; end if;
  update budget_members set role = p_role
    where budget_id = p_budget and user_id = p_user and role <> 'owner';
end $$;

-- Убрать участника (владелец) или выйти самому. Владельца убрать нельзя.
create or replace function public.remove_member(p_budget uuid, p_user uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not (budget_role(p_budget) = 'owner' or p_user = auth.uid()) then
    raise exception 'Недостаточно прав';
  end if;
  delete from budget_members
    where budget_id = p_budget and user_id = p_user and role <> 'owner';
end $$;

-- Изменить своё имя в бюджете.
create or replace function public.rename_self(p_budget uuid, p_name text)
returns void language sql security definer set search_path = public as $$
  update budget_members set display_name = trim(p_name)
    where budget_id = p_budget and user_id = auth.uid()
$$;

-- ───────────────────── Права доступа (RLS) ─────────────────────
-- Данные бюджета видят только его участники; менять могут владелец и редактор.

alter table public.budgets        enable row level security;
alter table public.budget_members enable row level security;
alter table public.invites        enable row level security;
alter table public.categories     enable row level security;
alter table public.transactions   enable row level security;

drop policy if exists budgets_select on public.budgets;
drop policy if exists budgets_update on public.budgets;
drop policy if exists budgets_delete on public.budgets;
create policy budgets_select on public.budgets for select to authenticated
  using (budget_role(id) is not null);
create policy budgets_update on public.budgets for update to authenticated
  using (budget_role(id) = 'owner') with check (budget_role(id) = 'owner' and owner_id = auth.uid());
create policy budgets_delete on public.budgets for delete to authenticated
  using (budget_role(id) = 'owner');

drop policy if exists members_select on public.budget_members;
create policy members_select on public.budget_members for select to authenticated
  using (budget_role(budget_id) is not null);

drop policy if exists invites_select on public.invites;
drop policy if exists invites_delete on public.invites;
create policy invites_select on public.invites for select to authenticated
  using (budget_role(budget_id) = 'owner');
create policy invites_delete on public.invites for delete to authenticated
  using (budget_role(budget_id) = 'owner');

drop policy if exists categories_select on public.categories;
drop policy if exists categories_insert on public.categories;
drop policy if exists categories_update on public.categories;
drop policy if exists categories_delete on public.categories;
create policy categories_select on public.categories for select to authenticated
  using (budget_role(budget_id) is not null);
create policy categories_insert on public.categories for insert to authenticated
  with check (can_edit(budget_id));
create policy categories_update on public.categories for update to authenticated
  using (can_edit(budget_id)) with check (can_edit(budget_id));
create policy categories_delete on public.categories for delete to authenticated
  using (can_edit(budget_id));

drop policy if exists transactions_select on public.transactions;
drop policy if exists transactions_insert on public.transactions;
drop policy if exists transactions_update on public.transactions;
drop policy if exists transactions_delete on public.transactions;
create policy transactions_select on public.transactions for select to authenticated
  using (budget_role(budget_id) is not null);
create policy transactions_insert on public.transactions for insert to authenticated
  with check (can_edit(budget_id) and created_by = auth.uid());
create policy transactions_update on public.transactions for update to authenticated
  using (can_edit(budget_id)) with check (can_edit(budget_id));
create policy transactions_delete on public.transactions for delete to authenticated
  using (can_edit(budget_id));

-- ───────────────────── Доступ через API ─────────────────────
-- Гостям (anon) не даём ничего; вошедшим — только то, что нужно сайту.

revoke all on public.budgets, public.budget_members, public.invites,
              public.categories, public.transactions from anon;
grant select, update, delete on public.budgets to authenticated;
grant select on public.budget_members to authenticated;
grant select, delete on public.invites to authenticated;
grant select, insert, update, delete on public.categories, public.transactions to authenticated;

revoke execute on function
  public.budget_role(uuid), public.can_edit(uuid),
  public.create_budget(text, text, text), public.create_invite(uuid, text),
  public.join_budget(text, text), public.set_member_role(uuid, uuid, text),
  public.remove_member(uuid, uuid), public.rename_self(uuid, text)
from public, anon;
grant execute on function
  public.budget_role(uuid), public.can_edit(uuid),
  public.create_budget(text, text, text), public.create_invite(uuid, text),
  public.join_budget(text, text), public.set_member_role(uuid, uuid, text),
  public.remove_member(uuid, uuid), public.rename_self(uuid, text)
to authenticated;

-- ═══════════════ Уведомления банка с телефона («Входящие») ═══════════════
-- Телефон присылает текст уведомления по личному токену; сайт показывает его
-- во «Входящих» только тому, чей это телефон.

create table if not exists public.inbox_tokens (
  token      text primary key,
  budget_id  uuid not null references public.budgets(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (budget_id, user_id)
);

create table if not exists public.inbox (
  id          uuid primary key default gen_random_uuid(),
  budget_id   uuid not null references public.budgets(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  title       text not null default '',
  body        text not null,
  received_at timestamptz not null default now(),
  status      text not null default 'new' check (status in ('new','done','skipped'))
);
create index if not exists inbox_owner on public.inbox (budget_id, user_id, status, received_at desc);

-- Запомненные соответствия «магазин → категория», общие для бюджета.
create table if not exists public.category_rules (
  budget_id   uuid not null references public.budgets(id) on delete cascade,
  pattern     text not null check (char_length(pattern) between 1 and 80),
  category_id uuid not null,
  primary key (budget_id, pattern),
  foreign key (budget_id, category_id) references public.categories (budget_id, id) on delete cascade
);

-- Получить свой токен для телефона (p_reset = true выдаёт новый, старый перестаёт работать).
create or replace function public.inbox_token(p_budget uuid, p_reset boolean default false)
returns text language plpgsql security definer set search_path = public as $$
declare v text;
begin
  if not can_edit(p_budget) then raise exception 'Недостаточно прав'; end if;
  if p_reset then delete from inbox_tokens where budget_id = p_budget and user_id = auth.uid(); end if;
  select token into v from inbox_tokens where budget_id = p_budget and user_id = auth.uid();
  if v is null then
    v := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
    insert into inbox_tokens (token, budget_id, user_id) values (v, p_budget, auth.uid());
  end if;
  return v;
end $$;

-- Общая часть приёма: проверка токена, защита от повторов и переполнения.
create or replace function public._inbox_store(p_token text, p_title text, p_body text)
returns void language plpgsql security definer set search_path = public as $$
declare t inbox_tokens; v_body text := left(trim(coalesce(p_body, '')), 1000);
begin
  select * into t from inbox_tokens where token = trim(p_token);
  if not found then raise exception 'Неверный токен'; end if;
  if not exists (select 1 from budget_members where budget_id = t.budget_id and user_id = t.user_id and role in ('owner','editor')) then
    raise exception 'Нет доступа к бюджету';
  end if;
  if v_body = '' then return; end if;
  if exists (select 1 from inbox where budget_id = t.budget_id and user_id = t.user_id
             and body = v_body and received_at > now() - interval '1 minute') then return; end if;
  if (select count(*) from inbox where budget_id = t.budget_id and user_id = t.user_id and status = 'new') >= 300 then return; end if;
  insert into inbox (budget_id, user_id, title, body)
    values (t.budget_id, t.user_id, left(trim(coalesce(p_title, '')), 200), v_body);
end $$;

-- Вариант 1 (основной): тело запроса — простой текст. Первая строка — токен, дальше текст уведомления.
create or replace function public.ingest_raw(text)
returns void language plpgsql security definer set search_path = public as $$
declare v text := replace($1, E'\r', ''); p int := position(E'\n' in v);
begin
  if p = 0 then return; end if;
  perform _inbox_store(substr(v, 1, p - 1), '', substr(v, p + 1));
end $$;

-- Вариант 2: JSON {"p_token": "...", "p_title": "...", "p_body": "..."}.
create or replace function public.ingest(p_token text, p_title text, p_body text)
returns void language sql security definer set search_path = public as $$
  select _inbox_store(p_token, p_title, p_body)
$$;

alter table public.inbox_tokens   enable row level security;   -- без политик: только через функции
alter table public.inbox          enable row level security;
alter table public.category_rules enable row level security;

drop policy if exists inbox_select on public.inbox;
drop policy if exists inbox_update on public.inbox;
drop policy if exists inbox_delete on public.inbox;
create policy inbox_select on public.inbox for select to authenticated
  using (user_id = auth.uid() and can_edit(budget_id));
create policy inbox_update on public.inbox for update to authenticated
  using (user_id = auth.uid() and can_edit(budget_id)) with check (user_id = auth.uid() and can_edit(budget_id));
create policy inbox_delete on public.inbox for delete to authenticated
  using (user_id = auth.uid());

drop policy if exists rules_select on public.category_rules;
drop policy if exists rules_insert on public.category_rules;
drop policy if exists rules_update on public.category_rules;
drop policy if exists rules_delete on public.category_rules;
create policy rules_select on public.category_rules for select to authenticated using (budget_role(budget_id) is not null);
create policy rules_insert on public.category_rules for insert to authenticated with check (can_edit(budget_id));
create policy rules_update on public.category_rules for update to authenticated using (can_edit(budget_id)) with check (can_edit(budget_id));
create policy rules_delete on public.category_rules for delete to authenticated using (can_edit(budget_id));

revoke all on public.inbox_tokens, public.inbox, public.category_rules from anon, authenticated;
grant select, delete on public.inbox to authenticated;
grant update (status) on public.inbox to authenticated;
grant select, insert, update, delete on public.category_rules to authenticated;

revoke execute on function public.inbox_token(uuid, boolean), public._inbox_store(text, text, text),
  public.ingest_raw(text), public.ingest(text, text, text) from public, anon, authenticated;
grant execute on function public.inbox_token(uuid, boolean) to authenticated;
-- Телефон не входит в аккаунт, поэтому приём открыт гостям; защита — токен.
grant execute on function public.ingest_raw(text), public.ingest(text, text, text) to anon, authenticated;
