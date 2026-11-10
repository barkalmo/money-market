-- Run once if you already ran schema.sql from the first version.

-- Assisted access: superadmin may open a client's portal read-only; acting for the client needs the client's acceptance.
create table if not exists assist_grants (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id), requested_by uuid not null references users(id),
  status text not null default 'pending' check (status in ('pending','accepted','declined','revoked')),
  requested_at timestamptz not null default now(), decided_at timestamptz, expires_at timestamptz
);
alter table assist_grants enable row level security;
create index if not exists assist_user_idx on assist_grants(user_id, requested_at desc);
-- Editable page content (superadmin "Site content")
insert into settings(key,value) values ('content','{}') on conflict (key) do nothing;
