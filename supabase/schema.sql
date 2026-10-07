create table if not exists public.user_activity (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users (id) on delete cascade,
    user_email text not null,
    activity text not null,
    operation text not null default '',
    carrier text not null default '',
    codec text not null default '',
    cipher text not null default '',
    payload_bits bigint not null default 0,
    integrity text not null default '',
    created_at timestamptz not null default now()
);

create index if not exists user_activity_user_created_idx
    on public.user_activity (user_id, created_at desc);

create index if not exists user_activity_created_idx
    on public.user_activity (created_at desc);

alter table public.user_activity enable row level security;

revoke all on table public.user_activity from anon, authenticated;
grant all on table public.user_activity to service_role;
