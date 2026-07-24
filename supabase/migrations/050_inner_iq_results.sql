create table if not exists public.inner_iq_results (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  taker_name text not null,
  taker_kind text not null default 'self' check (taker_kind in ('self','guest')),
  cognitive jsonb,
  personality jsonb,
  created_at timestamptz not null default now()
);

create index if not exists inner_iq_results_user_id_idx
  on public.inner_iq_results (user_id, created_at desc);

comment on table public.inner_iq_results is
  'Saved Inner I.Q Test results. One row per completed attempt. The owner user_id is always the logged-in account; taker_name and taker_kind distinguish the owner taking it as themselves from named guests (friends/family) taking it under the owner account. cognitive holds the six-faculty result; personality holds the Big Five result and is null until part two is built.';
