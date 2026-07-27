-- Phase 3 approval gate: agents propose actions here and a human must approve them before execution.

create table if not exists public.agent_proposals (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  agent_type text not null,
  action_type text not null,
  title text not null,
  target text,
  payload jsonb not null default '{}'::jsonb,
  cost_amount numeric(12,2) not null default 0,
  cost_currency text not null default 'USD',
  reversible boolean not null default false,
  reasoning text,
  status text not null default 'pending',
  created_at timestamptz not null default now(),
  decided_at timestamptz,
  executed_at timestamptz,
  execution_result jsonb,
  execution_error text,
  constraint agent_proposals_status_check check (status in ('pending','approved','rejected','executing','executed','failed'))
);

alter table public.agent_proposals enable row level security;

create index if not exists agent_proposals_user_status_idx
  on public.agent_proposals (user_id, status, created_at desc);
