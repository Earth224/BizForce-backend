-- CHANGES the database. Creates self_reviews.
-- Storage for weekly and monthly self-review cycles.
-- metrics is written before the model is called, so a failed narrative
-- still leaves the numbers on disk - which is what makes a review usable
-- as a reconciliation surface for revenue_events, a table nothing reads.
-- The unique index is FULL, not partial, so ON CONFLICT is usable here,
-- unlike revenue_events_stripe_event_id_key.
-- RLS is enabled with no policies: the backend uses the service role and
-- bypasses RLS, so no policy is intended and none is missing.
-- Already applied to the live database on 2026-09-06.

create table if not exists public.self_reviews (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null,
  period_type   text not null check (period_type in ('weekly', 'monthly')),
  period_start  timestamptz not null,
  period_end    timestamptz not null,
  metrics       jsonb not null,
  unreadable    text[] not null default '{}',
  narrative     text,
  model         text,
  created_at    timestamptz not null default now()
);

create unique index if not exists self_reviews_user_period_key
  on public.self_reviews (user_id, period_type, period_start);

create index if not exists self_reviews_user_recent_idx
  on public.self_reviews (user_id, created_at desc);

alter table public.self_reviews enable row level security;

comment on column public.self_reviews.metrics is
  'Aggregate counts for the period. Written before the model is called, so a failed narrative still leaves the numbers.';
comment on column public.self_reviews.unreadable is
  'Metric keys that could not be read for this period. A key listed here is unknown, NOT zero.';
comment on column public.self_reviews.narrative is
  'Model-written summary. NULL means the model call failed or has not run; the metrics are still valid.';
