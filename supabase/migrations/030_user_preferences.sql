-- Migration 030: user_preferences
-- Per-user preferences: Termaximus presence on/off, mist default position,
-- notifications enabled. Idempotent: safe to run against a database where
-- the table already exists — it will not error or alter the existing table.

create table if not exists public.user_preferences (
  user_id uuid primary key,
  termaximus_active boolean not null default true,
  mist_position text not null default 'top-right',
  notifications_enabled boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table public.user_preferences enable row level security;
