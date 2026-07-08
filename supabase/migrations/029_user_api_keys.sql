-- Migration 029: user_api_keys
-- Records the schema for a table already created live in Supabase for
-- BYOK (bring-your-own-key) storage of per-user provider API keys.
-- Idempotent: safe to run against a database where the table already
-- exists — it will not error or alter the existing table.

create table if not exists public.user_api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  provider text not null default 'anthropic',
  ciphertext text not null,
  iv text not null,
  auth_tag text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, provider)
);

alter table public.user_api_keys enable row level security;
