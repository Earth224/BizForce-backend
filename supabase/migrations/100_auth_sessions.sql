-- CHANGES the database. Server-side session state - the first this system has had.
-- Until now the JWT was the entire session: 7 days, not refreshable, and
-- logout was a literal no-op, so a stolen token could not be cancelled and
-- every user was signed out weekly with no way back but the password.
-- refresh_token_hash stores a HASH, never the token. Every refresh rotates,
-- and presenting an already-revoked token is treated as theft rather than as
-- a mistake - it revokes every session for that user.
-- The paired CHECK on revoked_at and revoked_reason exists so a revoked row
-- can always say why. A revocation with no reason is unauditable.
-- Already applied to the live database on 2026-09-08.

create table if not exists public.auth_sessions (
  id                  uuid        primary key default gen_random_uuid(),
  user_id             uuid        not null references public.users(id) on delete cascade,
  refresh_token_hash  text        not null,
  issued_at           timestamptz not null default now(),
  expires_at          timestamptz not null,
  last_used_at        timestamptz,
  revoked_at          timestamptz,
  revoked_reason      text,
  user_agent          text,
  ip                  text,
  constraint auth_sessions_expiry_after_issue check (expires_at > issued_at),
  constraint auth_sessions_revoked_reason_agrees
    check ((revoked_at is null and revoked_reason is null)
        or (revoked_at is not null and revoked_reason is not null))
);

create unique index if not exists auth_sessions_refresh_token_hash_key
  on public.auth_sessions (refresh_token_hash);

create index if not exists auth_sessions_user_active_idx
  on public.auth_sessions (user_id, expires_at desc)
  where revoked_at is null;

alter table public.auth_sessions enable row level security;
