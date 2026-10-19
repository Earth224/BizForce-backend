-- 138_youtube_api_calls.sql
--
-- THE YOUTUBE API UNIT LEDGER. One row per YouTube Data API call, written
-- BEFORE the request is sent (lib/youtubeQuota.js reserveYoutubeUnits), so a
-- call that fails, times out or is never answered still counts against the
-- day. Today's spend is the sum of units over today's rows (created_on, a UTC
-- date), across every caller: the whole API key, per UTC day, which is how
-- Google meters the project's quota.
--
-- FAIL CLOSED. Until this table exists, every YouTube call is refused: the
-- reservation insert fails, and no request is made without one.
--
-- caller names who spent the units: 'radar' (youtubeRadar.js) or
-- 'social_search' (reserved; Social Search makes no YouTube call today).
-- user_id is the account a call was made for, when there is one; the radar
-- has none.
--
-- Applied by hand in the Supabase SQL editor. Re-runnable.

create table if not exists public.youtube_api_calls (
  id          bigserial   primary key,
  created_on  date        not null default (now() at time zone 'utc')::date,
  caller      text        not null check (caller in ('radar', 'social_search')),
  user_id     uuid        null,
  units       int         not null check (units > 0),
  created_at  timestamptz not null default now()
);

create index if not exists youtube_api_calls_created_on_idx
  on public.youtube_api_calls (created_on);

-- The same posture as bsky_leads and job_runs: row level security on, no
-- policies, so only the service key (the server) can read or write it.
alter table public.youtube_api_calls enable row level security;

comment on table public.youtube_api_calls is
  'One row per YouTube Data API call, reserved before the request is sent. Today''s spend is sum(units) where created_on = the UTC date. Read against YOUTUBE_DAILY_UNIT_CAP (all callers) and YOUTUBE_RADAR_DAILY_UNITS (caller radar).';
