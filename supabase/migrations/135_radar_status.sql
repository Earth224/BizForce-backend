-- 135_radar_status.sql
-- APPLIED BY HAND before commit "Give the lead radar a heartbeat", and verified
-- live: the table, its 10 columns, its constraints, the updated_at trigger, RLS on
-- with no policies.
--
-- RECONSTRUCTED, NOT A VERBATIM COPY. The SQL text run by hand is not in this
-- repository. This file was written to match the live table as read back
-- (read-only, through the API's own description of public.radar_status): the 10
-- columns, their types, which are NOT NULL, the updated_at default, and the table
-- comment, all exactly as they read. The two CHECK constraints, the trigger and
-- RLS cannot be read back through that API; they are written here from the
-- migration's stated definition (source one of bluesky / mastodon / youtube;
-- last_outcome one of captured / nothing_new / backoff / login_failed /
-- no_credentials / error; updated_at maintained by trigger; RLS on, no policies).
-- Constraint and trigger NAMES below are Postgres's defaults and this repo's
-- convention, and may differ from the live ones.
--
-- WHAT IT IS FOR. "Is the lead radar running?" could only be answered from server
-- logs; a count of new bsky_leads cannot answer it, because the base rate is
-- about one lead a day. leadRadar.js now writes one row per source here: when the
-- process starts the radar (process_started_at), and at the end of every capture
-- tick with what that tick did. Only a STARTED radar writes it — never a check
-- that merely loads server.js.
--
-- Idempotent: IF NOT EXISTS on the table, the trigger dropped before it is
-- created, ENABLE ROW LEVEL SECURITY repeatable. REQUIRES 066 (public.set_updated_at).

BEGIN;

CREATE TABLE IF NOT EXISTS public.radar_status (
  source                 text        PRIMARY KEY
                                     CHECK (source IN ('bluesky', 'mastodon', 'youtube')),
  process_started_at     timestamptz,
  last_tick_started_at   timestamptz,
  last_tick_finished_at  timestamptz,
  last_outcome           text
                                     CHECK (last_outcome IN ('captured', 'nothing_new', 'backoff', 'login_failed', 'no_credentials', 'error')),
  searches               integer,
  captured               integer,
  resumes_at             timestamptz,
  last_error             text,
  updated_at             timestamptz NOT NULL DEFAULT now()
);

-- ── updated_at maintenance ──
-- public.set_updated_at() is NOT redefined here; 066 owns it.
DROP TRIGGER IF EXISTS radar_status_set_updated_at ON public.radar_status;
CREATE TRIGGER radar_status_set_updated_at
  BEFORE UPDATE ON public.radar_status
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ── access ──
-- RLS on and NO policies: only the service role (the server) reads or writes it.
ALTER TABLE public.radar_status ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public.radar_status IS
  'Heartbeat of the lead radars: one row per source, overwritten by the radar itself at process start and at the end of every tick. Proves the radar is alive without reading server logs. Written only by leadRadar.js when it runs as part of the production process; never by checks.';

COMMIT;
