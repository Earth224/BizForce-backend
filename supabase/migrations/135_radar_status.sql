-- 135_radar_status.sql
-- APPLIED BY HAND on 2026-10-10 and verified live: public.radar_status, 10 columns.
--
-- VERBATIM. Everything below this header is the exact SQL that was run by hand,
-- replacing the earlier reconstruction this file held.
--
-- WHAT IT IS FOR. "Is the lead radar running?" could only be answered from server
-- logs; a count of new bsky_leads cannot answer it, because the base rate is
-- about one lead a day. leadRadar.js writes one row per source here: when the
-- process starts the radar (process_started_at), and at the end of every capture
-- tick with what that tick did. Only a STARTED radar writes it — never a check
-- that merely loads server.js. REQUIRES 066 (public.set_updated_at).

BEGIN;

CREATE TABLE IF NOT EXISTS public.radar_status (
  source                 text PRIMARY KEY,
  process_started_at     timestamptz,
  last_tick_started_at   timestamptz,
  last_tick_finished_at  timestamptz,
  last_outcome           text,
  searches               integer,
  captured               integer,
  resumes_at             timestamptz,
  last_error             text,
  updated_at             timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.radar_status DROP CONSTRAINT IF EXISTS radar_status_source_check;
ALTER TABLE public.radar_status ADD  CONSTRAINT radar_status_source_check
  CHECK (source IN ('bluesky', 'mastodon', 'youtube'));

ALTER TABLE public.radar_status DROP CONSTRAINT IF EXISTS radar_status_outcome_check;
ALTER TABLE public.radar_status ADD  CONSTRAINT radar_status_outcome_check
  CHECK (last_outcome IS NULL OR last_outcome IN
    ('captured', 'nothing_new', 'backoff', 'login_failed', 'no_credentials', 'error'));

DROP TRIGGER IF EXISTS radar_status_set_updated_at ON public.radar_status;
CREATE TRIGGER radar_status_set_updated_at
  BEFORE UPDATE ON public.radar_status
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

ALTER TABLE public.radar_status ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public.radar_status IS
  'Heartbeat of the lead radars: one row per source, overwritten by the radar itself at process start and at the end of every tick. Proves the radar is alive without reading server logs. Written only by leadRadar.js when it runs as part of the production process; never by checks.';

COMMIT;
