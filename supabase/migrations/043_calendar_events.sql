-- 043_calendar_events.sql
-- calendar_events: reminders/anniversaries/birthdays/vacations for the
-- multi-calendar engine (oracle.html + mychart.html, BizForce-fronyend repo).
--
-- KEY DESIGN CHOICE: events anchor to jdn (Julian Day Number), not a
-- calendar-specific (year, month, day) triple. JDN is the universal pivot
-- the whole conversion engine is already built on, so an event created
-- while viewing the Hebrew calendar still lands on the correct day when
-- the user switches to Mayan/Coptic/etc. -- no per-calendar conversion
-- needed beyond what the engine already does at render time.
--
-- user_id FK targets public.users(id) -- the app's real user table.
-- server.js's requireAuth resolves req.user via supabase.from("users")
-- (i.e. public.users, the default schema) using a custom JWT -- this
-- project does not use Supabase Auth. This matches the corrected pattern
-- from 041_oracle_sync_messages_and_fk_repoint.sql, which fixed four
-- tables that had been mistakenly pointed at auth.users. Do NOT reference
-- auth.users(id) here -- that is exactly the bug 041 fixed.

CREATE TABLE IF NOT EXISTS public.calendar_events (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  jdn         integer NOT NULL,
  title       text NOT NULL,
  event_type  text NOT NULL DEFAULT 'other'
                CHECK (event_type IN ('reminder', 'anniversary', 'birthday', 'vacation', 'other')),
  notes       text,
  recurring   boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Fast month-range lookups: WHERE user_id = ? AND jdn BETWEEN ? AND ?
CREATE INDEX IF NOT EXISTS calendar_events_user_jdn_idx ON public.calendar_events (user_id, jdn);

ALTER TABLE public.calendar_events ENABLE ROW LEVEL SECURITY;

-- Idempotent policy creation via a pg_policies existence check: Postgres'
-- CREATE POLICY has no IF NOT EXISTS clause, so this mirrors
-- 037_cover_wraps.sql's DO-block guard pattern (itself mirroring
-- 035_bizbooks.sql) rather than "CREATE POLICY IF NOT EXISTS", which
-- isn't valid syntax.
--
-- NOTE: server.js talks to Supabase via SUPABASE_SERVICE_KEY
-- (service_role), which bypasses RLS entirely, so the real access control
-- for this table is enforced in the route handlers below via req.user.id
-- -- exactly like every other authenticated route in this file. These
-- policies are a defense-in-depth backstop, matching the pattern already
-- used by bizdoc/bizbooks/cover_wraps, not the primary enforcement
-- mechanism.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'calendar_events' AND policyname = 'calendar_events_select'
  ) THEN
    CREATE POLICY calendar_events_select ON public.calendar_events
    FOR SELECT USING (user_id = auth.uid());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'calendar_events' AND policyname = 'calendar_events_insert'
  ) THEN
    CREATE POLICY calendar_events_insert ON public.calendar_events
    FOR INSERT WITH CHECK (user_id = auth.uid());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'calendar_events' AND policyname = 'calendar_events_update'
  ) THEN
    CREATE POLICY calendar_events_update ON public.calendar_events
    FOR UPDATE USING (user_id = auth.uid());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'calendar_events' AND policyname = 'calendar_events_delete'
  ) THEN
    CREATE POLICY calendar_events_delete ON public.calendar_events
    FOR DELETE USING (user_id = auth.uid());
  END IF;
END $$;
