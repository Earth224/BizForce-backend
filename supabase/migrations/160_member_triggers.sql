-- 160_member_triggers.sql — member triggers and their firings
-- (intelligence layer B4)
--
-- PURPOSE. A trigger watches one number from the member's own account and,
-- when it crosses the line the member set, raises an alert, has an agent draft
-- a task, or pauses an agent's schedules (lib/triggers.js holds the closed
-- lists; lib/triggerRunner.js is the hourly pass, at :30 UTC, off unless
-- ENABLE_TRIGGERS is exactly "true"). Every firing goes through the gate
-- evaluator (lib/gates.js, action trigger_fire) and its row here carries the
-- id of that gate_decisions row.
--
-- THE METRICS are nine, each a count or sum over rows the member already has:
-- stock_at_reorder, blog_arrivals, tasks_failed, proposals_pending,
-- lead_scores (the owner only), bfc_balance, schedule_failures, spend_vs_cap,
-- helpful_share. Nothing new is tracked about anyone.
--
-- metric_window, not "window": WINDOW is a reserved word in PostgreSQL.
--
-- NOTHING A TRIGGER DOES PUBLISHES OR SENDS. A drafted task is a saved prompt
-- the member runs through the normal task route, where anything that would
-- publish or send still waits for approval.
--
-- agent_schedules.paused_reason gains 'trigger': a schedule a trigger paused.
-- Resume is the existing button.
--
-- PRIVACY AND ACCESS. Both tables are the member's own data: exported and
-- deleted with the account (lib/yourData.js), backed up (lib/backup.js), and
-- the foreign keys cascade. Row level security is on with no policies; only
-- the server's service role reads them, and every route filters on the
-- caller's user_id.

CREATE TABLE IF NOT EXISTS public.member_triggers (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  name             text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
  metric           text NOT NULL CHECK (metric IN (
                     'stock_at_reorder', 'blog_arrivals', 'tasks_failed', 'proposals_pending', 'lead_scores',
                     'bfc_balance', 'schedule_failures', 'spend_vs_cap', 'helpful_share')),
  metric_agent     text CHECK (metric_agent IS NULL OR char_length(metric_agent) BETWEEN 1 AND 40),
  comparator       text NOT NULL CHECK (comparator IN ('lt', 'lte', 'gt', 'gte', 'drop_pct')),
  threshold        numeric NOT NULL CHECK (threshold >= 0 AND threshold <= 1000000000),
  metric_window    text NOT NULL CHECK (metric_window IN ('now', '1h', '24h', '48h', '7d', '30d')),
  cooldown_hours   integer NOT NULL DEFAULT 24 CHECK (cooldown_hours BETWEEN 6 AND 168),
  action           jsonb NOT NULL CHECK (jsonb_typeof(action) = 'object' AND pg_column_size(action) <= 512),
  enabled          boolean NOT NULL DEFAULT true,
  last_value       numeric,
  last_checked_at  timestamptz,
  last_attempt_at  timestamptz,
  last_fired_at    timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);

-- One name per member, whatever its case or surrounding spaces.
CREATE UNIQUE INDEX IF NOT EXISTS member_triggers_user_name_key
  ON public.member_triggers (user_id, lower(btrim(name)));

-- The hourly pass reads the enabled triggers.
CREATE INDEX IF NOT EXISTS member_triggers_enabled_idx
  ON public.member_triggers (enabled, user_id);

ALTER TABLE public.member_triggers ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS public.trigger_firings (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  trigger_id        uuid NOT NULL REFERENCES public.member_triggers(id) ON DELETE CASCADE,
  metric_value      numeric,
  threshold         numeric,
  fired_at          timestamptz NOT NULL DEFAULT now(),
  outcome           text NOT NULL CHECK (outcome IN ('fired', 'action_failed', 'skipped_daily_cap', 'blocked_by_gate')),
  action_ref        text CHECK (action_ref IS NULL OR char_length(action_ref) BETWEEN 1 AND 120),
  gate_decision_id  uuid
);

-- The member's history, newest first, and today's count for the daily cap.
CREATE INDEX IF NOT EXISTS trigger_firings_user_fired_idx
  ON public.trigger_firings (user_id, fired_at DESC);

ALTER TABLE public.trigger_firings ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.agent_schedules
  DROP CONSTRAINT IF EXISTS agent_schedules_paused_reason_known;
ALTER TABLE public.agent_schedules
  ADD CONSTRAINT agent_schedules_paused_reason_known
  CHECK (paused_reason IS NULL OR paused_reason IN ('owner', 'failures', 'trigger'));
