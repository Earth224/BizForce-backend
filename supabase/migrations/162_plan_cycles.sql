-- 162_plan_cycles.sql — learning cycles (intelligence layer B8 and B9)
--
-- PURPOSE. One row per Executive plan the member reviews. A cycle is opened on
-- a finished plan (plan_task_id, an executive/plan ai_tasks row of the
-- member's). POST /api/executive/cycles/:id/review measures what the plan's
-- assignments recorded (lib/planCycle.js: executive_dispatches, the tool runs
-- in ai_tasks, the proposals filed from them, arrivals on the member's refs,
-- the Helpful share where at least 5 ratings exist) into `measured`, asks the
-- model ONCE for a review and a proposed next plan, keeps only the sentences
-- whose numbers all appear in `measured`, and stores the draft as
-- review_drafted. Only when the member approves does the next plan run, and
-- then only through POST /api/agents/executive/plan, which records its task in
-- next_plan_task_id and opens the next cycle with previous_cycle_id set.
--
-- status: open (no draft yet, or the draft was discarded), review_drafted,
-- approved, superseded (set aside by the member; nothing more happens to it).
-- reviewed_at holds the last review's time: at most one review per cycle in
-- any 24 hours.
--
-- THE MODEL DOES NOT LEARN. Each cycle builds on recorded results; the AI model
-- itself does not change.
--
-- agent_preferences.source gains 'lesson': a preference the member accepted
-- from the lessons their weekly self-review derived by rule. self_reviews
-- gains by_agent (the weekly per-agent breakdown) and lessons (the candidate
-- lessons derived from it by rule, with no model call). Both are written after
-- the review's metrics, best effort, so a review still works before this file
-- is applied.
--
-- PRIVACY AND ACCESS. The member's own data: exported and deleted with the
-- account (lib/yourData.js), backed up (lib/backup.js), and the foreign keys
-- cascade. Row level security is on with no policies; only the server's
-- service role reads it, and every route filters on the caller's user_id.

CREATE TABLE IF NOT EXISTS public.plan_cycles (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  plan_task_id       uuid NOT NULL REFERENCES public.ai_tasks(id) ON DELETE CASCADE,
  previous_cycle_id  uuid REFERENCES public.plan_cycles(id) ON DELETE SET NULL,
  status             text NOT NULL DEFAULT 'open'
                     CHECK (status IN ('open', 'review_drafted', 'approved', 'superseded')),
  measured           jsonb,
  review_text        text CHECK (review_text IS NULL OR char_length(review_text) <= 4000),
  next_plan_draft    text CHECK (next_plan_draft IS NULL OR char_length(next_plan_draft) <= 2000),
  next_plan_task_id  uuid REFERENCES public.ai_tasks(id) ON DELETE SET NULL,
  model              text,
  reviewed_at        timestamptz,
  approved_at        timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, plan_task_id)
);

CREATE INDEX IF NOT EXISTS plan_cycles_user_created_idx
  ON public.plan_cycles (user_id, created_at DESC);

ALTER TABLE public.plan_cycles ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.agent_preferences DROP CONSTRAINT IF EXISTS agent_preferences_source_check;
ALTER TABLE public.agent_preferences ADD CONSTRAINT agent_preferences_source_check
  CHECK (source IN ('member', 'suggestion', 'lesson'));

ALTER TABLE public.self_reviews ADD COLUMN IF NOT EXISTS by_agent jsonb;
ALTER TABLE public.self_reviews ADD COLUMN IF NOT EXISTS lessons jsonb;
