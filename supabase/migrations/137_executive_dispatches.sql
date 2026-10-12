-- 137_executive_dispatches.sql
-- APPLIED BY HAND on 2026-10-12 and verified live: public.executive_dispatches, 12 columns.
--
-- MATCHED TO THE LIVE TABLE. Before this file was written, the live table was
-- read (read-only, the PostgREST schema of 2026-10-12) and every column below
-- agrees with it: the 12 names, their types, which are NOT NULL, the defaults
-- on id and created_at, the three foreign keys (user_id -> users.id,
-- plan_task_id -> ai_tasks.id, tool_task_id -> ai_tasks.id), and the table
-- comment, verbatim. That schema does not show ON DELETE actions, CHECK
-- constraints, indexes or RLS; those are as the hand-run verification reported:
-- ON DELETE CASCADE from users and from the plan, ON DELETE SET NULL from the
-- tool's run, assignment_id >= 1, outcome in ran/refused/failed, one index on
-- (user_id, plan_task_id, created_at desc), RLS on with no policies. The
-- constraint and index names below are this file's; the live names were not
-- readable from here. The table held 0 rows when this was written.
--
-- WHAT IT IS FOR. POST /api/assignments/dispatch runs one assignment of an
-- executive/plan through dispatchToolCall. The tool writes its own ai_tasks
-- row, but nothing tied that row back to the plan and assignment it came from:
-- the chain id lived only on model_calls and in the HTTP response. The route
-- now writes one row here for every request that names a real plan of the
-- caller's: 'ran' with the tool's ai_tasks id and the chain id, 'refused' with
-- the reason and detail, 'failed' when the tool threw or answered with an
-- error. GET /api/command-center reads each assignment's latest row.
--
-- WRITTEN ONLY BY THE SERVER, with the service key. RLS is on with no policies,
-- so neither the anon key nor a signed-in client key can read or write it.

BEGIN;

CREATE TABLE IF NOT EXISTS public.executive_dispatches (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  plan_task_id    uuid NOT NULL REFERENCES public.ai_tasks(id) ON DELETE CASCADE,
  assignment_id   integer NOT NULL,
  agent_type      text,
  tool            text,
  outcome         text NOT NULL,
  refused_reason  text,
  detail          text,
  tool_task_id    uuid REFERENCES public.ai_tasks(id) ON DELETE SET NULL,
  chain_id        uuid,
  created_at      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.executive_dispatches DROP CONSTRAINT IF EXISTS executive_dispatches_assignment_id_check;
ALTER TABLE public.executive_dispatches ADD  CONSTRAINT executive_dispatches_assignment_id_check
  CHECK (assignment_id >= 1);

ALTER TABLE public.executive_dispatches DROP CONSTRAINT IF EXISTS executive_dispatches_outcome_check;
ALTER TABLE public.executive_dispatches ADD  CONSTRAINT executive_dispatches_outcome_check
  CHECK (outcome IN ('ran', 'refused', 'failed'));

CREATE INDEX IF NOT EXISTS executive_dispatches_user_plan_created_idx
  ON public.executive_dispatches (user_id, plan_task_id, created_at DESC);

ALTER TABLE public.executive_dispatches ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public.executive_dispatches IS
  'One row per dispatch of an Executive plan assignment (POST /api/assignments/dispatch): which plan and assignment, what ran, the ai_tasks row it produced, or why it was refused. Written only by the server. The link the Command Center reads.';

COMMIT;
