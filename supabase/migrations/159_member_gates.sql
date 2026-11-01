-- 159_member_gates.sql — member gates, and what the "Why?" view reads
-- (intelligence layer B2)
--
-- PURPOSE. A member gate is a rule a member writes for their own account in
-- the closed language of lib/gateRules.js: "Act only if <condition>". It is
-- asked after every platform gate has let an action through (an approval, an
-- automatic run, a scheduled run), and can only turn that pass into a block,
-- under the member's own gate name. It is never asked about an action the
-- platform refused, so it can never turn a platform fail into a pass.
--
-- THE RULE is plain JSON: conditions on known fields only (action_type,
-- agent, weekday, hour, approved, channel, amount), comparators from a fixed
-- set, AND / OR / NOT, at most 4 levels and 12 conditions. Nothing in it is
-- evaluated as text or code. The server validates every rule before it is
-- stored (POST and PUT /api/member-gates) and again before it is applied;
-- this table holds it as jsonb with a size and type check.
--
-- gate_decisions gains three nullable columns:
--   facts             the closed tokens the Decisions filter and the rule
--                     preview read (agent, action type, channel, approved);
--                     never a name, text, address or amount;
--   member_gate_id    the member gate that blocked the action, when one did
--                     (no foreign key: the record stays if the gate is deleted);
--   member_gate_name  its name when it blocked, which is the reason shown.
-- Until this migration is applied, the server writes rows without them.
--
-- agent_schedules.last_run_status gains skipped_member_gate: a scheduled run
-- the member's own gate stopped.
--
-- PRIVACY AND ACCESS. member_gates is the member's own data: it is exported
-- and deleted with the account (lib/yourData.js) and the foreign key
-- cascades. Row level security is on with no policies; only the server's
-- service role reads it, and every route filters on the caller's user_id.
--
-- RETENTION. member_gates rows live until the member deletes them or the
-- account. gate_decisions keeps its 90 days: lib/gateDecisionsSweep.js deletes
-- older rows daily at 04:30 UTC; the created_at index below serves it.

CREATE TABLE IF NOT EXISTS public.member_gates (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
  scope       text NOT NULL CHECK (scope IN ('proposal_approve', 'proposal_auto_execute', 'schedule_run', 'any')),
  rule        jsonb NOT NULL CHECK (jsonb_typeof(rule) = 'object' AND pg_column_size(rule) <= 4096),
  time_zone   text NOT NULL DEFAULT 'UTC' CHECK (char_length(time_zone) BETWEEN 1 AND 64),
  enabled     boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- A member's enabled gates for one scope, in the order they were made.
CREATE INDEX IF NOT EXISTS member_gates_user_scope_idx
  ON public.member_gates (user_id, scope, created_at);

ALTER TABLE public.member_gates ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.gate_decisions
  ADD COLUMN IF NOT EXISTS facts jsonb
    CHECK (facts IS NULL OR (jsonb_typeof(facts) = 'object' AND pg_column_size(facts) <= 512)),
  ADD COLUMN IF NOT EXISTS member_gate_id uuid,
  ADD COLUMN IF NOT EXISTS member_gate_name text
    CHECK (member_gate_name IS NULL OR char_length(member_gate_name) BETWEEN 1 AND 60);

-- The daily sweep reads the oldest rows first.
CREATE INDEX IF NOT EXISTS gate_decisions_created_idx
  ON public.gate_decisions (created_at);

ALTER TABLE public.agent_schedules
  DROP CONSTRAINT IF EXISTS agent_schedules_last_run_status_known;
ALTER TABLE public.agent_schedules
  ADD CONSTRAINT agent_schedules_last_run_status_known
  CHECK (last_run_status IS NULL OR last_run_status IN (
    'succeeded', 'failed', 'skipped_not_entitled', 'skipped_entitlement_unknown',
    'skipped_no_autonomy', 'skipped_invalid', 'skipped_member_gate'));
