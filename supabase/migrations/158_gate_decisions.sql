-- 158_gate_decisions.sql — one record per gate decision (intelligence layer B1).
--
-- WHY. A member's agents are stopped or let through by gates: the spend
-- ceilings, the daily call cap, the subscription, approval, the chain limits,
-- the marketing-mail rules. Until now most of those refusals lived only in a
-- response or a log line, so "why did this run, or not run" could not be
-- answered afterwards. Each decision now writes one row here (lib/gates.js
-- evaluates it; server.js recordGateDecision writes it).
--
-- WHAT A ROW HOLDS. The action (a closed list, the same as lib/gates.js
-- ACTIONS), its target (a kind and, for the member's own rows, the row id; never
-- an address, a prompt or an amount), the outcome, and `results`: the gates in
-- the order they ran, each as {gate, result, code}. The code is a short token
-- and its fixed sentence is in lib/gates.js REASONS, so nothing a member wrote
-- is copied here.
--
-- A FAILED WRITE NEVER CHANGES A DECISION. The record is written after the
-- gates have decided; a write that fails is logged ("[gates] record not
-- written") and the answer stands. Until this migration is applied every write
-- fails that way and nothing else changes.
--
-- RETENTION. 90 days (design report section 1.5). The daily sweep that deletes
-- older rows, gate_decisions_sweep through job_runs, comes in block B2; until
-- then rows are kept.
--
-- ACCESS. Row level security is on with NO policies: only the service role
-- (the server) reads or writes, and the server reads a member's rows only by
-- their own user_id. The rows are in the member's data export and are deleted
-- with the account (lib/yourData.js), and the foreign key cascades as well.

CREATE TABLE IF NOT EXISTS public.gate_decisions (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  action     text NOT NULL CHECK (action IN (
               'model_call', 'proposal_approve', 'proposal_auto_execute', 'dispatch', 'schedule_run',
               'marketing_email', 'outreach_send', 'bfc_transfer', 'social_post', 'trigger_fire',
               'task_run', 'route_access')),
  target     text NOT NULL CHECK (char_length(target) BETWEEN 1 AND 160),
  outcome    text NOT NULL CHECK (outcome IN ('ran', 'blocked', 'held_for_approval')),
  results    jsonb NOT NULL CHECK (jsonb_typeof(results) = 'array' AND pg_column_size(results) <= 2048),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- A member's recent decisions, newest first.
CREATE INDEX IF NOT EXISTS gate_decisions_user_recent_idx
  ON public.gate_decisions (user_id, created_at DESC);

-- A member's decisions for one action, newest first.
CREATE INDEX IF NOT EXISTS gate_decisions_user_action_idx
  ON public.gate_decisions (user_id, action, created_at DESC);

ALTER TABLE public.gate_decisions ENABLE ROW LEVEL SECURITY;
