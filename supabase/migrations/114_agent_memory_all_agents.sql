-- 114_agent_memory_all_agents.sql
--
-- LET EVERY REGISTERED AGENT WRITE MEMORY, NOT JUST THE SEVEN THAT EXISTED FIRST.
--
-- agent_memory.agent_type has been CHECKed against 7 values since migration 002
-- — the second migration in this project — plus 'oracle', added deliberately by
-- migration 026 when the Oracle needed its own rows. There are now 18 registered
-- agents in AGENT_SYSTEM_PROMPTS. The other 11 have never been able to write a
-- memory row: ads, email, community, influencer, social, etsy, store, broker,
-- publicist, rd and vertical_marketing.
--
-- THIS WAS NEVER A DECISION. Those 7 are simply the agents that existed when the
-- table was created; the other 11 were added later and nobody revisited the
-- constraint. No comment anywhere justifies the seven, and there is no pattern
-- in them beyond age — rd and executive do comparable work and only one is
-- allowed. Migration 026 is what a deliberate choice looks like here: a widening
-- with a stated reason, done once, for one feature.
--
-- Meanwhile the READ has always run for all 18. server.js says so at the read
-- site: "A soft read: SELECT isn't constrained by agent_memory's agent_type
-- CHECK, so this is safe to run for every agent type even though writes are
-- gated." Safe, and for 11 of the 18 permanently futile — a query that could
-- only ever return zero rows, for every user, forever.
--
-- ── THIS IS A BEHAVIOUR CHANGE, NOT A SCHEMA TIDY ─────────────────────────
--
-- Memory feeds buildAgentSystemPrompt. Eleven agents that have never had any
-- will start accumulating it, and their prompts — and therefore their output —
-- will change as it accrues. sales already holds 37 rows, so this is a measured
-- effect and not a theoretical one. Applying this migration is the moment that
-- starts, and it is worth knowing that rather than discovering it.
--
-- ── SAFETY ────────────────────────────────────────────────────────────────
--
-- PURELY WIDENING. The new set is a strict superset of the old, so no existing
-- row can violate it and the ALTER cannot fail on live data. Nothing is written,
-- updated or deleted. Idempotent in the style of 109 onward: the DROP is
-- IF EXISTS and the ADD replaces whatever is there, so a second run is a no-op.
--
-- 113 was the highest before this, so 114 is free and nothing is renumbered.
--
-- ORDER MATTERS. server.js derives MEMORY_AGENT_TYPES from AGENT_SYSTEM_PROMPTS,
-- so the code will attempt writes for all 19 as soon as it deploys — before this
-- migration runs, those fail with 23514. The code handles that window by
-- detecting the violation and logging it loudly, naming the agent and this file,
-- rather than swallowing it. It is a loud gap, not a silent one, and it closes
-- the moment this is applied.

ALTER TABLE agent_memory DROP CONSTRAINT IF EXISTS agent_memory_agent_type_check;

ALTER TABLE agent_memory ADD CONSTRAINT agent_memory_agent_type_check
  CHECK (agent_type IN (
    'seo',
    'sales',
    'content',
    'ads',
    'reputation',
    'analytics',
    'email',
    'community',
    'influencer',
    'operations',
    'executive',
    'social',
    'etsy',
    'store',
    'broker',
    'publicist',
    'rd',
    'vertical_marketing',
    'oracle'
  ));

COMMENT ON CONSTRAINT agent_memory_agent_type_check ON agent_memory IS
  'The 18 agents registered in AGENT_SYSTEM_PROMPTS, plus oracle, which is a separate feature rather than a registered agent. KEEP THIS IN STEP WITH THAT OBJECT: server.js derives MEMORY_AGENT_TYPES from Object.keys(AGENT_SYSTEM_PROMPTS).concat("oracle") precisely so the application side cannot drift from it again — the drift between a hand-maintained constant and this constraint is what left 11 agents unable to write memory from migration 002 until 114. A NEW AGENT NEEDS A MIGRATION: adding one to AGENT_SYSTEM_PROMPTS widens the constant automatically but not this check, and its writes will fail with 23514 until this list is widened too. server.js logs that case by name rather than swallowing it.';
