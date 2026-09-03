-- Dropped rather than widened, because widening would keep a copy of the agent
-- roster in Postgres.
--
-- 003 constrained source_agent and target_agent to eleven literals: executive,
-- seo, content, sales, analytics, operations, reputation, social, email,
-- community, influencer. The application now recognises seventeen agent types,
-- so ads, etsy, store, broker, publicist and rd were absent from the check
-- while being perfectly valid everywhere else.
--
-- WHAT THAT DID NOT CAUSE, stated plainly because it is the obvious assumption
-- and it is wrong: it never produced a 500. COLLABORATION_AGENT_TYPES in
-- server.js holds the same eleven names, and every path that writes this table
-- tests against it FIRST -- POST /api/collaborations returns 400 for an
-- unlisted source_agent or target_agent, and the orchestrator handoff skips
-- with unsupported_source_agent / missing_target_agent and logs it. The check
-- was therefore unreachable: it rejected nothing the application would have let
-- through. It was redundant, not harmful.
--
-- Which is the actual reason to drop it. Widening it to seventeen would make
-- Postgres a place the roster has to be maintained, needing a migration every
-- time an agent is added, and a migration is exactly what nobody remembers to
-- write -- which is how it came to list eleven of seventeen in the first place.
-- Leaving one authority in the application is the fix; adding a second one in
-- SQL is the bug restated.
--
-- WHAT THIS DOES NOT FIX: dropping these does not make the six missing types
-- usable. COLLABORATION_AGENT_TYPES still lists eleven and still gates every
-- write, so ads, etsy, store, broker, publicist and rd remain rejected with a
-- 400. This removes the duplicate; the application list is now the only place
-- that decides, and widening it there is a separate, deliberate change.
--
-- The table is NOT unread, so nothing here assumes it can be treated as
-- write-only: GET /api/collaborations lists rows, GET /api/collaborations/:id
-- reads one, and DELETE /api/collaborations/:id removes one. Only the type
-- vocabulary is being unconstrained -- collaboration_type and status keep their
-- own checks from 003, and neither is a roster.

alter table public.agent_collaborations
  drop constraint if exists agent_collaborations_source_agent_check;

alter table public.agent_collaborations
  drop constraint if exists agent_collaborations_target_agent_check;
