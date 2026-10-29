-- 153_agent_descriptions_cleared.sql — every agent shows its one honest
-- description; no stored copy can drift again.
--
-- WHY. ai_agents.description was copied into rows once and never rewritten,
-- and the pages showed it over their own honest text. On Oct 28 the owner's
-- live pages still read "Etsy listing optimization, keyword research, pricing
-- strategy, and competitor-shop analysis." for the Storefront agent, and
-- claimed "omnichannel performance" (Store), "ROI forecasting" (Influencer) and
-- "Review-generation systems" (Reputation): none of it what the code does.
--
-- The one honest description of each agent now lives in code, in
-- config/brain.js (PLATFORM_KNOWLEDGE.agents). GET /api/agents and
-- GET /api/agents/:type return it in place of the column, the frontend's text
-- is generated from it, sign-up seeding writes NULL, and POST and PUT
-- /api/agents refuse a description (a member can change the display name only).
--
-- NULL, NOT THE CANONICAL TEXT. A copy of the canonical text in every row would
-- be correct today and stale the next time a description is corrected — the
-- exact failure this fixes. NULL holds nothing that can go out of date.
--
-- The CHECK keeps it that way: no code path, old or new, can store a
-- description again. Apply this AFTER the backend that writes NULL is deployed;
-- an older server seeding "" for a new member would be refused by the CHECK.

UPDATE public.ai_agents
   SET description = NULL
 WHERE description IS NOT NULL;

ALTER TABLE public.ai_agents
  DROP CONSTRAINT IF EXISTS ai_agents_description_not_stored;

ALTER TABLE public.ai_agents
  ADD CONSTRAINT ai_agents_description_not_stored CHECK (description IS NULL);
