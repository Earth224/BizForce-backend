-- 132_agent_proposals_brief.sql
--
-- agent_proposals.brief — a TRANSCRIPTION, not a change.
--
-- ALREADY APPLIED BY HAND in the Supabase SQL editor before this file was
-- written; the column was confirmed live with a read-only select of
-- (id, brief) from agent_proposals. The SQL below is that statement pasted
-- here WITHOUT ALTERATION. `add column if not exists` makes running it again
-- against the live database a no-op.
--
-- WHY. When POST /api/agents/seo/generate-post REFUSES a draft, migration 131's
-- seo_refused_drafts keeps the brief it was written from. When it FILES one,
-- nothing kept it, so no one could tell what inputs produced a published
-- article. brief closes that, on the filed side:
--   topic, site_name, site_context, money_anchor
--                         the request's fields, under the same names and from
--                         the same values as seo_refused_drafts.brief
--   prompt_sha256         lowercase hex SHA-256 of the generation prompt,
--                         exactly as sent; the text is never stored
--   repair_prompt_sha256  the same for the claim-repair prompt when a repair
--                         call was made, null when none was
--
-- Written only by the generate-post route, at insert. Nothing updates it:
-- approve and reject change status, never brief. Null on every row filed
-- before this migration and on every route that does not write it.

alter table public.agent_proposals add column if not exists brief jsonb;
comment on column public.agent_proposals.brief is 'Inputs that produced this proposal, written only by the generating route at insert: topic, site_name, site_context, money_anchor, prompt_sha256, repair_prompt_sha256. Null on rows filed before migration 132 and on routes that do not write it.';
