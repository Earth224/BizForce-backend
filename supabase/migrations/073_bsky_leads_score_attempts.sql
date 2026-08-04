-- ============================================================================
-- 073_bsky_leads_score_attempts.sql
--
-- Applied to production before this file was written; recorded here so the
-- repo and the database agree. Migration 071 exists because twenty tables had
-- once drifted the same way.
--
-- WHY
--   scoreNewLeads caught any failure from the Anthropic call - a timeout, a
--   malformed JSON body, an exhausted key, a rate limit - and wrote
--   { intent_score: 0, status: "scored" }. The next query filters on
--   status = 'new', so that lead was never retried, and a call that never
--   happened was recorded identically to a post the model had genuinely read
--   and rated zero.
--
--   Measured on 2026-08-03 across 2,603 rows: 27 carry intent_score 0 with a
--   null intent_reason, which is that path's signature - the failure branch
--   wrote no reason because it had none. 18 bluesky, 9 youtube, 0 mastodon.
--   About 1% of the table, and among them may sit the highest-intent buyer
--   captured to date, indistinguishable from spam.
--
--   This column lets a failure be retried instead of buried. Under three
--   attempts the row stays 'new' and comes back on a later tick; at three it
--   is marked scored with the reason "scoring failed after 3 attempts", which
--   is what makes it tell apart from a real zero forever after.
--
-- NOT DONE HERE
--   The 27 existing rows are NOT reset to 'new'. Rescoring them is a decision
--   about spend, not about schema, and it belongs in its own statement run
--   deliberately rather than as a side effect of adding a column. The query
--   that finds them:
--
--     select id, source, matched_keyword, post_text
--     from public.bsky_leads
--     where status = 'scored' and intent_score = 0 and intent_reason is null;
--
-- SAFETY
--   Additive and idempotent. NOT NULL with a default, so existing rows take 0
--   and nothing is rewritten. Re-running is a no-op.
-- ============================================================================

set search_path = public;

alter table public.bsky_leads
  add column if not exists score_attempts integer not null default 0;
