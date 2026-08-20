-- ============================================================================
-- 078_bsky_leads_reply_invited.sql
--
-- NOT YET APPLIED. Same shape as 077: the code that reads this column ships in
-- the same commit, so until this runs every lead is null here and therefore
-- ineligible, and the outreach loop draws zero leads rather than replying to
-- anyone who did not ask. Intended failure direction, but it does mean outreach
-- is stopped until this is run.
--
-- WHY
--   The scorer asked two questions - does this person want something
--   (intent_score), and is it safe to contact them (outreach_safe). It never
--   asked the third: did they invite a reply.
--
--   A lead scored 72 and cleared the safety screen on this post:
--
--     "If I can't get to the store tomorrow, I'll be ordering delivery. Gonna
--      try and see if just plain ol bone broth helps at all. Also getting some
--      protein bars for when I don't have energy for cooking"
--
--   Every word of that says low energy. Not one word of it asks a question.
--   Answering it is not unsafe and the intent read was not wrong - it is
--   uninvited, and neither of the first two questions could see that. A
--   stranger replying with a supplement recommendation reads as someone
--   monitoring the author's timeline.
--
--   The two leads that ever converted both opened the floor explicitly:
--   "Ok chat real question: ... what's done stuff you can do to help get your
--   sex drive back up?" and "For the health conscious or nutritionist. Is there
--   anything I can eat specifically that will naturally boost my energy and
--   mood?" That is the difference this column stores.
--
--   true means a model read the post and judged that it asks a question of the
--   room, requests recommendations, or otherwise opens the floor to strangers.
--   false means it read the post and judged that no answer was solicited -
--   narration, commentary, a joke, or a statement of what the person is doing -
--   regardless of how plainly they have the problem.
--
-- WHY NULLABLE, AND WHY NO DEFAULT
--   The same three states 077 kept, for the same reason. Null means NOBODY HAS
--   SCREENED THIS ROW, which is a different claim from false ("screened, and
--   they did not ask"), and only the distinction makes the backlog findable:
--
--     select count(*) from public.bsky_leads where reply_invited is null;
--
--   A `not null default false` would collapse the two permanently. The
--   application treats null and false identically for eligibility, so the
--   looser column risks nothing and preserves the ability to audit.
--
--   Every row scored before this column existed stays null and becomes
--   ineligible - including rows that were scored under the suitability screen
--   and are otherwise perfectly good. Rescoring them is one Claude call each
--   and is a spend decision, so it belongs in its own deliberate statement:
--
--     update public.bsky_leads set status = 'new', score_attempts = 0
--     where reply_invited is null and status = 'scored';
--
--   Do NOT run that as part of this migration.
--
-- NOT DONE HERE
--   No index, no CHECK, no backfill - same reasoning as 077. 068 recorded that
--   this table carries no indexes beyond its primary key, and the outreach
--   query now filters on five columns together; adding the first index is a
--   change to live structure that deserves its own migration and an explain
--   plan behind it.
--
-- SAFETY
--   Additive and idempotent. Nullable with no default, so no existing row is
--   rewritten and the table is not locked for a scan. Re-running is a no-op.
-- ============================================================================

set search_path = public;

alter table public.bsky_leads
  add column if not exists reply_invited boolean;

comment on column public.bsky_leads.reply_invited is
  'Invitation screen from the lead scorer, independent of intent_score and of outreach_safe. true = a model judged that the post asks a question of the room, requests recommendations, or otherwise opens the floor to replies from strangers. false = a model judged that no answer was solicited (narration, commentary, a joke, or a statement of what the author is doing), regardless of how clearly they have the problem the product addresses. null = never screened; treated as ineligible for outreach exactly like false, but distinguishable for auditing. Only the exact model output "INVITED" produces true; every other value defaults to false.';
