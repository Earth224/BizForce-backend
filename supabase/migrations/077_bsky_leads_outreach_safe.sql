-- ============================================================================
-- 077_bsky_leads_outreach_safe.sql
--
-- NOT YET APPLIED. Unlike 073, this file is written before the change reaches
-- the database, and the code that reads the column is shipping in the same
-- commit. Until this runs, every lead is null here and therefore ineligible,
-- so the outreach loop draws zero leads rather than drafting anything unsafe.
-- That is the intended failure direction, but it does mean outreach is stopped
-- until this is run.
--
-- WHY
--   The scorer classified intent and nothing else: seekers versus teachers and
--   sellers. Whether a person is an appropriate RECIPIENT of an unsolicited
--   public reply mentioning a supplement or a book is a different question, and
--   nothing anywhere asked it. The two come apart in the worst place — someone
--   posting about a psychiatric medication change, or venting hopelessness at
--   2am, reads to an intent classifier as a person with a strong unmet need and
--   scores HIGH. Intent is exactly what the outreach loop selects on, so the
--   posts most likely to be answered with a product pitch were the ones where
--   doing so is least defensible.
--
--   The scorer now returns a second, independent judgement and it lands here.
--   True means a model read the post and judged that a stranger replying with
--   a product would read as helpful rather than intrusive; false means it read
--   the post and judged otherwise.
--
-- WHY NULLABLE, AND WHY NO DEFAULT
--   Three states are wanted, not two. Null means NOBODY HAS SCREENED THIS ROW,
--   which is not the same claim as false ("screened and refused"), and the
--   distinction is what makes the backlog findable later:
--
--     select count(*) from public.bsky_leads where outreach_safe is null;
--
--   A `not null default false` would collapse the two and leave no way to tell
--   an unscreened row from a refused one ever again. The application treats
--   null and false identically for eligibility, so nothing is at risk from the
--   looser column; only the ability to audit is preserved by it.
--
--   This also means the ~5,400 rows already in the table stay null and become
--   permanently ineligible for outreach. Rescoring them is a spend decision
--   (one Claude call per row) and belongs in its own deliberate statement, not
--   as a side effect of adding a column. The rows are found with:
--
--     update public.bsky_leads set status = 'new', score_attempts = 0
--     where outreach_safe is null and status = 'scored';
--
--   Do NOT run that as part of this migration. It re-queues thousands of paid
--   calls at once.
--
-- NOT DONE HERE
--   No index. The outreach query filters status, intent_score, source,
--   post_created_at and now outreach_safe together, and 068 already recorded
--   that this table carries no indexes beyond its primary key — adding the
--   first one is a change to live structure that deserves its own migration and
--   an explain plan behind it, not a line in a column addition.
--
--   No CHECK and no backfill, for the reasons above.
--
-- SAFETY
--   Additive and idempotent. Nullable with no default, so no existing row is
--   rewritten and the table is not locked for a scan. Re-running is a no-op.
-- ============================================================================

set search_path = public;

alter table public.bsky_leads
  add column if not exists outreach_safe boolean;

comment on column public.bsky_leads.outreach_safe is
  'Suitability screen from the lead scorer, independent of intent_score. true = a model judged this person an appropriate recipient of an unsolicited public product reply. false = a model judged otherwise (distress, medication, a named diagnosis, under a doctor''s care, a minor, or a reply that would read as intrusive). null = never screened; treated as ineligible for outreach exactly like false, but distinguishable for auditing. Only the exact model output "SAFE" produces true; every other value defaults to false.';
