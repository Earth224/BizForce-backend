-- ============================================================================
-- 074_outreach_sends.sql
--
-- Applied to production before this file was written; recorded here so the
-- repo and the database agree. Migration 071 exists because twenty tables had
-- once drifted the same way.
--
-- WHY THIS TABLE EXISTS
--
--   sendBlueskyReply and sendMastodonReply post PUBLIC replies, under the
--   operator's own account, to strangers who never asked to be contacted.
--   runSalesAutoConvert calls that path on a five-minute setInterval - 288
--   passes a day, up to 5 leads per user per pass - with no human in the loop.
--
--   Audited 2026-08-03: there was NO cap of any kind. Not daily, not hourly,
--   not per account. Searched for sent_today, send_count, daily_limit,
--   MAX_SENDS, send_quota and a dozen other spellings; nothing existed. The
--   only bounds were per-invocation slices (.slice(0, 10) on the route,
--   .slice(0, 5) on the autoloop), which bound one call and not a period, and
--   nothing stopped the next call a second later.
--
--   The entire safety of that path rested on two environment variables being
--   ABSENT: SALES_SEND_LIVE and SALES_AUTOLOOP_DRY_RUN. Someone adding
--   SALES_SEND_LIVE=true - reasonably, believing they were enabling a feature -
--   would have turned on unbounded automated public replies. That is a footgun
--   with no trigger guard, and this table is the guard.
--
-- WHAT IT IS FOR, IN ORDER OF IMPORTANCE
--
--   1. THE UNIQUE INDEX. (user_id, lead_post_uri) makes replying twice to one
--      person impossible at the database level rather than dependent on a
--      filter in application code. Segment mode already excluded contacted
--      leads; single-lead mode did not, so clicking Convert twice posted
--      twice. A constraint cannot be forgotten by a later code path.
--
--   2. THE DAILY CAP. Counting rows since the start of the UTC day is what
--      bounds how wrong a single day can go. The ceiling matters because the
--      Bluesky account posting these replies is the SAME account leadRadar.js
--      logs in with to search. Losing it to a spam suspension costs the
--      capture engine, not just the outreach - 1,876 leads captured to date
--      all arrived through that session.
--
--   3. THE RECORD. sales_lead_pipeline holds a mutable status column; this is
--      append-only. It is the only place that will be able to answer "what did
--      this system post publicly, in my name, and when" after the fact.
--
-- RLS: enabled with no policies - deny by default. server.js connects with the
-- service-role key and bypasses it. Matching the pattern of the foundation
-- tables in 071, and it matters more here: a row deleted from this table is a
-- person who can be replied to again and a day's ceiling reset.
--
-- SAFETY
--   Additive and idempotent. Creates nothing that existed before. Re-running
--   is a no-op.
-- ============================================================================

set search_path = public;

create table if not exists public.outreach_sends (
  id            uuid        primary key default gen_random_uuid(),
  user_id       uuid        not null,
  lead_post_uri text        not null,
  source        text        not null,
  platform_uri  text,
  sent_at       timestamptz not null default now()
);

-- No FK on user_id, matching lead_captures and sms_subscribers, whose own
-- migrations record the same choice.

-- The cap query: count rows for one user since the start of the UTC day.
create index if not exists outreach_sends_user_sent_idx
  on public.outreach_sends (user_id, sent_at desc);

-- One reply per person per operator, enforced by the database rather than by
-- remembering to filter. See note 1 above.
create unique index if not exists outreach_sends_user_lead_uniq
  on public.outreach_sends (user_id, lead_post_uri);

alter table public.outreach_sends enable row level security;
