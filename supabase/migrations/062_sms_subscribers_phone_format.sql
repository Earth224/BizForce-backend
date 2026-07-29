-- sms_subscribers.phone_number is now a fixed shape — this one CHANGES live structure.
--
-- 061 closed the integrity gaps around the campaign tables. This file closes the
-- one that actually cost something: the phone number format. A subscriber row
-- stored as "917 325 2291" is a row no equality filter finds, and both places
-- that matter are equality filters — the inbound STOP handler and the consent
-- gate on /api/sms/send. The cost of that gap was not abstract. It was an
-- opt-out that matched nobody: the carrier delivered a STOP, the update applied
-- to zero rows, the subscriber stayed opted in, and the drip engine kept
-- sending.
--
-- Two things happened before this file was written. The application now
-- canonicalizes through canonicalPhone at every write path, and the stored rows
-- were repaired tonight: three subscriber rows, one of which held
-- "917 325 2291" and was merged into the row already holding 19173252291 by
-- repointing its send-log rows onto that row and deleting it.
--
-- This migration is what stops it coming back. Canonicalizing in server.js
-- protects the write paths that exist today; a check constraint protects the
-- ones nobody has written yet. A future route that inserts a subscriber and
-- forgets the helper is the exact way the first bad row got in, and it should
-- fail loudly at insert rather than quietly create another number that cannot
-- be unsubscribed.
--
-- Checked against production data first, tonight, before being written here.
-- The checks and their results:
--
--   sms_subscribers, total rows ................................ 2
--   sms_subscribers, rows matching ^1[0-9]{10}$ ................ 2
--       19173252291 and 19175184669. Both eleven digits, both leading 1.
--   sms_subscribers, rows with a null phone_number ............. 0
--   sms_subscribers.phone_number, is_nullable .................. NO
--   lead_captures, total rows with a non-null phone ............ 3
--   lead_captures, rows matching ^1[0-9]{10}$ .................. 0
--
-- That first pair is what makes the statement below safe: adding a check
-- constraint validates it against every existing row and fails outright if any
-- violates it. Both live rows satisfy it. This was not assumed.
--
-- On how the nullability was read, stated exactly because the answer is load
-- bearing: this repo has no direct SQL connection — no DATABASE_URL, no pg
-- driver, only the PostgREST service-role client — so information_schema is not
-- reachable from here as a query. It was read instead from the schema PostgREST
-- itself publishes, which lists phone_number in the required set for
-- sms_subscribers. PostgREST marks a column required only when it is NOT NULL
-- and has no default, so that answer is unambiguous in this direction:
-- phone_number is NOT NULL.
--
-- That matters because a null passes a check constraint automatically — the
-- constraint would have had a hole in it. It does not: the column rejects null
-- already, so this constraint governs every row without exception, and the
-- nullable-column reasoning that applies to sms_campaign_enrollments.status in
-- 061 does not apply here.
--
-- Nor is a phoneless subscriber reachable by any current write path. The two
-- authenticated inserts require phone and 400 without it. /api/capture treats
-- phone as optional at the top level — an email-only capture is valid and
-- writes a lead_captures row — but it enters the sms_subscribers upsert only
-- under `if (phone && smsConsent)`, so the optional case never reaches this
-- table. The not-null and this check agree with the application rather than
-- constraining it.
--
-- THIS CONSTRAINT IS THE DATABASE-SIDE MIRROR OF canonicalPhone IN server.js.
-- It permits exactly what that helper produces and nothing else: eleven digits,
-- leading 1, no plus, no punctuation. The two definitions are one rule written
-- twice, and they have to move together. If canonicalPhone is ever widened to
-- accept country codes other than 1, this constraint must widen with it IN THE
-- SAME COMMIT — otherwise the helper starts returning values the database
-- refuses, and every international subscriber is rejected at insert with a
-- constraint violation surfacing as a 500. Widening the constraint first is the
-- safe order; widening the helper first is an outage.
--
-- The statement is guarded on pg_constraint the way 059 through 061 are, so a
-- partial application can be re-run safely. The guard matters more than it
-- looks: add constraint has no if-not-exists form, and the drop-then-recreate
-- idiom used elsewhere in this folder would re-validate against every row on
-- each run. Guarded, a re-run is genuinely free rather than merely correct.

-- ── sms_subscribers: phone_number is eleven digits beginning with 1 ──────────

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'sms_subscribers_phone_format_check'
      and conrelid = 'public.sms_subscribers'::regclass
  ) then
    alter table public.sms_subscribers
      add constraint sms_subscribers_phone_format_check
      check (phone_number ~ '^1[0-9]{10}$');
  end if;
end $$;

comment on constraint sms_subscribers_phone_format_check on public.sms_subscribers is
  'The database-side mirror of canonicalPhone in server.js: eleven digits, leading 1, no plus or punctuation. Permits exactly what that helper produces. Widening the helper to accept other country codes requires widening this constraint in the same commit, or every international subscriber is rejected at insert. The format is not cosmetic — the inbound STOP handler and the /api/sms/send consent gate both match phone_number by equality, so a row in any other shape cannot be opted out.';

-- ── Deliberately NOT done here: lead_captures.phone ─────────────────────────
--
-- /api/capture now canonicalizes before writing, and it writes both rows from
-- the same value, so lead_captures.phone receives canonical values from this
-- point forward. The symmetrical constraint on that column is still wrong to
-- add today, and this is not caution in the abstract — the rows were counted:
--
--   all 3 existing lead_captures rows hold "917 325 2291"
--   0 of them match ^1[0-9]{10}$
--
-- So the constraint that just succeeded against sms_subscribers would fail
-- against lead_captures on every row it has. Adding it blindly would abort this
-- migration outright and take the constraint above down with it.
--
-- The difference is that the subscriber rows were repaired first and these have
-- not been. That is the whole prerequisite: lead_captures.phone gets a
-- constraint once its contents are backfilled the same way — counted, rewritten
-- to canonical form, re-counted — and not before. Recorded here so the omission
-- reads as sequencing rather than oversight.
--
-- Worth noting for whoever does that backfill: the column is nullable and
-- email-only captures legitimately write null, so that constraint will need to
-- permit null explicitly or accept that null passes on its own. Unlike
-- phone_number above, the null case there is reachable and intended.
