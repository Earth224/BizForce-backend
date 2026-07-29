-- lead_captures.phone gets the shape sms_subscribers already has — the other half of 062.
--
-- 062 added the format constraint to sms_subscribers.phone_number and
-- deliberately did NOT add the matching one here. That omission was recorded
-- with its reason and its counts: all three lead_captures rows held
-- "917 325 2291", none matched the pattern, and the constraint would have
-- aborted 062 outright and taken the subscriber constraint down with it.
--
-- The prerequisite 062 stated was explicit — lead_captures.phone gets a
-- constraint once its contents are backfilled the same way the subscriber rows
-- were: counted, rewritten to canonical form, re-counted, and not before. That
-- backfill has now run. All three rows hold 19173252291. This file is the
-- follow-through on a decision already made and written down, not a new one.
--
-- Checked against production tonight, re-counted after the backfill rather than
-- taken on trust, because re-counting is the literal prerequisite:
--
--   lead_captures, total rows ............................ 3
--   lead_captures, rows with a non-null phone ............ 3
--   lead_captures, rows matching ^1[0-9]{10}$ ............ 3 after backfill, 0 before
--   lead_captures, rows with an unparseable phone ........ 0
--   lead_captures.phone, is_nullable ..................... YES
--
-- Rows that would violate the constraint below: 0. That is what makes the
-- statement safe — adding a check validates it against every existing row and
-- fails outright if any violates it. This was not assumed.
--
-- All three rows carry the same number, which is not a defect in this table.
-- lead_captures is an append-only record of submissions and has no uniqueness on
-- phone; three submissions of one number are three captures. It is
-- sms_subscribers that collapses them, through the onConflict user_id,phone_number
-- upsert in /api/capture — and canonicalizing before that upsert is what makes
-- the collapse actually happen rather than producing a second subscriber and a
-- second welcome enrollment.
--
-- ── On the null branch of the predicate ─────────────────────────────────────
--
-- The check is written `phone is null or phone ~ '...'`. The first branch is
-- redundant TO THE ENGINE and deliberately kept anyway: a check constraint in
-- Postgres passes when its predicate evaluates to null, and `null ~ '...'` is
-- null, so a null phone would satisfy `phone ~ '...'` on its own. Dropping the
-- branch would not change behaviour by one row.
--
-- It is not redundant to a reader. This is the difference between this column
-- and the one 062 constrained: sms_subscribers.phone_number is NOT NULL, so
-- there is no null case there to have an opinion about. This column is nullable
-- and the null case is reachable and intended — /api/capture accepts a capture
-- with an email and no phone, and writes null here. Without the explicit
-- branch, the next person to read this constraint cannot tell whether nulls
-- were permitted on purpose or whether someone forgot them and Postgres
-- silently covered it. The branch records the intent. It is documentation that
-- happens to be executable.
--
-- ── Coupling to canonicalPhone, same as 062 ─────────────────────────────────
--
-- This is the same database-side mirror of canonicalPhone in server.js that 062
-- describes, on the second column that helper now writes: /api/capture
-- canonicalizes once and writes both the lead_captures row and the
-- sms_subscribers row from that one value. The pattern here is character for
-- character the pattern there — eleven digits, leading 1, no plus, no
-- punctuation — and it carries the same coupling, now doubled.
--
-- If canonicalPhone is ever widened to accept country codes other than 1, BOTH
-- constraints must widen with it IN THE SAME COMMIT. There are two of them now,
-- and missing either one is the same outage: the helper starts returning values
-- the database refuses, and the insert fails with a constraint violation that
-- surfaces as a 500. Widening the constraints first is the safe order; widening
-- the helper first breaks capture for every international submission.
--
-- Guarded on pg_constraint the way 059 through 062 are, so a partial
-- application can be re-run safely — add constraint has no if-not-exists form,
-- and drop-then-recreate would re-validate against every row on each run.

-- ── lead_captures: phone is null, or eleven digits beginning with 1 ─────────

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'lead_captures_phone_format_check'
      and conrelid = 'public.lead_captures'::regclass
  ) then
    alter table public.lead_captures
      add constraint lead_captures_phone_format_check
      check (phone is null or phone ~ '^1[0-9]{10}$');
  end if;
end $$;

comment on constraint lead_captures_phone_format_check on public.lead_captures is
  'The database-side mirror of canonicalPhone in server.js, matching sms_subscribers_phone_format_check: eleven digits, leading 1, no plus or punctuation. The `phone is null` branch is redundant to the engine — a null predicate already passes a check — and is written explicitly to record that nulls are intended, not overlooked: this column is nullable and an email-only capture legitimately writes null, unlike sms_subscribers.phone_number which is NOT NULL. Widening canonicalPhone to accept other country codes requires widening this constraint and the sms_subscribers one in the same commit.';
