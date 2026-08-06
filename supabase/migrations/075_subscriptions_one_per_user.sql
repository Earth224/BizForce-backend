-- ============================================================================
-- 075_subscriptions_one_per_user.sql
--
-- Collapses `subscriptions` to one row per user, and makes the Stripe webhook
-- able to write a billing row for the first time in this project's history.
--
-- WHY THIS EXISTS
--
--   072 moved uniqueness OFF user_id and ONTO stripe_subscription_id, on the
--   reasoning that a person might hold a $29.99 chart subscription and a $199
--   platform subscription at once. The webhook was never updated to match: both
--   write paths still call upsert with onConflict user_id (server.js:2110 and
--   server.js:2188), and user_id carries only a plain btree. Postgres answers
--   ON CONFLICT against a non-unique column with 42P10.
--
--   So 072 fixed the missing stripe_price_id column and simultaneously
--   recreated the exact 42P10 it was written to eliminate, by moving the
--   target and leaving the code aimed at the old one. Billing has still never
--   processed a payment.
--
--   The premise is also gone. The chart product was reverted on 2026-08-02.
--   There is one product, one price, one plan: BizForceAI All Access at
--   $199/month. The owner has stated there will never be a second tier.
--   The schema was carrying multi-subscription complexity for a product that
--   no longer exists.
--
-- THE DECISION, ON THE RECORD
--
--   One row per USER. The row IS the entitlement.
--
--   The known cost, stated plainly rather than discovered later: if a second
--   billable option is ever introduced - an annual plan, a seat add-on,
--   anything with its own Stripe subscription - this design overwrites the
--   first row while Stripe goes on billing both, and the customer pays twice
--   while losing access to one. That is 072's argument and it remains true.
--   It is accepted because the owner has ruled out a second option, and
--   because reversing this is cheap while the table holds one row and there
--   are zero paying customers. If a second product is ever seriously
--   considered, THIS MIGRATION MUST BE REVISITED BEFORE IT SHIPS.
--
-- PRE-FLIGHT, VERIFIED AGAINST PRODUCTION 2026-08-06
--   total_rows = 1, users_with_duplicates = 0, null_user_id_rows = 0.
--   A unique index cannot be built over duplicates; there are none.
--
-- SAFETY
--   Additive except for one plain index that the new unique index supersedes
--   exactly. No column dropped, no column retyped, no row modified.
--   Idempotent - re-running is a no-op.
-- ============================================================================

set search_path = public;


-- ── 1. One row per user ─────────────────────────────────────────────────────
-- This is what makes `on conflict (user_id)` legal, which is what both webhook
-- write paths have always assumed and never had.
--
-- NOT partial. Every subscription row must belong to a user; a null user_id is
-- an orphaned billing record with nobody to grant entitlement to. Making the
-- index total means Postgres refuses to create such a row at all.
create unique index if not exists subscriptions_user_id_key
  on public.subscriptions (user_id);


-- ── 2. Remove the plain index the unique index supersedes ───────────────────
-- subscriptions_user_id_idx is a plain btree on exactly the column now covered
-- by a unique index. A unique index serves every lookup a plain one does, so
-- the second is pure write overhead on the billing table.
--
-- This is the same reasoning 072 applied when it dropped
-- subscriptions_stripe_subscription_id_idx, and the same distinction holds:
-- dropping a redundant PLAIN index is not the forbidden operation. The rule
-- against drop-then-create applies to UNIQUE constraints, where dropping also
-- destroys the backing index and rebuilds it on live data. Nothing here is
-- recreated, and the unique index above is created first, so the column is
-- never unindexed.
drop index if exists public.subscriptions_user_id_idx;


-- ============================================================================
-- KEPT DELIBERATELY
--
--   subscriptions_stripe_subscription_id_key (partial unique, from 072) stays.
--   It is still correct and still useful: it prevents two rows claiming the
--   same Stripe subscription, which is a different guarantee from one row per
--   user and costs nothing to keep.
--
--   subscriptions_user_plan_status_idx (composite, from 072) stays. Leading on
--   user_id it is now largely superseded, but it is a read optimisation on the
--   entitlement path and removing it is a separate measurement, not a cleanup.
--
-- NOT DONE HERE, DELIBERATELY - CARRIED FORWARD FROM 072
--
--   `plan` still defaults to 'starter', a value PLAN_CONFIG has no entry for
--   and no price maps to. Changing a column default belongs with the
--   application change that stops relying on it. Still logged, still not
--   silently altered.
--
--   Still no CHECK constraint on `plan`.
-- ============================================================================