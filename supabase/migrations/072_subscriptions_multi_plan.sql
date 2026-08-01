-- ============================================================================
-- 072_subscriptions_multi_plan.sql
--
-- Makes `subscriptions` capable of holding more than one subscription per
-- person, and fixes the reason the Stripe webhook has never successfully
-- written a row.
--
-- WHY THIS EXISTS
--
--   Two independent defects, both confirmed against production on 2026-07-31:
--
--   1. server.js writes `stripe_price_id` on every customer.subscription.*
--      event. The column does not exist. PostgREST rejects unknown columns
--      outright, so that entire webhook branch fails - the branch carrying
--      current_period_start, current_period_end and cancel_at_period_end.
--      Corroborating evidence: the one row in the table has a null
--      current_period_end, because nothing has ever written one.
--
--   2. Both webhook write paths call upsert with onConflict user_id, and
--      there is no unique constraint or unique index on user_id - only a
--      plain btree. Postgres answers ON CONFLICT against a non-unique column
--      with 42P10. The single row in this table was placed by hand in SQL
--      during the tier collapse; the webhook did not write it, because the
--      webhook has never written anything.
--
--   Stripe confirms the same picture from the other side: $0.00 gross volume
--   all time, 0 active subscribers, one customer at $0.00 total spend, and a
--   single declined $29.99 payment attempt. No subscription has ever
--   succeeded, so none of this has ever been exercised in anger.
--
-- THE DESIGN DECISION
--
--   The obvious repair is a unique index on user_id, which would make the
--   existing upsert work. It is the wrong repair, and it is wrong in a way
--   that only shows up on the customer who spends the most.
--
--   One row per USER means a person holds exactly one subscription. The whole
--   funnel is built on the chart product feeding the platform: someone buys a
--   $29.99 reading, sees what BizForceAI does, and later buys the $199 tier.
--   Under one-row-per-user that upgrade OVERWRITES the chart subscription in
--   this database while Stripe cheerfully goes on billing both. The customer
--   pays twice and loses access to one of them, and the first anyone hears of
--   it is a refund request or a chargeback.
--
--   So: one row per STRIPE SUBSCRIPTION. A person may hold a chart
--   subscription and a platform subscription simultaneously, each with its
--   own status, period and price. Entitlement stops asking "what plan is this
--   user on" and starts asking "does this user have an active subscription
--   with plan X" - which is the question the application actually has.
--
--   Made now because the table holds one row and there are no paying
--   customers. After the first subscriber this is a data migration.
--
-- SAFETY
--   Additive and idempotent. Nothing is dropped that carries data, no column
--   is retyped, no row is modified. Re-running is a no-op.
-- ============================================================================

set search_path = public;


-- ── 1. The column the webhook has been writing into nothing ─────────────────
-- Stripe's price id is the only durable link from a subscription back to the
-- product that was actually bought. Without it, a row's plan can only be
-- re-derived from a lookup map that may have changed since the sale.
alter table public.subscriptions
  add column if not exists stripe_price_id text;


-- ── 2. One row per Stripe subscription ──────────────────────────────────────
-- Partial rather than plain: Postgres permits many NULLs in a unique index
-- either way, but the WHERE clause states the intent instead of relying on
-- that behaviour being remembered. Rows with a null stripe_subscription_id
-- are legitimate - the hand-placed row is one - and they are simply not
-- covered by uniqueness.
--
-- This index is what makes `on conflict (stripe_subscription_id)` legal, and
-- it is deliberately NOT on user_id. See the design note above.
create unique index if not exists subscriptions_stripe_subscription_id_key
  on public.subscriptions (stripe_subscription_id)
  where stripe_subscription_id is not null;


-- ── 3. The entitlement lookup ───────────────────────────────────────────────
-- Every gate now asks the same question: does this user hold an active
-- subscription for this plan. Without this index that is a sequential scan of
-- the table on every gated request.
create index if not exists subscriptions_user_plan_status_idx
  on public.subscriptions (user_id, plan, status);


-- ── 4. Remove the index the unique index supersedes ─────────────────────────
-- subscriptions_stripe_subscription_id_idx is a plain btree on exactly the
-- column now covered by a unique index. A unique index serves every lookup a
-- plain one does, so the second is pure write overhead on the billing table.
--
-- Dropping a redundant PLAIN index is not the forbidden operation. The rule
-- against drop-then-create applies to UNIQUE constraints, where dropping also
-- destroys the backing index and rebuilds it on live data. Nothing here is
-- recreated and nothing is unprotected in between: the unique index above is
-- created first and already covers the column.
drop index if exists public.subscriptions_stripe_subscription_id_idx;


-- ============================================================================
-- NOT DONE HERE, DELIBERATELY
--
--   `plan` still defaults to 'starter' - a value PLAN_CONFIG has no entry for
--   and no price maps to. Changing a column default is a schema decision that
--   belongs with the application change that stops relying on it, not ahead
--   of it. Logged rather than silently altered.
--
--   No CHECK constraint on `plan`. The set of valid plans is going to move
--   while pricing settles, and a constraint that has to be dropped and
--   recreated on every pricing experiment costs more than it protects.
-- ============================================================================
