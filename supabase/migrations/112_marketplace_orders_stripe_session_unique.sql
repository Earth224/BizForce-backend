-- 112_marketplace_orders_stripe_session_unique.sql
--
-- ONE STRIPE CHECKOUT SESSION, ONE ORDER.
--
-- THE HOLE. The marketplace_usd branch of the Stripe webhook guards against a
-- duplicate order by reading marketplace_orders for the session id and
-- returning early if one is found. That is a read followed by a write with no
-- lock between them, and Stripe delivers events AT LEAST ONCE — retrying on
-- timeout, on a 500, and on its own schedule. Two deliveries of one event that
-- arrive close enough together both read "no order yet" and both insert. The
-- buyer is then charged once and recorded twice, and on a digital listing
-- receives two download rows.
--
-- The application check cannot close this by itself, however it is written: no
-- amount of care in two round trips over PostgREST produces mutual exclusion.
-- Only the database can refuse the second write, so the database is asked to.
--
-- ── CHECKED FOR DUPLICATES BEFORE WRITING THIS FILE ───────────────────────
--
-- A unique index cannot be built over a table that already violates it, so the
-- live table was read first rather than hoped about:
--
--   marketplace_orders rows            : 1
--   non-null stripe_session_id values  : 1
--   nulls                              : 0
--   duplicate session ids              : none
--
-- So this index builds. Had there been duplicates, that would have been the
-- more important finding — evidence the race had already fired — and this file
-- would have had to start by reconciling them rather than by adding a
-- constraint.
--
-- ── WHY NULLS ARE FINE ────────────────────────────────────────────────────
--
-- Every BFC order has a null stripe_session_id, because no Stripe session
-- exists for one. In Postgres a UNIQUE index treats NULLs as distinct, so any
-- number of BFC orders coexist under it without a partial WHERE clause. The
-- index is left unfiltered so that it also serves the webhook's lookup by
-- session id, which is the only other query that touches this column.
--
-- Written as a plain UNIQUE INDEX rather than ALTER TABLE ... ADD CONSTRAINT
-- for one reason: IF NOT EXISTS. CREATE UNIQUE INDEX IF NOT EXISTS is a no-op
-- on a second run; ADD CONSTRAINT has no such form and would error, which
-- would break the re-runnability every file from 109 onward has.
--
-- ── SAFETY ────────────────────────────────────────────────────────────────
--
-- Purely additive. No column is added, altered or dropped; no row is written,
-- updated or deleted. Re-running it changes nothing. 111 was the highest
-- before this, so 112 is free and nothing is renumbered.
--
-- NOT CONCURRENTLY, deliberately. CREATE INDEX CONCURRENTLY cannot run inside
-- a transaction block, which is how migrations are usually applied, and this
-- table has one row. The brief lock is not worth the footgun.

CREATE UNIQUE INDEX IF NOT EXISTS marketplace_orders_stripe_session_id_key
  ON public.marketplace_orders (stripe_session_id);

COMMENT ON INDEX public.marketplace_orders_stripe_session_id_key IS
  'One order per Stripe Checkout session. Stripe delivers webhook events at least once, and the marketplace_usd handler''s own read-then-insert check cannot exclude a concurrent redelivery — only this index can. NULL is not constrained, so BFC orders (which have no session) are unaffected however many there are. The handler still performs its read-first check; it is an optimisation and a log-quality measure, not the guarantee. When it loses the race the insert fails here with 23505 and the handler reports it as a no-op rather than as a failure, which is what a redelivery actually is.';
