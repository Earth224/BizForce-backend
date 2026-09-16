-- 118_marketplace_orders_listing_fkey_and_source_table.sql
--
-- DOCUMENT three things on marketplace_orders that exist and never had DDL.
--
-- ── WHAT WAS FOUND ────────────────────────────────────────────────────────
--
-- From pg_constraint and PostgREST's schema description on the live
-- database, 2026-09-15:
--
--   marketplace_orders_listing_id_fkey
--     FOREIGN KEY (listing_id) REFERENCES marketplace_listings(id)
--     ON DELETE SET NULL
--
--   marketplace_orders_amount_bfc_check
--     CHECK (amount_bfc >= 0)
--
--   column_name  | format | required | default
--   source_table | text   | no       | (none)
--
-- None of the three is in any migration. 034 creates the table with
-- listing_id as a bare uuid, amount_bfc with no check, and no source_table;
-- 112 and 113 add other things and mention the foreign key only in a comment
-- ("in no migration before this note").
--
-- ── THE FOREIGN KEY, AND WHY ITS ON DELETE ACTION IS THE POINT ────────────
--
-- SET NULL is not decoration. 113's whole reason for existing is that a
-- listing can vanish after an order is placed and the order must survive
-- that: the digital-file snapshot columns exist so the download still works
-- when listing_id has gone NULL. That design only holds if deleting a listing
-- nulls the reference rather than refusing (RESTRICT) or taking the order
-- with it (CASCADE). A rebuild with no foreign key at all gets a third
-- behaviour — the reference silently dangles — and every join through
-- listing_id returns nothing without anyone having been told the listing is
-- gone. The action was read from pg_get_constraintdef, not inferred.
--
-- ── THE CHECK ─────────────────────────────────────────────────────────────
--
-- amount_bfc >= 0 pairs with 034's amount_usd check, which 034 does declare.
-- The BFC RPCs (bfc_buy_listing, bfc_transfer) guard the amount before it
-- reaches this table, so the constraint is a backstop rather than the gate.
-- Transcribed because it exists.
--
-- Not transcribed: 034 gives amount_bfc DEFAULT 0 and the live column has no
-- default. Removing a default from a rebuild is neither additive nor
-- consequential — every writer supplies amount_bfc — so it is recorded here
-- and left.
--
-- ── source_table, WHOSE WRITER IS UNKNOWN ─────────────────────────────────
--
-- The one live order holds 'marketplace_listings' in this column. Nothing in
-- server.js or the frontend reads or writes source_table, and git history
-- for both repositories has never contained the name. It was written by hand
-- or by a path that no longer exists. It is transcribed because it is there
-- and a restore of that row needs somewhere to put the value; its meaning is
-- a guess and the comment below says so instead of guessing.
--
-- ── WHAT A REBUILD DOES WITHOUT THIS FILE ─────────────────────────────────
--
-- Nothing fails. That is the problem: the invariant 113 depends on is simply
-- not enforced, and the first listing deletion after a rebuild leaves an
-- order pointing at nothing with no error anywhere. The restore of the one
-- live order fails on source_table, which is loud, and that is the only
-- loud part.
--
-- ── SAFETY ────────────────────────────────────────────────────────────────
--
-- Purely additive. Each statement is guarded on the existence of what it
-- adds, so every one is a no-op against the live database and re-runnable
-- anywhere. No row is written or deleted, nothing is dropped or altered, and
-- no existing file is renumbered — 117 was the highest before this.

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'marketplace_orders_listing_id_fkey'
      and conrelid = 'public.marketplace_orders'::regclass
  ) then
    alter table public.marketplace_orders
      add constraint marketplace_orders_listing_id_fkey
      foreign key (listing_id) references public.marketplace_listings(id)
      on delete set null;
  end if;
end $$;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'marketplace_orders_amount_bfc_check'
      and conrelid = 'public.marketplace_orders'::regclass
  ) then
    alter table public.marketplace_orders
      add constraint marketplace_orders_amount_bfc_check
      check (amount_bfc >= 0);
  end if;
end $$;

ALTER TABLE public.marketplace_orders
  ADD COLUMN IF NOT EXISTS source_table text;

COMMENT ON CONSTRAINT marketplace_orders_listing_id_fkey ON public.marketplace_orders IS
  'ON DELETE SET NULL, and the action is load-bearing: migration 113 added digital_file_path/digital_file_name to marketplace_orders precisely so an order survives its listing being deleted, which this action is what makes possible. Existed live before any migration named it; transcribed in 118.';

COMMENT ON COLUMN public.marketplace_orders.source_table IS
  'WRITER UNKNOWN. Nullable text with no default. The one live row (2026-09-15) holds ''marketplace_listings''. No code in server.js or the frontend reads or writes this column and neither repository''s history has ever contained the name, so it was written by hand or by a path since removed. Transcribed in migration 118 because it exists and a restore needs it; the value''s meaning is not documented anywhere and this comment does not invent one. If a writer is found, replace this comment with what it does.';
