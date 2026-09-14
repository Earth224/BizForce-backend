-- 113_marketplace_orders_digital_snapshot.sql
--
-- THE ORDER CARRIES WHAT WAS BOUGHT, INSTEAD OF ONLY POINTING AT IT.
--
-- WHY. marketplace_orders.listing_id has a foreign key to marketplace_listings
-- (marketplace_orders_listing_id_fkey, in no migration before this note). A
-- listing deleted between checkout and payment therefore makes the order INSERT
-- fail with 23503: the customer is charged, no order row is written, and a
-- single log line is the whole trace. That is worse than the listing never
-- being marked sold, which is the defect it was found next to.
--
-- The fix is to stop the order depending on the listing still existing. The row
-- was always partly a snapshot — listing_title, is_digital and amount_usd are
-- all copies taken at purchase time, and migration 034 made listing_id nullable
-- — so this widens an existing design rather than introducing one.
--
-- ── WHAT THESE TWO COLUMNS BUY ────────────────────────────────────────────
--
-- Without them, an order whose listing_id is null cannot serve its download.
-- GET /api/purchases/:orderId/download resolves the file by joining through
-- listing_id to marketplace_listings.digital_file_path; with a null there, the
-- join finds nothing and the buyer gets 404. They would hold only the 7-day
-- signed URL the webhook stored at purchase, and after it expired they would
-- have paid in full for a file they can no longer reach.
--
-- So the snapshot has to be wide enough to serve the download on its own. That
-- is digital_file_path (the object key in the private bf-digital-goods bucket)
-- and digital_file_name (what the buyer sees the file called).
--
-- ── A CONSEQUENCE WORTH KNOWING ABOUT ─────────────────────────────────────
--
-- After this, a seller deleting a listing no longer takes the file away from
-- someone who already bought it: their order still names the object and the
-- download route still signs it. That is almost certainly right — they paid —
-- but it is a real change in what deletion means, and it is written here rather
-- than discovered later. Deletion is not, and after this cannot be, a way to
-- revoke access to a sold digital good.
--
-- ── NULLABLE, NO DEFAULT ──────────────────────────────────────────────────
--
-- Every order written before this migration has no snapshot, and NULL is the
-- honest thing for those rows to say. The download route falls back to the
-- foreign-key join whenever the snapshot is absent, so they keep working
-- exactly as they do now. Nothing is backfilled: the snapshot means "this is
-- what was bought, recorded at the time", and a value copied from the listing
-- today would be a claim about the past that nobody measured.
--
-- ── SAFETY ────────────────────────────────────────────────────────────────
--
-- Purely additive. ADD COLUMN IF NOT EXISTS, so a second run is a no-op. No
-- column is altered or dropped, no row is written, updated or deleted, and no
-- existing migration is renumbered — 112 was the highest before this.

ALTER TABLE public.marketplace_orders
  ADD COLUMN IF NOT EXISTS digital_file_path text,
  ADD COLUMN IF NOT EXISTS digital_file_name text;

COMMENT ON COLUMN public.marketplace_orders.digital_file_path IS
  'Snapshot, taken when the order was recorded, of marketplace_listings.digital_file_path — the object key inside the PRIVATE bf-digital-goods bucket. Exists so an order can serve its own download without the listing still being there: GET /api/purchases/:orderId/download prefers this and only falls back to joining through listing_id when it is NULL. NULL means either a non-digital purchase or an order written before migration 113, and neither is backfilled. Never served to a buyer directly; it is signed into a time-limited URL exactly as the listing column is.';

COMMENT ON COLUMN public.marketplace_orders.digital_file_name IS
  'Snapshot of marketplace_listings.digital_file_name, the filename the buyer sees on their download. NULL for a non-digital purchase or an order predating migration 113. Paired with digital_file_path; see that column''s comment.';
