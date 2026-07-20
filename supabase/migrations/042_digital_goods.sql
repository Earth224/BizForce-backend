-- 042_digital_goods.sql
-- Adds digital-good delivery to the marketplace_listings -> marketplace_orders
-- lane: sellers can mark a listing as digital with a stored file, and buyers
-- receive a signed download after a completed order. Idempotent and safe to
-- re-run against a database where these columns already exist.

-- ── marketplace_listings: seller-side digital file attachment ──
ALTER TABLE public.marketplace_listings
  ADD COLUMN IF NOT EXISTS is_digital         boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS digital_file_path  text,
  ADD COLUMN IF NOT EXISTS digital_file_name  text;

-- ── marketplace_orders: buyer-side digital delivery state ──
ALTER TABLE public.marketplace_orders
  ADD COLUMN IF NOT EXISTS is_digital    boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS download_url  text,
  ADD COLUMN IF NOT EXISTS delivered_at  timestamptz;

-- ── Storage bucket ──────────────────────────────────────────────────────
-- Paid digital goods are stored in a bucket named 'bf-digital-goods',
-- matching the existing 'bf-books' private-bucket naming convention.
-- This bucket must be created manually as PRIVATE in the Supabase
-- Dashboard > Storage (buckets are not created via SQL migration).
-- marketplace_listings.digital_file_path stores the object's path within
-- this bucket; downloads are served via time-limited signed URLs, never
-- a public URL.
