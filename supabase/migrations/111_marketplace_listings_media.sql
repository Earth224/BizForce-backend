-- 111_marketplace_listings_media.sql
--
-- DOCUMENT marketplace_listings.media, WHICH EXISTS AND NEVER HAD DDL.
--
-- The column has been live, written, read and rendered for as long as the
-- storefront has had images, and no migration in this directory creates it.
-- Migration 006 creates the table without it; 033, 042, 051, 055 and 057 are
-- the only ALTERs and none adds it. A database rebuilt from this directory
-- would come up without the column, and three writers and two read routes
-- would start failing at once.
--
-- This file adds nothing to the live database. It makes the directory describe
-- what is actually there.
--
-- ── THE DEFINITION, READ RATHER THAN INFERRED ─────────────────────────────
--
-- From information_schema.columns on the live database:
--
--   column_name | data_type | is_nullable | column_default
--   media       | jsonb     | NO          | '[]'::jsonb
--
-- THE INFERRED VALUE TURNED OUT TO BE RIGHT. THAT IS NOT A VINDICATION OF THE
-- INFERENCE, and it is worth writing down precisely because it is the outcome
-- that makes the shortcut look harmless next time.
--
-- The inference available before this read was: PostgREST reports format
-- "jsonb" and lists media among the table's required properties, which is how
-- it describes NOT NULL. Both of those held. The DEFAULT did not come from
-- there at all — PostgREST reported no default for media, and the guess
-- '[]'::jsonb came from the neighbouring crowdfunding_campaigns.media in
-- migration 031 and from every live row holding [].
--
-- THE CONTROL CASE STILL STANDS. That same PostgREST description also reports
-- no default for `tags`, and migration 006 shows tags is
-- `text[] NOT NULL DEFAULT '{}'`. So "PostgREST reports no default" is not
-- evidence of "there is no default" — it is evidence of nothing, for this
-- class of column. Had the guess been written into a migration it would have
-- been correct by luck, indistinguishable from correct by measurement, and the
-- next column documented the same way would have had the same odds and no
-- warning attached. The definition below is recorded because it was read.
--
-- ── IDEMPOTENT ────────────────────────────────────────────────────────────
--
-- ADD COLUMN IF NOT EXISTS: a no-op against the live database, where the
-- column already exists with exactly this definition, and correct in a rebuilt
-- one. Running it twice changes nothing the second time. No data is written, no
-- data is deleted, no column is dropped, and no existing file is renumbered —
-- 110 was the highest before this.

ALTER TABLE public.marketplace_listings
  ADD COLUMN IF NOT EXISTS media jsonb NOT NULL DEFAULT '[]'::jsonb;

-- ── THE CONTRACT, WHICH LIVES IN CODE AND NOT IN A CONSTRAINT ─────────────
--
-- Recorded here because nothing in the database enforces it. jsonb will accept
-- any shape at all; what keeps this column to the shape below is a single
-- function in server.js, and a reader of the schema alone would have no way to
-- know that.

COMMENT ON COLUMN public.marketplace_listings.media IS
  'Ordered array of media attachments for the listing, rendered by the storefront. Each entry is an object {url, type, name}: url is an https:// URL (entries whose url is missing, non-string or not https:// are dropped, so http:// and data: URIs cannot be stored); type is the MIME type, truncated to 100 characters, "" when absent; name is the original filename, truncated to 200 characters, "" when absent. AT MOST 12 ENTRIES — the array is truncated, not rejected, past that. NONE OF THIS IS ENFORCED BY THE DATABASE: jsonb accepts any shape, and the contract is imposed entirely by sanitizeMedia() in server.js, which also coerces a non-array input to []. The three writers that reach this column all pass through it — POST /api/marketplace/listings, PUT /api/marketplace/listings/:id, and the publish_listing proposal handler via insertListingWithSlug — so a direct write with the service key, bypassing those routes, can put any JSON here and nothing will object. Read by GET /api/marketplace/listings and GET /api/marketplace/listings/:id. URLs point at the PUBLIC bf-public storage bucket and are fetchable by anyone; unlike digital_file_path this column holds nothing private.';
