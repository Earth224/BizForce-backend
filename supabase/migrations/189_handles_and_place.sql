-- P2-1 (Nov 19 2026): one handle per member, and a coarse place for the Local feed.
-- Safe to re-run: CREATE TABLE / ADD COLUMN / CREATE INDEX IF NOT EXISTS, ON CONFLICT
-- DO NOTHING, and each named CHECK is dropped if it exists before it is added.
--
-- 1. bf_profiles.username becomes THE member handle (/@handle, the storefront,
--    support links). Migration 040's unique index on lower(username) stays. The new
--    CHECK fixes the format: 3 to 30 characters, lowercase letters, digits, '_' and
--    '-', not starting with '-'. NULL means no handle yet.
--    Checked live before writing (Nov 19 2026): the one bf_profiles row has the
--    username 'earth-rose', which passes, is not reserved and has no case duplicate.
-- 2. reserved_handles: names no member may take. The server reads it; members never
--    do, so row level security is on with no policies and anon/authenticated are
--    revoked (as in migration 110).
-- 3. place_city, place_region, place_country (ISO 3166-1 alpha-2, uppercase) and
--    local_opt_in: typed by the member, never taken from a device. Posts copy them
--    only while local_opt_in is true, and the partial index serves the Local feed.
--    These columns are part of the member's bf_profiles row, so they belong in the
--    data export and are deleted with the account like the rest of that row
--    (lib/yourData.js).
BEGIN;

ALTER TABLE public.bf_profiles DROP CONSTRAINT IF EXISTS bf_profiles_username_format;
ALTER TABLE public.bf_profiles ADD CONSTRAINT bf_profiles_username_format
  CHECK (username IS NULL OR username ~ '^[a-z0-9_][a-z0-9_-]{2,29}$');

CREATE TABLE IF NOT EXISTS public.reserved_handles (
  handle text PRIMARY KEY
);

ALTER TABLE public.reserved_handles DROP CONSTRAINT IF EXISTS reserved_handles_handle_lower;
ALTER TABLE public.reserved_handles ADD CONSTRAINT reserved_handles_handle_lower
  CHECK (handle = lower(handle));

INSERT INTO public.reserved_handles (handle) VALUES
  ('admin'), ('bizforce'), ('support'), ('help'), ('owner'), ('termaximus'),
  ('oracle'), ('api'), ('app'), ('settings'), ('inbox'), ('home'), ('hq'),
  ('create'), ('profile'), ('market'), ('local'), ('search')
ON CONFLICT (handle) DO NOTHING;

ALTER TABLE public.reserved_handles ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.reserved_handles FROM anon, authenticated;

ALTER TABLE public.bf_profiles
  ADD COLUMN IF NOT EXISTS place_city    text,
  ADD COLUMN IF NOT EXISTS place_region  text,
  ADD COLUMN IF NOT EXISTS place_country text,
  ADD COLUMN IF NOT EXISTS local_opt_in  boolean NOT NULL DEFAULT false;

ALTER TABLE public.bf_profiles DROP CONSTRAINT IF EXISTS bf_profiles_place_city_check;
ALTER TABLE public.bf_profiles ADD CONSTRAINT bf_profiles_place_city_check
  CHECK (place_city IS NULL OR char_length(place_city) BETWEEN 1 AND 80);

ALTER TABLE public.bf_profiles DROP CONSTRAINT IF EXISTS bf_profiles_place_region_check;
ALTER TABLE public.bf_profiles ADD CONSTRAINT bf_profiles_place_region_check
  CHECK (place_region IS NULL OR char_length(place_region) BETWEEN 1 AND 80);

ALTER TABLE public.bf_profiles DROP CONSTRAINT IF EXISTS bf_profiles_place_country_check;
ALTER TABLE public.bf_profiles ADD CONSTRAINT bf_profiles_place_country_check
  CHECK (place_country IS NULL OR place_country ~ '^[A-Z]{2}$');

CREATE INDEX IF NOT EXISTS bf_profiles_place_idx
  ON public.bf_profiles (place_country, place_region, place_city)
  WHERE local_opt_in;

COMMIT;
