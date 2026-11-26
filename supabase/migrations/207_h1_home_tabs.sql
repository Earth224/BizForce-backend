-- ===== PART 207a: the place lookup cache (run first) =====
-- H1 (Nov 25 2026): lib/geo.js turns a typed place ("San Diego, CA, US") into its city centre point with the free
-- OpenStreetMap Nominatim service, at most once per place: every answer is kept here, keyed by the normalized place text
-- (lower case, single spaces). found is false when Nominatim answered with nothing, so that place is not asked again.
-- The point is rounded to 2 decimals (about 1 km). This is not member data: no member id, only place names and points.
-- The server writes it with the service key; members never read it, so row level security is on with no policies and
-- anon and authenticated are revoked.
-- Paste-safe: no less-or-equal or greater-or-equal operators, no DO blocks, no transaction statements; every CHECK is
-- named and dropped if it exists first. Each part runs alone, in order: 207a, 207b, 207c, 207d, 207e.
CREATE TABLE IF NOT EXISTS public.geo_cache (
  place_key    text PRIMARY KEY,
  lat          numeric(5,2),
  lng          numeric(5,2),
  found        boolean NOT NULL DEFAULT false,
  looked_up_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.geo_cache DROP CONSTRAINT IF EXISTS geo_cache_key_check;
ALTER TABLE public.geo_cache ADD CONSTRAINT geo_cache_key_check CHECK (char_length(place_key) BETWEEN 1 AND 300);
ALTER TABLE public.geo_cache DROP CONSTRAINT IF EXISTS geo_cache_point_check;
ALTER TABLE public.geo_cache ADD CONSTRAINT geo_cache_point_check
  CHECK ((found AND lat BETWEEN -90 AND 90 AND lng BETWEEN -180 AND 180) OR (NOT found AND lat IS NULL AND lng IS NULL));
ALTER TABLE public.geo_cache ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.geo_cache FROM anon, authenticated;

-- ===== PART 207b: the city centre points (run second) =====
-- The profile place's point (Settings, Local) and a Need's own place's point, 2 decimals, city level only, never a
-- street address. NULL when the place is empty or the lookup found nothing or failed (Local then matches the city's
-- name as text). bf_profiles and posts already have row level security on; these columns are read only by the server
-- (Local, Market and the follow suggestions show a rounded distance, never the point) and are in the member's export.
ALTER TABLE public.bf_profiles ADD COLUMN IF NOT EXISTS place_lat numeric(5,2);
ALTER TABLE public.bf_profiles ADD COLUMN IF NOT EXISTS place_lng numeric(5,2);
ALTER TABLE public.bf_profiles DROP CONSTRAINT IF EXISTS bf_profiles_place_point_check;
ALTER TABLE public.bf_profiles ADD CONSTRAINT bf_profiles_place_point_check
  CHECK ((place_lat IS NULL AND place_lng IS NULL) OR (place_lat BETWEEN -90 AND 90 AND place_lng BETWEEN -180 AND 180));
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS need_lat numeric(5,2);
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS need_lng numeric(5,2);
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_need_point_check;
ALTER TABLE public.posts ADD CONSTRAINT posts_need_point_check
  CHECK ((need_lat IS NULL AND need_lng IS NULL) OR (need_lat BETWEEN -90 AND 90 AND need_lng BETWEEN -180 AND 180));
CREATE INDEX IF NOT EXISTS bf_profiles_place_point_idx ON public.bf_profiles (place_lat, place_lng) WHERE local_opt_in;

-- ===== PART 207c: Home's choices, per member (run third) =====
-- Local's reach (city: My city; 25: Within 25 mi, the default; anywhere) and "Use a different city" (the typed city and
-- its point), and when the member last opened Market (the Market dot shows only for listings newer than that). One row
-- per member, written by the server; in the member's export and deleted with the account.
CREATE TABLE IF NOT EXISTS public.home_prefs (
  user_id        uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  local_reach    text,
  local_place    text,
  local_lat      numeric(5,2),
  local_lng      numeric(5,2),
  market_seen_at timestamptz,
  updated_at     timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.home_prefs DROP CONSTRAINT IF EXISTS home_prefs_reach_check;
ALTER TABLE public.home_prefs ADD CONSTRAINT home_prefs_reach_check CHECK (local_reach IS NULL OR local_reach IN ('city', '25', 'anywhere'));
ALTER TABLE public.home_prefs DROP CONSTRAINT IF EXISTS home_prefs_place_check;
ALTER TABLE public.home_prefs ADD CONSTRAINT home_prefs_place_check CHECK (local_place IS NULL OR char_length(local_place) BETWEEN 2 AND 80);
ALTER TABLE public.home_prefs DROP CONSTRAINT IF EXISTS home_prefs_point_check;
ALTER TABLE public.home_prefs ADD CONSTRAINT home_prefs_point_check
  CHECK ((local_lat IS NULL AND local_lng IS NULL) OR (local_lat BETWEEN -90 AND 90 AND local_lng BETWEEN -180 AND 180));
ALTER TABLE public.home_prefs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.home_prefs FROM anon, authenticated;

-- ===== PART 207d: Like and Save on listings (run fourth) =====
-- The Market tab's Like and Save, with the same rules as posts' (lib/homeTabs.js): one per member per listing, a block
-- either way refuses, 200 likes an hour. Saved listings are private to the member. Both go with the listing or the
-- account, are in the member's export and are deleted with the account.
CREATE TABLE IF NOT EXISTS public.listing_likes (
  listing_id uuid NOT NULL REFERENCES public.marketplace_listings(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (listing_id, user_id)
);
CREATE INDEX IF NOT EXISTS listing_likes_user_idx ON public.listing_likes (user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS public.listing_saves (
  listing_id uuid NOT NULL REFERENCES public.marketplace_listings(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (listing_id, user_id)
);
CREATE INDEX IF NOT EXISTS listing_saves_user_idx ON public.listing_saves (user_id, created_at DESC);
ALTER TABLE public.listing_likes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.listing_saves ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.listing_likes FROM anon, authenticated;
REVOKE ALL ON public.listing_saves FROM anon, authenticated;

-- ===== PART 207e: Search's trigram indexes (run fifth) =====
-- lib/search.js matches text with ILIKE '%...%', which a trigram index serves (pg_trgm, free in Supabase, kept in the
-- extensions schema). Names and handles, business names, listing titles and descriptions, and post text.
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions;
CREATE INDEX IF NOT EXISTS bf_profiles_username_trgm_idx ON public.bf_profiles USING gin (username extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS bf_profiles_display_name_trgm_idx ON public.bf_profiles USING gin (display_name extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS profiles_business_name_trgm_idx ON public.profiles USING gin (business_name extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS marketplace_listings_title_trgm_idx ON public.marketplace_listings USING gin (title extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS marketplace_listings_description_trgm_idx ON public.marketplace_listings USING gin (description extensions.gin_trgm_ops);
CREATE INDEX IF NOT EXISTS posts_body_trgm_idx ON public.posts USING gin (body extensions.gin_trgm_ops);
