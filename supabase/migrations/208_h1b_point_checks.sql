-- ===== PART 208a: geo_cache's point rule (run first) =====
-- H1B (Nov 25 2026): 207's four point CHECKs let half a point through. A CHECK that comes out NULL passes, and
-- "lat BETWEEN ... AND lng BETWEEN ..." is NULL when lng is NULL, so a latitude with no longitude was accepted (proven live
-- on home_prefs, posts and geo_cache; each test row deleted). Each rule is replaced, same name, saying outright that both
-- values must be present; IS NOT NULL is never NULL. No table, column or data changes; no live row held a point.
-- Paste-safe: no less-or-equal or greater-or-equal operators, no DO blocks, no transaction statements. Each part runs alone,
-- in order: 208a, 208b, 208c, 208d. Applied live by the owner on Nov 25 2026.
ALTER TABLE public.geo_cache DROP CONSTRAINT IF EXISTS geo_cache_point_check;
ALTER TABLE public.geo_cache ADD CONSTRAINT geo_cache_point_check
  CHECK ((found AND lat IS NOT NULL AND lng IS NOT NULL AND lat BETWEEN -90 AND 90 AND lng BETWEEN -180 AND 180) OR (NOT found AND lat IS NULL AND lng IS NULL));

-- ===== PART 208b: bf_profiles' place point rule (run second) =====
ALTER TABLE public.bf_profiles DROP CONSTRAINT IF EXISTS bf_profiles_place_point_check;
ALTER TABLE public.bf_profiles ADD CONSTRAINT bf_profiles_place_point_check
  CHECK ((place_lat IS NULL AND place_lng IS NULL) OR (place_lat IS NOT NULL AND place_lng IS NOT NULL AND place_lat BETWEEN -90 AND 90 AND place_lng BETWEEN -180 AND 180));

-- ===== PART 208c: posts' Need point rule (run third) =====
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_need_point_check;
ALTER TABLE public.posts ADD CONSTRAINT posts_need_point_check
  CHECK ((need_lat IS NULL AND need_lng IS NULL) OR (need_lat IS NOT NULL AND need_lng IS NOT NULL AND need_lat BETWEEN -90 AND 90 AND need_lng BETWEEN -180 AND 180));

-- ===== PART 208d: home_prefs' chosen-city point rule (run fourth) =====
ALTER TABLE public.home_prefs DROP CONSTRAINT IF EXISTS home_prefs_point_check;
ALTER TABLE public.home_prefs ADD CONSTRAINT home_prefs_point_check
  CHECK ((local_lat IS NULL AND local_lng IS NULL) OR (local_lat IS NOT NULL AND local_lng IS NOT NULL AND local_lat BETWEEN -90 AND 90 AND local_lng BETWEEN -180 AND 180));
