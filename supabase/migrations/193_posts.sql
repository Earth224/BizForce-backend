-- P2-3A (Nov 20 2026): posts and their photos. Drafted in P2-0 as 192; shifted to 193
-- because 192 is the purchase fix.
-- Safe to re-run: CREATE TABLE / CREATE INDEX IF NOT EXISTS, and each named CHECK is
-- dropped if it exists before it is added.
-- Paste-safe: no less-or-equal or greater-or-equal operators; limits are written as
-- "< N+1" or BETWEEN.
--
-- 1. posts: one row per post. kind says what it shows; listing_id, campaign_id,
--    card_id and source_proposal_id link what it sells or came from, and are SET NULL
--    when that thing is deleted, so the post stays. New posts start 'pending' (the
--    policy screen and the moderation queue decide). place_* is copied from the
--    profile at publish, only if the member opted in to local. The counters are kept
--    by the triggers in 194 (tip_bfc_total by the tip function in 195).
-- 2. post_media: up to four files per post (idx 0 to 3). media_id and thumb_media_id
--    are member_media rows ON DELETE RESTRICT: a file a post uses cannot be deleted.
--
-- The old posts table (migration 123) was dropped; this is a new table, not a revival.
-- Members never read these tables directly: every read and write goes through Express
-- routes. Row level security is on with no policies and anon/authenticated are revoked
-- (as in 110, 189 and 191).
BEGIN;

-- 1. posts
CREATE TABLE IF NOT EXISTS public.posts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  author_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  kind text NOT NULL,
  body text NOT NULL DEFAULT '',
  listing_id uuid REFERENCES public.marketplace_listings(id) ON DELETE SET NULL,
  campaign_id uuid REFERENCES public.crowdfunding_campaigns(id) ON DELETE SET NULL,
  card_id uuid REFERENCES public.digital_cards(id) ON DELETE SET NULL,
  source_proposal_id uuid REFERENCES public.agent_proposals(id) ON DELETE SET NULL,
  audience text NOT NULL DEFAULT 'public',
  status text NOT NULL DEFAULT 'pending',
  place_city text,
  place_region text,
  place_country char(2),
  like_count int NOT NULL DEFAULT 0,
  comment_count int NOT NULL DEFAULT 0,
  save_count int NOT NULL DEFAULT 0,
  share_count int NOT NULL DEFAULT 0,
  tip_bfc_total int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  removed_at timestamptz,
  removed_reason text
);
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_kind_allowed;
ALTER TABLE public.posts ADD CONSTRAINT posts_kind_allowed
  CHECK (kind IN ('text','photo','video','product','service','listing','campaign','garage','card'));
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_body_length;
ALTER TABLE public.posts ADD CONSTRAINT posts_body_length
  CHECK (char_length(body) < 2201);
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_audience_allowed;
ALTER TABLE public.posts ADD CONSTRAINT posts_audience_allowed
  CHECK (audience IN ('public','followers'));
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_status_allowed;
ALTER TABLE public.posts ADD CONSTRAINT posts_status_allowed
  CHECK (status IN ('draft','pending','published','hidden','removed'));
CREATE INDEX IF NOT EXISTS posts_feed_idx ON public.posts (published_at DESC)
  WHERE status = 'published';
CREATE INDEX IF NOT EXISTS posts_author_idx ON public.posts (author_id, created_at DESC);
CREATE INDEX IF NOT EXISTS posts_market_idx ON public.posts (published_at DESC)
  WHERE status = 'published' AND (listing_id IS NOT NULL OR campaign_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS posts_local_idx
  ON public.posts (place_country, place_region, place_city, published_at DESC)
  WHERE status = 'published';

-- 2. post_media
CREATE TABLE IF NOT EXISTS public.post_media (
  post_id uuid NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  media_id uuid NOT NULL REFERENCES public.member_media(id) ON DELETE RESTRICT,
  thumb_media_id uuid REFERENCES public.member_media(id) ON DELETE RESTRICT,
  idx smallint NOT NULL,
  PRIMARY KEY (post_id, idx)
);
ALTER TABLE public.post_media DROP CONSTRAINT IF EXISTS post_media_idx_range;
ALTER TABLE public.post_media ADD CONSTRAINT post_media_idx_range
  CHECK (idx BETWEEN 0 AND 3);
CREATE INDEX IF NOT EXISTS post_media_media_idx ON public.post_media (media_id);

-- 3. no direct member access
ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.post_media ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.posts FROM anon, authenticated;
REVOKE ALL ON public.post_media FROM anon, authenticated;

COMMIT;
