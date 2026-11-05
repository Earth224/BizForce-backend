-- 168_social_post_images.sql
-- Applied by the owner by hand in the Supabase SQL editor on Nov 5, 2026. This file is the text as run.
--
-- Images from a member's Media Library in their Bluesky and Mastodon posts:
-- social_post_drafts.media_ids holds the chosen member_media ids, in order, at
-- most 4; member_mastodon_connections keeps the server's image size limit and
-- alt text (description) limit, read on connect from /api/v2/instance.

ALTER TABLE public.social_post_drafts
  ADD COLUMN IF NOT EXISTS media_ids uuid[] NOT NULL DEFAULT '{}'::uuid[];

ALTER TABLE public.social_post_drafts
  ADD CONSTRAINT social_post_drafts_media_ids_check CHECK (cardinality(media_ids) <= 4);

CREATE INDEX IF NOT EXISTS social_post_drafts_media_ids_idx
  ON public.social_post_drafts USING gin (media_ids);

ALTER TABLE public.member_mastodon_connections
  ADD COLUMN IF NOT EXISTS image_size_limit integer NOT NULL DEFAULT 16777216,
  ADD COLUMN IF NOT EXISTS media_description_limit integer NOT NULL DEFAULT 1500;

ALTER TABLE public.member_mastodon_connections
  ADD CONSTRAINT member_mastodon_connections_image_size_check CHECK (image_size_limit BETWEEN 1 AND 104857600),
  ADD CONSTRAINT member_mastodon_connections_media_desc_check CHECK (media_description_limit BETWEEN 1 AND 100000);
