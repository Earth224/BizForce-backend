-- 164: Bluesky reply references on social_post_drafts.
--
-- Applied by the owner by hand in the Supabase SQL editor on Nov 3, 2026. This file is the text as run.
--
-- A reply drafted from the Mentions inbox is filed as a social_post_drafts row
-- like any post. These four columns hold the address of the post it answers
-- (parent) and the top of that thread (root), as Bluesky gave them, so the
-- approved reply is posted in the right place. They are all empty for an
-- ordinary post, and all set (and well formed) for a Bluesky reply.

ALTER TABLE public.social_post_drafts
  ADD COLUMN IF NOT EXISTS reply_parent_uri text,
  ADD COLUMN IF NOT EXISTS reply_parent_cid text,
  ADD COLUMN IF NOT EXISTS reply_root_uri text,
  ADD COLUMN IF NOT EXISTS reply_root_cid text;
ALTER TABLE public.social_post_drafts
  ADD CONSTRAINT social_post_drafts_reply_refs_check CHECK (
    (reply_parent_uri IS NULL AND reply_parent_cid IS NULL AND reply_root_uri IS NULL AND reply_root_cid IS NULL)
    OR (
      platform = 'bluesky'
      AND char_length(reply_parent_uri) <= 1024
      AND char_length(reply_root_uri) <= 1024
      AND reply_parent_uri ~ '^at://did:[a-z]+:[A-Za-z0-9._:%-]+/app\.bsky\.feed\.post/[A-Za-z0-9._~:-]+$'
      AND reply_root_uri ~ '^at://did:[a-z]+:[A-Za-z0-9._:%-]+/app\.bsky\.feed\.post/[A-Za-z0-9._~:-]+$'
      AND reply_parent_cid ~ '^b[a-z2-7]{20,200}$'
      AND reply_root_cid ~ '^b[a-z2-7]{20,200}$'
    )
  );
