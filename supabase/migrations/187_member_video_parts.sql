-- Not yet applied. The owner applies it by hand in the Supabase SQL editor.
-- BV1: videos up to 500 MB, stored as parts within the Supabase Free plan.
-- Supabase: "For Free projects, the limit can't exceed 50 MB."
-- (supabase.com/docs/guides/storage/uploads/file-limits), so a video over
-- 50 MB is kept as up to 12 objects ("parts") of at most 45 MiB
-- (47185920 bytes) each, in order. The bf-video bucket's file_size_limit
-- stays 52428800: every part fits under it, and nothing needs a paid plan.
--
-- 1. member_videos.bytes may now be up to 500 MiB (524288000). It is still
--    the whole video's size, and sha256 is still the whole video's hash.
-- 2. member_videos.part_count: how many parts make the video. 1 is a video
--    stored as one object at path, which is every row added before this
--    migration (DEFAULT 1), so nothing already stored changes.
-- 3. member_video_parts: one row per part, written as each part is checked
--    (its size and sha256), before the video's row exists. upload_path is the
--    video's path (part 0 is stored at it, so the preview plays the start);
--    parts 1.. are stored at <path without extension>.p<NN>.<ext>. video_id is
--    set when the video is finalized. Deleting the video's row deletes its
--    part rows (the objects are removed by the server first, as today).
-- RLS: enabled, and anon and authenticated get nothing; only the server's
-- service role reads or writes these rows, as with member_videos.
BEGIN;

ALTER TABLE public.member_videos
  DROP CONSTRAINT IF EXISTS member_videos_bytes_check;
ALTER TABLE public.member_videos
  ADD CONSTRAINT member_videos_bytes_check CHECK (bytes > 0 AND bytes <= 524288000);

ALTER TABLE public.member_videos
  ADD COLUMN IF NOT EXISTS part_count smallint NOT NULL DEFAULT 1;
ALTER TABLE public.member_videos
  DROP CONSTRAINT IF EXISTS member_videos_part_count_check;
ALTER TABLE public.member_videos
  ADD CONSTRAINT member_videos_part_count_check CHECK (part_count >= 1 AND part_count <= 12);

CREATE TABLE IF NOT EXISTS public.member_video_parts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  video_id uuid NULL REFERENCES public.member_videos(id) ON DELETE CASCADE,
  upload_path text NOT NULL,
  idx smallint NOT NULL,
  path text NOT NULL UNIQUE,
  bytes bigint NOT NULL,
  sha256 text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_video_parts_idx_check CHECK (idx >= 0 AND idx <= 11),
  CONSTRAINT member_video_parts_bytes_check CHECK (bytes > 0 AND bytes <= 47185920),
  CONSTRAINT member_video_parts_sha_check CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT member_video_parts_upload_path_check CHECK (
    upload_path ~ '^video/[0-9a-f-]{36}/[0-9a-f]{32}\.(mp4|webm|mov)$' AND upload_path LIKE 'video/' || user_id::text || '/%'),
  CONSTRAINT member_video_parts_path_check CHECK (
    path ~ '^video/[0-9a-f-]{36}/[0-9a-f]{32}(\.p[0-9]{2})?\.(mp4|webm|mov)$' AND path LIKE 'video/' || user_id::text || '/%'),
  CONSTRAINT member_video_parts_order_unique UNIQUE (upload_path, idx)
);

CREATE INDEX IF NOT EXISTS member_video_parts_video_idx ON public.member_video_parts (video_id, idx);
CREATE INDEX IF NOT EXISTS member_video_parts_user_created_idx ON public.member_video_parts (user_id, created_at);

ALTER TABLE public.member_video_parts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.member_video_parts FROM anon, authenticated;

COMMIT;
