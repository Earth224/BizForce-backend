-- Not yet applied. The owner applies it by hand in the Supabase SQL editor.
-- TK1: a video's length, for TikTok's rule that "API clients must check if the
-- duration of the to-be-posted video follows the max_video_post_duration_sec
-- returned in the creator_info API." (developers.tiktok.com/docs/en/
-- content-sharing-guidelines). duration_ms is read from the file on the server
-- when the video is added (the MP4/MOV mvhd box), or, for a file whose length
-- the server cannot read (WebM, or no mvhd), a browser-measured length the
-- server sanity-checks. NULL means the length is not known: a TikTok post of
-- such a video is refused with a plain message rather than sent unchecked.
-- Rows added before this migration keep NULL. member_videos has no jsonb field
-- to hold this, so it is a column. The CHECK allows 1 ms to 4 hours. RLS is
-- unchanged.
BEGIN;

ALTER TABLE public.member_videos
  ADD COLUMN IF NOT EXISTS duration_ms integer NULL;

ALTER TABLE public.member_videos
  DROP CONSTRAINT IF EXISTS member_videos_duration_check;
ALTER TABLE public.member_videos
  ADD CONSTRAINT member_videos_duration_check CHECK (duration_ms IS NULL OR (duration_ms > 0 AND duration_ms <= 14400000));

COMMIT;
