-- 155_member_music.sql — a member's own music library and playlists, and the
-- private bucket the files live in.
--
-- WHY. The BizForce music player (frontend scripts/bf-music.js): members upload
-- their own music, build playlists and play them on the dashboard, in a
-- mini-bar on every app page, or in a pop-out window. bf_music_tracks
-- (migration 009) was not reused: it is the PUBLIC profile music, readable by
-- anyone (its RLS allows SELECT to all) and stored as public URLs in
-- bf-public. A library is private to its member.
--
-- 1. member_tracks: one row per uploaded file. storage_path is the file's
--    place in bf-music, always `<the member's id>/<time>.<ext>` (the CHECK
--    below; lib/music.js ownTrackPath is the same rule in the API). The size
--    limit is lib/music.js FILE_MAX_BYTES (25 MB); the per-member total
--    (MEMBER_TOTAL_BYTES, 250 MB) is enforced by the API before upload.
-- 2. member_playlists: a name and its tracks, in order (track_ids). The API
--    accepts only the member's own track ids, and deleting a track takes it
--    out of every playlist.
-- 3. The bf-music bucket: PRIVATE (no public URLs; playback is by signed URLs
--    that expire), 25 MB per object, audio types only.
--
-- Both tables are in the data export (metadata only: never the storage path
-- or the audio) and deleted with the account (lib/yourData.js); the files are
-- removed with it by lib/accountFiles.js, which lists bf-music/<member id>/.
--
-- RLS is on with no policies, so only the service role (the server) reads or
-- writes either table.

-- ── 1 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.member_tracks (
  id             uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid          NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  title          text          NOT NULL,
  artist         text,
  duration_secs  numeric(9,3),
  storage_path   text          NOT NULL UNIQUE,
  mime           text          NOT NULL,
  size_bytes     bigint        NOT NULL,
  created_at     timestamptz   NOT NULL DEFAULT now(),
  updated_at     timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT member_tracks_title_check CHECK (char_length(title) BETWEEN 1 AND 200),
  CONSTRAINT member_tracks_artist_check CHECK (artist IS NULL OR char_length(artist) BETWEEN 1 AND 200),
  CONSTRAINT member_tracks_duration_check CHECK (duration_secs IS NULL OR (duration_secs > 0 AND duration_secs <= 86400)),
  CONSTRAINT member_tracks_size_check CHECK (size_bytes BETWEEN 1 AND 26214400),
  CONSTRAINT member_tracks_mime_check CHECK (mime IN ('audio/mpeg', 'audio/mp4', 'audio/aac', 'audio/ogg', 'audio/flac', 'audio/wav')),
  CONSTRAINT member_tracks_own_folder_check CHECK (storage_path LIKE user_id::text || '/%')
);

CREATE INDEX IF NOT EXISTS member_tracks_user_idx
  ON public.member_tracks (user_id, created_at);

ALTER TABLE public.member_tracks ENABLE ROW LEVEL SECURITY;

-- ── 2 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.member_playlists (
  id          uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid          NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  name        text          NOT NULL,
  track_ids   uuid[]        NOT NULL DEFAULT '{}',
  created_at  timestamptz   NOT NULL DEFAULT now(),
  updated_at  timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT member_playlists_name_check CHECK (char_length(name) BETWEEN 1 AND 80),
  CONSTRAINT member_playlists_tracks_check CHECK (cardinality(track_ids) <= 500)
);

CREATE INDEX IF NOT EXISTS member_playlists_user_idx
  ON public.member_playlists (user_id, created_at);

ALTER TABLE public.member_playlists ENABLE ROW LEVEL SECURITY;

-- ── 3 ───────────────────────────────────────────────────────────────────────
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('bf-music', 'bf-music', false, 26214400,
        ARRAY['audio/mpeg', 'audio/mp4', 'audio/aac', 'audio/ogg', 'audio/flac', 'audio/wav'])
ON CONFLICT (id) DO UPDATE
  SET public = false,
      file_size_limit = EXCLUDED.file_size_limit,
      allowed_mime_types = EXCLUDED.allowed_mime_types;
