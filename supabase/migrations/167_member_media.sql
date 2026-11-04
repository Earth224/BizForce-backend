-- 167_member_media.sql — a member's own Media Library (build list item 4).
--
-- Applied by the owner by hand in the Supabase SQL editor on Nov 4, 2026. This file is the text as run.
--
-- One row per file a member added to their Media Library. The file itself is
-- in the public bf-public bucket at media/<user id>/<32 random hex>.<ext>
-- (lib/memberMedia.js mediaPath; the path CHECK below is the same pattern),
-- uploaded through the server by POST /api/media, which decides the type by
-- the file's first bytes and removes location and camera details from JPEG,
-- PNG and WebP photos before storing them. sha256 is of the stored bytes: the
-- same file added twice is one row (member_media_user_sha_key).
--
-- The verify after it ran: rls_on true, 11 columns, 8 check constraints,
-- 2 unique constraints, and the index member_media_user_created_idx.
--
-- RLS on with no policies, as 142 records for its tables: the server uses the
-- service role, and no page talks to Supabase directly.

CREATE TABLE public.member_media (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  path text NOT NULL UNIQUE,
  kind text NOT NULL CHECK (kind IN ('image', 'video')),
  mime text NOT NULL CHECK (mime IN ('image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm')),
  bytes integer NOT NULL CHECK (bytes > 0 AND bytes <= 10485760),
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  alt_text text NOT NULL DEFAULT '' CHECK (char_length(alt_text) <= 1000),
  label text NOT NULL DEFAULT '' CHECK (char_length(label) <= 120),
  metadata_stripped boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_media_path_check CHECK (path ~ '^media/[0-9a-f-]{36}/[0-9a-f]{32}\.(jpg|png|webp|gif|mp4|webm)$'),
  CONSTRAINT member_media_path_owner_check CHECK (path LIKE 'media/' || user_id::text || '/%'),
  CONSTRAINT member_media_user_sha_key UNIQUE (user_id, sha256)
);

CREATE INDEX member_media_user_created_idx ON public.member_media (user_id, created_at DESC);

ALTER TABLE public.member_media ENABLE ROW LEVEL SECURITY;
