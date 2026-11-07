-- Applied by the owner by hand in the Supabase SQL editor on Nov 7, 2026. This file is the text as run.

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('bf-video', 'bf-video', false, 52428800, ARRAY['video/mp4', 'video/webm', 'video/quicktime'])
ON CONFLICT (id) DO NOTHING;

CREATE TABLE public.member_youtube_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
  channel_id text NOT NULL,
  channel_title text NOT NULL,
  refresh_ciphertext text NOT NULL,
  refresh_iv text NOT NULL,
  refresh_auth_tag text NOT NULL,
  access_ciphertext text NOT NULL,
  access_iv text NOT NULL,
  access_auth_tag text NOT NULL,
  access_expires_at timestamptz NOT NULL,
  token_version integer NOT NULL DEFAULT 0,
  granted_scopes text,
  status text NOT NULL DEFAULT 'connected',
  last_ok_at timestamptz,
  last_error_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_youtube_connections_channel_id_check CHECK (channel_id ~ '^UC[A-Za-z0-9_-]{22}$'),
  CONSTRAINT member_youtube_connections_channel_title_check CHECK (char_length(channel_title) BETWEEN 1 AND 200),
  CONSTRAINT member_youtube_connections_refresh_check CHECK (refresh_ciphertext ~ '^[0-9a-f]+$' AND refresh_iv ~ '^[0-9a-f]{24}$' AND refresh_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT member_youtube_connections_access_check CHECK (access_ciphertext ~ '^[0-9a-f]+$' AND access_iv ~ '^[0-9a-f]{24}$' AND access_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT member_youtube_connections_token_version_check CHECK (token_version >= 0),
  CONSTRAINT member_youtube_connections_scopes_check CHECK (granted_scopes IS NULL OR (char_length(granted_scopes) <= 500 AND granted_scopes ~ '^[A-Za-z0-9:/._ -]*$')),
  CONSTRAINT member_youtube_connections_status_check CHECK (status IN ('connected', 'needs_reconnect')),
  CONSTRAINT member_youtube_connections_error_code_check CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 60)
);

ALTER TABLE public.member_youtube_connections ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.member_youtube_connections FROM anon, authenticated;

CREATE TABLE public.member_videos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  path text UNIQUE,
  mime text NOT NULL,
  bytes bigint NOT NULL,
  sha256 text NOT NULL,
  label text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'ready',
  youtube_video_id text,
  session_ciphertext text,
  session_iv text,
  session_auth_tag text,
  uploaded_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_videos_mime_check CHECK (mime IN ('video/mp4', 'video/webm', 'video/quicktime')),
  CONSTRAINT member_videos_bytes_check CHECK (bytes > 0 AND bytes <= 52428800),
  CONSTRAINT member_videos_sha_check CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT member_videos_label_check CHECK (char_length(label) <= 120),
  CONSTRAINT member_videos_status_check CHECK (status IN ('ready', 'uploaded', 'removed')),
  CONSTRAINT member_videos_path_check CHECK (path IS NULL OR (path ~ '^video/[0-9a-f-]{36}/[0-9a-f]{32}\.(mp4|webm|mov)$' AND path LIKE 'video/' || user_id::text || '/%')),
  CONSTRAINT member_videos_ready_path_check CHECK (status <> 'ready' OR path IS NOT NULL),
  CONSTRAINT member_videos_youtube_id_check CHECK (youtube_video_id IS NULL OR youtube_video_id ~ '^[A-Za-z0-9_-]{11}$'),
  CONSTRAINT member_videos_session_check CHECK (
    (session_ciphertext IS NULL AND session_iv IS NULL AND session_auth_tag IS NULL)
    OR (session_ciphertext ~ '^[0-9a-f]+$' AND session_iv ~ '^[0-9a-f]{24}$' AND session_auth_tag ~ '^[0-9a-f]{32}$')
  )
);

CREATE INDEX member_videos_user_created_idx ON public.member_videos (user_id, created_at DESC);

ALTER TABLE public.member_videos ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.member_videos FROM anon, authenticated;

ALTER TABLE public.oauth_states
  DROP CONSTRAINT oauth_states_purpose_check,
  DROP CONSTRAINT oauth_states_verifier_shape_check;

ALTER TABLE public.oauth_states
  ADD CONSTRAINT oauth_states_purpose_check CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google')),
  ADD CONSTRAINT oauth_states_verifier_shape_check CHECK (
    purpose = 'store_shopify'
    OR (verifier_ciphertext IS NOT NULL AND verifier_iv IS NOT NULL AND verifier_auth_tag IS NOT NULL)
  );
