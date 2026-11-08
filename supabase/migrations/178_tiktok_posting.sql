-- Applied by the owner by hand in the Supabase SQL editor on Nov 7, 2026. This file is the text as run.

CREATE TABLE public.member_tiktok_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
  open_id text NOT NULL,
  display_name text NOT NULL,
  refresh_ciphertext text NOT NULL,
  refresh_iv text NOT NULL,
  refresh_auth_tag text NOT NULL,
  access_ciphertext text NOT NULL,
  access_iv text NOT NULL,
  access_auth_tag text NOT NULL,
  access_expires_at timestamptz NOT NULL,
  refresh_expires_at timestamptz,
  token_version integer NOT NULL DEFAULT 0,
  granted_scopes text,
  status text NOT NULL DEFAULT 'connected',
  last_ok_at timestamptz,
  last_error_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_tiktok_connections_open_id_check CHECK (open_id ~ '^[A-Za-z0-9_.-]{1,100}$'),
  CONSTRAINT member_tiktok_connections_display_name_check CHECK (char_length(display_name) BETWEEN 1 AND 200),
  CONSTRAINT member_tiktok_connections_refresh_check CHECK (refresh_ciphertext ~ '^[0-9a-f]+$' AND refresh_iv ~ '^[0-9a-f]{24}$' AND refresh_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT member_tiktok_connections_access_check CHECK (access_ciphertext ~ '^[0-9a-f]+$' AND access_iv ~ '^[0-9a-f]{24}$' AND access_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT member_tiktok_connections_token_version_check CHECK (token_version >= 0),
  CONSTRAINT member_tiktok_connections_scopes_check CHECK (granted_scopes IS NULL OR (char_length(granted_scopes) <= 500 AND granted_scopes ~ '^[a-z0-9_.,]*$')),
  CONSTRAINT member_tiktok_connections_status_check CHECK (status IN ('connected', 'needs_reconnect')),
  CONSTRAINT member_tiktok_connections_error_code_check CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 60)
);

ALTER TABLE public.member_tiktok_connections ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.member_tiktok_connections FROM anon, authenticated;

ALTER TABLE public.member_videos
  ADD COLUMN IF NOT EXISTS tiktok_publish_id text,
  ADD COLUMN IF NOT EXISTS tiktok_status text,
  ADD COLUMN IF NOT EXISTS tiktok_posted_at timestamptz,
  ADD COLUMN IF NOT EXISTS tiktok_post_id text,
  ADD COLUMN IF NOT EXISTS tiktok_upload_ciphertext text,
  ADD COLUMN IF NOT EXISTS tiktok_upload_iv text,
  ADD COLUMN IF NOT EXISTS tiktok_upload_auth_tag text,
  ADD COLUMN IF NOT EXISTS tiktok_upload_expires_at timestamptz;

ALTER TABLE public.member_videos
  ADD CONSTRAINT member_videos_tiktok_publish_id_check CHECK (tiktok_publish_id IS NULL OR tiktok_publish_id ~ '^[A-Za-z0-9_.~-]{1,64}$'),
  ADD CONSTRAINT member_videos_tiktok_status_check CHECK (tiktok_status IS NULL OR tiktok_status IN ('initiated', 'processing', 'posted', 'failed')),
  ADD CONSTRAINT member_videos_tiktok_post_id_check CHECK (tiktok_post_id IS NULL OR tiktok_post_id ~ '^[0-9]{1,64}$'),
  ADD CONSTRAINT member_videos_tiktok_upload_check CHECK (
    (tiktok_upload_ciphertext IS NULL AND tiktok_upload_iv IS NULL AND tiktok_upload_auth_tag IS NULL AND tiktok_upload_expires_at IS NULL)
    OR (tiktok_upload_ciphertext ~ '^[0-9a-f]+$' AND tiktok_upload_iv ~ '^[0-9a-f]{24}$' AND tiktok_upload_auth_tag ~ '^[0-9a-f]{32}$' AND tiktok_upload_expires_at IS NOT NULL)
  );

ALTER TABLE public.oauth_states
  DROP CONSTRAINT oauth_states_purpose_check,
  DROP CONSTRAINT oauth_states_verifier_shape_check;

ALTER TABLE public.oauth_states
  ADD CONSTRAINT oauth_states_purpose_check CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google', 'tiktok_login')),
  ADD CONSTRAINT oauth_states_verifier_shape_check CHECK (
    purpose IN ('store_shopify', 'tiktok_login')
    OR (verifier_ciphertext IS NOT NULL AND verifier_iv IS NOT NULL AND verifier_auth_tag IS NOT NULL)
  );
