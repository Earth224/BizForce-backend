-- Applied by the owner by hand in the Supabase SQL editor on Nov 7, 2026. This file is the text as run.

CREATE TABLE public.member_instagram_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
  ig_user_id text NOT NULL,
  username text NOT NULL,
  account_type text NOT NULL,
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
  CONSTRAINT member_instagram_connections_ig_user_id_check CHECK (ig_user_id ~ '^[0-9]{1,30}$'),
  CONSTRAINT member_instagram_connections_username_check CHECK (char_length(username) BETWEEN 1 AND 100),
  CONSTRAINT member_instagram_connections_account_type_check CHECK (account_type IN ('BUSINESS', 'MEDIA_CREATOR')),
  CONSTRAINT member_instagram_connections_access_check CHECK (access_ciphertext ~ '^[0-9a-f]+$' AND access_iv ~ '^[0-9a-f]{24}$' AND access_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT member_instagram_connections_token_version_check CHECK (token_version >= 0),
  CONSTRAINT member_instagram_connections_scopes_check CHECK (granted_scopes IS NULL OR (char_length(granted_scopes) <= 500 AND granted_scopes ~ '^[a-z_,]*$')),
  CONSTRAINT member_instagram_connections_status_check CHECK (status IN ('connected', 'needs_reconnect')),
  CONSTRAINT member_instagram_connections_error_code_check CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 60)
);

ALTER TABLE public.member_instagram_connections ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.member_instagram_connections FROM anon, authenticated;

CREATE TABLE public.instagram_posts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  proposal_id uuid NOT NULL UNIQUE,
  kind text NOT NULL,
  container_id text,
  status text NOT NULL DEFAULT 'creating',
  media_id text,
  permalink text,
  video_id uuid REFERENCES public.member_videos(id) ON DELETE SET NULL,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  CONSTRAINT instagram_posts_kind_check CHECK (kind IN ('image', 'carousel', 'reel')),
  CONSTRAINT instagram_posts_container_check CHECK (container_id IS NULL OR container_id ~ '^[0-9]{1,30}$'),
  CONSTRAINT instagram_posts_status_check CHECK (status IN ('creating', 'processing', 'published', 'failed')),
  CONSTRAINT instagram_posts_media_check CHECK (media_id IS NULL OR media_id ~ '^[0-9]{1,30}$'),
  CONSTRAINT instagram_posts_permalink_check CHECK (permalink IS NULL OR (char_length(permalink) <= 300 AND permalink ~ '^https://www\.instagram\.com/')),
  CONSTRAINT instagram_posts_error_check CHECK (error IS NULL OR char_length(error) <= 300),
  CONSTRAINT instagram_posts_published_check CHECK ((status = 'published') = (media_id IS NOT NULL AND published_at IS NOT NULL)),
  CONSTRAINT instagram_posts_reel_video_check CHECK (kind <> 'reel' OR video_id IS NOT NULL OR status IN ('published', 'failed'))
);

CREATE INDEX instagram_posts_user_created_idx ON public.instagram_posts (user_id, created_at DESC);

ALTER TABLE public.instagram_posts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.instagram_posts FROM anon, authenticated;

ALTER TABLE public.oauth_states
  DROP CONSTRAINT oauth_states_purpose_check,
  DROP CONSTRAINT oauth_states_verifier_shape_check;

ALTER TABLE public.oauth_states
  ADD CONSTRAINT oauth_states_purpose_check CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google', 'tiktok_login', 'instagram_login')),
  ADD CONSTRAINT oauth_states_verifier_shape_check CHECK (
    purpose IN ('store_shopify', 'tiktok_login', 'instagram_login')
    OR (verifier_ciphertext IS NOT NULL AND verifier_iv IS NOT NULL AND verifier_auth_tag IS NOT NULL)
  );
