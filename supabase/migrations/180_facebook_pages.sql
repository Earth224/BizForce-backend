-- Applied by the owner by hand in the Supabase SQL editor on Nov 7, 2026. This file is the text as run.

CREATE TABLE public.member_facebook_pages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
  page_id text,
  page_name text,
  page_ciphertext text,
  page_iv text,
  page_auth_tag text,
  user_ciphertext text,
  user_iv text,
  user_auth_tag text,
  user_expires_at timestamptz,
  granted_scopes text,
  status text NOT NULL DEFAULT 'choosing',
  last_ok_at timestamptz,
  last_error_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_facebook_pages_page_id_check CHECK (page_id IS NULL OR page_id ~ '^[0-9]{1,30}$'),
  CONSTRAINT member_facebook_pages_page_name_check CHECK (page_name IS NULL OR char_length(page_name) BETWEEN 1 AND 200),
  CONSTRAINT member_facebook_pages_page_token_check CHECK (
    (page_ciphertext IS NULL AND page_iv IS NULL AND page_auth_tag IS NULL)
    OR (page_ciphertext ~ '^[0-9a-f]+$' AND page_iv ~ '^[0-9a-f]{24}$' AND page_auth_tag ~ '^[0-9a-f]{32}$')
  ),
  CONSTRAINT member_facebook_pages_user_token_check CHECK (
    (user_ciphertext IS NULL AND user_iv IS NULL AND user_auth_tag IS NULL)
    OR (user_ciphertext ~ '^[0-9a-f]+$' AND user_iv ~ '^[0-9a-f]{24}$' AND user_auth_tag ~ '^[0-9a-f]{32}$')
  ),
  CONSTRAINT member_facebook_pages_scopes_check CHECK (granted_scopes IS NULL OR (char_length(granted_scopes) <= 500 AND granted_scopes ~ '^[a-z_,]*$')),
  CONSTRAINT member_facebook_pages_status_check CHECK (status IN ('choosing', 'connected', 'needs_reconnect')),
  CONSTRAINT member_facebook_pages_shape_check CHECK (
    (status = 'choosing' AND user_ciphertext IS NOT NULL AND page_ciphertext IS NULL AND page_id IS NULL)
    OR (status IN ('connected', 'needs_reconnect') AND page_ciphertext IS NOT NULL AND page_id IS NOT NULL AND page_name IS NOT NULL AND user_ciphertext IS NULL)
  ),
  CONSTRAINT member_facebook_pages_error_code_check CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 60)
);

ALTER TABLE public.member_facebook_pages ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.member_facebook_pages FROM anon, authenticated;

CREATE TABLE public.facebook_posts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  proposal_id uuid NOT NULL UNIQUE,
  kind text NOT NULL,
  status text NOT NULL DEFAULT 'creating',
  post_id text,
  permalink text,
  video_id uuid REFERENCES public.member_videos(id) ON DELETE SET NULL,
  error text,
  removed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  CONSTRAINT facebook_posts_kind_check CHECK (kind IN ('text', 'photo', 'photos', 'video')),
  CONSTRAINT facebook_posts_status_check CHECK (status IN ('creating', 'publishing', 'published', 'failed')),
  CONSTRAINT facebook_posts_post_id_check CHECK (post_id IS NULL OR post_id ~ '^[0-9]{1,30}(_[0-9]{1,30})?$'),
  CONSTRAINT facebook_posts_permalink_check CHECK (permalink IS NULL OR (char_length(permalink) <= 300 AND permalink ~ '^https://www\.facebook\.com/')),
  CONSTRAINT facebook_posts_error_check CHECK (error IS NULL OR char_length(error) <= 300),
  CONSTRAINT facebook_posts_published_check CHECK ((status = 'published') = (post_id IS NOT NULL AND published_at IS NOT NULL)),
  CONSTRAINT facebook_posts_removed_check CHECK (removed_at IS NULL OR status = 'published')
);

CREATE INDEX facebook_posts_user_created_idx ON public.facebook_posts (user_id, created_at DESC);

ALTER TABLE public.facebook_posts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.facebook_posts FROM anon, authenticated;

ALTER TABLE public.oauth_states
  DROP CONSTRAINT oauth_states_purpose_check,
  DROP CONSTRAINT oauth_states_verifier_shape_check;

ALTER TABLE public.oauth_states
  ADD CONSTRAINT oauth_states_purpose_check CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google', 'tiktok_login', 'instagram_login', 'facebook_login')),
  ADD CONSTRAINT oauth_states_verifier_shape_check CHECK (
    purpose IN ('store_shopify', 'tiktok_login', 'instagram_login', 'facebook_login')
    OR (verifier_ciphertext IS NOT NULL AND verifier_iv IS NOT NULL AND verifier_auth_tag IS NOT NULL)
  );
