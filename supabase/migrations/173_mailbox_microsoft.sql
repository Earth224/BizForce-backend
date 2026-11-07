-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.

ALTER TABLE public.member_email_connections
  DROP CONSTRAINT member_email_connections_provider_check,
  DROP CONSTRAINT member_email_connections_auth_kind_check;

ALTER TABLE public.member_email_connections
  ADD COLUMN IF NOT EXISTS access_ciphertext text,
  ADD COLUMN IF NOT EXISTS access_iv text,
  ADD COLUMN IF NOT EXISTS access_auth_tag text,
  ADD COLUMN IF NOT EXISTS access_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS token_version integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS account_type text;

ALTER TABLE public.member_email_connections
  ADD CONSTRAINT member_email_connections_provider_check CHECK (provider IN ('gmail', 'yahoo', 'icloud', 'fastmail', 'other', 'outlook')),
  ADD CONSTRAINT member_email_connections_auth_kind_check CHECK (auth_kind IN ('app_password', 'oauth_microsoft')),
  ADD CONSTRAINT member_email_connections_access_ciphertext_check CHECK (access_ciphertext IS NULL OR access_ciphertext ~ '^[0-9a-f]+$'),
  ADD CONSTRAINT member_email_connections_access_iv_check CHECK (access_iv IS NULL OR access_iv ~ '^[0-9a-f]{24}$'),
  ADD CONSTRAINT member_email_connections_access_tag_check CHECK (access_auth_tag IS NULL OR access_auth_tag ~ '^[0-9a-f]{32}$'),
  ADD CONSTRAINT member_email_connections_token_version_check CHECK (token_version >= 0),
  ADD CONSTRAINT member_email_connections_kind_shape_check CHECK (
    (auth_kind = 'app_password' AND provider <> 'outlook'
      AND access_ciphertext IS NULL AND access_iv IS NULL AND access_auth_tag IS NULL
      AND access_expires_at IS NULL AND account_type IS NULL)
    OR
    (auth_kind = 'oauth_microsoft' AND provider = 'outlook'
      AND access_ciphertext IS NOT NULL AND access_iv IS NOT NULL AND access_auth_tag IS NOT NULL
      AND access_expires_at IS NOT NULL AND account_type IN ('personal', 'work'))
  );

CREATE TABLE public.oauth_states (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  purpose text NOT NULL,
  state_hash text NOT NULL UNIQUE,
  verifier_ciphertext text NOT NULL,
  verifier_iv text NOT NULL,
  verifier_auth_tag text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_states_purpose_check CHECK (purpose IN ('mailbox_microsoft')),
  CONSTRAINT oauth_states_hash_check CHECK (state_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT oauth_states_ciphertext_check CHECK (verifier_ciphertext ~ '^[0-9a-f]+$'),
  CONSTRAINT oauth_states_iv_check CHECK (verifier_iv ~ '^[0-9a-f]{24}$'),
  CONSTRAINT oauth_states_tag_check CHECK (verifier_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT oauth_states_expiry_check CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes')
);

CREATE INDEX oauth_states_user_idx ON public.oauth_states (user_id, created_at DESC);

ALTER TABLE public.oauth_states ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.oauth_states FROM anon, authenticated;
