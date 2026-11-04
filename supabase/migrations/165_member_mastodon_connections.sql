-- 165: a member's own Mastodon account (lib/memberMastodon.js).
--
-- Applied by the owner by hand in the Supabase SQL editor on Nov 3, 2026. This file is the text as run.
--
-- One row per member: the server they chose, the account it answered for, the
-- server's post length rules, and a personal access token (write:statuses and
-- read:accounts only), encrypted with lib/apiKeyCrypto.js. RLS is on with no
-- policy, so only the server reads it. member_social_setting_changes now also
-- logs the Mastodon "Post approved drafts automatically" setting.

CREATE TABLE public.member_mastodon_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
  instance_host text NOT NULL,
  account_id text NOT NULL,
  acct text NOT NULL,
  token_ciphertext text NOT NULL,
  token_iv text NOT NULL,
  token_auth_tag text NOT NULL,
  max_characters integer NOT NULL DEFAULT 500,
  characters_reserved_per_url integer NOT NULL DEFAULT 23,
  status text NOT NULL DEFAULT 'connected',
  auto_post boolean NOT NULL DEFAULT false,
  auto_post_changed_at timestamptz,
  last_ok_at timestamptz,
  last_error_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_mastodon_connections_host_check CHECK (char_length(instance_host) BETWEEN 4 AND 253 AND instance_host ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'),
  CONSTRAINT member_mastodon_connections_account_id_check CHECK (account_id ~ '^[A-Za-z0-9_-]{1,64}$'),
  CONSTRAINT member_mastodon_connections_acct_check CHECK (acct ~ '^[A-Za-z0-9_.-]{1,64}$'),
  CONSTRAINT member_mastodon_connections_ciphertext_check CHECK (token_ciphertext ~ '^[0-9a-f]+$'),
  CONSTRAINT member_mastodon_connections_iv_check CHECK (token_iv ~ '^[0-9a-f]{24}$'),
  CONSTRAINT member_mastodon_connections_auth_tag_check CHECK (token_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT member_mastodon_connections_max_chars_check CHECK (max_characters BETWEEN 1 AND 100000),
  CONSTRAINT member_mastodon_connections_url_chars_check CHECK (characters_reserved_per_url BETWEEN 0 AND 1000),
  CONSTRAINT member_mastodon_connections_status_check CHECK (status IN ('connected', 'needs_reconnect', 'disconnected')),
  CONSTRAINT member_mastodon_connections_error_code_check CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 60)
);

ALTER TABLE public.member_mastodon_connections ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE c text;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'public.member_social_setting_changes'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%platform%'
  LOOP
    EXECUTE format('ALTER TABLE public.member_social_setting_changes DROP CONSTRAINT %I', c);
  END LOOP;
END $$;

ALTER TABLE public.member_social_setting_changes
  ADD CONSTRAINT member_social_setting_changes_platform_check CHECK (platform IN ('bluesky', 'mastodon'));
