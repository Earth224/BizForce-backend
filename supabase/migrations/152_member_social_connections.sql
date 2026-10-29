-- 152_member_social_connections.sql — a member connects their OWN Bluesky
-- account with an app password, and the Social agent posts from it.
--
-- WHY. Block 5a. Until now every Bluesky post went out from the platform's one
-- account (BLUESKY_IDENTIFIER), so only the owner could file one. A member who
-- connects their own account posts from it instead, through the same approval
-- gate, or automatically when they turn that on. The platform account and Lead
-- Radar are unchanged.
--
-- 1. member_social_connections: one row per member per platform (unique
--    user_id, platform). Only 'bluesky' today.
--    - The app password is stored ENCRYPTED with lib/apiKeyCrypto.js, the same
--      scheme user_api_keys uses: AES-256-GCM under ENCRYPTION_SECRET (32 bytes,
--      hex), a random 12-byte IV per encryption, and the 16-byte auth tag. The
--      three CHECKs below accept lowercase hex only, so a plaintext app
--      password (xxxx-xxxx-xxxx-xxxx: it has dashes) can never be stored, even
--      by mistake.
--    - status: 'connected', 'needs_reconnect' (a session failed; the member is
--      told once and nothing is retried) or 'disconnected'.
--    - auto_post: "Post approved drafts automatically", OFF by default. Every
--      change is logged in member_social_setting_changes.
--    - last_ok_at, last_error_at, last_error_code: the last session that worked
--      and the last that failed. The code is a short label, never Bluesky's
--      words and never the password.
--    Disconnecting deletes the row. Deleting the account deletes it. The data
--    export shows only the platform, the handle and the date it was connected.
-- 2. member_social_setting_changes: one row per change of a member's social
--    setting (only auto_post today), so the member can see when automation was
--    turned on or off. Kept after a disconnect; deleted with the account.
--
-- RLS is on with no policies on both, so only the service role (the server)
-- reads or writes them.

-- ── 1 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.member_social_connections (
  id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                  uuid        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  platform                 text        NOT NULL,
  handle                   text        NOT NULL,
  did                      text        NOT NULL,
  app_password_ciphertext  text        NOT NULL,
  app_password_iv          text        NOT NULL,
  app_password_auth_tag    text        NOT NULL,
  status                   text        NOT NULL DEFAULT 'connected',
  auto_post                boolean     NOT NULL DEFAULT false,
  auto_post_changed_at     timestamptz,
  last_ok_at               timestamptz,
  last_error_at            timestamptz,
  last_error_code          text,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_social_connections_user_platform_unique UNIQUE (user_id, platform),
  CONSTRAINT member_social_connections_platform_check CHECK (platform IN ('bluesky')),
  CONSTRAINT member_social_connections_status_check CHECK (status IN ('connected', 'needs_reconnect', 'disconnected')),
  CONSTRAINT member_social_connections_handle_check CHECK (char_length(handle) BETWEEN 3 AND 253),
  CONSTRAINT member_social_connections_did_check CHECK (did LIKE 'did:%' AND char_length(did) <= 2048),
  CONSTRAINT member_social_connections_ciphertext_check CHECK (app_password_ciphertext ~ '^[0-9a-f]+$'),
  CONSTRAINT member_social_connections_iv_check CHECK (app_password_iv ~ '^[0-9a-f]{24}$'),
  CONSTRAINT member_social_connections_auth_tag_check CHECK (app_password_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT member_social_connections_error_code_check CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 60)
);

ALTER TABLE public.member_social_connections ENABLE ROW LEVEL SECURITY;

-- ── 2 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.member_social_setting_changes (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  platform    text        NOT NULL,
  setting     text        NOT NULL,
  old_value   boolean,
  new_value   boolean     NOT NULL,
  changed_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_social_setting_changes_platform_check CHECK (platform IN ('bluesky')),
  CONSTRAINT member_social_setting_changes_setting_check CHECK (setting IN ('auto_post'))
);

CREATE INDEX IF NOT EXISTS member_social_setting_changes_user_idx
  ON public.member_social_setting_changes (user_id, changed_at DESC);

ALTER TABLE public.member_social_setting_changes ENABLE ROW LEVEL SECURITY;
