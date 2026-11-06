-- 169: a member's own mailbox, connected with an app password (Email connection, Build A).
-- Applied by the owner by hand in the Supabase SQL editor on Nov 5, 2026. This file is the text as run.
--
-- One row per member. The app password is AES-256-GCM sealed by lib/apiKeyCrypto.js
-- (ENCRYPTION_SECRET) and is never returned by any route. IMAP is 993 with implicit
-- TLS only; SMTP is 465 or 587 (STARTTLS required). Messages are never stored.
-- RLS on with no policy: only the service role reads or writes it.

CREATE TABLE public.member_email_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
  provider text NOT NULL,
  email_address text NOT NULL,
  username text NOT NULL,
  imap_host text NOT NULL,
  imap_port integer NOT NULL DEFAULT 993,
  smtp_host text NOT NULL,
  smtp_port integer NOT NULL DEFAULT 465,
  auth_kind text NOT NULL DEFAULT 'app_password',
  secret_ciphertext text NOT NULL,
  secret_iv text NOT NULL,
  secret_auth_tag text NOT NULL,
  status text NOT NULL DEFAULT 'connected',
  last_ok_at timestamptz,
  last_error_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_email_connections_provider_check CHECK (provider IN ('gmail', 'yahoo', 'icloud', 'fastmail', 'other')),
  CONSTRAINT member_email_connections_email_check CHECK (char_length(email_address) <= 254 AND email_address ~ '^[^\s@]+@[^\s@]+\.[^\s@]+$'),
  CONSTRAINT member_email_connections_username_check CHECK (char_length(username) BETWEEN 1 AND 254),
  CONSTRAINT member_email_connections_imap_host_check CHECK (char_length(imap_host) BETWEEN 4 AND 253 AND imap_host ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'),
  CONSTRAINT member_email_connections_imap_port_check CHECK (imap_port = 993),
  CONSTRAINT member_email_connections_smtp_host_check CHECK (char_length(smtp_host) BETWEEN 4 AND 253 AND smtp_host ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'),
  CONSTRAINT member_email_connections_smtp_port_check CHECK (smtp_port IN (465, 587)),
  CONSTRAINT member_email_connections_auth_kind_check CHECK (auth_kind IN ('app_password')),
  CONSTRAINT member_email_connections_ciphertext_check CHECK (secret_ciphertext ~ '^[0-9a-f]+$'),
  CONSTRAINT member_email_connections_iv_check CHECK (secret_iv ~ '^[0-9a-f]{24}$'),
  CONSTRAINT member_email_connections_auth_tag_check CHECK (secret_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT member_email_connections_status_check CHECK (status IN ('connected', 'needs_reconnect', 'disconnected')),
  CONSTRAINT member_email_connections_error_code_check CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 60)
);

ALTER TABLE public.member_email_connections ENABLE ROW LEVEL SECURITY;
