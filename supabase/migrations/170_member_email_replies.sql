-- 170: replies a member files from their own inbox (Email connection, Build B).
-- Applied by the owner by hand in the Supabase SQL editor on Nov 5, 2026. This file is the text as run.
--
-- One row per filed reply. A reply goes only to the original sender, from the
-- member's own address, and only after the member approves its proposal.
-- RLS is on with no policies: only the service role reads or writes these rows.

CREATE TABLE public.member_email_replies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  task_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending_approval',
  to_address text NOT NULL,
  subject text NOT NULL,
  body text NOT NULL,
  in_reply_to text NOT NULL,
  reference_ids text NOT NULL DEFAULT '',
  source_uid bigint NOT NULL,
  smtp_message_id text,
  sent_at timestamptz,
  send_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_email_replies_status_check CHECK (status IN ('pending_approval', 'sent', 'send_failed', 'cancelled')),
  CONSTRAINT member_email_replies_to_check CHECK (char_length(to_address) <= 254 AND to_address ~ '^[^\s@]+@[^\s@]+\.[^\s@]+$'),
  CONSTRAINT member_email_replies_subject_check CHECK (char_length(subject) BETWEEN 1 AND 300 AND subject !~ '[\r\n]'),
  CONSTRAINT member_email_replies_body_check CHECK (char_length(body) BETWEEN 1 AND 20000),
  CONSTRAINT member_email_replies_in_reply_to_check CHECK (char_length(in_reply_to) <= 998 AND in_reply_to ~ '^<[^<>\s]+>$'),
  CONSTRAINT member_email_replies_references_check CHECK (char_length(reference_ids) <= 4000 AND reference_ids !~ '[\r\n]'),
  CONSTRAINT member_email_replies_uid_check CHECK (source_uid > 0),
  CONSTRAINT member_email_replies_sent_check CHECK ((status = 'sent') = (sent_at IS NOT NULL AND smtp_message_id IS NOT NULL)),
  CONSTRAINT member_email_replies_error_check CHECK (send_error IS NULL OR char_length(send_error) <= 300),
  CONSTRAINT member_email_replies_smtp_id_check CHECK (smtp_message_id IS NULL OR (char_length(smtp_message_id) <= 998 AND smtp_message_id ~ '^<[^<>\s]+>$'))
);

CREATE INDEX member_email_replies_user_sent_idx ON public.member_email_replies (user_id, sent_at DESC);

ALTER TABLE public.member_email_replies ENABLE ROW LEVEL SECURITY;
