-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.

ALTER TABLE public.digital_cards
  ADD COLUMN IF NOT EXISTS lead_form_on boolean NOT NULL DEFAULT false;

CREATE TABLE public.card_leads (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  card_id uuid NOT NULL REFERENCES public.digital_cards(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  name text NOT NULL,
  email text,
  phone text,
  message text NOT NULL DEFAULT '',
  consent_text text NOT NULL,
  status text NOT NULL DEFAULT 'new',
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT card_leads_name_check CHECK (char_length(name) BETWEEN 1 AND 120),
  CONSTRAINT card_leads_email_check CHECK (email IS NULL OR (char_length(email) <= 254 AND email ~ '^[^\s@]+@[^\s@]+\.[^\s@]+$')),
  CONSTRAINT card_leads_phone_check CHECK (phone IS NULL OR phone ~ '^[0-9+() .-]{3,40}$'),
  CONSTRAINT card_leads_message_check CHECK (char_length(message) <= 1000),
  CONSTRAINT card_leads_consent_check CHECK (char_length(consent_text) BETWEEN 10 AND 300),
  CONSTRAINT card_leads_status_check CHECK (status IN ('new', 'read', 'archived')),
  CONSTRAINT card_leads_contactable_check CHECK (email IS NOT NULL OR phone IS NOT NULL)
);

CREATE INDEX card_leads_user_created_idx ON public.card_leads (user_id, created_at DESC);
CREATE INDEX card_leads_card_created_idx ON public.card_leads (card_id, created_at DESC);

ALTER TABLE public.card_leads ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.card_leads FROM anon, authenticated;
