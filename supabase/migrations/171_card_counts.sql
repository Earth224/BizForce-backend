-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.

ALTER TABLE public.digital_cards
  ADD COLUMN IF NOT EXISTS discoverable boolean NOT NULL DEFAULT false;

CREATE TABLE public.card_view_counts (
  card_id uuid NOT NULL REFERENCES public.digital_cards(id) ON DELETE CASCADE,
  day date NOT NULL,
  views integer NOT NULL DEFAULT 0,
  qr_views integer NOT NULL DEFAULT 0,
  tel_taps integer NOT NULL DEFAULT 0,
  email_taps integer NOT NULL DEFAULT 0,
  save_taps integer NOT NULL DEFAULT 0,
  support_taps integer NOT NULL DEFAULT 0,
  PRIMARY KEY (card_id, day),
  CONSTRAINT card_view_counts_nonneg_check CHECK (views >= 0 AND qr_views >= 0 AND tel_taps >= 0 AND email_taps >= 0 AND save_taps >= 0 AND support_taps >= 0)
);

ALTER TABLE public.card_view_counts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.card_view_counts FROM anon, authenticated;

CREATE OR REPLACE FUNCTION public.bump_card_count(p_card uuid, p_kind text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF p_kind NOT IN ('views', 'qr_views', 'tel_taps', 'email_taps', 'save_taps', 'support_taps') THEN
    RAISE EXCEPTION 'unknown count kind';
  END IF;
  EXECUTE format(
    'INSERT INTO public.card_view_counts (card_id, day, %1$I) VALUES ($1, (now() AT TIME ZONE ''utc'')::date, 1)
     ON CONFLICT (card_id, day) DO UPDATE SET %1$I = public.card_view_counts.%1$I + 1',
    p_kind
  ) USING p_card;
END
$$;

REVOKE ALL ON FUNCTION public.bump_card_count(uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bump_card_count(uuid, text) TO service_role;
