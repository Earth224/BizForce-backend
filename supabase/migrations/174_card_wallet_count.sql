-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.

ALTER TABLE public.card_view_counts
  ADD COLUMN IF NOT EXISTS wallet_taps integer NOT NULL DEFAULT 0;

ALTER TABLE public.card_view_counts
  DROP CONSTRAINT card_view_counts_nonneg_check;

ALTER TABLE public.card_view_counts
  ADD CONSTRAINT card_view_counts_nonneg_check CHECK (views >= 0 AND qr_views >= 0 AND tel_taps >= 0 AND email_taps >= 0 AND save_taps >= 0 AND support_taps >= 0 AND wallet_taps >= 0);

CREATE OR REPLACE FUNCTION public.bump_card_count(p_card uuid, p_kind text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF p_kind NOT IN ('views', 'qr_views', 'tel_taps', 'email_taps', 'save_taps', 'support_taps', 'wallet_taps') THEN
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
