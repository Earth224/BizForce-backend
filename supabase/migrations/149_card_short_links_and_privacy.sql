-- 149_card_short_links_and_privacy.sql — a business card's short link, and
-- the fields a member can keep off their public card (launch item #10).
--
-- WHY. A card's public page served the email and phone to anyone holding the
-- link, with no way to keep either back, and the only link was
-- card-view.html?token=<32 hex characters>, too long to print or say aloud.
--
--   slug        the short link bizforceai.net/c/<slug>. Null: no short link
--               (the card-view link still works). 3 to 40 lowercase letters,
--               digits and single hyphens, starting and ending with a letter
--               or digit; server.js cardSlugFrom says the same and also
--               refuses CARD_SLUG_RESERVED. Unique across every card.
--   show_email  false keeps the email off the public card, its mailto link
--   show_phone  and its vCard; likewise the phone (tel link) and the
--   show_photo  member's profile photo (vCard PHOTO). True by default: every
--               card served all three until now, so true describes every
--               existing row and changes nothing a member sees.
--
-- No new table, so no new RLS policy: digital_cards already has its own, and
-- server.js reads and writes it with the service role.
--
-- DEPLOY ORDER. Apply this before relying on short links or hidden fields.
-- Until it is applied, server.js serves every card as before (it reads
-- select("*") and treats a missing show_* as shown), and a save that sets a
-- slug or a show_* field is refused with a 503 that names this migration.

ALTER TABLE public.digital_cards ADD COLUMN IF NOT EXISTS slug text;
ALTER TABLE public.digital_cards ADD COLUMN IF NOT EXISTS show_email boolean NOT NULL DEFAULT true;
ALTER TABLE public.digital_cards ADD COLUMN IF NOT EXISTS show_phone boolean NOT NULL DEFAULT true;
ALTER TABLE public.digital_cards ADD COLUMN IF NOT EXISTS show_photo boolean NOT NULL DEFAULT true;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'digital_cards_slug_format') THEN
    ALTER TABLE public.digital_cards ADD CONSTRAINT digital_cards_slug_format
      CHECK (slug IS NULL OR (slug ~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$' AND position('--' in slug) = 0));
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS digital_cards_slug_unique ON public.digital_cards (slug) WHERE slug IS NOT NULL;

COMMENT ON COLUMN public.digital_cards.slug IS
  'The short link bizforceai.net/c/<slug>. Null: none. Format and reserved words: server.js cardSlugFrom.';
COMMENT ON COLUMN public.digital_cards.show_email IS 'False keeps the email off the public card, its mailto link and its vCard.';
COMMENT ON COLUMN public.digital_cards.show_phone IS 'False keeps the phone off the public card, its tel link and its vCard.';
COMMENT ON COLUMN public.digital_cards.show_photo IS 'False keeps the member''s profile photo out of the public card''s vCard.';
