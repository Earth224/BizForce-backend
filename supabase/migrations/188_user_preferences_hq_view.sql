-- Applied by the owner by hand in the Supabase SQL editor on Nov 19, 2026 (verified live: both columns are text). Safe to re-run: ADD COLUMN IF NOT EXISTS, and each named CHECK is dropped if it exists before it is added.
-- HQ1 (Nov 19 2026): the phone dashboard's two display choices, saved with the
-- member's other settings so they follow the member to every device.
--
-- 1. user_preferences.hq_card_view: how the open portal's tools are drawn on a
--    phone: 'large' (the PH1 cards), 'compact' (one slim row per tool) or
--    'grid' (two columns of tiles). NULL means never chosen, which the page
--    reads as 'compact', the default.
-- 2. user_preferences.hq_orbit: whether the orbit is shown at the top of the
--    phone dashboard ('shown') or replaced by a row of five portal chips
--    ('hidden'). NULL means never chosen, which the page reads as 'shown'.
--
-- Both are display choices only. The page also keeps a device copy
-- (localStorage) so the choice applies before the server answers. The two
-- columns are part of the member's user_preferences row, so they belong in the
-- data export and are deleted with the account like the rest of that row
-- (lib/yourData.js). user_preferences already has row level security on
-- (migration 030). No new table.
BEGIN;

ALTER TABLE public.user_preferences
  ADD COLUMN IF NOT EXISTS hq_card_view text,
  ADD COLUMN IF NOT EXISTS hq_orbit     text;

ALTER TABLE public.user_preferences DROP CONSTRAINT IF EXISTS user_preferences_hq_card_view_check;
ALTER TABLE public.user_preferences ADD CONSTRAINT user_preferences_hq_card_view_check
  CHECK (hq_card_view IS NULL OR hq_card_view IN ('large', 'compact', 'grid'));

ALTER TABLE public.user_preferences DROP CONSTRAINT IF EXISTS user_preferences_hq_orbit_check;
ALTER TABLE public.user_preferences ADD CONSTRAINT user_preferences_hq_orbit_check
  CHECK (hq_orbit IS NULL OR hq_orbit IN ('shown', 'hidden'));

COMMIT;
