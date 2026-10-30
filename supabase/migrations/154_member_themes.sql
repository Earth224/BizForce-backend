-- 154_member_themes.sql — a member's saved looks, and which page wears which.
--
-- WHY. Block 4a, the theme engine. A member picks the top-left glow, the
-- bottom-right glow and the middle backdrop (black, a colour, or their own
-- photo with a dim) in Settings → Theme, saves it under a name, and applies it
-- to every page, this page, or the pages they tick. Until now every page drew
-- the same backdrop from its own <style>; the look did not belong to anyone.
--
-- 1. member_themes: one row per saved theme. `theme` is JSON validated in the
--    API (lib/themes.js validateTheme) against a CLOSED schema: lowercase
--    #rrggbb colours, the enums middle ∈ black/colour/photo and alive true or
--    false, numbers clamped, and no other key. Never raw CSS and never a URL:
--    the only path it may hold is the member's own uploaded photo,
--    theme-photos/<their id>/<digits>.(jpg|png|webp) in bf-public. The CHECKs
--    below are the floor under that (an object, a bounded size, a named row);
--    the full schema is a JS constant so changing it is a code change.
-- 2. user_preferences.default_theme_id: the main theme, worn by every page
--    without one of its own. NULL means the original look. Deleting the theme
--    sets it back to NULL.
-- 3. user_preferences.page_themes: { "<page key>": "<theme id>" }, the pages
--    given their own theme. Page keys are the app map's (lib/appMap.json), and
--    the API accepts only pages that wear a theme (lib/themes.js themedPages).
--    '{}' means none; a page not in it wears the main theme.
--
-- Both are in the data export and deleted with the account (lib/yourData.js:
-- member_themes is its own entry; user_preferences already was). Photos sit
-- under theme-photos/<member id>/ in bf-public, which lib/accountFiles.js
-- lists and removes with the account like every other bf-public folder.
--
-- RLS is on with no policies, so only the service role (the server) reads or
-- writes member_themes.

-- ── 1 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.member_themes (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  name        text        NOT NULL,
  theme       jsonb       NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_themes_name_check CHECK (char_length(name) BETWEEN 1 AND 60),
  CONSTRAINT member_themes_theme_object_check CHECK (jsonb_typeof(theme) = 'object'),
  CONSTRAINT member_themes_theme_size_check CHECK (octet_length(theme::text) <= 2048)
);

CREATE INDEX IF NOT EXISTS member_themes_user_idx
  ON public.member_themes (user_id, created_at);

ALTER TABLE public.member_themes ENABLE ROW LEVEL SECURITY;

-- ── 2 and 3 ─────────────────────────────────────────────────────────────────
ALTER TABLE public.user_preferences
  ADD COLUMN IF NOT EXISTS default_theme_id uuid REFERENCES public.member_themes(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS page_themes jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE public.user_preferences
  DROP CONSTRAINT IF EXISTS user_preferences_page_themes_object_check;
ALTER TABLE public.user_preferences
  ADD CONSTRAINT user_preferences_page_themes_object_check CHECK (jsonb_typeof(page_themes) = 'object');

COMMENT ON COLUMN public.user_preferences.default_theme_id IS
  'The member''s main theme (member_themes.id), worn by every page without its own. NULL means the original look.';
COMMENT ON COLUMN public.user_preferences.page_themes IS
  'Pages given their own theme: {"<app map page key>": "<member_themes.id>"}. Keys validated in the API against the app map''s themed pages. A page not listed wears the main theme.';
