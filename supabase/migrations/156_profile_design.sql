-- 156_profile_design.sql — how a member's public profile page looks.
--
-- WHY. Members design their own public profile ("Customise profile" on their
-- profile page): its own theme, the banner, the profile photo's size, shape
-- and ring, one of four layouts, the order of the sections and which are
-- shown, and the grid's and the videos' layout and order. Visitors see that
-- design on the profile, the support page and the storefront.
--
-- bf_profiles.profile_design holds it as JSON, validated in the API
-- (lib/profileDesign.js validateDesign) against a CLOSED schema: listed keys
-- only, enums, numbers clamped, lowercase #rrggbb colours, item ids for the
-- orders, and the theme held to lib/themes.js validateTheme, whose only path
-- is the member's own theme photo (theme-photos/<their id>/...). Never raw
-- CSS, never HTML, never a URL. The CHECKs below are the floor under that (an
-- object, a bounded size); the full schema is a JS constant, so changing it
-- is a code change. NULL means the page's default look.
--
-- The public profile route sends only the re-validated design, never the
-- stored value as it is (server.js BF_PUBLIC_PROFILE_COLUMNS). The column is
-- part of the member's bf_profiles row, so it is in the data export and
-- deleted with the account like the rest of that row (lib/yourData.js).
-- bf_profiles already has row level security on (migration 009).

ALTER TABLE public.bf_profiles
  ADD COLUMN IF NOT EXISTS profile_design jsonb;

ALTER TABLE public.bf_profiles
  DROP CONSTRAINT IF EXISTS bf_profiles_profile_design_check;
ALTER TABLE public.bf_profiles
  ADD CONSTRAINT bf_profiles_profile_design_check CHECK (
    profile_design IS NULL
    OR (jsonb_typeof(profile_design) = 'object' AND octet_length(profile_design::text) <= 16384)
  );
