-- ===== PART 206a: "Show my profile and listings in Google" (run first) =====
-- LR-4 (Nov 25 2026): user_preferences.show_in_google, the member's switch in settings.html, Privacy. NULL is never
-- chosen, which reads as ON (the owner's decision of Nov 20: Google visibility is on by default for members); false
-- turns it off; true turns it back on. A free account's profile and listings are never shown in Google whatever this
-- says (lib/publicPages.js). Turning it off makes the member's /@handle and /listing/<id> pages noindex and drops them
-- from /sitemap-profiles.xml and /sitemap-listings.xml at once. user_preferences already has row level security on
-- and is in the member's export (lib/yourData.js).
-- Paste-safe: no less-or-equal or greater-or-equal operators, no DO blocks, no transaction statements; every CHECK is
-- named and dropped if it exists first. Each part runs alone, in order: 206a, 206b.
ALTER TABLE public.user_preferences ADD COLUMN IF NOT EXISTS show_in_google boolean;

-- ===== PART 206b: IndexNow, once per address per day (run second) =====
-- lib/indexNow.js: when ENABLE_INDEXNOW is "true", the address of an indexable profile, listing or post that was
-- created or changed is sent to api.indexnow.org in a batch, at most once per address per UTC day. One row per
-- address: the day it was last sent. Only public page addresses are stored (no member id, nothing private). The
-- server writes it with the service key; members never read it, so row level security is on with no policies and
-- anon and authenticated are revoked.
CREATE TABLE IF NOT EXISTS public.indexnow_sent (
  url     text PRIMARY KEY,
  sent_on date NOT NULL
);
ALTER TABLE public.indexnow_sent DROP CONSTRAINT IF EXISTS indexnow_sent_url_check;
ALTER TABLE public.indexnow_sent ADD CONSTRAINT indexnow_sent_url_check
  CHECK (url LIKE 'https://bizforceai.net/%' AND length(url) < 501);
ALTER TABLE public.indexnow_sent ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.indexnow_sent FROM anon, authenticated;
