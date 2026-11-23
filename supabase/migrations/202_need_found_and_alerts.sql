-- ===== PART 202a: a Need marked Found (run first) =====
-- P3-3 (Nov 23 2026): the poster of a Need post can mark it Found, and reopen it. need_found_at is when they did;
-- NULL is open. A Found Need shows the tag FOUND in the feed, its "I can help" strip is gone, and it sends no
-- Need alerts (lib/needAlerts.js). Only a Need can be Found (posts_need_found_only_on_need), as 200c holds
-- need_place and need_when to Needs.
-- Paste-safe: no less-or-equal or greater-or-equal operators, no DO blocks, no transaction statements; every
-- CHECK is named and dropped if it exists first. Each part runs alone, in order: 202a, 202b.
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS need_found_at timestamptz;
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_need_found_only_on_need;
ALTER TABLE public.posts ADD CONSTRAINT posts_need_found_only_on_need
  CHECK (intent = 'need' OR need_found_at IS NULL);

-- ===== PART 202b: the member's Need alerts switch (run second) =====
-- user_preferences.need_alerts: "Need alerts in my categories" (settings.html, Preferences). NULL is never
-- chosen, which reads as ON for a member; false turns the alerts off; true turns them back on. A free account
-- never receives a Need alert whatever this says. The alerts are in-app notifications only: no email, no SMS,
-- no push (lib/needAlerts.js). user_preferences already has row level security on and is in the member's export.
ALTER TABLE public.user_preferences ADD COLUMN IF NOT EXISTS need_alerts boolean;
