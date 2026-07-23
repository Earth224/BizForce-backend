-- 046_oracle_sync_birth_name_hebrew.sql
-- Adds an optional Hebrew-script birth name to oracle_sync, so gematria
-- can be computed from the user's actual Hebrew letters instead of a
-- lossy Latin transliteration of birth_name -- e.g. both ט (9) and ת (400)
-- transliterate to "t", both כ (20) and ק (100) become "k", and both
-- ס (60) and שׂ become "s", so a transliterated gematria total would look
-- authoritative without being accurate. See computeHebrewGematria in
-- server.js, which refuses to compute a total when this column is empty
-- rather than silently falling back to birth_name.

ALTER TABLE public.oracle_sync ADD COLUMN IF NOT EXISTS birth_name_hebrew text;
