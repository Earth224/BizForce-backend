-- 044_oracle_sync_birth_name_arabic.sql
-- Adds an optional Arabic-script birth name to oracle_sync, so Abjad
-- (ʿIlm al-Ḥurūf) numerology can be computed from the user's actual Arabic
-- letters instead of a lossy Latin transliteration of birth_name -- e.g.
-- both ص (90) and س (60) transliterate to "s", and ط/ع/ذ/ظ have no clean
-- Latin equivalent at all, so a transliterated Abjad total would look
-- authoritative without being accurate. See computeAbjad in server.js,
-- which refuses to compute a total when this column is empty rather than
-- silently falling back to birth_name.

ALTER TABLE public.oracle_sync ADD COLUMN IF NOT EXISTS birth_name_arabic text;
