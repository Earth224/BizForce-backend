-- 045_oracle_sync_birth_name_greek.sql
-- Adds an optional Greek-script birth name to oracle_sync, so isopsephy
-- numerology can be computed from the user's actual Greek letters instead
-- of a lossy Latin transliteration of birth_name -- e.g. both η (8) and
-- ε (5) transliterate to "e", and ω (800) and ο (70) both become "o", so a
-- transliterated isopsephy total would look authoritative without being
-- accurate. See computeIsopsephy in server.js, which refuses to compute a
-- total when this column is empty rather than silently falling back to
-- birth_name.

ALTER TABLE public.oracle_sync ADD COLUMN IF NOT EXISTS birth_name_greek text;
