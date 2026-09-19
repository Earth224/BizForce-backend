-- Fix column types that were created as TEXT instead of their correct types.
--
-- WHAT THIS DOES. digital_cards.holographic_style and digital_cards.media_layout
-- existed as text on the live database when this file ran; it converted them to
-- boolean and jsonb. Both conversions are now guarded on the column's actual
-- current type and do nothing unless it is still text. What they do to a text
-- column is unchanged -- that is what ran on live and it is transcribed here
-- exactly.
--
-- WHY THE GUARDS WERE ADDED AFTER THIS WAS APPLIED. The header read "Safe to
-- run: USING clause handles NULL and any stored string values." That is true of
-- the USING clauses and false of the file. It was safe on live and only on live,
-- because of an ordering that a fresh run inverts:
--
--   on live   011's ADD COLUMN IF NOT EXISTS found holographic_style and
--             media_layout already present as text and added nothing, so both
--             columns reached this file as text and this file converted them.
--
--   on a fresh sequence   there is no earlier table. 011 creates
--             holographic_style as boolean and media_layout as jsonb, both
--             columns arrive here already converted, and the premise of this
--             file is gone.
--
-- Unguarded, that failed on `lower(holographic_style)` -- there is no
-- lower(boolean) -- and media_layout's `media_layout = ''` was waiting to fail
-- the same way behind it, since '' is not valid jsonb. Both were found by
-- rebuilding against an empty database, not by reading the file: every
-- statement here is legal SQL, and which of them can run depends on a state
-- that lives in another file.
--
-- EQUIVALENCE ON LIVE. Both columns were text when this ran, so both guards are
-- true there and both conversions execute exactly as before. The SET NOT NULL
-- and SET DEFAULT statements are left unguarded because they are idempotent on
-- either path: on a fresh run they restate what 011 already declares, and on
-- live they restate what the conversion leaves behind. Nothing about the live
-- outcome changes.

-- holographic_style: TEXT → BOOLEAN, only while it is still text.
DO $do$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name   = 'digital_cards'
       AND column_name  = 'holographic_style'
       AND data_type    = 'text'
  ) THEN
    EXECUTE $stmt$
      ALTER TABLE digital_cards
        ALTER COLUMN holographic_style TYPE boolean
        USING CASE
          WHEN holographic_style IS NULL THEN false
          WHEN lower(holographic_style) = 'true' THEN true
          ELSE false
        END
    $stmt$;
  END IF;
END
$do$;

ALTER TABLE digital_cards
  ALTER COLUMN holographic_style SET NOT NULL,
  ALTER COLUMN holographic_style SET DEFAULT false;

-- media_layout: TEXT → JSONB, only while it is still text.
DO $do$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name   = 'digital_cards'
       AND column_name  = 'media_layout'
       AND data_type    = 'text'
  ) THEN
    EXECUTE $stmt$
      ALTER TABLE digital_cards
        ALTER COLUMN media_layout TYPE jsonb
        USING CASE
          WHEN media_layout IS NULL OR media_layout = '' THEN '{}'::jsonb
          ELSE media_layout::jsonb
        END
    $stmt$;
  END IF;
END
$do$;

ALTER TABLE digital_cards
  ALTER COLUMN media_layout SET NOT NULL,
  ALTER COLUMN media_layout SET DEFAULT '{}';
