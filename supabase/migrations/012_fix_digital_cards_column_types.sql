-- Fix column types that were created as TEXT instead of their correct types.
-- Safe to run: USING clause handles NULL and any stored string values.

-- holographic_style: TEXT → BOOLEAN
ALTER TABLE digital_cards
  ALTER COLUMN holographic_style TYPE boolean
  USING CASE
    WHEN holographic_style IS NULL THEN false
    WHEN lower(holographic_style) = 'true' THEN true
    ELSE false
  END;

ALTER TABLE digital_cards
  ALTER COLUMN holographic_style SET NOT NULL,
  ALTER COLUMN holographic_style SET DEFAULT false;

-- media_layout: TEXT → JSONB
ALTER TABLE digital_cards
  ALTER COLUMN media_layout TYPE jsonb
  USING CASE
    WHEN media_layout IS NULL OR media_layout = '' THEN '{}'::jsonb
    ELSE media_layout::jsonb
  END;

ALTER TABLE digital_cards
  ALTER COLUMN media_layout SET NOT NULL,
  ALTER COLUMN media_layout SET DEFAULT '{}';
