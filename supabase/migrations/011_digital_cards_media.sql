-- Phase 11: Add media columns to digital_cards
-- Fixes internal server error when saving cards with video/image/audio content.
-- These columns are referenced in POST/PUT /api/digital-cards but were missing
-- from the original 007_digital_cards.sql schema.

ALTER TABLE digital_cards ADD COLUMN IF NOT EXISTS video_url        text;
ALTER TABLE digital_cards ADD COLUMN IF NOT EXISTS bg_image_url     text;
ALTER TABLE digital_cards ADD COLUMN IF NOT EXISTS audio_url        text;
ALTER TABLE digital_cards ADD COLUMN IF NOT EXISTS holographic_style boolean NOT NULL DEFAULT false;
ALTER TABLE digital_cards ADD COLUMN IF NOT EXISTS media_layout     jsonb   NOT NULL DEFAULT '{}';
ALTER TABLE digital_cards ADD COLUMN IF NOT EXISTS share_token      text    UNIQUE;
