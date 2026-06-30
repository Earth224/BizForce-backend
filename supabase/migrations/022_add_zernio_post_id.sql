-- Migration 022: Add zernio_post_id to social_post_drafts
-- Stores the Zernio post _id returned after successful publishing.

ALTER TABLE social_post_drafts
  ADD COLUMN IF NOT EXISTS zernio_post_id text;
