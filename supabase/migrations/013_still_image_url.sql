-- Add still_image_url column for the dissolving card poster image.
-- Separate from bg_image_url (card background layer) — this is the
-- full-screen still image that dissolves into the video pitch on card-view.
ALTER TABLE digital_cards ADD COLUMN IF NOT EXISTS still_image_url TEXT;
