ALTER TABLE marketplace_listings
ADD COLUMN IF NOT EXISTS price_usd integer CHECK (price_usd IS NULL OR price_usd >= 0);
