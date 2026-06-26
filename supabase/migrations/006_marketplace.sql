-- Phase 6: Service marketplace listings

CREATE TABLE IF NOT EXISTS marketplace_listings (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id   uuid        NOT NULL,
  title       text        NOT NULL,
  description text        NOT NULL DEFAULT '',
  price_bfc   integer     NOT NULL DEFAULT 0,
  category    text        NOT NULL DEFAULT 'other',
  tags        text[]      NOT NULL DEFAULT '{}',
  status      text        NOT NULL DEFAULT 'active',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT marketplace_listings_status_check CHECK (status IN ('active','paused','sold')),
  CONSTRAINT marketplace_listings_price_check  CHECK (price_bfc >= 0)
);

CREATE INDEX IF NOT EXISTS marketplace_listings_status_idx
  ON marketplace_listings (status);
CREATE INDEX IF NOT EXISTS marketplace_listings_category_idx
  ON marketplace_listings (category, status);
CREATE INDEX IF NOT EXISTS marketplace_listings_seller_idx
  ON marketplace_listings (seller_id);

ALTER TABLE marketplace_listings ENABLE ROW LEVEL SECURITY;

CREATE POLICY marketplace_listings_select_all   ON marketplace_listings FOR SELECT USING (status = 'active' OR seller_id = auth.uid());
CREATE POLICY marketplace_listings_insert_own   ON marketplace_listings FOR INSERT WITH CHECK (auth.uid() = seller_id);
CREATE POLICY marketplace_listings_update_own   ON marketplace_listings FOR UPDATE USING (auth.uid() = seller_id) WITH CHECK (auth.uid() = seller_id);
CREATE POLICY marketplace_listings_delete_own   ON marketplace_listings FOR DELETE USING (auth.uid() = seller_id);
