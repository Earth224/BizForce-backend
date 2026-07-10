-- Documents the pre-existing live marketplace_orders table (never previously captured in a migration),
-- and the USD/hybrid columns added for Stripe USD checkout.
CREATE TABLE IF NOT EXISTS marketplace_orders (
id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
listing_id uuid,
buyer_id uuid NOT NULL,
seller_id uuid NOT NULL,
amount_bfc integer NOT NULL DEFAULT 0,
listing_title text,
status text NOT NULL DEFAULT 'completed',
created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE marketplace_orders
ADD COLUMN IF NOT EXISTS amount_usd integer CHECK (amount_usd IS NULL OR amount_usd >= 0),
ADD COLUMN IF NOT EXISTS payment_method text NOT NULL DEFAULT 'bfc' CHECK (payment_method IN ('bfc','usd')),
ADD COLUMN IF NOT EXISTS stripe_session_id text;
