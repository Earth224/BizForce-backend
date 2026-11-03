-- 163_store_connections.sql — a member connects a Shopify or WooCommerce store
-- to the Store agent, READ-ONLY.
--
-- WHY. The Store agent's Stock & Margin and the "Items at their reorder point"
-- trigger read only what a member typed on the Inventory page. A member who
-- sells on Shopify or WooCommerce already keeps their products, stock and
-- orders there. This lets BizForce READ them (lib/storeSync.js). Nothing here,
-- and nothing in the code, ever writes to the store.
--
-- 1. member_store_connections: one row per member per store (unique user_id,
--    platform, store_url).
--    - platform: 'shopify' (store_url is the shop's *.myshopify.com domain) or
--      'woocommerce' (store_url is the shop's https origin).
--    - The credentials (Shopify: the Admin API access token; WooCommerce: the
--      consumer key and secret, as one JSON value) are stored ENCRYPTED with
--      lib/apiKeyCrypto.js, the scheme member_social_connections and
--      user_api_keys use: AES-256-GCM under ENCRYPTION_SECRET, a random 12-byte
--      IV and the 16-byte auth tag. The CHECKs accept lowercase hex only, so a
--      plaintext token (shpat_..., ck_..., or JSON) can never be stored.
--    - status: 'connected', 'needs_reconnect' (the store refused the
--      credentials; the member is told once and nothing is retried) or
--      'disconnected'.
--    - last_sync_at, last_error_code, last_error_at: the last sync that worked,
--      and a short label for the last that failed (never the store's words,
--      never a credential).
--    Disconnecting deletes the row and everything synced from it. Deleting the
--    account deletes it. The data export shows the platform, the store, its
--    status and the dates, never the credentials.
-- 2. inventory_items gains four columns, so a synced row says where it came
--    from and a member's own rows are never touched by a sync:
--    - source: NULL for a row the member entered (manual); 'shopify' or
--      'woocommerce' for a synced one.
--    - store_connection_id and external_id: which connection and which product
--      or variant in that store. A sync upserts on exactly this pair, which a
--      manual row (both NULL) can never match.
--    - synced_at: when the sync last wrote the row.
--    There is no foreign key from store_connection_id: inventory_movements is
--    ON DELETE RESTRICT on its item, so a cascade could be refused part-way.
--    lib/storeSync.js deletes a connection's rows itself, children first.
-- 3. store_order_summaries: one row per order, the SUMMARY only: the store's
--    order id, when it was placed, the total, the currency, and the line items
--    as SKU and quantity. No customer name, email, address or phone is ever
--    stored; there is no column for one, and line_items is checked to be an
--    array. Deleted with its connection (ON DELETE CASCADE) and with the
--    account.
--
-- RLS is on with no policies on both new tables, so only the service role (the
-- server) reads or writes them.
--
-- Safe to run twice.

-- ── 1 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.member_store_connections (
  id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 uuid        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  platform                text        NOT NULL,
  store_url               text        NOT NULL,
  credentials_ciphertext  text        NOT NULL,
  credentials_iv          text        NOT NULL,
  credentials_auth_tag    text        NOT NULL,
  status                  text        NOT NULL DEFAULT 'connected',
  last_sync_at            timestamptz,
  last_error_code         text,
  last_error_at           timestamptz,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_store_connections_unique UNIQUE (user_id, platform, store_url),
  CONSTRAINT member_store_connections_platform_check CHECK (platform IN ('shopify', 'woocommerce')),
  CONSTRAINT member_store_connections_status_check CHECK (status IN ('connected', 'needs_reconnect', 'disconnected')),
  CONSTRAINT member_store_connections_url_check CHECK (char_length(store_url) BETWEEN 4 AND 253),
  CONSTRAINT member_store_connections_ciphertext_check CHECK (credentials_ciphertext ~ '^[0-9a-f]+$'),
  CONSTRAINT member_store_connections_iv_check CHECK (credentials_iv ~ '^[0-9a-f]{24}$'),
  CONSTRAINT member_store_connections_auth_tag_check CHECK (credentials_auth_tag ~ '^[0-9a-f]{32}$'),
  CONSTRAINT member_store_connections_error_code_check CHECK (last_error_code IS NULL OR char_length(last_error_code) <= 60)
);

CREATE INDEX IF NOT EXISTS member_store_connections_status_idx
  ON public.member_store_connections (status);

ALTER TABLE public.member_store_connections ENABLE ROW LEVEL SECURITY;

-- ── 2 ───────────────────────────────────────────────────────────────────────
ALTER TABLE public.inventory_items ADD COLUMN IF NOT EXISTS source text;
ALTER TABLE public.inventory_items ADD COLUMN IF NOT EXISTS store_connection_id uuid;
ALTER TABLE public.inventory_items ADD COLUMN IF NOT EXISTS external_id text;
ALTER TABLE public.inventory_items ADD COLUMN IF NOT EXISTS synced_at timestamptz;

DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'inventory_items_source_check' AND conrelid = 'public.inventory_items'::regclass) THEN
  ALTER TABLE public.inventory_items ADD CONSTRAINT inventory_items_source_check CHECK (
    (source IS NULL AND store_connection_id IS NULL AND external_id IS NULL) OR
    (source IN ('shopify', 'woocommerce') AND store_connection_id IS NOT NULL AND external_id IS NOT NULL AND char_length(external_id) <= 100)
  );
END IF; END $$;

-- A plain UNIQUE (not a partial index), so the sync's upsert can name it; NULLs
-- are distinct, so every manual row stays outside it.
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'inventory_items_store_external_unique' AND conrelid = 'public.inventory_items'::regclass) THEN
  ALTER TABLE public.inventory_items ADD CONSTRAINT inventory_items_store_external_unique UNIQUE (store_connection_id, external_id);
END IF; END $$;

-- ── 3 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.store_order_summaries (
  id             uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid          NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  connection_id  uuid          NOT NULL REFERENCES public.member_store_connections(id) ON DELETE CASCADE,
  platform       text          NOT NULL,
  external_id    text          NOT NULL,
  ordered_at     timestamptz   NOT NULL,
  total          numeric(14,2),
  currency       text,
  line_items     jsonb         NOT NULL DEFAULT '[]'::jsonb,
  created_at     timestamptz   NOT NULL DEFAULT now(),
  updated_at     timestamptz   NOT NULL DEFAULT now(),
  CONSTRAINT store_order_summaries_unique UNIQUE (connection_id, external_id),
  CONSTRAINT store_order_summaries_platform_check CHECK (platform IN ('shopify', 'woocommerce')),
  CONSTRAINT store_order_summaries_external_check CHECK (char_length(external_id) BETWEEN 1 AND 100),
  CONSTRAINT store_order_summaries_currency_check CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
  CONSTRAINT store_order_summaries_line_items_check CHECK (jsonb_typeof(line_items) = 'array')
);

CREATE INDEX IF NOT EXISTS store_order_summaries_user_ordered_idx
  ON public.store_order_summaries (user_id, ordered_at DESC);

ALTER TABLE public.store_order_summaries ENABLE ROW LEVEL SECURITY;
