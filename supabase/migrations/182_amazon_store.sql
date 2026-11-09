-- Applied by the owner by hand in the Supabase SQL editor on Nov 8, 2026. This file is the text as run.
ALTER TABLE public.member_store_connections
  DROP CONSTRAINT member_store_connections_platform_check,
  DROP CONSTRAINT member_store_connections_token_shape_check,
  DROP CONSTRAINT member_store_connections_external_account_check;

ALTER TABLE public.member_store_connections
  ADD COLUMN IF NOT EXISTS marketplace_id text,
  ADD COLUMN IF NOT EXISTS region text;

ALTER TABLE public.member_store_connections
  ADD CONSTRAINT member_store_connections_platform_check CHECK (platform IN ('shopify', 'woocommerce', 'etsy', 'amazon')),
  ADD CONSTRAINT member_store_connections_external_account_check CHECK (
    external_account_id IS NULL
    OR (platform = 'etsy' AND external_account_id ~ '^[0-9]{1,30}$')
    OR (platform = 'amazon' AND external_account_id ~ '^[A-Z0-9]{8,20}$')
  ),
  ADD CONSTRAINT member_store_connections_marketplace_check CHECK (marketplace_id IS NULL OR marketplace_id ~ '^[A-Z0-9]{8,20}$'),
  ADD CONSTRAINT member_store_connections_region_check CHECK (region IS NULL OR region IN ('na', 'eu', 'fe')),
  ADD CONSTRAINT member_store_connections_token_shape_check CHECK (
    (platform = 'shopify' AND access_ciphertext IS NOT NULL AND access_iv IS NOT NULL AND access_auth_tag IS NOT NULL AND access_expires_at IS NOT NULL
      AND external_account_id IS NULL AND marketplace_id IS NULL AND region IS NULL)
    OR
    (platform = 'woocommerce' AND access_ciphertext IS NULL AND access_iv IS NULL AND access_auth_tag IS NULL AND access_expires_at IS NULL
      AND refresh_expires_at IS NULL AND location_id IS NULL AND location_name IS NULL AND external_account_id IS NULL
      AND marketplace_id IS NULL AND region IS NULL)
    OR
    (platform = 'etsy' AND access_ciphertext IS NOT NULL AND access_iv IS NOT NULL AND access_auth_tag IS NOT NULL AND access_expires_at IS NOT NULL
      AND location_id IS NULL AND location_name IS NULL AND external_account_id IS NOT NULL AND marketplace_id IS NULL AND region IS NULL)
    OR
    (platform = 'amazon' AND access_ciphertext IS NOT NULL AND access_iv IS NOT NULL AND access_auth_tag IS NOT NULL AND access_expires_at IS NOT NULL
      AND location_id IS NULL AND location_name IS NULL AND external_account_id IS NOT NULL AND marketplace_id IS NOT NULL AND region IS NOT NULL)
  );

CREATE UNIQUE INDEX IF NOT EXISTS member_store_connections_amazon_seller_key
  ON public.member_store_connections (external_account_id, marketplace_id) WHERE platform = 'amazon';

ALTER TABLE public.inventory_items
  DROP CONSTRAINT inventory_items_source_check;

ALTER TABLE public.inventory_items
  ADD CONSTRAINT inventory_items_source_check CHECK (
    source IS NULL
    OR (source IN ('shopify', 'woocommerce', 'etsy', 'amazon') AND store_connection_id IS NOT NULL AND external_id IS NOT NULL AND char_length(external_id) <= 100)
  );

ALTER TABLE public.store_order_summaries
  DROP CONSTRAINT store_order_summaries_platform_check;

ALTER TABLE public.store_order_summaries
  ADD CONSTRAINT store_order_summaries_platform_check CHECK (platform IN ('shopify', 'woocommerce', 'etsy', 'amazon'));

ALTER TABLE public.store_change_log
  ADD COLUMN IF NOT EXISTS confirmation text NOT NULL DEFAULT 'confirmed';

ALTER TABLE public.store_change_log
  ADD CONSTRAINT store_change_log_confirmation_check CHECK (confirmation IN ('confirmed', 'submitted'));

ALTER TABLE public.oauth_states
  DROP CONSTRAINT oauth_states_purpose_check,
  DROP CONSTRAINT oauth_states_verifier_shape_check,
  DROP CONSTRAINT oauth_states_context_check;

ALTER TABLE public.oauth_states
  ADD CONSTRAINT oauth_states_purpose_check CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google', 'tiktok_login', 'instagram_login', 'facebook_login', 'store_etsy', 'store_amazon')),
  ADD CONSTRAINT oauth_states_verifier_shape_check CHECK (
    purpose IN ('store_shopify', 'tiktok_login', 'instagram_login', 'facebook_login', 'store_amazon')
    OR (verifier_ciphertext IS NOT NULL AND verifier_iv IS NOT NULL AND verifier_auth_tag IS NOT NULL)
  ),
  ADD CONSTRAINT oauth_states_context_check CHECK (
    ((purpose IN ('store_shopify', 'store_etsy', 'store_amazon')) = (flow_context IS NOT NULL))
    AND (flow_context IS NULL OR octet_length(flow_context::text) <= 1000)
  );
