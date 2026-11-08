-- Applied by the owner by hand in the Supabase SQL editor on Nov 8, 2026. This file is the text as run.
ALTER TABLE public.member_store_connections
  DROP CONSTRAINT member_store_connections_platform_check,
  DROP CONSTRAINT member_store_connections_token_shape_check;

ALTER TABLE public.member_store_connections
  ADD COLUMN IF NOT EXISTS external_account_id text;

ALTER TABLE public.member_store_connections
  ADD CONSTRAINT member_store_connections_platform_check CHECK (platform IN ('shopify', 'woocommerce', 'etsy')),
  ADD CONSTRAINT member_store_connections_external_account_check CHECK (external_account_id IS NULL OR external_account_id ~ '^[0-9]{1,30}$'),
  ADD CONSTRAINT member_store_connections_token_shape_check CHECK (
    (platform = 'shopify' AND access_ciphertext IS NOT NULL AND access_iv IS NOT NULL AND access_auth_tag IS NOT NULL AND access_expires_at IS NOT NULL
      AND external_account_id IS NULL)
    OR
    (platform = 'woocommerce' AND access_ciphertext IS NULL AND access_iv IS NULL AND access_auth_tag IS NULL AND access_expires_at IS NULL
      AND refresh_expires_at IS NULL AND location_id IS NULL AND location_name IS NULL AND external_account_id IS NULL)
    OR
    (platform = 'etsy' AND access_ciphertext IS NOT NULL AND access_iv IS NOT NULL AND access_auth_tag IS NOT NULL AND access_expires_at IS NOT NULL
      AND location_id IS NULL AND location_name IS NULL AND external_account_id IS NOT NULL)
  );

CREATE UNIQUE INDEX IF NOT EXISTS member_store_connections_etsy_shop_key
  ON public.member_store_connections (external_account_id) WHERE platform = 'etsy';

ALTER TABLE public.inventory_items
  DROP CONSTRAINT inventory_items_source_check;

ALTER TABLE public.inventory_items
  ADD CONSTRAINT inventory_items_source_check CHECK (
    source IS NULL
    OR (source IN ('shopify', 'woocommerce', 'etsy') AND store_connection_id IS NOT NULL AND external_id IS NOT NULL AND char_length(external_id) <= 100)
  );

ALTER TABLE public.store_order_summaries
  DROP CONSTRAINT store_order_summaries_platform_check;

ALTER TABLE public.store_order_summaries
  ADD CONSTRAINT store_order_summaries_platform_check CHECK (platform IN ('shopify', 'woocommerce', 'etsy'));

ALTER TABLE public.oauth_states
  DROP CONSTRAINT oauth_states_purpose_check,
  DROP CONSTRAINT oauth_states_context_check;

ALTER TABLE public.oauth_states
  ADD CONSTRAINT oauth_states_purpose_check CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google', 'tiktok_login', 'instagram_login', 'facebook_login', 'store_etsy')),
  ADD CONSTRAINT oauth_states_context_check CHECK (
    ((purpose IN ('store_shopify', 'store_etsy')) = (flow_context IS NOT NULL))
    AND (flow_context IS NULL OR octet_length(flow_context::text) <= 1000)
  );
