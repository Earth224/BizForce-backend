-- Applied by the owner by hand in the Supabase SQL editor on Nov 7, 2026. This file is the text as run.

ALTER TABLE public.member_store_connections
  DROP CONSTRAINT member_store_connections_write_platform_check;

ALTER TABLE public.member_store_connections
  ADD COLUMN IF NOT EXISTS access_ciphertext text,
  ADD COLUMN IF NOT EXISTS access_iv text,
  ADD COLUMN IF NOT EXISTS access_auth_tag text,
  ADD COLUMN IF NOT EXISTS access_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS refresh_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS token_version integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS granted_scopes text,
  ADD COLUMN IF NOT EXISTS location_id text,
  ADD COLUMN IF NOT EXISTS location_name text,
  ADD COLUMN IF NOT EXISTS currency text;

ALTER TABLE public.member_store_connections
  ADD CONSTRAINT member_store_connections_access_ciphertext_check CHECK (access_ciphertext IS NULL OR access_ciphertext ~ '^[0-9a-f]+$'),
  ADD CONSTRAINT member_store_connections_access_iv_check CHECK (access_iv IS NULL OR access_iv ~ '^[0-9a-f]{24}$'),
  ADD CONSTRAINT member_store_connections_access_tag_check CHECK (access_auth_tag IS NULL OR access_auth_tag ~ '^[0-9a-f]{32}$'),
  ADD CONSTRAINT member_store_connections_token_version_check CHECK (token_version >= 0),
  ADD CONSTRAINT member_store_connections_scopes_check CHECK (granted_scopes IS NULL OR (char_length(granted_scopes) <= 500 AND granted_scopes ~ '^[a-z_,]*$')),
  ADD CONSTRAINT member_store_connections_location_id_check CHECK (location_id IS NULL OR location_id ~ '^gid://shopify/Location/[0-9]+$'),
  ADD CONSTRAINT member_store_connections_location_name_check CHECK (location_name IS NULL OR char_length(location_name) <= 200),
  ADD CONSTRAINT member_store_connections_currency_check CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
  ADD CONSTRAINT member_store_connections_token_shape_check CHECK (
    (platform = 'shopify' AND access_ciphertext IS NOT NULL AND access_iv IS NOT NULL AND access_auth_tag IS NOT NULL AND access_expires_at IS NOT NULL)
    OR
    (platform = 'woocommerce' AND access_ciphertext IS NULL AND access_iv IS NULL AND access_auth_tag IS NULL AND access_expires_at IS NULL
      AND refresh_expires_at IS NULL AND location_id IS NULL AND location_name IS NULL)
  );

CREATE UNIQUE INDEX IF NOT EXISTS member_store_connections_shopify_shop_key
  ON public.member_store_connections (lower(store_url)) WHERE platform = 'shopify';

ALTER TABLE public.inventory_items
  ADD COLUMN IF NOT EXISTS external_inventory_item_id text;

ALTER TABLE public.inventory_items
  ADD CONSTRAINT inventory_items_external_inventory_item_id_check CHECK (external_inventory_item_id IS NULL OR (char_length(external_inventory_item_id) <= 100 AND external_inventory_item_id ~ '^[0-9]+$'));

ALTER TABLE public.store_change_log
  ADD COLUMN IF NOT EXISTS currency text,
  ADD COLUMN IF NOT EXISTS location_name text;

ALTER TABLE public.store_change_log
  ADD CONSTRAINT store_change_log_currency_check CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
  ADD CONSTRAINT store_change_log_location_name_check CHECK (location_name IS NULL OR char_length(location_name) <= 200);

ALTER TABLE public.oauth_states
  DROP CONSTRAINT oauth_states_purpose_check;

ALTER TABLE public.oauth_states
  ALTER COLUMN verifier_ciphertext DROP NOT NULL,
  ALTER COLUMN verifier_iv DROP NOT NULL,
  ALTER COLUMN verifier_auth_tag DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS flow_context jsonb;

ALTER TABLE public.oauth_states
  ADD CONSTRAINT oauth_states_purpose_check CHECK (purpose IN ('mailbox_microsoft', 'store_shopify')),
  ADD CONSTRAINT oauth_states_verifier_shape_check CHECK (
    purpose <> 'mailbox_microsoft'
    OR (verifier_ciphertext IS NOT NULL AND verifier_iv IS NOT NULL AND verifier_auth_tag IS NOT NULL)
  ),
  ADD CONSTRAINT oauth_states_context_check CHECK (
    ((purpose = 'store_shopify') = (flow_context IS NOT NULL))
    AND (flow_context IS NULL OR octet_length(flow_context::text) <= 1000)
  );

CREATE TABLE public.shopify_webhook_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id text NOT NULL UNIQUE,
  topic text NOT NULL,
  shop_domain text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  CONSTRAINT shopify_webhook_events_id_check CHECK (char_length(webhook_id) BETWEEN 1 AND 200),
  CONSTRAINT shopify_webhook_events_topic_check CHECK (topic IN ('app/uninstalled', 'customers/data_request', 'customers/redact', 'shop/redact')),
  CONSTRAINT shopify_webhook_events_shop_check CHECK (char_length(shop_domain) BETWEEN 4 AND 253)
);

CREATE INDEX shopify_webhook_events_received_idx ON public.shopify_webhook_events (received_at);

ALTER TABLE public.shopify_webhook_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.shopify_webhook_events FROM anon, authenticated;
