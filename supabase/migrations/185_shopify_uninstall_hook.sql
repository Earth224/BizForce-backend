-- Not yet applied. The owner applies it by hand in the Supabase SQL editor.
-- W-T3: Shopify app/uninstalled, subscribed per shop. The app keeps
-- use_legacy_install_flow = true, and Shopify refuses app-specific webhook
-- subscriptions in shopify.app.toml with that flow, so the backend subscribes
-- each connected shop to APP_UNINSTALLED through the Admin API
-- (webhookSubscriptionCreate) after the connect and on later syncs.
-- uninstall_hook_at: when that subscription was last confirmed to point at the
-- backend's /api/webhooks/shopify. NULL means not yet confirmed: the next
-- Shopify sync tries again. Set on Shopify rows only; other platforms keep NULL.
-- member_store_connections has no jsonb field to hold this, so it is a column.
-- RLS is unchanged.
BEGIN;

ALTER TABLE public.member_store_connections
  ADD COLUMN IF NOT EXISTS uninstall_hook_at timestamptz NULL;

COMMIT;
