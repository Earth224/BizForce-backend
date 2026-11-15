-- Not yet applied. The owner applies it by hand in the Supabase SQL editor.
-- W1: Shopify webhooks, part 1 of 2. Columns on shopify_webhook_events (migration 176)
-- for the privacy webhooks, and a partial index for the retry sweep.
-- request_details: customers/data_request and customers/redact only. Holds the Shopify
-- customer id, the orders_requested or orders_to_redact ids, and the data_request id.
-- Never the email, phone or name.
-- RLS is unchanged: enabled, with all rights revoked from anon and authenticated (176).
BEGIN;

ALTER TABLE public.shopify_webhook_events
  ADD COLUMN IF NOT EXISTS request_details jsonb NULL,
  ADD COLUMN IF NOT EXISTS answered_at timestamptz NULL,
  ADD COLUMN IF NOT EXISTS owner_notified_at timestamptz NULL;

CREATE INDEX IF NOT EXISTS shopify_webhook_events_unprocessed_idx
  ON public.shopify_webhook_events (received_at)
  WHERE processed_at IS NULL;

COMMIT;
