-- VERIFY for migration 184_shopify_webhook_requests.sql. Read-only.
-- Expect four rows: three columns (all nullable) and one index.
SELECT 'column' AS kind, column_name AS name, data_type AS detail, is_nullable AS nullable
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'shopify_webhook_events'
  AND column_name IN ('request_details', 'answered_at', 'owner_notified_at')
UNION ALL
SELECT 'index' AS kind, indexname AS name, indexdef AS detail, NULL AS nullable
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename = 'shopify_webhook_events'
  AND indexname = 'shopify_webhook_events_unprocessed_idx'
ORDER BY kind, name;
