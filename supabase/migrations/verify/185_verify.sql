-- VERIFY for migration 185_shopify_uninstall_hook.sql. Read-only.
-- Expect one row: uninstall_hook_at, timestamp with time zone, nullable YES.
SELECT column_name AS name, data_type AS detail, is_nullable AS nullable
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'member_store_connections'
  AND column_name = 'uninstall_hook_at';
