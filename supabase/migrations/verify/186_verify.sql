-- VERIFY for migration 186_member_videos_duration.sql. Read-only.
-- Expect two rows:
--   column      duration_ms, integer, nullable YES
--   constraint  member_videos_duration_check, CHECK ((duration_ms IS NULL) OR ((duration_ms > 0) AND (duration_ms <= 14400000)))
SELECT 'column' AS kind, column_name AS name, data_type AS detail, is_nullable AS nullable
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'member_videos'
  AND column_name = 'duration_ms'
UNION ALL
SELECT 'constraint', conname, pg_get_constraintdef(oid), NULL
FROM pg_constraint
WHERE conrelid = 'public.member_videos'::regclass
  AND conname = 'member_videos_duration_check';
