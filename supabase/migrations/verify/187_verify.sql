-- VERIFY for migration 187_member_video_parts.sql. Read-only.
-- Expect 15 rows:
--   constraint  member_videos_bytes_check       CHECK (((bytes > 0) AND (bytes <= 524288000)))
--   column      member_videos.part_count         smallint, nullable NO, default 1
--   constraint  member_videos_part_count_check  CHECK (((part_count >= 1) AND (part_count <= 12)))
--   table       member_video_parts               rls true
--   column      member_video_parts.* x 9 (id, user_id, video_id, upload_path, idx, path, bytes, sha256, created_at)
--   grants      member_video_parts anon/authenticated privileges: 0
--   bucket      bf-video file_size_limit 52428800 (unchanged)
SELECT 'constraint' AS kind, conname AS name, pg_get_constraintdef(oid) AS detail
FROM pg_constraint
WHERE conrelid = 'public.member_videos'::regclass
  AND conname IN ('member_videos_bytes_check', 'member_videos_part_count_check')
UNION ALL
SELECT 'column', table_name || '.' || column_name, data_type || ', nullable ' || is_nullable || ', default ' || coalesce(column_default, '-')
FROM information_schema.columns
WHERE table_schema = 'public'
  AND ((table_name = 'member_videos' AND column_name = 'part_count') OR table_name = 'member_video_parts')
UNION ALL
SELECT 'table', relname, 'rls ' || relrowsecurity::text
FROM pg_class
WHERE oid = 'public.member_video_parts'::regclass
UNION ALL
SELECT 'grants', 'member_video_parts', 'anon/authenticated privileges: ' || count(*)::text
FROM information_schema.role_table_grants
WHERE table_schema = 'public' AND table_name = 'member_video_parts' AND grantee IN ('anon', 'authenticated')
UNION ALL
SELECT 'bucket', id, 'file_size_limit ' || coalesce(file_size_limit::text, 'null')
FROM storage.buckets
WHERE id = 'bf-video';
