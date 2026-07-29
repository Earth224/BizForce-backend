-- Adds a username column to bf_profiles, backfilled from profiles.username
-- (only where bf_profiles.username is still empty, so this is safe to re-run),
-- then enforces case-insensitive uniqueness the same way profiles.username
-- is expected to behave elsewhere in this project.

ALTER TABLE bf_profiles ADD COLUMN IF NOT EXISTS username text;

UPDATE bf_profiles bp
SET username = p.username
FROM profiles p
WHERE p.user_id = bp.user_id
  AND coalesce(p.username, '') <> ''
  AND coalesce(bp.username, '') = '';

CREATE UNIQUE INDEX IF NOT EXISTS bf_profiles_username_key ON bf_profiles (lower(username));
