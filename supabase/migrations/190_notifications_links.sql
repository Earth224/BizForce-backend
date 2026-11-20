-- P2-1 (Nov 19 2026): a notification that can open what it is about.
-- Safe to re-run: ADD COLUMN / CREATE INDEX IF NOT EXISTS, and each named CHECK is
-- dropped if it exists before it is added.
--
-- notifications (migration 081) has id, user_id, type, title, message, read,
-- read_at, created_at. Checked live before writing (Nov 19 2026): none of the four
-- new columns exist; the table has 10 rows, all of which keep NULL in the new
-- columns, which every CHECK below allows.
--
-- 1. actor_id: the member who caused the notice (a follower, a commenter, a
--    tipper). SET NULL when that account goes, so the recipient's notice stays.
-- 2. object_type and object_id: what the notice is about. No foreign key, because
--    the object may be any of several tables.
-- 3. link: where tapping the notice goes. A path on this site only (starts with
--    '/', not '//'), at most 300 characters, so a notice can never send a member
--    off-site.
-- 4. notifications_unread_idx: the Inbox's unread count and list.
--
-- The columns are part of the recipient's notifications rows, so they are exported
-- and deleted with the account like the rest of those rows (lib/yourData.js).
-- Row level security stays on (migration 081).
BEGIN;

ALTER TABLE public.notifications
  ADD COLUMN IF NOT EXISTS actor_id    uuid REFERENCES public.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS object_type text,
  ADD COLUMN IF NOT EXISTS object_id   uuid,
  ADD COLUMN IF NOT EXISTS link        text;

ALTER TABLE public.notifications DROP CONSTRAINT IF EXISTS notifications_object_type_check;
ALTER TABLE public.notifications ADD CONSTRAINT notifications_object_type_check
  CHECK (object_type IS NULL OR object_type IN
    ('post', 'comment', 'message', 'proposal', 'listing', 'order', 'tip',
     'follow', 'report', 'review', 'campaign'));

ALTER TABLE public.notifications DROP CONSTRAINT IF EXISTS notifications_link_check;
ALTER TABLE public.notifications ADD CONSTRAINT notifications_link_check
  CHECK (link IS NULL OR (link ~ '^/[^/]' AND char_length(link) <= 300));

CREATE INDEX IF NOT EXISTS notifications_unread_idx
  ON public.notifications (user_id, created_at DESC)
  WHERE read = false;

COMMIT;
