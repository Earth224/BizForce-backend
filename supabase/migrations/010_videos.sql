-- Phase 10: Videos section + extend bf_profiles with skills, industry, show_videos

ALTER TABLE bf_profiles ADD COLUMN IF NOT EXISTS skills      jsonb    NOT NULL DEFAULT '[]';
ALTER TABLE bf_profiles ADD COLUMN IF NOT EXISTS industry    text;
ALTER TABLE bf_profiles ADD COLUMN IF NOT EXISTS show_videos boolean  NOT NULL DEFAULT true;
ALTER TABLE bf_profiles ADD COLUMN IF NOT EXISTS title       text;

-- ── Videos ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bf_videos (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid        NOT NULL,
  title          text        NOT NULL,
  description    text,
  video_url      text        NOT NULL,
  video_type     text        NOT NULL DEFAULT 'youtube',
  thumbnail_url  text,
  sort_order     int         NOT NULL DEFAULT 0,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT bf_videos_type_check CHECK (video_type IN ('youtube','vimeo','upload'))
);

CREATE INDEX IF NOT EXISTS bf_videos_user_id_idx ON bf_videos (user_id, sort_order);

ALTER TABLE bf_videos ENABLE ROW LEVEL SECURITY;
CREATE POLICY bf_videos_select_public ON bf_videos FOR SELECT USING (true);
CREATE POLICY bf_videos_insert_own    ON bf_videos FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_videos_update_own    ON bf_videos FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_videos_delete_own    ON bf_videos FOR DELETE USING (auth.uid() = user_id);
