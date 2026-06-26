-- Phase 8: Flyer Generator saved flyers

CREATE TABLE IF NOT EXISTS saved_flyers (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL,
  name        text        NOT NULL DEFAULT 'Untitled Flyer',
  template    text        NOT NULL DEFAULT 'professional',
  color_theme text        NOT NULL DEFAULT 'neon',
  content     jsonb       NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT saved_flyers_template_check   CHECK (template    IN ('professional','bold','minimal')),
  CONSTRAINT saved_flyers_color_check      CHECK (color_theme IN ('neon','crimson','jade','gold'))
);

CREATE INDEX IF NOT EXISTS saved_flyers_user_id_idx
  ON saved_flyers (user_id, updated_at DESC);

ALTER TABLE saved_flyers ENABLE ROW LEVEL SECURITY;

CREATE POLICY saved_flyers_select_own ON saved_flyers FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY saved_flyers_insert_own ON saved_flyers FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY saved_flyers_update_own ON saved_flyers FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY saved_flyers_delete_own ON saved_flyers FOR DELETE USING (auth.uid() = user_id);
