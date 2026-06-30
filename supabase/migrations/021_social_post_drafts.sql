-- Migration 021: Social Post Drafts
-- Stores AI-generated social media post drafts per user.
-- No FK on user_id to match existing schema pattern (see 014_business_profiles.sql).

CREATE TABLE IF NOT EXISTS social_post_drafts (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid        NOT NULL,
  platform       text,
  content        text,
  status         text        NOT NULL DEFAULT 'pending',
  scheduled_for  timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS social_post_drafts_user_id_idx ON social_post_drafts (user_id);

ALTER TABLE social_post_drafts ENABLE ROW LEVEL SECURITY;

CREATE POLICY social_post_drafts_select_own ON social_post_drafts FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY social_post_drafts_insert_own ON social_post_drafts FOR INSERT
  WITH CHECK (auth.uid() = user_id);
CREATE POLICY social_post_drafts_update_own ON social_post_drafts FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY social_post_drafts_delete_own ON social_post_drafts FOR DELETE
  USING (auth.uid() = user_id);
