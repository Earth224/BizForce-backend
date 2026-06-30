-- Migration 014: Business Profile
-- One row per user; supplies business context to AI agents.
-- No FK on user_id to match existing schema pattern (see 009_profile_page.sql).

CREATE TABLE IF NOT EXISTS business_profiles (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid        NOT NULL UNIQUE,
  business_name     text,
  industry          text,
  website           text,
  location          text,
  target_audience   text,
  brand_voice       text,
  brand_values      text,
  business_goals    text,
  banned_topics     text,
  competitors       text,
  social_platforms  jsonb       NOT NULL DEFAULT '{}',
  posting_frequency text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS business_profiles_user_id_idx ON business_profiles (user_id);

ALTER TABLE business_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY business_profiles_select_own ON business_profiles FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY business_profiles_insert_own ON business_profiles FOR INSERT
  WITH CHECK (auth.uid() = user_id);
CREATE POLICY business_profiles_update_own ON business_profiles FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY business_profiles_delete_own ON business_profiles FOR DELETE
  USING (auth.uid() = user_id);
