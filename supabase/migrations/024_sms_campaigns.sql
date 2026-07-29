-- Migration 024: SMS Campaigns
-- Stores SMS broadcast campaigns per user.
-- No FK on user_id to match existing schema pattern (see 014_business_profiles.sql).

CREATE TABLE IF NOT EXISTS sms_campaigns (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid        NOT NULL,
  name            text        NOT NULL,
  status          text        NOT NULL DEFAULT 'draft',
  segment_filter  text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sms_campaigns_user_id_idx ON sms_campaigns (user_id);

ALTER TABLE sms_campaigns ENABLE ROW LEVEL SECURITY;

CREATE POLICY sms_campaigns_select_own ON sms_campaigns FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY sms_campaigns_insert_own ON sms_campaigns FOR INSERT
  WITH CHECK (auth.uid() = user_id);
CREATE POLICY sms_campaigns_update_own ON sms_campaigns FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY sms_campaigns_delete_own ON sms_campaigns FOR DELETE
  USING (auth.uid() = user_id);
