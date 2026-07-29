-- Migration 023: SMS Subscribers
-- Stores opted-in SMS contacts per user for the SMS Marketing Agent.
-- No FK on user_id to match existing schema pattern (see 014_business_profiles.sql).

CREATE TABLE IF NOT EXISTS sms_subscribers (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid        NOT NULL,
  phone_number      text        NOT NULL,
  customer_name     text,
  product_purchased text,
  consent_status    text        NOT NULL DEFAULT 'opted_in',
  consent_timestamp timestamptz NOT NULL DEFAULT now(),
  last_contacted    timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT sms_subscribers_user_phone_key UNIQUE (user_id, phone_number)
);

CREATE INDEX IF NOT EXISTS sms_subscribers_user_id_idx ON sms_subscribers (user_id);

ALTER TABLE sms_subscribers ENABLE ROW LEVEL SECURITY;

CREATE POLICY sms_subscribers_select_own ON sms_subscribers FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY sms_subscribers_insert_own ON sms_subscribers FOR INSERT
  WITH CHECK (auth.uid() = user_id);
CREATE POLICY sms_subscribers_update_own ON sms_subscribers FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY sms_subscribers_delete_own ON sms_subscribers FOR DELETE
  USING (auth.uid() = user_id);
