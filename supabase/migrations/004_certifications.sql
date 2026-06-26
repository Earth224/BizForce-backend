-- Phase 4: User certifications
-- Records certification attempts and earned badges for each user.

CREATE TABLE IF NOT EXISTS user_certifications (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid        NOT NULL,
  cert_id       text        NOT NULL,
  category      text        NOT NULL,
  score         integer     NOT NULL DEFAULT 0,
  passed        boolean     NOT NULL DEFAULT false,
  earned_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT user_certifications_user_cert_unique UNIQUE (user_id, cert_id),
  CONSTRAINT user_certifications_score_check CHECK (score >= 0 AND score <= 100)
);

CREATE INDEX IF NOT EXISTS user_certifications_user_id_idx
  ON user_certifications (user_id);

CREATE INDEX IF NOT EXISTS user_certifications_user_id_passed_idx
  ON user_certifications (user_id, passed);

ALTER TABLE user_certifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_certifications_select_own
  ON user_certifications FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY user_certifications_insert_own
  ON user_certifications FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY user_certifications_update_own
  ON user_certifications FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);
