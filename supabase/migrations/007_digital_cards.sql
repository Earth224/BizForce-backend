-- Phase 7: Digital business cards

CREATE TABLE IF NOT EXISTS digital_cards (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL,
  full_name  text        NOT NULL DEFAULT '',
  job_title  text        NOT NULL DEFAULT '',
  email      text        NOT NULL DEFAULT '',
  phone      text        NOT NULL DEFAULT '',
  company    text        NOT NULL DEFAULT '',
  website    text        NOT NULL DEFAULT '',
  theme      text        NOT NULL DEFAULT 'dark',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS digital_cards_user_id_idx ON digital_cards (user_id);

ALTER TABLE digital_cards ENABLE ROW LEVEL SECURITY;

CREATE POLICY digital_cards_select_own ON digital_cards FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY digital_cards_insert_own ON digital_cards FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY digital_cards_update_own ON digital_cards FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY digital_cards_delete_own ON digital_cards FOR DELETE USING (auth.uid() = user_id);
