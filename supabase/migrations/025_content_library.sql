CREATE TABLE IF NOT EXISTS content_library (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  type text NOT NULL CHECK (type IN ('blog','sms')),
  title text,
  keyword text,
  source_url text,
  body text NOT NULL,
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','used')),
  created_at timestamptz NOT NULL DEFAULT now()
);
