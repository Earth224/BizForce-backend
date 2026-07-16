-- Backfill: cover_wraps table (Cover Designer) created live, never migrated. Idempotent. Documents live truth.
-- Mirrors 035_bizbooks.sql's RLS pattern (RLS enabled, owner_id = auth.uid() policies) since that's
-- the pattern the sibling table in this project actually uses.

CREATE TABLE IF NOT EXISTS cover_wraps (
id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
owner_id uuid NOT NULL,
name text,
trim_size text DEFAULT '6x9',
page_count integer,
paper_stock text DEFAULT 'white',
front_design jsonb,
spine_design jsonb,
back_design jsonb,
created_at timestamptz DEFAULT now(),
updated_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cover_wraps_owner_id_idx ON cover_wraps (owner_id);

ALTER TABLE cover_wraps ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'cover_wraps' AND policyname = 'cover_wraps_select'
  ) THEN
    CREATE POLICY cover_wraps_select ON cover_wraps
    FOR SELECT USING (owner_id = auth.uid());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'cover_wraps' AND policyname = 'cover_wraps_insert'
  ) THEN
    CREATE POLICY cover_wraps_insert ON cover_wraps
    FOR INSERT WITH CHECK (owner_id = auth.uid());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'cover_wraps' AND policyname = 'cover_wraps_update'
  ) THEN
    CREATE POLICY cover_wraps_update ON cover_wraps
    FOR UPDATE USING (owner_id = auth.uid());
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'cover_wraps' AND policyname = 'cover_wraps_delete'
  ) THEN
    CREATE POLICY cover_wraps_delete ON cover_wraps
    FOR DELETE USING (owner_id = auth.uid());
  END IF;
END $$;
