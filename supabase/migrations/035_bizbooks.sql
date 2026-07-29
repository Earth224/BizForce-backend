-- Storage bucket 'bf-books' must be created manually in Supabase Dashboard > Storage
-- Set bucket to PRIVATE (Public toggle OFF) — generated books are served via
-- short-lived signed download URLs, never a permanent public URL.

CREATE TABLE IF NOT EXISTS bizbooks (
id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
owner_id uuid NOT NULL,
title text NOT NULL,
author text,
storage_path text NOT NULL, -- path within the private bf-books bucket
page_count int, -- optional, if we can capture it
status text NOT NULL DEFAULT 'ready' CHECK (status IN ('ready','processing','failed')),
created_at timestamptz NOT NULL DEFAULT now(),
updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE bizbooks ENABLE ROW LEVEL SECURITY;

CREATE POLICY bizbooks_select ON bizbooks
FOR SELECT USING (owner_id = auth.uid());
CREATE POLICY bizbooks_insert ON bizbooks
FOR INSERT WITH CHECK (owner_id = auth.uid());
CREATE POLICY bizbooks_update ON bizbooks
FOR UPDATE USING (owner_id = auth.uid());
CREATE POLICY bizbooks_delete ON bizbooks
FOR DELETE USING (owner_id = auth.uid());
