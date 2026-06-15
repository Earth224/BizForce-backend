-- Agent memory foundation
-- Run in Supabase SQL Editor before using /api/memory routes.

CREATE TABLE IF NOT EXISTS agent_memory (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  agent_type text NOT NULL,
  assignment_id uuid,
  memory_type text NOT NULL,
  title text NOT NULL,
  content text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_memory_agent_type_check
    CHECK (agent_type IN ('seo', 'content', 'sales', 'analytics', 'operations', 'reputation', 'executive')),
  CONSTRAINT agent_memory_memory_type_check
    CHECK (memory_type IN ('goal', 'task', 'campaign', 'insight', 'metric', 'conversation', 'report'))
);

CREATE INDEX IF NOT EXISTS agent_memory_user_id_idx
  ON agent_memory (user_id);

CREATE INDEX IF NOT EXISTS agent_memory_agent_type_idx
  ON agent_memory (agent_type);

CREATE INDEX IF NOT EXISTS agent_memory_memory_type_idx
  ON agent_memory (memory_type);

CREATE INDEX IF NOT EXISTS agent_memory_created_at_desc_idx
  ON agent_memory (created_at DESC);

ALTER TABLE agent_memory ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_memory_select_own
  ON agent_memory
  FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY agent_memory_insert_own
  ON agent_memory
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY agent_memory_update_own
  ON agent_memory
  FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY agent_memory_delete_own
  ON agent_memory
  FOR DELETE
  USING (auth.uid() = user_id);
