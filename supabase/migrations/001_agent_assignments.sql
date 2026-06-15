-- Phase 1: agent_assignments foundation
-- Run in Supabase SQL Editor before using /api/assignments routes.

CREATE TABLE IF NOT EXISTS agent_assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  executive_task_id uuid NOT NULL,
  assignment_number integer NOT NULL,
  agent_type text NOT NULL,
  mission text,
  priority text,
  timeline text,
  tasks jsonb NOT NULL DEFAULT '[]'::jsonb,
  kpis jsonb NOT NULL DEFAULT '[]'::jsonb,
  risks jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_assignments_status_check
    CHECK (status IN ('pending', 'in_progress', 'completed', 'failed')),
  CONSTRAINT agent_assignments_unique_assignment
    UNIQUE (user_id, executive_task_id, assignment_number, agent_type)
);

CREATE INDEX IF NOT EXISTS agent_assignments_user_id_status_idx
  ON agent_assignments (user_id, status);

CREATE INDEX IF NOT EXISTS agent_assignments_user_id_executive_task_id_idx
  ON agent_assignments (user_id, executive_task_id);

CREATE INDEX IF NOT EXISTS agent_assignments_user_id_created_at_idx
  ON agent_assignments (user_id, created_at DESC);

ALTER TABLE agent_assignments ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_assignments_select_own
  ON agent_assignments
  FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY agent_assignments_insert_own
  ON agent_assignments
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY agent_assignments_update_own
  ON agent_assignments
  FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY agent_assignments_delete_own
  ON agent_assignments
  FOR DELETE
  USING (auth.uid() = user_id);
