-- Agent collaboration foundation
-- Run in Supabase SQL Editor before using /api/collaborations routes.

CREATE TABLE IF NOT EXISTS agent_collaborations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  parent_assignment_id uuid,
  source_agent text NOT NULL,
  target_agent text NOT NULL,
  collaboration_type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_collaborations_source_agent_check
    CHECK (source_agent IN ('executive', 'seo', 'content', 'sales', 'analytics', 'operations', 'reputation', 'social', 'email', 'community', 'influencer')),
  CONSTRAINT agent_collaborations_target_agent_check
    CHECK (target_agent IN ('executive', 'seo', 'content', 'sales', 'analytics', 'operations', 'reputation', 'social', 'email', 'community', 'influencer')),
  CONSTRAINT agent_collaborations_collaboration_type_check
    CHECK (collaboration_type IN ('handoff', 'request', 'response', 'review', 'approval', 'insight', 'memory_share')),
  CONSTRAINT agent_collaborations_status_check
    CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS agent_collaborations_user_id_idx
  ON agent_collaborations (user_id);

CREATE INDEX IF NOT EXISTS agent_collaborations_parent_assignment_id_idx
  ON agent_collaborations (parent_assignment_id);

CREATE INDEX IF NOT EXISTS agent_collaborations_source_agent_idx
  ON agent_collaborations (source_agent);

CREATE INDEX IF NOT EXISTS agent_collaborations_target_agent_idx
  ON agent_collaborations (target_agent);

CREATE INDEX IF NOT EXISTS agent_collaborations_status_idx
  ON agent_collaborations (status);

CREATE INDEX IF NOT EXISTS agent_collaborations_created_at_desc_idx
  ON agent_collaborations (created_at DESC);

ALTER TABLE agent_collaborations ENABLE ROW LEVEL SECURITY;

CREATE POLICY agent_collaborations_select_own
  ON agent_collaborations
  FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY agent_collaborations_insert_own
  ON agent_collaborations
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY agent_collaborations_update_own
  ON agent_collaborations
  FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY agent_collaborations_delete_own
  ON agent_collaborations
  FOR DELETE
  USING (auth.uid() = user_id);
