-- Migration 027: Sales Agent lead-conversion pipeline tracking
-- Run in Supabase SQL Editor.
--
-- bsky_leads (populated by Lead Radar, see leadRadar.js) has no user_id at
-- all — it is a single shared, platform-wide capture feed, not per-tenant
-- data. Its own `status` column is Lead Radar's internal scoring lifecycle
-- ("new" = not yet scored, "scored" = scored and ready to display).
-- Reusing that column for the Sales Agent's contacted/converted pipeline
-- would collide with Lead Radar's own queries (scoreNewLeads() selects
-- status = 'new'; GET /api/leads selects status = 'scored') and break lead
-- capture/scoring.
--
-- Instead, this table tracks each user's own progress on a given shared
-- lead independently, keyed by bsky_leads.post_uri (the same stable unique
-- key Lead Radar already upserts on) rather than bsky_leads.id, so this
-- migration has no dependency on that table's column types.

CREATE TABLE IF NOT EXISTS sales_lead_pipeline (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid        NOT NULL,
  lead_post_uri  text        NOT NULL,
  status         text        NOT NULL DEFAULT 'new'
                 CHECK (status IN ('new', 'drafted', 'contacted', 'replied', 'converted')),
  last_draft     text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT sales_lead_pipeline_user_lead_key UNIQUE (user_id, lead_post_uri)
);

CREATE INDEX IF NOT EXISTS sales_lead_pipeline_user_status_idx
  ON sales_lead_pipeline (user_id, status);

ALTER TABLE sales_lead_pipeline ENABLE ROW LEVEL SECURITY;

CREATE POLICY sales_lead_pipeline_select_own ON sales_lead_pipeline FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY sales_lead_pipeline_insert_own ON sales_lead_pipeline FOR INSERT
  WITH CHECK (auth.uid() = user_id);
CREATE POLICY sales_lead_pipeline_update_own ON sales_lead_pipeline FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY sales_lead_pipeline_delete_own ON sales_lead_pipeline FOR DELETE
  USING (auth.uid() = user_id);
