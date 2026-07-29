-- Migration 028: Public lead capture table
-- Run in Supabase SQL Editor.
--
-- Backs POST /api/capture (server.js) — a public, unauthenticated landing-page
-- endpoint (e.g. vitality.html) that captures email/phone/name, then
-- optionally syncs into sms_subscribers + sms_campaign_enrollments when
-- sms_consent is true. owner_id is hardcoded in server.js (no logged-in user
-- context for a public visitor), so no FK to auth.users, matching the
-- existing schema pattern (see 014_business_profiles.sql / 023_sms_subscribers.sql).

CREATE TABLE IF NOT EXISTS lead_captures (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id          uuid        NOT NULL,
  source            text        NOT NULL DEFAULT 'direct'
                    CHECK (source IN ('bluesky', 'mastodon', 'youtube', 'direct', 'other')),
  brand             text        NOT NULL DEFAULT 'mrearthrose'
                    CHECK (brand IN ('mrearthrose', 'swordvitality', 'blacksuncircle', 'bizforce')),
  email             text,
  phone             text,
  name              text,
  sms_consent       boolean     NOT NULL DEFAULT false,
  email_consent     boolean     NOT NULL DEFAULT false,
  consent_ip        text,
  consent_timestamp timestamptz NOT NULL DEFAULT now(),
  status            text        NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new', 'synced', 'enrolled')),
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS lead_captures_owner_id_idx ON lead_captures (owner_id);
CREATE INDEX IF NOT EXISTS lead_captures_status_idx ON lead_captures (status);

ALTER TABLE lead_captures ENABLE ROW LEVEL SECURITY;

-- The public /api/capture route writes via the service-role key (bypasses
-- RLS entirely), so these policies only govern direct anon/authenticated
-- access if this table is ever queried from the client side.
CREATE POLICY lead_captures_select_own ON lead_captures FOR SELECT
  USING (auth.uid() = owner_id);
