-- 136_social_post_publishing.sql
--
-- AN ALTER MIGRATION on public.social_post_drafts (created by 021, zernio_post_id
-- added by 022). No table is created and no row is touched. APPLIED BY HAND in the
-- Supabase SQL editor on 2026-10-11 and verified live: the verify query returned
-- 8 rows — the columns platform_post_uri, platform_post_cid, published_at,
-- publish_error and proposal_id, and the constraints
-- social_post_drafts_proposal_id_fkey, social_post_drafts_status_check and
-- social_post_drafts_published_check.
--
-- WHAT IT IS FOR. The Social agent's drafts will be filed as agent_proposals rows,
-- approved by the owner, and published by the proposal executor as top-level
-- Bluesky posts through lib/bskyGate.js. This prepares the table for that: where
-- the published post's uri and cid are recorded, when it was published, why a
-- publish failed, and which proposal the draft was filed as.
--
-- STATUS, CONSTRAINED FOR THE FIRST TIME. 021 left status as free text and
-- PUT /api/social-drafts/:id writes whatever the caller sends. The table held
-- 0 rows when this was written (read-only count, 2026-10-11), so no live value
-- has to be carried. The values the code writes today are kept, so nothing that
-- works now starts failing:
--   'pending'        the column default (021), and PUT's fallback
--   'not_published'  POST /api/social-drafts while SOCIAL_ACCOUNTS_SCOPED is false
--   'scheduled'      POST /api/social-drafts, Zernio path, with scheduled_for
--   'published'      POST /api/social-drafts, Zernio path, publishNow
-- and the publishing flow adds 'pending_approval' and 'publish_failed'.
-- The frontend never writes status: it sends "pending" in the POST body, which
-- the route ignores, and it never calls PUT.
--
-- WHAT THE CHECK DOES TO PUT. PUT stores any status string up to 40 characters
-- today; after this, anything outside the list above is refused by the database
-- and PUT answers 500 "Save failed". A PUT of 'published' is refused too, by the
-- check below, because PUT cannot set platform_post_uri or published_at. PUT can
-- still set 'pending_approval' and 'publish_failed'; closing that is the route's
-- job, not this migration's.
--
-- PUBLISHED MEANS POSTED. status = 'published' requires platform_post_uri and
-- published_at. 0 live rows, so no row violates it. NOTE: the Zernio path in
-- POST /api/social-drafts inserts 'published' with neither set; it is
-- unreachable while SOCIAL_ACCOUNTS_SCOPED is false, and this check would refuse
-- it if it were reached. That refusal is intended: a draft is never marked
-- published without proof that it was posted.
--
-- Dropping and re-adding each constraint inside one transaction means there is
-- no moment without it. Running this a second time is harmless.

BEGIN;

ALTER TABLE public.social_post_drafts
  ADD COLUMN IF NOT EXISTS platform_post_uri text,
  ADD COLUMN IF NOT EXISTS platform_post_cid text,
  ADD COLUMN IF NOT EXISTS published_at      timestamptz,
  ADD COLUMN IF NOT EXISTS publish_error     text,
  ADD COLUMN IF NOT EXISTS proposal_id       uuid;

ALTER TABLE public.social_post_drafts DROP CONSTRAINT IF EXISTS social_post_drafts_proposal_id_fkey;
ALTER TABLE public.social_post_drafts ADD  CONSTRAINT social_post_drafts_proposal_id_fkey
  FOREIGN KEY (proposal_id) REFERENCES public.agent_proposals(id) ON DELETE SET NULL;

ALTER TABLE public.social_post_drafts DROP CONSTRAINT IF EXISTS social_post_drafts_status_check;
ALTER TABLE public.social_post_drafts ADD  CONSTRAINT social_post_drafts_status_check
  CHECK (status IN ('pending', 'not_published', 'scheduled',
                    'pending_approval', 'published', 'publish_failed'));

ALTER TABLE public.social_post_drafts DROP CONSTRAINT IF EXISTS social_post_drafts_published_check;
ALTER TABLE public.social_post_drafts ADD  CONSTRAINT social_post_drafts_published_check
  CHECK (status <> 'published' OR (platform_post_uri IS NOT NULL AND published_at IS NOT NULL));

COMMENT ON COLUMN public.social_post_drafts.platform_post_uri IS
  'The published post''s identifier on the platform (for Bluesky, the at:// uri returned by the post call). Set only by the server after a successful publish; required when status is published.';
COMMENT ON COLUMN public.social_post_drafts.platform_post_cid IS
  'The published post''s content id on the platform (for Bluesky, the cid returned with the uri). Set only by the server after a successful publish.';
COMMENT ON COLUMN public.social_post_drafts.published_at IS
  'When the server published the post. Set only by the server after a successful publish; required when status is published.';
COMMENT ON COLUMN public.social_post_drafts.publish_error IS
  'Why the last publish attempt did not post (including a rate limit), recorded with status publish_failed. Null when no attempt has failed.';
COMMENT ON COLUMN public.social_post_drafts.proposal_id IS
  'The agent_proposals row this draft was filed as for the owner''s approval. Null for drafts saved directly; set to null if the proposal is deleted.';

COMMIT;
