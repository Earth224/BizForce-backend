-- 166_campaign_sharing.sql — a crowdfunding campaign's public page, off by
-- default, at bizforceai.net/campaign/<share_id> (build list item 3).
--
-- Applied by the owner by hand in the Supabase SQL editor on Nov 4, 2026. This file is the text as run.
--
-- WHY. A campaign could be seen only by signed-in members, on campaigns.html,
-- and had no link of its own. This adds the switch and the link:
--
--   share_id          16 lowercase base32 characters (a-z, 2-7), made from 10
--                     random bytes by lib/campaignShare.js newShareId. Null
--                     until sharing is first turned on. "Make a new link"
--                     replaces it, so the old link stops working at once.
--                     Unique across every campaign.
--   share_on          false by default: no campaign is public until its owner
--                     turns sharing on. It needs a share_id.
--   discoverable      false by default: without it the page is noindex and is
--                     left out of /api/sitemap/campaigns.xml.
--   share_changed_at  when sharing was last switched or the link replaced.
--
-- THE POLICY. campaigns_select (031) let any role read every active campaign.
-- server.js reads with the service role, which RLS does not bind, so the
-- policy now lets a signed-in member read only their own rows directly.
--
-- No new table, so no new RLS enablement and no backup list change.

ALTER TABLE public.crowdfunding_campaigns
  ADD COLUMN IF NOT EXISTS share_id text,
  ADD COLUMN IF NOT EXISTS share_on boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS discoverable boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS share_changed_at timestamptz;

ALTER TABLE public.crowdfunding_campaigns
  ADD CONSTRAINT crowdfunding_campaigns_share_id_check CHECK (share_id IS NULL OR share_id ~ '^[a-z2-7]{16}$'),
  ADD CONSTRAINT crowdfunding_campaigns_share_needs_id_check CHECK (share_on = false OR share_id IS NOT NULL);

CREATE UNIQUE INDEX IF NOT EXISTS crowdfunding_campaigns_share_id_key
  ON public.crowdfunding_campaigns (share_id) WHERE share_id IS NOT NULL;

ALTER POLICY campaigns_select ON public.crowdfunding_campaigns
  TO authenticated
  USING (owner_id = auth.uid());
