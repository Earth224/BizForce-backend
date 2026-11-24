-- ===== PART 204a: the member's business Fingerprint (run first) =====
-- LR-2 (Nov 23 2026): Lead Radar for every member. One row per member (lib/leadFingerprint.js builds it from what
-- BizForce already holds: listings, Offer posts, the profile and the place). Fields the member changed are named in
-- edited_fields, and an automatic rebuild never overwrites them. sources: where to look (bizforce, bluesky, youtube,
-- threads), each a boolean.
-- Paste-safe: no less-or-equal or greater-or-equal operators, no DO blocks, no transaction statements; every CHECK is
-- named and dropped if it exists first. Each part runs alone, in order: 204a, 204b, 204c, 204d, 204e, 204f.
-- Row level security is on with no policies, like every table: only the server (service role) reads or writes.
CREATE TABLE IF NOT EXISTS public.lead_fingerprints (
  user_id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  categories text[] NOT NULL DEFAULT '{}',
  place_city text,
  place_region text,
  reach text NOT NULL DEFAULT 'online',
  keywords text[] NOT NULL DEFAULT '{}',
  not_for_me text[] NOT NULL DEFAULT '{}',
  who_you_serve text,
  offer_summary text,
  sources jsonb NOT NULL DEFAULT '{"bizforce": true, "bluesky": true, "youtube": false, "threads": false}'::jsonb,
  built_at timestamptz,
  edited_at timestamptz,
  edited_fields text[] NOT NULL DEFAULT '{}'
);
ALTER TABLE public.lead_fingerprints DROP CONSTRAINT IF EXISTS lead_fingerprints_reach_check;
ALTER TABLE public.lead_fingerprints ADD CONSTRAINT lead_fingerprints_reach_check
  CHECK (reach IN ('city', '25mi', 'online'));
ALTER TABLE public.lead_fingerprints DROP CONSTRAINT IF EXISTS lead_fingerprints_keywords_check;
ALTER TABLE public.lead_fingerprints ADD CONSTRAINT lead_fingerprints_keywords_check
  CHECK (cardinality(keywords) < 13 AND cardinality(not_for_me) < 13 AND cardinality(categories) < 13);
ALTER TABLE public.lead_fingerprints DROP CONSTRAINT IF EXISTS lead_fingerprints_text_check;
ALTER TABLE public.lead_fingerprints ADD CONSTRAINT lead_fingerprints_text_check
  CHECK ((who_you_serve IS NULL OR char_length(who_you_serve) < 201) AND (offer_summary IS NULL OR char_length(offer_summary) < 301)
    AND (place_city IS NULL OR char_length(place_city) < 81) AND (place_region IS NULL OR char_length(place_region) < 81));
ALTER TABLE public.lead_fingerprints DROP CONSTRAINT IF EXISTS lead_fingerprints_sources_check;
ALTER TABLE public.lead_fingerprints ADD CONSTRAINT lead_fingerprints_sources_check
  CHECK (jsonb_typeof(sources) = 'object');
ALTER TABLE public.lead_fingerprints ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.lead_fingerprints FROM anon, authenticated;

-- ===== PART 204b: each member's own leads (run second) =====
-- A public post (or a BizForce Need) that matched the member's Fingerprint. author_place (the place a card shows) and
-- scored_at (when the model scored it; NULL waits, so a lead over the day's scoring cap is kept for the next day) are
-- beyond the brief's column list and are named in the LR-2 report. Rows not saved, replied or won are deleted after
-- 30 days (lib/memberRadar.js purgeOldLeads, the daily job member_leads_purge).
CREATE TABLE IF NOT EXISTS public.member_leads (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  source text NOT NULL,
  external_id text NOT NULL,
  url text,
  author_handle text,
  author_place text,
  text text NOT NULL DEFAULT '',
  posted_at timestamptz,
  matched_keyword text,
  match_reason text,
  score integer,
  scored_at timestamptz,
  outreach_safe boolean,
  reply_invited boolean,
  status text NOT NULL DEFAULT 'new',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.member_leads DROP CONSTRAINT IF EXISTS member_leads_source_check;
ALTER TABLE public.member_leads ADD CONSTRAINT member_leads_source_check
  CHECK (source IN ('bizforce', 'bluesky', 'youtube', 'threads'));
ALTER TABLE public.member_leads DROP CONSTRAINT IF EXISTS member_leads_status_check;
ALTER TABLE public.member_leads ADD CONSTRAINT member_leads_status_check
  CHECK (status IN ('new', 'saved', 'dismissed', 'replied', 'won', 'lost', 'archived'));
ALTER TABLE public.member_leads DROP CONSTRAINT IF EXISTS member_leads_score_check;
ALTER TABLE public.member_leads ADD CONSTRAINT member_leads_score_check
  CHECK (score IS NULL OR score BETWEEN 0 AND 100);
ALTER TABLE public.member_leads DROP CONSTRAINT IF EXISTS member_leads_text_check;
ALTER TABLE public.member_leads ADD CONSTRAINT member_leads_text_check
  CHECK (char_length(text) < 1001 AND char_length(external_id) BETWEEN 1 AND 300
    AND (url IS NULL OR char_length(url) < 601) AND (author_handle IS NULL OR char_length(author_handle) < 201)
    AND (author_place IS NULL OR char_length(author_place) < 121) AND (match_reason IS NULL OR char_length(match_reason) < 201)
    AND (matched_keyword IS NULL OR char_length(matched_keyword) < 81));
ALTER TABLE public.member_leads DROP CONSTRAINT IF EXISTS member_leads_user_source_external_key;
ALTER TABLE public.member_leads ADD CONSTRAINT member_leads_user_source_external_key UNIQUE (user_id, source, external_id);
CREATE INDEX IF NOT EXISTS member_leads_user_created_idx ON public.member_leads (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS member_leads_unscored_idx ON public.member_leads (user_id, created_at) WHERE scored_at IS NULL;
ALTER TABLE public.member_leads ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.member_leads FROM anon, authenticated;

-- ===== PART 204c: the replies a member approved and posted (run third) =====
-- One row per reply, written in the same guarded step as the send (server.js POST /api/leads/:id/send): one reply per
-- member per post (the unique key below), at most 3 different members per external post, 5 a day per member
-- (OUTREACH_DAILY_CAP) and OUTREACH_ACCOUNT_DAILY_CEILING across all members, all counted at the send.
CREATE TABLE IF NOT EXISTS public.member_lead_replies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  member_lead_id uuid REFERENCES public.member_leads(id) ON DELETE SET NULL,
  platform text NOT NULL,
  external_id text NOT NULL,
  text text NOT NULL,
  platform_uri text,
  sent_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.member_lead_replies DROP CONSTRAINT IF EXISTS member_lead_replies_platform_check;
ALTER TABLE public.member_lead_replies ADD CONSTRAINT member_lead_replies_platform_check
  CHECK (platform IN ('bluesky', 'threads'));
ALTER TABLE public.member_lead_replies DROP CONSTRAINT IF EXISTS member_lead_replies_text_check;
ALTER TABLE public.member_lead_replies ADD CONSTRAINT member_lead_replies_text_check
  CHECK (char_length(text) BETWEEN 1 AND 300 AND char_length(external_id) BETWEEN 1 AND 300
    AND (platform_uri IS NULL OR char_length(platform_uri) < 601));
ALTER TABLE public.member_lead_replies DROP CONSTRAINT IF EXISTS member_lead_replies_user_platform_external_key;
ALTER TABLE public.member_lead_replies ADD CONSTRAINT member_lead_replies_user_platform_external_key UNIQUE (user_id, platform, external_id);
CREATE INDEX IF NOT EXISTS member_lead_replies_sent_idx ON public.member_lead_replies (sent_at DESC);
CREATE INDEX IF NOT EXISTS member_lead_replies_post_idx ON public.member_lead_replies (platform, external_id);
ALTER TABLE public.member_lead_replies ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.member_lead_replies FROM anon, authenticated;

-- ===== PART 204d: the shared search cache (run fourth) =====
-- One row per (source, normalized keyword): a keyword many members share is searched once per interval (30 minutes
-- for Bluesky) and its results are matched to each of those members.
CREATE TABLE IF NOT EXISTS public.lead_search_cache (
  source text NOT NULL,
  keyword text NOT NULL,
  last_run_at timestamptz NOT NULL DEFAULT now(),
  last_count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (source, keyword)
);
ALTER TABLE public.lead_search_cache DROP CONSTRAINT IF EXISTS lead_search_cache_check;
ALTER TABLE public.lead_search_cache ADD CONSTRAINT lead_search_cache_check
  CHECK (source IN ('bluesky', 'youtube', 'threads') AND char_length(keyword) BETWEEN 2 AND 40 AND last_count > -1);
ALTER TABLE public.lead_search_cache ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.lead_search_cache FROM anon, authenticated;

-- ===== PART 204e: a member's Threads connection (run fifth) =====
-- The member's own Threads account (lib/threadsAuth.js), its long-lived token encrypted as the other integrations'
-- are (lib/apiKeyCrypto.js: ciphertext, iv, auth tag, hex). keyword_search_state: until Meta approves
-- threads_keyword_search a search sees only the member's own posts ('own_posts_only'); the screens say "Waiting for
-- Meta's approval" then.
CREATE TABLE IF NOT EXISTS public.threads_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,
  threads_user_id text NOT NULL,
  username text NOT NULL,
  access_ciphertext text NOT NULL,
  access_iv text NOT NULL,
  access_auth_tag text NOT NULL,
  access_expires_at timestamptz NOT NULL,
  granted_scopes text,
  keyword_search_state text NOT NULL DEFAULT 'unknown',
  status text NOT NULL DEFAULT 'connected',
  last_ok_at timestamptz,
  last_error_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.threads_connections DROP CONSTRAINT IF EXISTS threads_connections_check;
ALTER TABLE public.threads_connections ADD CONSTRAINT threads_connections_check
  CHECK (threads_user_id ~ '^[0-9]{1,30}$' AND char_length(username) BETWEEN 1 AND 100
    AND access_ciphertext ~ '^[0-9a-f]+$' AND access_iv ~ '^[0-9a-f]{24}$' AND access_auth_tag ~ '^[0-9a-f]{32}$'
    AND (granted_scopes IS NULL OR (char_length(granted_scopes) < 501 AND granted_scopes ~ '^[a-z_,]*$'))
    AND keyword_search_state IN ('unknown', 'own_posts_only', 'approved')
    AND status IN ('connected', 'needs_reconnect')
    AND (last_error_code IS NULL OR char_length(last_error_code) < 61));
ALTER TABLE public.threads_connections ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.threads_connections FROM anon, authenticated;

-- ===== PART 204f: a notification about a lead (run sixth) =====
-- Lead Radar's in-app notice for a lead scoring 70 or more (type lead_alert, at most 3 a day per member, one per lead;
-- no email, SMS or push) names the lead as its object: object_type 'member_lead'. The list is migration 190's plus
-- that one value; every existing row stays allowed.
ALTER TABLE public.notifications DROP CONSTRAINT IF EXISTS notifications_object_type_check;
ALTER TABLE public.notifications ADD CONSTRAINT notifications_object_type_check
  CHECK (object_type IS NULL OR object_type IN
    ('post', 'comment', 'message', 'proposal', 'listing', 'order', 'tip',
     'follow', 'report', 'review', 'campaign', 'member_lead'));
