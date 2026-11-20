-- P2-2 (Nov 20 2026): the safety tables. They ship BEFORE posts, so the first post can
-- already be blocked, muted, reported and reviewed.
-- Safe to re-run: CREATE TABLE / CREATE INDEX IF NOT EXISTS, and each named CHECK is
-- dropped if it exists before it is added.
--
-- 1. member_blocks: a member blocks another. Neither sees the other's posts, comments
--    or profile, and neither can message the other (enforced by the server).
-- 2. member_mutes: a member mutes another. Only the muter stops seeing them; the muted
--    member is not told.
-- 3. content_reports: a member reports a post, comment, profile, listing, campaign,
--    message or review. One OPEN report per reporter per object (a partial unique
--    index); the queue index serves the admin list. reporter_id and owner_id are SET
--    NULL when an account is deleted, so the record of what was reported stays.
-- 4. moderation_queue: one row per object under review, from a report, the policy
--    screen, a new member's first posts or a copyright notice. Priority 1 is minor
--    safety and legal. The waiting index serves the review list.
-- 5. copyright_notices: a notice from a rights holder and any counter-notice.
--
-- Members never read these tables directly: every read and write goes through Express
-- routes. Row level security is on with no policies and anon/authenticated are revoked
-- (as in migrations 110 and 189). The older admin_flags and moderation_logs (migration
-- 083) stay as they are: moderation_logs records each admin action.
BEGIN;

-- 1. blocks
CREATE TABLE IF NOT EXISTS public.member_blocks (
  blocker_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  blocked_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (blocker_id, blocked_id)
);
ALTER TABLE public.member_blocks DROP CONSTRAINT IF EXISTS member_blocks_not_self;
ALTER TABLE public.member_blocks ADD CONSTRAINT member_blocks_not_self
  CHECK (blocker_id <> blocked_id);
CREATE INDEX IF NOT EXISTS member_blocks_blocked_idx ON public.member_blocks (blocked_id);

-- 2. mutes
CREATE TABLE IF NOT EXISTS public.member_mutes (
  muter_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  muted_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (muter_id, muted_id)
);
ALTER TABLE public.member_mutes DROP CONSTRAINT IF EXISTS member_mutes_not_self;
ALTER TABLE public.member_mutes ADD CONSTRAINT member_mutes_not_self
  CHECK (muter_id <> muted_id);

-- 3. reports
CREATE TABLE IF NOT EXISTS public.content_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
  object_type text NOT NULL,
  object_id uuid NOT NULL,
  owner_id uuid REFERENCES public.users(id) ON DELETE SET NULL,   -- whose content it is
  reason text NOT NULL,
  detail text,
  status text NOT NULL DEFAULT 'open',
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz
);
ALTER TABLE public.content_reports DROP CONSTRAINT IF EXISTS content_reports_object_type;
ALTER TABLE public.content_reports ADD CONSTRAINT content_reports_object_type
  CHECK (object_type IN ('post','comment','profile','listing','campaign','message','review'));
ALTER TABLE public.content_reports DROP CONSTRAINT IF EXISTS content_reports_reason;
ALTER TABLE public.content_reports ADD CONSTRAINT content_reports_reason
  CHECK (reason IN ('spam','harassment','hate','sexual','minor_safety','violence',
    'health_claim','prohibited_item','scam','copyright','impersonation','privacy','other'));
ALTER TABLE public.content_reports DROP CONSTRAINT IF EXISTS content_reports_detail_length;
ALTER TABLE public.content_reports ADD CONSTRAINT content_reports_detail_length
  CHECK (detail IS NULL OR char_length(detail) < 1001);
ALTER TABLE public.content_reports DROP CONSTRAINT IF EXISTS content_reports_status;
ALTER TABLE public.content_reports ADD CONSTRAINT content_reports_status
  CHECK (status IN ('open','actioned','dismissed'));
CREATE UNIQUE INDEX IF NOT EXISTS content_reports_once
  ON public.content_reports (reporter_id, object_type, object_id) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS content_reports_queue_idx
  ON public.content_reports (status, created_at);

-- 4. the moderation queue
CREATE TABLE IF NOT EXISTS public.moderation_queue (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  object_type text NOT NULL,
  object_id uuid NOT NULL,
  owner_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
  source text NOT NULL,
  priority smallint NOT NULL DEFAULT 2,   -- 1 = minor safety or legal
  report_count int NOT NULL DEFAULT 0,
  screen_findings jsonb,
  state text NOT NULL DEFAULT 'waiting',
  decided_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
  decided_at timestamptz,
  decision_note text,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.moderation_queue DROP CONSTRAINT IF EXISTS moderation_queue_source;
ALTER TABLE public.moderation_queue ADD CONSTRAINT moderation_queue_source
  CHECK (source IN ('report','policy_screen','new_member','copyright_notice'));
ALTER TABLE public.moderation_queue DROP CONSTRAINT IF EXISTS moderation_queue_priority;
ALTER TABLE public.moderation_queue ADD CONSTRAINT moderation_queue_priority
  CHECK (priority BETWEEN 1 AND 3);
ALTER TABLE public.moderation_queue DROP CONSTRAINT IF EXISTS moderation_queue_report_count;
ALTER TABLE public.moderation_queue ADD CONSTRAINT moderation_queue_report_count
  CHECK (report_count > -1);
ALTER TABLE public.moderation_queue DROP CONSTRAINT IF EXISTS moderation_queue_state;
ALTER TABLE public.moderation_queue ADD CONSTRAINT moderation_queue_state
  CHECK (state IN ('waiting','kept','hidden','removed'));
ALTER TABLE public.moderation_queue DROP CONSTRAINT IF EXISTS moderation_queue_note_length;
ALTER TABLE public.moderation_queue ADD CONSTRAINT moderation_queue_note_length
  CHECK (decision_note IS NULL OR char_length(decision_note) < 1001);
CREATE UNIQUE INDEX IF NOT EXISTS moderation_queue_object_once
  ON public.moderation_queue (object_type, object_id);
CREATE INDEX IF NOT EXISTS moderation_queue_waiting_idx
  ON public.moderation_queue (priority, created_at) WHERE state = 'waiting';

-- 5. copyright notices
CREATE TABLE IF NOT EXISTS public.copyright_notices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  claimant_name text NOT NULL,
  claimant_email text NOT NULL,
  work text NOT NULL,
  object_type text NOT NULL,
  object_id uuid NOT NULL,
  good_faith boolean NOT NULL,
  signature text NOT NULL,
  counter_notice jsonb,
  status text NOT NULL DEFAULT 'received',
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.copyright_notices DROP CONSTRAINT IF EXISTS copyright_notices_status;
ALTER TABLE public.copyright_notices ADD CONSTRAINT copyright_notices_status
  CHECK (status IN ('received','removed','rejected','countered','restored'));

-- members never touch these tables directly
ALTER TABLE public.member_blocks     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.member_mutes      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.content_reports   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.moderation_queue  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.copyright_notices ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.member_blocks     FROM anon, authenticated;
REVOKE ALL ON public.member_mutes      FROM anon, authenticated;
REVOKE ALL ON public.content_reports   FROM anon, authenticated;
REVOKE ALL ON public.moderation_queue  FROM anon, authenticated;
REVOKE ALL ON public.copyright_notices FROM anon, authenticated;

COMMIT;
