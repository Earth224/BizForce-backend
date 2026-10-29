-- 151_learning_loop.sql — each member's agents learn from that member's own
-- ratings, pinned examples and stated preferences. The AI model does not change.
--
-- WHY. Diagnostic §5. A member had no way to tell an agent "that was good" or
-- "that was too long", and nothing a member said about one run reached the next.
-- These two tables hold what the member tells each agent; lib/learningLoop.js
-- turns them into a short block placed BELOW the system rules and the
-- compliance rails of every prompt for that member and that agent, and never
-- above them. The rails themselves are code-level scans of the output and read
-- neither table.
--
-- 1. agent_feedback: one row per member per run (unique task_id, user_id), so a
--    rating can be changed but never doubled. rating is 'up' or 'down'; reason
--    is one of six fixed choices or null; comment is at most 200 characters.
--    pinned marks a 👍 run the member chose as an example: at most 5 pinned per
--    member per agent, enforced by the server (the newest pin unpins the
--    oldest), and a pin requires rating 'up' (checked here too).
-- 2. agent_preferences: at most 8 per member per agent (enforced by the
--    server), each at most 80 characters. source says whether the member typed
--    it or accepted a suggestion; a suggestion is never stored until accepted.
--
-- Both are the member's own data: in the data export, deleted with the account
-- (and with the run, for feedback), and readable by no other member. RLS is on
-- with no policies, so only the service role (the server) reads or writes them.

-- ── 1 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.agent_feedback (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  task_id     uuid        NOT NULL REFERENCES public.ai_tasks(id) ON DELETE CASCADE,
  user_id     uuid        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  agent_type  text        NOT NULL,
  rating      text        NOT NULL,
  reason      text,
  comment     text,
  pinned      boolean     NOT NULL DEFAULT false,
  pinned_at   timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_feedback_task_user_unique UNIQUE (task_id, user_id),
  CONSTRAINT agent_feedback_rating_check CHECK (rating IN ('up', 'down')),
  CONSTRAINT agent_feedback_reason_check CHECK (reason IS NULL OR reason IN ('Too long', 'Too short', 'Wrong tone', 'Off topic', 'Inaccurate', 'Other')),
  CONSTRAINT agent_feedback_comment_check CHECK (comment IS NULL OR char_length(comment) <= 200),
  CONSTRAINT agent_feedback_pin_check CHECK (pinned = false OR (rating = 'up' AND pinned_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS agent_feedback_user_agent_idx ON public.agent_feedback (user_id, agent_type, updated_at DESC);
CREATE INDEX IF NOT EXISTS agent_feedback_agent_updated_idx ON public.agent_feedback (agent_type, updated_at DESC);

alter table public.agent_feedback enable row level security;

-- ── 2 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.agent_preferences (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  agent_type  text        NOT NULL,
  text        text        NOT NULL,
  source      text        NOT NULL DEFAULT 'member',
  created_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_preferences_text_check CHECK (char_length(text) BETWEEN 1 AND 80),
  CONSTRAINT agent_preferences_source_check CHECK (source IN ('member', 'suggestion'))
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_preferences_unique_text ON public.agent_preferences (user_id, agent_type, lower(text));

alter table public.agent_preferences enable row level security;
