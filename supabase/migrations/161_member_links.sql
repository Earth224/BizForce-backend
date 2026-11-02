-- 161_member_links.sql — a member's switches on the agent network
-- (intelligence layer B6 and B7)
--
-- PURPOSE. The agent network (lib/agentNetwork.js) declares the links by which
-- one agent's work really reaches another: Executive plan dispatches, the
-- Executive-to-Sales handoff, SEO posts published into the content library,
-- and Lead Radar posts read by R&D demand signals. A member may switch any
-- declared link OFF, and on again, and nothing else: a row here can only ever
-- name a declared link, because PUT /api/agents/network/links refuses any
-- other (link_not_declared). A link switched off is refused by whatever would
-- have carried work along it, with the reason link_disabled_by_member, and the
-- refusal is recorded through the gate evaluator as G26.
--
-- id is a plain row id, so the export (lib/yourData.js) can page and
-- de-duplicate by it; one row per member and link is the UNIQUE key.
--
-- No row means the link is on. A row that cannot be read leaves the platform's
-- decision standing, as a member gate does.
--
-- PRIVACY AND ACCESS. The member's own data: exported and deleted with the
-- account (lib/yourData.js), backed up (lib/backup.js), and the foreign key
-- cascades. Row level security is on with no policies; only the server's
-- service role reads it, and every route filters on the caller's user_id.

CREATE TABLE IF NOT EXISTS public.member_links (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  from_agent  text NOT NULL CHECK (from_agent ~ '^[a-z_]{1,40}$'),
  to_agent    text NOT NULL CHECK (to_agent ~ '^[a-z_]{1,40}$'),
  enabled     boolean NOT NULL DEFAULT true,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, from_agent, to_agent),
  CHECK (from_agent <> to_agent)
);

ALTER TABLE public.member_links ENABLE ROW LEVEL SECURITY;
