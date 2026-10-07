-- 131_seo_refused_drafts.sql
--
-- One row each time POST /api/agents/seo/generate-post refuses a draft the
-- model has already written.
--
-- Before this, a refused draft was discarded unseen: the 422 carried the
-- reason and, for the claim screen, the flagged sentences, and nothing else
-- of an article that had been paid for. Whether a refusal was right could not
-- be judged, because the article it refused no longer existed.
--
-- WHAT A ROW HOLDS:
--   stage         which gate refused it — unparseable, title, body_length,
--                 money_link, compliance, compliance_disclaimer, slug,
--                 slug_taken, internal_links, claims — or after_repair:<gate>
--                 when the claim repair ran and its rewritten article was the
--                 one refused
--   refusal       the response body the caller got, exactly
--   title .. body the draft as the model returned it, before any repair
--   raw_response  only when stage is unparseable: the model's text, since
--                 there are no fields to hold
--   repair        when the claim repair ran: outcome, reason, each flagged
--                 sentence before and after, the model's answer, and the
--                 rewritten title, meta description and body
--   brief         what the caller asked for — topic, site_name, site_context,
--                 money_anchor — which nothing else in the system stores
--
-- A draft that is FILED is not here: it is in agent_proposals, and a filed
-- draft that was repaired carries payload.claim_repair there.
--
-- Written by the server with the service role only. No retention rule: rows
-- accumulate until someone deletes them.
--
-- To be applied by hand. Until it is, the route logs "refused draft NOT stored"
-- on every refusal and answers exactly as it does with the table present.

begin;

create table if not exists public.seo_refused_drafts (
  id                 uuid        primary key default gen_random_uuid(),
  user_id            uuid        not null,
  created_at         timestamptz not null default now(),
  mode               text        not null check (mode in ('listing', 'external', 'own_page')),
  money_target       text,
  compliance_profile text,
  stage              text        not null check (char_length(stage) between 1 and 60),
  refusal            jsonb       not null,
  title              text,
  slug               text,
  meta_description   text,
  keyword            text,
  body               text,
  reasoning          text,
  raw_response       text,
  repair             jsonb,
  brief              jsonb
);

create index if not exists seo_refused_drafts_user_created_idx on public.seo_refused_drafts (user_id, created_at desc);

alter table public.seo_refused_drafts enable row level security;
revoke all on public.seo_refused_drafts from anon, authenticated;

comment on table public.seo_refused_drafts is
  'Drafts POST /api/agents/seo/generate-post refused after the model wrote them: the draft, the refusal sent, the claim repair if one ran, and the brief. Service role only.';

commit;
