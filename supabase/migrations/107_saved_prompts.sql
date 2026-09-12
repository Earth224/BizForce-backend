-- CHANGES the database. CREATES a table: public.saved_prompts, nine columns,
-- two indexes, three CHECK constraints, RLS enabled with no policies.
--
-- WHY THIS EXISTS. A task worth running once is usually worth running again -
-- the weekly report, the same outreach message to a different customer - and
-- until now there was nowhere to keep one. Every repeat was retyped, which means
-- it was retyped slightly differently each time.
--
-- THE BLANKS ARE IN THE TEXT, NOT IN A COLUMN. A prompt may carry {{name}}
-- placeholders and the client supplies a value for each at run time. Nothing
-- here records which blanks a prompt has, deliberately: the API parses the
-- prompt on every run, so the list cannot go stale against a prompt somebody
-- edited. A separate column would be a second copy of something the text
-- already says, and the text is what reaches the model.
--
-- UNIQUE ON (user_id, lower(btrim(name))), so one person cannot end up with
-- "Weekly report" and "weekly report " and no way to tell them apart in a list.
-- Two different people may both have a "Weekly report": the uniqueness is per
-- account, never global. The API catches the 23505 this raises rather than
-- pre-checking the name - a SELECT before the INSERT answers a question about a
-- moment that has already passed, so it can only add a race, never remove the
-- branch that handles the collision.
--
-- agent_type IS NOT CHECKED BY A CONSTRAINT, matching how mist_position,
-- preferred_language and the card orderings are handled: the valid set is the
-- live AGENT_SYSTEM_PROMPTS object in the API, so registering a new agent is a
-- code change rather than a migration. Migration 064's comment naming seventeen
-- agent types when there are eighteen is the receipt for why a copy of that list
-- does not go in the schema.
--
-- RLS ENABLED WITH NO POLICIES IS DENY-ALL, and that is the intent: nothing
-- reaches this table except through the API with the service key, where every
-- query filters on the caller's own user_id. Enabling it without policies means
-- a future anon-key client cannot read the table by accident - it reads nothing
-- at all until somebody writes a policy deliberately.
--
-- last_used_at is nullable because a prompt that has never been run has no
-- honest value for it, and use_count defaults to 0 with a CHECK that it never
-- goes negative.
--
-- Already applied to the live database on 2026-09-12, before this file was
-- written.

create table if not exists public.saved_prompts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  agent_type text not null,
  prompt text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_used_at timestamptz,
  use_count integer not null default 0,
  constraint saved_prompts_name_not_blank check (length(btrim(name)) > 0),
  constraint saved_prompts_prompt_not_blank check (length(btrim(prompt)) > 0),
  constraint saved_prompts_use_count_not_negative check (use_count >= 0)
);

create unique index if not exists saved_prompts_user_name_key
  on public.saved_prompts (user_id, lower(btrim(name)));

create index if not exists saved_prompts_user_agent_idx
  on public.saved_prompts (user_id, agent_type);

alter table public.saved_prompts enable row level security;

comment on table public.saved_prompts is
  'A task a user wrote once and re-runs. The prompt may contain blanks written as {{name}}; the client collects a value for each blank at run time and substitutes them before sending the task. Blanks are NOT stored as a separate column: the prompt text is the single source of truth for which blanks exist, so a prompt edited to add a blank cannot disagree with a stale list. RLS is enabled with no policies, which is deny-all: every read and write goes through the API with the service key.';

comment on column public.saved_prompts.agent_type is
  'Which agent this prompt is for. Validated in the API against the live AGENT_SYSTEM_PROMPTS keys, not by a CHECK, so registering a new agent does not need a migration.';

comment on column public.saved_prompts.use_count is
  'How many times this prompt has been run. Incremented by the API when a run is launched, not when it completes — it counts intent to use, which is what makes a prompt worth keeping.';
