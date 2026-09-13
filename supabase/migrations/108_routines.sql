-- CHANGES the database. CREATES a table: public.routines, eight columns, one
-- unique index, three CHECK constraints, RLS enabled with no policies.
--
-- WHY THIS EXISTS. The agent tools are individually useful and collectively a
-- chore: the same four get run in the same order every Monday morning, by hand,
-- one at a time. A routine is that sequence written down once and pressed once.
--
-- IT RUNS THROUGH THE CHAIN DISPATCHER, WHICH IS THE POINT. Each step goes
-- through dispatchToolCall, so ENABLE_AGENT_CHAINING, CHAIN_MAX_DEPTH,
-- CHAIN_MAX_FANOUT, CHAIN_MAX_CALLS, the entitlement re-check and the per-user
-- daily model-call cap all apply exactly as they do to any other chain. Nothing
-- in the routine code re-implements or relaxes any of them: a routine is a
-- convenience for assembling a chain, never a way around what a chain may do.
--
-- A STEP DOES NOT READ THE PREVIOUS STEP'S OUTPUT, deliberately. Each runs on
-- the inputs stored against it. Threading output into input is where a list
-- somebody can read becomes a program, and none of the limits above were
-- designed for a program.
--
-- THE STEP COUNT IS CAPPED IN THE API, NOT BY A CONSTRAINT, at the lower of
-- CHAIN_MAX_CALLS and CHAIN_MAX_FANOUT - both read live from the environment.
-- Fan-out is usually the lower of the two and is the one that actually bites:
-- every step of a routine dispatches from one chain id at one depth, so the
-- steps are siblings in a single fan-out bucket rather than a ladder. A routine
-- capped at CHAIN_MAX_CALLS alone would save nine steps and then refuse its
-- fourth one at run time, every time. A CHECK here could not express that at
-- all: the limits are environment variables, so the cap belongs where they are
-- read.
--
-- UNIQUE ON (user_id, lower(btrim(name))), so one person cannot end up with
-- "Monday" and "monday " and no way to tell them apart; two different people
-- may both have a "Monday". The API catches the 23505 rather than pre-checking,
-- because a SELECT before the INSERT answers a question about a moment that has
-- already passed.
--
-- RLS ENABLED WITH NO POLICIES IS DENY-ALL, and that is the intent: nothing
-- reaches this table except through the API with the service key, where every
-- query filters on the caller's own user_id.
--
-- Already applied to the live database on 2026-09-12, before this file was
-- written.

create table if not exists public.routines (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  steps jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_run_at timestamptz,
  run_count integer not null default 0,
  constraint routines_name_not_blank check (length(btrim(name)) > 0),
  constraint routines_steps_is_array check (jsonb_typeof(steps) = 'array'),
  constraint routines_run_count_not_negative check (run_count >= 0)
);

create unique index if not exists routines_user_name_key
  on public.routines (user_id, lower(btrim(name)));

alter table public.routines enable row level security;

comment on table public.routines is
  'A named sequence of agent tool calls the user assembled, run on demand by pressing Run. Each step is an object { agent, tool, inputs } where inputs is the request body for that tool route. Steps run in array order, one at a time, through dispatchToolCall — so ENABLE_AGENT_CHAINING, the depth, fan-out and total-call limits, the entitlement check and the per-user daily model-call cap all apply unchanged. A step does NOT read the previous step''s output; each runs on its own stored inputs. RLS is enabled with no policies, which is deny-all: every read and write goes through the API with the service key.';

comment on column public.routines.steps is
  'A JSON array of { agent, tool, inputs }. Validated in the API against the live router and TOOL_INPUT_SPECS at save time AND again at run time, because a tool can be renamed or removed between the two. The count of steps is capped in the API below CHAIN_MAX_CALLS, so a routine cannot be assembled that is guaranteed to be cut short.';

comment on column public.routines.run_count is
  'How many times the routine has been started. Incremented when a run begins, not when it finishes — a routine that failed halfway was still run.';
