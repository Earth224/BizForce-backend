-- CHANGES the database. Records every model call and what it cost.
--
-- WHY THIS EXISTS. Before it, nothing in this system knew what it had spent.
-- callAnthropicText received response.usage from the API and discarded it, there
-- was no token count anywhere, no cost table, and no per-user quota -
-- getMonthlyUsage returns zeroedUsage() with counting_implemented: false, and
-- incrementTaskUsage is a no-op with no callers. The question "what did today
-- cost" had no answer at any price.
--
-- user_id is NULLABLE and set to null on delete, deliberately. A call made by a
-- user who later deletes their account still happened and still cost money;
-- erasing the spend record with the user would make the ledger lie about history.
--
-- created_on is a DATE rather than being derived from created_at, so "what has
-- this user spent today" is an index hit rather than a range scan over
-- timestamps. That query will run on every gated request once a cap exists.
--
-- chain_id and chain_depth are present and unused. Agent-to-agent chaining is
-- the next thing to be built, and a runaway chain is the failure this table is
-- most needed for - fan-out 3 with no depth limit is 3, 9, 27, 81 calls. The
-- columns are here now so the ledger can answer "which chain, and how deep"
-- from the first chained call rather than after a second migration.
--
-- Already applied to the live database on 2026-09-10.

create table if not exists public.model_calls (
  id             bigserial   primary key,
  user_id        uuid        references public.users(id) on delete set null,
  agent_type     text,
  route          text,
  model          text        not null,
  input_tokens   integer     not null default 0,
  output_tokens  integer     not null default 0,
  chain_id       uuid,
  chain_depth    smallint    not null default 0,
  created_on     date        not null default (now() at time zone 'utc')::date,
  created_at     timestamptz not null default now(),

  constraint model_calls_tokens_not_negative
    check (input_tokens >= 0 and output_tokens >= 0),
  constraint model_calls_depth_not_negative
    check (chain_depth >= 0)
);

create index if not exists model_calls_user_day_idx
  on public.model_calls (user_id, created_on);

create index if not exists model_calls_chain_idx
  on public.model_calls (chain_id)
  where chain_id is not null;

alter table public.model_calls enable row level security;
