-- 116_agent_memory_transcription.sql
--
-- agent_memory — a transcription, not a change. And a correction of 002.
--
-- ── 002 DESCRIBES A TABLE THAT WAS NEVER BUILT ────────────────────────────
--
-- 002_agent_memory.sql is not stale. A stale file is a subset of what exists.
-- 002 diverges from the live table in both directions at once, which is only
-- possible if it was never the thing that built it. Read column by column
-- from PostgREST's schema description and from pg_constraint on the live
-- database, 2026-09-15:
--
--   THREE LIVE COLUMNS 002 NEVER MENTIONS, and the only three that are
--   NOT NULL besides id:
--
--     agent          text   NOT NULL
--     memory_key     text   NOT NULL
--     memory_value   text   nullable
--
--   ONE COLUMN 002 DECLARES THAT DOES NOT EXIST:
--
--     assignment_id  uuid
--
--   EIGHT COLUMNS 002 DECLARES NOT NULL THAT ARE NULLABLE LIVE:
--
--     user_id, agent_type, memory_type, title, content, metadata,
--     created_at, updated_at
--
--   ONE CONSTRAINT 002 DECLARES THAT DOES NOT EXIST:
--
--     agent_memory_memory_type_check
--       CHECK (memory_type IN ('goal','task','campaign','insight','metric',
--                              'conversation','report'))
--
--   ONE CONSTRAINT THAT EXISTS AND 002 DOES NOT DECLARE:
--
--     agent_memory_user_id_fkey
--       FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
--
-- The live column ORDER is the tell. It is id, user_id, agent, memory_key,
-- memory_value, created_at, updated_at, and THEN agent_type, memory_type,
-- title, content, metadata. Postgres appends columns in the order they were
-- added, so the table began as a seven-column (agent, key, value) store and
-- 002's columns were bolted onto it afterwards, by hand, all nullable. 002
-- was written as the design; the database was built as something else and
-- then made to resemble it.
--
-- The one thing 002's lineage got right is agent_type_check: 026 and 114
-- drop-and-recreate it by name, and the live constraint is exactly 114's
-- nineteen-agent list. That is because 026 and 114 ran against the live
-- table. 002 did not.
--
-- ── WHAT A REBUILD DOES WITHOUT THIS FILE ─────────────────────────────────
--
-- IT DOES NOT REACH THIS FILE. Migration 098 runs
--
--   delete from public.agent_memory where ... and memory_key like ...
--
-- against the table 002 built, which has no memory_key column. That is
-- ERROR 42703 and the migration run stops at 098, sixteen files before this
-- one. NOTHING IN THIS FILE CAN FIX THAT: it is numbered after 098 and the
-- rule for this batch is that 001-114 are not edited. Closing it needs either
-- 002 to gain the three columns or 098 to guard its delete on the column
-- existing, and both are edits to existing files. It is recorded here so the
-- next person to attempt a rebuild is not surprised at 098.
--
-- Suppose 098 were guarded. Then a rebuild reaching 116 without it would have
-- a table with no agent, memory_key or memory_value, and every one of the 23
-- agent_memory writes in server.js names all three — the orchestrator, the
-- routines runner, lead-status, every tool completion. Each is a PGRST204
-- and nothing is applied. Every memory write on the platform fails. The 68
-- live rows cannot be restored either: they have values for columns the
-- rebuilt table lacks.
--
-- And the rows that could be restored would then be refused: 002's eight NOT
-- NULLs happen to hold for all 68 live rows today, but memory_type_check does
-- not exist live for a reason, and a rebuilt table that enforces a list of
-- seven memory types will reject the first row whose writer never heard of
-- it.
--
-- ── WHAT THIS FILE DOES, IN TWO KINDS ─────────────────────────────────────
--
-- ADDITIVE, and a no-op live: the three columns and the foreign key. Each is
-- guarded on its own existence.
--
-- REBUILD-ONLY RELAXATIONS, and a no-op live: dropping the eight NOT NULLs
-- and the memory_type check. Against the live database every one of these
-- statements finds nothing to do — the columns are already nullable and the
-- constraint is already absent — and each is guarded on exactly that, so the
-- guard documents what it expects to find. They exist so that a rebuilt table
-- that got 002's shape ends up with the live shape. They drop nothing that
-- exists live. They are the only statements in this batch that are not pure
-- additions, and they are here because a transcription that could not relax
-- what 002 wrongly tightened would not be a transcription of this table.
--
-- ── WHAT IS DELIBERATELY NOT DONE ─────────────────────────────────────────
--
-- assignment_id IS NOT DROPPED from a rebuild and NOT ADDED to live. It is
-- harmless where it exists (nullable, unindexed) and its absence live is a
-- latent bug rather than a feature: orchestrateAgentWorkflow writes
-- assignment_id when an assignment id is a real uuid, which today it never is
-- (agent_assignments has 0 rows and the dashboard's ids are asg_ strings), so
-- the write that would fail live has never fired. Adding the column live
-- would be a change to the live database, which this batch does not make.
-- Recorded; decide separately.
--
-- The DEFAULT on metadata is NOT ASSERTED. 002 says '{}'::jsonb. PostgREST
-- reports no default for any jsonb column on any table (the control case 111
-- documented), so whether live has that default is unread, and an unread
-- default is not written down. information_schema.columns is the query that
-- answers it.
--
-- Indexes and RLS policies are not touched: 002 declares four indexes and
-- four policies and neither pg_indexes nor pg_policies has been read for this
-- table yet.
--
-- ── SAFETY ────────────────────────────────────────────────────────────────
--
-- Every statement is guarded and re-runnable. No row is written, updated or
-- deleted. No column or constraint that exists on the live database is
-- dropped or altered. No existing file is renumbered — 115 was the highest
-- before this.

-- ── The three columns 002 never had ───────────────────────────────────────

ALTER TABLE public.agent_memory
  ADD COLUMN IF NOT EXISTS agent        text,
  ADD COLUMN IF NOT EXISTS memory_key   text,
  ADD COLUMN IF NOT EXISTS memory_value text;

-- NOT NULL on agent and memory_key is set separately, because a rebuilt table
-- that received them above gets them nullable while the live table already
-- has them NOT NULL. Guarded twice: skipped when the column is already NOT
-- NULL (live — the statement is never issued there), and skipped with a
-- notice rather than failed when the column holds a NULL (neither the live
-- state nor a rebuild, but the one case SET NOT NULL would error on).
do $$
declare
  col text;
  has_null boolean;
begin
  foreach col in array array['agent', 'memory_key'] loop
    if exists (
      select 1 from pg_attribute
      where attrelid = 'public.agent_memory'::regclass
        and attname = col and attnotnull and not attisdropped
    ) then
      continue;
    end if;
    execute format('select exists (select 1 from public.agent_memory where %I is null)', col) into has_null;
    if has_null then
      raise notice '116: agent_memory.% holds NULL rows; NOT NULL not set', col;
    else
      execute format('alter table public.agent_memory alter column %I set not null', col);
    end if;
  end loop;
end $$;

-- ── The foreign key 002 never declared ────────────────────────────────────
--
-- ON DELETE CASCADE, read from pg_constraint: deleting a user deletes their
-- memories. Guarded on the constraint name, same as 094 and 089.
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'agent_memory_user_id_fkey'
      and conrelid = 'public.agent_memory'::regclass
  ) then
    alter table public.agent_memory
      add constraint agent_memory_user_id_fkey
      foreign key (user_id) references public.users(id) on delete cascade;
  end if;
end $$;

-- ── REBUILD-ONLY: the eight NOT NULLs 002 declared and live does not have ──
--
-- Each is a no-op live. attnotnull is read first so the statement is only
-- issued where 002's shape is actually present.
do $$
declare
  col text;
begin
  foreach col in array array[
    'user_id', 'agent_type', 'memory_type', 'title',
    'content', 'metadata', 'created_at', 'updated_at'
  ] loop
    if exists (
      select 1 from pg_attribute
      where attrelid = 'public.agent_memory'::regclass
        and attname = col
        and attnotnull
        and not attisdropped
    ) then
      execute format('alter table public.agent_memory alter column %I drop not null', col);
    end if;
  end loop;
end $$;

-- ── REBUILD-ONLY: the memory_type check 002 declared and live does not have ─
--
-- DROP CONSTRAINT IF EXISTS is a no-op live: pg_constraint has no such row
-- for this table. On a rebuild it removes the seven-value list that would
-- otherwise refuse writers 002 never anticipated.
ALTER TABLE public.agent_memory
  DROP CONSTRAINT IF EXISTS agent_memory_memory_type_check;

-- ── Column comments ───────────────────────────────────────────────────────

COMMENT ON TABLE public.agent_memory IS
  'Per-user, per-agent memory rows read into agent system prompts. TRANSCRIBED in migration 116 from the live database; migration 002 describes a different table that was never built (see 116''s header for the column-by-column divergence). The live table began as an (agent, memory_key, memory_value) store and gained agent_type, memory_type, title, content and metadata afterwards, all nullable. The only NOT NULL columns besides id are agent and memory_key. There is NO memory_type check. Every writer in server.js supplies agent, agent_type, memory_key, memory_value, memory_type, title, content and metadata together, so the nullability is latent rather than exercised.';

COMMENT ON COLUMN public.agent_memory.agent IS
  'The agent that wrote this memory. Always equal to agent_type on every live row (68 of 68 on 2026-09-15) and always written alongside it; two columns because the table predates agent_type and nothing was consolidated. NOT NULL. Not in migration 002.';

COMMENT ON COLUMN public.agent_memory.memory_key IS
  'Writer-chosen key such as sales_handoff_<task id>, <agent>_completed_assignment or sales_lead_status_<uri>_<ms>. NOT unique — the same key can be written many times — and NOT NULL. Migration 098 deletes by pattern on this column, which is why a rebuild from 002 halts there. Not in migration 002.';

COMMENT ON COLUMN public.agent_memory.memory_value IS
  'The memory text as first stored, before title/content existed. Every writer now sets it to the same value as content. Nullable, no default. Not in migration 002.';
