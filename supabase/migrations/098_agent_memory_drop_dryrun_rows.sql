-- CHANGES the database. One-time DATA cleanup, not a schema change.
-- Removes 7,864 sales-convert dry-run rehearsals from agent_memory, out of
-- 7,925 rows. They were written by convertSingleLead on dry runs, which was
-- fixed in 4a97f95 so it no longer happens. They mattered because the memory
-- read that feeds each agent prompt takes the five most recent rows by
-- created_at and does not select metadata, so the one field that identifies a
-- rehearsal could never have filtered them out.
-- All three markers must match. A row carrying only some of them survives on
-- purpose. Verified before running: all three matched the same 7,864 rows.
-- Idempotent - a second run deletes nothing.
-- Already applied to the live database on 2026-09-07.
--
-- AMENDED AFTER IT WAS APPLIED — 2026-09-15
--   This file was committed on 2026-09-07 (83b0ed5) and ran against the live
--   database as a single bare DELETE. It was amended on 2026-09-15 to wrap that
--   DELETE in a guard on agent_memory.memory_key existing. The DELETE itself
--   is character-for-character the original.
--
--   WHY. memory_key is a live column that migration 002 never declared — the
--   table 002 builds on a fresh database has no such column — and no file
--   before this one adds it. Migration 116 transcribes it, but 116 is numbered
--   above this file. So on a fresh database the original DELETE fails with
--   42703 (column "memory_key" does not exist) and the rebuild halts here.
--   With the guard, a fresh run skips the DELETE — correctly, since a fresh
--   agent_memory holds no rows to clean — and 116 adds the column later.
--
--   THE EQUIVALENCE, WHICH IS THE ONLY REASON THIS EDIT IS PERMITTED. Against
--   the database this file already ran on, memory_key exists (it is one of the
--   three NOT NULL columns on the live table, read from PostgREST and
--   pg_attribute on 2026-09-15), so the guard is true and the DELETE executes
--   exactly as before. It is already idempotent — the 7,864 rows are gone and
--   a re-run deletes nothing — and wrapping it in a DO block changes neither
--   its text nor its plan. On a database where the guard is false the
--   original would not have run at all; it would have errored on the column
--   reference. There is therefore no database on which the two versions
--   produce different results.

do $$
begin
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name   = 'agent_memory'
      and column_name  = 'memory_key'
  ) then
    delete from public.agent_memory
    where metadata->>'dry_run' = 'true'
      and memory_key like 'sales_convert_dryrun_%'
      and title like '[DRY RUN]%';
  else
    raise notice '098: agent_memory.memory_key does not exist yet (migration 116 adds it); the dry-run cleanup is skipped — a fresh table has nothing to clean';
  end if;
end $$;
