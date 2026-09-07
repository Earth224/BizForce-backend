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

delete from public.agent_memory
where metadata->>'dry_run' = 'true'
  and memory_key like 'sales_convert_dryrun_%'
  and title like '[DRY RUN]%';
