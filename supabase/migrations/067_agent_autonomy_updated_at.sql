-- 067_agent_autonomy_updated_at.sql
-- Attaches the generic updated_at trigger to public.agent_autonomy and corrects the
-- column comment 064 left behind. Two changes, both to an existing table, neither
-- touching any row's data.
--
-- REQUIRES 066 TO HAVE RUN FIRST. The trigger below references
-- public.set_updated_at(), which 066_birth_records.sql creates. 066 owns that
-- function and this file does not redefine, replace or alter it. Run out of order,
-- the CREATE TRIGGER fails with "function public.set_updated_at() does not exist"
-- and nothing is left half-applied.
--
-- Idempotent and safe to re-run in full: the trigger is dropped-if-exists before
-- being created, since CREATE TRIGGER has no IF NOT EXISTS form, and COMMENT ON
-- simply overwrites whatever comment is there.
--
-- Scope note: 064 created two tables, agent_autonomy and job_runs. Only
-- agent_autonomy is touched here, because job_runs has no updated_at column at all
-- — its lifecycle is recorded by started_at and finished_at, which the claim
-- statement and the completion update set explicitly. There is nothing for this
-- trigger to maintain there, so attaching one would be noise.

-- ── agent_autonomy: updated_at is now maintained by a trigger ──
-- The route that toggles enabled no longer has to remember to set updated_at, and
-- more importantly a future route that forgets cannot silently leave the column
-- stale. That was the failure 064's comment predicted and could only warn about,
-- there being no trigger convention in this folder at the time.
DROP TRIGGER IF EXISTS agent_autonomy_set_updated_at ON public.agent_autonomy;
CREATE TRIGGER agent_autonomy_set_updated_at
  BEFORE UPDATE ON public.agent_autonomy
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ── Correct the updated_at column comment ──
-- 064 recorded, accurately at the time:
--
--   'Defaults to now() on insert but is NOT maintained by a trigger — no trigger
--    is created here, deliberately, since this folder has no update-timestamp
--    trigger convention to follow. The route that toggles enabled must set
--    updated_at = now() in the same update. Left unmaintained it will silently
--    equal created_at forever, which reads as "never changed" and would be wrong.'
--
-- Every clause of that was true when it was written and the first two are now
-- false: a trigger does maintain the column, and the convention it said did not
-- exist was established in 066. Replaced rather than left in place, because a
-- column comment is the documentation someone reads instead of the migration
-- history, and one that tells them to set updated_at by hand would have them
-- writing redundant code at best and doubting the trigger at worst.
COMMENT ON COLUMN public.agent_autonomy.updated_at IS
  'Maintained automatically by the agent_autonomy_set_updated_at trigger, which runs BEFORE UPDATE FOR EACH ROW and calls public.set_updated_at() — the generic function established as this schema''s convention in migration 066. Callers do not need to set this column, and setting it explicitly is harmless but pointless: the trigger overwrites whatever value an UPDATE supplies. Supersedes the comment 064 carried, which correctly said at the time that no trigger maintained this column and that the toggle route had to set it by hand. Rows last written BEFORE the trigger existed still hold an updated_at equal to their created_at; see the migration for why those are deliberately left alone.';

-- ── Deliberately NOT done here: no backfill ──
-- No existing row is modified by this file. Rows written before the trigger existed
-- keep an updated_at equal to their created_at, and that is the correct outcome
-- rather than an oversight.
--
-- The information needed to fix them does not exist. Nothing recorded when those
-- rows were actually last changed — that is precisely the gap this trigger closes
-- going forward, and closing it forward does not reach backward. Any backfill would
-- therefore have to invent a value: now() would claim every historical row was
-- touched at migration time, which is false for all of them and would destroy the
-- one true fact still available, that the row has not been modified since creation.
--
-- An honest stale timestamp is more useful than a confident wrong one. A reader who
-- sees updated_at equal to created_at learns either that the row was never changed
-- or that it predates the trigger, and both readings are compatible with the truth.
-- A reader who sees a fabricated migration-time timestamp learns something false and
-- has no way to detect it.
