-- ============================================================================
-- 065_reserved_tombstone.sql
--
-- Intentionally empty. This number was reserved for a transcription of
-- public.users and never written, leaving a hole in the sequence
-- (...063, 064, 066...). A gap invites the assumption that a file was lost.
--
-- The work this number was reserved for was completed, expanded to all
-- twenty untracked foundation tables, and landed as
-- 071_transcribe_foundation_tables.sql.
--
-- This file exists so the sequence reads continuously and so nobody spends
-- an hour looking for a migration that was never written.
-- ============================================================================

select 1;
