-- Migration 026: Allow the Oracle to write agent_memory rows
-- Run in Supabase SQL Editor.
--
-- agent_memory.agent_type currently CHECKs against 7 values (see
-- 002_agent_memory.sql). The Oracle now writes/reads its own rows in this
-- same shared table (scoped by user_id + agent_type = 'oracle'), alongside
-- its existing full-history oracle_messages table — this just extends the
-- allowed agent_type set so those inserts don't fail the constraint.

ALTER TABLE agent_memory DROP CONSTRAINT IF EXISTS agent_memory_agent_type_check;

ALTER TABLE agent_memory ADD CONSTRAINT agent_memory_agent_type_check
  CHECK (agent_type IN ('seo', 'content', 'sales', 'analytics', 'operations', 'reputation', 'executive', 'oracle'));
