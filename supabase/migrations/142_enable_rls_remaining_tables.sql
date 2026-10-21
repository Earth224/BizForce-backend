-- 142_enable_rls_remaining_tables.sql
--
-- ROW LEVEL SECURITY ON THE EIGHT TABLES THE MIGRATIONS CREATE WITHOUT IT.
-- Every other table the migrations create (89 of 97) already enables it.
--
--   content_library     025  blog posts and drafts (user_id, body)
--   marketplace_orders  034  orders (buyer_id, seller_id)
--   oracle_sync         041  Oracle sync state (user_id)
--   oracle_messages     041  Oracle chat messages (user_id, content)
--   push_subscriptions  048  push endpoints and keys (user_id, endpoint)
--   inner_iq_results    050  quiz results (user_id)
--   agent_autonomy      064  per-agent on/off switches (user_id)
--   job_runs            064  job claim markers; no personal data, enabled so
--                            that every table is the same
--
-- LIVE STATE when this was written (2026-10-21, read-only, head-only counts
-- with the anon key against the service key): the anon key reads 0 rows of
-- each of these that has rows (content_library 6, marketplace_orders 1,
-- oracle_sync 1, oracle_messages 26, inner_iq_results 1, agent_autonomy 3,
-- job_runs 29), so RLS was already turned on by hand in production;
-- push_subscriptions has no rows, so its state could not be read that way.
-- This migration records that state so a database rebuilt from the
-- migrations has it too, and turns it on wherever it is still off.
--
-- NO POLICIES, deliberately. server.js connects with SUPABASE_SERVICE_KEY, and
-- the service role bypasses RLS, so every route behaves exactly as before. No
-- frontend page talks to Supabase directly (no supabase-js, no anon key, no
-- /rest/v1 in BizForce-fronyend), so nothing loses access. What it closes is
-- direct reads and writes with the anon or an authenticated key. The posture
-- is the one 069, 070, 083, 091, 094, 138 and 140 record for their tables.
--
-- Applied by hand in the Supabase SQL editor. Re-runnable: enabling RLS that
-- is already on is a no-op.

alter table if exists public.content_library    enable row level security;
alter table if exists public.marketplace_orders enable row level security;
alter table if exists public.oracle_sync        enable row level security;
alter table if exists public.oracle_messages    enable row level security;
alter table if exists public.push_subscriptions enable row level security;
alter table if exists public.inner_iq_results   enable row level security;
alter table if exists public.agent_autonomy     enable row level security;
alter table if exists public.job_runs           enable row level security;
