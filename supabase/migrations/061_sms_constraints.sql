-- SMS integrity constraints — this one CHANGES live structure.
--
-- 059 and 060 were transcriptions: they recorded structure that already existed
-- and were expected to run against production as no-ops. This file is not that.
-- Every statement below alters the live schema, and each one can fail against
-- existing data rather than merely doing nothing.
--
-- So each was checked against production data first, tonight, before being
-- written here. The checks and their results:
--
--   sms_campaign_messages, rows with a null user_id ............ 0
--   sms_campaign_messages, duplicate (campaign_id, step_order) . was 1, now 0
--       The one duplicate was resolved before this migration was written: its
--       send-log rows were repointed onto an identical sibling message and the
--       duplicate row was deleted. The pair is clean at the time of writing.
--   sms_campaign_enrollments, orphaned user_id ................. 0
--   sms_campaign_enrollments, orphaned campaign_id ............. 0
--   sms_campaign_enrollments, orphaned subscriber_id ........... 0
--   sms_campaign_enrollments, distinct status values present ... completed only
--
-- Those results are what make the statements below safe: an alter adding a
-- foreign key, a check or a not-null validates against every existing row and
-- fails outright if any violates it. None of this was assumed.
--
-- The status check allows 'active' as well as 'completed' even though only
-- completed is present live. Both are values server.js writes — the drip engine
-- selects on active and writes completed when a sequence finishes — so a
-- constraint permitting only what happens to be in the table today would start
-- rejecting new enrollments immediately.
--
-- The column is nullable and a null passes a check constraint automatically,
-- which is the behaviour wanted here: POST /api/capture inserts an enrollment
-- without a status and lets the column default supply it.
--
-- Foreign keys target public.users, NOT auth.users. This project has a
-- documented history of hand-created tables carrying keys pointed at Supabase's
-- empty auth.users, where every insert fails 23503 and surfaces as an
-- unexplained 500; migration 041 exists solely to repoint four such tables onto
-- public.users. These three are written that way from the start.
--
-- Every statement is guarded, so a partial application can be re-run safely.
-- The guards check pg_constraint and information_schema rather than relying on
-- drop-then-recreate, which matters more here than in a transcription: dropping
-- and re-adding a foreign key re-validates it against every row, so the guarded
-- form makes a re-run genuinely free rather than merely correct.

-- ── sms_campaign_enrollments: referential integrity ─────────────────────────

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'sms_campaign_enrollments_user_id_fkey'
      and conrelid = 'public.sms_campaign_enrollments'::regclass
  ) then
    alter table public.sms_campaign_enrollments
      add constraint sms_campaign_enrollments_user_id_fkey
      foreign key (user_id) references public.users (id) on delete cascade;
  end if;
end $$;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'sms_campaign_enrollments_campaign_id_fkey'
      and conrelid = 'public.sms_campaign_enrollments'::regclass
  ) then
    alter table public.sms_campaign_enrollments
      add constraint sms_campaign_enrollments_campaign_id_fkey
      foreign key (campaign_id) references public.sms_campaigns (id) on delete cascade;
  end if;
end $$;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'sms_campaign_enrollments_subscriber_id_fkey'
      and conrelid = 'public.sms_campaign_enrollments'::regclass
  ) then
    alter table public.sms_campaign_enrollments
      add constraint sms_campaign_enrollments_subscriber_id_fkey
      foreign key (subscriber_id) references public.sms_subscribers (id) on delete cascade;
  end if;
end $$;

-- ── sms_campaign_enrollments: status is now a closed set ────────────────────

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'sms_campaign_enrollments_status_check'
      and conrelid = 'public.sms_campaign_enrollments'::regclass
  ) then
    alter table public.sms_campaign_enrollments
      add constraint sms_campaign_enrollments_status_check
      check (status in ('active', 'completed'));
  end if;
end $$;

-- ── sms_campaign_messages: user_id is no longer optional ────────────────────

-- Guarded on information_schema rather than attempted blindly: set not null
-- scans the table and fails if any row holds null. The check above found none,
-- but a guard means re-running this after a partial application does nothing
-- instead of rescanning.
do $$
begin
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'sms_campaign_messages'
      and column_name = 'user_id'
      and is_nullable = 'YES'
  ) then
    alter table public.sms_campaign_messages
      alter column user_id set not null;
  end if;
end $$;

-- ── sms_campaign_messages: one message per step per campaign ────────────────

-- This is the constraint with real consequences. runDripEngine loads a
-- campaign's messages ordered by step_order and then indexes into that array by
-- the enrollment's current_step. Two messages sharing a step_order within one
-- campaign make that array's order depend on whatever order the planner returns
-- rows in, so a subscriber can receive one of them on one run and the other on
-- the next, and neither the code nor the data would show anything wrong.
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'sms_campaign_messages_campaign_step_key'
      and conrelid = 'public.sms_campaign_messages'::regclass
  ) then
    alter table public.sms_campaign_messages
      add constraint sms_campaign_messages_campaign_step_key unique (campaign_id, step_order);
  end if;
end $$;

comment on constraint sms_campaign_messages_campaign_step_key on public.sms_campaign_messages is
  'One message per step per campaign. The drip engine indexes into step_order-ordered messages by current_step, so duplicate steps within a campaign make the send order depend on planner row order and it can differ between runs.';

-- ── sms_send_log: the column the log route orders by ────────────────────────

-- GET /api/sms/send-log orders by sent_at, and this table grows by one row per
-- message sent, so the scan it does today gets slower for as long as the system
-- is used.
create index if not exists sms_send_log_sent_at_idx
  on public.sms_send_log (sent_at);
