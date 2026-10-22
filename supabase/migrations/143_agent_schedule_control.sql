-- 143_agent_schedule_control.sql
--
-- CHANGES the database. agent_schedules learns how its last turn went, and can
-- be paused without being deleted. NOT YET APPLIED: the owner runs this in the
-- Supabase SQL editor. Every statement is `add column if not exists`, so
-- running it twice is a no-op, and nothing here rewrites an existing value.
--
-- WHY. A scheduled run that failed left its trace in two places only: the
-- Railway log, and job_runs.last_error for the hour slot it ran in, which
-- names one failure among everyone's and is cleared by the next claim of that
-- hour. The member whose schedule it was saw nothing; the agent page showed
-- "Last ran on" from last_run_on, which a failure never writes, so a schedule
-- failing every day read as one that last ran a week ago. And the only way to
-- stop a schedule was to delete it, which deleted the instruction with it.
--
--   paused                true stops the runner (agentScheduleIsDue answers
--                         false) and keeps the instruction, the cadence and
--                         the day and hour exactly as they were. Distinct from
--                         `enabled`, which no route writes.
--   paused_reason         'owner' when the member pressed Pause, 'failures'
--                         when the runner paused it after three failed runs in
--                         a row. Null when not paused.
--   last_run_status       what happened the last time this schedule came due:
--                           succeeded                   the task was queued
--                           failed                      it could not be queued
--                           skipped_not_entitled        no active subscription
--                           skipped_entitlement_unknown the subscription could
--                                                       not be read, so nothing
--                                                       ran (fail closed)
--                           skipped_no_autonomy         Autonomous mode is off
--                           skipped_invalid             the agent or task type
--                                                       is no longer offered
--                         Null until the first due slot after this migration.
--   last_error            the reason, in words a member can read. Null after a
--                         success. On a skip it says "skipped: ..." so it can
--                         be shown as it stands.
--   last_attempt_at       when the runner last looked at this schedule in a
--                         due slot, whatever the outcome. last_run_on is still
--                         the day it last SUCCEEDED and still the guard
--                         against a second run the same day.
--   last_task_id          the ai_tasks row the last successful run queued, so
--                         the card can link to it. Not a foreign key: a member
--                         deleting a task must not be refused because a
--                         schedule once pointed at it, and a dangling id is a
--                         link to "not found", not an error.
--   consecutive_failures  failed runs since the last success or the last
--                         Resume. Skips do not count: a lapsed subscription or
--                         an unreadable one is not the schedule failing, and
--                         pausing it for that would stop it resuming by itself.
--
-- NO BACKFILL. Every existing row gets paused false and consecutive_failures 0,
-- which is what they are, and null in the rest, which is accurate: nothing was
-- recorded about their runs before this.
--
-- RLS is already enabled on this table (102); columns inherit it.

alter table public.agent_schedules
  add column if not exists paused boolean not null default false;

alter table public.agent_schedules
  add column if not exists paused_reason text
    constraint agent_schedules_paused_reason_known
    check (paused_reason is null or paused_reason in ('owner', 'failures'));

alter table public.agent_schedules
  add column if not exists last_run_status text
    constraint agent_schedules_last_run_status_known
    check (last_run_status is null or last_run_status in (
      'succeeded', 'failed', 'skipped_not_entitled', 'skipped_entitlement_unknown',
      'skipped_no_autonomy', 'skipped_invalid'));

alter table public.agent_schedules
  add column if not exists last_error text;

alter table public.agent_schedules
  add column if not exists last_attempt_at timestamptz;

alter table public.agent_schedules
  add column if not exists last_task_id uuid;

alter table public.agent_schedules
  add column if not exists consecutive_failures integer not null default 0
    constraint agent_schedules_consecutive_failures_non_negative
    check (consecutive_failures >= 0);

comment on column public.agent_schedules.paused is 'True stops the runner and keeps the schedule unchanged. Written by PUT /api/agent-schedules/:agent_type/pause and /resume, and by the runner after three failed runs in a row.';
comment on column public.agent_schedules.last_run_status is 'Outcome of the last due slot: succeeded, failed, skipped_not_entitled, skipped_entitlement_unknown, skipped_no_autonomy or skipped_invalid. Written only by the hourly runner.';
comment on column public.agent_schedules.consecutive_failures is 'Failed runs since the last success or Resume. Skips do not count. At three the runner pauses the schedule with paused_reason failures.';
