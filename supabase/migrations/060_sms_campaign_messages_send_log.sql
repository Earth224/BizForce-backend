-- sms_campaign_messages and sms_send_log — a transcription, not a change.
--
-- Both of these tables ALREADY EXIST IN PRODUCTION. Like sms_campaign_enrollments
-- in 059, they were created outside the migration system and have never had DDL
-- in this repo in any form, while server.js reads and writes both: the drip
-- engine loads a campaign's messages and writes a row to the send log for every
-- message it sends, and the campaign routes list and create messages.
--
-- What follows was read out of information_schema, pg_index and pg_constraint
-- against the live database, so that a fresh clone can rebuild both tables as
-- they actually are. Every statement is guarded; running this against the live
-- database is a no-op.
--
-- These were the last two SMS tables with no DDL to check a query against, which
-- is exactly the condition that let GET /api/sms/campaigns/:id/enrollments order
-- by a column that did not exist until it was caught tonight.
--
-- Three things this file deliberately does NOT do. All three are changes to live
-- structure, and each needs a data check first, so each belongs in its own
-- migration rather than being smuggled into a transcription:
--
-- 1. sms_campaign_messages.user_id is left nullable, which is what is live, even
--    though the user_id on every sibling SMS table is not null. Tightening it
--    starts by finding out whether any rows already hold null — an alter to
--    set not null fails outright if any do.
--
-- 2. No unique constraint on (campaign_id, step_order). This one has teeth: the
--    drip engine loads a campaign's messages ordered by step_order and then
--    indexes into that array by current_step, so two messages sharing a
--    step_order within one campaign make the send order depend on whatever
--    order the planner returns them in, and it can differ between runs. Adding
--    the constraint requires checking for existing duplicates first, because it
--    fails against any that are already there.
--
-- 3. No index on sms_send_log.sent_at, even though GET /api/sms/send-log orders
--    by it and this table grows by one row per message sent. Adding an index is
--    safe and would not fail, but it is still a change to live structure rather
--    than a record of it.
--
-- RLS is enabled on both with zero policies, for the same reason recorded in
-- 059: server.js connects with the service-role key, which bypasses RLS
-- entirely, and there is no Supabase client in the frontend. Access control is
-- the req.user.id scoping in the route handlers.

-- ── sms_campaign_messages ───────────────────────────────────────────────────

create table if not exists public.sms_campaign_messages (
  id           uuid        not null default gen_random_uuid(),
  campaign_id  uuid        not null,
  step_order   integer     not null,
  message_body text        not null,
  delay_hours  integer     not null default 0,
  created_at   timestamptz not null default now(),
  user_id      uuid,
  constraint sms_campaign_messages_pkey primary key (id)
);

comment on table public.sms_campaign_messages is
  'Transcribed from the live database, which is where this table was created. Predates having DDL in this repo.';

-- add constraint has no if-not-exists form, so this is guarded on pg_constraint
-- the same way 059 guards its unique constraint.
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'sms_campaign_messages_campaign_id_fkey'
      and conrelid = 'public.sms_campaign_messages'::regclass
  ) then
    alter table public.sms_campaign_messages
      add constraint sms_campaign_messages_campaign_id_fkey
      foreign key (campaign_id) references public.sms_campaigns (id) on delete cascade;
  end if;
end $$;

create index if not exists sms_campaign_messages_campaign_id_idx
  on public.sms_campaign_messages (campaign_id);

alter table public.sms_campaign_messages enable row level security;

-- ── sms_send_log ────────────────────────────────────────────────────────────

-- message_body sits last, after sent_at, rather than beside the other message
-- fields. That ordering is not a style choice: a column lands at the end when it
-- is added by a later alter, so this one was added to the table after it was
-- first created. The order is preserved deliberately, so a fresh clone
-- reproduces the live column order rather than a tidier one.
create table if not exists public.sms_send_log (
  id            uuid        not null default gen_random_uuid(),
  user_id       uuid        not null,
  campaign_id   uuid,
  subscriber_id uuid,
  message_id    uuid,
  phone_number  text,
  status        text,
  twilio_sid    text,
  sent_at       timestamptz not null default now(),
  message_body  text,
  constraint sms_send_log_pkey primary key (id)
);

comment on table public.sms_send_log is
  'Transcribed from the live database, which is where this table was created. Predates having DDL in this repo.';

-- No foreign keys. None exist live — campaign_id, subscriber_id and message_id
-- are bare uuids, on the same terms as the enrollment table in 059.

create index if not exists sms_send_log_campaign_id_idx
  on public.sms_send_log (campaign_id);

create index if not exists sms_send_log_user_id_idx
  on public.sms_send_log (user_id);

-- Already idempotent: enabling row level security on a table that already has
-- it enabled succeeds and changes nothing, so no guard is needed around this.
alter table public.sms_send_log enable row level security;
