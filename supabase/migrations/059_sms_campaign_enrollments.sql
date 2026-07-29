-- sms_campaign_enrollments — a transcription, not a change.
--
-- This table ALREADY EXISTS IN PRODUCTION. It was hand-created outside the
-- migration system and has never had DDL in this repo in any form, while
-- server.js references it seven times. What follows was read out of
-- information_schema and pg_index against the live database, so that a fresh
-- clone can rebuild the table as it actually is.
--
-- It is not intended to change anything in production. Every statement is
-- guarded, so running this against the live database is a no-op.
--
-- Two things this file deliberately does NOT do:
--
-- 1. No foreign keys. user_id, campaign_id and subscriber_id are bare uuids
--    with no referential integrity — nothing points at public.users,
--    sms_campaigns or sms_subscribers. That is what is live, so that is what
--    this records. Adding them is a separate decision that has to start by
--    looking for orphaned rows: an alter that adds a foreign key fails
--    outright if existing data violates it.
--
-- 2. No check constraint on status. 'active' is a default and an application
--    convention, not a rule the database enforces. Same reasoning — record
--    what is live rather than quietly add a constraint that could fail
--    against rows already in the table.
--
-- RLS is enabled with zero policies, which is also not an oversight. server.js
-- connects with the service-role key, which bypasses RLS entirely, and there is
-- no Supabase client in the frontend. Access control for this table is the
-- req.user.id scoping in the route handlers, not a policy.

create table if not exists public.sms_campaign_enrollments (
  id            uuid        not null default gen_random_uuid(),
  user_id       uuid        not null,
  campaign_id   uuid        not null,
  subscriber_id uuid        not null,
  current_step  integer     not null default 0,
  status        text        default 'active'::text,
  next_send_at  timestamptz,
  enrolled_at   timestamptz not null default now(),
  constraint sms_campaign_enrollments_pkey primary key (id)
);

comment on table public.sms_campaign_enrollments is
  'Transcribed from the live database, which is where this table was created. Predates having DDL in this repo.';

-- The three comments below are read off what runDripEngine and the enroll
-- routes in server.js actually do with these columns, not off their names.

comment on column public.sms_campaign_enrollments.current_step is
  'Zero-based index into the sms_campaign_messages rows for this campaign, ordered by step_order — the message the drip engine sends next. Incremented by one after each successful send; once it reaches the message count the enrollment is marked completed.';

comment on column public.sms_campaign_enrollments.status is
  'Drip engine state. The engine selects only rows set to active, and writes completed once current_step has passed the last message. Those are the only two values server.js writes; the database does not enforce the set.';

comment on column public.sms_campaign_enrollments.next_send_at is
  'Earliest time the next message may be sent — the drip engine skips the enrollment while this is in the future. Set to now plus the delay_hours of the next message after each send. Null means send on the next run: either the enrollment is new, or there is no next message.';

-- add constraint has no if-not-exists form, and the drop-then-recreate idiom
-- used elsewhere in this folder is wrong here: dropping a unique constraint
-- drops its backing index, so recreating it would rebuild that index on a live
-- table. That is not a no-op. Guarded on pg_constraint instead.
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'sms_enrollments_campaign_subscriber_key'
      and conrelid = 'public.sms_campaign_enrollments'::regclass
  ) then
    alter table public.sms_campaign_enrollments
      add constraint sms_enrollments_campaign_subscriber_key unique (campaign_id, subscriber_id);
  end if;
end $$;

create index if not exists sms_enrollments_campaign_id_idx
  on public.sms_campaign_enrollments (campaign_id);

create index if not exists sms_enrollments_next_send_at_idx
  on public.sms_campaign_enrollments (next_send_at);

create index if not exists sms_enrollments_user_id_idx
  on public.sms_campaign_enrollments (user_id);

-- Already idempotent: enabling row level security on a table that already has
-- it enabled succeeds and changes nothing, so no guard is needed around this.
alter table public.sms_campaign_enrollments enable row level security;
