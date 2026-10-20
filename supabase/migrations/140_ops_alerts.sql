-- 140_ops_alerts.sql
--
-- THE OPEN OWNER ALERTS. One row per alert key that is open right now
-- (lib/opsAlert.js): a job_runs error, a failed Stripe webhook, a failed or
-- stale nightly backup, or /health's database probe failing. The row is
-- written when the alert opens or its error changes, and deleted when it
-- clears, at which point one "resolved" email is sent.
--
-- WHY A TABLE. Dedupe ("at most once per 6 hours") and "resolved" both need
-- to know what was already sent. Held in memory, every deploy would re-send
-- each open alert and never send its "resolved". Until this table exists,
-- alerts still send and that state is kept per process, which is logged once.
--
-- No personal data: keys are job names and fixed trigger names, errors are
-- server error text truncated to 500 characters.
--
-- Applied by hand in the Supabase SQL editor. Re-runnable.

create table if not exists public.ops_alerts (
  alert_key     text        primary key,
  what          text        not null,
  fingerprint   text        not null,
  error         text        null,
  where_to_look text        null,
  log_tag       text        null,
  opened_at     timestamptz not null,
  last_sent_at  timestamptz null
);

-- The same posture as job_runs: row level security on, no policies, so only
-- the service key (the server) can read or write it.
alter table public.ops_alerts enable row level security;

comment on table public.ops_alerts is
  'Open owner alerts (lib/opsAlert.js), one row per key. last_sent_at is when the owner was last emailed (null: never, e.g. no recipient set); a key with the same fingerprint is emailed at most once per 6 hours. Deleted when the alert clears.';
