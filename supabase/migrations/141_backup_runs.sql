-- 141_backup_runs.sql
--
-- ONE ROW PER NIGHTLY BACKUP RUN (lib/backup.js runNightlyBackup), success or
-- failure: when it ran, whether it was sent, whether every table was whole,
-- the backup id and number of parts, the encrypted size, and the row count of
-- every table in it (the manifest's counts).
--
-- WHY A TABLE. job_runs.nightly_backup (written by lib/opsAlert.js
-- backupFinished) keeps only the latest run, and finished_at there is the last
-- SUCCESS, which is what the 30-hour staleness alert reads. That row has no
-- room for counts. This keeps the history, so "how many contacts were in
-- Tuesday's backup" and "when did a table start coming back partial" have an
-- answer without opening an encrypted file.
--
-- No personal data: table names, counts, sizes, reasons and server error text.
-- Until this table exists the backup still runs and sends; the failed insert
-- is logged with [NightlyBackup][FAILED].
--
-- Applied by hand in the Supabase SQL editor. Re-runnable.

create table if not exists public.backup_runs (
  id          uuid        primary key default gen_random_uuid(),
  started_at  timestamptz not null,
  finished_at timestamptz not null,
  ok          boolean     not null,  -- sent, and every table whole
  sent        boolean     not null,  -- every part was accepted by Resend
  reason      text        null,      -- null when ok; "incomplete", or why nothing was sent
  error       text        null,
  backup_id   text        null,      -- the manifest's backup_id, shared by every part
  parts       integer     null,
  bytes       bigint      null,      -- encrypted bytes across all parts
  total_rows  integer     null,
  counts      jsonb       not null default '{}'::jsonb,  -- table name -> rows in the backup
  problems    jsonb       not null default '{}'::jsonb,  -- { incomplete: [...], errored: [...] }
  commit      text        null
);

create index if not exists backup_runs_started_at_idx on public.backup_runs (started_at desc);

-- The same posture as job_runs: row level security on, no policies, so only
-- the service key (the server) can read or write it.
alter table public.backup_runs enable row level security;

comment on table public.backup_runs is
  'One row per nightly backup run (lib/backup.js). ok = sent and every table whole. counts holds each table''s rows in that backup. The latest success is also job_runs.nightly_backup.finished_at, which the staleness alert reads.';
