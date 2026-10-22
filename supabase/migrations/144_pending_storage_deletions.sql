-- 144_pending_storage_deletions.sql
--
-- CHANGES the database. One new table, nothing else touched. NOT YET APPLIED:
-- the owner runs this in the Supabase SQL editor BEFORE the backend that uses
-- it deploys. Every statement is `if not exists`, so running it twice is a
-- no-op.
--
-- WHY. Deleting an account (POST /api/me/delete) now deletes the member's
-- uploaded files from Supabase Storage as well as their rows. The rows go
-- first, inside the delete; the files go after, in batches. A batch Storage
-- refuses (an outage, a timeout) must not be forgotten, so each file in it is
-- written here, and a daily job (pending_storage_deletions in job_runs, 04:15
-- UTC) tries again until the file is gone. lib/accountFiles.js does both.
--
--   bucket            the Storage bucket: bf-public, bf-books or
--                     bf-digital-goods
--   path              the object key inside it
--   attempts          how many removals have failed; the first failure writes
--                     1. At 5 the owner gets one ops alert, and the retries go on
--   last_error        what Storage said the last time
--   last_attempt_at   when the last retry ran
--   created_at        when the delete first failed to remove it
--
-- NO MEMBER ID IS STORED. The account is already deleted when a row is written
-- here; the path is all the retry needs. A path may contain the deleted
-- member's id as a folder name, which is how Storage names their files, and
-- the row is removed once the file is.
--
-- RLS on, no policy: only the service key (the server) reads or writes it.

create table if not exists public.pending_storage_deletions (
  id uuid primary key default gen_random_uuid(),
  bucket text not null,
  path text not null,
  attempts integer not null default 1 check (attempts >= 0),
  last_error text,
  last_attempt_at timestamptz,
  created_at timestamptz not null default now(),
  unique (bucket, path)
);

alter table public.pending_storage_deletions enable row level security;
