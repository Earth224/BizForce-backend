-- ============================================================================
-- 079_users_password_reset_and_login_tracking.sql
--
-- ALREADY APPLIED to production before this file was written; recorded here so
-- the repo and the database agree. The same situation 073 documents, and the
-- reason 071 exists at all.
--
-- WHY
--   Four columns on public.users were being written by server.js and defined
--   nowhere. 071 transcribed that table from pg_catalog on 2026-07-31 and none
--   of the four appear in it, so a fresh clone replayed the migration series
--   into a schema the application could not write to:
--
--     password_reset_token       written by POST /api/auth/password-reset
--     password_reset_expires_at  written by the same route
--     last_login_at              written by POST /api/auth/login
--     last_login_ip              written by the same route
--
--   The login pair had been failing silently since it was written: that update
--   does not capture its error either, so every successful login has been
--   discarding a failed write and returning a token anyway. Nothing in the
--   logs said so.
--
-- THE PARTIAL UNIQUE INDEX
--   password_reset_token is looked up as the sole identifier of a password
--   reset - POST /api/auth/password-reset/confirm resolves a user by nothing
--   else. Two rows holding the same token would make that lookup ambiguous,
--   and .maybeSingle() answers an ambiguous match with an error rather than a
--   choice, so the failure would be a broken reset rather than a wrong one.
--   That is the better failure, but it is still worth making impossible.
--
--   Partial on NOT NULL, and that is the whole reason the index can exist. The
--   column is null for every user who has no reset in flight, which is nearly
--   all of them at any moment. Postgres treats nulls as distinct in a unique
--   index, so a plain unique index would technically work - but it would also
--   carry an entry for every row in the table to enforce a constraint that only
--   ever concerns the handful with a live token. The partial index stores only
--   those, and is the index the confirm route's lookup actually uses.
--
--   Tokens are 32 random bytes from crypto.randomBytes, so a collision is not a
--   practical concern. This index is not defending against chance; it is
--   defending against a future code path that assigns a token without clearing
--   the previous one.
--
-- NOT DONE HERE
--   No index on last_login_at. Nothing queries it yet - it is written and never
--   read - and indexing a column on the strength of a future report is how a
--   table accumulates indexes nobody can account for.
--
--   No NOT NULL and no defaults. All four columns are legitimately absent for
--   most rows: a user who has never reset a password and never logged in since
--   the columns existed has four nulls, and that is the correct description of
--   them rather than a gap to be filled.
--
--   No expiry sweep. Rows keep a spent or lapsed token until the next reset
--   overwrites it or the confirm route clears it. A stale token is already
--   refused on its expiry timestamp, so a cleanup job would be tidying rather
--   than protecting, and it would need a schedule this system does not have.
--
-- SAFETY
--   Additive and idempotent. Nullable with no defaults, so no existing row is
--   rewritten and the table is not locked for a scan. Every statement is
--   guarded; running this against production is a no-op by design.
-- ============================================================================

set search_path = public;

alter table public.users
  add column if not exists password_reset_token text;

alter table public.users
  add column if not exists password_reset_expires_at timestamptz;

alter table public.users
  add column if not exists last_login_at timestamptz;

alter table public.users
  add column if not exists last_login_ip text;

create unique index if not exists users_password_reset_token_uniq
  on public.users (password_reset_token)
  where password_reset_token is not null;

comment on column public.users.password_reset_token is
  'Single-use password reset token: 32 random bytes hex-encoded, from crypto.randomBytes(32). Set by POST /api/auth/password-reset, consumed and cleared by POST /api/auth/password-reset/confirm in the same update that writes the new password_hash, so a token cannot be replayed. Null means no reset is in flight, which is the normal state.';

comment on column public.users.password_reset_expires_at is
  'When the token in password_reset_token stops being accepted; one hour after it was issued. The confirm route refuses a token whose expiry is null or has passed, so a row carrying a token with no expiry is unusable rather than permanent - the safe direction if a future writer ever sets one without the other.';

comment on index public.users_password_reset_token_uniq is
  'One live reset token at a time, across all users. Partial on NOT NULL because the column is null for nearly every row and only rows with a token in flight need to be constrained or indexed. Also serves the confirm route''s lookup, which resolves a user by token alone.';

comment on column public.users.last_login_at is
  'Timestamp of the most recent successful login, written by POST /api/auth/login. Written but not yet read anywhere.';

comment on column public.users.last_login_ip is
  'req.ip at the most recent successful login. Behind a proxy this is only meaningful if Express is configured to trust it; treat it as advisory rather than as evidence.';
