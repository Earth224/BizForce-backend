-- ============================================================================
-- 122_users_email_verification_columns.sql
--
-- WHY
--   Email verification has never been recorded anywhere. POST /api/auth/register
--   mints email_verification_token and stores it; POST /api/auth/verify-email
--   finds the user by that token, clears it, writes updated_at and answers
--   success. Nothing marks the account verified.
--
--   It used to try. The route wrote email_verified: true and registration wrote
--   email_verified: false, until both were stripped on 2026-04-29 (724dd91,
--   25ff2df) because no migration had ever created that column and the writes
--   were failing. The fix at the time was to stop writing, which left the route
--   claiming a verification it could not store.
--
--     email_verified_at              when the address was confirmed; null means
--                                    not confirmed. A timestamp rather than the
--                                    old boolean, so the record also says when.
--     email_verification_expires_at  when email_verification_token stops being
--                                    accepted, set alongside the token at
--                                    registration, on the same terms as
--                                    password_reset_expires_at (079).
--
-- NOT verification_status
--   users.verification_status (000, text default 'pending') is ADMIN BUSINESS
--   verification. POST /api/admin/verify/:userId wrote 'verified' to it until
--   b4fbb11 stripped that write the same day. Email confirmation and an admin
--   vouching for a business are different facts about an account, and sharing
--   one column would make them indistinguishable. This migration does not touch
--   it, and nothing in the email verification path writes it.
--
-- NOT DONE HERE
--   No backfill. No existing account has confirmed an address: no link was ever
--   sent. Null in email_verified_at is the accurate description of all of them,
--   not a gap to be filled. The tokens some of them hold (5 of 11 accounts on
--   2026-09-28; the other 6 hold none) have no expiry, and the verify route
--   refuses a token whose expiry is null, so those old tokens are unusable
--   rather than permanent.
--
--   No NOT NULL and no defaults. A DEFAULT now() on email_verified_at would
--   mark every new account verified at the moment it was created, which is the
--   exact claim this column exists to stop making without evidence.
--
--   No expiry sweep, for the reason 079 gives for reset tokens: a lapsed token
--   is already refused on its expiry, so a cleanup job would be tidying rather
--   than protecting.
--
-- THE PARTIAL UNIQUE INDEX
--   email_verification_token is the sole identifier POST /api/auth/verify-email
--   resolves a user by, exactly as password_reset_token is for the reset
--   confirm route, so it gets the index 079 gave that column, in the same form.
--   Two rows holding one token would make the lookup ambiguous, and
--   .maybeSingle() answers that with an error rather than a choice.
--
--   Partial on NOT NULL. On 2026-09-28, 5 of the 11 rows held a token and 6
--   held none; none of the 5 is shared, so the index builds. From here every
--   registration adds a token and every verification clears one, so the index
--   holds only accounts with a verification still outstanding.
--   Tokens are 32 random bytes from crypto.randomBytes, so a collision is not a
--   practical concern; like 079's, this index defends against a future code
--   path that assigns a token without clearing the previous one.
--
--   It is built without CONCURRENTLY, as 079's was, so it holds a write lock on
--   users for the duration of the build. The table is small enough that this
--   is brief, but it blocks registrations and logins while it runs.
--
-- SAFETY
--   Additive and idempotent. The two columns are nullable with no defaults, so
--   no existing row is rewritten. The index build is the one step that reads
--   the whole table and holds a write lock while it does (see above). Every
--   statement is guarded. Nothing is dropped, renamed or altered, and no
--   existing file is renumbered: 121 was the highest before this.
-- ============================================================================

set search_path = public;

alter table public.users
  add column if not exists email_verified_at timestamptz;

alter table public.users
  add column if not exists email_verification_expires_at timestamptz;

create unique index if not exists users_email_verification_token_uniq
  on public.users (email_verification_token)
  where email_verification_token is not null;

comment on column public.users.email_verified_at is
  'When the account confirmed its email address, written by POST /api/auth/verify-email when a valid, unexpired email_verification_token is presented. Null means the address has not been confirmed, which is true of every account created before this column existed. Records a fact only: nothing gates on it. Distinct from verification_status, which is admin business verification.';

comment on column public.users.email_verification_expires_at is
  'When the token in email_verification_token stops being accepted. Set with the token at registration. The verify route refuses a token whose expiry is null or has passed, so a row carrying a token with no expiry (every account created before this column existed) is unusable rather than permanent.';

comment on index public.users_email_verification_token_uniq is
  'One holder per verification token, across all users. Partial on NOT NULL so a token cleared on verification leaves the index. Also serves the verify route''s lookup, which resolves a user by token alone.';
