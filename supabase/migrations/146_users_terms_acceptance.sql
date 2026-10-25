-- 146_users_terms_acceptance.sql — which Terms each member accepted, and when.
--
-- WHY. Sign-up now requires the box "I am 18 or older and agree to the Terms
-- and Privacy Policy" (POST /api/auth/register refuses without it), and the
-- acceptance must be on record: when, and which version of the Terms.
--
--   terms_accepted_at  when the member last accepted the Terms.
--   terms_version      the version they accepted: lib/legal.js TERMS_VERSION
--                      at that moment, an ISO date such as '2026-10-23'.
--
-- Written by POST /api/auth/register (with the account) and by
-- POST /api/me/terms/accept (a member accepting updated Terms). Read by
-- GET /api/me/terms. A member whose terms_version is null or older than the
-- current version is shown "We've updated our Terms" once, until they accept;
-- that notice never blocks their access to their data or to Billing.
--
-- NO BACKFILL. No existing account ever accepted these Terms, so null is the
-- accurate description of every existing row. Those members see the notice.
-- No default: a DEFAULT now() would record an acceptance nobody gave.
--
-- No new table, so no new RLS policy: public.users already has its own.

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS terms_accepted_at timestamptz;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS terms_version text;

COMMENT ON COLUMN public.users.terms_accepted_at IS
  'When the member last accepted the Terms and Privacy Policy. Null: never accepted (accounts made before 2026-10-23).';
COMMENT ON COLUMN public.users.terms_version IS
  'The Terms version accepted at terms_accepted_at: lib/legal.js TERMS_VERSION, an ISO date.';
