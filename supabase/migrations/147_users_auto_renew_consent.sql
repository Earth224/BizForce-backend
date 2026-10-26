-- 147_users_auto_renew_consent.sql — when each member agreed to automatic
-- renewal at checkout, and to which wording.
--
-- WHY. California's Automatic Renewal Law asks for the consumer's affirmative
-- consent to the automatic renewal terms before the subscription is charged.
-- Before a checkout session is created, billing.html and app.html show a box,
-- unchecked by default, beside the price: "I agree that All Access renews
-- automatically every month at $199 until I cancel, and that I can cancel
-- online at any time in Billing." (server.js autoRenewConsent, from
-- PLAN_CONFIG). POST /api/stripe/checkout refuses without it, and records it
-- here before the session exists.
--
--   auto_renew_consent_at       when the member last ticked the box and
--                               started a checkout.
--   auto_renew_consent_version  the wording they agreed to: server.js
--                               AUTO_RENEW_CONSENT_VERSION at that moment, an
--                               ISO date such as '2026-10-26'.
--
-- The same two values go into the Stripe checkout session's metadata and the
-- subscription's metadata.
--
-- NO BACKFILL and no default: nobody has ticked this box yet, so null is the
-- accurate description of every existing row.
--
-- No new table, so no new RLS policy: public.users already has its own.

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS auto_renew_consent_at timestamptz;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS auto_renew_consent_version text;

COMMENT ON COLUMN public.users.auto_renew_consent_at IS
  'When the member last agreed to automatic renewal at checkout. Null: never (no checkout since 2026-10-26).';
COMMENT ON COLUMN public.users.auto_renew_consent_version IS
  'The automatic-renewal wording agreed to at auto_renew_consent_at: server.js AUTO_RENEW_CONSENT_VERSION, an ISO date.';
