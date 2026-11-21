-- APPLIED (P3-2, recorded Nov 21 2026): applied BY HAND by the owner on Nov 21 2026, and verified by the owner
-- afterwards: the 2 columns below are present on public.bf_profiles.
-- This file records what is live. It was written after the owner applied it, to match the owner's description of
-- what was applied: bf_profiles.verified_reason text (NULL, or 'member', 'seller' or 'official', held by the CHECK
-- named bf_profiles_verified_reason_allowed) and bf_profiles.verified_at timestamptz, both added IF NOT EXISTS.
--
-- 199 (P3-2, Nov 21 2026): the Verified badge (lib/verified.js).
--   verified_reason  why the badge shows; NULL shows none.
--                    'member'   a paid BizForce member while entitled (kept in step with the membership by the server:
--                               set when it becomes active, cleared when it ends, and reconciled by a scheduled job);
--                    'seller'   a verified seller, set and removed by the owner (POST /api/admin/verify/:userId,
--                               POST /api/admin/unverify/:userId);
--                    'official' the owner's official accounts, set by the owner.
--                    Cleared on a ban, an admin un-verify, or a moderation removal of the profile.
--   verified_at      when the current reason was set; NULL when there is none.
-- No new table, so no row level security change: bf_profiles keeps the policies it has.
-- Safe to re-run: both columns are added IF NOT EXISTS.
-- Paste-safe: no less-or-equal or greater-or-equal operators.

ALTER TABLE public.bf_profiles
  ADD COLUMN IF NOT EXISTS verified_reason text
    CONSTRAINT bf_profiles_verified_reason_allowed
    CHECK (verified_reason IS NULL OR verified_reason IN ('member', 'seller', 'official'));

ALTER TABLE public.bf_profiles
  ADD COLUMN IF NOT EXISTS verified_at timestamptz;
