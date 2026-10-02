-- ============================================================================
-- 126_screen_removals_unsupported_economics.sql
--
-- WHAT THIS IS
--   Lets testimonial_screen_removals (migrations 124, 125) hold a third kind of
--   finding: pattern 'unsupported_economics', written by
--   screenUnsupportedEconomics in server.js. Only the check constraint changes.
--
-- WHAT AN 'unsupported_economics' ROW IS
--   A sentence from an agent's reply asserting a margin or cost fact about the
--   user's business ("Your margin allows it.", "The six-pack at $55 is your
--   margin driver.", "the strongest unit economics") when the business profile
--   holds no costs. Like 'sales_superlative', the sentence was NOT removed: it
--   was kept, marked [UNVERIFIED], and noted at the top, because the claim may
--   be true and the owner can check it. The row records it for review.
--
-- WHO READS IT: unchanged from 124 — nothing in the product. RLS with no
--   policies, anon and authenticated revoked.
--
-- BEFORE THIS IS APPLIED, inserts of 'unsupported_economics' rows fail the
-- constraint. recordTestimonialRemovals inserts each pattern separately, so
-- only those rows are lost; the task and the other findings are unaffected.
--
-- APPLY BY HAND, once, in the SQL editor.
-- ============================================================================

alter table public.testimonial_screen_removals
  drop constraint if exists testimonial_screen_removals_pattern_known;

alter table public.testimonial_screen_removals
  add constraint testimonial_screen_removals_pattern_known
    check (pattern in ('quoted_first_person', 'attributed_claim', 'both', 'sales_superlative', 'unsupported_economics'));
