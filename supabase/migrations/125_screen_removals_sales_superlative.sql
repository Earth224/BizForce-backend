-- ============================================================================
-- 125_screen_removals_sales_superlative.sql
--
-- WHAT THIS IS
--   Lets testimonial_screen_removals (migration 124) hold a second kind of
--   finding: pattern 'sales_superlative', written by screenSalesSuperlatives
--   in server.js. Only the table's check constraint changes.
--
-- WHAT A 'sales_superlative' ROW IS
--   A sentence from an agent's reply that claims how the user's products sell
--   ("your highest-volume products", "they drive volume") when the business
--   profile holds no sales figures by product. Unlike the testimonial
--   patterns, the sentence was NOT removed from the result: it was kept, marked
--   [UNVERIFIED], and noted at the top, because such a claim may be true. The
--   row records it so the screen can be reviewed. The table's name predates
--   this pattern; the pattern column says which kind each row is.
--
-- WHO READS IT: unchanged from 124 — nothing in the product. RLS with no
--   policies, anon and authenticated revoked.
--
-- BEFORE THIS IS APPLIED, inserts of 'sales_superlative' rows fail the old
-- constraint. recordTestimonialRemovals inserts each pattern separately, so
-- that failure is logged and costs only those rows: the testimonial removals
-- beside them are still recorded, and the task is stored as before.
--
-- APPLY BY HAND, once, in the SQL editor.
-- ============================================================================

alter table public.testimonial_screen_removals
  drop constraint if exists testimonial_screen_removals_pattern_known;

alter table public.testimonial_screen_removals
  add constraint testimonial_screen_removals_pattern_known
    check (pattern in ('quoted_first_person', 'attributed_claim', 'both', 'sales_superlative'));
