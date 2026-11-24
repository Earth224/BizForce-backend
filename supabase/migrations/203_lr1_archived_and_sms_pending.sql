-- ===== PART 203a: a sales pipeline row may be archived (run first) =====
-- LR-1 (Nov 23 2026): stranded leads are archived, never re-scored and never deleted
-- (scripts/oneoff/lr1Archive.js). bsky_leads.status has no CHECK, so 'archived' needs nothing there;
-- sales_lead_pipeline.status has the inline CHECK from 027, which Postgres named
-- sales_lead_pipeline_status_check. It is dropped and added back with 'archived' as a sixth value.
-- Every read of the pipeline skips archived rows, and a member cannot set the status (server.js
-- SALES_LEAD_STATUSES leaves it out).
-- Paste-safe: no less-or-equal or greater-or-equal operators, no DO blocks, no transaction statements; every
-- CHECK is named and dropped if it exists first. Each part runs alone, in order: 203a, 203b.
ALTER TABLE public.sales_lead_pipeline DROP CONSTRAINT IF EXISTS sales_lead_pipeline_status_check;
ALTER TABLE public.sales_lead_pipeline ADD CONSTRAINT sales_lead_pipeline_status_check
  CHECK (status IN ('new', 'drafted', 'contacted', 'replied', 'converted', 'archived'));

-- ===== PART 203b: an SMS number is pending until consent is recorded (run second) =====
-- LR-1 (Nov 23 2026): sms_subscribers.consent_status defaulted to 'opted_in' (023), so a row written without a
-- status read as consent. The default is now 'pending'. The add and import routes write opted_in only with a
-- recorded consent_events row (its source and time). Existing rows are not changed.
ALTER TABLE public.sms_subscribers ALTER COLUMN consent_status SET DEFAULT 'pending';
