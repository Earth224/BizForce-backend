-- The deals table had six columns while its own routes wrote thirteen fields.
--
-- 071 transcribed public.deals from the live database as it stood: id, user_id,
-- title, description, deal_type, created_at. Nothing else. But POST /api/deals
-- inserts amount, stage, contact_name, contact_email, expected_close_date,
-- probability and updated_at alongside those, and PUT /api/deals/:id allows six
-- of the same seven plus updated_at on every call.
--
-- PostgREST rejects an insert naming a column it cannot find with PGRST204, and
-- both routes throw on error, so every write returned 500. That is not a theory
-- about what might have happened: it is why the table had ZERO rows. The one
-- route that worked was GET, which faithfully returned an empty list, and
-- DELETE, which had nothing to delete.
--
-- The read side was wrong in a quieter way. GET /api/dashboard sums deal.amount
-- into metrics.revenue_pipeline and filters deal.stage === "won" into
-- metrics.won_revenue. Neither column existed, so those two figures were
-- STRUCTURALLY always zero -- not "zero because there are no deals", but zero
-- for any number of deals, since Number(undefined || 0) is 0 and
-- String(undefined).toLowerCase() is "undefined" and never "won". Adding rows
-- without adding these columns would have left the dashboard confidently
-- reporting no revenue while the pipeline filled up.
--
-- Same family as the usage_logs mismatch that 500'd the dashboard: code written
-- against a schema that was never applied. The difference is where it surfaced.
-- usage_logs failed on the read and took a route down loudly; deals failed on
-- the write and left an empty table that looked merely unused.
--
-- ON THE ABSENCE OF A CHECK CONSTRAINT for stage: deliberate, and the same
-- argument 084 makes for dropping the agent_collaborations type checks. A stage
-- vocabulary in Postgres is a second copy of a list the application already
-- owns, and a second copy is the thing that drifts -- 003's eleven-of-seventeen
-- agent types are what that looks like a year later. The application validates
-- stage; this column stores it.

alter table public.deals
  add column if not exists amount numeric(12,2),
  add column if not exists stage text not null default 'new',
  add column if not exists contact_name text,
  add column if not exists contact_email text,
  add column if not exists expected_close_date date,
  add column if not exists probability integer,
  add column if not exists updated_at timestamptz not null default now();

create index if not exists deals_user_stage_idx
  on public.deals (user_id, stage);

create index if not exists deals_user_created_idx
  on public.deals (user_id, created_at desc);

comment on column public.deals.amount is 'Deal value in major units (dollars), never cents.';
comment on column public.deals.stage is 'Pipeline stage. Validated in the application, deliberately not a CHECK — a stage list in Postgres is a second copy that drifts.';
comment on column public.deals.probability is 'Percent, 0-100.';
