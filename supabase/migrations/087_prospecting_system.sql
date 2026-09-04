-- ============================================================================
-- 087_prospecting_system.sql
--
-- prospects and icp_profiles — a transcription, not a change.
--
-- Both tables ALREADY EXIST IN PRODUCTION. They were created outside the
-- migration system and have never had DDL in this repo, which is the same
-- condition 068 recorded for bsky_leads and 083 for the five untracked tables:
-- structure that is live, queried, and impossible to check a query against from
-- the repo. What follows lets a fresh clone rebuild them as they actually are.
-- Every statement is guarded; running this against the live database is a no-op.
--
-- WHAT WAS VERIFIED FROM THIS REPO, AND WHAT WAS SUPPLIED
--   Verified live before writing this file, because approximating schema is how
--   083's rule came to be written:
--     - Both tables exist and are empty.
--     - Every column below exists: 24 on prospects, 9 on icp_profiles.
--     - Every column type, probed by feeding each column a value its type
--       cannot parse and reading the resulting 22P02 or 22007. uuid, integer,
--       boolean, text and timestamp were all confirmed this way; criteria and
--       criteria_results were confirmed jsonb rather than json because both
--       accept the containment operator, which json does not support.
--     - All four foreign key RELATIONSHIPS, via PostgREST embedding, which
--       resolves only where a foreign key exists. Checked against a known
--       control (crm_customers -> contacts, from 086) to confirm the technique
--       reports absence correctly: prospects -> bsky_leads does not resolve,
--       which is the expected answer and is why lead_post_uri is plain text.
--
--   NOT readable from here, and supplied by the operator verbatim from an
--   information_schema query run against the live database: every NOT NULL,
--   every DEFAULT, both primary keys, the column each foreign key sits on,
--   every ON DELETE action, the absence of CHECK constraints, all six indexes,
--   the RLS posture, the absence of triggers, and all six column comments,
--   which were run live and read back. information_schema, pg_indexes,
--   pg_class and pg_constraint all return PGRST205 through PostgREST, so none
--   of it could be confirmed independently.
--
--   The primary key on each table is `id uuid not null default
--   gen_random_uuid() primary key`. That could not be read from here either —
--   pg_constraint is PGRST205 like the rest of the catalog — and it is recorded
--   here as confirmed against the live database, not inferred from the
--   convention every other table in this schema follows.
--
-- WHY prospects IS ITS OWN TABLE, AND NOT crm_customers WITH status 'prospect'
--   crm_customers.status already carries 'prospect' among lead / prospect /
--   active / dormant / churned, so the question was live and had to be settled
--   rather than assumed.
--
--   The lifecycles do not meet. A prospect can be DISQUALIFIED, which has no
--   counterpart on the customer side: 'churned' is a customer who left, not
--   someone who never qualified, and disqualified_reason is meaningless on a
--   customer row. Merging the two puts two lifecycles in one status column,
--   which is how an enum becomes twelve values that no longer describe one
--   thing.
--
--   The cardinalities do not meet either. Prospects arrive in bulk from a
--   shared upstream feed — bsky_leads holds 6,889 rows — while customers are
--   typed in by hand. A table absorbing machine-generated volume and a table
--   holding hand-curated records want different indexes and different
--   retention, and merging them makes every CRM list query pay for the prospect
--   volume.
--
--   And this decision has already been made once here, for the same reason: 027
--   declined to reuse bsky_leads.status for the Sales Agent's pipeline, writing
--   that reusing one status column for two lifecycles collides with the queries
--   of both. This is that argument a second time.
--
--   The cost of the split is a person who can exist as two rows. That is what
--   converted_customer_id and converted_at are for, and why the conversion path
--   is a function rather than two writes from a route.
--
-- WHAT THIS FILE DELIBERATELY DOES NOT CONTAIN
--   The conversion function. It lands in 088, on its own, so the table DDL and
--   the function stay independently replayable: a function is dropped and
--   recreated freely, tables are not, and pinning them together would mean
--   replaying table DDL to fix a function body.
--
--   No CHECK on prospects.status. Deliberate, and the same call deals.stage and
--   crm_customers.status already got — see 084, which dropped two type CHECKs
--   for this reason. The vocabulary lives in the application, where adding a
--   value is an edit rather than schema drift, and where an unrecognised value
--   can be answered with a 400 instead of surfacing as a constraint violation
--   and a 500.
--
--   No trigger on updated_at. 066 defines public.set_updated_at(), but
--   crm_customers and deals both maintain updated_at from the application and
--   these follow them. One convention per schema beats two.
--
-- DEPENDENCIES
--   public.users must exist. public.crm_customers must exist — created in 086,
--   which is why this is 087. icp_profiles is created before prospects because
--   prospects.icp_profile_id references it.
--
-- SAFETY
--   Idempotent throughout: create table if not exists, create index if not
--   exists, enable row level security is a no-op when already enabled, and
--   comment on replaces rather than appends. Re-running changes nothing.
-- ============================================================================

set search_path = public;

-- ── icp_profiles ────────────────────────────────────────────────────────────
-- Created first: prospects.icp_profile_id references it.
--
-- pass_threshold sits beside criteria because a rubric without its pass mark is
-- not a rubric — the same weights mean different things at 0 and at 60 — and
-- keeping them in one row means a score and the bar it was judged against
-- cannot drift apart.

create table if not exists public.icp_profiles (
  id             uuid        not null default gen_random_uuid() primary key,
  user_id        uuid        not null references public.users(id) on delete cascade,
  name           text        not null,
  description    text,
  criteria       jsonb       not null default '[]'::jsonb,
  pass_threshold integer     not null default 0,
  is_active      boolean     not null default true,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

-- ── prospects ───────────────────────────────────────────────────────────────

create table if not exists public.prospects (
  id                    uuid        not null default gen_random_uuid() primary key,
  user_id               uuid        not null references public.users(id) on delete cascade,
  name                  text        not null,
  company               text,
  title                 text,
  email                 text,
  phone                 text,
  website               text,
  social_handle         text,
  source                text,
  lead_post_uri         text,
  status                text        not null default 'new',
  fit_score             integer,
  qualification_notes   text,
  disqualified_reason   text,
  last_researched_at    timestamptz,
  converted_customer_id uuid        references public.crm_customers(id) on delete set null,
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now(),
  notes                 text,
  icp_profile_id        uuid        references public.icp_profiles(id) on delete set null,
  criteria_results      jsonb       not null default '[]'::jsonb,
  last_contacted_at     timestamptz,
  converted_at          timestamptz
);

-- ── indexes ─────────────────────────────────────────────────────────────────
-- The two composite indexes follow the 086 convention: every list query on a
-- per-user table filters user_id first, so an index leading with the second
-- column would not be used.
--
-- The three partial indexes are partial on purpose. lead_post_uri,
-- converted_customer_id and icp_profile_id are all nullable and all expected to
-- be null on most rows, so a full index would be mostly null entries. For the
-- unique one the predicate is what makes it CORRECT rather than merely smaller:
-- without `where lead_post_uri is not null`, a second hand-entered prospect for
-- the same user would collide on (user_id, null) and be refused.

create index if not exists prospects_user_status_idx
  on public.prospects (user_id, status);

create index if not exists prospects_user_created_idx
  on public.prospects (user_id, created_at desc);

create unique index if not exists prospects_user_lead_uri_uniq
  on public.prospects (user_id, lead_post_uri)
  where lead_post_uri is not null;

create index if not exists prospects_converted_idx
  on public.prospects (converted_customer_id)
  where converted_customer_id is not null;

create index if not exists prospects_icp_idx
  on public.prospects (icp_profile_id)
  where icp_profile_id is not null;

create index if not exists icp_profiles_user_active_idx
  on public.icp_profiles (user_id, is_active);

-- ── row level security ──────────────────────────────────────────────────────
-- ENABLED ON BOTH, WITH ZERO POLICIES. The same posture 083 recorded, and for
-- the same reason: every read and write the application performs uses the
-- service-role key, which bypasses RLS entirely, so this changes nothing about
-- how the platform behaves today. What it does is close the default — a table
-- with RLS enabled and no policy returns an empty result to anon and
-- authenticated rather than every row, which is the opposite of what
-- bsky_leads' single `using (true)` policy does.
--
-- Enabled-with-no-policies is a deliberate posture, not an unfinished one. If
-- these tables are ever reached with a user-scoped key, the correct answer is
-- nothing until a policy says otherwise.
--
-- Note that this is the one line here that cannot be verified from the repo in
-- either direction while both tables are empty: RLS-on-with-no-policy and
-- RLS-off both return an empty array to a key holding the table grant. It is
-- recorded on the operator's word, like the rest of the constraint metadata.

alter table public.icp_profiles enable row level security;
alter table public.prospects    enable row level security;

-- ── column comments ─────────────────────────────────────────────────────────

comment on column public.prospects.lead_post_uri is
  'Optional link to a bsky_leads row by post_uri, matching the sales_lead_pipeline convention: plain text, no foreign key, so this table does not depend on that one''s column types. NULLABLE by design — most prospects are entered or imported by hand and were never a social post. The partial unique index prevents importing the same lead twice per user while leaving hand-entered rows unconstrained.';

comment on column public.prospects.email is
  'DISPLAY AND REFERENCE ONLY, NEVER A SEND TARGET. Same rule as crm_customers.email: no format check, no normaliser, and no path from here to sendEmail, which requires a contact_id and reads consent_events.';

comment on column public.prospects.phone is
  'DISPLAY AND REFERENCE ONLY, NEVER A SEND TARGET. Same rule as crm_customers.phone. canonicalPhone would null an international number, an extension or a partial one, which is why no normaliser runs here.';

comment on column public.prospects.converted_at is
  'The conversion moment, recorded separately because updated_at moves on every edit and cannot answer when a prospect became a customer.';

comment on column public.prospects.criteria_results is
  'Per-criterion evaluation for this prospect against its ICP. Structured objects — must NOT go through normalizeJsonbArray, which coerces every element to a trimmed string and would store "[object Object]".';

comment on column public.prospects.converted_customer_id is
  'Set when a prospect becomes a CRM customer. ON DELETE SET NULL so deleting the customer does not delete the prospect history that produced them.';
