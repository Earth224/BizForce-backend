-- ============================================================================
-- 094_business_profiles_transcription.sql
--
-- business_profiles — a transcription, not a change.
--
-- The table ALREADY EXISTS IN PRODUCTION and does not match the file that
-- claims to create it. This records what is actually there, in the same spirit
-- as 034 (marketplace_orders), 071 (the foundation tables), 089 (the wallet
-- functions) and 091 (the inventory pair): the schema was built live, and a
-- migration directory that does not contain it cannot rebuild it.
-- `create table if not exists` and guarded column adds make this a no-op in
-- effect against the live database.
--
-- ── 014 AND 015 DESCRIBE A DIFFERENT TABLE ─────────────────────────────────
--   This is not a stale file that fell behind. A stale file would be a SUBSET
--   of what exists. 014_business_profiles.sql and 015_business_profiles_extra_
--   fields.sql diverge from the live table in BOTH DIRECTIONS, which is only
--   possible if they were never the thing that built it.
--
--   FIVE COLUMNS THEY DECLARE THAT DO NOT EXIST:
--     brand_values, business_goals, banned_topics, competitors,
--     posting_frequency
--
--   TEN LIVE COLUMNS THEY NEVER MENTION:
--     niche, revenue_goal, monthly_budget, automation_level, monthly_revenue,
--     primary_goal, top_keywords, top_competitors, business_description, goals
--
--   Fifteen columns appear in both. No migration after 015 touches the table:
--   021, 023 and 028 name business_profiles only in comments, citing its
--   no-foreign-key pattern.
--
--   The tell that 014 was written from imagination rather than transcribed is
--   automation_level and revenue_goal. They are live columns that nothing in
--   either repository has ever read, and nobody inventing a schema would think
--   to invent them.
--
-- ── THE DIVERGENCE CAUSED HARM, IT WAS NOT MERELY UNTIDY ───────────────────
--   Both halves of the codebase were written against 014, so both were wrong in
--   ways that looked like ordinary emptiness rather than like a bug.
--
--   THE READ SIDE, silent and total. config/brain.js:formatBusinessProfile
--   read p.business_goals and p.competitors — two of the five phantom names.
--   Both resolved to undefined, so the "Not provided" fallback fired, and that
--   block reaches EVERY AGENT AND THE ORACLE through all six
--   buildAgentSystemPrompt call sites. Every model this platform runs was told:
--
--       Goals: Not provided
--       Competitors: Not provided
--
--   against a row holding "Revenue Growth" in primary_goal and a full
--   competitor list in top_competitors. An empty-looking profile is exactly
--   what an unfilled profile looks like, which is why it went unnoticed. Two
--   inline copies of the same formatting, in POST /api/business-chat and
--   POST /api/insights/page, carried the same fault, plus a `positioning` name
--   that exists in neither the live table nor in 014.
--
--   THE WRITE SIDE, loud but unattributed. The POST /api/business-profile
--   upsert built an unconditional object literal naming all five phantom
--   columns. PostgREST rejects an unknown column with PGRST204 and does not
--   partially apply, so every request failed and THAT ROUTE COULD NOT SAVE
--   ANYTHING AT ALL for as long as those keys were in the literal. The PATCH
--   route built its updates conditionally, so it failed only for a client that
--   sent one of the five by name — which agents/content.html does, for six of
--   its twelve fields.
--
--   Both were corrected against this transcription, not against 014.
--
-- ── FOUR DUPLICATE PAIRS ───────────────────────────────────────────────────
--   Four concepts are stored twice under different names. Each pair holds the
--   same value on the live row today. They are recorded here rather than
--   reconciled, because collapsing one is a data decision and this file only
--   describes.
--
--     niche / industry
--       written by: both, aliased in each direction
--       read by:    formatBusinessProfile reads `industry`; the dashboard form
--                   renders both inputs; agents/content.html posts `industry`
--       load-bearing: industry — it is what reaches the model
--
--     primary_goal / goals
--       written by: both, aliased; agents/content.html's `business_goals` maps
--                   onto primary_goal
--       read by:    formatBusinessProfile reads primary_goal, falling back to
--                   goals; the dashboard form reads primary_goal
--       load-bearing: primary_goal. Nothing has ever written `goals`.
--
--     business_description / description
--       written by: both, aliased in each direction
--       read by:    formatBusinessProfile reads `description`; the dashboard
--                   form reads `business_description`
--       load-bearing: description — and the alias is what keeps the model's
--                   Description line current, since the dashboard posts only
--                   the other spelling
--
--     monthly_revenue / revenue_goal
--       written by: monthly_revenue from the dashboard; revenue_goal by nothing
--       read by:    the dashboard form reads monthly_revenue; no prompt reads
--                   either
--       load-bearing: neither reaches a model
--
--   BOTH SPELLINGS OF EVERY PAIR ARE NOW ACCEPTED BY BOTH ROUTES, in a fixed
--   precedence, and each write fills both columns. That is deliberate: it means
--   a client that knows only one name cannot leave the other stale, and the two
--   members cannot drift apart into disagreeing answers to the same question.
--
-- ── social_platforms IS TEXT ───────────────────────────────────────────────
--   Not the `jsonb NOT NULL DEFAULT '{}'` 014 declares. It is nullable text
--   with no default, and the live row holds the string "All Platforms".
--
--   Both routes guarded it as jsonb: a value that was not a non-array object
--   was replaced with a JavaScript {}. Every client sends a string — the
--   dashboard reads it straight from a text input — so that guard rejected
--   every real value and substituted an empty object. It never fired only
--   because the five phantom columns failed the request first. THE MOMENT THOSE
--   WERE REMOVED, THAT LINE WOULD HAVE WRITTEN {} OVER "All Platforms", which
--   is why the type correction had to ship in the same commit as the removal
--   rather than after it. It is safeText now, like every other text column.
--
-- ── TWO COLUMNS NOTHING READS ──────────────────────────────────────────────
--   automation_level and revenue_goal have NO READER anywhere in either
--   repository — not in a prompt, not in a route, not in a page, not in a
--   comment. automation_level is the only column on this table carrying a
--   non-null default ('moderate'), so every row asserts a value that nothing
--   consults.
--
--   Both became WRITABLE when the POST payload was made conditional, because
--   until then a key with nothing behind it would have nulled its column on
--   every save. They are written now and read never, which is a smaller gap
--   than being unreachable, but it is still a gap: something intended them.
--
-- ── user_id IS NULLABLE, BUT IT IS NOT UNPROTECTED ─────────────────────────
--   Precisely: the column permits NULL, and a NULL would be an ownerless row
--   that no route could ever reach. But any NON-NULL value is enforced —
--   business_profiles_user_id_fkey references users(id), so a user_id naming a
--   user that does not exist is rejected by the database, and
--   business_profiles_user_id_unique holds it to one profile per user.
--
--   014 declares `user_id uuid NOT NULL UNIQUE`. It is right about UNIQUE, in
--   substance if not in name, and wrong about NOT NULL — and its header claim
--   that there is "No FK on user_id to match existing schema pattern (see
--   009_profile_page.sql)" is wrong too. The foreign key exists.
--
--   So the only gap the schema leaves is the NULL itself, and both write routes
--   close it in practice: user_id is always set from req.user.id, taken from
--   the verified token and never from the request body. That is a property of
--   the call sites rather than of the column, and a NOT NULL would make it a
--   property of the table — but nothing today can produce the row it would
--   prevent.
--
--   ON DELETE CASCADE is worth recording rather than passing over. Deleting a
--   user deletes their business profile, which is the right choice here: the
--   row is grounding context about that person's business and nothing else, it
--   is reachable only through them, and an orphan would be unreadable by any
--   route and meaningless to any agent. It is the same reasoning 069 applied to
--   consent_events.contact_id, pointing the other way — there, cascading was
--   right because an orphaned consent event proves nothing about anybody.
--   Compare 091, which chose RESTRICT for inventory_movements.item_id because
--   an orphaned movement still carries quantity and cost that a closed period
--   depends on. Nothing on this table has that property.
--
-- ── HOW THIS WAS READ ──────────────────────────────────────────────────────
--   Columns, order, types, nullability and defaults came from
--   information_schema.columns. Constraints came from pg_constraint, indexes
--   from pg_indexes, and the RLS posture from pg_class and pg_policy. All of it
--   is transcribed verbatim; nothing below is inferred from 014, which has been
--   shown wrong in five separate directions now — the five phantom columns, the
--   ten it omits, social_platforms' type, the NOT NULL set, and the claim that
--   there is no foreign key on user_id.
--
--   There is no SQL path from the working environment — .env carries
--   SUPABASE_URL and the keys but no DATABASE_URL, and no postgres driver is
--   installed — so the catalog output was supplied rather than queried from
--   here. That is the same split 091 records and for the same reason: the half
--   a column listing cannot carry is exactly the half that matters, and a file
--   built from the API alone "would have looked complete, widened three
--   columns, dropped five indexes including a uniqueness rule, and silently
--   left RLS off".
--
--   THE UNIQUE INDEX ON user_id IS LOAD-BEARING FOR THE APPLICATION, not just
--   for data integrity. server.js upserts against this table with
--   { onConflict: "user_id" } at three sites, and Postgres can satisfy
--   ON CONFLICT only against a unique constraint or unique index covering that
--   exact column. Without business_profiles_user_id_unique, every one of those
--   upserts raises 42P10 and the profile cannot be saved at all.
--
--   That is not hypothetical here. 072 moved uniqueness off subscriptions.
--   user_id and onto stripe_subscription_id without updating the two webhook
--   paths that upsert on user_id, and 075 records the result: 42P10 on every
--   write, and billing that "has still never processed a payment". A second
--   shape of the same trap sits in 080, where revenue_events carries a PARTIAL
--   unique index on stripe_event_id — a partial index serves ON CONFLICT only
--   when the statement repeats its predicate, so moving this constraint to a
--   partial one would break the upserts just as thoroughly as removing it.
--
--   Anyone touching the constraint below should read 075 first.
-- ============================================================================


-- ── business_profiles ──────────────────────────────────────────────────────
-- Every column is nullable and every column is text, except the five noted.
-- id is the only NOT NULL column on the table. automation_level, created_at
-- and updated_at are the only columns with a default.
--
-- Column order is the live ordinal order, which is not tidy — created_at and
-- updated_at sit in the middle rather than at the end, and the four duplicate
-- pairs are split across it. That is what the table looks like, and reordering
-- it here would make this file disagree with a `select *` for no benefit.
create table if not exists public.business_profiles (
  id                    uuid                     not null default gen_random_uuid(),
  user_id               uuid,
  business_name         text,
  niche                 text,
  target_audience       text,
  website               text,
  revenue_goal          text,
  monthly_budget        text,
  brand_voice           text,
  automation_level      text                     default 'moderate'::text,
  created_at            timestamp with time zone default now(),
  updated_at            timestamp with time zone default now(),
  business_type         text,
  location              text,
  offer                 text,
  monthly_revenue       text,
  primary_goal          text,
  top_keywords          text,
  top_competitors       text,
  social_platforms      text,
  products_services     text,
  business_description  text,
  description           text,
  industry              text,
  goals                 text
);


-- ── Columns, guarded ───────────────────────────────────────────────────────
-- `create table if not exists` above is inert against the live database, so it
-- cannot add a column to a table that already exists. These repeat every column
-- as a guarded add, following 091, so that a replay against a database holding
-- an OLDER shape — one built from 014, for instance — converges on the live
-- shape rather than silently keeping the wrong one.
--
-- Deliberately NOT included: the five columns 014 declares that the live table
-- does not have. This file records what exists; adding brand_values,
-- business_goals, banned_topics, competitors or posting_frequency here would
-- make a replayed database diverge from production in the same direction 014
-- already did.

alter table public.business_profiles add column if not exists user_id              uuid;
alter table public.business_profiles add column if not exists business_name        text;
alter table public.business_profiles add column if not exists niche                text;
alter table public.business_profiles add column if not exists target_audience      text;
alter table public.business_profiles add column if not exists website              text;
alter table public.business_profiles add column if not exists revenue_goal         text;
alter table public.business_profiles add column if not exists monthly_budget       text;
alter table public.business_profiles add column if not exists brand_voice          text;
alter table public.business_profiles add column if not exists automation_level     text default 'moderate'::text;
alter table public.business_profiles add column if not exists created_at           timestamp with time zone default now();
alter table public.business_profiles add column if not exists updated_at           timestamp with time zone default now();
alter table public.business_profiles add column if not exists business_type        text;
alter table public.business_profiles add column if not exists location             text;
alter table public.business_profiles add column if not exists offer                text;
alter table public.business_profiles add column if not exists monthly_revenue      text;
alter table public.business_profiles add column if not exists primary_goal         text;
alter table public.business_profiles add column if not exists top_keywords         text;
alter table public.business_profiles add column if not exists top_competitors      text;
alter table public.business_profiles add column if not exists social_platforms     text;
alter table public.business_profiles add column if not exists products_services    text;
alter table public.business_profiles add column if not exists business_description text;
alter table public.business_profiles add column if not exists description          text;
alter table public.business_profiles add column if not exists industry             text;
alter table public.business_profiles add column if not exists goals                text;


-- ── Keys and constraints ───────────────────────────────────────────────────
-- Three constraints, and NO CHECK CONSTRAINTS OF ANY KIND — every value rule on
-- this table lives in the application. Guarded on conname rather than
-- DROP-then-ADD, following 071 and 091: these are live objects, and a drop
-- would briefly remove a live constraint to re-add it identically.
--
-- The PRIMARY KEY and UNIQUE clauses below create business_profiles_pkey and
-- business_profiles_user_id_unique — both unique btree indexes — implicitly.
-- They are NOT repeated in an index section, because a separate CREATE INDEX
-- under the same name would fail. Those two are the only indexes on the table:
-- 014's business_profiles_user_id_idx does not exist, and does not need to,
-- since the unique index already serves every lookup by user_id.

do $$ begin if not exists (select 1 from pg_constraint where conname = 'business_profiles_pkey' and conrelid = 'public.business_profiles'::regclass) then
  alter table public.business_profiles add constraint business_profiles_pkey PRIMARY KEY (id);
end if; end $$;

do $$ begin if not exists (select 1 from pg_constraint where conname = 'business_profiles_user_id_unique' and conrelid = 'public.business_profiles'::regclass) then
  alter table public.business_profiles add constraint business_profiles_user_id_unique UNIQUE (user_id);
end if; end $$;

do $$ begin if not exists (select 1 from pg_constraint where conname = 'business_profiles_user_id_fkey' and conrelid = 'public.business_profiles'::regclass) then
  alter table public.business_profiles add constraint business_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
end if; end $$;


-- ── Row level security: enabled, with no policies ──────────────────────────
-- Read from pg_class rather than assumed: relrowsecurity is true and
-- relforcerowsecurity is false, and pg_policy returns no rows. There are no
-- policies to transcribe. THE ABSENCE IS THE DESIGN, and it is the same posture
-- 083 records for its five tables, 091 for the inventory pair, 070 for
-- email_sends and 069 for contacts and consent_events.
--
-- 014 declares four auth.uid() policies — select, insert, update and delete.
-- NONE OF THEM EXISTS. That is the most dangerous of its five errors, because
-- it is the one that would have been believed: a reader checking whether this
-- table is protected would have found four policies in the migration directory
-- and stopped looking.
--
-- server.js connects with SUPABASE_SERVICE_KEY and the service role bypasses
-- RLS entirely, so every backend route behaves exactly as it would with RLS
-- off; enabling it costs the application nothing. What it buys is that the
-- anon key reads nothing here. Access control stays where it already is, in
-- the route handlers, scoped by req.user.id.
--
-- THE HAZARD, in the terms 083 states it: a denied table answers the anon key
-- with HTTP 200 and an EMPTY BODY, not 42501 permission denied. The anon role
-- HOLDS the table grant and RLS alone is what stops it, so a single narrow
-- policy added here is the only thing standing between the anon key and every
-- business profile on the platform — which is, by construction, the most
-- context-rich row about each user that this system holds.

alter table public.business_profiles enable row level security;


-- ── Comments ───────────────────────────────────────────────────────────────
-- THESE EIGHT ARE NEW, NOT TRANSCRIBED. Unlike 091, which pasted its comments
-- back verbatim from the live database, nothing on this table carried a comment
-- to read. Every line below was written from the investigation this file
-- records, so treat them as findings rather than as recovered documentation —
-- the same distinction 091 draws between what PostgREST could report and what
-- had to come from the catalogs.
comment on table public.business_profiles is
  'One row per user: the shared grounding context every agent and the Oracle read through buildAgentSystemPrompt before answering. Transcribed in 094 from the live database; 014 and 015 describe a different table and are wrong in both directions.';

comment on column public.business_profiles.user_id is
  'Nullable, with no foreign key. Ownership is enforced entirely by the route handlers, which filter on the id from the verified token and never from the request body. Nothing at the database level prevents an ownerless row.';

comment on column public.business_profiles.social_platforms is
  'TEXT, not jsonb. 014 declares jsonb NOT NULL DEFAULT ''{}'' and both write routes guarded it accordingly, replacing the string every client actually sends with an empty object. The live row holds "All Platforms".';

comment on column public.business_profiles.automation_level is
  'No reader anywhere in either repository. The only column on this table with a non-null default, so every row asserts a value nothing consults.';

comment on column public.business_profiles.revenue_goal is
  'No reader anywhere in either repository. Distinct from monthly_revenue, which the dashboard form does read; neither reaches a model.';

comment on column public.business_profiles.primary_goal is
  'The live half of the primary_goal/goals pair. formatBusinessProfile reads this first and falls back to goals; nothing has ever written goals. Both spellings are accepted by both write routes so the pair cannot drift.';

comment on column public.business_profiles.description is
  'The half of the business_description/description pair that reaches the model — formatBusinessProfile reads this one, while the dashboard form posts only business_description. The write-side alias between them is what keeps the prompt current.';

comment on column public.business_profiles.top_competitors is
  'Read into every agent prompt by formatBusinessProfile. It was read as `competitors` — a column that does not exist — until 8ea5de9, so every agent was told "Competitors: Not provided" while this column held the list.';
