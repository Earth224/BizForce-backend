-- job_runs and agent_autonomy — new objects, not a transcription and not a constraint.
--
-- This file is a third kind of migration, and it is worth naming the difference
-- because the three preceding groups are each something else.
--
-- 059 and 060 were TRANSCRIPTIONS. Both described tables that already existed in
-- production, hand-created outside the migration system, and both were expected
-- to run against the live database as complete no-ops. Nothing in either file
-- introduced anything; they recorded what was already there so a fresh clone
-- could rebuild it.
--
-- 061, 062 and 063 were CONSTRAINTS on existing structure. Every statement in
-- those files altered live tables, each could fail against existing rows, and so
-- each was preceded by a count against production data recorded in the header.
--
-- This file is neither. Both tables below are NEW. Neither exists in production,
-- neither exists in this repo, and no code reads or writes either one yet. There
-- is no live data to check against, because there is no live table — so the
-- data-count section that 061 through 063 all carry has nothing to report here,
-- and its absence is not an omission. The checks that DID matter for a file that
-- creates objects are recorded below instead: whether these objects already
-- exist under some other name, and whether the foreign key points where this
-- project has historically gotten it wrong.
--
-- What was checked before writing, and what was found:
--
--   Searched the entire migrations folder, case-insensitively, for last_run,
--   scheduler, job_run and cron. Total matches: 1.
--
--     049_calendar_event_reminders.sql:21 — the word "scheduler" inside a column
--     comment on calendar_event_reminders.sent_at, describing when the reminder
--     sweep fires. It is prose about a different table's send-once marker. It is
--     not a last-run marker, not a job registry, and not scoped to a job at all.
--
--   So: no table in this folder records when any scheduled job last ran. There is
--   nothing to transcribe and nothing this duplicates. That was verified here
--   rather than taken on report.
--
--   Also counted while there: the folder holds 58 .sql files numbered 001 through
--   063, with 016 through 020 absent. The highest number is 063; the file count
--   is 58. Noted because "the 63 existing migrations" is the numbering, not the
--   inventory, and the grep above covered all 58 files that exist.
--
--   Confirmed the foreign key target against 041, which exists specifically to
--   correct four tables — oracle_sync, oracle_messages, profile_videos and
--   profile_music — whose user_id keys were created pointing at Supabase's
--   auth.users. That table is empty in this project, so every insert against
--   those tables failed 23503 and surfaced as an unexplained 500. The key below
--   targets public.users(id), written that way from the start, the same as the
--   three keys in 061.
--
--   Confirmed AGENT_SYSTEM_PROMPTS at server.js:158 holds exactly 17 keys: seo,
--   sales, content, ads, reputation, analytics, email, community, influencer,
--   operations, executive, social, etsy, store, broker, publicist, rd. Counted
--   rather than assumed, because the decision not to constrain agent_type below
--   depends on that list living in JavaScript.


-- ── public.job_runs ─────────────────────────────────────────────────────────
--
-- WHY THIS EXISTS. The daily Store Agent proposal pass is registered at
-- server.js:16252 as setInterval(storeProposalTick, 86400000), preceded by a
-- setTimeout that fires it once five minutes after boot. An 86400000 ms interval
-- is "24 hours after this process started", not "once a day at a wall-clock
-- time", and the process is on Railway, where every deploy replaces it. The
-- timer resets with the process, so the pass runs at whatever time of day the
-- container last restarted, and the schedule drifts to follow deploys.
--
-- The two failure modes both matter and they point in opposite directions. Deploy
-- once mid-afternoon and the boot timer fires the pass five minutes later even
-- though it already ran that morning — so it runs twice, or more, once per
-- deploy. Deploy every twenty hours and the 24-hour interval never arrives
-- before the process is replaced, so the pass never fires from the interval at
-- all and only the boot-timer run ever happens. Which of these occurred on any
-- given day is currently unknowable: nothing writes a record of a run. The logs
-- say "[StoreProposals] Tick starting..." and Railway retains them for a window,
-- and that is the entire audit trail.
--
-- The in-process guard that exists does not help with this. storeProposalTick
-- checks a module-level storeProposalPassRunning boolean at server.js:16205 and
-- returns early if a previous run is still going. That variable lives in one
-- Node process's memory. It prevents a pass overlapping itself inside a single
-- container; it cannot prevent the new container from running a pass the old one
-- already ran, because the replacement starts with the boolean back at false and
-- no knowledge of anything before it. Cross-restart is exactly the case that is
-- unprotected, and it is the case that Railway deploys create.
--
-- This table is the durable half of that guard. It is deliberately minimal — a
-- claim marker and enough state to see failures — and it is not a job queue, not
-- a scheduler, and not a lock service.

create table if not exists public.job_runs (
  job_name    text not null,
  last_run_on date,
  started_at  timestamptz,
  finished_at timestamptz,
  last_error  text,
  constraint job_runs_pkey primary key (job_name)
);

comment on table public.job_runs is
  'One row per scheduled background job, keyed by job name. The claim pattern this table exists for: update public.job_runs set last_run_on = current_date, started_at = now(), last_error = null where job_name = $1 and last_run_on is distinct from current_date — then check the affected row count. One row affected means this process holds today''s claim and should proceed. Zero rows affected means another process already claimed today and this run must exit without doing any work. The conditional update is the claim; there is no separate select, because a select followed by an update is two statements and two processes can both pass the select. This is the same idiom the proposal decision routes already use to claim a proposal row — POST /api/proposals/:id/reject at server.js:3765 updates where id and user_id match AND status = ''pending'', then treats a null result as 409 Conflict rather than re-reading the row. Same shape, same reason: let the database decide who won. The codebase gets one pattern for claiming, not two.';

comment on column public.job_runs.job_name is
  'Identifier of the scheduled job, for example daily_store_proposals. Primary key, so there is exactly one row per job and the claim update targets it directly. Not a foreign key to anything — job names live in server.js, the same way agent_type does below.';

comment on column public.job_runs.last_run_on is
  'The calendar day this job last claimed. A date and not a timestamptz on purpose: the question the claim asks is "has this job already run today", not "how long ago did it run". A timestamptz would force the claim to compare against an interval, and an interval comparison drifts — a run at 23:50 followed by one at 00:10 is ten minutes apart and two different days, and it is the day that matters. Compared with is distinct from rather than <> so that the initial null claims correctly; null <> current_date is null, which is not true, and the first run of a new job would never claim.';

comment on column public.job_runs.started_at is
  'When the current or most recent run began. Set by the same conditional update that sets last_run_on, so it is written only by the process that won the claim.';

comment on column public.job_runs.finished_at is
  'When the most recent run completed. A row with started_at set and finished_at null means either a run currently in progress or a run that died partway — a crash, an OOM kill, or a Railway deploy replacing the container mid-pass. THOSE TWO STATES ARE INDISTINGUISHABLE from this table alone, and that is a deliberate limitation rather than an oversight: telling them apart requires a heartbeat the running job updates periodically, so that a stale heartbeat identifies a dead run. This table has no heartbeat. The consequence is bounded and acceptable for a daily job — a run that dies after claiming has already written last_run_on, so it holds the day and the job does not retry until tomorrow. That is the correct trade for a proposal pass, where a skipped day costs nothing and a double run spends Claude tokens and creates duplicate proposals. It would be the wrong trade for a job that must not be skipped, and such a job needs the heartbeat added before it uses this table.';

comment on column public.job_runs.last_error is
  'Message from the most recent failure, cleared by the claim update on each new run. Exists so that a job which has been failing silently for a week is visible in one query against this table, instead of requiring someone to notice absent output in a log retention window that may already have rolled over.';


-- ── public.agent_autonomy ───────────────────────────────────────────────────
--
-- WHY THIS EXISTS. Nothing anywhere records whether a user has enabled autonomous
-- mode — not per agent, not globally. There is no column, no table and no flag.
--
-- What the daily pass uses instead is billing status. runStoreProposalPass at
-- server.js:16146 opens by selecting user_id from subscriptions where status is
-- 'active', and every id it gets back is enrolled in the pass. That query is a
-- correct query about billing and the wrong question entirely for this purpose:
-- an active subscription means a card is being charged, not that the subscriber
-- asked an agent to act on their behalf. Every paying user is currently enrolled
-- in autonomous proposal generation whether they asked for it or not, and there
-- is no setting anywhere they could have used to ask.
--
-- This table is where that answer goes, so the pass can filter on consent rather
-- than on payment.
--
-- TWO THINGS BELOW ARE DELIBERATE AND BOTH ARE LOAD BEARING.
--
-- 1. THE ABSENCE OF A ROW MEANS DISABLED. There is no backfill in this file, no
--    default enrollment, and no seeding of rows for existing subscribers. The
--    enabled column defaults to false, so even an explicitly created row is off
--    until someone turns it on. This is not caution about migration safety — it
--    is the entire point of the table. The current arrangement enrolls people via
--    a billing-status proxy that is not consent; a migration that backfilled
--    enabled = true for active subscribers would reproduce exactly that mistake
--    and give it the appearance of a recorded preference, which is worse than
--    the honest proxy because it would then look like the users had chosen. A
--    user who has never seen this setting must not be enrolled by the fact that
--    the setting now exists. Read the absence of a row as "has not opted in",
--    which is true of every user on the day this migration runs.
--
--    The corollary for whoever wires this up: the pass must join or filter such
--    that a missing row excludes the user. An inner join on agent_autonomy with
--    enabled = true does that correctly. A left join with a coalesce defaulting
--    to true would silently restore the current behaviour and defeat the table.
--
-- 2. THERE IS NO CHECK CONSTRAINT ON agent_type. The 17 known agent keys live in
--    AGENT_SYSTEM_PROMPTS at server.js:158 — a JavaScript object literal the
--    database cannot see. A check constraint listing those 17 values here would
--    be a second copy of that list, in a different language, in a different file,
--    updated by a different action. The two would drift, and the drift would be
--    silent in the dangerous direction: adding an 18th agent to server.js is a
--    one-line change that ships fine, works in every manual route, and then
--    fails at insert the first time a user toggles autonomy for it, surfacing as
--    a constraint violation dressed up as a 500. The database would be enforcing
--    a list nobody remembered it had.
--
--    This is the opposite call from 062, and the difference is worth stating
--    since both involve a rule duplicated between server.js and the schema. There,
--    the constraint mirroring canonicalPhone was worth the duplication because
--    the format rule is stable, it is one regex, the header says in capitals that
--    the two must move in the same commit, and the cost of a bad row was concrete
--    and already paid — a subscriber who could not be unsubscribed. Here the list
--    is 17 values and expected to grow, the cost of a bad value is one useless
--    row in a settings table that no query would match, and no such thing as an
--    unreachable-consequence bug follows from it.
--
--    VALIDATION FOR agent_type BELONGS AT THE API BOUNDARY: the route that writes
--    this table must reject any agent_type not present as a key in
--    AGENT_SYSTEM_PROMPTS, checked against that object directly — Object
--    .prototype.hasOwnProperty.call(AGENT_SYSTEM_PROMPTS, agentType) — and return
--    400 rather than inserting. Checked against the object, not against a copied
--    array, so there is exactly one list of agents in this system and adding the
--    18th agent requires editing exactly one place.

create table if not exists public.agent_autonomy (
  id         uuid        not null default gen_random_uuid(),
  user_id    uuid        not null,
  agent_type text        not null,
  enabled    boolean     not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint agent_autonomy_pkey primary key (id),
  constraint agent_autonomy_user_id_fkey
    foreign key (user_id) references public.users (id) on delete cascade
);

comment on table public.agent_autonomy is
  'Per-user, per-agent opt-in to autonomous action. THE ABSENCE OF A ROW MEANS DISABLED, and enabled defaults to false so an existing row is off until set. There is no backfill and no default enrollment by design: the behaviour this replaces enrolled every user whose subscriptions row was active, which is billing status and not consent. Any query that drives autonomous work off this table must exclude users with no row — an inner join on enabled = true — not default a missing row to true. No check constraint on agent_type: the 17 keys live in AGENT_SYSTEM_PROMPTS in server.js and a list here would be a second copy that drifts. That validation belongs in the route that writes this table, checked against AGENT_SYSTEM_PROMPTS directly, returning 400 on an unknown agent_type.';

comment on column public.agent_autonomy.agent_type is
  'Matches a key in AGENT_SYSTEM_PROMPTS in server.js — 17 of them at the time of writing: seo, sales, content, ads, reputation, analytics, email, community, influencer, operations, executive, social, etsy, store, broker, publicist, rd. Not constrained by the database; see the table comment and the header for why, and for where that validation goes instead.';

comment on column public.agent_autonomy.enabled is
  'Whether this user has turned this agent loose. False by default, and a user with no row for an agent is equivalent to false. This is the only column any autonomy check should read, and it must be read as true-means-yes rather than not-false-means-yes.';

comment on column public.agent_autonomy.updated_at is
  'Defaults to now() on insert but is NOT maintained by a trigger — no trigger is created here, deliberately, since this folder has no update-timestamp trigger convention to follow. The route that toggles enabled must set updated_at = now() in the same update. Left unmaintained it will silently equal created_at forever, which reads as "never changed" and would be wrong.';

-- add constraint has no if-not-exists form, so the unique constraint is guarded on
-- pg_constraint the way 059 through 063 are. The create table above carries its
-- primary key and foreign key inline, which if not exists covers on a re-run;
-- this one is separate because a table that already exists from a partial
-- application would skip the create entirely and never reach an inline
-- definition. Guarded here it is added either way.
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'agent_autonomy_user_agent_key'
      and conrelid = 'public.agent_autonomy'::regclass
  ) then
    alter table public.agent_autonomy
      add constraint agent_autonomy_user_agent_key unique (user_id, agent_type);
  end if;
end $$;

comment on constraint agent_autonomy_user_agent_key on public.agent_autonomy is
  'One autonomy row per user per agent. This is what makes the toggle route an upsert on (user_id, agent_type) rather than a select-then-insert-or-update, and it is what stops two rows disagreeing about whether one agent is enabled for one user — a disagreement no query could resolve, since neither row would be more correct than the other.';

-- Partial: the query this serves is "which agents has this user turned on", so
-- disabled rows are never the subject of it. A row toggled back off leaves the
-- index rather than sitting in it as dead weight, and the index stays proportional
-- to the number of enabled agents rather than to the number of rows ever created.
create index if not exists agent_autonomy_user_id_enabled_idx
  on public.agent_autonomy (user_id)
  where enabled;


-- ── Deliberately NOT done here ──────────────────────────────────────────────
--
-- No row is inserted into job_runs for daily_store_proposals. The claim update
-- described in the table comment matches zero rows against an empty table, which
-- means the first-ever claim would find nothing to update and read as "already
-- claimed" — so the code that uses this must either seed its own row or, better,
-- use an insert ... on conflict (job_name) do update ... where job_runs
-- .last_run_on is distinct from current_date, which claims and creates in one
-- statement and stays correct on every run after. Seeding a row here instead
-- would hide that requirement from whoever writes the caller and leave the same
-- bug waiting for the second job to be added.
--
-- No RLS on either table. server.js connects with the service-role key, which
-- bypasses RLS entirely, and there is no Supabase client in the frontend, so the
-- same reasoning recorded in 059 applies: access control is the req.user.id
-- scoping in the route handlers. Note that this is a real decision for
-- agent_autonomy in a way it is not for job_runs — agent_autonomy is per-user
-- data, and the day a frontend Supabase client is introduced, this table needs a
-- policy before it is readable from it. job_runs holds no user data and never
-- should.
--
-- No changes to server.js. Nothing reads or writes either table yet. This file
-- creates the objects; wiring the daily pass to claim through job_runs, and to
-- filter users through agent_autonomy instead of subscriptions.status, is a
-- separate change against a schema that by then already exists.
