-- bsky_leads — a transcription, not a change.
--
-- This table ALREADY EXISTS IN PRODUCTION. It was created outside the migration
-- system and has never had DDL in this repo in any form, while four files read
-- and write it: leadRadar.js, mastodonRadar.js and youtubeRadar.js all upsert
-- into it, and server.js references it six times. Migration 027 mentions it by
-- name and builds sales_lead_pipeline around it, but does not create it.
--
-- What follows was read out of the live database, so that a fresh clone can
-- rebuild the table as it actually is. Every statement is guarded; running this
-- against the live database is a no-op.
--
-- It is the last Lead Radar table with no DDL to check a query against, which is
-- the same condition 060 recorded for the SMS tables — and the same condition
-- that let GET /api/sms/campaigns/:id/enrollments order by a column that did not
-- exist. bsky_leads is larger and more heavily queried than either table 060
-- covered, so it carried more of that risk for longer.
--
-- Four things this file deliberately does NOT do. All four would be changes to
-- live structure rather than a record of it, and each needs its own data check
-- first, so each belongs in its own migration:
--
-- 1. No CHECK on status or source. Both are application conventions, not rules
--    the database enforces. See the column comments below — this diverges from
--    lead_captures, which constrains both of its equivalents, and that
--    divergence is recorded here rather than closed here.
--
-- 2. No NOT NULL on created_at. It is nullable live, which diverges from every
--    other table in this schema. Tightening it starts by finding out whether any
--    row already holds null: an alter that sets not null fails outright if any
--    does.
--
-- 3. No foreign keys, because there is nothing to point at. The table has no
--    user_id and no owner column of any kind. See the table comment.
--
-- 4. No index on intent_score, even though GET /api/leads orders by it
--    descending across the whole table. Adding an index is safe and would not
--    fail, but it is still a change to live structure rather than a record of
--    it.
--
-- RLS is enabled AND ONE POLICY EXISTS: "authenticated can read leads", for
-- select, to authenticated, using (true). Transcribed below with the rest.
--
-- What that policy does today: nothing. server.js and the three radar modules
-- connect with the service-role key, which bypasses RLS entirely, so every read
-- and write the application performs is unaffected by it in either direction.
--
-- What it grants: unrestricted read of every row in this table, to any holder of
-- a Supabase-issued JWT, through PostgREST. `using (true)` has no predicate to
-- narrow it — not by owner, not by source, not by status. Every row, to every
-- authenticated caller.
--
-- Why that is not currently reachable: this project does not use Supabase auth.
-- It signs its own tokens with JWT_SECRET (jwt.sign in createToken, verified
-- against the same secret in requireAuth), and there is no Supabase client
-- anywhere in the frontend — not one file references it. So no token that
-- PostgREST would accept as `authenticated` exists to be held, and the grant sits
-- unexercised.
--
-- Why it still matters: it makes the multi-tenancy problem described in the
-- table comment concrete rather than theoretical. That comment says every row is
-- visible to every operator through GET /api/leads. This policy says the same
-- thing one layer lower, and it is already written — introducing a frontend
-- Supabase client, or migrating to Supabase auth, activates it without anyone
-- editing a policy or reviewing this decision. The grant would not be a new
-- choice at that point; it would be an old one taking effect.
--
-- Why it is transcribed rather than narrowed here: narrowing or dropping it is a
-- change to live behaviour, and this file is a transcription. It belongs in its
-- own migration, alongside the decision about what should replace it — which
-- cannot be answered until this table has an owner column to scope by, since
-- there is nothing in a row today that identifies whose lead it is.

create table if not exists public.bsky_leads (
  id                uuid        not null default gen_random_uuid(),
  created_at        timestamptz default now(),
  post_uri          text        not null,
  post_cid          text,
  author_did        text,
  author_handle     text,
  post_text         text,
  matched_keyword   text,
  lang              text,
  intent_score      integer,
  intent_reason     text,
  suggested_product text,
  status            text        default 'new'::text,
  source            text        not null default 'bluesky'::text,
  post_id           text,
  constraint bsky_leads_pkey primary key (id)
);

comment on table public.bsky_leads is
  'Transcribed from the live database, which is where this table was created. Predates having DDL in this repo. A shared, platform-wide DISCOVERY FEED of social posts — not a contact list. Every row is a public post that matched an intent keyword, and the table holds no email, no phone, no name and no owner: author_handle and author_did identify a social account, not a person who has given anyone contact details. Nothing here was submitted to us; it was found. IT HAS NO user_id, so every row is visible to every operator through GET /api/leads, which filters only on status. That is survivable while BizForceAI has one customer using Lead Radar and becomes a multi-tenancy problem the moment there is a second: two customers would see each other''s scored leads, and the scoring itself is done against one hardcoded account''s business profile. Partitioning this table by tenant is a prerequisite for selling Lead Radar to anyone else, not a later refinement.';

-- add constraint has no if-not-exists form, and the drop-then-recreate idiom
-- used elsewhere in this folder is wrong here for the reason 059 records:
-- dropping a unique constraint drops its backing index, so recreating it would
-- rebuild that index on a live table. That is not a no-op. Guarded on
-- pg_constraint instead.
--
-- This constraint is load bearing. All three radar modules upsert with
-- onConflict "post_uri" and ignoreDuplicates, so it is what stops the same post
-- being captured again on every polling cycle — leadRadar runs every five
-- minutes against the same keywords and would otherwise re-insert the same
-- results indefinitely.
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'bsky_leads_post_uri_key'
      and conrelid = 'public.bsky_leads'::regclass
  ) then
    alter table public.bsky_leads
      add constraint bsky_leads_post_uri_key unique (post_uri);
  end if;
end $$;

-- ── Indexes ─────────────────────────────────────────────────────────────────
--
-- Four exist live beyond none: the primary key's index, the unique constraint's
-- backing index, and the three below. bsky_leads_post_uri_key is NOT created
-- here as an index — it is the index Postgres builds for the unique constraint
-- above, so creating it separately would produce a second, duplicate index.

create index if not exists idx_bsky_leads_status
  on public.bsky_leads (status);

-- DESC is not decoration. Recorded exactly as live, and it matches how the table
-- is read: newest first.
create index if not exists idx_bsky_leads_created
  on public.bsky_leads (created_at desc);

create index if not exists bsky_leads_source_idx
  on public.bsky_leads (source);

-- Already idempotent: enabling row level security on a table that already has it
-- enabled succeeds and changes nothing, so no guard is needed around this.
alter table public.bsky_leads enable row level security;

-- create policy has no if-not-exists form, so this is guarded on pg_policy the
-- same way the unique constraint above is guarded on pg_constraint. Not
-- drop-then-create: dropping a policy on a live table leaves a window, however
-- brief, in which RLS is enabled with nothing permitting the read, and a
-- transcription must not be able to change behaviour even for an instant.
--
-- Recorded exactly as live, permissive and unqualified. See the header for what
-- this grants and why it is transcribed rather than narrowed.
do $$
begin
  if not exists (
    select 1
    from pg_policy
    where polname = 'authenticated can read leads'
      and polrelid = 'public.bsky_leads'::regclass
  ) then
    create policy "authenticated can read leads"
      on public.bsky_leads
      for select
      to authenticated
      using (true);
  end if;
end $$;

-- ── Column comments ─────────────────────────────────────────────────────────
--
-- Read off what the radar modules and server.js actually do with these columns,
-- not off their names.

comment on column public.bsky_leads.status is
  'Lead Radar''s internal scoring lifecycle, and only that. Set to new on capture by all three radar modules (via the column default — none of them writes it explicitly), then to scored by scoreNewLeads once the model has rated it. Those are the only two values written. DIVERGENCE FROM THE REST OF THIS SCHEMA, RECORDED RATHER THAN CLOSED: there is no CHECK constraint here, while lead_captures.status is constrained to (new, synced, enrolled) and sales_lead_pipeline.status to five values. Adding one would first need a count of the distinct values actually present. Note also that 027 chose to build a separate table rather than reuse this column for the sales pipeline, precisely because this lifecycle and that one are different things.';

comment on column public.bsky_leads.source is
  'Which network the post came from. leadRadar.js writes nothing and relies on the column default of bluesky; mastodonRadar.js writes mastodon; youtubeRadar.js writes youtube. DIVERGENCE, RECORDED RATHER THAN CLOSED: no CHECK constraint, while lead_captures.source is constrained to (bluesky, mastodon, youtube, direct, other) — a set this column''s three live values are a subset of. Constraining this one is a small change that needs a distinct-value count first.';

comment on column public.bsky_leads.created_at is
  'DIVERGENCE, RECORDED RATHER THAN CLOSED: nullable here, while every other table in this schema declares created_at NOT NULL DEFAULT now(). The default means nothing written by the current code paths can produce a null, so the nullability is latent rather than exercised — but idx_bsky_leads_created orders by this column and a null would sort unpredictably against the intent. Tightening it requires first counting rows that already hold null, because an alter setting not null fails outright if any do.';

comment on column public.bsky_leads.post_id is
  'The Mastodon status id, and NOT vestigial — it is written by mastodonRadar.js and read by sendMastodonReply in server.js, which passes it as in_reply_to_id when posting a reply. It is null for Bluesky and YouTube rows by design: Bluesky is addressed by post_uri and YouTube has no reply path here, so only the Mastodon capture populates it. It is also null on Mastodon rows captured before the column existed, which sendMastodonReply handles explicitly by refusing to send with reason missing_post_id rather than replying to the wrong thread. DO NOT DROP THIS COLUMN — dropping it silently disables every Mastodon reply.';

comment on column public.bsky_leads.post_uri is
  'The stable unique key every capture path upserts on, and the key sales_lead_pipeline.lead_post_uri joins back to. 027 chose it over this table''s id precisely so that table would carry no dependency on this one''s column types.';

comment on column public.bsky_leads.author_handle is
  'A social account handle, not a contact address. Together with author_did it is the only identifying information this table holds, and neither is a channel anyone consented to be contacted through — replies are public posts, not messages to a subscriber. This table must not be treated as a source of contacts for the SMS system or any future email system; consent for those lives in lead_captures and sms_subscribers, which record it explicitly.';
