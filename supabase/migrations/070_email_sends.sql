-- 070_email_sends.sql
-- Adds public.email_sends: one row per email this system attempts to send, with
-- the outcome written back onto it.
--
-- Purely additive. It creates one new table, its constraints, its indexes and one
-- trigger, and touches nothing that already exists. contacts and consent_events
-- are left exactly as 069 created them; lead_captures, sms_subscribers and
-- bsky_leads are untouched. The only reference to an existing table is the
-- foreign key onto public.contacts.
--
-- IT PRECEDES THE THING IT RECORDS. As of this migration there is no email
-- capability in this repo at all — no dependency in package.json, no send call
-- anywhere in server.js, no provider configuration. This table exists so that
-- when a send path is written it has somewhere to write from the first line,
-- rather than being built first and instrumented afterwards. A send path that
-- ships without a ledger is one that cannot answer "did that person get it",
-- and adding the ledger later means the first weeks of sends are unaccounted
-- for permanently.
--
-- Idempotent and safe to re-run, on the same terms as 066 and 069: table
-- creation is guarded, every constraint is dropped-if-exists before being added,
-- every index is guarded, the trigger is dropped before being created, ENABLE
-- ROW LEVEL SECURITY is a no-op when already on, and COMMENT ON simply
-- overwrites.

-- ── email_sends: one row per attempt ──
CREATE TABLE IF NOT EXISTS public.email_sends (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id     uuid,
  to_email       text        NOT NULL,
  from_email     text        NOT NULL,
  subject        text        NOT NULL,
  template       text        NOT NULL,
  provider       text        NOT NULL DEFAULT 'resend',
  provider_id    text,
  status         text        NOT NULL DEFAULT 'queued',
  error_message  text,
  sent_at        timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- ── contact_id is nullable, and the delete rule differs from consent_events ──
-- ON DELETE SET NULL, deliberately, and the contrast with 069 is the point.
--
-- consent_events CASCADES: consent evidence about a person who has been deleted
-- proves nothing about anybody, and keeping it would mean holding records of
-- someone specifically because they asked to be forgotten. It should go with
-- them.
--
-- This table does NOT cascade. A send record is not evidence about a person, it
-- is an operational fact about this sending domain's own history: mail left
-- here, addressed there, and either landed or did not. That history has to
-- survive the contact for two reasons. Deliverability accounting is one — bounce
-- and complaint rates are computed over what was actually sent, and a ledger
-- that shrinks when contacts are deleted reports a rate that is quietly wrong.
-- Answering a complaint is the other: if someone says they were mailed without
-- consent, "we have no record" is the worst possible answer, and deleting the
-- contact must not produce it.
--
-- What SET NULL preserves and what it removes is the whole design. The row keeps
-- to_email, the subject, the template and the outcome. It loses the link to a
-- person. After an erasure request there is a record that mail went to an
-- address, and nothing joining that address to a name, a phone number, a source
-- or a consent history — the operational fact survives, the person does not.
ALTER TABLE public.email_sends DROP CONSTRAINT IF EXISTS email_sends_contact_id_fkey;
ALTER TABLE public.email_sends ADD  CONSTRAINT email_sends_contact_id_fkey
  FOREIGN KEY (contact_id) REFERENCES public.contacts(id) ON DELETE SET NULL;

-- ── status is a closed set, including two values nothing can write yet ──
-- queued, sent and failed are what a send path writes: the row is inserted
-- queued before the provider is called, then moved to sent or failed by whatever
-- the provider returns.
--
-- bounced and complained are NOT reachable today. They are set by a provider
-- webhook, and no such webhook exists — there is no route, no signature
-- verification, no handler. They are in the constraint anyway, on purpose: a
-- closed set that omits them means the webhook's first act is a migration to
-- widen a CHECK, written under whatever time pressure a deliverability problem
-- brings with it. Recording them now costs nothing and means the webhook has
-- somewhere to write on the day it is built.
--
-- The distinction between the two matters more than it looks. A bounce is a
-- delivery failure and is the sending domain's problem to fix. A complaint is a
-- person pressing "this is spam", which is a consent revocation arriving through
-- a side channel — and when the webhook is written, a complained event should
-- write a revoked row into consent_events, not merely update a status here.
ALTER TABLE public.email_sends DROP CONSTRAINT IF EXISTS email_sends_status_check;
ALTER TABLE public.email_sends ADD  CONSTRAINT email_sends_status_check
  CHECK (status IN ('queued', 'sent', 'failed', 'bounced', 'complained'));

-- ── to_email is the same shape contacts.email already enforces ──
-- Character for character contacts_email_shape_check from 069: one or more
-- non-@ characters, an @, one or more non-@ characters, a dot, one or more
-- non-@ characters.
--
-- THIS IS NOW THE FOURTH COPY OF THAT RULE. The four are:
--
--   1. contacts_email_shape_check              migration 069
--   2. this constraint                         migration 070
--   3. the regex in POST /api/contacts/capture server.js
--   4. the client-side check in chart.html     frontend repo
--
-- ALL FOUR MUST MOVE TOGETHER IF ANY ONE WIDENS. The failure modes are not
-- symmetrical, which is why this is worth stating rather than assuming. Widening
-- the database constraints first is harmless — the application simply keeps
-- refusing addresses the database would have taken. Widening the application
-- first is an outage: the route accepts an address, the insert violates the
-- constraint, and the person gets a 500 that names nothing. The safe order is
-- always constraints first, application second, and the same rule governs the
-- three phone-format copies recorded in 062, 063 and 069.
--
-- No `to_email IS NULL` branch, because the column is NOT NULL — unlike
-- contacts.email, which is nullable and whose constraint carries that branch.
-- There is no send without a recipient.
ALTER TABLE public.email_sends DROP CONSTRAINT IF EXISTS email_sends_to_email_shape_check;
ALTER TABLE public.email_sends ADD  CONSTRAINT email_sends_to_email_shape_check
  CHECK (to_email ~ '^[^@]+@[^@]+\.[^@]+$');

-- ── Index on the contact ──
CREATE INDEX IF NOT EXISTS email_sends_contact_id_idx
  ON public.email_sends (contact_id);

-- ── The index the operational queries need ──
-- Ordered for the two questions this table is actually asked: what is stuck in
-- queued, and what failed recently. status narrows it, created_at DESC puts the
-- newest first, and both questions stop after a page of rows.
CREATE INDEX IF NOT EXISTS email_sends_status_created_idx
  ON public.email_sends (status, created_at DESC);

-- ── The webhook lookup, partial ──
-- Partial on provider_id IS NOT NULL because that is the only shape the lookup
-- ever uses, and because the column is null for the entire window between the
-- row being inserted and the provider answering. Indexing those nulls would mean
-- carrying every queued and every failed row in an index that no query on it can
-- use — a failed send never receives a provider id at all.
CREATE INDEX IF NOT EXISTS email_sends_provider_id_idx
  ON public.email_sends (provider_id)
  WHERE provider_id IS NOT NULL;

-- ── updated_at maintenance ──
-- public.set_updated_at() is NOT redefined here. It was created by 066,
-- deliberately generic rather than named for its first table, and 069 was the
-- first to attach to it rather than growing a copy. This is the second. There
-- remains exactly one definition of the function in this folder.
--
-- It matters more on this table than on contacts. A row here is written once and
-- then updated at least once more — queued to sent, and possibly again to
-- bounced or complained days later — so updated_at is the answer to "when did we
-- last learn something about this send", which is a question that gets asked.
--
-- Dropped before creating: CREATE TRIGGER has no IF NOT EXISTS form, so the
-- drop-then-create pair is what keeps this file re-runnable.
DROP TRIGGER IF EXISTS email_sends_set_updated_at ON public.email_sends;
CREATE TRIGGER email_sends_set_updated_at
  BEFORE UPDATE ON public.email_sends
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ── Row level security: enabled, with no policies ──
-- Deny by default, the same posture 069 records for contacts and consent_events,
-- 066 for birth_records and 059 through 063 for the SMS tables.
--
-- What this does NOT affect: server.js connects with the service-role key, which
-- bypasses RLS entirely, so every backend read and write against this table
-- behaves exactly as it would with RLS off. Enabling it costs the application
-- nothing.
--
-- What it does affect: with RLS on and zero policies, the anon key can read
-- nothing here. This table holds an email address on every row, and alongside it
-- the subject line of what was sent — which is to say it holds both who was
-- contacted and what they were told, for people who are not account holders.
--
-- Why deny-by-default rather than a policy set: this table has no owner column
-- at all, not even a nullable one. Ownership is reachable only through
-- contact_id onto contacts.owner_id, and that link is deliberately severed by
-- ON DELETE SET NULL above — so a policy scoping by owner would silently stop
-- covering exactly the rows whose contact was deleted. There is no correct
-- USING clause for a table whose ownership link is designed to be broken.
-- Access control is the route handlers, the same posture 059, 066 and 069
-- record.
ALTER TABLE public.email_sends ENABLE ROW LEVEL SECURITY;

-- ── Comments ──

COMMENT ON TABLE public.email_sends IS
  'THE DELIVERABILITY LEDGER. One row per email this system attempts to send. The row is written BEFORE the provider is called, with status queued, and updated with the outcome afterwards — never written after the fact. That ordering is the whole design: a row inserted before the call exists even if the call throws, the process dies, or the provider times out, so a send that vanished leaves a queued row behind rather than no trace. A ledger written after a successful send can only ever record the sends that succeeded, which is the opposite of what a deliverability ledger is for.

bounced and complained are in the status constraint but are NOT reachable by any code today. They are written by a provider webhook that does not exist — no route, no signature verification, no handler. They are declared now so that building the webhook does not also require a migration to widen a CHECK under deliverability pressure. When that webhook is written, a complained event should also write a revoked row into consent_events: pressing "this is spam" is a consent revocation arriving through a side channel, and recording it only as a send status would leave the ledger in 069 saying the person still consents.

As of this migration nothing writes this table. There is no email dependency in package.json and no send call anywhere in server.js. The gate on chart.html already promises "unsubscribe any time" to everyone who submits an address, and that promise is currently unbacked by any sending or unsubscribing code — this table is the first piece of closing that gap, not the whole of it.';

COMMENT ON COLUMN public.email_sends.contact_id IS
  'Which contact this went to, when there still is one. NULLABLE and ON DELETE SET NULL rather than the CASCADE consent_events uses, and the difference is deliberate: consent evidence about a deleted person proves nothing and should go with them, while a send record is an operational fact about this sending domain''s own history that has to outlive the recipient. After an erasure request the row keeps to_email, the subject and the outcome, and loses the join to a name, a phone number, a source and a consent history. Deliverability rates stay computable and a complaint stays answerable; the person is still gone.';

COMMENT ON COLUMN public.email_sends.provider_id IS
  'The provider''s own message id — Resend''s, under the current default. THE ONLY JOIN KEY BACK TO THE PROVIDER''S RECORDS. A webhook delivering a bounce or a complaint arrives carrying this id and nothing else that identifies the send: not our uuid, which the provider never saw, and not reliably the recipient, since one address can have many sends in flight. Without this stored, an inbound event cannot be matched to anything and the only options are to guess by address and timestamp or to discard it. Null between the row being inserted and the provider answering, and null forever on a send that failed before reaching the provider — which is why the index on it is partial.';

COMMENT ON COLUMN public.email_sends.status IS
  'queued on insert, then sent or failed from the provider''s response, then possibly bounced or complained from a webhook. Note that sent means the provider ACCEPTED it, not that it was delivered — those are different facts and the gap between them is exactly what bounced exists to record. Treating sent as delivered is the mistake this column is shaped to prevent.';

COMMENT ON COLUMN public.email_sends.template IS
  'Which template produced this message, stored per send rather than inferred later. Without it a bounce rate cannot be attributed to anything actionable: knowing 4% of mail bounced is not useful, knowing 4% of one template''s mail bounced is. Recorded at send time because the template file will change and a row that names it keeps meaning what it meant.';

COMMENT ON COLUMN public.email_sends.sent_at IS
  'When the provider accepted the message, distinct from created_at (when the row was queued) and from updated_at (when anything last changed, including a bounce days later). Null while queued and null forever on a failure. The three timestamps answer three different questions and collapsing any two of them loses one.';
