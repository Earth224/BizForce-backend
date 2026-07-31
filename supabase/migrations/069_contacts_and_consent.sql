-- 069_contacts_and_consent.sql
-- Adds public.contacts and public.consent_events: one row per person who has
-- given us a way to reach them, and an append-only ledger of every time they
-- granted or revoked permission on a channel.
--
-- Purely additive. It creates two new tables, their constraints, their indexes
-- and one trigger, and touches nothing that already exists. lead_captures,
-- sms_subscribers and bsky_leads are left exactly as migrations 028, 023 and 068
-- record them — not altered, not renamed, not read from, not written to. Every
-- existing write path keeps working unchanged.
--
-- THIS IS A SPINE, NOT A SWITCH. Nothing in server.js writes these tables yet.
-- Backfilling them from lead_captures and sms_subscribers, and repointing the
-- capture routes onto them, are separate pieces of work that come after this
-- structure exists and can be checked. A migration that both creates a table and
-- migrates the data into it cannot be reviewed as either one.
--
-- Idempotent and safe to re-run, on the same terms as 066: table creation is
-- guarded, every constraint is dropped-if-exists before being added, every index
-- is guarded, the trigger is dropped before being created, ENABLE ROW LEVEL
-- SECURITY is a no-op when already on, and COMMENT ON simply overwrites.

-- ── contacts: one row per reachable person ──
CREATE TABLE IF NOT EXISTS public.contacts (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id    uuid,
  email       text,
  phone       text,
  name        text,
  source      text        NOT NULL DEFAULT 'direct',
  brand       text        NOT NULL DEFAULT 'bizforce',
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ── owner_id references public.users, and is deliberately nullable ──
-- public.users, NOT auth.users: this project has a documented history of keys
-- pointed at Supabase's empty auth.users, where every insert fails 23503 and
-- surfaces as an unexplained 500. Migration 041 exists solely to repoint four such
-- tables, and 061 wrote its SMS keys this way from the start. So does this.
--
-- ON DELETE SET NULL rather than CASCADE. A contact is a person who gave someone
-- permission to reach them; that permission, and the evidence of it, does not
-- stop existing because the operator closed their account. Cascading would delete
-- the consent ledger along with it — see the note on consent_events below.
ALTER TABLE public.contacts DROP CONSTRAINT IF EXISTS contacts_owner_id_fkey;
ALTER TABLE public.contacts ADD  CONSTRAINT contacts_owner_id_fkey
  FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE SET NULL;

-- ── A contact must be contactable ──
-- Not a tautology worth skipping. /api/capture already refuses a submission with
-- neither an email nor a phone, and this is the database-side mirror of that
-- rule: a row with neither is not a contact who can be reached, it is a name with
-- no channel, and it would sit in this table forever satisfying every other
-- constraint while being useless to every consumer of it.
ALTER TABLE public.contacts DROP CONSTRAINT IF EXISTS contacts_contactable_check;
ALTER TABLE public.contacts ADD  CONSTRAINT contacts_contactable_check
  CHECK (email IS NOT NULL OR phone IS NOT NULL);

-- ── phone is the same shape the other two tables already enforce ──
-- Character for character the pattern in sms_subscribers_phone_format_check (062)
-- and lead_captures_phone_format_check (063): eleven digits, leading 1, no plus,
-- no punctuation. That is not tidiness. Those two constraints exist because a
-- number stored as "917 325 2291" is a number no equality filter finds, and the
-- cost was a real opt-out that matched nobody — the carrier delivered a STOP, the
-- update applied to zero rows, and the drip engine kept sending. A third table
-- holding phone numbers in a different shape would reintroduce exactly that.
--
-- THIS IS NOW THE THIRD DATABASE-SIDE MIRROR OF canonicalPhone IN server.js.
-- If that helper is ever widened to accept country codes other than 1, ALL THREE
-- constraints must widen with it IN THE SAME COMMIT. Missing any one of them is
-- the same outage: the helper starts returning values the database refuses and
-- the insert fails with a constraint violation surfacing as a 500. Widening the
-- constraints first is the safe order; widening the helper first is the outage.
--
-- The `phone IS NULL` branch is deliberate and reachable: this column is nullable
-- and an email-only contact is valid, exactly as 063 records for lead_captures.
ALTER TABLE public.contacts DROP CONSTRAINT IF EXISTS contacts_phone_format_check;
ALTER TABLE public.contacts ADD  CONSTRAINT contacts_phone_format_check
  CHECK (phone IS NULL OR phone ~ '^1[0-9]{10}$');

-- ── email is checked loosely, on purpose ──
-- One character before an @, and a dot somewhere after it. That is all.
--
-- The looseness is the design, not a shortcut. A CHECK constraint that attempts
-- real RFC 5322 validation rejects addresses that are valid and deliverable —
-- plus-addressing, quoted local parts, new gTLDs, internationalised domains — and
-- every one of those rejections is a person who tried to give us their address
-- and was told it was wrong. A constraint here can only ever catch the obvious:
-- an empty string, a stray name with no @, a value from the wrong form field.
--
-- The real test of an email address is whether mail sent to it is delivered, and
-- that test cannot be run by Postgres. It belongs to whatever sends the mail —
-- which, as of this migration, does not exist in this repo at all: there is no
-- email dependency in package.json and no send call anywhere in the codebase.
ALTER TABLE public.contacts DROP CONSTRAINT IF EXISTS contacts_email_shape_check;
ALTER TABLE public.contacts ADD  CONSTRAINT contacts_email_shape_check
  CHECK (email IS NULL OR email ~ '^[^@]+@[^@]+\.[^@]+$');

-- ── Index on the owner column ──
CREATE INDEX IF NOT EXISTS contacts_owner_id_idx
  ON public.contacts (owner_id);

-- ── One contact per address per owner, and one per number per owner ──
-- Both partial on owner_id IS NOT NULL, which is what makes them safe to add
-- while CAPTURE_OWNER_ID is still a literal in server.js. See the column comment
-- on owner_id for why that matters.
--
-- lower() on both so "Person@Example.com" and "person@example.com" collide,
-- because they are one mailbox and two rows for them is two of everything
-- downstream. On phone the lower() is a no-op against a canonical all-digit
-- value and is kept for symmetry, so the two indexes read as one rule applied
-- twice rather than two rules that happen to differ.
CREATE UNIQUE INDEX IF NOT EXISTS contacts_owner_email_uniq
  ON public.contacts (owner_id, lower(email))
  WHERE email IS NOT NULL AND owner_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS contacts_owner_phone_uniq
  ON public.contacts (owner_id, lower(phone))
  WHERE phone IS NOT NULL AND owner_id IS NOT NULL;

-- ── consent_events: the ledger ──
CREATE TABLE IF NOT EXISTS public.consent_events (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_id   uuid        NOT NULL,
  channel      text        NOT NULL,
  action       text        NOT NULL,
  source       text,
  page_url     text,
  ip_address   text,
  user_agent   text,
  note         text,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- ── Every event belongs to a contact ──
-- ON DELETE CASCADE, with one consequence worth stating plainly rather than
-- discovering later: deleting a contact destroys their consent history along with
-- them. That is correct for an erasure request, where the point is that nothing
-- remains. It is also exactly what removes the evidence described in the table
-- comment below. Both are true at once, and the resolution is that contacts
-- should be deleted deliberately and rarely, not that this key should be
-- ON DELETE SET NULL — an orphaned consent event proves nothing about anybody.
ALTER TABLE public.consent_events DROP CONSTRAINT IF EXISTS consent_events_contact_id_fkey;
ALTER TABLE public.consent_events ADD  CONSTRAINT consent_events_contact_id_fkey
  FOREIGN KEY (contact_id) REFERENCES public.contacts(id) ON DELETE CASCADE;

-- ── channel and action are closed sets ──
-- Closed here, unlike lead_captures.status and bsky_leads.status, because these
-- two columns are read to decide whether a message may lawfully be sent. A typo
-- that stored 'SMS' or 'grant' would not be caught by any query — it would simply
-- fail to match, and the contact would be treated as having no consent on that
-- channel, or worse, as never having revoked it.
ALTER TABLE public.consent_events DROP CONSTRAINT IF EXISTS consent_events_channel_check;
ALTER TABLE public.consent_events ADD  CONSTRAINT consent_events_channel_check
  CHECK (channel IN ('email', 'sms'));

ALTER TABLE public.consent_events DROP CONSTRAINT IF EXISTS consent_events_action_check;
ALTER TABLE public.consent_events ADD  CONSTRAINT consent_events_action_check
  CHECK (action IN ('granted', 'revoked'));

-- ── The index the consent lookup needs ──
-- Ordered to serve exactly one question, which is the only question this table is
-- ever asked in a send path: for this contact and this channel, what is the most
-- recent action? contact_id and channel narrow it, occurred_at DESC puts the
-- answer first, and the query stops at one row.
CREATE INDEX IF NOT EXISTS consent_events_contact_channel_time_idx
  ON public.consent_events (contact_id, channel, occurred_at DESC);

-- ── updated_at maintenance ──
-- public.set_updated_at() is NOT redefined here. It was created by 066, which is
-- deliberately generic rather than named for its first table precisely so later
-- tables could attach to it instead of each growing a copy. This is the first
-- table to take 066 up on that, and there remains exactly one definition of the
-- function in this folder.
--
-- Dropped before creating: CREATE TRIGGER has no IF NOT EXISTS form, so the
-- drop-then-create pair is what keeps this file re-runnable, the same idiom 066
-- uses and the same one the constraints above use.
DROP TRIGGER IF EXISTS contacts_set_updated_at ON public.contacts;
CREATE TRIGGER contacts_set_updated_at
  BEFORE UPDATE ON public.contacts
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- No trigger on consent_events, and no updated_at column on it either. That is
-- not an omission to be corrected later — a row in that table records something
-- that happened at a moment in time, and a record of a past event does not get
-- edited. See the append-only note in its table comment.

-- ── Row level security: enabled on both, with no policies ──
-- Deny by default, and that is the intended end state rather than a stage on the
-- way to writing policies — the same posture 066 records for birth_records and
-- 059 through 063 record for the SMS tables.
--
-- What this does NOT affect: server.js connects with the service-role key, which
-- bypasses RLS entirely, so every backend read and write against these tables
-- behaves exactly as it would with RLS off. Enabling it costs the application
-- nothing.
--
-- What it does affect: with RLS on and zero policies, the anon key can read
-- nothing from either table. That matters more here than for most tables in this
-- schema. contacts holds a name, an email address and a phone number for people
-- who are not account holders, and consent_events holds the IP address, the page
-- and the user agent captured at the moment they consented — which is to say, it
-- holds the evidence and the personal data together.
--
-- Why deny-by-default rather than a policy set: a policy needs a column to scope
-- by, and owner_id is nullable here on purpose. Every row written while
-- CAPTURE_OWNER_ID is still a literal has no meaningful owner to compare
-- auth.uid() against, so any USING clause would either expose every unowned row
-- or hide them from the service role too. Ownership for those rows is not
-- expressible in SQL today; it is enforced in the route handlers, the same
-- posture 059 and 066 record. If a frontend Supabase client is ever introduced,
-- both tables need a deliberate policy design — and 068 is the cautionary case,
-- where a permissive `using (true)` policy sits on bsky_leads waiting to be
-- activated by exactly that change.
ALTER TABLE public.contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.consent_events ENABLE ROW LEVEL SECURITY;

-- ── Comments ──

COMMENT ON TABLE public.contacts IS
  'One row per person who has given someone a way to reach them. The spine a unified capture writes to, replacing nothing yet: lead_captures, sms_subscribers and bsky_leads all keep working unchanged, and backfilling from them is separate work that comes after this exists. A contact is a person with a channel, which is why the contactable check requires an email or a phone — bsky_leads by contrast holds social posts that were found rather than submitted, has no email, phone or name column, and must never be treated as a source of rows for this table: a public post is not consent to be contacted.';

COMMENT ON COLUMN public.contacts.owner_id IS
  'Which account this contact belongs to. NULLABLE ON PURPOSE, and the nullability is the point rather than a concession. server.js currently hardcodes CAPTURE_OWNER_ID as a literal UUID (one line, one value, near the /api/capture handler), so every contact captured from a public landing page is attributed to one account regardless of which brand or funnel produced it. That works while BizForceAI has one operator and breaks the moment there is a second customer using lead capture — at which point every capture still lands on the first operator''s account. This column is where that constant goes when it stops being a constant. Until then, rows may legitimately carry a null owner. Note that both unique indexes are PARTIAL on owner_id IS NOT NULL, so unowned rows do not collide with one another while the literal is still in place — a design that would otherwise let one operator''s capture block another''s the day multi-tenancy arrives.';

COMMENT ON COLUMN public.contacts.last_seen IS
  'Updated every time this contact is seen again — a repeat submission, a second funnel, a returning visitor. Distinct from updated_at, which the trigger moves on ANY column change including a name correction. first_seen and last_seen together answer how long someone has been in the system and whether they are still active; updated_at answers when the row was last edited. Conflating them loses both answers.';

COMMENT ON INDEX public.contacts_owner_email_uniq IS
  'One contact per email address per owner, case-insensitive. Partial on both columns being non-null: a null email is not a duplicate of another null email, and unowned rows are exempt while CAPTURE_OWNER_ID is a literal. Postgres treats nulls as distinct in a unique index anyway, so the WHERE clause is about the owner_id half — without it, every unowned contact would compete for one slot per address across all future tenants.';

COMMENT ON INDEX public.contacts_owner_phone_uniq IS
  'One contact per phone number per owner. The phone half of contacts_owner_email_uniq, on the same terms. lower() is a no-op against a canonical all-digit number and is kept so the two indexes read as one rule rather than two.';

COMMENT ON TABLE public.consent_events IS
  'APPEND-ONLY LEDGER of consent. One row per grant or revocation, per channel, per contact, never updated and never deleted except by cascade from the contact.

WHY A LEDGER AND NOT A FLAG: a boolean column records THAT someone consented. A ledger records that they consented at 14:32 on the 3rd from this IP address on this page, and revoked at 09:15 on the 20th. Under the TCPA only the second is evidence — a defendant who can produce a boolean has produced nothing, and statutory damages run $500 per message, trebled to $1,500 for a willful violation, per message and with no cap. The difference between the two designs is the difference between a defensible record and an expensive one.

CURRENT CONSENT IS DERIVED, NEVER STORED: the consent state for a contact on a channel is the action of the most recent row for that contact and channel, read at the moment it is needed. There is no cached flag anywhere, which means there is no second copy that can drift from the first.

That is what makes the existing bug structurally impossible here rather than merely fixed. Today POST /api/sms/inbound sets sms_subscribers.consent_status to opted_out when a STOP arrives, while lead_captures.sms_consent for the same person stays true forever — two tables holding the same fact, only one of them updated, and no foreign key or any other link between them to even notice the disagreement. Neither row is wrong on its own terms; there is simply no single answer to ask for. A derived read has one answer by construction.

APPEND-ONLY IS CURRENTLY A DISCIPLINE, NOT A GUARANTEE. Nothing in the database prevents an UPDATE or a DELETE against this table — that is enforced today only by the route handlers being written not to. A trigger raising an exception on UPDATE OR DELETE belongs in its own migration, once the write paths that populate this table exist and are settled; adding it now would constrain code that has not been written yet, and the first backfill would have to work around it.';

COMMENT ON COLUMN public.consent_events.occurred_at IS
  'When the consent action actually happened, which is not always when the row was written — a backfill from lead_captures.consent_timestamp or sms_subscribers.consent_timestamp must set this to the ORIGINAL timestamp, not to now(). created_at records when the row entered this table. Keeping them separate is what lets a backfilled history stay truthful about the past instead of collapsing every historical grant onto the date of the migration.';

COMMENT ON COLUMN public.consent_events.ip_address IS
  'The address the consent action came from, captured because it is evidence rather than telemetry. lead_captures already records this as consent_ip for captures that came through /api/capture; sms_subscribers records nothing of the kind, so a subscriber added through the authenticated routes has no provenance at all today. This column is where that gap closes.';

COMMENT ON COLUMN public.consent_events.page_url IS
  'The page the person was on when they acted. Together with ip_address and user_agent this is the answer to "what were they doing when they consented", which no existing table can answer for an SMS subscriber. Nullable because a revocation arriving by SMS STOP has no page — the absence is meaningful and should not be filled with a placeholder.';
