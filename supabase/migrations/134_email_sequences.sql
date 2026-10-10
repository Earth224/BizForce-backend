-- 134_email_sequences.sql
-- APPLIED BY HAND on 2026-10-10 and verified live: both tables, all constraints, RLS on.
-- CREATES two new tables: public.email_sequences and
-- public.email_sequence_enrollments. A CREATE migration, not a transcription and
-- not an alteration: nothing that already exists is changed, and no row anywhere
-- is read or written.
--
-- WHAT THEY ARE FOR. The Email agent drafts a sequence (POST
-- /api/agents/email/sequence). That draft will be filed as an agent_proposals
-- row; approving it will create one email_sequences row and enroll the owner's
-- contacts whose latest email consent is "confirmed", one
-- email_sequence_enrollments row each. A scheduler will send each due step
-- through sendMarketingEmail, and a refusal for suppression or consent stops
-- that contact's enrollment. None of that code exists yet. This file only
-- prepares the tables, so the code that fills them has somewhere to write from
-- its first line — the order 070 followed for email_sends.
--
-- DELAYS ARE COUNTED FROM THE PREVIOUS EMAIL. The sequence route's instruction
-- to the model defines DELAY_DAYS as "whole number of days after the previous
-- email; use 0 for the first email", and each step in steps carries that number
-- as delay_days. So next_send_at is always the previous step's send time plus
-- the next step's delay_days, and for step 0 the moment of enrollment plus its
-- delay_days. It is never the sequence's start plus a cumulative day.
--
-- Run by hand in the Supabase SQL editor, in one transaction. Idempotent and
-- safe to re-run, on the same terms as 069 and 070: table creation is guarded,
-- every constraint is dropped-if-exists before being added, every index is
-- guarded, each trigger is dropped before being created, ENABLE ROW LEVEL
-- SECURITY is a no-op when already on, and COMMENT ON simply overwrites.
--
-- REQUIRES 066 (public.set_updated_at), 054 (agent_proposals) and 069 (contacts).

BEGIN;

-- ── email_sequences: one row per approved sequence ──
CREATE TABLE IF NOT EXISTS public.email_sequences (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id        uuid        NOT NULL,
  proposal_id     uuid,
  source_task_id  uuid,
  name            text        NOT NULL,
  brand           text,
  steps           jsonb       NOT NULL,
  status          text        NOT NULL DEFAULT 'active',
  approved_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

-- ── owner_id references public.users, as contacts.owner_id does ──
-- public.users, NOT auth.users, for the reason 069 records: keys pointed at
-- Supabase's empty auth.users fail every insert with 23503.
--
-- ON DELETE CASCADE, where contacts.owner_id is SET NULL, and the difference is
-- forced rather than chosen: this column is NOT NULL, so SET NULL is not
-- available. A sequence is the owner's own campaign, not evidence about a
-- third party, so it goes with the account — the rule agent_proposals.user_id
-- (054) and agent_schedules.user_id (102) follow.
ALTER TABLE public.email_sequences DROP CONSTRAINT IF EXISTS email_sequences_owner_id_fkey;
ALTER TABLE public.email_sequences ADD  CONSTRAINT email_sequences_owner_id_fkey
  FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE CASCADE;

-- ── proposal_id: the approval that created this sequence ──
-- ON DELETE SET NULL. Deleting a proposal row must not delete a running
-- sequence and every enrollment under it; the sequence loses its pointer to
-- where it came from and nothing else.
ALTER TABLE public.email_sequences DROP CONSTRAINT IF EXISTS email_sequences_proposal_id_fkey;
ALTER TABLE public.email_sequences ADD  CONSTRAINT email_sequences_proposal_id_fkey
  FOREIGN KEY (proposal_id) REFERENCES public.agent_proposals(id) ON DELETE SET NULL;

-- source_task_id has the type of ai_tasks.id (uuid) and deliberately NO
-- foreign key. It is provenance — which run drafted this — and an ai_tasks row
-- being cleaned up must neither delete a sequence nor be blocked by one.

-- ── status is a closed set ──
-- Closed because the scheduler reads it to decide whether to send, and a typo
-- that stored 'Active' would match nothing and silently stop a sequence.
ALTER TABLE public.email_sequences DROP CONSTRAINT IF EXISTS email_sequences_status_check;
ALTER TABLE public.email_sequences ADD  CONSTRAINT email_sequences_status_check
  CHECK (status IN ('active', 'paused', 'completed', 'cancelled'));

-- ── The index the owner's own views need ──
CREATE INDEX IF NOT EXISTS email_sequences_owner_status_idx
  ON public.email_sequences (owner_id, status);

-- ── email_sequence_enrollments: one row per contact per sequence ──
CREATE TABLE IF NOT EXISTS public.email_sequence_enrollments (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sequence_id   uuid        NOT NULL,
  contact_id    uuid        NOT NULL,
  next_step     integer     NOT NULL DEFAULT 0,
  next_send_at  timestamptz,
  status        text        NOT NULL DEFAULT 'active',
  stop_reason   text,
  last_sent_at  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- ── Both keys cascade ──
-- An enrollment means nothing without its sequence or its contact. Deleting a
-- contact (an erasure request) removes their enrollments with them, the same
-- rule consent_events follows in 069; what was actually sent survives in
-- email_sends, whose contact_id is SET NULL by 070.
ALTER TABLE public.email_sequence_enrollments DROP CONSTRAINT IF EXISTS email_sequence_enrollments_sequence_id_fkey;
ALTER TABLE public.email_sequence_enrollments ADD  CONSTRAINT email_sequence_enrollments_sequence_id_fkey
  FOREIGN KEY (sequence_id) REFERENCES public.email_sequences(id) ON DELETE CASCADE;

ALTER TABLE public.email_sequence_enrollments DROP CONSTRAINT IF EXISTS email_sequence_enrollments_contact_id_fkey;
ALTER TABLE public.email_sequence_enrollments ADD  CONSTRAINT email_sequence_enrollments_contact_id_fkey
  FOREIGN KEY (contact_id) REFERENCES public.contacts(id) ON DELETE CASCADE;

-- ── A contact is enrolled in a sequence at most once ──
-- So a repeated approval, or a retried enrollment pass, cannot send the same
-- person the same step twice: the second insert conflicts instead.
ALTER TABLE public.email_sequence_enrollments DROP CONSTRAINT IF EXISTS email_sequence_enrollments_sequence_contact_key;
ALTER TABLE public.email_sequence_enrollments ADD  CONSTRAINT email_sequence_enrollments_sequence_contact_key
  UNIQUE (sequence_id, contact_id);

ALTER TABLE public.email_sequence_enrollments DROP CONSTRAINT IF EXISTS email_sequence_enrollments_next_step_check;
ALTER TABLE public.email_sequence_enrollments ADD  CONSTRAINT email_sequence_enrollments_next_step_check
  CHECK (next_step >= 0);

ALTER TABLE public.email_sequence_enrollments DROP CONSTRAINT IF EXISTS email_sequence_enrollments_status_check;
ALTER TABLE public.email_sequence_enrollments ADD  CONSTRAINT email_sequence_enrollments_status_check
  CHECK (status IN ('active', 'completed', 'stopped'));

-- ── The index the scheduler needs ──
-- One question, asked every tick: which active enrollments are due now?
-- status narrows it, next_send_at orders it.
CREATE INDEX IF NOT EXISTS email_sequence_enrollments_status_next_send_idx
  ON public.email_sequence_enrollments (status, next_send_at);

-- ── updated_at maintenance ──
-- public.set_updated_at() is NOT redefined here; 066 owns it, and 067, 069 and
-- 070 attach to it the same way. Dropped before creating: CREATE TRIGGER has no
-- IF NOT EXISTS form.
DROP TRIGGER IF EXISTS email_sequences_set_updated_at ON public.email_sequences;
CREATE TRIGGER email_sequences_set_updated_at
  BEFORE UPDATE ON public.email_sequences
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS email_sequence_enrollments_set_updated_at ON public.email_sequence_enrollments;
CREATE TRIGGER email_sequence_enrollments_set_updated_at
  BEFORE UPDATE ON public.email_sequence_enrollments
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ── Row level security: enabled on both, with no policies ──
-- Deny by default, the posture 069 and 070 record. server.js uses the
-- service-role key, which bypasses RLS, so the application is unaffected; the
-- anon key can read nothing. Enrollments join a sequence's copy to the people
-- receiving it, who are not account holders. Access control is the route
-- handlers.
ALTER TABLE public.email_sequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_sequence_enrollments ENABLE ROW LEVEL SECURITY;

-- ── Comments ──

COMMENT ON TABLE public.email_sequences IS
  'One row per email sequence an owner approved. Created by the agent_proposals executor when an Email agent sequence proposal is approved; never by the model directly. Sends go only through sendMarketingEmail, one step at a time, per enrollment.';

COMMENT ON COLUMN public.email_sequences.id IS
  'Primary key. Generated by the database.';
COMMENT ON COLUMN public.email_sequences.owner_id IS
  'The account whose sequence this is, and whose contacts it may be sent to. Same type and target as contacts.owner_id (public.users.id), but NOT NULL and ON DELETE CASCADE. Written once by the approval executor, from the proposal''s user_id.';
COMMENT ON COLUMN public.email_sequences.proposal_id IS
  'The agent_proposals row whose approval created this sequence. Written once by the approval executor. Null for a sequence created any other way, or after that proposal was deleted (ON DELETE SET NULL).';
COMMENT ON COLUMN public.email_sequences.source_task_id IS
  'The ai_tasks row (same type as ai_tasks.id) whose run drafted the steps. Provenance only, with no foreign key. Written once by the approval executor from the proposal payload; null when unknown.';
COMMENT ON COLUMN public.email_sequences.name IS
  'What the owner calls this sequence, shown in lists. Written by the approval executor from the proposal.';
COMMENT ON COLUMN public.email_sequences.brand IS
  'Which brand this sequence speaks for. When set, it matches contacts.brand, and only contacts of that brand are enrolled. Null means no brand restriction. Written by the approval executor.';
COMMENT ON COLUMN public.email_sequences.steps IS
  'The approved steps, in order, as a JSON array in the shape POST /api/agents/email/sequence returns: each element has step (1-based), delay_days, cumulative_day, purpose, subject, body and subject_measurement. delay_days counts days AFTER THE PREVIOUS EMAIL (0 for the first), as the route''s instruction to the model defines it. Written once by the approval executor and not edited afterwards, so what was approved is what is sent.';
COMMENT ON COLUMN public.email_sequences.status IS
  'active: the scheduler sends due steps. paused: nothing is sent, enrollments keep their place. completed: every enrollment has finished or stopped. cancelled: the owner ended it; nothing more is sent. Written by the approval executor (active) and by the owner''s routes and the scheduler afterwards.';
COMMENT ON COLUMN public.email_sequences.approved_at IS
  'When the owner approved the proposal that created this sequence. Written once by the approval executor; null for a sequence created without an approval.';
COMMENT ON COLUMN public.email_sequences.created_at IS
  'When the row was written. Set by the database default.';
COMMENT ON COLUMN public.email_sequences.updated_at IS
  'Maintained by the email_sequences_set_updated_at trigger (public.set_updated_at(), migration 066). Callers do not set it.';

COMMENT ON TABLE public.email_sequence_enrollments IS
  'One row per contact enrolled in a sequence: where that person is in it and when their next email is due. Created by the approval executor for each of the owner''s contacts whose latest email consent is confirmed; advanced or stopped by the scheduler.';

COMMENT ON COLUMN public.email_sequence_enrollments.id IS
  'Primary key. Generated by the database.';
COMMENT ON COLUMN public.email_sequence_enrollments.sequence_id IS
  'The sequence this enrollment belongs to. ON DELETE CASCADE. Written once by the approval executor.';
COMMENT ON COLUMN public.email_sequence_enrollments.contact_id IS
  'The person being sent the sequence. ON DELETE CASCADE, so an erased contact leaves no enrollment behind. Written once by the approval executor.';
COMMENT ON COLUMN public.email_sequence_enrollments.next_step IS
  'The ZERO-BASED index into email_sequences.steps of the NEXT step to send — 0 before anything is sent, steps length once all have gone. Not the 1-based step number the steps carry. Written by the approval executor (0) and incremented by the scheduler after each send.';
COMMENT ON COLUMN public.email_sequence_enrollments.next_send_at IS
  'When the step at next_step becomes due. delay_days counts from the PREVIOUS email, so this is the previous step''s actual send time (last_sent_at) plus the next step''s delay_days, and for step 0 the enrollment time plus that step''s delay_days. Null when nothing more is due (completed or stopped). Written by the approval executor and by the scheduler after each send.';
COMMENT ON COLUMN public.email_sequence_enrollments.status IS
  'active: the scheduler sends the step at next_step once next_send_at has passed. completed: every step was sent. stopped: sending ended early, with stop_reason saying why. Written by the approval executor (active) and the scheduler.';
COMMENT ON COLUMN public.email_sequence_enrollments.stop_reason IS
  'Why sending stopped early, when status is stopped: for example the sendMarketingEmail refusal reason (suppressed, no_consent, not_confirmed) or the owner cancelling. Null otherwise. Written by the scheduler or the owner''s routes.';
COMMENT ON COLUMN public.email_sequence_enrollments.last_sent_at IS
  'When the most recent step for this contact was accepted by sendMarketingEmail. Null until the first send. Written by the scheduler; next_send_at is computed from it.';
COMMENT ON COLUMN public.email_sequence_enrollments.created_at IS
  'When the contact was enrolled. Set by the database default.';
COMMENT ON COLUMN public.email_sequence_enrollments.updated_at IS
  'Maintained by the email_sequence_enrollments_set_updated_at trigger (public.set_updated_at(), migration 066). Callers do not set it.';

COMMIT;
