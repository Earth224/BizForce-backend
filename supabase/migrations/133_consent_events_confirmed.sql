-- 133_consent_events_confirmed.sql
--
-- consent_events.action gains 'confirmed'. Nothing else changes.
--
-- WHY. Marketing email moves to double opt-in. POST /api/contacts/capture
-- still records 'granted' on submission; the person then confirms through a
-- link sent to that address, and that confirmation is recorded as a new
-- append-only row with action 'confirmed'. sendMarketingEmail will require the
-- LATEST email event to be 'confirmed'. Migration 069 constrained action to
-- ('granted', 'revoked'), which refuses that row, so the constraint is widened
-- here and only here: both existing values are kept, no row is touched, and
-- the channel, foreign key, index and RLS from 069 are left as they are.
--
-- Run by hand in the Supabase SQL editor. Dropping and re-adding inside one
-- transaction means there is no moment without the constraint. Running it a
-- second time is harmless: the drop finds the widened constraint and the add
-- recreates it identically.

begin;

alter table public.consent_events drop constraint if exists consent_events_action_check;
alter table public.consent_events add constraint consent_events_action_check
  check (action in ('granted', 'revoked', 'confirmed'));

commit;
