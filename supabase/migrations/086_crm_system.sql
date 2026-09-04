-- The CRM System: crm_customers and crm_activities.
--
-- WHY THESE EXIST SEPARATELY FROM public.contacts, which already holds people.
--
-- contacts is the consent-ledger spine. Nothing user-facing writes it: four
-- internal paths do — findOrCreateUserContact on registration,
-- POST /api/contacts/capture, findOrCreateContactByPhone from /api/capture, and
-- recordSmsConsentEvent from the Twilio inbound handler. There is no read route,
-- no update route and no delete route for it anywhere, and that is not an
-- oversight. It is the table sendEmail and the SMS consent gate read to decide
-- whether a message may lawfully be sent.
--
-- Three properties of contacts make it the wrong place for a CRM record:
--
--   1. owner_id MEANS TWO DIFFERENT THINGS. On rows written by the capture and
--      SMS paths it is CAPTURE_OWNER_ID, a hardcoded literal standing for the
--      operator. On rows written by findOrCreateUserContact it is the account
--      holder's own id. Both meanings are live in the four rows currently in the
--      table. A per-user CRM list filtered on that column would show the
--      operator every landing-page capture and show everyone else almost
--      nothing. crm_customers.user_id has exactly one meaning: the account
--      holder, always.
--
--   2. ITS MERGE POLICY DELIBERATELY LEAVES ONE PERSON AS TWO ROWS. When a
--      capture arrives whose email matches one row and whose phone matches
--      another, findOrCreateContactByPhone attaches the consent event to the
--      PHONE row — because that row carries the SMS history that is the TCPA
--      evidence — and leaves the email row untouched. It does not merge, delete
--      or rewrite anything. Duplicates are the correct outcome there and would
--      be a defect in a CRM list.
--
--   3. DELETING A CONTACT CASCADES ITS CONSENT EVIDENCE. 069 records this
--      plainly: consent_events.contact_id is ON DELETE CASCADE, so removing a
--      contact destroys the proof that they granted or revoked permission. That
--      is right for an erasure request and catastrophic as an everyday
--      operation, which is why 069 concludes contacts "should be deleted
--      deliberately and rarely".
--
-- A CRM needs the opposite lifecycle. Records are created, edited and deleted
-- freely by the user who owns them, because that is what a book of business is.
-- Giving contacts that lifecycle would put a delete button in front of consent
-- evidence. Giving CRM records the contacts lifecycle would make them
-- uneditable. So they are two tables, and the optional contact_id below is the
-- only link between them — nullable, never required, and never written from a
-- request body, because linking a sales record to a consent record is a consent
-- decision rather than a form field.

create table if not exists public.crm_customers (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  company text,
  email text,
  phone text,
  status text not null default 'lead',
  source text,
  notes text,
  last_contacted_at timestamptz,
  contact_id uuid references public.contacts(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists crm_customers_user_status_idx
  on public.crm_customers (user_id, status);

create index if not exists crm_customers_user_created_idx
  on public.crm_customers (user_id, created_at desc);

create index if not exists crm_customers_contact_idx
  on public.crm_customers (contact_id)
  where contact_id is not null;

create table if not exists public.crm_activities (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.crm_customers(id) on delete cascade,
  activity_type text not null,
  note text,
  occurred_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create index if not exists crm_activities_customer_idx
  on public.crm_activities (customer_id, occurred_at desc);

alter table public.crm_customers enable row level security;
alter table public.crm_activities enable row level security;

comment on table public.crm_customers is 'User-owned CRM records. Distinct from public.contacts, which is the consent ledger spine written by internal paths and deliberately never merged. user_id here always means the account holder, unlike contacts.owner_id which means the operator on capture rows and the account holder on registration rows.';

comment on column public.crm_customers.contact_id is 'Optional link to a consent-ledger row. ON DELETE SET NULL: deleting a CRM record must never cascade into consent evidence.';

comment on column public.crm_customers.email is 'DISPLAY AND REFERENCE ONLY, NEVER A SEND TARGET. No format check and no normaliser is applied, so a user may store whatever their business actually uses. sendEmail requires a contact_id and reads consent_events; it cannot be called with a raw address. Do NOT add a feature that creates a contacts row from a CRM record to satisfy it — that manufactures consent evidence out of a sales note.';

comment on column public.crm_customers.phone is 'DISPLAY AND REFERENCE ONLY, NEVER A SEND TARGET. Deliberately unconstrained so a real business can store an international number, an extension, or a partial one — canonicalPhone would turn all three into null. The SMS path resolves consent through a contacts row keyed on a canonical number, so a value here can never reach it, and nothing should be built that makes it.';

comment on table public.crm_activities is 'Activities belong to a crm_customers row and are reachable only through it. Deliberately NO user_id: ownership is the parent''s, and a denormalised copy would be a second claim about who owns this with nothing keeping the two in agreement.';
