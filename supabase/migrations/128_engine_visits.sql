-- 128_engine_visits.sql
--
-- One row each time someone arrives at bizforceai.net from a Lead Radar reply.
--
-- Before this, a reply could link bizforceai.net but nothing recorded that
-- anyone arrived, so whether the engine drives traffic to the platform could not
-- be measured at all. POST /api/engine-visits writes here, from the landing page,
-- when the page was reached through a link carrying ?ref=lr-<10 hex>.
--
-- A VISIT IS NOT A CAPTURE. lead_captures holds a person who chose to give an
-- email or phone, with their consent. This holds only that somebody followed a
-- reply's link: which reply (ref), which page they landed on, and when. Nothing
-- about who they are.
--
-- WHAT IS DELIBERATELY NOT STORED: IP address, user agent, referrer, cookies,
-- any session or account id, the full URL. None is needed to answer "did the
-- engine send anyone, and from which reply", and each would make an anonymous
-- arrival identifiable. Without them visits cannot be de-duplicated per person;
-- a ref counts every arrival through that reply's link, including other people
-- reading the public thread, and anyone can post a well-formed ref, so this is
-- a measure of arrivals, not of unique people.
--
-- ref joins back to a lead by recomputing it: 'lr-' || the first 10 hex of
-- sha256('leadradar:' || outreach_sends.lead_post_uri) — outreachRefToken in
-- server.js.
--
-- To be applied by hand. Until it is, the route answers 503 and writes nothing.

begin;

create table if not exists public.engine_visits (
  id           bigserial   primary key,
  ref          text        not null check (ref ~ '^lr-[0-9a-f]{10}$'),
  landing_path text        not null check (char_length(landing_path) between 1 and 200 and landing_path ~ '^/[A-Za-z0-9/._-]*$'),
  arrived_on   date        not null default (now() at time zone 'utc')::date,
  created_at   timestamptz not null default now()
);

create index if not exists engine_visits_ref_idx on public.engine_visits (ref);
create index if not exists engine_visits_arrived_on_idx on public.engine_visits (arrived_on);

-- Written only by the server with the service role; read by nobody else.
alter table public.engine_visits enable row level security;
revoke all on public.engine_visits from anon, authenticated;
revoke all on sequence public.engine_visits_id_seq from anon, authenticated;

comment on table public.engine_visits is
  'Arrivals at bizforceai.net through a Lead Radar reply link (?ref=lr-...). ref, landing path, date and time only: no IP, user agent, referrer, cookie or account. Written by POST /api/engine-visits.';

commit;
