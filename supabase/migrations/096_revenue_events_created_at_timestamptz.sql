-- CHANGES the database. Does not transcribe.
-- revenue_events.created_at was created as `timestamp without time zone`
-- by migration 071. now() returns timestamptz, so every insert converted
-- through the writing session's TimeZone and the stored value could not
-- say which zone it meant. Verified 0 rows before conversion, 2026-09-06.
-- Already applied to the live database on 2026-09-06.

alter table public.revenue_events
  alter column created_at type timestamptz
  using created_at at time zone 'UTC';

alter table public.revenue_events
  alter column created_at set default now();

alter table public.revenue_events
  alter column created_at set not null;
