alter table public.calendar_events
  add column if not exists recur_calendar text not null default 'gregorian';

alter table public.calendar_events
  drop constraint if exists calendar_events_event_type_check;

alter table public.calendar_events
  add constraint calendar_events_event_type_check
  check (event_type in ('reminder','anniversary','birthday','vacation','work','personal','other'));

comment on column public.calendar_events.recur_calendar is
  'Which calendar system an annually-recurring event repeats in. Events are JDN-anchored so they land on the same real day across systems; recurrence is a separate axis and must follow the calendar the event was created in.';
