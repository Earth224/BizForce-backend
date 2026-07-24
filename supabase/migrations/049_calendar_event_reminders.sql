alter table public.calendar_events
  add column if not exists remind_at timestamptz;

alter table public.calendar_events
  add column if not exists reminder_minutes_before integer;

alter table public.calendar_events
  add column if not exists reminder_sent_at timestamptz;

create index if not exists calendar_events_remind_at_idx
  on public.calendar_events (remind_at)
  where remind_at is not null and reminder_sent_at is null;

comment on column public.calendar_events.remind_at is
  'Absolute UTC instant to fire a push reminder for this event. Computed by the client from the event day plus a chosen local time, so it survives regardless of which calendar the event was created in. Null means no reminder set.';

comment on column public.calendar_events.reminder_minutes_before is
  'How far before the event the user asked to be reminded, stored so the UI can show the original choice. Purely informational; remind_at is the source of truth for firing.';

comment on column public.calendar_events.reminder_sent_at is
  'Set to now() when the scheduler fires this reminder, so it is never sent twice. The partial index above only covers rows that still need sending.';
