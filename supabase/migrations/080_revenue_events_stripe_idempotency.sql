alter table public.revenue_events
  add column if not exists stripe_event_id text,
  add column if not exists user_id uuid,
  add column if not exists currency text,
  add column if not exists event_type text;

create unique index if not exists revenue_events_stripe_event_id_key
  on public.revenue_events (stripe_event_id)
  where stripe_event_id is not null;

comment on column public.revenue_events.amount is 'Amount in major units (dollars), never cents.';
comment on column public.revenue_events.stripe_event_id is 'Stripe event ID. Unique. The idempotency key for webhook redelivery.';
comment on column public.revenue_events.event_type is 'The Stripe event type this row came from.';
