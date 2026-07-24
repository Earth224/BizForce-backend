create table if not exists public.push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  endpoint text not null,
  p256dh text not null,
  auth text not null,
  user_agent text,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  unique (user_id, endpoint)
);

create index if not exists push_subscriptions_user_id_idx
  on public.push_subscriptions (user_id);

comment on table public.push_subscriptions is
  'Web Push subscriptions, one row per user per device. endpoint plus the p256dh and auth keys are what the browser hands back from PushManager.subscribe and are required to encrypt a message to that device. A device may unsubscribe silently, so a 404 or 410 from the push service means the row should be deleted.';
