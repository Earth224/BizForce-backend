create table if not exists public.websites (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text,
  url text not null,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists websites_user_active_idx
  on public.websites (user_id, active);

create table if not exists public.favorites (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  business_id uuid not null,
  created_at timestamptz not null default now(),
  constraint favorites_user_business_uniq unique (user_id, business_id)
);

create table if not exists public.admin_flags (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  flagged_by uuid references public.users(id) on delete set null,
  reason text,
  status text not null default 'open',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists admin_flags_created_idx
  on public.admin_flags (created_at desc);

create table if not exists public.moderation_logs (
  id uuid primary key default gen_random_uuid(),
  admin_id uuid references public.users(id) on delete set null,
  target_user_id uuid references public.users(id) on delete set null,
  action text not null,
  reason text,
  created_at timestamptz not null default now()
);

create index if not exists moderation_logs_target_created_idx
  on public.moderation_logs (target_user_id, created_at desc);

create table if not exists public.reddit_leads (
  id uuid primary key default gen_random_uuid(),
  reddit_id text not null unique,
  title text,
  body text,
  author text,
  subreddit text,
  permalink text,
  reddit_created timestamptz,
  matched_keyword text,
  created_at timestamptz not null default now()
);

-- ── Row level security: enabled, with no policies ──
--
-- ZERO POLICIES IS DELIBERATE, NOT AN OMISSION. Nothing is missing below this
-- line; the absence is the design, and it is recorded here so nobody later
-- reads it as work that was forgotten.
--
-- server.js connects with SUPABASE_SERVICE_KEY, and the service role bypasses
-- RLS entirely, so every backend route against these five tables behaves
-- exactly as it would with RLS off. Enabling it costs the application nothing.
--
-- What it does affect: with RLS on and zero policies, the anon key can read
-- nothing here. That is the same posture 070 records for email_sends and 069
-- for contacts and consent_events. Access control for all five stays where it
-- already is — in the route handlers, scoped by req.user.id and requireAdmin.
--
-- Verified live rather than assumed, on 2026-09-03: users and contacts, both
-- configured exactly this way, returned ZERO rows to the anon key while the
-- service key read 11 and 4 real rows out of them.
--
-- THE HAZARD, stated because the evidence above is easy to misread: a denied
-- table answers the anon key with HTTP 200 and an EMPTY BODY, not 42501
-- permission denied. That distinction is the entire warning. A 42501 would
-- mean the anon role lacks the table grant; 200-and-empty means it HOLDS the
-- grant and RLS alone is what stops it. So a single narrow policy added to any
-- of these five is the only thing standing between the anon key and that
-- table's contents — there is no second barrier underneath it. Whoever writes
-- one is not loosening a restriction, they are removing the only one there is.
alter table public.websites enable row level security;
alter table public.favorites enable row level security;
alter table public.admin_flags enable row level security;
alter table public.moderation_logs enable row level security;
alter table public.reddit_leads enable row level security;
