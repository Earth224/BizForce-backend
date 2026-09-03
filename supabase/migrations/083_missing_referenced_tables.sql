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

alter table public.websites enable row level security;
alter table public.favorites enable row level security;
alter table public.admin_flags enable row level security;
alter table public.moderation_logs enable row level security;
alter table public.reddit_leads enable row level security;
