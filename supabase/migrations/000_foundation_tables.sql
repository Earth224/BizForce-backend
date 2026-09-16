-- ============================================================================
-- 000_foundation_tables.sql
--
-- THE TWENTY FOUNDATION TABLES, NUMBERED SO THEY EXIST BEFORE ANYTHING NEEDS
-- THEM.
--
-- WHY THIS FILE EXISTS
--   071_transcribe_foundation_tables.sql transcribed the twenty tables that
--   predate the migration series — users, profiles, ai_agents, ai_tasks,
--   subscriptions and fifteen more — from pg_catalog on the live project, and
--   its header says that with it the directory "replays from empty into a
--   working schema". That is true only if 071 runs FIRST. Numbered 071, it
--   runs after ten files that already depend on its tables:
--
--     040  UPDATE bf_profiles ... FROM profiles
--     041  FOREIGN KEY ... REFERENCES public.users(id) x2;
--          ALTER TABLE public.profile_videos / public.profile_music
--     043, 048, 050, 054  REFERENCES users(id) inside CREATE TABLE
--     052  CREATE UNIQUE INDEX ... ON public.ai_agents
--     061, 064, 066, 069  ADD CONSTRAINT ... FOREIGN KEY ... REFERENCES users
--
--   A fresh run in numeric order therefore halts at 040, with ERROR 42P01
--   relation "profiles" does not exist, and never reaches 071. Found on
--   2026-09-15 by walking 001-114 in order with a model of what each file
--   leaves behind (the checker is described in the commit that adds this
--   file).
--
--   Those ten files are not guarded and 071 is not renumbered. A guard on
--   each would be ten edits to applied migrations, each needing its own
--   equivalence argument, to work around one ordering fact; renumbering 071
--   would rewrite the history of a file that has run. This file instead
--   puts the same DDL at the front of the sequence, where 071's own header
--   says it needs to be.
--
-- WHAT THIS FILE IS
--   A FAITHFUL COPY, NOT A SUBSET. Every executable statement below is
--   071's executable body — lines 40 through 408 of that file on 2026-09-15
--   — reproduced without alteration: the search_path, both extensions, the
--   twenty CREATE TABLEs, the thirty-one guarded constraints, the sixteen
--   indexes, the twenty ENABLE ROW LEVEL SECURITY statements and the sixteen
--   guarded policies. Two files that half-agree are worse to reason about
--   than two that fully agree, so nothing was left behind in 071: after this
--   file, 071 finds every object it would create already present and does
--   nothing. scripts/checkFoundationFilesAgree.js asserts the two files
--   define the same tables with the same columns, and the same statements,
--   so they cannot drift apart unnoticed.
--
--   The policies reference auth.uid(). They are carried here for the same
--   reason 071 carried them — they exist on the live database — and with
--   the same caveat 071 records: they only create on a Supabase project,
--   where auth.uid() exists, and they never match at runtime because this
--   application connects with the service-role key. On a plain PostgreSQL
--   they would fail to create wherever they lived, so putting them here
--   changes nothing about where a rebuild can run.
--
-- IDEMPOTENT, AND A NO-OP ON THE LIVE DATABASE
--   Every CREATE in 071 was already guarded — create table if not exists,
--   create index if not exists, DO blocks testing pg_constraint and
--   pg_policy, create extension if not exists — so nothing had to be made
--   idempotent for this copy; none differed. On the database this directory
--   describes, every one of the twenty tables, thirty-one constraints,
--   sixteen indexes and sixteen policies already exists, RLS is already
--   enabled on all twenty, and both extensions are installed. Every
--   statement below therefore finds its object present and does nothing.
--   Running this file against the live database changes nothing, exactly
--   as 071 does; that is the same equivalence 090 and 098 now state for
--   their amendments, and it is what permits a new file to sit at the front
--   of a sequence that has already run.
--
-- WHERE CHANGES TO THESE TABLES GO
--   Not here and not in 071. Both files are transcriptions of one moment;
--   editing either makes them disagree with each other or with history. A
--   change to any of the twenty tables is its own migration, numbered next.
--
-- KNOWN DEFECTS
--   071's closing section lists seven defects in these tables that were
--   transcribed as-is rather than corrected. They are transcribed as-is here
--   too, for the same reason, and that list is not repeated: it lives in 071.
-- ============================================================================

set search_path = public;

-- pg_get_constraintdef emits unqualified references (REFERENCES users(id)).
-- The search_path above is what resolves them on replay.

-- usage_logs.id defaults to uuid_generate_v4(), which lives in uuid-ossp.
-- Every other table uses the built-in gen_random_uuid(). Without this
-- extension a fresh replay fails on usage_logs and nothing else.
create extension if not exists "uuid-ossp";
create extension if not exists pgcrypto;


-- ============================================================================
-- 1. TABLES
-- ============================================================================

create table if not exists public.ai_agents (
  id uuid default gen_random_uuid() not null,
  user_id uuid not null,
  type text not null,
  display_name text,
  description text,
  active boolean default true not null,
  settings jsonb default '{}'::jsonb not null,
  tasks_completed integer default 0 not null,
  estimated_roi numeric default 0 not null,
  created_at timestamp with time zone default now() not null,
  updated_at timestamp with time zone default now() not null
);

create table if not exists public.ai_reports (
  id uuid default gen_random_uuid() not null,
  user_id uuid,
  agent text,
  task_type text,
  prompt text,
  summary text,
  result text,
  unread boolean default true,
  created_at timestamp with time zone default now()
);

create table if not exists public.ai_tasks (
  id uuid default gen_random_uuid() not null,
  user_id uuid not null,
  agent_type text default 'general'::text not null,
  prompt text not null,
  result text,
  status text default 'processing'::text not null,
  created_at timestamp with time zone default now() not null,
  task_type text default 'general'::text,
  error text,
  completed_at timestamp with time zone,
  updated_at timestamp with time zone default now()
);

create table if not exists public.automation_queue (
  id uuid default gen_random_uuid() not null,
  user_id uuid,
  task_type text not null,
  payload jsonb,
  status text default 'pending'::text,
  requires_approval boolean default true,
  created_at timestamp with time zone default now(),
  executed_at timestamp with time zone
);

create table if not exists public.businesses (
  id uuid default gen_random_uuid() not null,
  business_name text,
  website text,
  products text,
  target_customer text,
  tone text,
  goals text,
  email text,
  plan text,
  created_at text,
  status text,
  total_revenue numeric default 0,
  total_leads numeric default 0,
  total_posts numeric default 0
);

create table if not exists public.chat_messages (
  id uuid default gen_random_uuid() not null,
  user_id uuid not null,
  role text not null,
  content text not null,
  created_at timestamp with time zone default now() not null
);

create table if not exists public.deals (
  id uuid default gen_random_uuid() not null,
  user_id uuid,
  title text not null,
  description text,
  deal_type text,
  created_at timestamp without time zone default now()
);

create table if not exists public.follows (
  follower_id uuid not null,
  following_id uuid not null
);

create table if not exists public.messages (
  id uuid default gen_random_uuid() not null,
  sender_id uuid,
  receiver_id uuid,
  content text not null,
  created_at timestamp without time zone default now()
);

create table if not exists public.posts (
  id uuid default gen_random_uuid() not null,
  user_id uuid,
  content text not null,
  created_at timestamp without time zone default now()
);

create table if not exists public.profile_music (
  id uuid default gen_random_uuid() not null,
  user_id uuid,
  title text not null,
  artist text,
  audio_url text not null,
  cover_url text,
  duration_secs integer,
  sort_order integer default 0,
  created_at timestamp with time zone default now()
);

create table if not exists public.profile_portfolio (
  id uuid default gen_random_uuid() not null,
  user_id uuid,
  title text not null,
  description text,
  image_url text,
  url text,
  category text,
  sort_order integer default 0,
  created_at timestamp with time zone default now()
);

create table if not exists public.profile_products (
  id uuid default gen_random_uuid() not null,
  user_id uuid,
  name text not null,
  price numeric(10,2),
  description text,
  image_url text,
  buy_link text,
  created_at timestamp with time zone default now(),
  listing_kind text default 'good'::text not null,
  category text,
  status text default 'active'::text not null,
  currency text default 'USD'::text not null,
  updated_at timestamp with time zone default now() not null
);

create table if not exists public.profile_videos (
  id uuid default gen_random_uuid() not null,
  user_id uuid,
  title text not null,
  description text,
  video_url text not null,
  video_type text default 'youtube'::text not null,
  thumbnail_url text,
  sort_order integer default 0,
  created_at timestamp with time zone default now()
);

create table if not exists public.profiles (
  id uuid default gen_random_uuid() not null,
  email text,
  business_name text,
  industry text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  user_id uuid,
  banner_url text,
  full_name text,
  username text,
  bio text,
  website text,
  location text,
  logo_url text,
  contact_email text,
  contact_phone text,
  social_links jsonb default '{}'::jsonb,
  products_services jsonb default '[]'::jsonb,
  photos jsonb default '[]'::jsonb,
  videos jsonb default '[]'::jsonb,
  testimonials jsonb default '[]'::jsonb,
  custom_brand_colors jsonb default '{}'::jsonb,
  subscription_plan text,
  subscription_status text,
  profile_visibility text default 'public'::text,
  seo_title text,
  seo_description text
);

create table if not exists public.revenue_events (
  id uuid default gen_random_uuid() not null,
  business_id uuid,
  staff_member text,
  amount numeric,
  created_at timestamp without time zone default now()
);

create table if not exists public.subscriptions (
  id uuid default gen_random_uuid() not null,
  user_id uuid,
  stripe_customer_id text,
  stripe_subscription_id text,
  plan text default 'starter'::text,
  status text default 'inactive'::text,
  current_period_start timestamp with time zone,
  current_period_end timestamp with time zone,
  cancel_at_period_end boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

create table if not exists public.tasks (
  id uuid default gen_random_uuid() not null,
  business_id uuid,
  staff_member text,
  task_type text,
  content text,
  created_at timestamp without time zone default now()
);

create table if not exists public.usage_logs (
  id uuid default uuid_generate_v4() not null,
  user_id uuid,
  agent text,
  prompt text,
  response text,
  created_at timestamp without time zone default now()
);

create table if not exists public.users (
  id uuid default gen_random_uuid() not null,
  email text not null,
  password_hash text not null,
  business_name text,
  industry text,
  bio text,
  avatar_url text,
  subscription_status text default 'free'::text,
  subscription_id text,
  created_at timestamp without time zone default now(),
  role text default 'user'::text,
  verification_status text default 'pending'::text,
  banned_at timestamp with time zone,
  email_verification_token text,
  signup_ip text,
  updated_at timestamp with time zone default now()
);


-- ============================================================================
-- 2. CONSTRAINTS
-- ============================================================================

do $$ begin if not exists (select 1 from pg_constraint where conname = 'ai_agents_pkey' and conrelid = 'public.ai_agents'::regclass) then alter table public.ai_agents add constraint ai_agents_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'ai_reports_pkey' and conrelid = 'public.ai_reports'::regclass) then alter table public.ai_reports add constraint ai_reports_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'ai_tasks_pkey' and conrelid = 'public.ai_tasks'::regclass) then alter table public.ai_tasks add constraint ai_tasks_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'automation_queue_pkey' and conrelid = 'public.automation_queue'::regclass) then alter table public.automation_queue add constraint automation_queue_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'businesses_pkey' and conrelid = 'public.businesses'::regclass) then alter table public.businesses add constraint businesses_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'chat_messages_pkey' and conrelid = 'public.chat_messages'::regclass) then alter table public.chat_messages add constraint chat_messages_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'deals_pkey' and conrelid = 'public.deals'::regclass) then alter table public.deals add constraint deals_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'follows_pkey' and conrelid = 'public.follows'::regclass) then alter table public.follows add constraint follows_pkey PRIMARY KEY (follower_id, following_id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'messages_pkey' and conrelid = 'public.messages'::regclass) then alter table public.messages add constraint messages_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'posts_pkey' and conrelid = 'public.posts'::regclass) then alter table public.posts add constraint posts_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profile_music_pkey' and conrelid = 'public.profile_music'::regclass) then alter table public.profile_music add constraint profile_music_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profile_portfolio_pkey' and conrelid = 'public.profile_portfolio'::regclass) then alter table public.profile_portfolio add constraint profile_portfolio_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profile_products_pkey' and conrelid = 'public.profile_products'::regclass) then alter table public.profile_products add constraint profile_products_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profile_videos_pkey' and conrelid = 'public.profile_videos'::regclass) then alter table public.profile_videos add constraint profile_videos_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profiles_pkey' and conrelid = 'public.profiles'::regclass) then alter table public.profiles add constraint profiles_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'revenue_events_pkey' and conrelid = 'public.revenue_events'::regclass) then alter table public.revenue_events add constraint revenue_events_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'subscriptions_pkey' and conrelid = 'public.subscriptions'::regclass) then alter table public.subscriptions add constraint subscriptions_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'tasks_pkey' and conrelid = 'public.tasks'::regclass) then alter table public.tasks add constraint tasks_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'usage_logs_pkey' and conrelid = 'public.usage_logs'::regclass) then alter table public.usage_logs add constraint usage_logs_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'users_pkey' and conrelid = 'public.users'::regclass) then alter table public.users add constraint users_pkey PRIMARY KEY (id); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'ai_agents_user_id_type_key' and conrelid = 'public.ai_agents'::regclass) then alter table public.ai_agents add constraint ai_agents_user_id_type_key UNIQUE (user_id, type); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'users_email_key' and conrelid = 'public.users'::regclass) then alter table public.users add constraint users_email_key UNIQUE (email); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'chat_messages_role_check' and conrelid = 'public.chat_messages'::regclass) then alter table public.chat_messages add constraint chat_messages_role_check CHECK ((role = ANY (ARRAY['user'::text, 'assistant'::text]))); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profile_videos_video_type_check' and conrelid = 'public.profile_videos'::regclass) then alter table public.profile_videos add constraint profile_videos_video_type_check CHECK ((video_type = ANY (ARRAY['youtube'::text, 'vimeo'::text, 'upload'::text]))); end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'ai_reports_user_id_fkey' and conrelid = 'public.ai_reports'::regclass) then alter table public.ai_reports add constraint ai_reports_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE; end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'automation_queue_user_id_fkey' and conrelid = 'public.automation_queue'::regclass) then alter table public.automation_queue add constraint automation_queue_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE; end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profile_music_user_id_fkey' and conrelid = 'public.profile_music'::regclass) then alter table public.profile_music add constraint profile_music_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE; end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profile_videos_user_id_fkey' and conrelid = 'public.profile_videos'::regclass) then alter table public.profile_videos add constraint profile_videos_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE; end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profiles_id_fkey' and conrelid = 'public.profiles'::regclass) then alter table public.profiles add constraint profiles_id_fkey FOREIGN KEY (id) REFERENCES users(id) ON DELETE CASCADE; end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'profiles_user_id_fkey' and conrelid = 'public.profiles'::regclass) then alter table public.profiles add constraint profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE; end if; end $$;
do $$ begin if not exists (select 1 from pg_constraint where conname = 'subscriptions_user_id_fkey' and conrelid = 'public.subscriptions'::regclass) then alter table public.subscriptions add constraint subscriptions_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE; end if; end $$;


-- ============================================================================
-- 3. INDEXES
-- ============================================================================

create index if not exists ai_agents_user_active_idx ON public.ai_agents USING btree (user_id, active);
create index if not exists ai_reports_created_at_idx ON public.ai_reports USING btree (created_at DESC);
create index if not exists ai_reports_user_id_idx ON public.ai_reports USING btree (user_id);
create index if not exists ai_tasks_agent_type_idx ON public.ai_tasks USING btree (agent_type);
create index if not exists ai_tasks_created_at_idx ON public.ai_tasks USING btree (created_at);
create index if not exists ai_tasks_status_idx ON public.ai_tasks USING btree (status);
create index if not exists ai_tasks_task_type_idx ON public.ai_tasks USING btree (task_type);
create index if not exists ai_tasks_user_id_idx ON public.ai_tasks USING btree (user_id);
create index if not exists idx_ai_tasks_status ON public.ai_tasks USING btree (status);
create index if not exists idx_ai_tasks_user_id ON public.ai_tasks USING btree (user_id);
create index if not exists idx_chat_messages_user ON public.chat_messages USING btree (user_id, created_at);
create unique index if not exists profiles_user_id_unique_idx ON public.profiles USING btree (user_id);
create unique index if not exists profiles_username_key ON public.profiles USING btree (username) WHERE (username IS NOT NULL);
create index if not exists subscriptions_stripe_customer_id_idx ON public.subscriptions USING btree (stripe_customer_id);
create index if not exists subscriptions_stripe_subscription_id_idx ON public.subscriptions USING btree (stripe_subscription_id);
create index if not exists subscriptions_user_id_idx ON public.subscriptions USING btree (user_id);


-- ============================================================================
-- 4. ROW LEVEL SECURITY
-- ============================================================================

alter table public.ai_agents enable row level security;
alter table public.ai_reports enable row level security;
alter table public.ai_tasks enable row level security;
alter table public.automation_queue enable row level security;
alter table public.businesses enable row level security;
alter table public.chat_messages enable row level security;
alter table public.deals enable row level security;
alter table public.follows enable row level security;
alter table public.messages enable row level security;
alter table public.posts enable row level security;
alter table public.profile_music enable row level security;
alter table public.profile_portfolio enable row level security;
alter table public.profile_products enable row level security;
alter table public.profile_videos enable row level security;
alter table public.profiles enable row level security;
alter table public.revenue_events enable row level security;
alter table public.subscriptions enable row level security;
alter table public.tasks enable row level security;
alter table public.usage_logs enable row level security;
alter table public.users enable row level security;


-- ============================================================================
-- 5. POLICIES
-- ============================================================================

do $$ begin if not exists (select 1 from pg_policy where polname = 'Users can create their own ai tasks' and polrelid = 'public.ai_tasks'::regclass) then create policy "Users can create their own ai tasks" on public.ai_tasks for insert to public with check ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users can delete their own tasks' and polrelid = 'public.ai_tasks'::regclass) then create policy "Users can delete their own tasks" on public.ai_tasks for delete to public using ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users can insert their own tasks' and polrelid = 'public.ai_tasks'::regclass) then create policy "Users can insert their own tasks" on public.ai_tasks for insert to public with check ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users can read their own tasks' and polrelid = 'public.ai_tasks'::regclass) then create policy "Users can read their own tasks" on public.ai_tasks for select to public using ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users can update their own ai tasks' and polrelid = 'public.ai_tasks'::regclass) then create policy "Users can update their own ai tasks" on public.ai_tasks for update to public using ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users can update their own tasks' and polrelid = 'public.ai_tasks'::regclass) then create policy "Users can update their own tasks" on public.ai_tasks for update to public using ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users can view their own ai tasks' and polrelid = 'public.ai_tasks'::regclass) then create policy "Users can view their own ai tasks" on public.ai_tasks for select to public using ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users manage own tasks' and polrelid = 'public.ai_tasks'::regclass) then create policy "Users manage own tasks" on public.ai_tasks for all to public using ((auth.uid() = user_id)) with check ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Public read music' and polrelid = 'public.profile_music'::regclass) then create policy "Public read music" on public.profile_music for select to public using (true); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users manage own music' and polrelid = 'public.profile_music'::regclass) then create policy "Users manage own music" on public.profile_music for all to public using ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Public read portfolio' and polrelid = 'public.profile_portfolio'::regclass) then create policy "Public read portfolio" on public.profile_portfolio for select to public using (true); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users manage own portfolio' and polrelid = 'public.profile_portfolio'::regclass) then create policy "Users manage own portfolio" on public.profile_portfolio for all to public using ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Public read products' and polrelid = 'public.profile_products'::regclass) then create policy "Public read products" on public.profile_products for select to public using (true); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users manage own products' and polrelid = 'public.profile_products'::regclass) then create policy "Users manage own products" on public.profile_products for all to public using ((auth.uid() = user_id)); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Public read videos' and polrelid = 'public.profile_videos'::regclass) then create policy "Public read videos" on public.profile_videos for select to public using (true); end if; end $$;
do $$ begin if not exists (select 1 from pg_policy where polname = 'Users manage own videos' and polrelid = 'public.profile_videos'::regclass) then create policy "Users manage own videos" on public.profile_videos for all to public using ((auth.uid() = user_id)); end if; end $$;

