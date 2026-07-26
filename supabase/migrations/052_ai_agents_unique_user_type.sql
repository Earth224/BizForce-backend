-- Prevents duplicate agent rows per user: one row per user per agent type.

create unique index if not exists ai_agents_user_type_key
  on public.ai_agents (user_id, type);
