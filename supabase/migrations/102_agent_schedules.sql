-- CHANGES the database. Per-agent run schedules - the "when" that makes the
-- autonomy toggle mean something.
-- A schedule is the WHEN; agent_autonomy is the MAY. Both must be true for a
-- scheduled run to happen, so a schedule cannot bypass the consent toggle.
-- day_of_month allows 1-31. THE RUNNER MUST CLAMP: when the month is shorter
-- than the stored day, run on the last day of that month. Someone who asks for
-- the 31st means month-end, and without the clamp a day 29, 30 or 31 schedule
-- would silently skip up to five months a year.
-- The weekly and monthly CHECKs spell out `is not null` rather than relying on
-- a BETWEEN alone. A CHECK only rejects FALSE, and `NULL between 0 and 6` is
-- NULL, so the shorter form passed a weekly schedule with no day named - a row
-- that would never fire and never say why. Caught on a replica before it shipped.
-- Already applied to the live database on 2026-09-10.

create table if not exists public.agent_schedules (
  id            uuid        primary key default gen_random_uuid(),
  user_id       uuid        not null references public.users(id) on delete cascade,
  agent_type    text        not null,
  task_type     text        not null,
  prompt        text        not null,
  cadence       text        not null,
  hour_utc      smallint    not null default 7,
  day_of_week   smallint,
  day_of_month  smallint,
  enabled       boolean     not null default true,
  last_run_on   date,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),

  constraint agent_schedules_cadence_known
    check (cadence in ('daily', 'weekly', 'monthly')),
  constraint agent_schedules_hour_in_day
    check (hour_utc between 0 and 23),
  constraint agent_schedules_weekly_names_a_day
    check (cadence <> 'weekly' or (day_of_week is not null and day_of_week between 0 and 6)),
  constraint agent_schedules_monthly_names_a_day
    check (cadence <> 'monthly' or (day_of_month is not null and day_of_month between 1 and 31)),
  constraint agent_schedules_prompt_not_blank
    check (length(btrim(prompt)) > 0)
);

create unique index if not exists agent_schedules_user_agent_key
  on public.agent_schedules (user_id, agent_type);

create index if not exists agent_schedules_due_idx
  on public.agent_schedules (cadence, hour_utc)
  where enabled;

alter table public.agent_schedules enable row level security;
