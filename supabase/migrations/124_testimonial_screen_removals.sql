-- ============================================================================
-- 124_testimonial_screen_removals.sql
--
-- WHAT THIS IS
--   A record of what screenFabricatedTestimonials (server.js) takes out of an
--   agent's result before the result is stored. processAiTask writes one row
--   per removed passage: the task, the account, the agent, which detection
--   pattern matched, and the passage itself.
--
-- WHY
--   The screen replaces each detected passage with a marked [TESTIMONIAL
--   NEEDED] slot and stores only the redacted text, so until now the original
--   was unrecoverable. In clean-run-3 it removed one passage from a social
--   content calendar that, from its position, looks like a theme label rather
--   than a testimonial, and there was no way to tell. A false positive could
--   not be reviewed, and the detector could not be tuned against evidence.
--
-- WHO READS IT: NOTHING IN THE PRODUCT
--   No route, page, prompt builder or job selects from this table. It exists
--   to be read by hand, in the SQL editor, to review the screen. The only
--   code that touches it is the insert in processAiTask, and
--   scripts/checkAgentBriefTruth.js asserts that stays true.
--   Row level security is enabled with NO policies, and anon and
--   authenticated are revoked outright, so neither the anon key nor a
--   signed-in user's token can read it through PostgREST. The service role
--   bypasses RLS, as it does everywhere; that is the server and a person with
--   database access.
--
-- WHAT IS IN IT
--   The passage is model output that was judged to be invented customer
--   words, not anything a user typed: a quotation the user supplied, in the
--   request or the business profile, is exempt from the screen and never
--   reaches this table. A false positive can still hold a line the user would
--   recognise (a theme label, a founder's line), which is the point of keeping
--   it. It goes when the account or the task goes (ON DELETE CASCADE on both).
--
-- APPLY BY HAND, once, in the SQL editor. Until it is applied, processAiTask's
-- insert fails, is logged, and the task is stored exactly as before.
-- ============================================================================

create table if not exists public.testimonial_screen_removals (
  id          bigserial   primary key,
  task_id     uuid        not null references public.ai_tasks(id) on delete cascade,
  user_id     uuid        not null references public.users(id) on delete cascade,
  agent_type  text,
  pattern     text        not null,
  passage     text        not null,
  created_at  timestamptz not null default now(),
  constraint testimonial_screen_removals_pattern_known
    check (pattern in ('quoted_first_person', 'attributed_claim', 'both'))
);

create index if not exists testimonial_screen_removals_task_idx
  on public.testimonial_screen_removals (task_id);

alter table public.testimonial_screen_removals enable row level security;

revoke all on public.testimonial_screen_removals from anon, authenticated;
