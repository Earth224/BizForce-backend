-- CHANGES the database. Adds preferred_language to user_preferences.
-- NULL is the meaningful default: the Oracle mirrors whatever language the
-- seeker writes in, and the surfaces that never see their words - the daily
-- invocation and the page insights - stay English. A set value makes every
-- surface speak it explicitly, which is the only way those two can ever
-- answer in anything else.
-- No CHECK constraint on purpose. The valid set is a JS constant validated in
-- the route, the same way mist_position is handled, because a language list
-- grows and a CHECK would need a migration every time it did.
-- This is NOT a UI language setting. The interface is English and relies on
-- browser translation; this controls what the model writes.
-- Already applied to the live database on 2026-09-07.

alter table public.user_preferences
  add column if not exists preferred_language text;

comment on column public.user_preferences.preferred_language is
  'BCP-47 tag for the language the Oracle and the agents WRITE IN. NULL is meaningful, not merely unset: it means mirror whatever language the seeker writes in, and leave English on the surfaces that never see their words. Deliberately no CHECK constraint - the valid set is a JS constant validated in the route, matching how mist_position is handled, because a language list grows and a CHECK would need a migration every time it did. Not a UI language setting: the interface is English and relies on browser translation.';
