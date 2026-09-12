-- CHANGES the database. CREATES two columns:
--   user_preferences.dashboard_card_order   text,  nullable
--   user_preferences.dashboard_card_custom  jsonb, nullable
--
-- WHY THIS EXISTS. dashboard.html draws 26 feature cards as static markup, in a
-- deliberate editorial order that suits nobody in particular. The user can now
-- choose between four orderings - the order the page is written in, their own
-- arrangement, alphabetical, or the product's ranking of what matters first -
-- and the choice belongs to the account rather than to one browser, the same
-- way agent_card_order does in migration 105.
--
-- TWO COLUMNS, NOT ONE, because they answer two different questions: which
-- ordering is in force, and what the arrangement is. Keeping the arrangement
-- when the user switches to alphabetical and back is the whole point - folding
-- it into a single column would mean rebuilding it every time they looked at
-- another ordering.
--
-- THE ARRANGEMENT IS A LIST OF SLUGS, NOT OF POSITIONS. Each card carries a
-- data-card slug in the page (frontend commit d522d6a), chosen to survive both
-- a retitling and a destination page being renamed. Positions would not: they
-- silently mean a different card the moment one is inserted.
--
-- NOT VALIDATED AGAINST THE 26 SLUGS THAT EXIST TODAY, deliberately. The API
-- checks the shape - lowercase slug characters, no duplicates, bounded length
-- and count - and nothing about which cards exist, so adding or renaming a card
-- in the page needs no server change. A slug the page no longer renders is
-- ignored at display time and a card missing from the array is appended in page
-- order, so the arrangement degrades rather than breaking.
--
-- Both nullable with no default: NULL means never chosen and never arranged,
-- which is a real state and the one every existing row is in. No CHECK
-- constraint on either, the same reasoning mist_position, preferred_language
-- and agent_card_order are written to - the valid set is a JS constant checked
-- in the route, so changing it is a code change rather than a migration.
--
-- Already applied to the live database on 2026-09-12, before this file was
-- written.

alter table public.user_preferences
  add column if not exists dashboard_card_order text,
  add column if not exists dashboard_card_custom jsonb;

comment on column public.user_preferences.dashboard_card_order is
  'Which ordering the user chose for the dashboard feature cards: default, custom, alphabetical or importance. NULL means never chosen, and the client falls back to default (the order the cards are written in the page). Validated in the API against a constant list, not by a CHECK, so adding an ordering does not need a migration.';

comment on column public.user_preferences.dashboard_card_custom is
  'The user''s own arrangement: a JSON array of dashboard card slugs (the data-card values in dashboard.html), in the order they want them. NULL means never arranged. A slug the page no longer renders is ignored at display time, and a card missing from the array is appended in page order, so adding or removing a card never loses the arrangement.';
