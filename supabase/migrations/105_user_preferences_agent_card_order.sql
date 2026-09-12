-- CHANGES the database. CREATES a column: user_preferences.agent_card_order,
-- text, nullable.
--
-- WHY THIS EXISTS. The agent cards can be ordered three ways - by importance,
-- alphabetically, or shuffled - and until now the choice lived only in the
-- browser, in localStorage under bf_agent_order. That made it a per-browser
-- setting wearing the clothes of a per-account one: the same person signing in
-- on a phone got the default back, and the settings page had to say so in its
-- own note. This column is the durable record. localStorage stays, as the
-- mirror agents-hub.html and ai-agents.html read synchronously before paint,
-- because making either grid wait on a fetch would draw the cards in one order
-- and then resort them.
--
-- NULL MEANS NEVER CHOSEN, and it is a real value rather than a missing one.
-- Everyone who picked an ordering before this column existed has it in their
-- browser and nothing on their account, and null is how that state is said. The
-- API writes null when the setting is cleared, and the client reads null as
-- leave the local choice alone rather than as reset to importance. Nullable
-- with no default, so the column says nothing about rows that predate it.
--
-- No CHECK constraint on purpose, the same way mist_position and
-- preferred_language are handled: the valid set is a JS constant validated in
-- the route - AGENT_CARD_ORDERS in server.js, mirroring ORDERINGS in the
-- frontend's scripts/bf-agent-order.js - so adding a fourth ordering is a code
-- change rather than a migration.
--
-- Already applied to the live database on 2026-09-12, before this file was
-- written.

alter table public.user_preferences
  add column if not exists agent_card_order text;

comment on column public.user_preferences.agent_card_order is
  'Which ordering the user chose for the agent cards: importance, alphabetical or random. NULL means never chosen, and the client falls back to its own default (importance). Validated in the API against the client''s ORDERINGS list, not by a CHECK, so adding an ordering does not need a migration.';
