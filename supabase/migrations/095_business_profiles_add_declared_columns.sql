-- ============================================================================
-- 095_business_profiles_add_declared_columns.sql
--
-- brand_values, banned_topics and posting_frequency — an ADD, not a
-- transcription.
--
-- 094 is the transcription: it recorded the live business_profiles as it stood,
-- against a 014 that describes a different table. This file does the opposite
-- thing and must not be mistaken for more of the same. THESE THREE COLUMNS DID
-- NOT EXIST. They are created here, and the database changes.
--
-- ── WHY ADD RATHER THAN RECORD ─────────────────────────────────────────────
--   014_business_profiles.sql declares all three. Nothing ever created them.
--   That put them in the worst category a field can occupy: named in the
--   migration directory, absent from the table, and wired into the application
--   at both ends as though they were real.
--
--   The write side sent them. agents/content.html's profile editor posts all
--   three — two textareas and a four-option select — and the POST route carried
--   them in its payload. While the payload was an unconditional literal naming
--   five phantom columns, PostgREST rejected the whole request with PGRST204
--   and nothing saved at all. Once the phantoms were removed the save
--   succeeded, and these three were simply dropped: the user typed into a form
--   that reported "Saved!" and discarded the values without an error.
--
--   The read side expected them. Both of this table's editors read them back
--   and rendered blanks.
--
--   Adding the columns is the correct resolution rather than deleting the
--   fields, because the fields were not speculative — they have readers, and
--   those readers were written deliberately.
--
-- ── EIGHTEEN GUARDED READS THAT NEVER FIRED ────────────────────────────────
--   scripts/agent-profile.js builds the BUSINESS CONTEXT block for the task
--   form, and it is loaded by EIGHTEEN agent pages — every root <type>-agent
--   page plus the five under agents/. Two of its lines are:
--
--       if (p.brand_values)  lines.push("Brand Values: "    + p.brand_values);
--       if (p.banned_topics) lines.push("Topics to Avoid: " + p.banned_topics);
--
--   Both are guarded, so both have been silently inert for the life of the
--   file. No agent has ever seen either line. The guard is what made this
--   invisible: an absent column and an empty field produce the same output, and
--   the same output is "the line is not there".
--
--   BANNED_TOPICS IS THE ONE THAT MATTERS. It is a "topics to avoid"
--   instruction — the user telling every agent what not to say — and it has
--   never once reached a model. This platform's Sales Agent brain carries
--   explicit compliance rules about a vitality product: never claim a cure,
--   never compare to a named prescription drug, never say "guaranteed". Those
--   rules are hardcoded in the brain and they held. What did not reach the
--   model is the user's OWN list of things to avoid, which is the part only
--   they can know and the part no hardcoded rule can anticipate.
--
--   A field that silently discards a safety instruction is worse than a field
--   that does not exist, because the user believes the instruction was given.
--
--   posting_frequency has no reader anywhere. It is added with the other two
--   because it is the third column 014 declared and the third field that form
--   collects, and leaving one of three discarded would reproduce in miniature
--   exactly the inconsistency this file exists to end.
--
-- ── 094 IS NOW ONE COLUMN-SET BEHIND ───────────────────────────────────────
--   094 transcribed twenty-five columns. There are twenty-eight. That file is
--   not wrong — it was accurate when written, and it is deliberately left
--   alone rather than edited, because a transcription that gets quietly updated
--   stops being evidence of what was found.
--
--   READ 094 THEN 095, IN ORDER, FOR THE TRUE HISTORY. That is the same
--   relationship 091 and 093 have: 091 recorded the inventory schema including
--   a comment on counted_quantity that asserted an invariant which does not
--   hold, and 093 replaced the comment rather than rewriting 091. The earlier
--   file records what was there; the later one records what changed and why.
--   Editing the earlier one would destroy the only record that the mistake was
--   ever made.
--
-- ── WHAT THIS DOES NOT DO ──────────────────────────────────────────────────
--   business_goals and competitors — the other two names 014 declares — are
--   NOT added. They are not missing columns; they are wrong names for columns
--   that exist. primary_goal, goals and top_competitors already hold that data,
--   and both write routes alias the 014 spellings onto them. Creating them
--   would produce a third and fourth copy of two values this table already
--   stores twice, which is the problem 094 documents under FOUR DUPLICATE
--   PAIRS, not a fix for it.
--
--   No constraint, index or RLS change. The posture 094 records is unaltered:
--   RLS enabled, zero policies, three constraints, no CHECKs.
-- ============================================================================


-- ── The three columns ──────────────────────────────────────────────────────
-- All text, all nullable, no defaults — matching every other column on this
-- table except id, automation_level, created_at and updated_at. Guarded with
-- `if not exists` so a replay is a no-op, following 091 and 094.
--
-- posting_frequency is 100 characters in the application (safeText caps it) and
-- unbounded here, matching how every other text column on this table is
-- declared. The four values the select offers — Daily, 3x/week, Weekly,
-- Custom — are deliberately NOT a CHECK constraint: this table carries no CHECK
-- constraints at all, and "Custom" already means the vocabulary is open.

alter table public.business_profiles add column if not exists brand_values      text;
alter table public.business_profiles add column if not exists banned_topics     text;
alter table public.business_profiles add column if not exists posting_frequency text;


-- ── Comments ───────────────────────────────────────────────────────────────
-- TRANSCRIBED VERBATIM, as run against the live database. Unlike 094's eight,
-- which are marked as authored from an investigation, these three are the
-- text that is actually on the columns. The distinction is worth keeping:
-- a reader can trust these to match `\d+ business_profiles` and should treat
-- 094's as findings.

comment on column public.business_profiles.banned_topics is 'Topics or messaging the user wants avoided. Read by scripts/agent-profile.js into the BUSINESS CONTEXT block on all 18 agent pages — those reads are guarded and had never fired, because 014 declared this column and the live table never had it. A user could type it, see "Saved!", and no agent was ever told.';

comment on column public.business_profiles.brand_values is 'Core brand values. Same 18 readers and the same history as banned_topics: declared by 014, absent live, silently discarded on every save.';

comment on column public.business_profiles.posting_frequency is 'Content cadence, a four-option select on agents/content.html. No reader anywhere — added because the control exists and the alternative was deleting a field users can already fill in.';
