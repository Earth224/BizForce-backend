-- 120_business_profiles_social_platforms_text.sql
--
-- business_profiles — make a rebuild land where live is, without editing 014.
--
-- ── WHAT WAS FOUND ────────────────────────────────────────────────────────
--
-- 094 already records that 014 and 015 describe a table that was never built,
-- and transcribes the live shape with `create table if not exists`. That is
-- exactly right against the live database and exactly wrong on a fresh one:
-- 014 runs first, so 014's table is the one that exists when 094 arrives,
-- and 094's create is the no-op. What a fresh run produces, against what is
-- live (PostgREST schema description and pg_constraint, 2026-09-15):
--
--   column / constraint          fresh run (014+015+094)        live
--   social_platforms             jsonb NOT NULL DEFAULT '{}'    text, nullable, no default
--   user_id                      NOT NULL                       nullable
--   created_at, updated_at       NOT NULL                       nullable
--   business_goals, competitors  exist (014)                    absent
--   UNIQUE (user_id)             two: business_profiles_user_id_key (014, implicit)
--                                     business_profiles_user_id_unique (094)
--                                                               one: business_profiles_user_id_unique
--
-- Everything else — the ten columns 094 adds, the primary key, the foreign
-- key to users with ON DELETE CASCADE — lands correctly.
--
-- ── THE ONE THAT BREAKS ───────────────────────────────────────────────────
--
-- social_platforms. server.js writes it as text in both places that write it:
--
--   server.js:12705   setField("social_platforms", 500, "social_platforms")
--   server.js:34883   updates.social_platforms = safeText(req.body.social_platforms, 500) || null
--
-- and the one live row holds the string  All Platforms  — not JSON. On a
-- rebuilt table that column is jsonb NOT NULL, so that write is refused as
-- invalid JSON, and the `|| null` branch is refused by NOT NULL. Every
-- business-profile save fails, and the row every agent prompt is built from
-- cannot be restored. The other divergences are harmless: every writer
-- supplies user_id, the timestamps have defaults, the two phantom columns are
-- nullable and 094 already re-pointed their readers, and a second UNIQUE on
-- the same column is redundant rather than wrong.
--
-- ── WHY THIS IS A NEW FILE AND NOT AN EDIT TO 014 ─────────────────────────
--
-- 014 could be corrected to say `text`, and that would be the smaller diff.
-- It is not done because the rule for this work is that 001-114 are not
-- edited: a migration that has run is a record of what ran, and rewriting
-- it makes the directory disagree with every database it was ever applied
-- to. So the correction is a later file that only acts where 014's shape is
-- actually present. Same construction as 117's id conversion.
--
-- ── THE GUARD, WHICH MAKES THIS IMPOSSIBLE TO FIRE AGAINST LIVE ───────────
--
-- Three conditions, all read before anything is done:
--
--   1. The column's current type must be jsonb. Live is text, so live is
--      excluded by type alone — the ALTER is never issued there. A column
--      that is neither text nor jsonb is left alone with a notice.
--   2. The table must hold zero rows. A rebuild has written nothing yet;
--      live has one row. A jsonb column WITH rows is neither state, and
--      rather than cast somebody's JSON to text on a guess, the block
--      refuses with a notice.
--   3. Only then: drop the default (which is '{}'::jsonb and would be wrong
--      for text), change the type, drop NOT NULL.
--
-- The remaining relaxations — the three NOT NULLs and the duplicate UNIQUE —
-- are each guarded on finding the thing they relax, and each is a no-op
-- live. All of them are REBUILD-ONLY in the sense 116, 117 and 119 use: they
-- never drop or alter anything that exists on the live database.
--
-- ── WHAT IS DELIBERATELY NOT DONE ─────────────────────────────────────────
--
-- business_goals and competitors are NOT dropped from a rebuild and NOT
-- added live. Nullable, unread since 094 moved the readers, and dropping a
-- column is not something this batch does even against a rebuild. Recorded;
-- a rebuilt table is a superset of live by these two columns.
--
-- ── SAFETY ────────────────────────────────────────────────────────────────
--
-- Every statement is guarded and re-runnable. No row is written, updated or
-- deleted. Nothing that exists on the live database is dropped or altered:
-- the type change sits behind a guard the live table cannot satisfy, and
-- every other statement checks for 014's shape before acting. No existing
-- file is renumbered — 119 was the highest before this.

-- ── REBUILD-ONLY: social_platforms jsonb → text, on an empty table only ───
do $$
declare
  current_type text;
  row_count    bigint;
begin
  select format_type(a.atttypid, a.atttypmod)
    into current_type
  from pg_attribute a
  where a.attrelid = 'public.business_profiles'::regclass
    and a.attname = 'social_platforms'
    and not a.attisdropped;

  if current_type = 'text' then
    -- Live, or an already-corrected rebuild. Nothing to do.
    return;
  end if;

  if current_type is distinct from 'jsonb' then
    raise notice '120: business_profiles.social_platforms is % — neither text nor jsonb; left untouched', current_type;
    return;
  end if;

  select count(*) into row_count from public.business_profiles;
  if row_count > 0 then
    raise notice '120: business_profiles.social_platforms is jsonb and the table holds % row(s); refusing to change the type of a populated table', row_count;
    return;
  end if;

  alter table public.business_profiles
    alter column social_platforms drop default;
  alter table public.business_profiles
    alter column social_platforms type text using social_platforms::text;
  alter table public.business_profiles
    alter column social_platforms drop not null;
end $$;

-- ── REBUILD-ONLY: the three NOT NULLs 014 declared and live does not have ─
do $$
declare
  col text;
begin
  foreach col in array array['user_id', 'created_at', 'updated_at'] loop
    if exists (
      select 1 from pg_attribute
      where attrelid = 'public.business_profiles'::regclass
        and attname = col and attnotnull and not attisdropped
    ) then
      execute format('alter table public.business_profiles alter column %I drop not null', col);
    end if;
  end loop;
end $$;

-- ── REBUILD-ONLY: 014's implicit UNIQUE, which live does not have ─────────
--
-- 014 wrote `user_id uuid NOT NULL UNIQUE` inline, which Postgres names
-- business_profiles_user_id_key. Live has only 094's explicitly named
-- business_profiles_user_id_unique. The drop is guarded on the other one
-- existing, so uniqueness on user_id is never lost even for an instant.
do $$
begin
  if exists (
    select 1 from pg_constraint
    where conname = 'business_profiles_user_id_key'
      and conrelid = 'public.business_profiles'::regclass
  ) and exists (
    select 1 from pg_constraint
    where conname = 'business_profiles_user_id_unique'
      and conrelid = 'public.business_profiles'::regclass
  ) then
    alter table public.business_profiles
      drop constraint business_profiles_user_id_key;
  end if;
end $$;

COMMENT ON COLUMN public.business_profiles.social_platforms IS
  'Free text, nullable, no default — e.g. ''All Platforms''. Written by PUT /api/business-profile and the profile upsert via safeText(…, 500), never as JSON. Migration 014 declared this jsonb NOT NULL DEFAULT ''{}'', which the live table never was; 094 transcribed the live shape but cannot override 014 on a fresh database, and migration 120 converts a freshly-rebuilt jsonb column to text while the table is still empty.';
