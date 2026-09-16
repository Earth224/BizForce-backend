-- 119_lead_captures_transcription.sql
--
-- lead_captures — a transcription, not a change. 028 is wrong in both
-- directions.
--
-- ── WHAT WAS FOUND ────────────────────────────────────────────────────────
--
-- Read from pg_constraint and PostgREST's schema description on the live
-- database, 2026-09-15. The table holds 0 rows.
--
--   LIVE CONSTRAINTS:
--     lead_captures_pkey                 PRIMARY KEY (id)
--     lead_captures_contact_present      CHECK (email IS NOT NULL OR phone IS NOT NULL)
--     lead_captures_phone_format_check   CHECK (phone IS NULL OR phone ~ '^1[0-9]{10}$')
--
--   028 DECLARES THREE CHECKS THAT DO NOT EXIST:
--     lead_captures_source_check   CHECK (source IN ('bluesky','mastodon','youtube','direct','other'))
--     lead_captures_brand_check    CHECK (brand  IN ('mrearthrose','swordvitality','blacksuncircle','bizforce'))
--     lead_captures_status_check   CHECK (status IN ('new','synced','enrolled'))
--
--   028 DOES NOT DECLARE THE ONE CHECK THAT EXISTS:
--     lead_captures_contact_present  — 063 added phone_format_check by name
--     and is the only other file to touch the table; contact_present is in
--     neither.
--
--   TWO COLUMNS 028 DECLARES NOT NULL THAT ARE NULLABLE LIVE:
--     owner_id           028: uuid NOT NULL             live: uuid, nullable
--     consent_timestamp  028: timestamptz NOT NULL DEFAULT now()
--                                                       live: timestamptz, nullable, no default
--
-- Columns, types and the other defaults match. Same diagnosis as 094 gave
-- business_profiles and 116 gives agent_memory: a file that is a superset
-- in one place and a subset in another was written from intent, and the
-- table was built by hand from a different draft.
--
-- ── WHAT A REBUILD DOES WITHOUT THIS FILE ─────────────────────────────────
--
-- Nothing breaks, and that is stated plainly because it bounds this file's
-- importance. POST /api/capture writes source and brand from CAPTURE_SOURCES
-- and CAPTURE_BRANDS in server.js, which are the same five and four values
-- 028's checks list; writes status 'new'; always supplies owner_id
-- (CAPTURE_OWNER_ID) and consent_timestamp. So a rebuilt table with 028's
-- extra checks and NOT NULLs accepts everything the only writer produces.
-- The one thing a rebuild lacks is contact_present, and that is the one
-- constraint that guards something real: a capture with neither an email
-- nor a phone is a row nobody can act on, and only the live table refuses
-- it.
--
-- With 0 rows, no restore is at stake.
--
-- ── WHAT THIS FILE DOES, IN TWO KINDS ─────────────────────────────────────
--
-- ADDITIVE, and a no-op live: contact_present, guarded on its name.
--
-- REBUILD-ONLY RELAXATIONS, and a no-op live: dropping the three checks 028
-- declared, the two NOT NULLs, and the consent_timestamp default. Against
-- the live database none of these exists, every statement is guarded on
-- finding it, and each therefore does nothing there. They exist so a
-- rebuilt table that got 028's shape ends up with the live shape rather
-- than a stricter one. Whether the live table SHOULD have 028's source and
-- brand checks is a fair question — the lists exist in code and 084 argued
-- against keeping a second copy of a code-owned list in Postgres — but it is
-- a question for a change, and this file is a transcription.
--
-- ── SAFETY ────────────────────────────────────────────────────────────────
--
-- Every statement is guarded and re-runnable. No row is written, updated or
-- deleted. Nothing that exists on the live database is dropped or altered.
-- No existing file is renumbered — 118 was the highest before this.

-- ── The check that exists and 028 never declared ──────────────────────────
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'lead_captures_contact_present'
      and conrelid = 'public.lead_captures'::regclass
  ) then
    alter table public.lead_captures
      add constraint lead_captures_contact_present
      check (email is not null or phone is not null);
  end if;
end $$;

-- ── REBUILD-ONLY: the three checks 028 declared and live does not have ────
--
-- 028 wrote them inline on the column, so Postgres named them
-- <table>_<column>_check. DROP CONSTRAINT IF EXISTS is a no-op live.
ALTER TABLE public.lead_captures
  DROP CONSTRAINT IF EXISTS lead_captures_source_check,
  DROP CONSTRAINT IF EXISTS lead_captures_brand_check,
  DROP CONSTRAINT IF EXISTS lead_captures_status_check;

-- ── REBUILD-ONLY: the two NOT NULLs and the one default ───────────────────
do $$
declare
  col text;
begin
  foreach col in array array['owner_id', 'consent_timestamp'] loop
    if exists (
      select 1 from pg_attribute
      where attrelid = 'public.lead_captures'::regclass
        and attname = col and attnotnull and not attisdropped
    ) then
      execute format('alter table public.lead_captures alter column %I drop not null', col);
    end if;
  end loop;

  if exists (
    select 1 from pg_attrdef d
    join pg_attribute a on a.attrelid = d.adrelid and a.attnum = d.adnum
    where d.adrelid = 'public.lead_captures'::regclass
      and a.attname = 'consent_timestamp'
  ) then
    alter table public.lead_captures alter column consent_timestamp drop default;
  end if;
end $$;

COMMENT ON CONSTRAINT lead_captures_contact_present ON public.lead_captures IS
  'A capture must carry at least one way to reach the person. Existed live before any migration named it; transcribed in 119. Pairs with contacts_contactable_check in 069, which expresses the same rule on the contacts spine.';

COMMENT ON COLUMN public.lead_captures.consent_timestamp IS
  'When consent was recorded, as supplied by POST /api/capture. Nullable with NO default on the live table — migration 028 declared NOT NULL DEFAULT now(), which the live table never had, and 119 transcribes the live shape. A default here would stamp capture time onto a row whose consent time was never supplied, which is the wrong thing to claim about consent.';
