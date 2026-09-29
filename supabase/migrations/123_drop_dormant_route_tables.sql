-- ============================================================================
-- 123_drop_dormant_route_tables.sql
--
-- WHY
--   Drops six tables whose only writers were routes deleted in af4d434
--   ("Delete twenty-one routes no page has ever called"):
--
--     follows           POST/DELETE /api/follow/:userId, GET /api/followers,
--                       GET /api/following
--     favorites         POST/DELETE /api/favorites/:businessId
--     posts             GET /api/feed, POST /api/posts, DELETE /api/posts/:id
--     deals             GET/POST/PUT/DELETE /api/deals (and a read in
--                       GET /api/dashboard, which af4d434 took off it)
--     websites          GET/POST/DELETE /api/websites
--     analytics_events  GET /api/analytics, POST /api/analytics/event
--
--   Every one of those routes is gone, no page ever called any of them, and
--   nothing else in the application reads or writes these tables. They are
--   dropped rather than kept because nothing can write them any more: an
--   empty table with no writer is not dormant data, it is schema describing a
--   feature that does not exist, and it invites the next reader to assume it
--   does. Five of the deleted routes had never worked against these tables at
--   all — follows has no created_at, posts has no media_url, post_type or
--   updated_at, and there is no foreign key between posts and profiles for the
--   feed's embed to use.
--
--   All six held ZERO ROWS when this was written (read live, 2026-09-29), and
--   the pre-flight below refuses to drop any of them that does not still hold
--   zero when it runs. There is no data to lose, and none is archived.
--
-- WHAT WAS CHECKED BEFORE WRITING THIS
--   - Row counts, live: 0 in all six.
--   - Code: no reference in server.js, lib/ or config/ outside the deleted
--     routes, except lib/backup.js's BACKUP_TABLES, which drops all six in the
--     same change as this file (see NOT DONE HERE).
--   - Foreign keys, from the live constraint export (2026-09-15) and every
--     migration since: NONE point AT these tables. The only foreign keys
--     involved point FROM them — analytics_events, favorites and websites each
--     reference users(id) — and those belong to the tables being dropped.
--   - Views, functions, triggers, policies: the migrations define none that
--     name these tables beyond their own indexes (081, 083, 085). The LIVE
--     catalogs could not be read from where this was written, and this
--     repository has recorded live objects that had no DDL here (121), so the
--     pre-flight below checks the live catalogs itself at apply time.
--
-- THE PRE-FLIGHT, AND WHY THE WHOLE FILE IS ONE TRANSACTION
--   Before any DROP, for each table that exists, it raises — aborting the
--   transaction, so NOTHING is dropped — if:
--     1. the table holds any row;
--     2. a foreign key on another table references it;
--     3. a view or materialised view depends on it;
--     4. a function outside the platform schemas names it in its body
--        (pg_depend does not track names inside plpgsql, so a trigger function
--        on another table that inserts into, say, deals would otherwise break
--        silently on its next run);
--     5. a row-level-security policy on ANOTHER table names it;
--     6. a pg_cron job's command names it (if pg_cron is installed).
--   Checks 4-6 match the table name as a whole word, so they can refuse on a
--   function or policy that merely mentions the word — "deals" in a comment,
--   say. That is deliberate: a false refusal costs a look, a false pass costs a
--   broken function discovered in production.
--
-- NO CASCADE, ON ANY OF THE SIX
--   Each DROP says RESTRICT (the default, written out so it is not mistaken for
--   an omission). A bare DROP that fails on a dependency the pre-flight missed
--   is the right outcome; CASCADE would silently take the dependent object with
--   it. What RESTRICT still removes, correctly, is what belongs to each table:
--   its own indexes, its own constraints (including its foreign keys to
--   users), its own triggers and its own RLS policies.
--
-- NOT DONE HERE
--   - lib/backup.js: all six were in BACKUP_TABLES. They are removed from that
--     list in the same change. The backup would not have stopped — its loop
--     records a missing table as ERROR and carries on — but it would have
--     reported six errors every night for tables that no longer exist.
--   - profiles.logo_url and profiles.banner_url, written only by the deleted
--     POST /api/profile/upload-logo and upload-banner, are NOT dropped:
--     messages.html reads logo_url for avatars. Both are null on every row.
--   - The plan config's maxWebsites field, read only by the deleted
--     enforceWebsiteLimit, is application code and is not touched by a
--     migration.
--   - notifications is NOT touched. It lost one writer (POST /api/follow) but
--     keeps others, and GET /api/notifications is being surfaced, not deleted.
--   - Comments in server.js that cite the deleted deal helpers as design
--     history are left as they are.
--
-- SAFETY
--   One transaction: the pre-flight raising aborts it, and nothing is dropped.
--   Every DROP is IF EXISTS, and the pre-flight skips a table that is already
--   gone, so running this file twice is a no-op the second time. Irreversible
--   only in the sense that the DDL would have to be recreated — from 000
--   (follows, posts), 081 (analytics_events), 083 (websites, favorites) and
--   085 (deals) — and with zero rows there is no data to restore.
-- ============================================================================

begin;

do $$
declare
  t      text;
  n      bigint;
  hits   text;
  word   text;
begin
  foreach t in array array['follows', 'favorites', 'posts', 'deals', 'websites', 'analytics_events'] loop
    if to_regclass('public.' || t) is null then
      raise notice '123: public.% does not exist; nothing to drop.', t;
      continue;
    end if;

    word := '\m' || t || '\M';

    -- 1. Still empty.
    execute format('select count(*) from public.%I', t) into n;
    if n > 0 then
      raise exception '123 refused: public.% holds % row(s). Nothing was dropped.', t, n;
    end if;

    -- 2. No other table's foreign key points at it.
    select string_agg(c.conrelid::regclass::text || ' (' || c.conname || ')', ', ')
      into hits
      from pg_constraint c
     where c.contype = 'f'
       and c.confrelid = ('public.' || t)::regclass
       and c.conrelid <> c.confrelid;
    if hits is not null then
      raise exception '123 refused: public.% is referenced by foreign key(s): %. Nothing was dropped.', t, hits;
    end if;

    -- 3. No view or materialised view depends on it.
    select string_agg(distinct v.oid::regclass::text, ', ')
      into hits
      from pg_depend d
      join pg_rewrite r on r.oid = d.objid and d.classid = 'pg_rewrite'::regclass
      join pg_class v on v.oid = r.ev_class
     where d.refobjid = ('public.' || t)::regclass
       and v.oid <> d.refobjid;
    if hits is not null then
      raise exception '123 refused: public.% is used by view(s): %. Nothing was dropped.', t, hits;
    end if;

    -- 4. No function outside the platform schemas names it.
    select string_agg(p.oid::regprocedure::text, ', ')
      into hits
      from pg_proc p
      join pg_namespace ns on ns.oid = p.pronamespace
     where ns.nspname not in ('pg_catalog', 'information_schema', 'auth', 'storage', 'realtime',
                              'graphql', 'graphql_public', 'extensions', 'pgsodium', 'pgsodium_masks',
                              'vault', 'net', 'supabase_functions', 'supabase_migrations', 'cron', 'pgbouncer')
       and p.prosrc ~* word;
    if hits is not null then
      raise exception '123 refused: public.% is named in function(s): %. Nothing was dropped.', t, hits;
    end if;

    -- 5. No policy on another table names it.
    select string_agg(pol.schemaname || '.' || pol.tablename || ' / ' || pol.policyname, ', ')
      into hits
      from pg_policies pol
     where not (pol.schemaname = 'public' and pol.tablename = t)
       and (coalesce(pol.qual, '') ~* word or coalesce(pol.with_check, '') ~* word);
    if hits is not null then
      raise exception '123 refused: public.% is named in policy/policies on other tables: %. Nothing was dropped.', t, hits;
    end if;

    -- 6. No pg_cron job names it.
    if to_regclass('cron.job') is not null then
      execute 'select string_agg(jobid::text || '' '' || coalesce(jobname, ''''), '', '') from cron.job where command ~* $1'
        into hits using word;
      if hits is not null then
        raise exception '123 refused: public.% is named in pg_cron job(s): %. Nothing was dropped.', t, hits;
      end if;
    end if;
  end loop;
end $$;

drop table if exists public.follows          restrict;
drop table if exists public.favorites        restrict;
drop table if exists public.posts            restrict;
drop table if exists public.deals            restrict;
drop table if exists public.websites         restrict;
drop table if exists public.analytics_events restrict;

commit;
