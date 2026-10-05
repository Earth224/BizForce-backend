-- 130_engine_visits_blog_ref.sql
--
-- engine_visits records arrivals from a second source: a published blog post
-- whose money link is a page on this platform (money_path on POST
-- /api/agents/seo/generate-post). publish_blog_post adds ?ref=bl-<10 hex> to
-- that link, and the landing page posts it to POST /api/engine-visits as it
-- already does an lr- ref.
--
-- Migration 128 pinned ref to '^lr-[0-9a-f]{10}$', so the table refuses a bl-
-- ref with 23514 however the route validates it. This widens the constraint to
-- exactly the two shapes the route accepts (ENGINE_VISIT_REF in server.js):
--
--   lr-<10 hex>  a Lead Radar reply. Joins to outreach_sends by recomputing
--                'lr-' || left(encode(sha256(convert_to('leadradar:' || lead_post_uri, 'UTF8')), 'hex'), 10)
--   bl-<10 hex>  a blog post. Joins to content_library by recomputing
--                'bl-' || left(encode(sha256(convert_to('blog:' || user_id || ':' || slug, 'UTF8')), 'hex'), 10)
--                — blogRefToken in server.js. (user_id, slug) is the per-author
--                unique key, so one ref names one post.
--
-- Nothing else about the table changes: the same columns, the same path rule,
-- still no IP, user agent, referrer, cookie or account. Every lr- value 128
-- accepted, this accepts.
--
-- 128 declared the check inline, so its name is whatever Postgres generated
-- (engine_visits_ref_check by convention). It is found by what it checks rather
-- than by that name, so this works whatever it was called, and the new one is
-- named explicitly.
--
-- Not applied by this commit. Apply by hand in the SQL editor, after 128. Until
-- it is, a bl- arrival is answered 503 naming this file and nothing is written;
-- lr- arrivals are unaffected.

begin;

do $$
declare
  c record;
begin
  for c in
    select conname
      from pg_constraint
     where conrelid = 'public.engine_visits'::regclass
       and contype = 'c'
       and pg_get_constraintdef(oid) like '%(ref ~%'
  loop
    execute format('alter table public.engine_visits drop constraint %I', c.conname);
  end loop;
end $$;

alter table public.engine_visits
  add constraint engine_visits_ref_check check (ref ~ '^(lr|bl)-[0-9a-f]{10}$');

comment on table public.engine_visits is
  'Arrivals at bizforceai.net through an engine link: a Lead Radar reply (?ref=lr-...) or a published blog post''s money link (?ref=bl-...). ref, landing path, date and time only: no IP, user agent, referrer, cookie or account. Written by POST /api/engine-visits.';

commit;
