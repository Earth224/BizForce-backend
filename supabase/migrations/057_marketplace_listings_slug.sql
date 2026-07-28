-- Adds a public slug to marketplace_listings for the /listing/<slug> URL.
-- Nullable on purpose: a row inserted before the application sets a slug must
-- still be insertable, so this migration adds the column, backfills what is
-- already there, and indexes it. No trigger, no application code.

alter table public.marketplace_listings
  add column if not exists slug text;

comment on column public.marketplace_listings.slug is
  'Public URL segment for /listing/<slug>. Unique across the whole table, since the path carries no seller handle. Null until the application assigns one.';

-- Backfill from the title: lowercase, spaces and underscores to hyphens, drop
-- everything that is not a lowercase letter, digit or hyphen, collapse hyphen
-- runs, trim the ends. A title that reduces to nothing (punctuation or a
-- non-Latin script) falls back to 'listing' and is then made unique by the
-- collision pass below like any other duplicate.
--
-- Uniqueness is table-wide. Within a group of rows that produce the same base
-- slug, the earliest-created row keeps it unqualified and the rest take the
-- first eight characters of their uuid as a suffix. Ordering is by created_at
-- with id as a tiebreaker, so the outcome does not depend on the order the
-- planner happens to return rows in.
--
-- Ranking reads every row while the update writes only the null ones, so
-- re-running this after a partial failure reproduces the same assignment
-- instead of renumbering rows that already have a slug.
with candidate as (
  select
    id,
    created_at,
    coalesce(
      nullif(
        trim(both '-' from
          regexp_replace(
            regexp_replace(
              regexp_replace(lower(title), '[[:space:]_]+', '-', 'g'),
              '[^a-z0-9-]', '', 'g'
            ),
            '-+', '-', 'g'
          )
        ),
        ''
      ),
      'listing'
    ) as base_slug
  from public.marketplace_listings
),
ranked as (
  select
    id,
    base_slug,
    row_number() over (
      partition by base_slug
      order by created_at asc, id asc
    ) as rn
  from candidate
)
update public.marketplace_listings as m
set slug = case
             when r.rn = 1 then r.base_slug
             else r.base_slug || '-' || left(r.id::text, 8)
           end
from ranked as r
where m.id = r.id
  and m.slug is null;

-- Partial unique index: the URL must resolve to exactly one listing, while
-- rows still waiting for a slug stay unconstrained. Created after the backfill
-- so any residual duplicate fails loudly here rather than passing silently.
create unique index if not exists marketplace_listings_slug_key
  on public.marketplace_listings (slug)
  where slug is not null;
