-- Records which property a post was written for, and what happened to it there.
--
-- A post written for an external site is stored in content_library as a draft
-- and is never served on this platform's public blog. Nothing else in the
-- schema says where such a post belongs or whether it ever went live: status
-- 'draft' is also what an ordinary unfinished post looks like, and published_at
-- only ever describes publication here. These three columns are the only
-- record of the external side.
--
-- All three are nullable, and null on site means this platform — which is what
-- every existing row is. No backfill: every current row is already correct.

alter table public.content_library
  add column if not exists site                  text,
  add column if not exists external_url          text,
  add column if not exists external_published_at timestamptz;

comment on column public.content_library.site is
  'The property this post was written for, as a bare hostname such as swordvitality.com. Null means this platform, which is the default for every post written for the marketplace.';

comment on column public.content_library.external_url is
  'Where this post actually went live on that external property, filled in after it is published there. Null means not yet published externally.';

comment on column public.content_library.external_published_at is
  'When this post went live on the external property. Null while it has not been published there.';

-- Partial index: the query this serves is "every post for this property", and
-- the null rows — every post written for this platform, which is the
-- overwhelming majority — are never filtered on, so they stay out of the index.
create index if not exists content_library_site_idx
  on public.content_library (site)
  where site is not null;
