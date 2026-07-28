-- Adds the fields a content_library row needs to become a public blog post:
-- a URL segment, a search snippet, a go-live timestamp, and its internal link graph.

alter table public.content_library
  add column if not exists slug             text,
  add column if not exists meta_description text,
  add column if not exists published_at     timestamptz,
  add column if not exists internal_links   jsonb;

comment on column public.content_library.slug is
  'URL segment for the public post page. Null until the post is given a public address.';

comment on column public.content_library.meta_description is
  'Search-result snippet for this post — the text a search engine shows beneath the title.';

comment on column public.content_library.published_at is
  'When the post went live. Null while the post is a draft or was never published.';

comment on column public.content_library.internal_links is
  'The posts and money pages this article links to, recorded so the internal link graph can be audited and rebalanced.';

-- Partial unique index: a slug must be unique per author, while the many rows
-- with no slug (drafts, SMS copy) stay unconstrained.
create unique index if not exists content_library_user_slug_key
  on public.content_library (user_id, slug)
  where slug is not null;

-- Listing one author's published posts, newest first.
create index if not exists content_library_published_idx
  on public.content_library (user_id, type, published_at desc)
  where status = 'published';
