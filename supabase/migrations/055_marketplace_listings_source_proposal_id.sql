-- Records which agent proposal created a listing; null for listings a seller created directly.

alter table public.marketplace_listings
  add column if not exists source_proposal_id uuid;

comment on column public.marketplace_listings.source_proposal_id is
  'The agent_proposals row whose execution created this listing. Null when the listing was created directly by a seller.';

-- Partial unique index: one proposal can create at most one listing, while the
-- many seller-created rows with a null source_proposal_id stay unconstrained.
create unique index if not exists marketplace_listings_source_proposal_id_key
  on public.marketplace_listings (source_proposal_id)
  where source_proposal_id is not null;
