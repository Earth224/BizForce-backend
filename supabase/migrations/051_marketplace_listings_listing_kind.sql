-- Adds listing_kind to marketplace_listings; 'product' and 'service' are the two intended values.

alter table public.marketplace_listings
  add column if not exists listing_kind text not null default 'product';
