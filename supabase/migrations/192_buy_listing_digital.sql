-- P2-2 (Nov 20 2026): bfc_buy_listing copies the digital fields into the order, keeps a
-- digital listing on sale, and refuses a purchase between blocked members.
-- Safe to re-run: CREATE OR REPLACE FUNCTION, and the guard below only drops what it finds.
--
-- THE LIVE FUNCTION (read by the owner, Nov 20 2026; the same body migration 089 transcribed)
-- selects seller_id, price_bfc, status and title only, always marks the listing 'sold', and
-- inserts the order without is_digital, digital_file_path or digital_file_name. So a BizCash
-- purchase of a digital listing recorded is_digital = false (its column default, migration
-- 042) and no file snapshot (migration 113), and the listing was sold after one copy.
--
-- WHAT CHANGES, AND ONLY THIS:
-- 1. The listing read (still FOR UPDATE) also reads is_digital, digital_file_path and
--    digital_file_name, and the order insert copies them.
-- 2. The listing is marked 'sold' only when it is NOT digital. A digital listing stays
--    'active' and sells many copies.
-- 3. A buyer who has blocked the seller, or whom the seller has blocked (member_blocks,
--    migration 191, either way), is refused with 'listing not available', the same words as
--    a listing that is not on sale, so a block is never revealed.
-- Everything else is as it was: the arguments, the return value (the buyer's new balance),
-- SECURITY DEFINER, search_path, the other errors and their order, and the bfc_transfer call
-- with its description.
--
-- ONE ORDER PER DIGITAL COPY. No migration in this repository puts a unique rule on
-- marketplace_orders other than marketplace_orders_stripe_session_id_key (migration 112),
-- where NULLs are distinct and BizCash orders have no session id, so a second order of the
-- same listing was never refused by it. The table existed live before any migration recorded
-- it (034), so the block below also drops any unique index or constraint whose only column
-- is listing_id, should one exist live, and says so with a NOTICE. Nothing else is touched.
BEGIN;

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT i.indexrelid::regclass::text AS index_name, c.conname
    FROM pg_index i
    LEFT JOIN pg_constraint c ON c.conindid = i.indexrelid AND c.conrelid = i.indrelid
    WHERE i.indrelid = 'public.marketplace_orders'::regclass
      AND i.indisunique AND NOT i.indisprimary
      AND i.indnatts = 1
      AND i.indkey[0] = (SELECT attnum FROM pg_attribute
                         WHERE attrelid = 'public.marketplace_orders'::regclass AND attname = 'listing_id')
  LOOP
    IF r.conname IS NOT NULL THEN
      EXECUTE format('ALTER TABLE public.marketplace_orders DROP CONSTRAINT %I', r.conname);
    ELSE
      EXECUTE format('DROP INDEX %s', r.index_name);
    END IF;
    RAISE NOTICE '192: dropped the unique rule % on marketplace_orders (listing_id): a digital listing sells many copies', r.index_name;
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION public.bfc_buy_listing(p_buyer uuid, p_listing_id uuid)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  v_seller uuid;
  v_price integer;
  v_status text;
  v_title text;
  v_is_digital boolean;
  v_file_path text;
  v_file_name text;
  v_new_balance integer;
begin
  select seller_id, price_bfc, status, title, is_digital, digital_file_path, digital_file_name
    into v_seller, v_price, v_status, v_title, v_is_digital, v_file_path, v_file_name
    from marketplace_listings
    where id = p_listing_id
    for update;

  if v_seller is null then
    raise exception 'listing not found';
  end if;

  if v_status <> 'active' then
    raise exception 'listing not available';
  end if;

  if p_buyer = v_seller then
    raise exception 'cannot buy your own listing';
  end if;

  if exists (
    select 1 from member_blocks
    where (blocker_id = p_buyer and blocked_id = v_seller)
       or (blocker_id = v_seller and blocked_id = p_buyer)
  ) then
    raise exception 'listing not available';
  end if;

  v_new_balance := bfc_transfer(
    p_buyer,
    v_seller,
    v_price,
    'Marketplace purchase: ' || coalesce(v_title, 'listing')
  );

  if coalesce(v_is_digital, false) = false then
    update marketplace_listings
      set status = 'sold', updated_at = now()
      where id = p_listing_id;
  end if;

  insert into marketplace_orders (listing_id, buyer_id, seller_id, amount_bfc, listing_title, status,
                                  is_digital, digital_file_path, digital_file_name)
  values (p_listing_id, p_buyer, v_seller, v_price, v_title, 'completed',
          coalesce(v_is_digital, false), v_file_path, v_file_name);

  return v_new_balance;
end;
$function$;

-- as migration 090 left it (CREATE OR REPLACE keeps the grants; restated so a re-run is exact):
-- members never call this function directly; the server does, with the service role
REVOKE EXECUTE ON FUNCTION public.bfc_buy_listing(uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bfc_buy_listing(uuid, uuid) TO service_role;

COMMIT;
