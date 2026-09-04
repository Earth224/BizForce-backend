-- ============================================================================
-- 089_record_missing_bfc_functions.sql
--
-- bfc_transfer and bfc_buy_listing — a transcription, not a change.
--
-- Both functions ALREADY EXIST IN PRODUCTION and neither has ever had DDL in
-- this repo. Both bodies below were read back verbatim from pg_proc on the live
-- database. `create or replace` makes running this against the live database a
-- no-op in effect.
--
-- WHAT WAS BROKEN, AND IT WAS NOT MERELY UNDOCUMENTED
--   Until this file, the entire migration history contained exactly two
--   `create function` statements: bfc_donate in 031_crowdfunding.sql and
--   public.set_updated_at() in 066_birth_records.sql. Three wallet RPCs are
--   called from server.js. One of them had a definition.
--
--   031 creates bfc_donate, and bfc_donate's body calls bfc_transfer:
--
--     v_new_balance := bfc_transfer(p_donor, v_owner, p_amount, ...);
--
--   PostgreSQL does not resolve function calls inside a plpgsql body at CREATE
--   time — the body is stored as text and resolved on first execution. So a
--   fresh clone running the migrations in order created bfc_donate SUCCESSFULLY
--   and reported no error. The schema looked complete. Every donation then
--   failed at runtime with `function bfc_transfer(uuid, uuid, integer, text)
--   does not exist`, and it failed at the point where money was being moved.
--
--   That is the worst shape a missing migration can take: not a build that
--   fails loudly on replay, but one that succeeds and defers the failure to the
--   first user who tries to pay someone.
--
--   bfc_buy_listing had no definition anywhere either. It is called at
--   server.js:15416, from POST /api/marketplace/listings/:id/buy, and on a
--   fresh clone that route would have failed the same way — except with no
--   migration referencing it at all, nothing in the repo even hinted the
--   function was expected to exist.
--
--   The comment at server.js:14191 asserted the opposite:
--
--     "The three RPCs this repo defines — bfc_transfer, bfc_buy_listing and
--      bfc_donate — are wallet mutations, not aggregates"
--
--   That was true of one of the three. The claim is worth recording because it
--   is exactly the kind of statement that stops anyone looking: a reader
--   checking whether the RPCs were tracked would have read that line and moved
--   on. Correcting the comment is a server.js change and belongs in its own
--   commit, not in a migration.
--
-- ORDERING HAZARD, RECORDED RATHER THAN FIXED
--   This file must run BEFORE 031 for a clean replay, and it does not. 089 runs
--   after 031, so on a genuinely fresh database the sequence is still:
--
--     031  creates bfc_donate  (succeeds; body unresolved, calls bfc_transfer)
--     ...
--     089  creates bfc_transfer and bfc_buy_listing
--
--   That order works. Because the body is only resolved at execution time,
--   bfc_donate does not need bfc_transfer to exist when it is created — it
--   needs it to exist before the first donation. Any replay that runs the whole
--   directory to completion before serving traffic ends in a correct state, and
--   this file is what makes that true where it previously was not.
--
--   It is recorded here instead of renumbering for the same reason 071 was:
--   migration files that have already run are a log, and rewriting history to
--   read more tidily breaks every checkout that has applied them. The hazard is
--   real only for a partial replay — stopping between 031 and 089 leaves a
--   database that boots, accepts donations, and fails on each one. If this
--   directory is ever replayed in stages, run it to the end.
--
-- WHY THESE TWO ARE FUNCTIONS AT ALL
--   Both move money across more than one table and cannot be half-done.
--   bfc_transfer debits one wallet, credits another and writes two
--   wallet_transactions rows; bfc_buy_listing calls bfc_transfer, flips a
--   listing to sold and writes an order. Each takes `for update` on the row it
--   depends on — the sender's wallet, the listing — so two concurrent callers
--   cannot both pass the balance check or both sell the same listing. Sequential
--   writes from a route could not offer either guarantee; see the comment above
--   creditWallet in server.js for what the alternative looks like when it goes
--   wrong.
--
-- SAFETY
--   `create or replace` on both. Idempotent, and a no-op against the live
--   database where both already exist in exactly this form.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.bfc_transfer(p_from uuid, p_to uuid, p_amount integer, p_description text DEFAULT ''::text)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
cur integer;
new_from_balance integer;
begin
if p_from = p_to then
raise exception 'cannot transfer to self';
end if;
if p_amount is null or p_amount <= 0 then
raise exception 'amount must be positive';
end if;

select balance into cur from user_wallets where user_id = p_from for update;
if cur is null then
raise exception 'sender wallet not found';
end if;
if cur < p_amount then
raise exception 'insufficient balance';
end if;

update user_wallets set balance = balance - p_amount, updated_at = now()
where user_id = p_from
returning balance into new_from_balance;

insert into user_wallets (user_id, balance, currency, updated_at)
values (p_to, p_amount, 'BFC', now())
on conflict (user_id)
do update set balance = user_wallets.balance + p_amount, updated_at = now();

insert into wallet_transactions (user_id, type, amount, description)
values (p_from, 'debit', p_amount, coalesce(p_description, 'Transfer sent'));
insert into wallet_transactions (user_id, type, amount, description)
values (p_to, 'credit', p_amount, coalesce(p_description, 'Transfer received'));

return new_from_balance;
end;
$function$;

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
  v_new_balance integer;
begin
  select seller_id, price_bfc, status, title
    into v_seller, v_price, v_status, v_title
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

  v_new_balance := bfc_transfer(
    p_buyer,
    v_seller,
    v_price,
    'Marketplace purchase: ' || coalesce(v_title, 'listing')
  );

  update marketplace_listings
    set status = 'sold', updated_at = now()
    where id = p_listing_id;

  insert into marketplace_orders (listing_id, buyer_id, seller_id, amount_bfc, listing_title, status)
  values (p_listing_id, p_buyer, v_seller, v_price, v_title, 'completed');

  return v_new_balance;
end;
$function$;
