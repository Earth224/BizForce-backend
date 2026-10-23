-- 145_bfc_transfers.sql — every member-to-member BFC transfer, with both parties.
--
-- WHY. BizForce Market is a member trade system and BFC its closed-loop trade
-- credit, so every trade must be on record with both parties, the amount and
-- the time. Purchases already are (marketplace_orders: buyer_id, seller_id,
-- amount_bfc, listing_title) and so are donations (campaign_donations:
-- donor_id, owner_id, amount_bfc, campaign_id). A transfer is not: bfc_send
-- (139) calls bfc_transfer, which writes one 'debit' row for the sender and
-- one 'credit' row for the recipient in wallet_transactions, each described
-- 'Transfer' and neither naming the other member. This table is the record of
-- who sent what to whom; lib/trades.js reads it for each member's trade ledger.
--
-- 1. The table. created_at is the transaction's now(), which is also the
--    created_at of the two ledger rows bfc_transfer writes in the same
--    transaction, so the record and its ledger rows carry the same instant.
-- 2. bfc_send writes one row after bfc_transfer succeeds, in the same
--    transaction: both land or neither does. Body otherwise migration 139's.
-- 3. Backfill. Transfers made before this migration are recovered from the
--    ledger: a sender's 'debit' row described 'Transfer' and a recipient's
--    'credit' row described 'Transfer' with the same created_at and amount are
--    one transfer (bfc_transfer writes both in one transaction, so they share
--    now()). Only an UNAMBIGUOUS pair is recorded: exactly one such debit and
--    exactly one such credit at that instant. Anything else is left out, and
--    the member's trade ledger then reports that it does not reconcile with
--    the wallet, rather than guessing a counterparty.

-- ── 1 ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.bfc_transfers (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_id    uuid        NOT NULL REFERENCES public.users(id),
  recipient_id uuid        NOT NULL REFERENCES public.users(id),
  amount_bfc   integer     NOT NULL CHECK (amount_bfc > 0),
  created_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT bfc_transfers_not_self CHECK (sender_id <> recipient_id)
);

CREATE INDEX IF NOT EXISTS bfc_transfers_sender_idx    ON public.bfc_transfers (sender_id, created_at);
CREATE INDEX IF NOT EXISTS bfc_transfers_recipient_idx ON public.bfc_transfers (recipient_id, created_at);
-- One record per instant and pair, so the backfill can be run again safely.
CREATE UNIQUE INDEX IF NOT EXISTS bfc_transfers_once ON public.bfc_transfers (sender_id, recipient_id, created_at);

alter table public.bfc_transfers enable row level security;
-- No policy: only the server's service key reads it, as for wallet_transactions' writes.

-- ── 2 ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.bfc_send(p_from uuid, p_to uuid, p_amount integer, p_max_per_transfer integer, p_daily_cap integer, p_hold_days integer)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
v_created timestamptz;
v_sent integer;
v_balance integer;
begin
if p_max_per_transfer is null or p_max_per_transfer < 1
   or p_daily_cap is null or p_daily_cap < 1
   or p_hold_days is null or p_hold_days < 0 then
raise exception 'limits_invalid: every transfer limit must be given (max %, daily cap %, hold days %)', p_max_per_transfer, p_daily_cap, p_hold_days;
end if;
if p_from = p_to then
raise exception 'cannot transfer to self';
end if;
if p_amount is null or p_amount <= 0 then
raise exception 'amount must be positive';
end if;
if p_amount > p_max_per_transfer then
raise exception 'over_per_transfer_max: % BFC is more than the % BFC one transfer may move', p_amount, p_max_per_transfer;
end if;
if not exists (select 1 from users where id = p_to) then
raise exception 'unknown_recipient: no account has the id %', p_to;
end if;

select created_at into v_created from users where id = p_from;
if v_created is null then
raise exception 'unknown_sender: no account has the id %', p_from;
end if;
if v_created > now() - make_interval(days => p_hold_days) then
raise exception 'new_account_hold: an account can send BFC % days after it was opened; this one can from %', p_hold_days, v_created + make_interval(days => p_hold_days);
end if;

perform 1 from user_wallets where user_id = p_from for update;

select coalesce(sum(amount), 0) into v_sent
from wallet_transactions
where user_id = p_from
  and type = 'debit'
  and description = 'Transfer'
  and created_at > now() - interval '24 hours';

if v_sent + p_amount > p_daily_cap then
raise exception 'over_daily_cap: % BFC sent in the last 24 hours, and % more would pass the % BFC cap', v_sent, p_amount, p_daily_cap;
end if;

v_balance := bfc_transfer(p_from, p_to, p_amount, 'Transfer');

insert into bfc_transfers (sender_id, recipient_id, amount_bfc)
values (p_from, p_to, p_amount);

return v_balance;
end;
$function$;

revoke execute on function public.bfc_send(uuid, uuid, integer, integer, integer, integer) from public, anon, authenticated;
grant  execute on function public.bfc_send(uuid, uuid, integer, integer, integer, integer) to service_role;

COMMENT ON FUNCTION public.bfc_send(uuid, uuid, integer, integer, integer, integer) IS
  'Member-to-member BFC transfer behind POST /api/wallet/transfer. Refuses an unknown recipient, an amount over p_max_per_transfer, a sender whose users.created_at is within p_hold_days, and a send that would take the sender''s ''Transfer'' debits over p_daily_cap in the last 24 hours (read under the sender''s wallet row lock), then calls bfc_transfer with description ''Transfer'' and records the transfer, with both parties, in bfc_transfers. Migrations 139 and 145. EXECUTE is service_role only.';

-- ── 3 ─────────────────────────────────────────────────────────────────────
insert into public.bfc_transfers (sender_id, recipient_id, amount_bfc, created_at)
select d.user_id, c.user_id, d.amount, d.created_at
from public.wallet_transactions d
join public.wallet_transactions c
  on c.created_at = d.created_at
 and c.amount = d.amount
 and c.type = 'credit'
 and c.description = 'Transfer'
 and c.user_id <> d.user_id
where d.type = 'debit'
  and d.description = 'Transfer'
  and (select count(*) from public.wallet_transactions x
        where x.created_at = d.created_at and x.type = 'debit' and x.description = 'Transfer') = 1
  and (select count(*) from public.wallet_transactions x
        where x.created_at = d.created_at and x.type = 'credit' and x.description = 'Transfer') = 1
  and exists (select 1 from public.users u where u.id = d.user_id)
  and exists (select 1 from public.users u where u.id = c.user_id)
on conflict (sender_id, recipient_id, created_at) do nothing;
