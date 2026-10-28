-- 148_bfc_donate_limits.sql — a campaign donation obeys the transfer limits,
-- and donations and transfers share ONE 24-hour total.
--
-- WHY. bfc_donate (migration 031) moved any amount, any number of times a
-- day, from an account of any age, to any active campaign but the donor's
-- own. Transfers have had three limits since migration 139 (bfc_send): at most
-- p_max_per_transfer in one go, at most p_daily_cap in any 24 hours, and none
-- at all within p_hold_days of the account being opened. A donation went
-- around all three. The launch hardening of 2026-10-27 puts donations under
-- the same three limits, from the same values (lib/bfcTransferLimits.js), and
-- makes the 24 hours one total: a member's 'Transfer' debits and 'Donation: '
-- debits are summed together by both functions, so 2,000 BFC a day is 2,000
-- across both, not 2,000 of each.
--
-- 1. bfc_donate takes the three limits. The old three-argument function is
--    DROPPED first, so the uncapped signature cannot still be called. Every
--    refusal raises a reason before a colon, as bfc_send does, and the route
--    maps each to a status. The donor's wallet row is locked BEFORE the
--    24-hour total is read, the same lock bfc_send takes, so a donation and a
--    transfer sent at once cannot both slip under the cap. What a donation
--    writes is unchanged from 031: bfc_transfer's two ledger rows described
--    'Donation: ' || title, one campaign_donations row, and raised_bfc.
-- 2. bfc_send counts donations in its 24-hour total too. Its body is
--    otherwise migration 145's, word for word.

-- ── 1 ───────────────────────────────────────────────────────────────────────
DROP FUNCTION IF EXISTS public.bfc_donate(uuid, uuid, integer);

CREATE OR REPLACE FUNCTION public.bfc_donate(p_donor uuid, p_campaign_id uuid, p_amount integer, p_max_per_transfer integer, p_daily_cap integer, p_hold_days integer)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
v_owner uuid;
v_status text;
v_title text;
v_created timestamptz;
v_sent integer;
v_new_balance integer;
begin
if p_max_per_transfer is null or p_max_per_transfer < 1
   or p_daily_cap is null or p_daily_cap < 1
   or p_hold_days is null or p_hold_days < 0 then
raise exception 'limits_invalid: every donation limit must be given (max %, daily cap %, hold days %)', p_max_per_transfer, p_daily_cap, p_hold_days;
end if;
if p_amount is null or p_amount <= 0 then
raise exception 'invalid_amount: a donation must be a positive whole number of BFC';
end if;
if p_amount > p_max_per_transfer then
raise exception 'over_per_transfer_max: % BFC is more than the % BFC one donation may move', p_amount, p_max_per_transfer;
end if;

select created_at into v_created from users where id = p_donor;
if v_created is null then
raise exception 'unknown_sender: no account has the id %', p_donor;
end if;
if v_created > now() - make_interval(days => p_hold_days) then
raise exception 'new_account_hold: an account can send BFC % days after it was opened; this one can from %', p_hold_days, v_created + make_interval(days => p_hold_days);
end if;

perform 1 from user_wallets where user_id = p_donor for update;

select owner_id, status, title
into v_owner, v_status, v_title
from crowdfunding_campaigns
where id = p_campaign_id
for update;

if v_owner is null then
raise exception 'campaign_not_found: no campaign has the id %', p_campaign_id;
end if;
if v_owner = p_donor then
raise exception 'self_donation: you cannot donate to your own campaign';
end if;
if v_status <> 'active' then
raise exception 'campaign_not_active: this campaign is not accepting donations';
end if;

select coalesce(sum(amount), 0) into v_sent
from wallet_transactions
where user_id = p_donor
  and type = 'debit'
  and (description = 'Transfer' or description like 'Donation: %')
  and created_at > now() - interval '24 hours';

if v_sent + p_amount > p_daily_cap then
raise exception 'over_daily_cap: % BFC sent in the last 24 hours, transfers and donations together, and % more would pass the % BFC cap', v_sent, p_amount, p_daily_cap;
end if;

v_new_balance := bfc_transfer(p_donor, v_owner, p_amount, 'Donation: ' || v_title);

insert into campaign_donations (campaign_id, donor_id, owner_id, amount_bfc)
values (p_campaign_id, p_donor, v_owner, p_amount);

update crowdfunding_campaigns
set raised_bfc = raised_bfc + p_amount,
updated_at = now()
where id = p_campaign_id;

return v_new_balance;
end;
$function$;

revoke execute on function public.bfc_donate(uuid, uuid, integer, integer, integer, integer) from public, anon, authenticated;
grant  execute on function public.bfc_donate(uuid, uuid, integer, integer, integer, integer) to service_role;

COMMENT ON FUNCTION public.bfc_donate(uuid, uuid, integer, integer, integer, integer) IS
  'Campaign donation behind POST /api/crowdfunding/campaigns/:id/donate. Refuses an amount over p_max_per_transfer, a donor whose users.created_at is within p_hold_days, an unknown or inactive campaign, a donation to the donor''s own campaign, and one that would take the donor''s ''Transfer'' and ''Donation: '' debits together over p_daily_cap in the last 24 hours (read under the donor''s wallet row lock); then calls bfc_transfer with description ''Donation: '' || title, records campaign_donations and adds to raised_bfc. Migrations 031 and 148. EXECUTE is service_role only.';

-- ── 2 ───────────────────────────────────────────────────────────────────────
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
  and (description = 'Transfer' or description like 'Donation: %')
  and created_at > now() - interval '24 hours';

if v_sent + p_amount > p_daily_cap then
raise exception 'over_daily_cap: % BFC sent in the last 24 hours, transfers and donations together, and % more would pass the % BFC cap', v_sent, p_amount, p_daily_cap;
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
  'Member-to-member BFC transfer behind POST /api/wallet/transfer. Refuses an unknown recipient, an amount over p_max_per_transfer, a sender whose users.created_at is within p_hold_days, and a send that would take the sender''s ''Transfer'' and ''Donation: '' debits together over p_daily_cap in the last 24 hours (read under the sender''s wallet row lock), then calls bfc_transfer with description ''Transfer'' and records the transfer, with both parties, in bfc_transfers. Migrations 139, 145 and 148. EXECUTE is service_role only.';
