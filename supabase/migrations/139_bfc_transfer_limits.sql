-- 139_bfc_transfer_limits.sql
--
-- BIZCASH (BFC) MOVES ONLY TO REAL ACCOUNTS, AND ONLY WITHIN LIMITS. The
-- launch audit (2026-10-19), items #13 and #18. Four changes:
--
--   1. bfc_transfer refuses a recipient with no users row. It used to upsert
--      a wallet for whatever uuid it was given, so a mistyped or invented id
--      took the BFC into a wallet nobody could ever use. The check comes
--      before any write. bfc_buy_listing and bfc_donate call bfc_transfer
--      too; their recipients (a listing's seller, a campaign's owner) are
--      always accounts, so for them nothing changes.
--
--   2. bfc_send, new: the member-to-member transfer behind
--      POST /api/wallet/transfer. It enforces the three limits the route
--      reads from the environment (lib/bfcTransferLimits.js) — the most one
--      transfer may move, the most one account may send in any 24 hours, and
--      the hold on a new account — and then calls bfc_transfer. The route
--      checks the same limits first so it can say which one refused; this
--      function is the one that decides, because it takes the sender's
--      wallet row lock before it reads the 24-hour total, so two transfers
--      from one sender are counted one after the other and can never both
--      fit under the cap against the same total. The description is fixed
--      ('Transfer'), not a parameter, because the 24-hour total counts that
--      description: a caller must not be able to send under another name and
--      escape the cap.
--
--   3. A foreign key from user_wallets.user_id to users(id), added only when
--      no wallet lacks an account. A read-only count on 2026-10-19 found 0
--      such wallets out of 15. If one has appeared by the time this runs, the
--      key is skipped with a NOTICE naming the count, and nothing else in
--      this file is affected. No ON DELETE action: deleting an account that
--      still has a wallet is refused, so a balance is never dropped silently.
--
--   4. The policies user_wallets_insert_own and user_wallets_update_own
--      (migration 005) are dropped. They let `auth.uid() = user_id` insert
--      and update a wallet row — set its own balance — for any request made
--      with the anon key and a Supabase Auth session. That cannot be
--      exploited today: BizForceAI signs people in with its own tokens, not
--      Supabase Auth, so auth.uid() is null for every request, and the anon
--      key is not shipped to the browser. But they are a balance-setting
--      permission waiting for the day either of those changes, and nothing
--      uses them: every wallet write goes through the service key and the
--      SECURITY DEFINER functions. user_wallets_select_own stays; reading
--      one's own balance is harmless.
--
-- ERROR MESSAGES START WITH A REASON. bfc_send and bfc_transfer raise
-- 'unknown_recipient: …', 'over_per_transfer_max: …', 'over_daily_cap: …',
-- 'new_account_hold: …', 'limits_invalid: …' and the existing
-- 'insufficient balance', and the route turns the part before the colon into
-- the response's `reason`.
--
-- Applied by hand in the Supabase SQL editor. Re-runnable: create or replace,
-- a guarded constraint, drop policy if exists. Until it is applied, the route
-- calls a bfc_send that does not exist and answers 503 naming this file, so
-- no transfer goes through unlimited in the meantime.

-- ── 1. bfc_transfer: the recipient must be an account ─────────────────────
-- The body of migration 089's bfc_transfer, with the recipient check added
-- after the self and amount checks. Same signature, so 090's grants stand.
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
if not exists (select 1 from users where id = p_to) then
raise exception 'unknown_recipient: no account has the id %', p_to;
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

-- ── 2. bfc_send: a member-to-member transfer, within limits ───────────────
CREATE OR REPLACE FUNCTION public.bfc_send(p_from uuid, p_to uuid, p_amount integer, p_max_per_transfer integer, p_daily_cap integer, p_hold_days integer)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
v_created timestamptz;
v_sent integer;
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

-- The sender's wallet row is the per-sender lock. It is taken before the
-- 24-hour total is read, so a second transfer from the same sender waits
-- here until the first has written its debit, and then counts it.
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

return bfc_transfer(p_from, p_to, p_amount, 'Transfer');
end;
$function$;

-- The same posture 090 gave every other BFC function: the server's service
-- key may call it, nobody else may.
revoke execute on function public.bfc_send(uuid, uuid, integer, integer, integer, integer) from public, anon, authenticated;
grant  execute on function public.bfc_send(uuid, uuid, integer, integer, integer, integer) to service_role;

COMMENT ON FUNCTION public.bfc_send(uuid, uuid, integer, integer, integer, integer) IS
  'Member-to-member BFC transfer behind POST /api/wallet/transfer. Refuses an unknown recipient, an amount over p_max_per_transfer, a sender whose users.created_at is within p_hold_days, and a send that would take the sender''s ''Transfer'' debits over p_daily_cap in the last 24 hours (read under the sender''s wallet row lock), then calls bfc_transfer with description ''Transfer''. Migration 139. EXECUTE is service_role only.';

-- ── 3. user_wallets.user_id references users(id), when no orphan exists ───
do $$
declare
  v_orphans integer;
begin
  if exists (select 1 from pg_constraint where conname = 'user_wallets_user_id_fkey') then
    raise notice '139: user_wallets_user_id_fkey already exists; nothing to add';
  else
    select count(*) into v_orphans
    from user_wallets w
    where not exists (select 1 from users u where u.id = w.user_id);

    if v_orphans > 0 then
      raise notice '139: % wallet(s) have no users row, so user_wallets_user_id_fkey was NOT added. Resolve them, then run this file again.', v_orphans;
    else
      alter table public.user_wallets
        add constraint user_wallets_user_id_fkey
        foreign key (user_id) references public.users(id);
    end if;
  end if;
end $$;

-- ── 4. the latent auth.uid() write policies on user_wallets ───────────────
drop policy if exists user_wallets_insert_own on public.user_wallets;
drop policy if exists user_wallets_update_own on public.user_wallets;
