-- 121_record_bfc_credit_and_bfc_debit.sql
--
-- bfc_credit and bfc_debit — a transcription, not a change.
--
-- Both functions ALREADY EXIST IN PRODUCTION and neither has ever had DDL in
-- this repository. 089 recorded that fact when it transcribed bfc_transfer
-- and bfc_buy_listing ("089 recorded only two of the four missing RPCs"),
-- and 090 said it again while issuing REVOKE against them. Both bodies below
-- were read out of pg_proc on the live database on 2026-09-15 with
-- pg_get_functiondef and are pasted here WITHOUT ALTERATION — signature,
-- RETURNS, LANGUAGE, SECURITY DEFINER, the absence of SET search_path, and
-- every line of the body. `create or replace` makes running this against the
-- live database a no-op in effect.
--
-- NOT RECONSTRUCTED. A summary of each function existed before its source
-- did, and it would have been easy to write a body that matched the summary.
-- A money function written from a summary is a money function nobody has
-- read. These are the read ones.
--
-- ── WHAT THEY ARE ─────────────────────────────────────────────────────────
--
-- The two primitives under the wallet. bfc_credit upserts a user's wallet
-- row adding p_amount (creating the wallet at p_amount if none exists) and
-- writes one ledger row of type 'credit' or 'reward'. bfc_debit locks the
-- wallet row (SELECT ... FOR UPDATE), refuses when there is no wallet or the
-- balance is short, decrements, and writes one ledger row of type 'debit'.
-- Both return the new balance.
--
-- bfc_transfer (089) does NOT call them: it inlines its own lock, decrement,
-- upsert and two ledger rows. The three agree on the ledger shape — every
-- wallet_transactions insert in this schema is (user_id, type, amount,
-- description), four columns, no balance_after, no reference to an order or
-- a counterparty — and on the constraints they lean on, all of which are
-- live: user_wallets_user_id_key UNIQUE (user_id), which the ON CONFLICT in
-- bfc_credit requires; wallet_transactions_type_check restricting type to
-- ('credit','debit','reward'), which is exactly bfc_credit's own guard plus
-- bfc_debit's literal; and wallet_transactions_amount_check (amount > 0),
-- which both functions enforce first with a clearer message.
--
-- NOTHING IN server.js CALLS EITHER. The application calls bfc_transfer,
-- bfc_buy_listing, bfc_donate, record_inventory_movement and
-- convert_prospect_to_customer by name, and never these two. 090 revoked
-- EXECUTE from public, anon and authenticated and granted it to service_role
-- only, so nothing outside the service key can reach them either. They are
-- transcribed because they exist, because bfc_transfer's author evidently
-- wrote them first and then chose to inline rather than compose, and because
-- a rebuild that lacks them cannot run 090.
--
-- ── 1. THIS FILE DOES NOT FIX THE 090 HALT ────────────────────────────────
--
-- 090 runs
--
--   revoke execute on function public.bfc_credit(uuid, integer, text, text) from ...;
--   revoke execute on function public.bfc_debit(uuid, integer, text) from ...;
--
-- REVOKE on a function that does not exist is an error, not a no-op. On a
-- fresh database nothing before 090 creates these two, so the migration run
-- stops at 090 — thirty-one files before this one. This file is numbered
-- 121 because that is the next number and files are not renumbered; the
-- consequence is that it sits ABOVE the statement that needs it and cannot
-- help it. What this file does is make the two functions RECOVERABLE: their
-- source is in the directory, in the form pg_proc holds it. What it does not
-- do is make a rebuild reach them.
--
-- What would: either 090 guarded on the functions existing (a DO block
-- around each REVOKE/GRANT, or `to_regprocedure(...) is not null`), or these
-- two CREATEs placed in a file numbered below 090. Both are edits to files
-- that have run, and both are outside this batch. Until one of them is
-- made, a person completing a rebuild by hand runs THIS FILE before 090,
-- then continues from 090. That is a manual step and it is written down
-- here so it is not rediscovered.
--
-- ── 2. NO search_path, AND IT IS NOT ADDED HERE ───────────────────────────
--
-- Neither function sets search_path. Every other function in this database
-- does — bfc_transfer and bfc_buy_listing carry `SET search_path TO
-- 'public'` (089), bfc_donate and set_updated_at `SET search_path = public`
-- (031, 066), and the prospecting and inventory functions were read the
-- same way from pg_proc. These two are the exceptions.
--
-- Why it matters: SECURITY DEFINER runs the body as the function's OWNER,
-- which is postgres. Without a pinned search_path, the unqualified names in
-- the body — user_wallets, wallet_transactions, now() — resolve through the
-- CALLER's search_path. A caller able to create objects in a schema that
-- sorts ahead of public could plant a user_wallets table or a now() function
-- of their own and have the postgres role execute against it. That is the
-- textbook shape of privilege escalation through SECURITY DEFINER, and it is
-- exactly what the other six functions' SET search_path closes off.
--
-- Why it is NOT added here: this is a transcription, and a transcription
-- that improves what it transcribes has stopped being one. Adding the clause
-- would make the directory describe a function the database does not have,
-- which is the condition this whole batch exists to end. The exposure is
-- also bounded today: 090 left EXECUTE with service_role alone, and the
-- service role has no reason to carry a hostile search_path. It is recorded
-- here as a thing to DECIDE, in its own migration — `ALTER FUNCTION ... SET
-- search_path = public` on each, which is one statement per function, changes
-- no behaviour for any honest caller, and makes these two match the other
-- six.
--
-- ── SAFETY ────────────────────────────────────────────────────────────────
--
-- Idempotent through `create or replace`. No table is touched, no row is
-- written or deleted, and no existing file is renumbered — 120 was the
-- highest before this. Grants are not restated; 090 owns them.

CREATE OR REPLACE FUNCTION public.bfc_credit(p_user_id uuid, p_amount integer, p_type text, p_description text DEFAULT ''::text)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
declare
new_balance integer;
begin
if p_amount is null or p_amount <= 0 then
raise exception 'amount must be positive';
end if;
if p_type not in ('credit','reward') then
raise exception 'invalid credit type: %', p_type;
end if;

insert into user_wallets (user_id, balance, currency, updated_at)
values (p_user_id, p_amount, 'BFC', now())
on conflict (user_id)
do update set balance = user_wallets.balance + p_amount, updated_at = now()
returning balance into new_balance;

insert into wallet_transactions (user_id, type, amount, description)
values (p_user_id, p_type, p_amount, coalesce(p_description,''));

return new_balance;
end;
$function$;

CREATE OR REPLACE FUNCTION public.bfc_debit(p_user_id uuid, p_amount integer, p_description text DEFAULT ''::text)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
declare
cur integer;
new_balance integer;
begin
if p_amount is null or p_amount <= 0 then
raise exception 'amount must be positive';
end if;

select balance into cur from user_wallets where user_id = p_user_id for update;
if cur is null then
raise exception 'wallet not found';
end if;
if cur < p_amount then
raise exception 'insufficient balance';
end if;

update user_wallets set balance = balance - p_amount, updated_at = now()
where user_id = p_user_id
returning balance into new_balance;

insert into wallet_transactions (user_id, type, amount, description)
values (p_user_id, 'debit', p_amount, coalesce(p_description,''));

return new_balance;
end;
$function$;

COMMENT ON FUNCTION public.bfc_credit(uuid, integer, text, text) IS
  'Adds p_amount BFC to p_user_id''s wallet, creating the wallet at that amount if none exists, and writes one wallet_transactions row of type p_type (''credit'' or ''reward'' only). Returns the new balance. SECURITY DEFINER, owner postgres, NO search_path pinned — see migration 121''s header. Transcribed verbatim from pg_proc in 121; never had DDL before that. Not called by server.js; EXECUTE is service_role only (090).';

COMMENT ON FUNCTION public.bfc_debit(uuid, integer, text) IS
  'Removes p_amount BFC from p_user_id''s wallet under SELECT ... FOR UPDATE, raising ''wallet not found'' or ''insufficient balance'', and writes one wallet_transactions row of type ''debit''. Returns the new balance. SECURITY DEFINER, owner postgres, NO search_path pinned — see migration 121''s header. Transcribed verbatim from pg_proc in 121; never had DDL before that. Not called by server.js; EXECUTE is service_role only (090).';
