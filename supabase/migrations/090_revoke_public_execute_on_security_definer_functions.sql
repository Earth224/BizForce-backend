-- ============================================================================
-- 090_revoke_public_execute_on_security_definer_functions.sql
--
-- Six SECURITY DEFINER functions were executable by anon. This revokes that.
--
-- WHAT WAS WRONG
--   All six functions below are SECURITY DEFINER, which means RLS does not
--   apply to them and the acting user is whatever the CALLER passes as a
--   parameter — p_from, p_user_id, p_buyer, p_donor. That design is correct
--   only while the set of callers is trusted. server.js is the intended caller
--   and holds the service key.
--
--   PostgreSQL grants EXECUTE on a new function to PUBLIC by default. It is the
--   one privilege in the system that is granted rather than withheld on
--   creation, and it is granted silently. anon is a member of PUBLIC, and
--   Supabase grants anon USAGE on schema public as part of project setup, so
--   the two defaults compose into a live grant without anyone choosing it.
--
--   No REVOKE statement appears anywhere in the first ninety migrations in this
--   directory. Nothing was ever taken away, because nothing recorded that
--   anything had been given.
--
--   The result, measured before this file ran:
--
--     anon_exec  true on all six
--     acl        =X/postgres | postgres=X/postgres | anon=X/postgres |
--                authenticated=X/postgres | service_role=X/postgres
--
--   The leading "=X/postgres" with an empty grantee is the PUBLIC grant.
--
--   Measured after:
--
--     anon_exec  false on all six
--     authed_exec false on all six
--     service_exec true on all six
--     acl        postgres=X/postgres | service_role=X/postgres
--
-- WHY bfc_credit WAS THE SHARP EDGE
--   Not every one of the six was equally dangerous, and the difference is worth
--   stating because it is the difference between money moving and money
--   appearing.
--
--   bfc_transfer is zero-sum and self-limiting. It names a source wallet, takes
--   `for update` on it, and refuses with 'insufficient balance' when the source
--   is short. A caller who could execute it could rearrange balances that
--   already existed; it could not create a credit out of nothing, because every
--   credit it writes is paid for by a debit it just checked.
--
--   bfc_credit has no source. Its signature is (p_user_id, p_amount, p_type,
--   p_description) — a user and a number, and it adds. There is no second
--   wallet to check against, so there is nothing in the function's own shape
--   that could bound it. The exposure was therefore not money moving between
--   wallets: it was money being MINTED, to any wallet, in any quantity, by
--   anyone holding the anon key. bfc_debit is the exact mirror — (p_user_id,
--   p_amount, p_description), no source, subtracting — so it could zero any
--   balance in the system.
--
-- WHAT LIMITED IT IN PRACTICE
--   This was latent, not reachable. The anon key is not shipped to any browser:
--   neither the key nor the Supabase project URL appears anywhere in the
--   frontend's HTML or JavaScript. Every frontend page talks to the Railway
--   backend with a bf_token, and the backend holds the service key server-side.
--   There was no published path from a browser to these functions.
--
--   That is a description of the current deployment, not a property of the
--   schema. It was one leaked key away from being live — and JWT_SECRET sits in
--   the same .env as the anon key, so anyone holding that file could mint an
--   anon token rather than needing the issued one. "Not currently reachable" is
--   not a control; it is a coincidence that held.
--
-- THE STANDING RULE
--   Every future SECURITY DEFINER function that takes an acting user as a
--   parameter ships its REVOKE in the same migration that creates it.
--
--   Not in a follow-up, and not left to a later audit. The default runs the
--   wrong way, the grant is invisible in the function's own DDL, and nothing in
--   this repository would have caught it — there is no test, no startup check
--   and no review step that reads pg_proc.proacl. The only reason this file
--   exists is that someone asked the question directly. The next function will
--   not get that, so it has to carry its own answer.
--
--   record_inventory_movement is the immediate case: it will be SECURITY
--   DEFINER and it will trust p_user_id absolutely, because inventory_movements
--   has no user_id column and the only route to an owner is through the
--   inventory_items row it locks.
--
-- ORDERING AND SAFETY
--   REVOKE and GRANT are idempotent — re-running this file changes nothing.
--   It must run AFTER 089, which is where bfc_transfer and bfc_buy_listing are
--   created; revoking on a function that does not exist yet is an error, not a
--   no-op. bfc_debit and bfc_credit still have no CREATE anywhere in this
--   directory — they exist live and 089 recorded only two of the four missing
--   RPCs — so on a genuinely fresh database the two statements naming them will
--   fail. Transcribing those two bodies belongs in its own migration.
--
--   One thing this file does not survive: DROP. `create or replace function`
--   PRESERVES the existing ACL, so replacing any of these six keeps the revoke
--   in force. Dropping and recreating one resets it to the PUBLIC default
--   silently. That is the specific way this fix gets undone, and it is why the
--   rule above is written as "in the same migration" rather than "once".
-- ============================================================================

revoke execute on function public.bfc_transfer(uuid, uuid, integer, text) from public, anon, authenticated;
revoke execute on function public.bfc_credit(uuid, integer, text, text) from public, anon, authenticated;
revoke execute on function public.bfc_debit(uuid, integer, text) from public, anon, authenticated;
revoke execute on function public.bfc_donate(uuid, uuid, integer) from public, anon, authenticated;
revoke execute on function public.bfc_buy_listing(uuid, uuid) from public, anon, authenticated;
revoke execute on function public.convert_prospect_to_customer(uuid, uuid) from public, anon, authenticated;

grant execute on function public.bfc_transfer(uuid, uuid, integer, text) to service_role;
grant execute on function public.bfc_credit(uuid, integer, text, text) to service_role;
grant execute on function public.bfc_debit(uuid, integer, text) to service_role;
grant execute on function public.bfc_donate(uuid, uuid, integer) to service_role;
grant execute on function public.bfc_buy_listing(uuid, uuid) to service_role;
grant execute on function public.convert_prospect_to_customer(uuid, uuid) to service_role;
