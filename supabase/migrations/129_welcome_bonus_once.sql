-- ============================================================================
-- 129_welcome_bonus_once.sql
--
-- The 1,000 BFC welcome bonus is granted once per account, on the first
-- subscription activation (grantWelcomeBonusOnce in server.js). The code reads
-- the ledger before granting, which stops a redelivered or repeated activation.
-- It cannot stop two deliveries landing in the same instant: both could read
-- "no bonus yet" before either writes.
--
-- This index closes that. bfc_credit inserts the wallet_transactions row and
-- increments user_wallets.balance in one transaction, so a second concurrent
-- grant fails here with 23505 and its balance increment rolls back with it.
-- grantWelcomeBonusOnce treats 23505 as "already granted".
--
-- 'Welcome bonus' is the description registration wrote before this change,
-- so every account that got the bonus at signup is covered by the same index.
-- Read 2026-10-05: 13 such rows, no account with more than one, so the index
-- builds on the live data as it stands.
--
-- Not applied by this commit. Apply by hand in the SQL editor. Until it is,
-- the ledger read is the only guard, and the concurrent window above is open.
-- ============================================================================

create unique index if not exists wallet_transactions_welcome_bonus_once
  on public.wallet_transactions (user_id)
  where type = 'reward' and description = 'Welcome bonus';
