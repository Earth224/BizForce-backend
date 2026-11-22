-- ===== PART 201a: the member welcome, once per account (run first) =====
-- NAMED (Nov 21 2026, P3-1D): 201a changed by the owner before applying: the clawed-back signup grant must not block the member welcome.
-- BEFORE the index covered description IN ('Welcome bonus', 'member_welcome'). AFTER it covers 'member_welcome' only, exactly as
-- applied; lib/memberWelcome.js counts an uncleared signup 'Welcome bonus' as the one grant in code.
-- P3-1C (Nov 21 2026): BizCash is for members only. An account receives 1,000 BFC ONE time, when it
-- becomes a member (lib/memberWelcome.js grantMemberWelcome), and never twice, even if it leaves and
-- rejoins. Free accounts hold 0.
-- The ledger is wallet_transactions (005). It has no reason column: the reason is the description, which
-- has no CHECK, and the type CHECK (credit, debit, reward) already allows both rows this block writes, so no
-- CHECK changes. What is added is the database guard: at most ONE member_welcome row per account. bfc_credit
-- writes the balance and the row in one transaction, so a second concurrent grant fails here with 23505 and its
-- balance increment rolls back with it. An uncleared signup 'Welcome bonus' still counts as the account's one grant,
-- but in code (lib/memberWelcome.js), so that a free account whose signup grant was cleared (201b) can be welcomed.
-- 129's index on 'Welcome bonus' is unrelated and stays.
-- Read Nov 21 2026: no 'member_welcome' rows, so it builds.
-- Paste-safe: no less-or-equal or greater-or-equal operators, no DO blocks, no transaction statements.
-- Each part runs alone, in order: 201a, 201b.
CREATE UNIQUE INDEX IF NOT EXISTS wallet_transactions_member_welcome_once
  ON public.wallet_transactions (user_id)
  WHERE type = 'reward' AND description = 'member_welcome';

-- ===== PART 201b: the free-account clawback, once per account (run second) =====
-- scripts/oneoff/p31cClawback.js removes the 1,000 BFC signup grant from free accounts with ONE debit each
-- (bfc_debit, description 'free_account_clawback'). The ledger has no idempotency-key column, so the key
-- "p31c-clawback-<user id>" is this index: one clawback row per account. A second run, or two at once,
-- fails here with 23505 and the balance decrement rolls back with it.
-- Read Nov 21 2026: no 'free_account_clawback' rows, so it builds.
CREATE UNIQUE INDEX IF NOT EXISTS wallet_transactions_free_clawback_once
  ON public.wallet_transactions (user_id)
  WHERE type = 'debit' AND description = 'free_account_clawback';
