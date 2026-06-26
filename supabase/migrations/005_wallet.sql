-- Phase 5: BizForce Credits wallet

CREATE TABLE IF NOT EXISTS user_wallets (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL UNIQUE,
  balance    integer     NOT NULL DEFAULT 0,
  currency   text        NOT NULL DEFAULT 'BFC',
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS wallet_transactions (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL,
  type        text        NOT NULL,
  amount      integer     NOT NULL,
  description text        NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT wallet_transactions_type_check   CHECK (type IN ('credit','debit','reward')),
  CONSTRAINT wallet_transactions_amount_check CHECK (amount > 0)
);

CREATE INDEX IF NOT EXISTS wallet_transactions_user_id_idx
  ON wallet_transactions (user_id);
CREATE INDEX IF NOT EXISTS wallet_transactions_user_created_idx
  ON wallet_transactions (user_id, created_at DESC);

ALTER TABLE user_wallets        ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallet_transactions ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_wallets_select_own ON user_wallets FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY user_wallets_insert_own ON user_wallets FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY user_wallets_update_own ON user_wallets FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE POLICY wallet_transactions_select_own ON wallet_transactions FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY wallet_transactions_insert_own ON wallet_transactions FOR INSERT WITH CHECK (auth.uid() = user_id);
