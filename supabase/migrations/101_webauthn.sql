-- CHANGES the database. Passkey credentials and the challenges that authorise them.
-- A challenge is single-use and short-lived: consumed_at is set when it is spent,
-- and a spent or expired challenge must never authorise a ceremony.
-- user_id is nullable because a LOGIN ceremony begins before the user is
-- identified - the whole point of a discoverable credential is that the
-- authenticator names the account. A REGISTER ceremony always knows who is
-- asking, which is why the CHECK requires a user for that purpose only.
-- credential_id is unique across all users: an authenticator's credential
-- belongs to exactly one account, and a collision would mean two accounts
-- claiming the same key.
-- sign_count is the authenticator's own counter. It must only ever increase;
-- a value that goes backwards is the signature of a cloned authenticator.
-- Already applied to the live database on 2026-09-09.

create table if not exists public.webauthn_credentials (
  id             uuid        primary key default gen_random_uuid(),
  user_id        uuid        not null references public.users(id) on delete cascade,
  credential_id  text        not null,
  public_key     text        not null,
  sign_count     bigint      not null default 0,
  transports     text[],
  nickname       text,
  aaguid         text,
  backed_up      boolean,
  created_at     timestamptz not null default now(),
  last_used_at   timestamptz,
  constraint webauthn_credentials_sign_count_nonneg check (sign_count >= 0)
);

create unique index if not exists webauthn_credentials_credential_id_key
  on public.webauthn_credentials (credential_id);

create index if not exists webauthn_credentials_user_idx
  on public.webauthn_credentials (user_id, created_at desc);

create table if not exists public.webauthn_challenges (
  id           uuid        primary key default gen_random_uuid(),
  user_id      uuid        references public.users(id) on delete cascade,
  challenge    text        not null,
  purpose      text        not null,
  expires_at   timestamptz not null,
  consumed_at  timestamptz,
  created_at   timestamptz not null default now(),
  constraint webauthn_challenges_purpose_known
    check (purpose in ('register', 'login')),
  constraint webauthn_challenges_expiry_after_issue
    check (expires_at > created_at),
  constraint webauthn_challenges_register_has_user
    check (purpose <> 'register' or user_id is not null)
);

create unique index if not exists webauthn_challenges_challenge_key
  on public.webauthn_challenges (challenge);

create index if not exists webauthn_challenges_sweep_idx
  on public.webauthn_challenges (expires_at)
  where consumed_at is null;

alter table public.webauthn_credentials enable row level security;
alter table public.webauthn_challenges  enable row level security;
