-- ============================================================================
-- supabase/seeds/check_entitled_account.sql
--
-- WHAT THIS IS
--   A SEED, not a schema change. It creates one account that exists only so
--   four check scripts can exercise the ENTITLED path, which none of them has
--   ever reached:
--
--     scripts/checkEntitlementGate.js       scripts/checkSelfReviewEntitlement.js
--     scripts/checkRoutineStepCap.js        scripts/checkRemainingSpendPaths.js
--
--   Each looks for "a non-admin users row with a subscriptions row whose status
--   is active or trialing". No such account exists: the three live
--   subscription rows are canceled or past_due, and the designated check
--   account (53e6b330-...) must stay UNsubscribed, because three of the four
--   use it as the account that must be refused.
--
-- THE ACCOUNT
--   users          email 'check-entitled@bizforceai.invalid', role 'user',
--                  business_name and bio saying what it is.
--   subscriptions  status 'active', plan 'all_access', current_period_end NULL,
--                  stripe_subscription_id NULL, stripe_customer_id NULL.
--
--   ⚠️ IT IS GENUINELY ENTITLED IN PRODUCTION UNTIL THE ROW IS DELETED.
--   getUserPlan reads this table, never Stripe, so requireActiveSubscription
--   lets it through. Nothing takes that away on its own: every write to
--   subscriptions is in handleStripeEvent and keys on a Stripe id this row does
--   not have, and a NULL current_period_end is "no period recorded", which
--   subscriptionExpiryState never treats as expired.
--
-- WHY NO ONE CAN SIGN IN AS IT
--   password_hash is '!locked: seed account for the entitled check scripts;
--   not a bcrypt hash, no password matches' - 92 characters. POST
--   /api/auth/login decides with bcryptjs's compare(password, password_hash),
--   and bcryptjs 2.4.3 returns false for ANY stored hash whose length is not
--   60 before it looks at the password (dist/bcrypt.js, compare and
--   compareSync: `if (hash.length !== 60) ... false`). Every hash bcryptjs
--   produces is exactly 60 characters beginning "$2", so no password can
--   produce this value either. The other ways in:
--     register        refuses: the email is taken (users_email_key).
--     refresh         needs a session; none is ever created for it.
--     webauthn        needs a registered credential, which needs a session.
--     password reset  mails its token, and .invalid is reserved (RFC 2606 and
--                     RFC 6761) and can never receive mail. The token is
--                     readable only by someone with database access, who could
--                     already write the row directly.
--   The guard below refuses to run if the stored value is ever 60 characters.
--
-- WHAT A SQL INSERT SKIPS
--   POST /api/auth/register does all of this in application code, and none of
--   it is a trigger, so this seed does none of it:
--     - a profiles row                  (the account has no profile)
--     - a "welcome" notifications row
--     - a user_wallets row with 1000 BFC, and its wallet_transactions reward
--     - a contacts row (findOrCreateUserContact)
--     - a verification email (and its email_sends row)
--     - a session
--   users.subscription_status stays at its default 'free': the Stripe webhook
--   mirrors 'active' onto it for real subscribers, but nothing reads it for
--   entitlement. A check-script failure caused by one of these missing rows is
--   a property of this seed, not of the entitled path.
--
-- WHERE IT APPEARS
--   No product count, list or ledger. Every read of users or subscriptions in
--   server.js and lib/ is keyed by one user id, email or Stripe id; there is no
--   admin user list and no subscriber count. revenue_events is written only
--   by handleStripeEvent, so this row never produces a revenue event, and
--   Stripe has no customer for it. The only code that scans for it is the four
--   scripts above.
--
-- WHY THIS IS NOT IN supabase/migrations
--   Migrations describe schema, and scripts/rebuildFromScratch.js applies
--   every .sql file in that folder, in order, to build a database from
--   nothing. A seed there would plant a production-entitled account in every
--   database ever rebuilt from this repo. Nothing runs supabase/seeds/
--   automatically. (Not supabase/seed.sql either: the Supabase CLI runs that
--   file on every `db reset`.) Apply it by hand, once, in the SQL editor.
--
-- THE GUARDS (all inside one transaction, so a refusal inserts nothing)
--   1. Reports the live constraints, unique indexes and triggers on both
--      tables as NOTICEs, read from the catalog at apply time.
--   2. Refuses if either table has a user-defined trigger: a trigger is a side
--      effect this header does not describe.
--   3. Refuses if the email already belongs to an account that is not this
--      seed (role admin, or a password_hash other than the locked value).
--   4. Refuses if the account's subscriptions row has ever been touched by
--      Stripe (a stripe_subscription_id or stripe_customer_id set).
--   5. Afterwards, asserts the result: exactly one users row, role 'user', a
--      locked hash; exactly one subscriptions row, active, all_access, no
--      Stripe ids. Anything else raises, and the transaction rolls back.
--
-- IDEMPOTENT
--   Both inserts are skipped when the row already exists, so running this
--   twice is a no-op the second time, and the assertions still run.
--
-- TO REMOVE IT
--   begin;
--   delete from public.subscriptions
--    where user_id = (select id from public.users
--                      where email = 'check-entitled@bizforceai.invalid');
--   delete from public.users
--    where email = 'check-entitled@bizforceai.invalid'
--      and password_hash like '!locked:%';
--   commit;
--   The subscriptions row would also go with the users row (ON DELETE
--   CASCADE); it is deleted first so the entitlement ends even if the users
--   delete is refused. If the users delete fails on a foreign key, a check run
--   left residue under the account: find it before removing it.
-- ============================================================================

begin;

do $$
declare
  seed_email  constant text := 'check-entitled@bizforceai.invalid';
  locked_hash constant text := '!locked: seed account for the entitled check scripts; not a bcrypt hash, no password matches';
  r           record;
  hits        text;
  uid         uuid;
  n           int;
begin
  if length(locked_hash) = 60 then
    raise exception 'check_entitled_account refused: the locked hash is 60 characters, the one length bcryptjs will compare. Nothing was inserted.';
  end if;

  -- 1. What the live catalog says, at apply time.
  for r in
    select c.conrelid::regclass::text as tbl, c.conname, c.contype, pg_get_constraintdef(c.oid) as def
      from pg_constraint c
     where c.conrelid in ('public.users'::regclass, 'public.subscriptions'::regclass)
     order by 1, 2
  loop
    raise notice 'constraint  %  %  (%)  %', r.tbl, r.conname, r.contype, r.def;
  end loop;
  for r in
    select i.indrelid::regclass::text as tbl, i.indexrelid::regclass::text as idx, pg_get_indexdef(i.indexrelid) as def
      from pg_index i
     where i.indrelid in ('public.users'::regclass, 'public.subscriptions'::regclass)
       and i.indisunique
     order by 1, 2
  loop
    raise notice 'unique index  %  %  %', r.tbl, r.idx, r.def;
  end loop;

  -- 2. No trigger may fire on these inserts.
  select string_agg(t.tgrelid::regclass::text || '.' || t.tgname, ', ')
    into hits
    from pg_trigger t
   where t.tgrelid in ('public.users'::regclass, 'public.subscriptions'::regclass)
     and not t.tgisinternal;
  if hits is not null then
    raise exception 'check_entitled_account refused: trigger(s) on users/subscriptions: %. Their side effects are not described in this seed. Nothing was inserted.', hits;
  end if;

  -- 3. The email is this seed's or nobody's.
  select id into uid from public.users where email = seed_email;
  if uid is not null then
    select count(*) into n from public.users
     where id = uid and lower(coalesce(role, '')) = 'user' and password_hash = locked_hash;
    if n <> 1 then
      raise exception 'check_entitled_account refused: % already exists and is not this seed (role or password_hash differ). Nothing was changed.', seed_email;
    end if;
  end if;

  -- 4. Stripe has never touched its subscription.
  if uid is not null then
    select count(*) into n from public.subscriptions
     where user_id = uid and (stripe_subscription_id is not null or stripe_customer_id is not null);
    if n > 0 then
      raise exception 'check_entitled_account refused: the seed account has a subscriptions row carrying a Stripe id. It is no longer a hand-placed row. Nothing was changed.';
    end if;
  end if;

  -- The inserts.
  insert into public.users (email, password_hash, role, business_name, bio)
  values (seed_email, locked_hash, 'user',
          'CHECK ACCOUNT - entitled test fixture, not a customer',
          'Created by supabase/seeds/check_entitled_account.sql so the check scripts can exercise the entitled path. Cannot sign in. Delete with the SQL in that file''s header.')
  on conflict (email) do nothing;

  select id into uid from public.users where email = seed_email;

  insert into public.subscriptions (user_id, plan, status, current_period_end, stripe_subscription_id, stripe_customer_id)
  select uid, 'all_access', 'active', null, null, null
   where not exists (select 1 from public.subscriptions where user_id = uid);

  -- 5. The result is exactly what the header describes.
  select count(*) into n from public.users
   where email = seed_email and lower(coalesce(role, '')) = 'user' and password_hash = locked_hash and length(password_hash) <> 60;
  if n <> 1 then
    raise exception 'check_entitled_account: expected one locked, non-admin users row for %, found %. Rolled back.', seed_email, n;
  end if;
  select count(*) into n from public.subscriptions where user_id = uid;
  if n <> 1 then
    raise exception 'check_entitled_account: expected one subscriptions row for the seed account, found %. Rolled back.', n;
  end if;
  select count(*) into n from public.subscriptions
   where user_id = uid and status = 'active' and plan = 'all_access' and current_period_end is null
     and stripe_subscription_id is null and stripe_customer_id is null;
  if n <> 1 then
    raise exception 'check_entitled_account: the seed account''s subscriptions row is not active / all_access / no period / no Stripe ids (someone changed it). Rolled back.';
  end if;

  raise notice 'check_entitled_account: % is %, entitled by one hand-placed all_access row.', seed_email, uid;
end $$;

commit;
