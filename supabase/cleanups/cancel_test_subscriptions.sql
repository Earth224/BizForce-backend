-- ============================================================================
-- supabase/cleanups/cancel_test_subscriptions.sql  (launch audit #14, 2026-10-21)
-- The owner's copy is Downloads\cleanup-test-subscriptions.sql, byte for byte
-- the same; scripts/checkTestAccounts.js pins this one.
--
-- WHAT THIS DOES
--   Sets status = 'canceled' on exactly ten subscriptions rows. All ten belong
--   to the clean-run harness accounts (email on the reserved @bizforceai.invalid
--   domain, which can never receive mail and which no person signs in to),
--   created for the model comparison of 2026-10-02/03. Each was placed by hand:
--   plan all_access, no Stripe subscription, no Stripe customer, no price, no
--   period end. None is a customer and none was ever paid for.
--
--   It deletes nothing. It changes no other column but updated_at, and no
--   other table.
--
-- WHAT IT LEAVES ALONE, ON PURPOSE
--   88239d99-4303-4350-aa61-c0c9d6b01b94, the entitled check account's row
--   (supabase/seeds/check_entitled_account.sql). The check suite needs it
--   active: scripts/checkRunResidue.js refuses to run checkEntitlementGate,
--   checkSelfReviewEntitlement, checkRoutineStepCap and checkRemainingSpendPaths
--   unless that account holds exactly one subscription with status 'active'.
--   It is a test account, so lib/testAccounts.js already keeps it out of every
--   revenue figure.
--
-- HOW TO RUN IT (Supabase dashboard > SQL Editor)
--   1. Run STEP 1 alone. It must list exactly the ten rows below, each 'active'.
--   2. Run STEP 2 (begin ... commit). If the rows are not exactly those ten,
--      it raises "cleanup refused" and changes nothing.
--   3. Run STEP 3. It must show the ten rows 'canceled' and the check
--      account's row still 'active'.
-- ============================================================================


-- STEP 1. PREVIEW: exactly the rows STEP 2 will change.
select s.id, s.user_id, s.status, s.plan, s.current_period_end, s.stripe_price_id, s.created_at
  from public.subscriptions s
  join public.users u on u.id = s.user_id
 where s.id in (
         'fc3489ed-9fb7-43b4-a519-09da23d67c5e',
         '54b28acb-99fc-45aa-b337-e1a3567c1f9e',
         '6877d019-e4e8-4031-89b7-cf622d78b78c',
         'db387ea2-28d0-46e1-a6e8-551a5299e8cf',
         'b4e2d9e3-f15c-42fc-b91c-5ce54be1aec3',
         '5249f289-381e-4316-9f3b-05528a3ed2c0',
         '5e323ea9-3bf8-49e1-b749-34882df97aa8',
         'e0577090-2bf7-4fce-af5c-bcdaa835e2a0',
         '3bf9ecfe-072d-4743-84be-675ea83f9c3d',
         '740fc7ee-d8a1-4602-91a2-0d5a784f8287'
       )
   and s.status = 'active'
   and s.stripe_subscription_id is null
   and s.stripe_customer_id is null
   and lower(u.email) like '%@bizforceai.invalid'
 order by s.created_at;


-- STEP 2. THE CHANGE: all ten or none.
begin;

do $$
declare
  n integer;
begin
  select count(*) into n
    from public.subscriptions s
    join public.users u on u.id = s.user_id
   where s.id in (
           'fc3489ed-9fb7-43b4-a519-09da23d67c5e',
           '54b28acb-99fc-45aa-b337-e1a3567c1f9e',
           '6877d019-e4e8-4031-89b7-cf622d78b78c',
           'db387ea2-28d0-46e1-a6e8-551a5299e8cf',
           'b4e2d9e3-f15c-42fc-b91c-5ce54be1aec3',
           '5249f289-381e-4316-9f3b-05528a3ed2c0',
           '5e323ea9-3bf8-49e1-b749-34882df97aa8',
           'e0577090-2bf7-4fce-af5c-bcdaa835e2a0',
           '3bf9ecfe-072d-4743-84be-675ea83f9c3d',
           '740fc7ee-d8a1-4602-91a2-0d5a784f8287'
         )
     and s.status = 'active'
     and s.stripe_subscription_id is null
     and s.stripe_customer_id is null
     and lower(u.email) like '%@bizforceai.invalid';
  if n <> 10 then
    raise exception 'cleanup refused: expected 10 matching rows, found %. Nothing was changed.', n;
  end if;

  update public.subscriptions s
     set status = 'canceled', updated_at = now()
    from public.users u
   where u.id = s.user_id
     and s.id in (
           'fc3489ed-9fb7-43b4-a519-09da23d67c5e',
           '54b28acb-99fc-45aa-b337-e1a3567c1f9e',
           '6877d019-e4e8-4031-89b7-cf622d78b78c',
           'db387ea2-28d0-46e1-a6e8-551a5299e8cf',
           'b4e2d9e3-f15c-42fc-b91c-5ce54be1aec3',
           '5249f289-381e-4316-9f3b-05528a3ed2c0',
           '5e323ea9-3bf8-49e1-b749-34882df97aa8',
           'e0577090-2bf7-4fce-af5c-bcdaa835e2a0',
           '3bf9ecfe-072d-4743-84be-675ea83f9c3d',
           '740fc7ee-d8a1-4602-91a2-0d5a784f8287'
         )
     and s.status = 'active'
     and s.stripe_subscription_id is null
     and s.stripe_customer_id is null
     and lower(u.email) like '%@bizforceai.invalid';
  get diagnostics n = row_count;
  if n <> 10 then
    raise exception 'cleanup refused: the update matched % rows, not 10. Nothing was changed.', n;
  end if;
end
$$;

commit;


-- STEP 3. VERIFY: the ten are 'canceled'; the check account's row is still 'active'.
select s.id, s.status, s.updated_at
  from public.subscriptions s
 where s.id in (
         'fc3489ed-9fb7-43b4-a519-09da23d67c5e',
         '54b28acb-99fc-45aa-b337-e1a3567c1f9e',
         '6877d019-e4e8-4031-89b7-cf622d78b78c',
         'db387ea2-28d0-46e1-a6e8-551a5299e8cf',
         'b4e2d9e3-f15c-42fc-b91c-5ce54be1aec3',
         '5249f289-381e-4316-9f3b-05528a3ed2c0',
         '5e323ea9-3bf8-49e1-b749-34882df97aa8',
         'e0577090-2bf7-4fce-af5c-bcdaa835e2a0',
         '3bf9ecfe-072d-4743-84be-675ea83f9c3d',
         '740fc7ee-d8a1-4602-91a2-0d5a784f8287',
         '88239d99-4303-4350-aa61-c0c9d6b01b94'
       )
 order by s.status, s.id;
