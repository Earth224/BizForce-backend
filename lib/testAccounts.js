/* ══════════════════════════════════════════════════════════════════════════
   lib/testAccounts.js — which accounts are tests, in one place (launch audit #14).

   THE DEFECT. The audit counted 11 "active" subscriptions. None of them is a
   customer: all 11 belong to accounts on the reserved .invalid domain, which
   can never receive mail and which no person signs in to. One is the entitled
   check account (supabase/seeds/check_entitled_account.sql); ten are the
   clean-run accounts the model comparison of 2026-10-02/03 used. A count of
   subscribers, revenue or MRR that includes them reports customers who do not
   exist.

   THE DEFINITION. An account is a test account when ANY of these holds:
     - its id is one of `ids`: the check suite's subject account, the one
       BIZFORCE_CHECK_USER_ID names (scripts/checkRunResidue.js,
       SUGGESTED_SUBJECT_ID);
     - its email matches one of `emailPatterns`:
         +bftest   the owner's own test sign-ups (…+bftest2@…, …+bftest3@…);
         @bizforceai.invalid   the check and harness accounts (the entitled
                   seed and the clean-run accounts). server.js's
                   TASK_MODEL_HARNESS_DOMAIN names the same domain.

   WHAT USES IT. Every place that counts subscribers, revenue or MRR excludes
   these accounts. Today that is one place: lib/selfReview.js, whose revenue
   figures are the only revenue read in the codebase. scripts/checkTestAccounts.js
   fails on any new read of subscriptions or revenue_events across accounts
   that does not go through this file.

   THE OWNER IS NOT COUNTED EITHER, and is not a test. isUncountedAccount
   is the question every count asks: a test account, or the owner account
   (lib/ownerAccount.js OWNER_ACCOUNT_ID, by id only). The owner's own Stripe
   charges to himself are not revenue and he is not a subscriber.

   WHAT DOES NOT. Entitlement. getUserPlan and requireActiveSubscription never
   ask this question, so a test account with an active subscription still
   passes the gate, and the checks that need an entitled account keep working.
   ══════════════════════════════════════════════════════════════════════════ */

const { OWNER_ACCOUNT_ID } = require("./ownerAccount");

const TEST_ACCOUNTS = Object.freeze({
  ids: Object.freeze([
    "53e6b330-d31c-4958-a10b-516397e7b9c9"   // the check suite's subject account
  ]),
  emailPatterns: Object.freeze([
    /\+bftest[^@]*@/i,
    /@bizforceai\.invalid$/i
  ])
});

/* user: { id, email }. Either may be missing; a missing field matches nothing. */
function isTestAccount(user) {
  if (!user) return false;
  const id = String(user.id || "").toLowerCase();
  if (id && TEST_ACCOUNTS.ids.indexOf(id) !== -1) return true;
  const email = String(user.email || "").trim();
  return email !== "" && TEST_ACCOUNTS.emailPatterns.some(function (re) { return re.test(email); });
}

/* Left out of every subscriber, revenue and MRR count: a test account, or the
   owner account, known by id alone. */
function isUncountedAccount(user) {
  if (!user) return false;
  return String(user.id || "").toLowerCase() === OWNER_ACCOUNT_ID || isTestAccount(user);
}

module.exports = { TEST_ACCOUNTS, isTestAccount, isUncountedAccount };
