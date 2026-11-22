/* ══════════════════════════════════════════════════════════════════════════
   lib/memberWelcome.js — P3-1C (Nov 21 2026): BizCash is for members only.

   THE OWNER'S RULE. Free accounts never hold BizCash. Every new member starts
   with 1,000 BFC, once per account, given at the moment it becomes a member,
   never twice, even if it leaves and rejoins. The owner's account is never
   touched.

   WHO HAS ALREADY HAD THEIR ONE (NAMED, Nov 21 2026, P3-1D: the owner's final
   rule). BEFORE any signup "Welcome bonus" row counted as the one grant. AFTER:
     - a member_welcome row: already granted;
     - a signup "Welcome bonus" reward row with NO free_account_clawback debit
       (the signup grant was kept): already granted;
     - a signup grant that was cleared (scripts/oneoff/p31cClawback.js wrote the
       clawback): NOT counted, so that account receives the member welcome
       when it joins, once.

   TWO LAYERS AGAINST A DOUBLE GRANT.
     1. The ledger read below.
     2. Migration 201a (as the owner applied it): a unique partial index on
        wallet_transactions (user_id) where type = 'reward' and description =
        'member_welcome'. bfc_credit writes the balance and the row in one
        transaction, so a second concurrent grant fails on the index (23505)
        and its balance increment rolls back with it. A 23505 is "already
        granted".

   It never throws into a caller that must not fail (the billing webhook):
   callers log and continue, see server.js grantMemberWelcomeLogged.
   ══════════════════════════════════════════════════════════════════════════ */

const { OWNER_ACCOUNT_ID } = require("./ownerAccount");

const MEMBER_WELCOME_BFC = 1000;
const MEMBER_WELCOME_DESCRIPTION = "member_welcome";
// What registration wrote to every signup before the grant moved to membership.
const SIGNUP_GRANT_DESCRIPTION = "Welcome bonus";
// The one-off debit that clears a free account's signup grant (scripts/oneoff/p31cClawback.js, migration 201b).
const FREE_CLAWBACK_DESCRIPTION = "free_account_clawback";
const WELCOME_DESCRIPTIONS = Object.freeze([MEMBER_WELCOME_DESCRIPTION, SIGNUP_GRANT_DESCRIPTION, FREE_CLAWBACK_DESCRIPTION]);

// What a member reads in their wallet history for the two machine reasons.
const LEDGER_LABELS = Object.freeze({
  member_welcome: "Member welcome: 1,000 BizCash",
  free_account_clawback: "BizCash removed: free accounts do not hold BizCash"
});

/* The decision on the rows the read returns, apart so a check can hold it to the rule. */
function alreadyWelcomed(rows) {
  const list = rows || [];
  const has = (type, description) => list.some(r => r && r.type === type && r.description === description);
  if (has("reward", MEMBER_WELCOME_DESCRIPTION)) return true;
  if (has("reward", SIGNUP_GRANT_DESCRIPTION) && !has("debit", FREE_CLAWBACK_DESCRIPTION)) return true;
  return false;
}

async function grantMemberWelcome(supabase, userId) {
  if (!userId) return { granted: false, reason: "no_user" };
  if (userId === OWNER_ACCOUNT_ID) return { granted: false, reason: "owner" };

  const prior = await supabase
    .from("wallet_transactions")
    .select("type, description")
    .eq("user_id", userId)
    .in("description", WELCOME_DESCRIPTIONS);
  if (prior.error) {
    throw new Error("could not read whether user " + userId + " already has a welcome grant: " + prior.error.message);
  }
  if (alreadyWelcomed(prior.data)) return { granted: false, reason: "already_granted" };

  const credit = await supabase.rpc("bfc_credit", {
    p_user_id: userId,
    p_amount: MEMBER_WELCOME_BFC,
    p_type: "reward",
    p_description: MEMBER_WELCOME_DESCRIPTION
  });
  if (credit.error) {
    if (credit.error.code === "23505") return { granted: false, reason: "already_granted" };
    throw new Error("bfc_credit refused the member welcome for user " + userId + ": " + credit.error.message +
      ". It runs as one transaction, so neither the balance nor a ledger row was written.");
  }
  return { granted: true, amount: MEMBER_WELCOME_BFC };
}

module.exports = {
  MEMBER_WELCOME_BFC, MEMBER_WELCOME_DESCRIPTION, SIGNUP_GRANT_DESCRIPTION, FREE_CLAWBACK_DESCRIPTION,
  WELCOME_DESCRIPTIONS, LEDGER_LABELS, alreadyWelcomed, grantMemberWelcome
};
