/* ══════════════════════════════════════════════════════════════════════════
   scripts/oneoff/p31cClawback.js — P3-1C/P3-1D (Nov 21 2026): free accounts do
   not hold BizCash. Clears the 1,000 BFC signup grant from the 13 free accounts
   that still hold it, with ONE ledger debit each.

     node scripts/oneoff/p31cClawback.js            dry run: reads only, writes nothing
     node scripts/oneoff/p31cClawback.js --apply    writes the debits

   AN ACCOUNT IS CLEARED ONLY WHEN ALL OF THESE HOLD, read fresh on every run:
     1. it is not the owner (OWNER_ACCOUNT_ID);
     2. it is still a free account: getUserPlan (server.js, the server's own
        answer, read through __selfReviewPlanFor) is not active;
     3. its balance is exactly 1000;
     4. its only ledger row is the signup grant: reward, 1000, "Welcome bonus".
   Any account failing one is SKIPPED, with the reason, and nothing is written
   for it.

   ONCE PER ACCOUNT. The debit is bfc_debit(user, 1000, "free_account_clawback"),
   one transaction for the balance and the row. Migration 201b's unique index
   allows one such row per account (it stands in for the key
   "p31c-clawback-<user id>"), so a second debit fails with 23505 and its balance
   change rolls back; a 23505 is reported as already done. An account already
   cleared (the signup grant plus one clawback, balance 0) is reported as
   already done without any write.

   Never touches any account outside ACCOUNTS. 6df1851e is not in the list.
   ══════════════════════════════════════════════════════════════════════════ */

const ACCOUNTS = Object.freeze([
  "c9529df5-914f-49f4-975f-9418dadfc049", "662828dd-acc4-471e-8800-023b53ac1dae", "9bd0356f-5cd8-4df1-a7d7-441300fc1cd6",
  "41c116e3-2c21-41aa-8cb1-5ebfd4ea9963", "6f4ad16d-aecd-4f98-ab61-f55998e5ceb7", "5252d5e4-a643-4058-a247-85c6738ef796",
  "692f12da-7661-4e7e-9d61-f55b2a3d586d", "90d93363-63dd-4a62-9133-947d17077ce0", "d5345ff2-cc0f-48ec-b660-c2d6667c0d82",
  "01ade328-a5fc-42fa-bf11-c0a0abfa3502", "a69abc72-8ce9-4610-a71f-7ca8af0f617f", "cefd2f3b-8d89-4024-9986-0216aec704fd",
  "c4f80587-a54d-4568-8fc6-1e3ef8a7a582"
]);
const AMOUNT = 1000;
const SIGNUP = "Welcome bonus";
const CLAWBACK = "free_account_clawback";

function isSignupRow(r) { return r && r.type === "reward" && Number(r.amount) === AMOUNT && r.description === SIGNUP; }
function isClawbackRow(r) { return r && r.type === "debit" && Number(r.amount) === AMOUNT && r.description === CLAWBACK; }

/* One account's decision from what was read: { action: "debit" | "done" | "skip", reason }. Pure, for the check. */
function decide(a) {
  if (a.isOwner) return { action: "skip", reason: "the owner's account" };
  if (a.planError) return { action: "skip", reason: "its tier could not be read: " + a.planError };
  if (a.member) return { action: "skip", reason: "it is a member now (" + (a.accessReason || "active") + ")" };
  if (a.readError) return { action: "skip", reason: "its wallet or ledger could not be read: " + a.readError };
  const rows = a.rows || [];
  const wallets = a.wallets || [];
  if (wallets.length > 1) return { action: "skip", reason: wallets.length + " wallet rows" };
  const balance = wallets.length ? Number(wallets[0].balance) : null;
  if (rows.length === 2 && rows.filter(isSignupRow).length === 1 && rows.filter(isClawbackRow).length === 1 && balance === 0) {
    return { action: "done", reason: "already cleared: the signup grant and one clawback, balance 0" };
  }
  if (balance !== AMOUNT) return { action: "skip", reason: "balance is " + balance + ", not exactly " + AMOUNT };
  if (rows.length !== 1 || !isSignupRow(rows[0])) {
    return { action: "skip", reason: "the ledger is not the signup grant alone (" + rows.length + " row(s): " +
      rows.map(r => r.type + " " + r.amount + " " + JSON.stringify(r.description)).join("; ") + ")" };
  }
  return { action: "debit", reason: "free, balance 1000, only the signup grant" };
}

/* deps: { supabase, planFor(id) -> getUserPlan answer, ownerId, accounts?, apply, log } */
async function runClawback(deps) {
  const log = deps.log || console.log;
  const accounts = deps.accounts || ACCOUNTS;
  const out = { debited: [], done: [], skipped: [], failed: [] };
  log("p31cClawback: " + (deps.apply ? "APPLY (writes)" : "DRY RUN (reads only, writes nothing)") + ", " + accounts.length + " account(s)");
  for (const id of accounts) {
    const a = { isOwner: id === deps.ownerId };
    if (!a.isOwner) {
      try {
        const plan = await deps.planFor(id);
        a.member = !!(plan && plan.active === true);
        a.accessReason = plan && plan.access_reason;
      } catch (e) { a.planError = (e && e.message) || String(e); }
      if (!a.member && !a.planError) {
        const w = await deps.supabase.from("user_wallets").select("balance").eq("user_id", id);
        const t = await deps.supabase.from("wallet_transactions").select("type, amount, description, created_at").eq("user_id", id);
        if (w.error || t.error) a.readError = (w.error || t.error).message;
        a.wallets = w.data || [];
        a.rows = t.data || [];
      }
    }
    const d = decide(a);
    const head = "  " + id + "  ";
    if (d.action === "skip") { out.skipped.push({ id, reason: d.reason }); log(head + "SKIPPED: " + d.reason); continue; }
    if (d.action === "done") { out.done.push(id); log(head + "already done: " + d.reason); continue; }
    if (!deps.apply) { out.debited.push(id); log(head + "would debit " + AMOUNT + " BFC (" + CLAWBACK + "): " + d.reason); continue; }
    const r = await deps.supabase.rpc("bfc_debit", { p_user_id: id, p_amount: AMOUNT, p_description: CLAWBACK });
    if (r.error && r.error.code === "23505") { out.done.push(id); log(head + "already done: the clawback index refused a second debit (23505)"); continue; }
    if (r.error) { out.failed.push({ id, reason: r.error.message }); log(head + "FAILED: " + r.error.message + " (one transaction: nothing written)"); continue; }
    out.debited.push(id);
    log(head + "debited " + AMOUNT + " BFC (" + CLAWBACK + ")");
  }
  log("summary: " + (deps.apply ? "debited " : "would debit ") + out.debited.length + ", already done " + out.done.length +
    ", skipped " + out.skipped.length + ", failed " + out.failed.length);
  return out;
}

module.exports = { ACCOUNTS, AMOUNT, SIGNUP, CLAWBACK, decide, runClawback };

if (require.main === module) {
  (async () => {
    require("dotenv").config({ path: require("path").join(__dirname, "..", "..", ".env") });
    const apply = process.argv.includes("--apply");
    // The server's own tier answer. Loading server.js starts it as the checks do; this process exits when done.
    const server = require("../../server.js");
    const { createClient } = require("@supabase/supabase-js");
    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY);
    const { OWNER_ACCOUNT_ID } = require("../../lib/ownerAccount");
    const out = await runClawback({ supabase, planFor: (id) => server.__selfReviewPlanFor(id), ownerId: OWNER_ACCOUNT_ID, apply });
    process.exit(out.failed.length ? 1 : 0);
  })().catch((e) => { console.error("p31cClawback FAILED: " + ((e && e.message) || e)); process.exit(1); });
}
