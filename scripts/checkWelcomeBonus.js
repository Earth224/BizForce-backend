/* ══════════════════════════════════════════════════════════════════════════
   checkWelcomeBonus.js — the 1,000 BFC welcome bonus is paid once, on the first
   subscription, and never at registration.

   THE CHANGE. Registration granted 1,000 BFC to every signup, before anyone
   could have paid: free BFC a free account could spend on BFC-priced listings
   or donate. Registration now creates the wallet at 0, and
   grantWelcomeBonusOnce pays the bonus from the checkout.session.completed
   activation branch — once per account, ever.

   WHAT THIS PROVES
     1. In source: registration creates the wallet at 0 and writes no bonus;
        the activation branch calls grantWelcomeBonusOnce; the grant reads the
        ledger before it writes.
     2. Against the real ledger, on the seed account (which has never had a
        wallet): the first grant pays 1,000 BFC and writes one "Welcome bonus"
        row; a second grant — a redelivered webhook, a second checkout, a
        lapsed subscriber resubscribing — pays nothing and writes nothing.
     3. An account that got the bonus at registration under the old code
        (clean-run-1) is not paid again: its balance and ledger are unchanged.
        Read and compared only; nothing is written to it.

   CLEANUP. The seed account must have no wallet and no bonus row when this
   starts, or the run refuses before writing. Everything written is then under
   the seed account and is removed at the end — the bonus rows and the wallet —
   and read back; anything left is a failure. A crash leaves at most one wallet
   and two ledger rows under the seed account, named in the error.

   MUTATE=grant-twice     removes the ledger read from grantWelcomeBonusOnce at
                          compile time. Section 1's read check and section 2's
                          second-grant checks must go red. Section 3 is skipped
                          under this mutation, so a fixture account is never
                          paid by it.
   MUTATE=register-grant  puts the 1,000 BFC back into registration's wallet
                          insert at compile time. Section 1 must go red.
   Nothing is written to server.js on disk.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { resolveSubjectAccount, resolveEntitledAccount, assertNotOwner } = require("./checkRunResidue");
resolveSubjectAccount();   // the suite's guard: refuses unless BIZFORCE_CHECK_USER_ID is set

const fs = require("fs");
const path = require("path");
const Module = require("module");
const { braceMatch } = require("./_shared");
const REPO = path.join(__dirname, "..");
const SERVER_PATH = path.join(REPO, "server.js");

const MUTATIONS = ["grant-twice", "register-grant"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

/* An account that got the bonus at registration under the old code. */
const LEGACY_BONUS_ACCOUNT = "5252d5e4-a643-4058-a247-85c6738ef796";   // clean-run-1@bizforceai.invalid

const EDITS = {
  "grant-twice": {
    from: '  if (prior.data && prior.data.length) {\n    return { granted: false, reason: "already_granted" };\n  }\n',
    to: "",
    say: "grantWelcomeBonusOnce no longer reads the ledger first — a second grant must pay again."
  },
  "register-grant": {
    from: '        user_id: user.id, balance: 0, currency: "BFC", updated_at: nowIso()\n',
    to: '        user_id: user.id, balance: 1000, currency: "BFC", updated_at: nowIso()\n',
    say: "registration creates the wallet with 1,000 BFC again."
  }
};
let compiledSource = null;
{
  const realCompile = Module.prototype._compile;
  Module.prototype._compile = function (content, filename) {
    if (path.resolve(filename) === path.resolve(SERVER_PATH)) {
      content = content.replace(/\r\n/g, "\n");
      if (MUTATE) {
        const edit = EDITS[MUTATE];
        const hits = content.split(edit.from).length - 1;
        if (hits !== 1) { console.error("MUTATION REFUSED: expected exactly one anchor, found " + hits); process.exit(1); }
        content = content.replace(edit.from, edit.to);
        console.error("\n!! MUTATION: " + edit.say);
      }
      compiledSource = content;
    }
    return realCompile.call(this, content, filename);
  };
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

process.env.PORT = process.env.CHECK_PORT || "0";
const quiet = console.log; console.log = function () {};
const server = require(SERVER_PATH);
console.log = quiet;

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);

function blockAfter(src, marker) {
  const at = src.indexOf(marker);
  if (at < 0) return "";
  const open = src.indexOf("{", at + marker.length - 1);
  return src.slice(open, braceMatch(src, open));
}

async function ledger(userId) {
  const w = await supabase.from("user_wallets").select("id, balance").eq("user_id", userId);
  if (w.error) throw new Error("wallet read: " + w.error.message);
  const t = await supabase.from("wallet_transactions").select("id, amount").eq("user_id", userId)
    .eq("type", "reward").eq("description", "Welcome bonus");
  if (t.error) throw new Error("ledger read: " + t.error.message);
  return { wallets: w.data || [], bonusRows: t.data || [], balance: (w.data && w.data[0]) ? w.data[0].balance : null };
}

let seedId = null;
async function cleanup() {
  if (!seedId) return true;
  assertNotOwner(seedId, "welcome-bonus cleanup was pointed at the owner's account");
  await supabase.from("wallet_transactions").delete().eq("user_id", seedId).eq("type", "reward").eq("description", "Welcome bonus");
  await supabase.from("user_wallets").delete().eq("user_id", seedId);
  const after = await ledger(seedId);
  const clean = after.wallets.length === 0 && after.bonusRows.length === 0;
  console.log("    read-back: seed wallets " + after.wallets.length + ", bonus rows " + after.bonusRows.length);
  return clean;
}
process.on("SIGINT", function () { cleanup().then(function () { process.exit(130); }); });

(async function main() {
  /* ── 1. in source ──────────────────────────────────────────────────── */
  console.log("\n══ 1. registration, the activation branch and the grant, in source ══");
  const src = compiledSource || "";
  const register = blockAfter(src, 'app.post("/api/auth/register"');
  check("1. registration creates the wallet at 0 BFC", /user_id: user\.id, balance: 0, currency: "BFC"/.test(register) && !/balance: 1000/.test(register),
    register ? "wallet insert not at 0" : "register route not found");
  check("1. registration writes no welcome-bonus row", register.length > 0 && !/description: "Welcome bonus"/.test(register));
  const stripeHandler = blockAfter(src, "async function handleStripeEvent(event) {");
  const checkoutBranch = blockAfter(stripeHandler, 'if (event.type === "checkout.session.completed") {');
  check("1. checkout.session.completed grants the bonus", /grantWelcomeBonusOnce\(userId\)/.test(checkoutBranch));
  const grantFn = blockAfter(src, "async function grantWelcomeBonusOnce(userId) {");
  check("1. the grant reads the ledger and stops when the bonus is already there",
    /\.eq\("description", WELCOME_BONUS_DESCRIPTION\)/.test(grantFn) && /if \(prior\.data && prior\.data\.length\) \{\s*return \{ granted: false, reason: "already_granted" \};/.test(grantFn));
  check("1. a duplicate refused by migration 129's index counts as already granted", /creditErr\.code === "23505"/.test(grantFn));

  /* ── 2. the seed account, twice ────────────────────────────────────── */
  console.log("\n══ 2. the first subscription pays; the second activation does not ══");
  const seed = await resolveEntitledAccount(supabase);
  assertNotOwner(seed.id, "the welcome-bonus subject is the owner's account");
  const before = await ledger(seed.id);
  if (before.wallets.length || before.bonusRows.length) {
    console.log("    REFUSING: the seed account already has " + before.wallets.length + " wallet(s) and " +
      before.bonusRows.length + " bonus row(s). Nothing was written. Remove them by hand if a previous run left them.");
    process.exit(1);
  }
  seedId = seed.id;
  try {
    const first = await server.__grantWelcomeBonusOnce(seed.id);
    const afterFirst = await ledger(seed.id);
    console.log("    first grant: " + JSON.stringify(first) + "; balance " + afterFirst.balance + ", bonus rows " + afterFirst.bonusRows.length);
    check("2. the first grant pays 1,000 BFC", first.granted === true && afterFirst.balance === 1000, JSON.stringify(first) + " balance " + afterFirst.balance);
    check("2. and writes exactly one Welcome bonus row", afterFirst.bonusRows.length === 1, afterFirst.bonusRows.length);

    const second = await server.__grantWelcomeBonusOnce(seed.id);
    const afterSecond = await ledger(seed.id);
    console.log("    second grant: " + JSON.stringify(second) + "; balance " + afterSecond.balance + ", bonus rows " + afterSecond.bonusRows.length);
    check("2. a second activation pays nothing (redelivery, second checkout, resubscription)",
      second.granted === false && second.reason === "already_granted", JSON.stringify(second));
    check("2. the balance is still 1,000 and there is still one bonus row",
      afterSecond.balance === 1000 && afterSecond.bonusRows.length === 1, "balance " + afterSecond.balance + ", rows " + afterSecond.bonusRows.length);

    /* ── 3. an account paid at registration under the old code ───────── */
    console.log("\n══ 3. an account that got the bonus at signup is not paid again ══");
    if (MUTATE === "grant-twice") {
      console.log("    skipped under MUTATE=grant-twice, so the fixture account is never paid by the mutation");
    } else {
      const legacyBefore = await ledger(LEGACY_BONUS_ACCOUNT);
      const legacy = await server.__grantWelcomeBonusOnce(LEGACY_BONUS_ACCOUNT);
      const legacyAfter = await ledger(LEGACY_BONUS_ACCOUNT);
      console.log("    clean-run-1: " + JSON.stringify(legacy) + "; balance " + legacyBefore.balance + " → " + legacyAfter.balance +
        ", bonus rows " + legacyBefore.bonusRows.length + " → " + legacyAfter.bonusRows.length);
      check("3. it already has the registration-era bonus row", legacyBefore.bonusRows.length === 1, legacyBefore.bonusRows.length);
      check("3. the grant declines and changes nothing",
        legacy.granted === false && legacy.reason === "already_granted" &&
        legacyAfter.balance === legacyBefore.balance && legacyAfter.bonusRows.length === legacyBefore.bonusRows.length,
        JSON.stringify(legacy));
    }
  } finally {
    console.log("\n══ cleanup ══");
    const clean = await cleanup();
    check("nothing this run wrote is left under the seed account", clean);
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(async function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  try { await cleanup(); } catch (e) { console.error("cleanup after the throw failed: " + (e && e.message)); }
  process.exit(1);
});
