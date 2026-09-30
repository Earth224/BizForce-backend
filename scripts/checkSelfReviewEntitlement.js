/* ══════════════════════════════════════════════════════════════════════════
   checkSelfReviewEntitlement.js — the nightly self-review pass, and the proof
   it no longer spends on accounts that are not paying.

   WHAT WAS WRONG. runSelfReviewPass selected its users from agent_autonomy
   where enabled = true. That is CONSENT — "my agents may act on their own" —
   and it says nothing about whether the account is paying for them.
   POST /api/self-reviews/run sits behind requireActiveSubscription, but this
   pass never goes near that route: it calls generateSelfReview directly. So an
   account that never subscribed, or subscribed once and lapsed, kept getting a
   model call every night on the platform's key for as long as its autonomy row
   stayed switched on.

   HOW THIS TESTS IT. The pass is not a route and cannot be driven with a
   request, so this drives the real exported function: it enrols two accounts in
   agent_autonomy — one entitled, one not — runs runSelfReviewPass, and reads
   back what each of them spent. A re-implementation of the pass would prove
   only that the re-implementation is gated.

   THE ANTHROPIC SDK IS STUBBED, so the generation that SHOULD happen costs
   nothing and is counted rather than billed. The ledger row it writes is real,
   which is the point: "the unentitled account wrote zero model_calls rows"
   is then a measurement of the same table the invoice comes from.

   EVERY ROW THIS SCRIPT CAUSES IS REMOVED AGAIN, under both accounts, on every
   way out including a crash. Two residue guards rather than one, because a
   guard deletes only rows belonging to its own subject — correctly refusing
   anything else — and this check necessarily writes under two accounts. The
   agent_autonomy enrolments are restored by hand, since those are rows this
   script MODIFIED rather than created.

   MUTATE=ungate replaces the pass's plan lookup with one that says everybody is
   entitled — which is exactly how the pass behaved before this commit — and the
   refusal assertions must go red. A suite nobody has watched fail is a claim
   about itself rather than about the code.

   THE PASS IS KEPT TO THIS SCRIPT'S TWO ACCOUNTS. runSelfReviewPass takes every
   account with analytics autonomy on, and the owner has it on; the owner is
   admin-exempt, so the pass used to generate for them too, with the stub's
   text. It never did only because production had always written that period's
   review first — but run between a period's end and production's 07:00 pass,
   this check would have written the owner's monthly review itself, and
   production would then have skipped the period as done. The plan lookup the
   pass asks before any write now refuses every account but the subject and the
   seed account (checkRunResidue.js, passScope), under MUTATE as well, and the
   owner's self_reviews and model_calls counts are asserted unchanged.

   The entitled account is the seed account, found by email
   (resolveEntitledAccount) — never the first entitled account a read returns.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount, resolveEntitledAccount, passScope, refuseEveryPlan,
  OWNER_ACCOUNT_ID } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const path = require("path");
const REPO = path.join(__dirname, "..");

const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);
let modelCalls = [];

function FakeAnthropic(options) {
  const instance = new RealAnthropic(options);
  instance.messages = {
    create: async function (args) {
      modelCalls.push({ model: (args && args.model) || "stubbed" });
      return {
        id: "msg_check_" + modelCalls.length,
        model: (args && args.model) || "stubbed",
        content: [{ type: "text", text: "Stubbed narrative for the entitlement check." }],
        stop_reason: "end_turn",
        usage: { input_tokens: 1, output_tokens: 1 }
      };
    }
  };
  return instance;
}
Object.keys(RealAnthropic).forEach(function (k) { FakeAnthropic[k] = RealAnthropic[k]; });
require.cache[SDK_PATH].exports = FakeAnthropic;

const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () {
  const made = realExpress.apply(this, arguments);
  if (!app) app = made;
  return made;
};
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;

process.env.PORT = process.env.CHECK_PORT || "0";
const server = require(path.join(REPO, "server.js"));
/* Before anything else can run: until the two accounts are known, every
   account is out of scope for every pass. */
server.__setPassPlanLookup(refuseEveryPlan);

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

const SPEND_TABLES = ["ai_tasks", "model_calls", "self_reviews"];

/* The subject account's guard, built before anything else so a previous
   crashed run is swept before this one writes. */
const residue = createResidueGuard({
  supabase: supabase,
  name: "selfReviewEntitlement",
  subject: SUBJECT_USER_ID,
  tables: SPEND_TABLES
});
residue.install();

let payingResidue = null;   /* built once the entitled account is discovered */

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const SELF_REVIEW_AGENT_TYPE = "analytics";
const enrolled = [];

async function enrol(userId) {
  const existing = await supabase.from("agent_autonomy")
    .select("enabled").eq("user_id", userId)
    .eq("agent_type", SELF_REVIEW_AGENT_TYPE).maybeSingle();
  if (existing.error) throw new Error("autonomy read failed for " + userId + ": " + existing.error.message);

  if (existing.data) {
    enrolled.push({ userId: userId, restore: existing.data.enabled, existed: true });
    const up = await supabase.from("agent_autonomy").update({ enabled: true })
      .eq("user_id", userId).eq("agent_type", SELF_REVIEW_AGENT_TYPE);
    if (up.error) throw new Error("could not enable autonomy for " + userId + ": " + up.error.message);
    return;
  }

  const ins = await supabase.from("agent_autonomy")
    .insert({ user_id: userId, agent_type: SELF_REVIEW_AGENT_TYPE, enabled: true });
  if (ins.error) throw new Error("could not enrol " + userId + ": " + ins.error.message);
  enrolled.push({ userId: userId, restore: null, existed: false });
}

/* Restored to exactly what was there before, which for a row this script
   created means removing it. An enrolment left switched on would be this check
   quietly signing an account up for nightly model calls. */
async function unenrol() {
  for (const e of enrolled) {
    if (e.existed) {
      await supabase.from("agent_autonomy").update({ enabled: e.restore })
        .eq("user_id", e.userId).eq("agent_type", SELF_REVIEW_AGENT_TYPE);
    } else {
      await supabase.from("agent_autonomy").delete()
        .eq("user_id", e.userId).eq("agent_type", SELF_REVIEW_AGENT_TYPE);
    }
  }
  console.log("[fixture] agent_autonomy: " + enrolled.length + " enrolment(s) restored to what they were");
}

async function countsFor(userId) {
  const out = {};
  for (const t of SPEND_TABLES) {
    const r = await supabase.from(t).select("id", { count: "exact", head: true }).eq("user_id", userId);
    out[t] = r.count;
  }
  return out;
}

/* Hands every row the pass just wrote to the guard that owns that account. */
async function recordNewRows(guard, userId, sinceIso) {
  for (const t of SPEND_TABLES) {
    const r = await supabase.from(t).select("id").eq("user_id", userId).gte("created_at", sinceIso);
    (r.data || []).forEach(function (row) { guard.record(t, row.id); });
  }
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  if (typeof server.__runSelfReviewPass !== "function") {
    console.error("server.js does not export __runSelfReviewPass — this check cannot drive the pass.");
    process.exit(1);
  }

  const UNGATED = process.env.MUTATE === "ungate";
  if (UNGATED) {
    console.log("\n!! MUTATION: the pass is told every account is entitled — the refusal checks must fail.");
  }

  console.log("\n══ subjects ══");
  const usersResult = await supabase.from("users").select("id, email, role");
  if (usersResult.error) throw usersResult.error;

  const unentitled = (usersResult.data || []).filter(function (u) { return u.id === SUBJECT_USER_ID; })[0];
  /* The seed account, by email. Refuses and exits — no search — if it is not. */
  const paying = await resolveEntitledAccount(supabase);
  const admin = (usersResult.data || []).filter(function (u) { return String(u.role).toLowerCase() === "admin"; })[0];

  if (!unentitled) { console.error("subject " + SUBJECT_USER_ID + " is not in users"); process.exit(1); }
  if (!admin) { console.error("no account with role admin"); process.exit(1); }

  /* The pass may reach these two and nobody else. Under MUTATE=ungate the two
     are told they are entitled; everyone else is still refused. */
  const scope = passScope([unentitled.id, paying.id], UNGATED
    ? async function () { return { active: true, exempt: false, inactive_reason: null, access_reason: null }; }
    : function (userId) { return server.__selfReviewPlanFor(userId); });
  server.__setPassPlanLookup(scope.lookup);

  console.log("  unentitled : " + unentitled.id + "  (" + unentitled.email + ")");
  console.log("  paying     : " + paying.id + "  (" + paying.email + ")");
  console.log("  admin      : " + admin.id + "  (" + admin.email + ", role " + admin.role + ")");

  payingResidue = createResidueGuard({
    supabase: supabase,
    name: "selfReviewEntitlement-entitled",
    subject: paying.id,
    tables: SPEND_TABLES
  });
  payingResidue.install();
  await payingResidue.sweepPrevious(paying.id);

  /* THE ADMIN IS NOT ENROLLED BY THIS SCRIPT, AND THE PASS DOES NOT REACH IT.
     It is a live account with thousands of real rows in it. It is enrolled in
     analytics autonomy of its own accord, so the unscoped pass processed it —
     and, being exempt, generated for it with the stub's text. The scope above
     turns it away before any write. Its exemption is still asserted here, from
     the plan lookup the pass would have used; that is a read. */
  console.log("\n══ the entitlement answer each account gets ══");
  const planUnentitled = await server.__selfReviewPlanFor(unentitled.id);
  const planPaying = await server.__selfReviewPlanFor(paying.id);
  const planAdmin = await server.__selfReviewPlanFor(admin.id);
  check("the unentitled account is not entitled", planUnentitled && planUnentitled.active !== true,
    planUnentitled && ("active=" + planUnentitled.active + " reason=" + planUnentitled.inactive_reason));
  check("the paying account is entitled", planPaying && planPaying.active === true,
    planPaying && ("active=" + planPaying.active));
  check("the admin passes by exemption, so gating this pass does not lock the owner out",
    planAdmin && planAdmin.active === true && planAdmin.exempt === true && planAdmin.access_reason === "admin",
    planAdmin && ("active=" + planAdmin.active + " exempt=" + planAdmin.exempt));

  const before = { unentitled: await countsFor(unentitled.id), paying: await countsFor(paying.id) };
  const ownerBefore = await countsFor(OWNER_ACCOUNT_ID);
  console.log("\n══ row counts BEFORE ══");
  Object.keys(before).forEach(function (k) {
    console.log("  " + k.padEnd(11) + "  " + SPEND_TABLES.map(function (t) {
      return t + ": " + before[k][t];
    }).join("   "));
  });

  const startedAt = new Date(Date.now() - 2000).toISOString();

  console.log("\n══ enrolling both accounts in agent_autonomy ══");
  await enrol(unentitled.id);
  await enrol(paying.id);
  console.log("  both now have " + SELF_REVIEW_AGENT_TYPE + " autonomy enabled — consent, which is all the");
  console.log("  pass used to ask for.");

  console.log("\n══ running the real nightly pass ══");
  const summary = await server.__runSelfReviewPass();
  await recordNewRows(residue, unentitled.id, startedAt);
  await recordNewRows(payingResidue, paying.id, startedAt);
  console.log("  summary: " + JSON.stringify(summary));

  console.log("\n══ what the pass reported ══");
  check("it saw both enrolled accounts", summary.users >= 2, "users=" + summary.users);
  check("the summary has a skippedNotEntitled field at all",
    Object.prototype.hasOwnProperty.call(summary, "skippedNotEntitled"), Object.keys(summary).join(", "));
  check("at least one account was skipped for no active subscription",
    summary.skippedNotEntitled >= 1, "skippedNotEntitled=" + summary.skippedNotEntitled);

  /* Every account the pass saw beyond these two was turned away by the scope,
     and of the two, exactly one was refused by the gate: the unentitled
     subject. The paying account got through. */
  console.log("  turned away by the scope: " + scope.refused.size + " account(s)" +
    (scope.refused.has(OWNER_ACCOUNT_ID) ? ", the owner among them" : ""));
  check("every account beyond this script's two was refused by the scope, before any write",
    summary.users - 2 === scope.refused.size && !scope.refused.has(unentitled.id) && !scope.refused.has(paying.id),
    "users=" + summary.users + " refused by scope=" + scope.refused.size);
  check("of this script's two, only the unentitled subject was refused by the gate",
    summary.skippedNotEntitled - scope.refused.size === 1,
    "skippedNotEntitled=" + summary.skippedNotEntitled + " minus " + scope.refused.size + " refused by scope" +
    " (expected exactly 1: only the unentitled subject)");

  const after = { unentitled: await countsFor(unentitled.id), paying: await countsFor(paying.id) };
  console.log("\n══ row counts AFTER ══");
  Object.keys(after).forEach(function (k) {
    console.log("  " + k.padEnd(11) + "  " + SPEND_TABLES.map(function (t) {
      return t + ": " + after[k][t] + " (" + (after[k][t] - before[k][t] >= 0 ? "+" : "") + (after[k][t] - before[k][t]) + ")";
    }).join("   "));
  });

  console.log("\n══ the unentitled account spent nothing ══");
  check("zero ai_tasks rows written", after.unentitled.ai_tasks === before.unentitled.ai_tasks,
    before.unentitled.ai_tasks + " → " + after.unentitled.ai_tasks);
  check("zero model_calls rows written", after.unentitled.model_calls === before.unentitled.model_calls,
    before.unentitled.model_calls + " → " + after.unentitled.model_calls);
  check("no self_reviews row written — nothing is recorded as run that did not run",
    after.unentitled.self_reviews === before.unentitled.self_reviews,
    before.unentitled.self_reviews + " → " + after.unentitled.self_reviews);

  console.log("\n══ the entitled account was reviewed ══");
  check("it got at least one self_reviews row",
    after.paying.self_reviews > before.paying.self_reviews,
    before.paying.self_reviews + " → " + after.paying.self_reviews);
  check("a model call was made for it", modelCalls.length >= 1, "model calls: " + modelCalls.length);
  check("and it was billed, so the gate did not suppress real work",
    after.paying.model_calls > before.paying.model_calls,
    before.paying.model_calls + " → " + after.paying.model_calls);

  /* The tripwire. If a change widens the pass past the scope, the owner's
     review is what it displaces; this is where that would show. */
  const ownerAfter = await countsFor(OWNER_ACCOUNT_ID);
  console.log("\n══ the owner's account ══");
  console.log("  " + SPEND_TABLES.map(function (t) { return t + ": " + ownerBefore[t] + " → " + ownerAfter[t]; }).join("   "));
  check("the owner's self_reviews count is unchanged", ownerAfter.self_reviews === ownerBefore.self_reviews,
    ownerBefore.self_reviews + " → " + ownerAfter.self_reviews);
  check("the owner's model_calls count is unchanged", ownerAfter.model_calls === ownerBefore.model_calls,
    ownerBefore.model_calls + " → " + ownerAfter.model_calls);

  console.log("\n══ cleanup ══");
  await unenrol();
  const mine = await residue.cleanup("end of run");
  const theirs = await payingResidue.cleanup("end of run");
  if (mine.leftovers.length || theirs.leftovers.length) failures++;

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(async function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  try { await unenrol(); } catch (e) { /* the guards still run on the way out */ }
  process.exit(1);
});
