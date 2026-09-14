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
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
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

  if (process.env.MUTATE === "ungate") {
    server.__setSelfReviewPlanLookup(async function () {
      return { active: true, exempt: false, inactive_reason: null, access_reason: null };
    });
    console.log("\n!! MUTATION: the pass is told every account is entitled — the refusal checks must fail.");
  }

  console.log("\n══ subjects ══");
  const usersResult = await supabase.from("users").select("id, email, role");
  if (usersResult.error) throw usersResult.error;
  const subsResult = await supabase.from("subscriptions").select("user_id, status");
  if (subsResult.error) throw subsResult.error;

  const activeSubs = (subsResult.data || [])
    .filter(function (r) { return ["active", "trialing"].indexOf(r.status) !== -1; })
    .map(function (r) { return r.user_id; });

  const unentitled = (usersResult.data || []).filter(function (u) { return u.id === SUBJECT_USER_ID; })[0];
  const paying = (usersResult.data || []).filter(function (u) {
    return activeSubs.indexOf(u.id) !== -1 && String(u.role).toLowerCase() !== "admin";
  })[0];
  const admin = (usersResult.data || []).filter(function (u) { return String(u.role).toLowerCase() === "admin"; })[0];

  if (!unentitled) { console.error("subject " + SUBJECT_USER_ID + " is not in users"); process.exit(1); }
  if (!paying) { console.error("no non-admin account with an active subscription"); process.exit(1); }
  if (!admin) { console.error("no account with role admin"); process.exit(1); }

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

  /* THE ADMIN IS NOT ENROLLED BY THIS SCRIPT. It is a live account with
     thousands of real rows in it, and signing it up for a nightly pass to see
     what happens would be doing real work on somebody's account to satisfy a
     test.

     It is, however, already enrolled in analytics autonomy of its own accord,
     so the pass below really does process it — which makes the admin path a
     live observation rather than a simulation. Both halves are asserted: the
     answer getUserPlan gives for it, and the fact that the pass did not count
     it among the accounts it refused. */
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

  /* THE ADMIN IS ENROLLED AND WAS PROCESSED, so if the exemption were not
     honoured here it would show up as a second refusal. Exactly one account in
     this pass is unentitled — the subject — so exactly one refusal is the
     assertion that the admin (and the paying account) got through. */
  check("no entitled account was refused — the admin passed the gate",
    summary.skippedNotEntitled === 1, "skippedNotEntitled=" + summary.skippedNotEntitled +
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
