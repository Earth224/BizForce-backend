/* ══════════════════════════════════════════════════════════════════════════
   checkRoutineStepCap.js — a routine gets its own ceiling, and the run-time
   half agrees with the save-time half.

   THE DEFECT. A routine was capped at 3 steps because routineMaxSteps() was
   Math.min(CHAIN_MAX_CALLS, CHAIN_MAX_FANOUT). CHAIN_MAX_FANOUT exists to stop
   ONE STEP dispatching a spray of tools it chose itself; a routine is a list a
   person typed, reviewed and saved. The steps of a routine share a chain id and
   a depth, so they landed in one fan-out bucket and were refused at the fourth.

   WHAT THIS PROVES

     1. A 10-step routine SAVES.
     2. An 11-step routine is refused, and the message names ROUTINE_MAX_STEPS
        rather than a borrowed limit.
     3. A 10-step routine RUNS all ten steps, with no chain_fanout_reached
        anywhere — the save cap and the run-time behaviour agree, which is the
        whole point. Before this change step 4 was refused every time.
     4. The per-minute ceiling on dispatched steps refuses the right call and
        says why. Dispatched steps bypass aiLimiter, so without this the step
        cap was standing in for a rate limit.
     5. Every step that ran is in model_calls, so the 250-a-day ceiling counts
        them exactly as it counts a button press.

   AND WHAT IT PROVES IS STILL TRUE: CHAIN_MAX_FANOUT is untouched and still
   refuses the fourth dispatch of any chain that is NOT a user-authored
   sequence. That is the mutation, below — it is not enough to show routines got
   through; it has to be shown that everything else did not.

   MUTATE=fanout-counts dispatches four times WITHOUT sequence:true, which is
   how every model-originated chain still arrives. The fourth must be refused
   with chain_fanout_reached. If it is not, the exemption was written too wide
   and fan-out has been disabled for everyone.

   ENABLE_AGENT_CHAINING is set to "true" for this process only — dispatch
   refuses outright otherwise, and the thing under test is what happens after
   that gate. Fixtures live under the subject account and are removed with a
   verified read-back; the owner's routine is read for contrast, never written.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

/* Before server.js loads: the dispatcher's own gate, and a rate ceiling low
   enough to be reached inside one routine run. Both are read at call time, so
   the second is re-set per scenario below. */
process.env.ENABLE_AGENT_CHAINING = "true";

const path = require("path");
const REPO = path.join(__dirname, "..");

const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);
let modelCalls = 0;

function FakeAnthropic(options) {
  const instance = new RealAnthropic({ apiKey: "sk-ant-stub", timeout: 1000 });
  instance.messages = {
    create: async function (args) {
      modelCalls++;
      return {
        id: "msg_check_" + modelCalls,
        model: (args && args.model) || "stubbed",
        /* The shape email/subject-lines actually parses: "subject | angle" per
           line, read off the route's own parse rather than guessed. An earlier
           draft returned "SUBJECT: one"; every step 502'd, the routine stopped at
           step one, and the ten-step case went untested. */
        content: [{ type: "text", text: "Your order is ready | urgency\nA quick question about your setup | curiosity\nThree ideas for this week | value" }],
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

/* THE ACTOR HAS TO BE ENTITLED, WHICH THE SUBJECT ACCOUNT IS NOT.
   dispatchToolCall re-applies the entitlement gate for every step — the
   middleware is bypassed on that path, so it checks getUserPlan itself and
   fails closed. The designated check account has no subscription, so every step
   of every routine it owns is refused "not_entitled" before fan-out or rate is
   ever reached, and none of what this file tests would be exercised.

   So the actor is discovered at run time: an account with an ACTIVE
   subscription that is not an admin, the same way
   scripts/checkSelfReviewEntitlement.js picks one. resolveSubjectAccount() is
   still called first and still does its job — it enforces that
   BIZFORCE_CHECK_USER_ID is set and refuses the owner outright — and the guard
   below is built around the actor so every row this run writes is owned,
   recorded and removed.

   routines has a user_id, so the guard can own it outright alongside the two
   spend tables, unlike the marketplace tables which key on seller_id. */
let ACTOR_USER_ID = null;
let residue = null;

const MUTATING = process.env.MUTATE === "fanout-counts";

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const stamp = Date.now();

function steps(n) {
  const out = [];
  for (let i = 1; i <= n; i++) {
    out.push({ agent: "email", tool: "subject-lines", inputs: { purpose: "Check fixture step " + i } });
  }
  return out;
}

function callRoute(routePath, method, req) {
  const layer = app._router.stack.filter(function (l) {
    return l.route && l.route.path === routePath && l.route.methods[method];
  })[0];
  if (!layer) throw new Error("route not mounted: " + routePath);
  const stack = layer.route.stack;
  /* requireAuth / requireActiveSubscription / aiLimiter are skipped: the user
     is supplied directly, and what is under test is everything after them. */
  const handler = stack[stack.length - 1].handle;
  return new Promise(function (resolve) {
    let done = false;
    const fin = function (r) { if (!done) { done = true; resolve(r); } };
    const res = {
      statusCode: 200,
      status: function (c) { this.statusCode = c; return this; },
      json: function (p) { fin({ status: this.statusCode, body: p }); return this; }
    };
    Promise.resolve()
      .then(function () { return handler(req, res, function (e) { fin({ status: 500, body: { error: String(e) } }); }); })
      .catch(function (e) { fin({ status: 500, body: { error: String(e) } }); });
  });
}

async function ledgerCountSince(sinceIso) {
  const r = await supabase.from("model_calls").select("id, route")
    .eq("user_id", ACTOR_USER_ID).gte("created_at", sinceIso);
  (r.data || []).forEach(function (row) { residue.record("model_calls", row.id); });
  return (r.data || []).length;
}

async function noteRoutine(id) { if (id) residue.record("routines", id); }

(async function main() {
  const usersResult = await supabase.from("users").select("id, email, role");
  if (usersResult.error) throw usersResult.error;
  const subsResult = await supabase.from("subscriptions").select("user_id, status");
  if (subsResult.error) throw subsResult.error;
  const activeSubs = (subsResult.data || [])
    .filter(function (r) { return ["active", "trialing"].indexOf(r.status) !== -1; })
    .map(function (r) { return r.user_id; });
  const actor = (usersResult.data || []).filter(function (u) {
    return activeSubs.indexOf(u.id) !== -1 && String(u.role).toLowerCase() !== "admin";
  })[0];
  if (!actor) {
    console.error("No non-admin account with an active subscription to run a routine as. " +
      "Every dispatch would be refused not_entitled and nothing here would be tested.");
    process.exit(1);
  }

  ACTOR_USER_ID = actor.id;
  residue = createResidueGuard({
    supabase: supabase,
    name: "routineStepCap",
    subject: ACTOR_USER_ID,
    tables: ["ai_tasks", "model_calls", "routines"]
  });
  residue.install();
  await residue.sweepPrevious(ACTOR_USER_ID);

  console.log("\n══ who this runs as ══");
  console.log("    env subject (unentitled, not used as the actor): " + SUBJECT_USER_ID);
  console.log("    actor, entitled                                : " + ACTOR_USER_ID + "  (" + actor.email + ")");

  console.log("\n══ the limits in force ══");
  console.log("    ROUTINE_MAX_STEPS        : " + server.__routineMaxSteps());
  console.log("    ROUTINE_STEPS_PER_MINUTE : " + server.__dispatchPerMinuteLimit());
  check("the routine cap is 10, not the old borrowed 3", server.__routineMaxSteps() === 10,
    String(server.__routineMaxSteps()));

  const ownerRoutines = await supabase.from("routines")
    .select("id", { count: "exact", head: true }).neq("user_id", ACTOR_USER_ID);
  console.log("    routines not belonging to the subject: " + ownerRoutines.count + " (read only)");

  try {
    /* ── 1. a 10-step routine saves ────────────────────────────────────── */
    console.log("\n══ 1. saving a 10-step routine ══");
    const save10 = await callRoute("/api/routines", "post", {
      user: { id: ACTOR_USER_ID },
      body: { name: "CHECK 10-step " + stamp, steps: steps(10) },
      params: {}, query: {}, headers: {}
    });
    check("a 10-step routine saves", save10.status === 200 || save10.status === 201,
      save10.status + " " + JSON.stringify(save10.body).slice(0, 160));
    const routineId = save10.body && save10.body.routine && save10.body.routine.id;
    await noteRoutine(routineId);
    console.log("    routine id: " + routineId);

    /* ── 2. an 11-step routine is refused, naming the real limit ───────── */
    console.log("\n══ 2. saving an 11-step routine ══");
    const save11 = await callRoute("/api/routines", "post", {
      user: { id: ACTOR_USER_ID },
      body: { name: "CHECK 11-step " + stamp, steps: steps(11) },
      params: {}, query: {}, headers: {}
    });
    await noteRoutine(save11.body && save11.body.routine && save11.body.routine.id);
    console.log("    refusal: " + JSON.stringify(save11.body).slice(0, 220));
    check("an 11-step routine is refused", save11.status === 400, String(save11.status));
    check("the refusal names ROUTINE_MAX_STEPS, not a borrowed limit",
      !!(save11.body && save11.body.error && save11.body.error.indexOf("ROUTINE_MAX_STEPS") !== -1),
      save11.body && save11.body.error);
    check("and carries max_steps so the page can learn it",
      save11.body && save11.body.max_steps === 10, String(save11.body && save11.body.max_steps));

    /* ── 3. it runs all ten steps, with no fan-out refusal ─────────────── */
    console.log("\n══ 3. running the 10-step routine ══");
    process.env.ROUTINE_STEPS_PER_MINUTE = "120";   /* not what is under test here */
    const sinceRun = new Date(Date.now() - 2000).toISOString();
    modelCalls = 0;

    const run = await callRoute("/api/routines/:id/run", "post", {
      user: { id: ACTOR_USER_ID }, params: { id: routineId }, body: {}, query: {}, headers: {}
    });
    /* The run route returns its per-step results under "steps", not "outcomes" —
       read from the route rather than assumed. */
    const outcomes = (run.body && run.body.steps) || [];
    const ok = outcomes.filter(function (o) { return o.status === "ok"; });
    const fanoutRefusals = outcomes.filter(function (o) { return o.refused_reason === "chain_fanout_reached"; });

    console.log("    HTTP " + run.status + "; " + ok.length + " of " + outcomes.length + " step(s) ok");
    outcomes.slice(0, 12).forEach(function (o) {
      console.log("      step " + o.step + ": " + o.status +
        (o.refused_reason ? "  (" + o.refused_reason + ")" : ""));
    });

    check("all ten steps ran", ok.length === 10, ok.length + " ok of " + outcomes.length);
    check("no step was refused for fan-out", fanoutRefusals.length === 0,
      fanoutRefusals.length + " fan-out refusal(s)");
    check("the model was called once per step", modelCalls === 10, String(modelCalls));

    /* ── 5. the daily cap sees every one of them ───────────────────────── */
    const ledger = await ledgerCountSince(sinceRun);
    console.log("    model_calls rows written by the run: " + ledger);
    check("every step is in the ledger, so the 250/day cap counts it", ledger === 10, String(ledger));

    /* ── 4. the per-minute ceiling ─────────────────────────────────────── */
    console.log("\n══ 4. the per-minute ceiling on dispatched steps ══");
    process.env.ROUTINE_STEPS_PER_MINUTE = "3";
    console.log("    ROUTINE_STEPS_PER_MINUTE lowered to " + server.__dispatchPerMinuteLimit() +
      " for this scenario; the counter already holds this minute's dispatches.");

    const run2 = await callRoute("/api/routines/:id/run", "post", {
      user: { id: ACTOR_USER_ID }, params: { id: routineId }, body: {}, query: {}, headers: {}
    });
    const out2 = (run2.body && run2.body.steps) || [];
    const rateRefused = out2.filter(function (o) { return o.refused_reason === "dispatch_rate_reached"; });
    console.log("    first refused outcome: " + JSON.stringify(rateRefused[0] || out2[0] || null).slice(0, 240));
    check("the run was stopped by the rate ceiling", rateRefused.length >= 1,
      "no dispatch_rate_reached among " + out2.length + " outcome(s)");
    check("and the refusal explains itself",
      !!(rateRefused[0] && rateRefused[0].detail && rateRefused[0].detail.indexOf("ROUTINE_STEPS_PER_MINUTE") !== -1),
      rateRefused[0] && rateRefused[0].detail);
    await ledgerCountSince(sinceRun);
    process.env.ROUTINE_STEPS_PER_MINUTE = "120";

    /* ── the mutation: fan-out still guards everything else ────────────── */
    console.log("\n══ CHAIN_MAX_FANOUT still guards a non-sequence chain ══");
    console.log("    Four dispatches from one chain id at one depth, WITHOUT sequence:true —");
    console.log("    which is how every model-originated chain still arrives. The fourth must");
    console.log("    be refused, or the exemption was written too wide.");

    const crypto = require("crypto");
    const chainId = crypto.randomUUID();
    const results = [];
    for (let i = 0; i < 4; i++) {
      const d = await server.__dispatchToolCall({
        userId: ACTOR_USER_ID, agentType: "email", tool: "subject-lines",
        body: { purpose: "fan-out probe " + (i + 1) },
        chain: MUTATING
          ? { id: chainId, depth: 0, callsSoFar: i, sequence: true }
          : { id: chainId, depth: 0, callsSoFar: i }
      });
      results.push(d && d.ok === true ? "ok" : (d && d.refused_reason) || "failed");
    }
    await ledgerCountSince(sinceRun);
    console.log("    four dispatches: " + JSON.stringify(results));
    if (MUTATING) {
      console.log("\n    !! MUTATION: sequence:true was set on a chain that is not a routine, so the");
      console.log("       fourth dispatch is exempt. This assertion must go red.\n");
    }
    check("the fourth non-sequence dispatch is refused for fan-out",
      results[3] === "chain_fanout_reached", "results: " + JSON.stringify(results));
    check("and the first three were allowed", results.slice(0, 3).every(function (r) { return r === "ok"; }),
      JSON.stringify(results.slice(0, 3)));
  } finally {
    console.log("\n══ cleanup ══");
    const cleanupResult = await residue.cleanup("end of run");
    if (cleanupResult.leftovers.length) failures++;
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(async function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
