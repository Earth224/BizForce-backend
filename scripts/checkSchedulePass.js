"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkSchedulePass.js — a scheduled agent run does not outlive the
   subscription that paid for it.

   WHY THIS IS A CHECK. ENABLE_AGENT_SCHEDULES is "true" in production (read
   from Railway, 2026-10-04), so runAgentSchedulePass runs there every hour.
   Nothing else covers it. This was scripts/schedule-runner.test.js, which
   already proved the right things, but nothing ran it.

   WHAT THIS PROVES. The REAL runAgentSchedulePass and its due-ness helpers,
   extracted from server.js by brace-matching and run in a vm context:
     a. due, autonomy on, entitled: runs once, last_run_on written
     b. not entitled: not run, not stamped, one log naming why
     c. getUserPlan throws or returns null: FAILS CLOSED, not run
     d. the admin exemption runs
     e. an unentitled schedule does not use up the per-tick ceiling
     f. one plan lookup per user per pass, including when it throws
     g. autonomy off: not run, and the plan is never looked up

   ⚠️ THE DATABASE IS FAKE. Supabase, getUserPlan and runScheduledAgentTask
   are stubs shaped like the calls the function makes today. A renamed column,
   a changed table or a different query shape in agent_schedules or
   agent_autonomy would NOT be caught here; this proves the pass's decisions,
   not its reads. No network, no database, no BIZFORCE_CHECK_USER_ID needed.

   MUTATE=gate   removes the `entitlement.plan.active !== true` refusal from the
                 extracted pass, in memory. b and e must go red: an unentitled
                 account's schedule runs. Nothing is written to server.js.

   PINS CHANGED BY MIGRATION 143 (schedule outcomes, pause), each named:
     PIN a.write   BEFORE: the one write on s1 was exactly { last_run_on }.
                   AFTER:  the one write on s1 is { last_run_on, last_run_status
                           "succeeded", last_error null, last_task_id null,
                           consecutive_failures 0, last_attempt_at NOW }: the
                           runner records the outcome in the same write.
     PIN stamps    BEFORE: `stamps` was every agent_schedules update.
                   AFTER:  `stamps` is every update that sets last_run_on (the
                           thing b, c, c2, d, e and g assert about), and
                           `writes` is every update. A skip now writes its
                           outcome, so "no update at all" is no longer the
                           test for "not run"; "no last_run_on" is.
     PIN context   BEFORE: the vm held the five extracted functions.
                   AFTER:  it also holds AGENT_SCHEDULE_FAILURES_TO_PAUSE and
                           AGENT_SCHEDULE_SKIP_TEXT, extracted the same way, and
                           an opsAlerts stub. The new behaviour (outcomes,
                           pause, lapse) is proved in checkScheduleControl.js.
     NEW b/c/c2/g  each skip records its own status and words on its own row.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const assert = require("assert");

const MUTATIONS = ["gate"];
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

const REPO = path.join(__dirname, "..");
const src = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");

function extract(signature) {
  const start = src.indexOf(signature);
  assert(start > 0, signature + " not found");
  let depth = 0, i = src.indexOf("{", start), end = -1;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  return src.slice(start, end);
}

function extractLine(prefix) {
  const start = src.indexOf(prefix);
  assert(start > 0, prefix + " not found");
  return src.slice(start, src.indexOf("\n", start));
}

let code = [extractLine("var AGENT_SCHEDULE_FAILURES_TO_PAUSE = "), extract("var AGENT_SCHEDULE_SKIP_TEXT = {") + ";"].join("\n") + "\n\n" + [
  "function agentScheduleUtcDay(now) {",
  "function agentScheduleDaysInUtcMonth(now) {",
  "function agentScheduleEffectiveMonthDay(dayOfMonth, now) {",
  "function agentScheduleIsDue(row, now) {",
  "async function runAgentSchedulePass(now, maxPerTick) {"
].map(extract).join("\n\n");

if (MUTATE === "gate") {
  const GATE = "    if (entitlement.plan.active !== true) {\n";
  code = MUT.replaceOnce(code, GATE, "    if (false) {\n", "gate");
  console.log("\n!! MUTATION: the entitlement gate is gone from runAgentSchedulePass — an unentitled schedule must now run.");
}

const NOW = new Date("2026-09-11T09:00:00.000Z");   // hour 9, a Friday
function sched(id, userId, agent) {
  return { id, user_id: userId, agent_type: agent || "seo", task_type: "general",
           prompt: "p", cadence: "daily", hour_utc: 9, day_of_week: null, day_of_month: null,
           enabled: true, last_run_on: null };
}

/* opts: { schedules, autonomy:[{user_id,agent_type}], plans:{userId: result|Error|null}, maxPerTick } */
async function runTick(opts) {
  const logs = [], runs = [], writes = [], planCalls = [];
  const fakeSupabase = {
    from(name) {
      if (name === "agent_schedules") {
        return {
          select() { return { eq() { return { eq() { return { or: async () => ({ data: opts.schedules, error: null }) }; } }; } }; },
          update(payload) { return { eq: async (col, val) => { writes.push({ payload, where: [col, val] }); return { error: null }; } }; }
        };
      }
      if (name === "agent_autonomy") {
        return { select() { return { eq() { return { in() { return { in: async () => ({ data: opts.autonomy, error: null }) }; } }; } }; } };
      }
      throw new Error("unexpected table " + name);
    }
  };
  const ctx = {
    supabase: fakeSupabase,
    console: { log: (m) => logs.push(["log", String(m)]), error: (m) => logs.push(["error", String(m)]), warn: (m) => logs.push(["warn", String(m)]) },
    AGENT_SYSTEM_PROMPTS: { seo: "x", content: "x", executive: "x" },
    allowedTaskTypes: ["general"],
    getUserPlan: async (userId) => {
      planCalls.push(userId);
      const r = opts.plans[userId];
      if (r instanceof Error) throw r;
      return r;
    },
    runScheduledAgentTask: async (schedule) => { runs.push(schedule.id); return { ok: true, status: 202, payload: {} }; },
    opsAlerts: { scheduleAutoPaused: async () => ({ sent: false, reason: "stub" }) }
  };
  vm.createContext(ctx);
  vm.runInContext(code + "\nthis.runAgentSchedulePass = runAgentSchedulePass;", ctx);
  const summary = await ctx.runAgentSchedulePass(NOW, opts.maxPerTick == null ? 25 : opts.maxPerTick);
  const all = JSON.parse(JSON.stringify(writes));
  return { logs, runs, writes: all, stamps: all.filter(w => "last_run_on" in w.payload), planCalls, summary: JSON.parse(JSON.stringify(summary)) };
}

// The one outcome write on a schedule, or a failure naming what was there.
function outcomeOf(r, id) {
  const mine = r.writes.filter(w => w.where[1] === id);
  assert.strictEqual(mine.length, 1, id + " writes: " + JSON.stringify(mine));
  return mine[0].payload;
}

const ENTITLED = { plan: "all_access", active: true, inactive_reason: null, exempt: false };
const LAPSED   = { plan: "all_access", active: false, inactive_reason: "status", exempt: false };
const ADMIN    = { plan: "admin_exempt", active: true, inactive_reason: null, exempt: true, access_reason: "admin" };

let failures = 0;
async function t(name, fn) {
  try { await fn(); console.log("    pass  " + name); }
  catch (e) { failures++; console.log("    FAIL  " + name + "  [" + e.message + "]"); }
}

(async () => {
  console.log("\n══ runAgentSchedulePass, extracted from server.js (fake database) ══");
  await t("a) due, autonomy on, entitled: runs once, last_run_on written", async () => {
    const r = await runTick({ schedules: [sched("s1", "uA")], autonomy: [{ user_id: "uA", agent_type: "seo" }], plans: { uA: ENTITLED } });
    assert.deepStrictEqual(r.runs, ["s1"]);
    // PIN a.write (was: [{ payload: { last_run_on: "2026-09-11" }, where: ["id", "s1"] }])
    assert.deepStrictEqual(r.stamps, [{ payload: { last_run_on: "2026-09-11", last_run_status: "succeeded", last_error: null,
      last_task_id: null, consecutive_failures: 0, last_attempt_at: NOW.toISOString() }, where: ["id", "s1"] }]);
    assert.strictEqual(r.writes.length, 1);
    assert.strictEqual(r.summary.launched, 1);
    assert.strictEqual(r.summary.skippedNotEntitled, 0);
  });

  await t("b) due, autonomy on, not entitled: not run, not stamped, one log naming user, agent, inactive_reason", async () => {
    const r = await runTick({ schedules: [sched("s1", "uA", "content")], autonomy: [{ user_id: "uA", agent_type: "content" }], plans: { uA: LAPSED } });
    assert.deepStrictEqual(r.runs, []);
    assert.deepStrictEqual(r.stamps, []);
    const skipLines = r.logs.filter(l => /Skipped .* — no active subscription/.test(l[1]));
    assert.strictEqual(skipLines.length, 1, JSON.stringify(r.logs));
    assert(/uA/.test(skipLines[0][1]) && /content/.test(skipLines[0][1]) && /"status"/.test(skipLines[0][1]), skipLines[0][1]);
    assert.strictEqual(r.summary.skippedNotEntitled, 1);
    assert.strictEqual(r.summary.failed, 0);
    // NEW b: the skip is recorded on its own row, in the card's words.
    assert.deepStrictEqual(outcomeOf(r, "s1"), { last_run_status: "skipped_not_entitled", last_error: "skipped: subscription not active",
      last_attempt_at: NOW.toISOString() });
  });

  await t("c) getUserPlan throws for A, B entitled: A not run/not stamped, B runs", async () => {
    const r = await runTick({
      schedules: [sched("sA", "uA"), sched("sB", "uB")],
      autonomy: [{ user_id: "uA", agent_type: "seo" }, { user_id: "uB", agent_type: "seo" }],
      plans: { uA: new Error("plan-db-down"), uB: ENTITLED }
    });
    assert.deepStrictEqual(r.runs, ["sB"]);
    assert.deepStrictEqual(r.stamps.map(s => s.where[1]), ["sB"]);
    const errLines = r.logs.filter(l => /entitlement could not be determined/.test(l[1]));
    assert.strictEqual(errLines.length, 1, JSON.stringify(r.logs));
    assert(/uA/.test(errLines[0][1]) && /seo/.test(errLines[0][1]) && /plan-db-down/.test(errLines[0][1]), errLines[0][1]);
    assert.strictEqual(r.summary.failed, 1);
    assert.strictEqual(r.summary.launched, 1);
    // NEW c: A's skip is recorded as "could not check subscription".
    assert.deepStrictEqual(outcomeOf(r, "sA"), { last_run_status: "skipped_entitlement_unknown",
      last_error: "skipped: could not check subscription", last_attempt_at: NOW.toISOString() });
  });

  await t("c2) getUserPlan returns null: fails closed, not run, not stamped", async () => {
    const r = await runTick({ schedules: [sched("s1", "uA")], autonomy: [{ user_id: "uA", agent_type: "seo" }], plans: { uA: null } });
    assert.deepStrictEqual(r.runs, []);
    assert.deepStrictEqual(r.stamps, []);
    assert(r.logs.some(l => /entitlement could not be determined/.test(l[1]) && /returned no result/.test(l[1])));
    // NEW c2
    assert.strictEqual(outcomeOf(r, "s1").last_run_status, "skipped_entitlement_unknown");
  });

  await t("d) admin exemption (active true): runs", async () => {
    const r = await runTick({ schedules: [sched("s1", "admin1")], autonomy: [{ user_id: "admin1", agent_type: "seo" }], plans: { admin1: ADMIN } });
    assert.deepStrictEqual(r.runs, ["s1"]);
    assert.strictEqual(r.stamps.length, 1);
  });

  await t("e) MAX_PER_TICK=1, one unentitled then one entitled: the entitled one runs", async () => {
    const r = await runTick({
      schedules: [sched("sLapsed", "uL"), sched("sPaid", "uP")],
      autonomy: [{ user_id: "uL", agent_type: "seo" }, { user_id: "uP", agent_type: "seo" }],
      plans: { uL: LAPSED, uP: ENTITLED }, maxPerTick: 1
    });
    assert.deepStrictEqual(r.runs, ["sPaid"]);
    assert.deepStrictEqual(r.stamps.map(s => s.where[1]), ["sPaid"]);
    assert.strictEqual(r.summary.ceilingReached, false);
  });

  await t("f) one user, three due schedules: getUserPlan called exactly once", async () => {
    const r = await runTick({
      schedules: [sched("s1", "uA", "seo"), sched("s2", "uA", "content"), sched("s3", "uA", "executive")],
      autonomy: [{ user_id: "uA", agent_type: "seo" }, { user_id: "uA", agent_type: "content" }, { user_id: "uA", agent_type: "executive" }],
      plans: { uA: ENTITLED }
    });
    assert.deepStrictEqual(r.planCalls, ["uA"]);
    assert.deepStrictEqual(r.runs, ["s1", "s2", "s3"]);
  });

  await t("f2) one user, three due schedules, plan lookup throws: called once, none run", async () => {
    const r = await runTick({
      schedules: [sched("s1", "uA", "seo"), sched("s2", "uA", "content"), sched("s3", "uA", "executive")],
      autonomy: [{ user_id: "uA", agent_type: "seo" }, { user_id: "uA", agent_type: "content" }, { user_id: "uA", agent_type: "executive" }],
      plans: { uA: new Error("down") }
    });
    assert.deepStrictEqual(r.planCalls, ["uA"]);
    assert.deepStrictEqual(r.runs, []);
    assert.strictEqual(r.summary.failed, 3);
  });

  await t("g) autonomy off: not run, getUserPlan not called", async () => {
    const r = await runTick({ schedules: [sched("s1", "uA")], autonomy: [], plans: { uA: ENTITLED } });
    assert.deepStrictEqual(r.runs, []);
    assert.deepStrictEqual(r.planCalls, []);
    assert.deepStrictEqual(r.stamps, []);
    assert.strictEqual(r.summary.skippedNoAutonomy, 1);
    // NEW g
    assert.deepStrictEqual(outcomeOf(r, "s1"), { last_run_status: "skipped_no_autonomy",
      last_error: "skipped: Autonomous mode is off for this agent", last_attempt_at: NOW.toISOString() });
  });

  console.log("\n    extracted " + code.length + " chars");
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
