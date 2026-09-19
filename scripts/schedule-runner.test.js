"use strict";
/* Extracts the REAL runAgentSchedulePass and its due-ness helpers from
   server.js (brace-matched) and runs them in a vm context with stubs for
   getUserPlan, runScheduledAgentTask and Supabase. No network, no database. */
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");

const src = fs.readFileSync("C:/Users/ALGORITHM/BizForce-backend/server.js", "utf8");

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

const code = [
  "function agentScheduleUtcDay(now) {",
  "function agentScheduleDaysInUtcMonth(now) {",
  "function agentScheduleEffectiveMonthDay(dayOfMonth, now) {",
  "function agentScheduleIsDue(row, now) {",
  "async function runAgentSchedulePass(now, maxPerTick) {"
].map(extract).join("\n\n");

const NOW = new Date("2026-09-11T09:00:00.000Z");   // hour 9, a Friday
function sched(id, userId, agent) {
  return { id, user_id: userId, agent_type: agent || "seo", task_type: "general",
           prompt: "p", cadence: "daily", hour_utc: 9, day_of_week: null, day_of_month: null,
           enabled: true, last_run_on: null };
}

/* opts: { schedules, autonomy:[{user_id,agent_type}], plans:{userId: result|Error|null}, maxPerTick } */
async function runTick(opts) {
  const logs = [], runs = [], stamps = [], planCalls = [];
  const fakeSupabase = {
    from(name) {
      if (name === "agent_schedules") {
        return {
          select() { return { eq() { return { eq() { return { or: async () => ({ data: opts.schedules, error: null }) }; } }; } }; },
          update(payload) { return { eq: async (col, val) => { stamps.push({ payload, where: [col, val] }); return { error: null }; } }; }
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
    runScheduledAgentTask: async (schedule) => { runs.push(schedule.id); return { ok: true, status: 202, payload: {} }; }
  };
  vm.createContext(ctx);
  vm.runInContext(code + "\nthis.runAgentSchedulePass = runAgentSchedulePass;", ctx);
  const summary = await ctx.runAgentSchedulePass(NOW, opts.maxPerTick == null ? 25 : opts.maxPerTick);
  return { logs, runs, stamps: JSON.parse(JSON.stringify(stamps)), planCalls, summary: JSON.parse(JSON.stringify(summary)) };
}

const ENTITLED = { plan: "all_access", active: true, inactive_reason: null, exempt: false };
const LAPSED   = { plan: "all_access", active: false, inactive_reason: "status", exempt: false };
const ADMIN    = { plan: "admin_exempt", active: true, inactive_reason: null, exempt: true, access_reason: "admin" };

let failures = 0;
async function t(name, fn) {
  try { await fn(); console.log("PASS " + name); }
  catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); }
}

(async () => {
  await t("a) due, autonomy on, entitled: runs once, last_run_on written", async () => {
    const r = await runTick({ schedules: [sched("s1", "uA")], autonomy: [{ user_id: "uA", agent_type: "seo" }], plans: { uA: ENTITLED } });
    assert.deepStrictEqual(r.runs, ["s1"]);
    assert.deepStrictEqual(r.stamps, [{ payload: { last_run_on: "2026-09-11" }, where: ["id", "s1"] }]);
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
  });

  await t("c2) getUserPlan returns null: fails closed, not run, not stamped", async () => {
    const r = await runTick({ schedules: [sched("s1", "uA")], autonomy: [{ user_id: "uA", agent_type: "seo" }], plans: { uA: null } });
    assert.deepStrictEqual(r.runs, []);
    assert.deepStrictEqual(r.stamps, []);
    assert(r.logs.some(l => /entitlement could not be determined/.test(l[1]) && /returned no result/.test(l[1])));
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
  });

  console.log("extracted " + code.length + " chars; failures: " + failures);
  process.exitCode = failures ? 1 : 0;
})();
