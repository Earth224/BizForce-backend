"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkScheduleControl.js — a scheduled run's failure reaches its owner, a
   schedule can be paused without losing it, and nothing runs for a member
   whose subscription is not active.

   WHAT RUNS. The REAL code, extracted from server.js and the frontend's
   scripts/agent-profile.js and run in vm contexts against a fake database
   that honours the filters it is given:
     - runAgentSchedulePass and agentScheduleIsDue, ticked hour by hour over
       simulated days, so "never runs", "runs once" and "no catch-up" are
       counted, not inferred;
     - the GET, pause and resume route handlers;
     - lib/opsAlert.js's scheduleAutoPaused / scheduleResumed, with a fake send;
     - runDripForAllUsers with the real createPassEntitlementCache;
     - the agent page's schedule card (loadSchedule, renderSchedule,
       bindSchedule) in a fake DOM, fed the rows the runner wrote.

     R1  a failed run is recorded on its own schedule: status, reason, when;
         the card shows "failed" and the reason; a success links to its task
     R2  three failures in a row pause the schedule, exactly one ops alert;
         paused, it does not run or alert again; the card says why
     R3  a paused schedule never runs; Resume restores it unchanged and it
         runs once at its next slot; pause and resume are owner-scoped and
         idempotent
     R4  a lapsed member: nothing runs, nothing is deleted, each skip is
         recorded, the card says it is waiting; on return it runs at its next
         slot only (no catch-up burst), and a weekly one waits for its day
     R5  a failed entitlement read runs nothing, says so, and the card claims
         nothing about the subscription
     D   the SMS drip loop refuses lapsed and unreadable members
     S   every scheduled background job is accounted for: each that acts for
         a member checks entitlement (fail closed), and each that does not is
         a named exception with its reason

   ⚠️ THE DATABASE IS FAKE. It applies eq / in / or filters and update /
   upsert / delete the way PostgREST would for these shapes; it does not know
   the live columns. Migration 143 must be applied for the real reads to work.

   MUTATE=<name> edits the extracted runner IN MEMORY (server.js is never
   written). MUTATE=all runs each in its own process; every one must be caught.
     ignores_paused       agentScheduleIsDue no longer tests paused
     ignores_entitlement  the `plan.active !== true` refusal is gone
     unknown_runs         a plan lookup that throws is read as entitled
     catchup              a slot missed today is made up later the same day:
                          the hour filter is dropped and "this hour" becomes
                          "this hour or after", so a schedule renewed or
                          resumed after its slot runs at once (the burst this
                          must not have)
     failure_unrecorded   a failed run writes nothing to its row
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const assert = require("assert");

const MUTATIONS = ["ignores_paused", "ignores_entitlement", "unknown_runs", "catchup", "failure_unrecorded"];
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const AP_SRC = fs.readFileSync(path.join(FRONTEND, "scripts", "agent-profile.js"), "utf8").replace(/\r\n/g, "\n");
const { createOpsAlerts } = require("../lib/opsAlert");

/* ── extraction ─────────────────────────────────────────────────────────── */
function extract(signature) {
  const start = SRC.indexOf(signature);
  assert(start > 0, signature + " not found");
  const end = MUT.braceMatch(SRC, SRC.indexOf("{", start));
  return SRC.slice(start, end);
}
function extractLine(prefix) {
  const start = SRC.indexOf(prefix);
  assert(start > 0, prefix + " not found");
  return SRC.slice(start, SRC.indexOf("\n", start));
}
function routeHandler(signature) {
  const start = SRC.indexOf(signature);
  assert(start > 0, signature + " not found");
  const fnStart = SRC.indexOf("async function (req, res, next) {", start);
  return "(" + SRC.slice(fnStart, MUT.braceMatch(SRC, SRC.indexOf("{", fnStart))) + ")";
}
function bodyOf(name) {
  const def = MUT.definitionOf(MUT.after, name);
  assert(def, name + " not found in server.js");
  return def;
}

let RUNNER = [extractLine("var AGENT_SCHEDULE_FAILURES_TO_PAUSE = "), extract("var AGENT_SCHEDULE_SKIP_TEXT = {") + ";",
  extract("function agentScheduleUtcDay(now) {"),
  extract("function agentScheduleDaysInUtcMonth(now) {"),
  extract("function agentScheduleEffectiveMonthDay(dayOfMonth, now) {"),
  extract("function agentScheduleIsDue(row, now) {"),
  extract("async function runAgentSchedulePass(now, maxPerTick) {")].join("\n\n");

const FIELDS_DEFS = bodyOf("AGENT_SCHEDULE_FIELDS") + "\n" + bodyOf("AGENT_SCHEDULE_CARD_FIELDS");
const GET_ROUTE = routeHandler('app.get("/api/agent-schedules", requireAuth, ');
const PAUSE_ROUTE = routeHandler('app.put("/api/agent-schedules/:agent_type/pause", requireAuth, ');
const RESUME_ROUTE = routeHandler('app.put("/api/agent-schedules/:agent_type/resume", requireAuth, ');
const DRIP = "var PASS_PLAN_LOOKUP = { override: null };\n" + extract("function createPassEntitlementCache() {") + "\n" +
  extract("async function runDripForAllUsers() {");

if (MUTATE === "ignores_paused") {
  RUNNER = MUT.replaceOnce(RUNNER, "  if (row.paused === true) return false;\n", "", "ignores_paused");
} else if (MUTATE === "ignores_entitlement") {
  RUNNER = MUT.replaceOnce(RUNNER, "    if (entitlement.plan.active !== true) {\n", "    if (false) {\n", "ignores_entitlement");
} else if (MUTATE === "unknown_runs") {
  RUNNER = MUT.replaceOnce(RUNNER, "        planByUser[userId] = { plan: null, error: planErr };\n",
    "        planByUser[userId] = { plan: { active: true }, error: null };\n", "unknown_runs");
} else if (MUTATE === "catchup") {
  RUNNER = MUT.replaceOnce(RUNNER, "    .eq(\"hour_utc\", hour)\n", "", "catchup: the hour filter");
  RUNNER = MUT.replaceOnce(RUNNER, "  if (Number(row.hour_utc) !== now.getUTCHours()) return false;\n",
    "  if (Number(row.hour_utc) > now.getUTCHours()) return false;\n", "catchup: the hour test");
} else if (MUTATE === "failure_unrecorded") {
  RUNNER = MUT.replaceOnce(RUNNER, "    var recorded = await recordScheduleOutcome(schedule, patch);\n",
    "    var recorded = true;\n", "failure_unrecorded");
}
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE + " (the extracted runner, in memory)");

/* ── the fake database ──────────────────────────────────────────────────── */
function makeDb(tables) {
  const db = { tables: tables, log: [], fail: null };
  function project(row, cols) {
    if (!cols || cols === "*") return Object.assign({}, row);
    const out = {};
    cols.split(",").map(c => c.trim()).filter(Boolean).forEach(c => { out[c] = row[c]; });
    return out;
  }
  function orFilter(expr) {
    const parts = expr.split(",");
    return function (r) {
      return parts.some(function (p) {
        const bits = p.split("."), col = bits[0], op = bits[1], val = bits.slice(2).join(".");
        if (op === "is" && val === "null") return r[col] == null;
        if (op === "neq") return r[col] != null && String(r[col]) !== val;
        throw new Error("the fake does not know or-term " + p);
      });
    };
  }
  db.from = function (table) {
    const q = { table: table, op: "select", cols: "*", returning: false, patch: null, row: null, onConflict: null, filters: [] };
    const b = {
      select(cols) { q.cols = cols || "*"; q.returning = true; return b; },
      update(patch) { q.op = "update"; q.patch = patch; return b; },
      delete() { q.op = "delete"; return b; },
      upsert(row, o) { q.op = "upsert"; q.row = row; q.onConflict = o && o.onConflict; return b; },
      insert(row) { q.op = "insert"; q.row = row; return b; },
      eq(c, v) { q.filters.push(r => r[c] === v); return b; },
      in(c, vs) { q.filters.push(r => vs.indexOf(r[c]) !== -1); return b; },
      or(expr) { q.filters.push(orFilter(expr)); return b; },
      order() { return b; },
      limit() { return b; },
      single() { q.single = true; return b; },
      then(resolve, reject) { return Promise.resolve().then(run).then(resolve, reject); }
    };
    function run() {
      const rows = db.tables[table] = db.tables[table] || [];
      if (db.fail) { const f = db.fail(q); if (f) return { data: null, error: f }; }
      const hit = rows.filter(r => q.filters.every(f => f(r)));
      db.log.push({ table: table, op: q.op, patch: q.patch ? JSON.parse(JSON.stringify(q.patch)) : null, ids: hit.map(r => r.id || r.alert_key || r.user_id) });
      if (q.op === "select") return { data: hit.map(r => project(r, q.cols)), error: null };
      if (q.op === "update") {
        hit.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(q.patch))));
        return { data: q.returning ? hit.map(r => project(r, q.cols)) : null, error: null };
      }
      if (q.op === "delete") {
        db.tables[table] = rows.filter(r => hit.indexOf(r) === -1);
        return { data: q.returning ? hit.map(r => project(r, q.cols)) : null, error: null };
      }
      if (q.op === "upsert") {
        const keys = String(q.onConflict || "id").split(",");
        const found = rows.find(r => keys.every(k => r[k] === q.row[k]));
        if (found) Object.assign(found, q.row); else rows.push(Object.assign({}, q.row));
        return { data: null, error: null };
      }
      if (q.op === "insert") { rows.push(Object.assign({}, q.row)); return { data: [project(q.row, q.cols)], error: null }; }
      throw new Error("the fake does not know op " + q.op);
    }
    return b;
  };
  return db;
}

/* ── the world: schedules, plans, and a clock ticked hour by hour ─────── */
const DEFINITION = ["task_type", "prompt", "cadence", "hour_utc", "day_of_week", "day_of_month", "enabled", "created_at", "updated_at"];
function definitionOf(row) { const o = {}; DEFINITION.forEach(k => { o[k] = row[k]; }); return o; }

function schedRow(id, user, agent, extra) {
  return Object.assign({
    id: id, user_id: user, agent_type: agent, task_type: "general", prompt: "Write the weekly report for " + id,
    cadence: "daily", hour_utc: 9, day_of_week: null, day_of_month: null, enabled: true, last_run_on: null,
    created_at: "2026-09-01T00:00:00.000Z", updated_at: "2026-09-01T00:00:00.000Z",
    paused: false, paused_reason: null, last_run_status: null, last_error: null, last_attempt_at: null,
    last_task_id: null, consecutive_failures: 0
  }, extra || {});
}

const ENTITLED = { plan: "all_access", active: true, inactive_reason: null, exempt: false };
const LAPSED = { plan: "all_access", active: false, inactive_reason: "status", exempt: false };

function makeWorld(schedules, plans) {
  const autonomy = [];
  schedules.forEach(s => autonomy.push({ user_id: s.user_id, agent_type: s.agent_type, enabled: true }));
  const w = { db: makeDb({ agent_schedules: schedules, agent_autonomy: autonomy }), plans: plans, fail: {}, runs: [], alerts: [], logs: [], taskSeq: 0 };
  const ctx = {
    supabase: w.db,
    console: { log: m => w.logs.push(String(m)), error: m => w.logs.push(String(m)), warn: m => w.logs.push(String(m)) },
    AGENT_SYSTEM_PROMPTS: { seo: "x", content: "x", executive: "x" },
    allowedTaskTypes: ["general"],
    getUserPlan: async function (userId) { const p = w.plans[userId]; if (p instanceof Error) throw p; return p; },
    runScheduledAgentTask: async function (s) {
      w.runs.push({ id: s.id, at: w.now.toISOString() });
      if (w.fail[s.id]) return { ok: false, status: 500, payload: { error: w.fail[s.id] } };
      w.taskSeq += 1;
      return { ok: true, status: 202, payload: { success: true, queued: true, task: { id: "task-" + s.id + "-" + w.taskSeq } } };
    },
    opsAlerts: { scheduleAutoPaused: async function (info) { w.alerts.push(JSON.parse(JSON.stringify(info))); return { sent: true }; } }
  };
  vm.createContext(ctx);
  vm.runInContext(RUNNER + "\nthis.pass = runAgentSchedulePass;", ctx);
  w.tick = async function (iso) { w.now = new Date(iso); return ctx.pass(w.now, 25); };
  // Every hour of each day from `day` (YYYY-MM-DD) for `days` days.
  w.hours = async function (startIso, hours) {
    const start = Date.parse(startIso);
    for (let h = 0; h < hours; h++) await w.tick(new Date(start + h * 3600000).toISOString());
  };
  w.days = (day, days) => w.hours(day + "T00:00:00.000Z", days * 24);
  w.row = id => w.db.tables.agent_schedules.find(r => r.id === id);
  w.runsOf = id => w.runs.filter(r => r.id === id).map(r => r.at);
  return w;
}

/* ── the route handlers ─────────────────────────────────────────────────── */
async function callRoute(handlerSrc, db, user, params, extra) {
  const calls = [];
  const ctx = Object.assign({
    supabase: db, console: { log() {}, error() {}, warn() {} },
    opsAlerts: { scheduleResumed: function (u, a) { calls.push(["scheduleResumed", u, a]); return Promise.resolve({}); } }
  }, extra || {});
  vm.createContext(ctx);
  vm.runInContext(FIELDS_DEFS, ctx);
  const fn = vm.runInContext(handlerSrc, ctx);
  const out = await new Promise(function (resolve) {
    const res = {
      statusCode: 200,
      status(c) { this.statusCode = c; return this; },
      json(b) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(b)) }); return this; }
    };
    Promise.resolve(fn({ user: user, params: params || {}, body: {} }, res, err => resolve({ status: 500, error: err })))
      .catch(err => resolve({ status: 500, error: err }));
  });
  out.calls = calls;
  return out;
}
const pauseAs = (db, uid, agent) => callRoute(PAUSE_ROUTE, db, { id: uid, role: "user" }, { agent_type: agent });
const resumeAs = (db, uid, agent) => callRoute(RESUME_ROUTE, db, { id: uid, role: "user" }, { agent_type: agent });
const getAs = (db, uid, plan) => callRoute(GET_ROUTE, db, { id: uid, role: "user" }, {}, {
  getUserPlan: async function () { if (plan instanceof Error) throw plan; return plan; }
});

/* ── the card, in a fake DOM ───────────────────────────────────────────── */
function fakeEl(tag) {
  const el = { tagName: String(tag || "").toUpperCase(), id: null, className: "", hidden: false, disabled: false, value: "",
    href: "", style: {}, children: [], options: [], listeners: {}, _text: "", isText: false,
    appendChild(c) { this.children.push(c); c.parentNode = this; return c; },
    insertBefore(c) { this.children.push(c); c.parentNode = this; return c; },
    removeChild(c) { this.children = this.children.filter(x => x !== c); return c; },
    setAttribute(k, v) { this[k] = String(v); }, getAttribute(k) { return this[k] == null ? null : this[k]; },
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
    click() { (this.listeners.click || []).forEach(f => f({ preventDefault() {}, target: this })); },
    querySelector() { return null; }, querySelectorAll() { return []; }, insertAdjacentHTML() {}
  };
  Object.defineProperty(el, "textContent", {
    get() { return this._text + this.children.map(c => c.textContent).join(""); },
    set(v) { this._text = this.isText ? String(v) : ""; if (!this.isText) { this.children = []; if (String(v) !== "") this._text = String(v); } }
  });
  Object.defineProperty(el, "innerHTML", { get() { return ""; }, set() { this.children = []; this._text = ""; } });
  el.classList = { add() {}, remove() {}, contains() { return false; }, toggle() {} };
  return el;
}

async function settle() { for (let i = 0; i < 12; i++) await new Promise(r => setImmediate(r)); }

function loadCard(handler) {
  const els = new Map();
  const document = {
    head: fakeEl("head"), body: fakeEl("body"),
    createElement: t => fakeEl(t),
    createTextNode: t => { const n = fakeEl(""); n.isText = true; n._text = String(t); return n; },
    getElementById: id => { if (!els.has(id)) { const e = fakeEl("div"); e.id = id; els.set(id, e); } return els.get(id); },
    querySelector() { return null; }, querySelectorAll() { return []; }, addEventListener() {}
  };
  const requests = [];
  const window = { AGENT_PROFILE_CONFIG: { agentType: "seo", agentLabel: "SEO Agent", taskTypes: [{ value: "general", label: "General" }] } };
  const ctx = {
    window: window, document: document, console: { log() {}, warn() {}, error() {} },
    localStorage: { getItem: k => (k === "bf_token" ? "check-token" : null), setItem() {}, removeItem() {} },
    fetch: function (url, init) {
      const p = String(url).replace(/^https?:\/\/[^/]+/, "");
      const method = (init && init.method) || "GET";
      requests.push(method + " " + p);
      const r = handler(method, p) || { status: 404, body: { error: "unplanned " + method + " " + p } };
      return Promise.resolve({ ok: r.status >= 200 && r.status < 300, status: r.status,
        json: () => Promise.resolve(JSON.parse(JSON.stringify(r.body))) });
    },
    setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {}, navigator: {}, location: { search: "" }
  };
  ctx.window.document = document;
  vm.createContext(ctx);
  const tail = '  document.addEventListener("DOMContentLoaded", inject);\n})();';
  assert(AP_SRC.lastIndexOf(tail) !== -1, "agent-profile.js does not end where expected");
  vm.runInContext(AP_SRC.slice(0, AP_SRC.lastIndexOf(tail)) +
    "  window.__sched = { loadSchedule: loadSchedule, bindSchedule: bindSchedule };\n" + tail, ctx);
  const card = { els: els, requests: requests, api: window.__sched };
  card.el = id => document.getElementById(id);
  card.text = id => card.el(id).hidden === true ? "" : card.el(id).textContent;
  card.visible = id => card.el(id).hidden !== true;
  return card;
}
async function cardFor(row, subscriptionActive, extraHandler) {
  const card = loadCard(function (method, p) {
    if (extraHandler) { const r = extraHandler(method, p); if (r) return r; }
    if (method === "GET" && p === "/api/agent-schedules") {
      return { status: 200, body: { schedules: row ? [Object.assign({}, row, { agent_type: "seo" })] : [], subscription_active: subscriptionActive } };
    }
    return null;
  });
  card.api.bindSchedule();
  card.api.loadSchedule();
  await settle();
  return card;
}

/* ── the runner ───────────────────────────────────────────────────────────── */
let failures = 0;
function check(name, ok, detail) {
  if (ok) console.log("    pass  " + name);
  else { failures++; console.log("    FAIL  " + name + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const deletesIn = db => db.log.filter(l => l.op === "delete");

(async function main() {
  console.log("checkScheduleControl — server.js, lib/opsAlert.js and the frontend at " + FRONTEND + "; no network, no database");

  /* ── R1 ─────────────────────────────────────────────────────────────── */
  console.log("\n══ R1. a failed run is recorded on its own schedule, and the card shows it ══");
  {
    const w = makeWorld([schedRow("sA", "uA", "seo"), schedRow("sB", "uB", "seo")], { uA: ENTITLED, uB: ENTITLED });
    w.fail.sA = "the model provider refused the request (quota exceeded)";
    const summary = await w.tick("2026-10-05T09:00:00.000Z");
    const a = w.row("sA"), b = w.row("sB");
    check("R1.1 both due schedules were attempted once", w.runsOf("sA").length === 1 && w.runsOf("sB").length === 1, JSON.stringify(w.runs));
    check("R1.2 the failure is on sA's row: status failed, the reason in words, when",
      a.last_run_status === "failed" && a.last_error === "The task could not be started: the model provider refused the request (quota exceeded)" &&
      a.last_attempt_at === "2026-10-05T09:00:00.000Z", JSON.stringify(a));
    check("R1.3 ...and it counts one failure, is not stamped as run, and is not paused",
      a.consecutive_failures === 1 && a.last_run_on === null && a.paused === false, JSON.stringify(a));
    check("R1.4 the success is on sB's row: succeeded, its task, last_run_on, no error",
      b.last_run_status === "succeeded" && b.last_task_id === "task-sB-1" && b.last_run_on === "2026-10-05" && b.last_error === null &&
      b.consecutive_failures === 0, JSON.stringify(b));
    check("R1.5 the hour's summary still counts the failure", summary.failed === 1 && summary.launched === 1, JSON.stringify(summary));
    check("R1.6 one failure raises no alert", w.alerts.length === 0, JSON.stringify(w.alerts));

    let card = await cardFor(a, true);
    const lastA = card.text("apSchedLast");
    check("R1.7 the card: \"Last run: <when> — failed. <reason>\"",
      /^Last run: .+ — failed\. The task could not be started: the model provider refused the request \(quota exceeded\)$/.test(lastA) &&
      card.el("apSchedLast").className.indexOf("failed") !== -1, lastA);
    check("R1.8 ...with no task link (none was created)", !card.el("apSchedLast").children.some(c => c.tagName === "A"));
    card = await cardFor(b, true);
    const link = card.el("apSchedLast").children.find(c => c.tagName === "A");
    check("R1.9 a success: \"Last run: <when> — succeeded.\" and \"Open the task\" linking to run.html?id=<task>",
      /^Last run: .+ — succeeded\. Open the task$/.test(card.text("apSchedLast")) && link && link.href === "/run.html?id=task-sB-1",
      card.text("apSchedLast") + " | " + (link && link.href));
    card = await cardFor(schedRow("sOld", "uA", "seo", { last_run_on: "2026-09-09" }), true);
    check("R1.10 a row from before outcomes were recorded still says only \"Last ran on 9th September 2026.\"",
      card.text("apSchedLast") === "Last ran on 9th September 2026.", card.text("apSchedLast"));
  }

  /* ── R2 ─────────────────────────────────────────────────────────────── */
  console.log("\n══ R2. three failures in a row pause the schedule, with exactly one alert ══");
  {
    const w = makeWorld([schedRow("sF", "uA", "seo")], { uA: ENTITLED });
    w.fail.sF = "handler error 500";
    await w.days("2026-10-05", 2);
    let f = w.row("sF");
    check("R2.1 after two failed days: 2 failures, not paused, no alert",
      f.consecutive_failures === 2 && f.paused === false && w.alerts.length === 0, JSON.stringify([f, w.alerts]));
    await w.days("2026-10-07", 1);
    f = w.row("sF");
    check("R2.2 the third failure pauses it: paused, reason failures, count 3",
      f.paused === true && f.paused_reason === "failures" && f.consecutive_failures === 3 && f.last_run_status === "failed", JSON.stringify(f));
    check("R2.3 exactly one alert, naming the member, the agent, the count and the reason",
      w.alerts.length === 1 && w.alerts[0].user_id === "uA" && w.alerts[0].agent_type === "seo" && w.alerts[0].failures === 3 &&
      w.alerts[0].error === "handler error 500", JSON.stringify(w.alerts));
    await w.days("2026-10-08", 5);
    check("R2.4 paused: five more days, no run and no second alert (3 runs and 1 alert in all)",
      w.runsOf("sF").length === 3 && w.alerts.length === 1, JSON.stringify([w.runsOf("sF"), w.alerts.length]));
    check("R2.5 the runs were one per day at 09:00, never retried within a day",
      JSON.stringify(w.runsOf("sF")) === JSON.stringify(["2026-10-05T09:00:00.000Z", "2026-10-06T09:00:00.000Z", "2026-10-07T09:00:00.000Z"]),
      JSON.stringify(w.runsOf("sF")));
    check("R2.6 the instruction, cadence and time are untouched", JSON.stringify(definitionOf(f)) === JSON.stringify(definitionOf(schedRow("sF", "uA", "seo"))));
    const card = await cardFor(f, true);
    check("R2.7 the card: \"Paused after 3 failed runs in a row. It will not run again until you press Resume.\"",
      card.text("apSchedState") === "Paused after 3 failed runs in a row. It will not run again until you press Resume.", card.text("apSchedState"));
    check("R2.8 ...Resume shown, Pause hidden, Remove still there", card.visible("apSchedResumeBtn") && !card.visible("apSchedPauseBtn") && card.visible("apSchedDeleteBtn"));

    // The real lib: one email for the pause, deduped if raised again, resolved by Resume.
    const sent = [];
    const ops = createOpsAlerts({ supabase: makeDb({ ops_alerts: [] }), env: { OPS_ALERT_EMAIL: "owner+bftest@bizforceai.net", RESEND_API_KEY: "x" },
      send: async m => { sent.push(m.subject); return { ok: true, id: "m" + sent.length }; }, log: { log() {}, error() {} }, now: () => Date.parse("2026-10-07T09:00:01Z") });
    await ops.scheduleAutoPaused({ user_id: "uA", agent_type: "seo", failures: 3, error: "handler error 500" });
    await ops.scheduleAutoPaused({ user_id: "uA", agent_type: "seo", failures: 3, error: "handler error 500" });
    check("R2.9 lib/opsAlert.js: the pause emails the owner once, and a repeat is deduped",
      sent.length === 1 && sent[0] === "[BizForce ALERT] A scheduled seo run failed 3 times in a row and paused itself", JSON.stringify(sent));
    await ops.scheduleResumed("uA", "seo");
    check("R2.10 ...and Resume closes it with one \"resolved\"", sent.length === 2 && /^\[BizForce RESOLVED\]/.test(sent[1]), JSON.stringify(sent));
  }

  /* ── R3 ─────────────────────────────────────────────────────────────── */
  console.log("\n══ R3. a paused schedule never runs; Resume restores it unchanged ══");
  {
    const w = makeWorld([schedRow("sP", "uA", "content", { cadence: "weekly", day_of_week: 3, hour_utc: 14 }), schedRow("sQ", "uB", "content")],
      { uA: ENTITLED, uB: ENTITLED });
    const before = definitionOf(w.row("sP"));
    let r = await pauseAs(w.db, "uA", "content");
    check("R3.1 Pause: 200, the row comes back paused by its owner",
      r.status === 200 && r.body.schedule.paused === true && r.body.schedule.paused_reason === "owner", JSON.stringify(r));
    check("R3.2 ...and the response carries the card's fields", ["last_run_status", "last_error", "last_attempt_at", "last_task_id", "consecutive_failures"]
      .every(k => Object.prototype.hasOwnProperty.call(r.body.schedule, k)), Object.keys(r.body.schedule || {}).join(","));
    r = await pauseAs(w.db, "uA", "content");
    check("R3.3 Pause again: 200, still paused (idempotent)", r.status === 200 && r.body.schedule.paused === true);
    r = await pauseAs(w.db, "uC", "content");
    check("R3.4 another account pausing that agent: 404, and uA's and uB's rows are untouched",
      r.status === 404 && w.row("sQ").paused === false && w.row("sP").paused_reason === "owner", JSON.stringify(r));
    // Paused from Monday 2026-10-05 to Wednesday 2026-10-21 15:00, past its third Wednesday's 14:00 slot.
    await w.hours("2026-10-05T00:00:00.000Z", 16 * 24 + 15);
    check("R3.5 sixteen days paused (its Wednesday came three times): never run, nothing recorded",
      w.runsOf("sP").length === 0 && w.row("sP").last_run_status === null, JSON.stringify([w.runsOf("sP"), w.row("sP").last_run_status]));
    check("R3.6 the other member's schedule ran every day meanwhile", w.runsOf("sQ").length === 17, w.runsOf("sQ").length);
    const card = await cardFor(w.row("sP"), true);
    check("R3.7 the card: \"Paused. It will not run until you press Resume. The instruction, the days and the time are kept.\"",
      card.text("apSchedState") === "Paused. It will not run until you press Resume. The instruction, the days and the time are kept.", card.text("apSchedState"));
    r = await resumeAs(w.db, "uA", "content");
    check("R3.8 Resume: 200, not paused, no reason, failure count 0",
      r.status === 200 && r.body.schedule.paused === false && r.body.schedule.paused_reason === null && r.body.schedule.consecutive_failures === 0, JSON.stringify(r));
    check("R3.9 ...the instruction, cadence, day and hour are exactly as before the pause",
      JSON.stringify(definitionOf(w.row("sP"))) === JSON.stringify(before), JSON.stringify([definitionOf(w.row("sP")), before]));
    check("R3.10 ...and Resume closes any pause alert for that schedule", JSON.stringify(r.calls) === JSON.stringify([["scheduleResumed", "uA", "content"]]), JSON.stringify(r.calls));
    r = await resumeAs(w.db, "uA", "content");
    check("R3.11 Resume again: 200 (idempotent); a schedule that does not exist: 404",
      r.status === 200 && (await resumeAs(w.db, "uA", "seo")).status === 404);
    // Resumed at 15:00 on a Wednesday, an hour after its slot; ticked to the end of the next Wednesday.
    await w.hours("2026-10-21T15:00:00.000Z", 7 * 24 + 9);
    check("R3.12 resumed after that day's slot: nothing that day, nothing for the weeks it missed, then once on the next Wednesday at 14:00",
      JSON.stringify(w.runsOf("sP")) === JSON.stringify(["2026-10-28T14:00:00.000Z"]), JSON.stringify(w.runsOf("sP")));
    check("R3.13 nothing was deleted", deletesIn(w.db).length === 0 && w.db.tables.agent_schedules.length === 2);

    // A schedule the runner paused keeps its reason if Pause is pressed.
    const w2 = makeWorld([schedRow("sR", "uA", "seo", { paused: true, paused_reason: "failures", consecutive_failures: 3 })], { uA: ENTITLED });
    r = await pauseAs(w2.db, "uA", "seo");
    check("R3.14 Pause on a schedule the runner paused: 200, and it still says \"failures\"",
      r.status === 200 && r.body.schedule.paused_reason === "failures", JSON.stringify(r.body));
  }

  /* ── R4 ─────────────────────────────────────────────────────────────── */
  console.log("\n══ R4. a lapsed member: nothing runs, nothing is lost, no catch-up on return ══");
  {
    // 2026-10-05 is a Monday. sW is weekly on Wednesday (3), at 09:00 like sD.
    const w = makeWorld([schedRow("sD", "uL", "seo"), schedRow("sW", "uL", "content", { cadence: "weekly", day_of_week: 3 })], { uL: LAPSED });
    const before = { sD: definitionOf(w.row("sD")), sW: definitionOf(w.row("sW")) };
    // Lapsed from Monday 2026-10-05 00:00 until Monday 2026-10-12 12:00, three hours after that day's slot.
    await w.hours("2026-10-05T00:00:00.000Z", 7 * 24 + 12);
    const d = w.row("sD"), wk = w.row("sW");
    check("R4.1 a week lapsed: neither schedule ran", w.runs.length === 0, JSON.stringify(w.runs));
    check("R4.2 each skip is recorded: \"skipped: subscription not active\"",
      d.last_run_status === "skipped_not_entitled" && d.last_error === "skipped: subscription not active" &&
      d.last_attempt_at === "2026-10-12T09:00:00.000Z" && wk.last_attempt_at === "2026-10-07T09:00:00.000Z", JSON.stringify([d, wk]));
    check("R4.3 one record per due slot: 8 for the daily, 1 for the weekly",
      w.db.log.filter(l => l.op === "update" && l.ids[0] === "sD").length === 8 && w.db.log.filter(l => l.op === "update" && l.ids[0] === "sW").length === 1);
    check("R4.4 nothing deleted, nothing paused, no failure counted, last_run_on never stamped",
      deletesIn(w.db).length === 0 && w.db.tables.agent_schedules.length === 2 && !d.paused && !wk.paused &&
      d.consecutive_failures === 0 && d.last_run_on === null && wk.last_run_on === null);
    check("R4.5 the instructions and times are untouched",
      JSON.stringify(definitionOf(d)) === JSON.stringify(before.sD) && JSON.stringify(definitionOf(wk)) === JSON.stringify(before.sW));
    const got = await getAs(w.db, "uL", LAPSED);
    check("R4.6 GET says subscription_active: false, with both schedules and their status",
      got.status === 200 && got.body.subscription_active === false && got.body.schedules.length === 2 &&
      got.body.schedules.every(s => s.last_run_status === "skipped_not_entitled"), JSON.stringify(got.body));
    const card = await cardFor(d, false);
    check("R4.7 the card: \"Paused while your subscription is inactive. Resumes automatically when it's active again.\"",
      card.text("apSchedState") === "Paused while your subscription is inactive. Resumes automatically when it's active again.", card.text("apSchedState"));
    check("R4.8 ...and the last run line: \"Last run: <when> — skipped: subscription not active\"",
      /^Last run: .+ — skipped: subscription not active$/.test(card.text("apSchedLast")), card.text("apSchedLast"));
    check("R4.9 ...Pause (not Resume) is offered: the member did not pause it", card.visible("apSchedPauseBtn") && !card.visible("apSchedResumeBtn"));

    w.plans.uL = ENTITLED;   // renewed at 12:00 on Monday 2026-10-12
    await w.hours("2026-10-12T12:00:00.000Z", 12);
    check("R4.10 renewed after the day's 09:00 slot: nothing runs that day (the missed slot is not made up)",
      w.runs.length === 0, JSON.stringify(w.runs));
    await w.days("2026-10-13", 1);
    check("R4.11 the next day the daily runs ONCE, at its own 09:00 slot, and the weekly waits for its Wednesday",
      JSON.stringify(w.runsOf("sD")) === JSON.stringify(["2026-10-13T09:00:00.000Z"]) && w.runsOf("sW").length === 0, JSON.stringify(w.runs));
    await w.days("2026-10-14", 1);
    check("R4.12 by Wednesday: the weekly has run once at 09:00, the daily once a day",
      JSON.stringify(w.runsOf("sW")) === JSON.stringify(["2026-10-14T09:00:00.000Z"]) && w.runsOf("sD").length === 2, JSON.stringify(w.runs));
    check("R4.13 renewed: the card's lapse line is gone", (await cardFor(w.row("sD"), true)).visible("apSchedState") === false);
  }

  /* ── R5 ─────────────────────────────────────────────────────────────── */
  console.log("\n══ R5. a failed entitlement read runs nothing ══");
  {
    const w = makeWorld([schedRow("sX", "uX", "seo"), schedRow("sY", "uX", "content")], { uX: new Error("subscriptions read timed out") });
    const summary = await w.tick("2026-10-05T09:00:00.000Z");
    check("R5.1 neither schedule ran", w.runs.length === 0, JSON.stringify(w.runs));
    check("R5.2 each says \"skipped: could not check subscription\"",
      ["sX", "sY"].every(id => w.row(id).last_run_status === "skipped_entitlement_unknown" && w.row(id).last_error === "skipped: could not check subscription"),
      JSON.stringify([w.row("sX"), w.row("sY")]));
    check("R5.3 the hour does not close clean: both count as failures", summary.failed === 2, JSON.stringify(summary));
    check("R5.4 not counted toward the pause, not paused", w.row("sX").consecutive_failures === 0 && w.row("sX").paused === false);
    const got = await getAs(w.db, "uX", new Error("subscriptions read timed out"));
    check("R5.5 GET still answers with the schedules, and subscription_active: null", got.status === 200 && got.body.subscription_active === null &&
      got.body.schedules.length === 2, JSON.stringify(got));
    const card = await cardFor(w.row("sX"), null);
    check("R5.6 the card claims nothing about the subscription, and shows the skip",
      card.visible("apSchedState") === false && /— skipped: could not check subscription$/.test(card.text("apSchedLast")), card.text("apSchedLast"));
  }

  /* ── the card's controls ──────────────────────────────────────────────── */
  console.log("\n══ C. the card's Pause and Resume ══");
  {
    const row = schedRow("sC", "uA", "seo", { agent_type: "seo" });
    let card = await cardFor(row, true, function (method, p) {
      if (method === "PUT" && p === "/api/agent-schedules/seo/pause") return { status: 200, body: { schedule: Object.assign({}, row, { paused: true, paused_reason: "owner" }) } };
      if (method === "PUT" && p === "/api/agent-schedules/seo/resume") return { status: 200, body: { schedule: Object.assign({}, row) } };
      return null;
    });
    check("C1. a running schedule: Pause shown beside Remove, Resume hidden, no state line",
      card.visible("apSchedPauseBtn") && !card.visible("apSchedResumeBtn") && !card.visible("apSchedState"));
    card.el("apSchedPauseBtn").click(); await settle();
    check("C2. Pause sends PUT /api/agent-schedules/seo/pause and shows the server's paused row",
      card.requests.indexOf("PUT /api/agent-schedules/seo/pause") !== -1 && card.visible("apSchedResumeBtn") && !card.visible("apSchedPauseBtn") &&
      card.text("apSchedMsg") === "Schedule paused. The instruction, the days and the time are kept.", card.requests.join(", ") + " | " + card.text("apSchedMsg"));
    card.el("apSchedResumeBtn").click(); await settle();
    check("C3. Resume sends PUT .../resume and says no missed run is made up",
      card.requests.indexOf("PUT /api/agent-schedules/seo/resume") !== -1 && card.visible("apSchedPauseBtn") &&
      card.text("apSchedMsg") === "Schedule resumed. It runs next at its usual time; runs missed while it was paused are not made up.", card.text("apSchedMsg"));
    card = await cardFor(row, true, (method, p) => (method === "PUT" ? { status: 500, body: { error: "database unavailable" } } : null));
    card.el("apSchedPauseBtn").click(); await settle();
    check("C4. a Pause that failed leaves the schedule shown running and says why",
      card.visible("apSchedPauseBtn") && !card.visible("apSchedResumeBtn") && card.text("apSchedMsg") === "database unavailable", card.text("apSchedMsg"));
    const markup = AP_SRC.slice(AP_SRC.indexOf('id="apSchedViewActions"'), AP_SRC.indexOf('id="apSchedConfirm"'));
    check("C5. the buttons in order: Edit schedule, Pause, Resume, Remove",
      /apSchedEditBtn[\s\S]*apSchedPauseBtn">Pause<[\s\S]*apSchedResumeBtn" hidden>Resume<[\s\S]*apSchedDeleteBtn">Remove</.test(markup), markup.slice(0, 300));
    check("C6. the Remove confirmation no longer says a schedule cannot be paused, and points to Pause",
      AP_SRC.indexOf("There is no way to ") === -1 && AP_SRC.indexOf("To stop it for a while and ") !== -1);
  }

  /* ── D ─────────────────────────────────────────────────────────────────── */
  console.log("\n══ D. the SMS drip loop refuses lapsed and unreadable members ══");
  {
    const engine = [], logs = [];
    const db = makeDb({ sms_campaign_enrollments: [
      { user_id: "uOK", status: "active" }, { user_id: "uL", status: "active" }, { user_id: "uE", status: "active" }, { user_id: "uOK", status: "active" }] });
    const ctx = {
      supabase: db, console: { log: m => logs.push(String(m)), error: m => logs.push(String(m)) },
      getUserPlan: async function (u) { if (u === "uE") throw new Error("plans unreadable"); return u === "uOK" ? ENTITLED : LAPSED; },
      runDripEngine: async function (u) { engine.push(u); }
    };
    vm.createContext(ctx);
    vm.runInContext(DRIP + "\nthis.run = runDripForAllUsers;", ctx);
    await ctx.run();
    check("D1. only the entitled member's drip runs", JSON.stringify(engine) === JSON.stringify(["uOK"]), JSON.stringify(engine));
    check("D2. the lapsed one is logged \"skipped: subscription not active\"", logs.some(l => /uL — skipped: subscription not active/.test(l)), logs.join(" | "));
    check("D3. the unreadable one is logged \"skipped: could not check subscription\" (fail closed)", logs.some(l => /uE — skipped: could not check subscription/.test(l)));
    check("D4. no enrollment was changed or deleted", db.log.every(l => l.op === "select"));
  }

  /* ── S ─────────────────────────────────────────────────────────────────── */
  console.log("\n══ S. every scheduled background job, and its entitlement check ══");
  {
    const scheduled = new Set();
    let m;
    // NAMED (Oct 27 2026, launch item #7): BEFORE each interval was a bare setInterval(tick, ms) statement. AFTER each is
    // registered with the graceful shutdown, shutdownControl.trackInterval("tick", setInterval(tick, ms)), so either form counts.
    const iv = /^[ \t]*(?:shutdownControl\.trackInterval\("\w+", )?setInterval\((\w+),/gm;   // a statement, not a comment's example
    while ((m = iv.exec(SRC))) scheduled.add(m[1]);
    const cr = /cron\.schedule\([^,]+, function \(\) \{\s*(?:var \w+ = [^;]+;\s*)?([\w.]+)\(/g;
    while ((m = cr.exec(SRC))) scheduled.add(m[1]);
    const KNOWN = {
      // acts for a member: its pass must check entitlement
      agentScheduleTick:    { pass: "runAgentSchedulePass",  gate: "behaviour", why: "R1-R5 above" },
      storeProposalTick:    { pass: "runStoreProposalPass",  gate: "cache" },
      selfReviewTick:       { pass: "runSelfReviewPass",     gate: "cache" },
      salesAutoConvertTick: { pass: "runSalesAutoConvert",   gate: "cache" },
      dripTick:             { pass: "runDripForAllUsers",    gate: "cache", why: "D above" },
      // named exceptions
      emailSequenceTick:    { pass: "runEmailSequencePass",  exception: /u\.role === "admin"/, why: "sends only for sequences whose owner is an admin, who is exempt" },
      reminderTick:         { pass: "runDueReminders",       exception: /NO ENTITLEMENT CHECK, DELIBERATELY/, why: "a member's own calendar reminder to their own device; preparing needs no subscription (2026-10-05)" },
      // the platform's own, for no member
      youtubeRetentionTick: { platform: "deletes YouTube lead rows older than 30 days, the platform's own radar data" },
      "opsAlerts.scanTick": { platform: "the owner's ops alert scan" },
      runNightlyBackup:     { platform: "the nightly backup" },
      pendingStorageDeletionTick: { platform: "removes files of accounts already deleted (lib/accountFiles.js); there is no member left to be entitled" }
    };
    const extra = [...scheduled].filter(n => !KNOWN[n]), missing = Object.keys(KNOWN).filter(n => !scheduled.has(n));
    check("S1. the scheduled jobs in server.js are exactly the " + Object.keys(KNOWN).length + " accounted for here (a new one must be classified)",
      extra.length === 0 && missing.length === 0, "unclassified: " + extra.join(", ") + " | not found: " + missing.join(", "));
    for (const tick of Object.keys(KNOWN)) {
      const k = KNOWN[tick];
      if (k.platform) { console.log("    note  " + tick + ": the platform's own (" + k.platform + "), acts for no member"); continue; }
      const tickBody = bodyOf(tick), pass = bodyOf(k.pass);
      const calls = tickBody.indexOf(k.pass + "(") !== -1;
      if (k.exception) {
        // The function's own text or the comment directly above it.
        const at = SRC.indexOf(pass), lead = SRC.slice(Math.max(0, at - 1500), at);
        check("S. " + tick + " → " + k.pass + ": a named exception — " + k.why, calls && (k.exception.test(pass) || k.exception.test(lead)));
        continue;
      }
      const gate = k.gate === "behaviour"
        ? /await getUserPlan\(userId\)/.test(pass) && /if \(entitlement\.error \|\| !entitlement\.plan\) \{/.test(pass) && /if \(entitlement\.plan\.active !== true\) \{/.test(pass)
        : /createPassEntitlementCache\(\)/.test(pass) && /\.error \|\| !\w+\.plan\) \{/.test(pass) && /\.plan\.active !== true\) \{/.test(pass);
      check("S. " + tick + " → " + k.pass + " checks entitlement through getUserPlan, fail closed" + (k.why ? " (proved by " + k.why + ")" : ""), calls && gate);
    }
    const chain = bodyOf("dispatchToolCall");
    check("S. agent chaining (dispatchToolCall, runs inside a member's task) refuses not_entitled and fails closed on entitlement_unknown",
      /planState = await getUserPlan\(userId\)/.test(chain) && /chainRefusal\("entitlement_unknown"/.test(chain) && /planState\.active !== true/.test(chain));
    check("S. createPassEntitlementCache reads getUserPlan, the function every gate uses",
      /var planLookup = PASS_PLAN_LOOKUP\.override \|\| getUserPlan;/.test(bodyOf("createPassEntitlementCache")));
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  console.log("    FAIL  the check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
