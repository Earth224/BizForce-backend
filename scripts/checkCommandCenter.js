"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkCommandCenter — every dispatch of a real plan is recorded, and the
   Command Center is read from rows and nothing else.

   POST /api/assignments/dispatch, GET /api/command-center and (for comparison)
   GET /api/email/sequences are lifted from server.js and run in a vm against an
   in-memory Supabase that keeps its rows. Each request runs the route's WHOLE
   middleware chain, with stand-ins that behave as the real ones would for these
   accounts: requireAuth sets the user and their role, requireActiveSubscription
   refuses the lapsed account, aiLimiter passes. dispatchToolCall is a stand-in
   that answers as the real one does — ran, refused before the tool, or the tool
   threw — so no tool runs. No network, no model call, no database.

   WHAT THIS PROVES
     1. Dispatch records one executive_dispatches row per request that names a
        real plan of the caller's: 'ran' with tool_task_id (the result's
        task_id) and chain_id; 'refused' with refused_reason and detail, both
        for the route's own refusals and the dispatcher's; 'failed' when the
        tool threw. Every answer says recorded:true.
     2. Nothing is recorded for a plan that is not found, for another user's
        plan, or for a task that is not a plan.
     3. A failed record write leaves the answer unchanged but recorded:false,
        and is logged.
     4. GET /api/command-center: each section's contents from fixtures —
        needs_you, plans with each assignment's LATEST dispatch and its run's
        status (or "not dispatched"), activity, autopilot, outbound, spend.
     5. A section whose read fails answers ok:false with an error, never an
        empty list, and every other section still answers with its data.
     6. Sales dry runs are excluded from activity and counted separately.
     7. Another user's rows never appear, in any section.
     8. platform is present only for an admin.
     9. No subscription gate: requireAuth and nothing else, and a lapsed account
        reads it.

   MUTATE=<name> edits the lifted source (server.js on disk is never touched).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly once
   is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");

const MUTATIONS = {
  // the route's own refusals are no longer recorded
  "stop-recording-refusals": [["      var refuseRecorded = async function (reason, detail, assigned) {\n        var recorded = await recordExecutiveDispatch({\n",
    "      var refuseRecorded = async function (reason, detail, assigned) {\n        var recorded = false; if (false) await recordExecutiveDispatch({\n"]],
  // a section whose read failed answers as an empty list
  "failed-section-empty-ok": [["    return { ok: false, error: message };\n", "    return { ok: true, data: [] };\n"]],
  // sales dry runs are counted in activity
  "count-dry-run": [["      .gte(\"created_at\", since)\n      .or(\"agent_type.neq.sales,status.neq.dry_run\")\n", "      .gte(\"created_at\", since)\n"]],
  // the platform section is shown to every account
  "platform-to-everyone": [["    var isAdmin = req.user.role === \"admin\";\n", "    var isAdmin = true;\n"]],
  // the command center needs a subscription
  "gate-on-subscription": [["app.get(\"/api/command-center\", requireAuth, async function",
    "app.get(\"/api/command-center\", requireAuth, requireActiveSubscription, async function"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the source ─────────────────────────────────────────────────────────── */
let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) {
    SRC = MUT.replaceOnce(SRC, from, to, MUTATE);
  }
  console.log("\n!! MUTATION: " + MUTATE);
}

const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
function definitionOf(name) {
  let m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (m) return SRC.slice(m.index, s.braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
  const re = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
  while ((m = re.exec(SRC)) && SPANS.some(([x, y]) => m.index > x && m.index < y)) { /* a local */ }
  if (!m) return null;
  const brk = /;\n/g; brk.lastIndex = m.index + m[0].length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(m.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout",
  "requireAuth", "requireActiveSubscription", "requireAdmin", "aiLimiter", "crypto", "Date", "cron", "dispatchToolCall",
  // named inside MODEL_PRICES_SOURCE's text, not a dependency
  "Anthropic"]);
// Identifiers are followed through code only: a name in a comment is not a dependency.
const uncommented = (code) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
function routeText(method, route) {
  const sig = "app." + method + "(\"" + route + "\",";
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const ROUTES = [["post", "/api/assignments/dispatch"], ["get", "/api/command-center"], ["get", "/api/email/sequences"]];
const LIFTED = closure(ROUTES.map(([m, r]) => routeText(m, r)).join("\n\n"));

/* ── the fake database ──────────────────────────────────────────────────── */
const TABLES = ["ai_tasks", "executive_dispatches", "agent_proposals", "agent_autonomy", "agent_schedules", "email_sequences",
  "email_sequence_enrollments", "social_post_drafts", "content_library", "model_calls", "job_runs", "radar_status"];
function fakeDb(seed, fail) {
  const tables = {};
  TABLES.forEach(t => { tables[t] = ((seed || {})[t] || []).map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  function orClause(clause, row) {
    return clause.split(",").some(part => {
      const [col, op, val] = part.split(".");
      if (op === "neq") return row[col] !== null && row[col] !== undefined && row[col] !== val;
      if (op === "eq") return row[col] === val;
      throw new Error("fake db: unplanned or operator " + op);
    });
  }
  function keep(q, row) {
    return q.filters.every(f => {
      if (f[0] === "eq") return row[f[1]] === f[2];
      if (f[0] === "in") return f[2].indexOf(row[f[1]]) !== -1;
      if (f[0] === "gte") return row[f[1]] !== null && row[f[1]] !== undefined && row[f[1]] >= f[2];
      if (f[0] === "or") return orClause(f[1], row);
      return true;
    });
  }
  function project(q, row) {
    const copy = JSON.parse(JSON.stringify(row));
    if (!q.cols || q.cols.trim() === "*") return copy;
    const out = {};
    q.cols.split(",").map(c => c.trim()).forEach(c => { out[c] = copy[c] === undefined ? null : copy[c]; });
    return out;
  }
  function answer(q) {
    const injected = fail && fail(q);
    if (injected) return Promise.resolve({ data: null, error: injected, count: null });
    const rows = tables[q.table];
    if (!rows) return Promise.resolve({ data: null, error: { message: "unplanned table " + q.table } });
    if (q.op === "insert") {
      const row = Object.assign({ id: crypto.randomUUID(), created_at: new Date().toISOString() }, JSON.parse(JSON.stringify(q.payload)));
      rows.push(row);
      return Promise.resolve({ data: null, error: null });
    }
    let hits = rows.filter(r => keep(q, r));
    const orders = q.filters.filter(f => f[0] === "order");
    if (orders.length) {
      hits = hits.slice().sort((a, b) => {
        for (const o of orders) {
          const dir = o[2] && o[2].ascending === false ? -1 : 1;
          if (a[o[1]] < b[o[1]]) return -1 * dir;
          if (a[o[1]] > b[o[1]]) return 1 * dir;
        }
        return 0;
      });
    }
    const count = q.opts && q.opts.count === "exact" ? hits.length : null;
    const range = q.filters.find(f => f[0] === "range");
    if (range) hits = hits.slice(range[1], range[2] + 1);
    const limit = q.filters.find(f => f[0] === "limit");
    if (limit) hits = hits.slice(0, limit[1]);
    if (q.opts && q.opts.head) return Promise.resolve({ data: null, error: null, count });
    const copies = hits.map(r => project(q, r));
    if (q.single) return Promise.resolve({ data: copies[0] || null, error: null, count });
    return Promise.resolve({ data: copies, error: null, count });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, opts: null, payload: null, filters: [], single: false };
    log.push(q);
    const b = {
      select(cols, opts) { q.cols = cols || "*"; q.opts = opts || null; return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; }
    };
    ["eq", "in", "gte", "or", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, tables, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";   // admin, subscribed
const LAPSED = "aaaaaaaa-0000-4000-8000-000000000002";  // user, subscription lapsed
const OTHER = "aaaaaaaa-0000-4000-8000-000000000003";   // user, subscribed
const USERS = {
  [OWNER]: { role: "admin", subscribed: true },
  [LAPSED]: { role: "user", subscribed: false },
  [OTHER]: { role: "user", subscribed: true }
};
const NOW = Date.now();
const ago = (days) => new Date(NOW - days * 86400000).toISOString();
const id = (prefix, k) => prefix + "-1111-4111-8111-" + String(k).padStart(12, "0");
const T = (k) => id("71111111", k);   // ai_tasks
const P = (k) => id("72222222", k);   // plans (ai_tasks rows)
const D = (k) => id("73333333", k);   // executive_dispatches
const assignment = (n, extra) => Object.assign({ id: n, agent: "email", tool: "subject-lines", task: "Task " + n, priority: "high",
  inputs: { purpose: "fixture " + n }, is_dispatchable: true, problems: [], inputs_missing: [], route: "POST /api/agents/email/subject-lines" }, extra || {});
function plan(k, owner, days, assignments) {
  return { id: P(k), user_id: owner, agent_type: "executive", task_type: "executive/plan", status: "completed", prompt: "Plan " + k,
    created_at: ago(days), output: { goal: "Goal " + k, assignments: assignments } };
}
function task(k, owner, agent, status, days, taskType) {
  return { id: T(k), user_id: owner, agent_type: agent, task_type: taskType || "general", status, prompt: "t" + k, created_at: ago(days) };
}
function dispatchRow(k, owner, planK, assignmentId, outcome, days, extra) {
  return Object.assign({ id: D(k), user_id: owner, plan_task_id: P(planK), assignment_id: assignmentId, agent_type: "email", tool: "subject-lines",
    outcome, refused_reason: null, detail: null, tool_task_id: null, chain_id: null, created_at: ago(days) }, extra || {});
}
const MONTH_START = (() => { const n = new Date(NOW); return new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), 1)).toISOString().slice(0, 10); })();
function world() {
  return {
    ai_tasks: [
      // six plans of the owner's; the five newest are shown
      plan(1, OWNER, 1, [assignment(1), assignment(2, { is_dispatchable: false, problems: ["no such tool"], tool: "nope" }), assignment(3)]),
      plan(2, OWNER, 2, [assignment(1)]),
      plan(3, OWNER, 3, []),
      plan(4, OWNER, 4, [assignment(1)]),
      plan(5, OWNER, 5, [assignment(1)]),
      plan(6, OWNER, 6, [assignment(1)]),
      plan(7, OTHER, 0.5, [assignment(1)]),
      { id: T(90), user_id: OWNER, agent_type: "content", task_type: "content/outline", status: "completed", prompt: "not a plan", created_at: ago(1), output: {} },
      // runs
      task(1, OWNER, "content", "completed", 1, "content/outline"),
      task(2, OWNER, "content", "failed", 2),
      task(3, OWNER, "social", "completed", 3, "social/calendar"),
      task(4, OWNER, "email", "failed", 10),
      task(5, OWNER, "sales", "dry_run", 0.1),
      task(6, OWNER, "sales", "dry_run", 0.2),
      task(7, OWNER, "sales", "dry_run", 4),
      task(8, OWNER, "sales", "dry_run", 40),
      task(9, OWNER, "sales", "completed", 5),
      task(10, OWNER, "seo", "completed", 45),
      task(11, OTHER, "content", "failed", 1),
      task(12, OTHER, "sales", "dry_run", 1),
      task(13, OWNER, "email", "completed", 6, "email/subject-lines"),   // a dispatched run
      task(14, OWNER, "email", "failed", 7.5, "email/subject-lines")     // an older dispatched run
    ],
    executive_dispatches: [
      dispatchRow(1, OWNER, 1, 1, "failed", 7.5, { refused_reason: "handler_error", detail: "boom", tool_task_id: T(14) }),
      dispatchRow(2, OWNER, 1, 1, "ran", 6, { tool_task_id: T(13), chain_id: id("74444444", 1) }),
      dispatchRow(3, OWNER, 1, 2, "refused", 5, { refused_reason: "assignment_not_dispatchable", detail: "no such tool" }),
      dispatchRow(4, OTHER, 1, 3, "ran", 0.1, { tool_task_id: T(11) }),          // another user's row naming the owner's plan id
      dispatchRow(5, OWNER, 6, 1, "ran", 5.5, { tool_task_id: T(13) })           // the sixth plan, not shown
    ],
    agent_proposals: [
      { id: id("75555555", 1), user_id: OWNER, title: "Publish post A", agent_type: "seo", status: "pending", created_at: ago(1) },
      { id: id("75555555", 2), user_id: OWNER, title: "List item B", agent_type: "store", status: "pending", created_at: ago(2) },
      { id: id("75555555", 3), user_id: OWNER, title: "Done C", agent_type: "seo", status: "executed", created_at: ago(3) },
      { id: id("75555555", 4), user_id: OTHER, title: "Other's D", agent_type: "seo", status: "pending", created_at: ago(1) }
    ],
    agent_autonomy: [
      { user_id: OWNER, agent_type: "store", enabled: true, updated_at: ago(30) },
      { user_id: OWNER, agent_type: "ads", enabled: false, updated_at: ago(20) },
      { user_id: OTHER, agent_type: "seo", enabled: true, updated_at: ago(1) }
    ],
    agent_schedules: [
      { user_id: OWNER, agent_type: "content", task_type: "content_plan", prompt: "weekly", cadence: "weekly", hour_utc: 9, day_of_week: 1,
        day_of_month: null, enabled: true, last_run_on: null, created_at: ago(3), updated_at: ago(3) },
      { user_id: OTHER, agent_type: "seo", task_type: "general", prompt: "x", cadence: "daily", hour_utc: 1, day_of_week: null,
        day_of_month: null, enabled: true, last_run_on: null, created_at: ago(3), updated_at: ago(3) }
    ],
    email_sequences: [
      { id: id("76666666", 1), owner_id: OWNER, name: "Welcome", status: "active", created_at: ago(2), steps: [] },
      { id: id("76666666", 2), owner_id: OWNER, name: "Winback", status: "paused", created_at: ago(1), steps: [] },
      { id: id("76666666", 3), owner_id: OTHER, name: "Other's", status: "active", created_at: ago(1), steps: [] }
    ],
    email_sequence_enrollments: [
      { id: id("77777777", 1), sequence_id: id("76666666", 1), status: "active" },
      { id: id("77777777", 2), sequence_id: id("76666666", 1), status: "active" },
      { id: id("77777777", 3), sequence_id: id("76666666", 1), status: "stopped" },
      { id: id("77777777", 4), sequence_id: id("76666666", 3), status: "active" }
    ],
    social_post_drafts: [
      { id: id("78888888", 1), user_id: OWNER, status: "pending_approval" },
      { id: id("78888888", 2), user_id: OWNER, status: "published" },
      { id: id("78888888", 3), user_id: OWNER, status: "published" },
      { id: id("78888888", 4), user_id: OTHER, status: "published" }
    ],
    content_library: [
      { id: id("79999999", 1), user_id: OWNER, status: "published", published_at: ago(3) },
      { id: id("79999999", 2), user_id: OWNER, status: "published", published_at: ago(40) },
      { id: id("79999999", 3), user_id: OWNER, status: "draft", published_at: null },
      { id: id("79999999", 4), user_id: OTHER, status: "published", published_at: ago(1) }
    ],
    model_calls: [
      { id: 1, user_id: OWNER, model: "claude-sonnet-5", input_tokens: 1000000, output_tokens: 100000, funded_by: "platform", created_on: MONTH_START },
      { id: 2, user_id: OWNER, model: "claude-haiku-4-5-20251001", input_tokens: 500000, output_tokens: 0, funded_by: null, created_on: MONTH_START },
      { id: 3, user_id: OWNER, model: "claude-sonnet-5", input_tokens: 9000000, output_tokens: 0, funded_by: "user", created_on: MONTH_START },
      { id: 4, user_id: OWNER, model: "claude-sonnet-5", input_tokens: 9000000, output_tokens: 0, funded_by: "platform", created_on: "2000-01-01" },
      { id: 5, user_id: OTHER, model: "claude-sonnet-5", input_tokens: 9000000, output_tokens: 0, funded_by: "platform", created_on: MONTH_START }
    ],
    job_runs: [
      { job_name: "daily_self_reviews", last_run_on: "2026-10-12", started_at: ago(0.1), finished_at: ago(0.1), last_error: null }
    ],
    radar_status: [
      { source: "bluesky", last_outcome: "nothing_new", last_tick_finished_at: ago(0.01), last_error: null }
    ]
  };
}
// $2 for 1M sonnet-5 input + $1 for 100k output, $0.50 for 500k haiku input; the user-funded and last month's rows are not counted.
const EXPECTED_USD = 3.5;
const ENV_SET = { ENABLE_EMAIL_SEQUENCES: "true", MAIL_POSTAL_ADDRESS: "SECRET-POSTAL 9 Hidden Lane", RESEND_WEBHOOK_SECRET: "whsec_LEAKME",
  EMAIL_MARKETING_DAILY_CAP: "37" };

function build(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed, o.fail);
  const logs = [];
  const refusedBy = [];
  const dispatchCalls = [];
  const ctx = {
    supabase: db.client, JSON, Math, Promise, Date, crypto,
    /* BEFORE (backend 5da9dfe): no require; nothing lifted needed one.
       AFTER (legal pages): the sender readiness reads require("./lib/legal").POSTAL_ADDRESS,
       resolved from server.js's directory as server.js resolves it. */
    require: require("module").createRequire(path.join(REPO, "server.js")),
    nowIso: () => new Date().toISOString(),
    process: { env: Object.assign({}, o.env === undefined ? ENV_SET : o.env) },
    console: { log: m => logs.push(String(m)), error: (...a) => logs.push(a.map(String).join(" ")), warn: m => logs.push(String(m)) },
    requireAuth: function requireAuth(req, res, next) { req.user = { id: req.headers.user, role: USERS[req.headers.user].role }; next(); },
    requireActiveSubscription: function requireActiveSubscription(req, res, next) {
      if (!USERS[req.user.id].subscribed) { refusedBy.push("requireActiveSubscription"); return res.status(402).json({ error: "Subscription required", upgrade_required: true }); }
      next();
    },
    requireAdmin: function requireAdmin(req, res, next) {
      if (req.user.role !== "admin") { refusedBy.push("requireAdmin"); return res.status(403).json({ error: "Admin access required" }); }
      next();
    },
    aiLimiter: function aiLimiter(req, res, next) { next(); },
    dispatchToolCall: async function (args) {
      dispatchCalls.push(args);
      const mode = o.dispatch || "ran";
      if (mode === "ran") return { ok: true, status: 200, body: { success: true, task_id: T(13), persisted: true }, refused_reason: null };
      if (mode === "refused") return { ok: false, status: null, body: null, refused_reason: "chain_depth_reached", detail: "CHAIN_MAX_DEPTH is 2." };
      if (mode === "threw") return { ok: false, status: 500, body: null, refused_reason: "handler_error", detail: "the tool threw" };
      throw new Error("unplanned dispatch mode " + mode);
    }
  };
  const routes = {};
  const register = (method) => function (p) { routes[method + " " + p] = [].slice.call(arguments, 1); };
  ctx.app = { get: register("get"), post: register("post") };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);

  async function call(key, user, body) {
    const chain = routes[key];
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    const req = { headers: { user }, params: {}, query: {}, body: body || {} };
    let i = 0;
    let error = null;
    async function step() {
      const fn = chain[i++];
      if (!fn) return;
      let advanced = false;
      await fn(req, res, (e) => { if (e) { error = e; res.code = 500; return; } advanced = true; });
      if (advanced) await step();
    }
    await step();
    res.error = error;
    return res;
  }
  return {
    db, logs, routes, refusedBy, dispatchCalls,
    dispatch: (user, planId, assignmentId) => call("post /api/assignments/dispatch", user, { executive_task_id: planId, assignment_id: assignmentId }),
    center: (user) => call("get /api/command-center", user),
    sequences: (user) => call("get /api/email/sequences", user),
    newDispatches: () => db.tables.executive_dispatches.slice(world().executive_dispatches.length)
  };
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
// Key order is not part of a count.
const canon = (o) => o && typeof o === "object" && !Array.isArray(o) ? Object.keys(o).sort().reduce((m, k) => { m[k] = canon(o[k]); return m; }, {}) : o;
const SECTIONS = ["needs_you", "plans", "activity", "autopilot", "outbound", "spend"];

(async function main() {
  /* ── 1. dispatch records every outcome ─────────────────────────────────── */
  console.log("\n══ 1. every dispatch of a real plan is recorded ══");
  let b = build(world(), { dispatch: "ran" });
  let r = await b.dispatch(OWNER, P(1), 1);
  let rows = b.newDispatches();
  check("ran: the answer is ok, carries the chain id, and says recorded:true",
    r.code === 200 && r.body.ok === true && typeof r.body.chain_id === "string" && r.body.recorded === true, JSON.stringify(r.body));
  check("ran: exactly one row, outcome ran, the caller's id and the plan read back",
    rows.length === 1 && rows[0].outcome === "ran" && rows[0].user_id === OWNER && rows[0].plan_task_id === P(1) && rows[0].assignment_id === 1, JSON.stringify(rows));
  check("ran: tool_task_id is the result's task_id, chain_id is the answer's chain id, agent and tool from the assignment",
    rows[0] && rows[0].tool_task_id === T(13) && rows[0].chain_id === r.body.chain_id && rows[0].agent_type === "email" && rows[0].tool === "subject-lines" &&
    rows[0].refused_reason === null && rows[0].detail === null, JSON.stringify(rows[0]));

  b = build(world(), { dispatch: "refused" });
  r = await b.dispatch(OWNER, P(1), 1);
  rows = b.newDispatches();
  check("refused by the dispatcher: one row, outcome refused, with its reason and detail, recorded:true",
    rows.length === 1 && rows[0].outcome === "refused" && rows[0].refused_reason === "chain_depth_reached" && rows[0].detail === "CHAIN_MAX_DEPTH is 2." &&
    rows[0].tool_task_id === null && r.body.ok === false && r.body.recorded === true, JSON.stringify(rows) + " " + JSON.stringify(r.body));

  b = build(world());
  r = await b.dispatch(OWNER, P(1), 2);
  rows = b.newDispatches();
  check("refused by the route (not dispatchable): one row with refused_reason and detail, and the tool was never called",
    rows.length === 1 && rows[0].outcome === "refused" && rows[0].refused_reason === "assignment_not_dispatchable" && /not dispatchable/.test(rows[0].detail || "") &&
    b.dispatchCalls.length === 0 && r.body.refused_reason === "assignment_not_dispatchable" && r.body.recorded === true, JSON.stringify(rows) + " " + JSON.stringify(r.body));
  r = await b.dispatch(OWNER, P(1), 9);
  rows = b.newDispatches();
  check("refused by the route (no such assignment): a second row, assignment_not_in_plan, recorded:true",
    rows.length === 2 && rows[1].outcome === "refused" && rows[1].refused_reason === "assignment_not_in_plan" && rows[1].assignment_id === 9 && r.body.recorded === true,
    JSON.stringify(rows[1]) + " " + JSON.stringify(r.body));
  const noOutput = world();
  noOutput.ai_tasks.find(t => t.id === P(3)).output = null;
  b = build(noOutput);
  r = await b.dispatch(OWNER, P(3), 1);
  rows = b.newDispatches();
  check("refused by the route (plan has no output): one row, plan_has_no_output",
    rows.length === 1 && rows[0].refused_reason === "plan_has_no_output" && r.body.recorded === true, JSON.stringify(rows));

  b = build(world(), { dispatch: "threw" });
  r = await b.dispatch(OWNER, P(1), 1);
  rows = b.newDispatches();
  check("failed (the tool threw): one row, outcome failed, with the chain id and the error detail",
    rows.length === 1 && rows[0].outcome === "failed" && rows[0].refused_reason === "handler_error" && rows[0].detail === "the tool threw" &&
    rows[0].chain_id === r.body.chain_id && r.body.recorded === true, JSON.stringify(rows) + " " + JSON.stringify(r.body));

  /* ── 2. nothing for a plan that is not the caller's ───────────────────── */
  console.log("\n══ 2. nothing is recorded without a real plan of the caller's ══");
  b = build(world());
  r = await b.dispatch(OWNER, id("7fffffff", 1), 1);
  check("a missing plan: plan_not_found, no row, recorded:false",
    r.body.refused_reason === "plan_not_found" && b.newDispatches().length === 0 && r.body.recorded === false, JSON.stringify(r.body));
  r = await b.dispatch(OWNER, P(7), 1);
  check("another user's plan: plan_not_found, no row, the tool never called",
    r.body.refused_reason === "plan_not_found" && b.newDispatches().length === 0 && b.dispatchCalls.length === 0, JSON.stringify(r.body));
  r = await b.dispatch(OWNER, T(90), 1);
  check("a task that is not a plan: not_an_executive_plan, no row",
    r.body.refused_reason === "not_an_executive_plan" && b.newDispatches().length === 0, JSON.stringify(r.body));
  r = await b.dispatch(OWNER, "not-a-uuid", 1);
  check("a malformed id: 400, no row", r.code === 400 && b.newDispatches().length === 0, r.code);

  /* ── 3. a failed record write ─────────────────────────────────────────── */
  console.log("\n══ 3. a failed record write changes only recorded ══");
  const writeFails = q => q.table === "executive_dispatches" && q.op === "insert" ? { message: "permission denied for table executive_dispatches" } : null;
  const good = await build(world(), { dispatch: "ran" }).dispatch(OWNER, P(1), 1);
  b = build(world(), { dispatch: "ran", fail: writeFails });
  r = await b.dispatch(OWNER, P(1), 1);
  const strip = (x) => { const c = Object.assign({}, x); delete c.chain_id; delete c.recorded; return c; };
  check("ran with a failed write: the same answer, recorded:false",
    r.code === 200 && r.body.recorded === false && same(strip(r.body), strip(good.body)), JSON.stringify(r.body));
  check("and the failure is logged", b.logs.some(l => /DISPATCH NOT RECORDED/.test(l) && /permission denied/.test(l)), JSON.stringify(b.logs));
  b = build(world(), { fail: writeFails });
  r = await b.dispatch(OWNER, P(1), 2);
  check("refused with a failed write: still the refusal, recorded:false",
    r.code === 200 && r.body.refused_reason === "assignment_not_dispatchable" && r.body.recorded === false, JSON.stringify(r.body));

  /* ── 4. the command center, from fixtures ─────────────────────────────── */
  console.log("\n══ 4. GET /api/command-center, section by section ══");
  b = build(world());
  r = await b.center(OWNER);
  const cc = r.body || {};
  check("200, every section ok", r.code === 200 && SECTIONS.every(k => cc[k] && cc[k].ok === true), JSON.stringify(SECTIONS.map(k => [k, cc[k] && cc[k].ok, cc[k] && cc[k].error])));

  const ny = (cc.needs_you || {}).data || {};
  check("needs_you: the caller's two pending proposals, newest first, with id, title, agent_type, created_at",
    ny.pending_proposals && ny.pending_proposals.count === 2 && same(ny.pending_proposals.rows.map(x => x.title), ["Publish post A", "List item B"]) &&
    same(Object.keys(ny.pending_proposals.rows[0]), ["id", "title", "agent_type", "created_at"]), JSON.stringify(ny.pending_proposals));
  check("needs_you: the one run that failed in the last 7 days (not the 10-day-old one), with id, agent_type, task_type, created_at",
    ny.failed_runs_7d && ny.failed_runs_7d.count === 1 && ny.failed_runs_7d.rows.length === 1 && ny.failed_runs_7d.rows[0].id === T(2) &&
    same(Object.keys(ny.failed_runs_7d.rows[0]), ["id", "agent_type", "task_type", "created_at"]), JSON.stringify(ny.failed_runs_7d));
  const seqSender = (await b.sequences(OWNER)).body.sender;
  const ccSender = Object.assign({}, ny.email_sender); delete ccSender.blocked_by;
  check("needs_you: the sender's booleans are exactly GET /api/email/sequences's, and nothing blocks it",
    same(ccSender, seqSender) && same(ny.email_sender.blocked_by, []), JSON.stringify(ny.email_sender) + " vs " + JSON.stringify(seqSender));
  const unset = build(world(), { env: { EMAIL_MARKETING_DAILY_CAP: "x" } });
  const ny2 = (await unset.center(OWNER)).body.needs_you.data.email_sender;
  const seq2 = (await unset.sequences(OWNER)).body.sender;
  const ny2b = Object.assign({}, ny2); delete ny2b.blocked_by;
  /* BEFORE (backend 5da9dfe): "blocked_by names all four", postal_address_set among them, read from MAIL_POSTAL_ADDRESS.
     AFTER (legal pages): the postal address is lib/legal.js POSTAL_ADDRESS, the one copy, so it is always set and
     blocks nothing; the other three still do. */
  check("needs_you: with the sender unconfigured, the same booleans, and blocked_by names the three settings (the postal address is lib/legal.js's, always set)",
    same(ny2b, seq2) && ny2.postal_address_set === true && same(ny2.blocked_by, ["enabled", "webhook_secret_set", "daily_cap"]), JSON.stringify(ny2));
  check("needs_you: no environment value is in the answer", !/SECRET-POSTAL|whsec_LEAKME/.test(JSON.stringify(cc)));

  const plans = (cc.plans || {}).data || [];
  check("plans: the five newest of the caller's plans, newest first (not the sixth, not another user's)",
    same(plans.map(p => p.id), [P(1), P(2), P(3), P(4), P(5)]), JSON.stringify(plans.map(p => p.id)));
  check("plans: each with id, goal, status, created_at and assignments",
    plans[0] && plans[0].goal === "Goal 1" && same(Object.keys(plans[0]), ["id", "goal", "status", "created_at", "assignments"]), JSON.stringify(plans[0] && Object.keys(plans[0])));
  const a1 = (plans[0] && plans[0].assignments[0]) || {};
  check("plans: an assignment carries id, agent, tool, task, priority, is_dispatchable, problems, latest_dispatch",
    same(Object.keys(a1), ["id", "agent", "tool", "task", "priority", "is_dispatchable", "problems", "latest_dispatch"]), JSON.stringify(Object.keys(a1)));
  check("plans: the LATEST dispatch (ran, 6 days ago — not the older failure), with its run's status",
    a1.latest_dispatch && a1.latest_dispatch.outcome === "ran" && a1.latest_dispatch.tool_task_id === T(13) && a1.latest_dispatch.tool_task_status === "completed" &&
    a1.latest_dispatch.refused_reason === null && typeof a1.latest_dispatch.created_at === "string", JSON.stringify(a1.latest_dispatch));
  const a2 = (plans[0] && plans[0].assignments[1]) || {};
  check("plans: a refused assignment shows refused and its reason; its problems and is_dispatchable false are carried",
    a2.latest_dispatch && a2.latest_dispatch.outcome === "refused" && a2.latest_dispatch.refused_reason === "assignment_not_dispatchable" &&
    a2.is_dispatchable === false && same(a2.problems, ["no such tool"]), JSON.stringify(a2));
  const a3 = (plans[0] && plans[0].assignments[2]) || {};
  check("plans: an assignment with only another user's dispatch row is \"not dispatched\"", a3.latest_dispatch === "not dispatched", JSON.stringify(a3.latest_dispatch));
  check("plans: a plan with no assignments has an empty list", plans[2] && same(plans[2].assignments, []), JSON.stringify(plans[2]));

  const act = (cc.activity || {}).data || {};
  check("activity: last 30 days by agent_type and status, sales dry runs excluded (the six plans are executive runs)",
    same(canon(act.by_agent_type), canon({ executive: { completed: 6 }, content: { completed: 2, failed: 1 }, social: { completed: 1 },
      email: { failed: 2, completed: 1 }, sales: { completed: 1 } })), JSON.stringify(act.by_agent_type));
  check("activity: sales_dry_runs is the separate count of the three in the window (not the 40-day-old one, not another user's)",
    act.sales_dry_runs === 3, act.sales_dry_runs);
  check("activity: no dry_run status anywhere in the counts", !/dry_run/.test(JSON.stringify(act.by_agent_type)), JSON.stringify(act.by_agent_type));
  check("activity: total is the sum of the counts",
    act.total === Object.values(act.by_agent_type || {}).reduce((n, st) => n + Object.values(st).reduce((m, v) => m + v, 0), 0), act.total);
  check("activity: the ten newest runs, no dry run, with id, agent_type, task_type, status, created_at",
    Array.isArray(act.newest_runs) && act.newest_runs.length === 10 && act.newest_runs.every(x => x.status !== "dry_run") &&
    same(Object.keys(act.newest_runs[0]), ["id", "agent_type", "task_type", "status", "created_at"]), JSON.stringify(act.newest_runs));

  const ap = (cc.autopilot || {}).data || {};
  check("autopilot: the caller's two autonomy rows and one schedule",
    same((ap.autonomy || []).map(x => x.agent_type), ["ads", "store"]) && (ap.schedules || []).length === 1 && ap.schedules[0].agent_type === "content",
    JSON.stringify(ap));

  const ob = (cc.outbound || {}).data || {};
  check("outbound: the caller's sequences with enrollment counts by status",
    same(ob.email_sequences, [{ id: id("76666666", 2), name: "Winback", status: "paused", enrollments: {} },
      { id: id("76666666", 1), name: "Welcome", status: "active", enrollments: { active: 2, stopped: 1 } }]), JSON.stringify(ob.email_sequences));
  check("outbound: social drafts counted by status", same(ob.social_drafts_by_status, { pending_approval: 1, published: 2 }), JSON.stringify(ob.social_drafts_by_status));
  check("outbound: one item published in the last 30 days", ob.content_published_30d && ob.content_published_30d.count === 1, JSON.stringify(ob.content_published_30d));

  const sp = (cc.spend || {}).data || {};
  check("spend: this month's cost from modelSpendThisMonth (user-funded, last month's and another user's rows not counted)",
    Math.abs(sp.usd - EXPECTED_USD) < 1e-9 && sp.ledger_rows === 3, JSON.stringify(sp));
  check("spend: the monthly cap (default $60) and the note that cache tokens are not recorded",
    sp.monthly_cap_usd === 60 && /cache/i.test(sp.note || "") && /understate/i.test(sp.note || ""), JSON.stringify(sp));

  /* ── 5. a failed read fails its own section only ──────────────────────── */
  console.log("\n══ 5. one failed read never blanks the others ══");
  b = build(world(), { fail: q => q.table === "agent_proposals" ? { message: "proposals table unreachable" } : null });
  r = await b.center(OWNER);
  check("needs_you: ok false with the error, and no data", r.body.needs_you && r.body.needs_you.ok === false &&
    /proposals table unreachable/.test(r.body.needs_you.error || "") && r.body.needs_you.data === undefined, JSON.stringify(r.body.needs_you));
  check("every other section still answers with its data",
    ["plans", "activity", "autopilot", "outbound", "spend"].every(k => r.body[k].ok === true && r.body[k].data) && r.body.plans.data.length === 5,
    JSON.stringify(["plans", "activity", "autopilot", "outbound", "spend"].map(k => [k, r.body[k].ok])));
  b = build(world(), { fail: q => q.table === "model_calls" ? { message: "ledger unreachable" } : null });
  r = await b.center(OWNER);
  check("spend: a failed ledger read is ok false, never a zero", r.body.spend.ok === false && r.body.spend.data === undefined && r.body.needs_you.ok === true,
    JSON.stringify(r.body.spend));
  b = build(world(), { fail: q => q.table === "executive_dispatches" ? { message: "dispatches unreachable" } : null });
  r = await b.center(OWNER);
  check("plans: a failed dispatch read fails plans, never shows \"not dispatched\"", r.body.plans.ok === false && r.body.activity.ok === true,
    JSON.stringify(r.body.plans));

  /* ── 6. other users' rows, platform, the gate ─────────────────────────── */
  console.log("\n══ 6. scope, platform and gate ══");
  b = build(world());
  const owner = (await b.center(OWNER)).body;
  const other = (await b.center(OTHER)).body;
  const ownerText = JSON.stringify(owner);
  check("the owner's answer holds none of another user's rows",
    !/Other's D|Other's/.test(ownerText) && ownerText.indexOf(P(7)) === -1 && ownerText.indexOf(T(11)) === -1 && ownerText.indexOf(T(12)) === -1, "");
  check("another user's answer holds only their own: one pending proposal, one plan, one failed run",
    other.needs_you.data.pending_proposals.count === 1 && same(other.plans.data.map(p => p.id), [P(7)]) &&
    other.needs_you.data.failed_runs_7d.count === 1 && other.activity.data.sales_dry_runs === 1 && other.outbound.data.content_published_30d.count === 1,
    JSON.stringify([other.needs_you, other.plans.data.map(p => p.id)]));
  check("another user's plan shows \"not dispatched\" even though a row of theirs names the owner's plan",
    other.plans.data[0].assignments[0].latest_dispatch === "not dispatched", JSON.stringify(other.plans.data[0].assignments[0]));
  check("every query of every table was scoped to the caller (user_id or owner_id), except platform's",
    b.db.log.filter(q => ["job_runs", "radar_status", "email_sequence_enrollments"].indexOf(q.table) === -1)
      .every(q => q.filters.some(f => f[0] === "eq" && (f[1] === "user_id" || f[1] === "owner_id"))),
    JSON.stringify(b.db.log.filter(q => !q.filters.some(f => f[0] === "eq" && (f[1] === "user_id" || f[1] === "owner_id"))).map(q => q.table)));
  check("platform: present for the admin, with job_runs and radar_status",
    owner.platform && owner.platform.ok === true && owner.platform.data.job_runs.length === 1 && owner.platform.data.radar_status.length === 1,
    JSON.stringify(owner.platform));
  check("platform: absent for a non-admin", other.platform === undefined && !("platform" in other), JSON.stringify(Object.keys(other)));

  b = build(world());
  r = await b.center(LAPSED);
  check("a lapsed account reads the command center: 200, every section ok", r.code === 200 && SECTIONS.every(k => r.body[k] && r.body[k].ok === true),
    r.code + " " + JSON.stringify(r.body));
  check("no subscription gate refused anything", b.refusedBy.length === 0, JSON.stringify(b.refusedBy));
  check("GET /api/command-center: requireAuth and nothing else before the handler",
    same(b.routes["get /api/command-center"].slice(0, -1).map(f => f.name), ["requireAuth"]), JSON.stringify(b.routes["get /api/command-center"].slice(0, -1).map(f => f.name)));
  check("platform: absent for the lapsed non-admin too", r.body.platform === undefined);

  /* ── 7. no model call ─────────────────────────────────────────────────── */
  console.log("\n══ 7. read from rows only ══");
  const ccText = uncommented(routeText("get", "/api/command-center"));
  check("the command center route names no model call", !/callAnthropicText|messages\.create|toolGenerate/.test(LIFTED.slice(LIFTED.indexOf("async function commandCenterSection"))) &&
    !/callAnthropicText|messages\.create/.test(ccText));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
