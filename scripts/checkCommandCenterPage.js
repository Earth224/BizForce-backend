"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkCommandCenterPage — the dashboard's Command Center shows what really
   happened, and the local-only code and stale labels it replaced are gone.

   Frontend "A command center built on what really happened" added the Command
   Center above the Agent Work Queue, removed the local-only memory, messaging
   and autonomy stores (and every function that existed only to serve them),
   the dashboard's sample-output banner, the hidden Tier D tracker, the typed
   "18" agent count and executive-agent.html's locally computed stats grid.

   THE FIXTURES ARE THE REAL ROUTE'S ANSWERS. GET /api/command-center and
   POST /api/assignments/dispatch are lifted from server.js — with the real
   dispatchToolCall, which refuses with chaining_disabled because
   ENABLE_AGENT_CHAINING is not set here — and run in a vm against an
   in-memory database. The page's own Command Center script runs in a second
   vm with a stubbed DOM, and its fetch is answered by those routes. No
   network, no model call, no database.

   WHAT THIS PROVES
     1. Each section renders its data: needs you, executive plans, agent
        activity (sales dry runs apart), autopilot, outbound, spend (with the
        server's note verbatim) and, for an admin, platform.
     2. A section the server could not read shows its error in its own panel
        while every other section renders; it never reads as empty.
     3. "Nothing needs you" appears only when proposals, failed runs and the
        email sender are all real and empty.
     4. Dispatch appears only on a dispatchable assignment whose latest
        dispatch did not run; clicking it posts the plan id and the assignment
        id, shows the answer verbatim (a refusal included), then reads the
        Command Center again and shows the recorded refusal.
     5. The platform panel stays hidden when the answer has no platform.
     6. The topbar count is "—" until GET /api/agents answers, "?" when it
        fails, and no typed 18 remains.
     7. No .bf-sim-banner, no Tier D tracker, no "Sample" note or stats grid
        on executive-agent.html, which links to the Command Center instead.
     8. None of the removed functions is declared or named anywhere in the
        frontend; the Agent Work Queue and the browser-side parse that filled
        it are gone (launch audit #22a); every inline script in both pages
        parses; the Command Center sets no timer.
     9. The renderer is one shared script, scripts/bf-command-center.js (Block
        3a), loaded right after the section by dashboard.html and by
        executive-agent.html (Headquarters); the same answer renders the same
        panels on both, and a member's platform panel stays hidden on both.

   MUTATE=<name> edits the frontend files IN MEMORY. MUTATE=all runs each in
   its own process and passes only if every one fails at least one check. A
   mutation whose search text does not match exactly once is an ERROR, never
   counted as caught.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const DASH = "dashboard.html", EXEC = "executive-agent.html", CC = "scripts/bf-command-center.js";

const FAILED_PANEL = "            setPanel(PANELS[name], errorBox(section.error || \"the server gave no reason\"));\n";
/* NAMED (Block 3a, Oct 29 2026): the Command Center's renderer moved from dashboard.html into
   scripts/bf-command-center.js, so the three mutations anchored in it now edit that file
   (before: DASH). The markup mutations stay on DASH. */
const MUTATIONS = {
  // a section the server could not read says "Nothing needs you"
  "nothing-needs-you-on-failure": [[CC, FAILED_PANEL,
    "            setPanel(PANELS[name], name === \"needs_you\" ? '<p class=\"cc-clear\">Nothing needs you.</p>' : errorBox(section.error || \"the server gave no reason\"));\n"]],
  // Dispatch is offered on an assignment that already ran
  "dispatch-on-ran": [[CC, "                if (a.is_dispatchable === true && !ran) {\n", "                if (a.is_dispatchable === true) {\n"]],
  // the typed agent count comes back
  "restore-18": [[DASH, "<span class=\"topbar-agents-num\">—</span>", "<span class=\"topbar-agents-num\">18</span>"]],
  // a failed section renders as an empty panel
  "failed-section-empty": [[CC, FAILED_PANEL, "            setPanel(PANELS[name], \"\");\n"]],
  // the Agent Work Queue comes back below the Command Center (launch audit #22a)
  "work-queue-returns": [[DASH, "<section id=\"agentMemorySection\"",
    "<section id=\"agentAssignmentsSection\" class=\"bf-section\"><div id=\"activeAssignmentsList\"></div></section>\n<section id=\"agentMemorySection\""]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the frontend ───────────────────────────────────────────────────────── */
const FILES = {};
(function walk(dir) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
    const p = path.join(dir, d.name);
    if (d.isDirectory()) { if (!/^\.|node_modules/.test(d.name)) walk(p); }
    else if (/\.(html|js|css)$/.test(d.name)) FILES[path.relative(FRONTEND, p).replace(/\\/g, "/")] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
  });
})(FRONTEND);
if (!FILES[DASH] || !FILES[EXEC]) { console.error("Frontend not found at " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (frontend, in memory)");
}
const inlineScripts = (html) => {
  const out = []; const re = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/g; let m;
  while ((m = re.exec(html))) if (!(m[1] && /\bsrc=/.test(m[1]))) out.push(m[2]);
  return out;
};
/* NAMED (Block 3a, Oct 29 2026): before, the script under test was dashboard.html's inline
   "(function commandCenter() {" block. It is scripts/bf-command-center.js now, and section 9
   proves both pages load it right after their own #commandCenterSection. */
const CC_SCRIPT = [FILES[CC] || ""].filter(code => code.indexOf("(function commandCenter() {") !== -1);

/* ── the server, lifted (the same lifter as checkCommandCenter) ──────────── */
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
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
// dispatchToolCall is NOT stubbed: its gate is what answers the dispatch below.
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout",
  "requireAuth", "requireActiveSubscription", "requireAdmin", "aiLimiter", "crypto", "Date", "cron", "Anthropic"]);
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
const LIFTED = closure(routeText("get", "/api/command-center") + "\n\n" + routeText("post", "/api/assignments/dispatch"));

/* ── the fake database ──────────────────────────────────────────────────── */
const TABLES = ["ai_tasks", "executive_dispatches", "agent_proposals", "agent_autonomy", "agent_schedules", "email_sequences",
  "email_sequence_enrollments", "social_post_drafts", "content_library", "model_calls", "job_runs", "radar_status"];
function fakeDb(seed, fail) {
  const tables = {};
  TABLES.forEach(t => { tables[t] = ((seed || {})[t] || []).map(r => JSON.parse(JSON.stringify(r))); });
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
      rows.push(Object.assign({ id: crypto.randomUUID(), created_at: new Date().toISOString() }, JSON.parse(JSON.stringify(q.payload))));
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
    const b = {
      select(cols, opts) { q.cols = cols || "*"; q.opts = opts || null; return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; }
    };
    ["eq", "in", "gte", "or", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { tables, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";   // admin
const USER = "aaaaaaaa-0000-4000-8000-000000000002";    // not an admin
const OTHER = "aaaaaaaa-0000-4000-8000-000000000003";
const ROLES = { [OWNER]: "admin", [USER]: "user", [OTHER]: "user" };
const NOW = Date.now();
const ago = (days) => new Date(NOW - days * 86400000).toISOString();
const id = (prefix, k) => prefix + "-1111-4111-8111-" + String(k).padStart(12, "0");
const T = (k) => id("71111111", k), P = (k) => id("72222222", k), D = (k) => id("73333333", k);
const assignment = (n, extra) => Object.assign({ id: n, agent: "email", tool: "subject-lines", task: "Write subject lines " + n, priority: "high",
  inputs: { purpose: "fixture " + n }, is_dispatchable: true, problems: [], inputs_missing: [] }, extra || {});
const plan = (k, owner, days, goal, assignments) => ({ id: P(k), user_id: owner, agent_type: "executive", task_type: "executive/plan",
  status: "completed", prompt: "Plan " + k, created_at: ago(days), output: goal === null ? null : { goal, assignments } });
const task = (k, owner, agent, status, days, taskType) => ({ id: T(k), user_id: owner, agent_type: agent, task_type: taskType || "general",
  status, prompt: "t" + k, created_at: ago(days) });
const dispatchRow = (k, owner, planK, assignmentId, outcome, days, extra) => Object.assign({ id: D(k), user_id: owner, plan_task_id: P(planK),
  assignment_id: assignmentId, agent_type: "email", tool: "subject-lines", outcome, refused_reason: null, detail: null, tool_task_id: null,
  chain_id: null, created_at: ago(days) }, extra || {});
const MONTH_START = (() => { const n = new Date(NOW); return new Date(Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), 1)).toISOString().slice(0, 10); })();
function world() {
  return {
    ai_tasks: [
      plan(1, OWNER, 1, "Grow the newsletter", [
        assignment(1),                                                                   // ran
        assignment(2, { is_dispatchable: false, problems: ["no such tool"], tool: "nope" }), // refused, not runnable
        assignment(3),                                                                   // not dispatched
        assignment(4),                                                                   // refused: chaining disabled
        assignment(5)                                                                    // failed
      ]),
      plan(2, OWNER, 2, "Launch the spring sale", []),
      plan(3, OWNER, 3, null, null),
      plan(9, OTHER, 0.5, "Another account's goal", [assignment(1)]),
      task(1, OWNER, "content", "completed", 1, "content/outline"),
      task(2, OWNER, "content", "failed", 2, "content/outline"),
      task(3, OWNER, "social", "completed", 3, "social/calendar"),
      task(4, OWNER, "email", "failed", 10),
      task(5, OWNER, "sales", "dry_run", 0.1),
      task(6, OWNER, "sales", "dry_run", 0.2),
      task(7, OWNER, "sales", "dry_run", 4),
      task(9, OWNER, "sales", "completed", 5),
      task(10, OWNER, "seo", "completed", 45),
      task(11, OTHER, "content", "failed", 1),
      task(13, OWNER, "email", "completed", 6, "email/subject-lines"),
      task(14, OWNER, "email", "failed", 7.5, "email/subject-lines")
    ],
    executive_dispatches: [
      dispatchRow(1, OWNER, 1, 1, "failed", 7.5, { refused_reason: "handler_error", detail: "boom", tool_task_id: T(14) }),
      dispatchRow(2, OWNER, 1, 1, "ran", 6, { tool_task_id: T(13) }),
      dispatchRow(3, OWNER, 1, 2, "refused", 5, { refused_reason: "assignment_not_dispatchable", detail: "no such tool" }),
      dispatchRow(4, OWNER, 1, 4, "refused", 4, { refused_reason: "chaining_disabled" }),
      dispatchRow(5, OWNER, 1, 5, "failed", 3, { refused_reason: "handler_error", detail: "the tool threw" }),
      dispatchRow(6, OTHER, 1, 3, "ran", 0.1, { tool_task_id: T(11) })   // another account's row naming the owner's plan
    ],
    agent_proposals: [
      { id: id("75555555", 1), user_id: OWNER, title: "Publish post A", agent_type: "seo", status: "pending", created_at: ago(1) },
      { id: id("75555555", 2), user_id: OWNER, title: "List item B", agent_type: "store", status: "pending", created_at: ago(2) },
      { id: id("75555555", 3), user_id: OWNER, title: "Done C", agent_type: "seo", status: "executed", created_at: ago(3) },
      { id: id("75555555", 4), user_id: OTHER, title: "Another account's proposal", agent_type: "seo", status: "pending", created_at: ago(1) }
    ],
    agent_autonomy: [
      { user_id: OWNER, agent_type: "store", enabled: true, updated_at: ago(30) },
      { user_id: OWNER, agent_type: "ads", enabled: false, updated_at: ago(20) }
    ],
    agent_schedules: [
      { user_id: OWNER, agent_type: "content", task_type: "content_plan", prompt: "weekly", cadence: "weekly", hour_utc: 9, day_of_week: 1,
        day_of_month: null, enabled: true, last_run_on: null, created_at: ago(3), updated_at: ago(3) }
    ],
    email_sequences: [
      { id: id("76666666", 1), owner_id: OWNER, name: "Welcome", status: "active", created_at: ago(2), steps: [] },
      { id: id("76666666", 2), owner_id: OWNER, name: "Winback", status: "paused", created_at: ago(1), steps: [] }
    ],
    email_sequence_enrollments: [
      { id: id("77777777", 1), sequence_id: id("76666666", 1), status: "active" },
      { id: id("77777777", 2), sequence_id: id("76666666", 1), status: "active" },
      { id: id("77777777", 3), sequence_id: id("76666666", 1), status: "stopped" }
    ],
    social_post_drafts: [
      { id: id("78888888", 1), user_id: OWNER, status: "pending_approval" },
      { id: id("78888888", 2), user_id: OWNER, status: "published" },
      { id: id("78888888", 3), user_id: OWNER, status: "published" }
    ],
    content_library: [
      { id: id("79999999", 1), user_id: OWNER, status: "published", published_at: ago(3) },
      { id: id("79999999", 2), user_id: OWNER, status: "published", published_at: ago(40) }
    ],
    model_calls: [
      { id: 1, user_id: OWNER, model: "claude-sonnet-5", input_tokens: 1000000, output_tokens: 100000, funded_by: "platform", created_on: MONTH_START }
    ],
    job_runs: [
      { job_name: "daily_self_reviews", last_run_on: "2026-10-12", started_at: ago(0.1), finished_at: ago(0.1), last_error: null },
      { job_name: "weekly_digest", last_run_on: "2026-10-05", started_at: ago(7), finished_at: ago(7), last_error: "SMTP refused" }
    ],
    radar_status: [
      { source: "bluesky", last_outcome: "nothing_new", last_tick_finished_at: ago(0.01), last_error: null }
    ]
  };
}
const ENV_SET = { ENABLE_EMAIL_SEQUENCES: "true", MAIL_POSTAL_ADDRESS: "1 Fixture Lane", RESEND_WEBHOOK_SECRET: "whsec_fixture",
  EMAIL_MARKETING_DAILY_CAP: "37" };

/* The routes, run against one fake database. */
function server(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed, o.fail);
  const ctx = {
    supabase: db.client, JSON, Math, Promise, Date, crypto, Map, Set, AsyncLocalStorage: require("async_hooks").AsyncLocalStorage,
    /* BEFORE (backend 5da9dfe): no require; nothing lifted needed one.
       AFTER (legal pages): the sender readiness reads require("./lib/legal").POSTAL_ADDRESS,
       resolved from server.js's directory as server.js resolves it. */
    require: require("module").createRequire(path.join(REPO, "server.js")),
    nowIso: () => new Date().toISOString(),
    process: { env: Object.assign({}, o.env === undefined ? ENV_SET : o.env) },
    console: { log() {}, error() {}, warn() {} },
    requireAuth: function requireAuth(req, res, next) { req.user = { id: req.headers.user, role: ROLES[req.headers.user] }; next(); },
    requireActiveSubscription: function requireActiveSubscription(req, res, next) { next(); },
    aiLimiter: function aiLimiter(req, res, next) { next(); }
  };
  const routes = {};
  const register = (method) => function (p) { routes[method + " " + p] = [].slice.call(arguments, 1); };
  ctx.app = { get: register("get"), post: register("post"), _router: { stack: [] } };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function call(key, user, body) {
    const chain = routes[key];
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    const req = { headers: { user }, params: {}, query: {}, body: body || {} };
    let i = 0;
    async function step() {
      const fn = chain[i++];
      if (!fn) return;
      let advanced = false;
      await fn(req, res, (e) => { if (e) { res.code = 500; res.body = { error: e.message }; return; } advanced = true; });
      if (advanced) await step();
    }
    await step();
    return res;
  }
  return {
    db,
    center: (user) => call("get /api/command-center", user),
    dispatch: (user, body) => call("post /api/assignments/dispatch", user, body)
  };
}

/* ── the page ───────────────────────────────────────────────────────────── */
const unescape = (t) => t.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&amp;/g, "&");
const text = (html) => unescape(String(html).replace(/<br>/g, "\n").replace(/<[^>]+>/g, "")).replace(/[ \t]+/g, " ");
const settle = async () => { for (let i = 0; i < 40; i++) await new Promise(r => setImmediate(r)); };

/* Runs the Command Center script with a stubbed DOM. serve(method, url, init)
   answers each fetch with { status, body } or throws for a network failure. */
async function page(serve, opts) {
  const o = opts || {};
  const html = FILES[o.file || DASH];
  const els = {};
  const element = (elId) => {
    if (els[elId]) return els[elId];
    if (html.indexOf("id=\"" + elId + "\"") === -1) return null;
    const tag = new RegExp("<[a-z0-9]+[^>]*id=\"" + elId + "\"[^>]*>").exec(html)[0];
    els[elId] = { id: elId, innerHTML: "", textContent: "", disabled: false, listeners: {},
      style: { display: /display:none/.test(tag) ? "none" : "" },
      addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); } };
    return els[elId];
  };
  const calls = [];
  const fetch = (url, init) => {
    const call = { url, method: (init && init.method) || "GET", headers: (init && init.headers) || {}, body: init && init.body, responseText: null };
    calls.push(call);
    return Promise.resolve().then(() => serve(call.method, url, init)).then(r => {
      call.responseText = typeof r.body === "string" ? r.body : JSON.stringify(r.body);
      return { ok: r.status >= 200 && r.status < 300, status: r.status, text: () => Promise.resolve(call.responseText) };
    });
  };
  const ctx = {
    document: { getElementById: element, createElement: () => ({}), head: { appendChild() {} } },
    localStorage: { getItem: (k) => (k === "bf_token" && o.token !== null ? (o.token || "tok-owner") : null) },
    fetch, window: {}, Promise, JSON, Date, Object, Number, String, Array, isNaN, Math
  };
  vm.createContext(ctx);
  if (CC_SCRIPT.length !== 1) throw new Error("expected one Command Center script, found " + CC_SCRIPT.length);
  vm.runInContext(CC_SCRIPT[0], ctx);
  await settle();
  const panel = (name) => (element(name) || {}).innerHTML || "";
  return {
    calls, els, panel,
    text: (name) => text(panel(name)),
    buttons() {
      const out = []; const re = /<button[^>]*data-cc-dispatch[^>]*>/g; let m;
      while ((m = re.exec(panel("ccPlans")))) {
        out.push({ plan: unescape(/data-plan="([^"]*)"/.exec(m[0])[1]), assignment: unescape(/data-assignment="([^"]*)"/.exec(m[0])[1]) });
      }
      return out;
    },
    async click(b) {
      const attrs = { "data-plan": b.plan, "data-assignment": b.assignment, "data-cc-dispatch": "1" };
      const target = { disabled: false, textContent: "Dispatch", getAttribute: (k) => attrs[k], closest() { return this; } };
      (element("commandCenterSection").listeners.click || []).forEach(fn => fn({ target }));
      await settle();
    },
    async refresh() { (element("ccRefresh").listeners.click || []).forEach(fn => fn({ target: {} })); await settle(); }
  };
}
// Every fetch answered by the routes above, as the given account.
const live = (srv, user) => async (method, url, init) => {
  if (method === "GET" && /\/api\/command-center$/.test(url)) { const r = await srv.center(user); return { status: r.code, body: r.body }; }
  if (method === "POST" && /\/api\/assignments\/dispatch$/.test(url)) { const r = await srv.dispatch(user, JSON.parse(init.body)); return { status: r.code, body: r.body }; }
  throw new Error("unplanned request " + method + " " + url);
};
const PANEL_IDS = ["ccNeedsYou", "ccPlans", "ccActivity", "ccAutopilot", "ccOutbound", "ccSpend"];

(async function main() {
  /* ── 0. the fixtures are the real route's answers ─────────────────────── */
  console.log("\n══ 0. the fixtures ══");
  const full = server(world());
  const fullBody = (await full.center(OWNER)).body;
  const sections = ["needs_you", "plans", "activity", "autopilot", "outbound", "spend", "platform"];
  check("GET /api/command-center (lifted) answers every section ok for the admin, platform included",
    sections.every(k => fullBody[k] && fullBody[k].ok === true), JSON.stringify(sections.map(k => [k, fullBody[k] && fullBody[k].error])));
  const plans = fullBody.plans.data;
  const p1 = plans.find(p => p.id === P(1)) || { assignments: [] };
  const outcomeOf = (a) => typeof a.latest_dispatch === "object" ? a.latest_dispatch.outcome : a.latest_dispatch;
  check("plan 1's assignments read ran, refused, not dispatched, refused, failed",
    JSON.stringify(p1.assignments.map(outcomeOf)) === JSON.stringify(["ran", "refused", "not dispatched", "refused", "failed"]),
    JSON.stringify(p1.assignments.map(outcomeOf)));

  /* ── 1. each section renders its data ─────────────────────────────────── */
  console.log("\n══ 1. every section renders its data ══");
  let pg = await page(live(full, OWNER));
  const ny = fullBody.needs_you.data;
  const nyText = pg.text("ccNeedsYou");
  check("needs you: each pending proposal's title, linked to proposals.html",
    ny.pending_proposals.rows.length === 2 && ny.pending_proposals.rows.every(r => pg.panel("ccNeedsYou").indexOf('<a href="proposals.html">' + r.title + "</a>") !== -1),
    pg.panel("ccNeedsYou").slice(0, 300));
  check("needs you: the run that failed in the last 7 days, and not the older one",
    ny.failed_runs_7d.count === 1 && nyText.indexOf("content · content/outline") !== -1 && nyText.indexOf("email · general") === -1, nyText);
  check("needs you: with the sender configured, nothing holds mail, and it does not say \"Nothing needs you\"",
    nyText.indexOf("Nothing holds sequence mail.") !== -1 && nyText.indexOf("Nothing needs you") === -1, nyText);
  check("needs you: another account's proposal is not shown", nyText.indexOf("Another account's proposal") === -1);

  const plText = pg.text("ccPlans");
  check("plans: each plan's goal and date, and a plan with no goal says so",
    plText.indexOf("Grow the newsletter") !== -1 && plText.indexOf("Launch the spring sale") !== -1 && plText.indexOf("No goal recorded") !== -1 &&
    plText.indexOf("Another account's goal") === -1 && plans.every(p => plText.indexOf(new Date(p.created_at).toLocaleString()) !== -1), plText.slice(0, 400));
  check("plans: each assignment's agent, tool, task and priority",
    p1.assignments.every(a => plText.indexOf("#" + a.id + " " + a.agent + " · " + a.tool + " · " + a.priority) !== -1 && plText.indexOf(a.task) !== -1), plText.slice(0, 600));
  // The run opens on run.html (frontend "Every run can be opened, and agent pages read only the server").
  check("plans: the ran assignment shows its run's status and links to the run on run.html",
    plText.indexOf("Ran — the run is completed") !== -1 && pg.panel("ccPlans").indexOf('<a href="run.html?id=' + T(13) + '">open the run</a>') !== -1 &&
    pg.panel("ccPlans").indexOf("Task History") === -1, plText);
  check("plans: a refusal in plain words (not runnable; chaining switched off), a failure, and not dispatched",
    plText.indexOf("Refused — the plan marks this assignment as not runnable (assignment_not_dispatchable)") !== -1 &&
    plText.indexOf("Refused — agent chaining is switched off on the server (ENABLE_AGENT_CHAINING), so no tool may be dispatched (chaining_disabled)") !== -1 &&
    plText.indexOf("Failed — the tool failed while running (handler_error)") !== -1 && plText.indexOf("Not dispatched") !== -1, plText);
  check("plans: a plan with no assignments says so", plText.indexOf("This plan has no assignments.") !== -1);

  const act = fullBody.activity.data;
  const actText = pg.text("ccActivity");
  check("activity: the 30-day total and each agent's counts by status",
    actText.indexOf(act.total + " runs since") !== -1 && Object.keys(act.by_agent_type).length > 2 &&
    Object.keys(act.by_agent_type).every(agent => actText.indexOf(agent + " " + Object.keys(act.by_agent_type[agent]).sort().map(st => st + " " + act.by_agent_type[agent][st]).join(" · ")) !== -1),
    actText);
  check("activity: sales dry runs shown apart, as drafts never sent, and in no status count",
    act.sales_dry_runs === 3 && actText.indexOf("Sales dry runs, counted apart: 3 — drafts that were never sent.") !== -1 &&
    !(act.by_agent_type.sales && act.by_agent_type.sales.dry_run), actText);
  const newestPart = pg.panel("ccActivity").split("Newest runs")[1] || "";
  check("activity: the newest runs, one line each, none a dry run",
    act.newest_runs.length === 10 && (newestPart.match(/<li>/g) || []).length === act.newest_runs.length && newestPart.indexOf("dry_run") === -1,
    (newestPart.match(/<li>/g) || []).length + " of " + act.newest_runs.length);

  const apText = pg.text("ccAutopilot");
  check("autopilot: autonomy per agent and the schedule",
    apText.indexOf("store on") !== -1 && apText.indexOf("ads off") !== -1 && apText.indexOf("content · content_plan · weekly at 9:00 UTC · enabled") !== -1 &&
    apText.indexOf("No schedules") === -1, apText);

  const obText = pg.text("ccOutbound");
  check("outbound: each sequence with its enrollments, drafts by status, articles published in 30 days",
    obText.indexOf("Welcome · active active 2 · stopped 1") !== -1 && obText.indexOf("Winback · paused no enrollments") !== -1 &&
    obText.indexOf("pending_approval 1 · published 2") !== -1 && obText.indexOf("1 article published in the last 30 days.") !== -1, obText);

  const sp = fullBody.spend.data;
  const spText = pg.text("ccSpend");
  check("spend: \"$X of $Y this month\" from the server's figures",
    sp.usd > 0 && spText.indexOf("$" + sp.usd.toFixed(2) + " of $" + sp.monthly_cap_usd.toFixed(2) + " this month.") !== -1, spText);
  check("spend: the server's understates note, verbatim", typeof sp.note === "string" && /understates/.test(sp.note) && spText.indexOf(sp.note) !== -1, spText);

  const pfText = pg.text("ccPlatform");
  check("platform (admin): shown, each job's last run and its error, the radar's last tick and outcome",
    pg.els.ccPlatformPanel.style.display === "" && pfText.indexOf("daily_self_reviews last ran 2026-10-12") !== -1 &&
    pfText.indexOf("weekly_digest last ran 2026-10-05") !== -1 && pfText.indexOf("SMTP refused") !== -1 &&
    pfText.indexOf("bluesky last tick") !== -1 && pfText.indexOf("nothing_new") !== -1, pfText);
  check("one read when the page opens, and no timer in the Command Center script",
    pg.calls.length === 1 && pg.calls[0].method === "GET" && /\/api\/command-center$/.test(pg.calls[0].url) &&
    pg.calls[0].headers.Authorization === "Bearer tok-owner" && !/setInterval|setTimeout|requestAnimationFrame/.test(CC_SCRIPT[0]), JSON.stringify(pg.calls));
  await pg.refresh();
  check("Refresh reads it again", pg.calls.length === 2 && /\/api\/command-center$/.test(pg.calls[1].url), pg.calls.length);

  /* ── 2. a failed section ──────────────────────────────────────────────── */
  console.log("\n══ 2. a failed section shows its error; the rest render ══");
  const proposalsFail = server(world(), { fail: q => q.table === "agent_proposals" ? { message: "permission denied for table agent_proposals" } : null });
  const pfBody = (await proposalsFail.center(OWNER)).body;
  pg = await page(live(proposalsFail, OWNER));
  check("the route answers needs_you ok:false with an error, the rest ok",
    pfBody.needs_you.ok === false && /permission denied/.test(pfBody.needs_you.error) && ["plans", "activity", "autopilot", "outbound", "spend"].every(k => pfBody[k].ok === true),
    JSON.stringify(pfBody.needs_you));
  check("needs you shows that error in its own panel, and not \"Nothing needs you\"",
    pg.panel("ccNeedsYou").indexOf('class="cc-error"') !== -1 && pg.text("ccNeedsYou").indexOf(pfBody.needs_you.error) !== -1 &&
    pg.text("ccNeedsYou").indexOf("Nothing needs you") === -1, pg.panel("ccNeedsYou"));
  check("every other panel still renders its data",
    pg.text("ccPlans").indexOf("Grow the newsletter") !== -1 && pg.text("ccActivity").indexOf("runs since") !== -1 &&
    pg.text("ccAutopilot").indexOf("store on") !== -1 && pg.text("ccOutbound").indexOf("Welcome") !== -1 && pg.text("ccSpend").indexOf("this month") !== -1 &&
    ["ccPlans", "ccActivity", "ccAutopilot", "ccOutbound", "ccSpend"].every(p => pg.panel(p).indexOf("cc-error") === -1));
  const draftsFail = server(world(), { fail: q => q.table === "social_post_drafts" ? { message: "statement timeout on social_post_drafts" } : null });
  pg = await page(live(draftsFail, OWNER));
  check("a failed outbound shows its error, not \"No social drafts.\" or a zero",
    pg.text("ccOutbound").indexOf("statement timeout on social_post_drafts") !== -1 && pg.text("ccOutbound").indexOf("No social drafts") === -1 &&
    pg.text("ccOutbound").indexOf("0 articles") === -1, pg.text("ccOutbound"));
  const schedulesFail = server({}, { fail: q => q.table === "agent_schedules" ? { message: "relation agent_schedules is unavailable" } : null });
  pg = await page(live(schedulesFail, USER));
  check("a failed autopilot shows its error, never \"No schedules\"",
    pg.text("ccAutopilot").indexOf("relation agent_schedules is unavailable") !== -1 && pg.text("ccAutopilot").indexOf("No schedules") === -1, pg.text("ccAutopilot"));
  pg = await page(async () => ({ status: 500, body: { error: "Internal server error" } }));
  check("a failed request: every panel shows the error, none reads as empty, platform hidden",
    PANEL_IDS.every(p => pg.text(p).indexOf("Could not read this section: Internal server error") !== -1) &&
    PANEL_IDS.every(p => !/Nothing needs you|No schedules|No executive plans|\$0\.00/.test(pg.text(p))) && pg.els.ccPlatformPanel.style.display === "none",
    PANEL_IDS.map(p => pg.text(p)).join(" | "));
  pg = await page(async () => { throw new Error("Failed to fetch"); });
  check("a network failure: every panel shows it", PANEL_IDS.every(p => pg.text(p).indexOf("Failed to fetch") !== -1));
  pg = await page(async () => { throw new Error("no request expected"); }, { token: null });
  check("no session: every panel says so and no request is made", pg.calls.length === 0 && PANEL_IDS.every(p => pg.text(p).indexOf("you are not signed in") !== -1));

  /* ── 3. "Nothing needs you" only when all three are real and empty ────── */
  console.log("\n══ 3. \"Nothing needs you\" ══");
  const empty = server({});
  const emptyBody = (await empty.center(USER)).body;
  pg = await page(live(empty, USER));
  check("all three real and empty: \"Nothing needs you.\"",
    emptyBody.needs_you.ok === true && emptyBody.needs_you.data.pending_proposals.count === 0 && emptyBody.needs_you.data.failed_runs_7d.count === 0 &&
    emptyBody.needs_you.data.email_sender.blocked_by.length === 0 && pg.text("ccNeedsYou").trim() === "Nothing needs you.", pg.text("ccNeedsYou"));
  check("the empty account's other sections render as real and empty",
    pg.text("ccPlans").indexOf("No executive plans yet") !== -1 && pg.text("ccAutopilot").indexOf("No schedules") !== -1 &&
    pg.text("ccOutbound").indexOf("No email sequences.") !== -1 && pg.text("ccSpend").indexOf("$0.00 of $") !== -1, pg.text("ccAutopilot"));
  const blocked = server({}, { env: {} });
  pg = await page(live(blocked, USER));
  /* BEFORE (backend 5da9dfe): with no environment, "No postal address is set (MAIL_POSTAL_ADDRESS)" was one reason.
     AFTER (legal pages): the postal address is lib/legal.js POSTAL_ADDRESS, never unset, so that reason never shows. */
  check("the sender held: each reason in plain words, and not \"Nothing needs you\"",
    pg.text("ccNeedsYou").indexOf("Nothing needs you") === -1 && pg.text("ccNeedsYou").indexOf("Email sequences are switched off on the server (ENABLE_EMAIL_SEQUENCES)") !== -1 &&
    pg.text("ccNeedsYou").indexOf("No postal address is set") === -1, pg.text("ccNeedsYou"));
  const oneProposal = server({ agent_proposals: [world().agent_proposals[0]] });
  pg = await page(live(oneProposal, OWNER));
  check("one pending proposal: not \"Nothing needs you\"", pg.text("ccNeedsYou").indexOf("Nothing needs you") === -1 && pg.text("ccNeedsYou").indexOf("Publish post A") !== -1);
  const oneFailed = server({ ai_tasks: [task(2, USER, "content", "failed", 2, "content/outline")] });
  pg = await page(live(oneFailed, USER));
  check("one failed run: not \"Nothing needs you\"", pg.text("ccNeedsYou").indexOf("Nothing needs you") === -1 && pg.text("ccNeedsYou").indexOf("content · content/outline") !== -1);
  const nyFail = server({}, { fail: q => q.table === "ai_tasks" && q.filters.some(f => f[0] === "eq" && f[2] === "failed") ? { message: "failed runs could not be read" } : null });
  pg = await page(live(nyFail, USER));
  check("needs you failed while the rest are empty: its error, not \"Nothing needs you\"",
    pg.text("ccNeedsYou").indexOf("failed runs could not be read") !== -1 && pg.text("ccNeedsYou").indexOf("Nothing needs you") === -1, pg.text("ccNeedsYou"));

  /* ── 4. Dispatch ──────────────────────────────────────────────────────── */
  console.log("\n══ 4. Dispatch ══");
  const flow = server(world());
  pg = await page(live(flow, OWNER));
  const expected = [];
  (await flow.center(OWNER)).body.plans.data.forEach(p => (p.assignments || []).forEach(a => {
    if (a.is_dispatchable === true && outcomeOf(a) !== "ran") expected.push(p.id + "#" + a.id);
  }));
  const shown = pg.buttons().map(b => b.plan + "#" + b.assignment);
  check("Dispatch on exactly the dispatchable assignments whose latest dispatch did not run (not dispatched, refused, failed)",
    JSON.stringify(shown.slice().sort()) === JSON.stringify(expected.slice().sort()) &&
    JSON.stringify(expected.slice().sort()) === JSON.stringify([P(1) + "#3", P(1) + "#4", P(1) + "#5"]), JSON.stringify(shown));
  check("no Dispatch on the assignment that ran, or on the one that is not runnable",
    shown.indexOf(P(1) + "#1") === -1 && shown.indexOf(P(1) + "#2") === -1);
  const target = pg.buttons().find(b => b.plan === P(1) && b.assignment === "3");
  const before = pg.calls.length;
  await pg.click(target);
  const post = pg.calls[before] || {};
  let sent = null; try { sent = JSON.parse(post.body); } catch (e) { sent = null; }
  check("it posts exactly the plan id and the assignment id (a number), with the session",
    post.method === "POST" && /\/api\/assignments\/dispatch$/.test(post.url) && post.headers.Authorization === "Bearer tok-owner" &&
    JSON.stringify(sent) === JSON.stringify({ executive_task_id: P(1), assignment_id: 3 }), JSON.stringify(post));
  const recorded = flow.db.tables.executive_dispatches.filter(d => d.plan_task_id === P(1) && d.assignment_id === 3 && d.user_id === OWNER);
  check("the real dispatcher refused it (chaining disabled) and the route recorded the refusal",
    recorded.length === 1 && recorded[0].outcome === "refused" && recorded[0].refused_reason === "chaining_disabled", JSON.stringify(recorded));
  // The exact text the route answered this click with (its chain id is minted per request).
  const answerText = post.responseText || "";
  const plAfter = pg.text("ccPlans");
  check("the answer is shown verbatim, refusal and detail included, with its plain words",
    /"refused_reason":"chaining_disabled"/.test(answerText) && /ENABLE_AGENT_CHAINING is not exactly/.test(answerText) &&
    plAfter.indexOf(answerText) !== -1 &&
    plAfter.indexOf("Refused — agent chaining is switched off on the server (ENABLE_AGENT_CHAINING), so no tool may be dispatched (chaining_disabled)\n") !== -1,
    plAfter.slice(plAfter.indexOf("#3"), plAfter.indexOf("#3") + 600));
  check("then it reads the Command Center again", pg.calls.length === before + 2 && pg.calls[before + 1].method === "GET" &&
    /\/api\/command-center$/.test(pg.calls[before + 1].url), JSON.stringify(pg.calls.map(c => c.method + " " + c.url)));
  const a3 = plAfter.slice(plAfter.indexOf("#3 "), plAfter.indexOf("#4 "));
  check("and the refreshed section shows assignment 3 refused, still offering Dispatch",
    a3.indexOf("Refused — agent chaining is switched off") !== -1 && a3.indexOf("Not dispatched") === -1 &&
    pg.buttons().some(b => b.plan === P(1) && b.assignment === "3"), a3);

  /* ── 5. platform hidden when absent ───────────────────────────────────── */
  console.log("\n══ 5. platform ══");
  const userBody = (await full.center(USER)).body;
  pg = await page(live(full, USER));
  check("a non-admin's answer has no platform, and the panel stays hidden and empty",
    !("platform" in userBody) && pg.els.ccPlatformPanel.style.display === "none" && pg.panel("ccPlatform") === "", pg.els.ccPlatformPanel.style.display);
  const platFail = server(world(), { fail: q => q.table === "job_runs" ? { message: "job_runs unreadable" } : null });
  pg = await page(live(platFail, OWNER));
  check("an admin's failed platform shows its error", pg.els.ccPlatformPanel.style.display === "" && pg.text("ccPlatform").indexOf("job_runs unreadable") !== -1);

  /* ── 6. the topbar agent count ────────────────────────────────────────── */
  console.log("\n══ 6. the topbar agent count ══");
  const pill = /<span class="topbar-agents-num">([^<]*)<\/span>/.exec(FILES[DASH]);
  check("the markup shows \"—\" until GET /api/agents answers", pill && pill[1] === "—", pill && pill[1]);
  check("no typed 18 for the agent count anywhere in dashboard.html",
    !/topbar-agents-num">\s*18/.test(FILES[DASH]) && !/agentsNumEl\.textContent\s*=\s*["']18/.test(FILES[DASH]) && !/show\(["']18["']\)/.test(FILES[DASH]));
  const syncStart = FILES[DASH].indexOf("(function syncAgentsNavCountFromApi() {");
  const syncCode = syncStart < 0 ? "" : FILES[DASH].slice(syncStart, FILES[DASH].indexOf("})();", syncStart) + 5);
  async function pillAfter(answer, token) {
    const el = { textContent: pill ? pill[1] : "" };
    const ctx = { API_URL: "https://api.test", document: { querySelector: (q) => q === ".topbar-agents-num" ? el : null },
      localStorage: { getItem: () => token === undefined ? "tok" : token }, Promise, JSON, String, Array,
      fetch: () => answer() };
    vm.createContext(ctx);
    vm.runInContext(syncCode, ctx);
    const during = el.textContent;
    await settle();
    return { during, after: el.textContent };
  }
  const okAgents = await pillAfter(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ agents: [{ active: true }, { active: true }, { active: false }] }) }));
  check("while the request is out it reads \"—\"; when it answers, the active count", okAgents.during === "—" && okAgents.after === "2", JSON.stringify(okAgents));
  const http500 = await pillAfter(() => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) }));
  const network = await pillAfter(() => Promise.reject(new Error("Failed to fetch")));
  const notList = await pillAfter(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ nope: true }) }));
  const noToken = await pillAfter(() => Promise.reject(new Error("no request expected")), null);
  check("\"?\" when it fails: an error status, a network failure, an answer that is not a list, no session",
    http500.after === "?" && network.after === "?" && notList.after === "?" && noToken.after === "?",
    JSON.stringify([http500, network, notList, noToken]));

  /* ── 7. the stale labels ──────────────────────────────────────────────── */
  console.log("\n══ 7. the stale labels are gone ══");
  check("no .bf-sim-banner in dashboard.html (markup or CSS)", FILES[DASH].indexOf("bf-sim-banner") === -1);
  check("no Tier D tracker", FILES[DASH].indexOf("tierDAgentStatusTracker") === -1 && FILES[DASH].indexOf("Tier D Agents:") === -1);
  check("executive-agent.html has no \"Sample\" note, no stats grid and no confidence",
    !/\bSample\b/.test(FILES[EXEC]) && FILES[EXEC].indexOf("Nothing here is a measurement") === -1 && FILES[EXEC].indexOf("statsGrid") === -1 &&
    FILES[EXEC].indexOf("sim-note") === -1 && FILES[EXEC].indexOf("store.stats") === -1);
  check("…and links to the dashboard's Command Center, which exists",
    FILES[EXEC].indexOf('href="dashboard.html#commandCenterSection"') !== -1 && FILES[DASH].indexOf('<section id="commandCenterSection"') !== -1);
  check("executive-agent.html still reads the server (GET /api/agents/executive)", FILES[EXEC].indexOf("/api/agents/executive") !== -1);

  /* ── 8. the removed code ──────────────────────────────────────────────── */
  console.log("\n══ 8. the removed functions, and what stays ══");
  const REMOVED = ["saveExecutiveAssignmentMemories", "sendAgentMessage", "broadcastAgentMessage", "getAgentInbox", "getAgentMessagingBusInbox",
    "normalizeAgentMessagingName", "saveAgentMemory", "initializeExecutiveMemory", "loadExecutiveProject", "ensureExecutiveAutonomyEngineStore",
    "getExecutiveAutonomyEngineMemory", "getExecutiveAutonomyEngineSummary", "updateExecutiveAgentStats", "getExecutiveAgentSummary"];
  REMOVED.forEach(name => {
    const where = Object.keys(FILES).filter(f => new RegExp("\\b" + name + "\\b").test(FILES[f]));
    check(name + " is declared, exported and named nowhere in the frontend", where.length === 0, where.join(", "));
  });
  /* Launch audit #22a replaced two pins here. "processExecutiveAssignmentsFromReport
     remains and still records its run" and "the Agent Work Queue remains, below
     the Command Center" held a list kept only in this browser's localStorage;
     the queue and the parse that filled it are gone, and the Command Center is
     where executive plans and their dispatch live. */
  check("the Agent Work Queue and the browser-side parse that filled it are gone; the Command Center stays",
    FILES[DASH].indexOf('<section id="commandCenterSection"') !== -1 &&
    ["agentAssignmentsSection", "activeQueueSummary", "bizforce_agent_assignments", "processExecutiveAssignmentsFromReport",
      "recordExecutiveRunToStore", "renderAssignmentDashboard"].every(n => FILES[DASH].indexOf(n) === -1));
  [DASH, EXEC].forEach(file => {
    const scripts = inlineScripts(FILES[file]);
    const bad = []; scripts.forEach((code, i) => { try { new vm.Script(code); } catch (e) { bad.push(i + ": " + e.message); } });
    check("every inline script in " + file + " parses (" + scripts.length + ")", scripts.length > 0 && bad.length === 0, bad.join(" | "));
  });

  /* ── 9. one Command Center, two pages ─────────────────────────────────── */
  console.log("\n══ 9. the shared Command Center on the dashboard and in Headquarters ══");
  const loadsAfterSection = f => /<\/section>\s*(?:<script src="\/scripts\/bf-hq\.js"><\/script>\s*)?<script src="\/scripts\/bf-command-center\.js"><\/script>/.test(FILES[f]) &&
    (FILES[f].match(/<script src="\/scripts\/bf-command-center\.js"><\/script>/g) || []).length === 1;
  check("both pages load scripts/bf-command-center.js once, right after the section; neither keeps an inline copy",
    [DASH, EXEC].every(loadsAfterSection) && [DASH, EXEC].every(f => FILES[f].indexOf("(function commandCenter() {") === -1));
  const ids = f => (FILES[f].match(/<section id="commandCenterSection"[\s\S]*?<\/section>/) || [""])[0].match(/id="[A-Za-z]+"/g) || [];
  check("both pages carry the same Command Center markup ids", JSON.stringify(ids(DASH)) === JSON.stringify(ids(EXEC)) && ids(DASH).length === 11,
    JSON.stringify([ids(DASH), ids(EXEC)]));
  const onDash = await page(live(full, OWNER)), onExec = await page(live(full, OWNER), { file: EXEC });
  check("the same answer renders the same panels, word for word, on both pages",
    PANEL_IDS.concat(["ccPlatform"]).every(k => onDash.panel(k) === onExec.panel(k) && onDash.panel(k).length > 0) &&
    onExec.els.ccPlatformPanel.style.display === "", PANEL_IDS.filter(k => onDash.panel(k) !== onExec.panel(k)).join(","));
  const memberExec = await page(live(full, USER), { file: EXEC });
  check("in Headquarters, a member's Command Center keeps the platform panel hidden and empty",
    memberExec.els.ccPlatformPanel.style.display === "none" && memberExec.panel("ccPlatform") === "");

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
