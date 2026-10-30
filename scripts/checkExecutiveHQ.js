"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkExecutiveHQ — Executive Headquarters (executive-agent.html,
   scripts/bf-hq.js) and the calendar's "Agent runs" layer say only what the
   member's own rows say.

   Backend "Headquarters read side: one shared Command Center and the
   calendar's agent-run rule" added lib/agentLive.js runsBetween, GET
   /api/agents/live/calendar and the admin-only platform ceiling in the
   Command Center's platform section. Frontend "Executive Headquarters: every
   agent at a glance, alerts, approvals, and agent runs on the calendar" added
   scripts/bf-hq.js, the shared scripts/bf-command-center.js and the layer.

   THE ANSWERS ARE REAL. /api/agents/live is lib/agentLive.js buildLive over
   fixture reads with the runner's own agentScheduleIsDue; /api/command-center
   and /api/agents/live/calendar are the routes lifted from server.js and run
   against an in-memory database that records every write. The pages run in
   jsdom with their own scripts. No network, no model call, no database.

   WHAT THIS PROVES
     H1  the grid: all 18 agents, each tile's Now, Last, Next, Approvals and
         Score in /live's own words; the filters; attention and A–Z sorts; a
         tile opens its agent's page, in that page's accent;
     H2  polling as the agent panel does it: the same constants, 15 s while
         any agent runs, 60 s idle, stopped hidden or offline, 2× backoff on
         429 and 5xx to 5 minutes, reset by a good answer;
     H3  alerts only from real fields, each linked where it is fixed; the
         platform ceiling's dollars only in an admin's answer and page;
     H4  the approval queue: Approve and Reject post to the existing routes
         once per click, never without one, and say a 409 or a 402;
     H5  the Command Center renders in Headquarters from the shared script;
     H6  the calendar rule: runsBetween agrees with nextRun step by step for
         daily, weekly and monthly-31, on known dates; paused, disabled,
         autonomy-off, scheduler-off and lapsed show nothing, with why; the
         route writes nothing;
     H7  calendar.html: the layer is off until pressed, reads the route,
         places each run on its own day, says why a schedule shows nothing,
         and sends nothing but that GET;
     H8  reduced motion, and the pulse only on running tiles and real alerts;
     H9  keyboard and aria: tiles are labelled buttons, arrows and Home/End
         move between them, filters and sort say their state.

   Block 3b, the ACT side (backend "Headquarters act side: the app map knows
   HQ's command controls", frontend "Executive Headquarters: command any
   agent, run plans step by step, control every agent, by voice or keyboard"):
     H10 the command box: one POST /api/ai/tasks per Send, a 202 followed to
         its run; a tool opens on its own page (#tool=, read once, runs
         nothing); every acting tool (CHAIN_NON_DISPATCHABLE_TOOLS) never posts
         from Headquarters and goes to its page; the pickers are the canonical
         names and the app map's tools;
     H11 "Let the Executive decide": one POST /api/agents/executive/plan, and
         the plan on the board;
     H12 the plan runner: statuses from the dispatched run's own status, the
         progress line, one dispatch per "Run next" click (a double click is
         one), no automatic next dispatch, chaining off disables it in words;
         the server's own dispatch route refuses another member's plan and a
         dispatch with chaining off;
     H13 refusals by name: 402, the platform's daily AI limit, the daily cap,
         the per-minute limit, not entitled, chaining off, with the server's
         own messages;
     H14 voice fills the box and never sends; hidden where unsupported;
     H15 "Automatic", Pause and Resume call the existing routes once and never
         open the tile;
     H16 the agent page opens the named tool from #tool= and runs nothing.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR, never caught.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const SERVER = "server.js", LIB = "lib/agentLive.js";
const HQ = "scripts/bf-hq.js", CC = "scripts/bf-command-center.js", EXEC = "executive-agent.html", CAL = "calendar.html", AP = "scripts/agent-profile.js";
const PAYWALL = "scripts/bf-paywall.js", MAP = "lib/appMap.json", EMAIL_PAGE = "email-agent.html";

const MUTATIONS = {
  // the Command Center's platform section, and its ceiling in dollars, goes to every account (H3)
  "platform-figures-to-member": [[SERVER, "    var isAdmin = req.user.role === \"admin\";\n", "    var isAdmin = true;\n"]],
  /* Headquarters approves every pending proposal as soon as the page loads (H4).
     NAMED (Block 3b, Oct 29 2026): before, the approvals were inserted after every queue load, so a
     proposal that stayed pending (a 402 or a 409 reply) was approved again on each reload, forever,
     in the background of every later section. Once, on the first load, is the defect and ends. */
  "auto-approve": [[HQ, "  loadQueue();\n  fetchLive();\n})();",
    "  loadQueue().then(function () { Array.prototype.forEach.call(document.querySelectorAll('[data-hq-decide=\"approve\"]'), function (b) { decide(b); }); });\n  fetchLive();\n})();"]],
  // the calendar route ignores a schedule's pause, so a paused schedule shows runs (H6, H7)
  "calendar-on-paused": [[SERVER, "    body.schedules = schedules.rows.filter(function (row) { return live.AGENT_KEYS.indexOf(row.agent_type) !== -1; }).map(function (row) {\n",
    "    body.schedules = schedules.rows.filter(function (row) { return live.AGENT_KEYS.indexOf(row.agent_type) !== -1; }).map(function (row) {\n" +
    "      row = Object.assign({}, row, { paused: false });\n"]],
  // the calendar page saves each run it shows as a calendar_events row (H7)
  "calendar-writes-events": [[CAL, "          agentRuns.byJdn = byJdn;\n          agentRuns.lines = lines;\n",
    "          agentRuns.byJdn = byJdn;\n          agentRuns.lines = lines;\n" +
    "          Object.keys(byJdn).forEach(function (j) { fetch(API_URL + \"/api/calendar/events\", { method: \"POST\", headers: { \"Authorization\": \"Bearer \" + token, \"Content-Type\": \"application/json\" }, body: JSON.stringify({ jdn: Number(j), title: \"Agent run\" }) }); });\n"]],
  // the calendar steps a fixed number of days instead of agentLive's next-slot walk (H6, H7)
  "different-next-slot-rule": [[LIB, "    slot = nextSlot(row, slot, opts.isDue);\n",
    "    slot = new Date(slot.getTime() + (row.cadence === \"weekly\" ? 7 : row.cadence === \"monthly\" ? 30 : 1) * 86400000);\n"]],
  // Headquarters keeps polling while the tab is hidden (H2)
  "polling-while-hidden": [[HQ, "    if (document.hidden) stop(\"hidden\");\n    else fetchLive();\n", "    fetchLive();\n"],
    [HQ, "    if (document.hidden) { stop(\"hidden\"); return; }\n    if (offline())", "    if (offline())"]],
  // a tool that acts is posted from Headquarters instead of going through its page's approval (H10)
  "acting-tool-from-hq": [[HQ, "      if (acting) {\n        // Never from here: the page's own approval flow runs it.\n",
    "      if (acting) {\n        api(\"POST\", \"/api/agents/\" + agent + \"/\" + toolId, {});\n        // Never from here: the page's own approval flow runs it.\n"]],
  // after one dispatch answers, the runner dispatches the next assignment by itself (H12); once, so the mutant ends
  "auto-dispatch-next": [[HQ, "      .then(function () { act.dispatching[planId] = false; renderBoard(); reloadCenter(); refreshNow(); });\n",
    "      .then(function () { act.dispatching[planId] = false; renderBoard(); var again = document.querySelector('[data-hq-run-next=\"' + planId + '\"]'); if (again && !act.autoNext) { act.autoNext = true; runNext(again); } reloadCenter(); refreshNow(); });\n"]],
  // what the browser heard is sent at once, without Send (H14)
  "voice-auto-sends": [[HQ, "        box.focus();\n      };\n      r.onerror", "        box.focus();\n        send();\n      };\n      r.onerror"]],
  // "Run next" keeps no in-flight guard, so a double click dispatches twice (H12)
  "double-click-dispatches-twice": [[HQ, "    if (button.disabled || act.dispatching[planId]) return;\n", ""],
    [HQ, "    act.dispatching[planId] = true;\n    button.disabled = true;\n", ""]],
  // a refused task says nothing (H13)
  "refusal-swallowed": [[HQ, "        if (res.status !== 202 || !res.body || !res.body.task) { say(refusalOf(res.status, res.body)); return; }\n",
    "        if (res.status !== 202 || !res.body || !res.body.task) { return; }\n"]],
  // pressing a control also opens the agent's page (H15)
  "toggle-opens-tile": [[HQ, "    var turnOn = button.getAttribute(\"aria-pressed\") !== \"true\";\n",
    "    var turnOn = button.getAttribute(\"aria-pressed\") !== \"true\";\n    go(AGENTS[type].page);\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[SERVER, LIB, MAP].forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
[HQ, CC, EXEC, CAL, AP, PAYWALL, EMAIL_PAGE].forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
// A page script's request that nobody handles is a failure counted here, never a crash of the harness.
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));

/* ── the lib, from the (possibly mutated) text ── */
function compileLib(src) {
  const file = path.join(REPO, LIB);
  const m = new Module(file, module); m.filename = file; m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(src, file);
  return m.exports;
}
const LIVE = compileLib(FILES[LIB]);

/* ── a fixed clock: Wednesday 20 January 2027, 10:20 UTC ── */
const NOW = Date.parse("2027-01-20T10:20:00.000Z");
function fixedDate(ms) {
  const Real = Date;
  function D(...a) { if (!(this instanceof D)) return new Real(ms).toString(); return a.length ? new Real(...a) : new Real(ms); }
  D.prototype = Real.prototype;
  D.now = () => ms; D.parse = Real.parse; D.UTC = Real.UTC;
  return D;
}
const ago = m => new Date(NOW - m * 60000).toISOString();
const DAY = 1440;

/* ── the server, lifted ── */
const SRC = FILES[SERVER];
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
// Every top-level definition indexed in one pass, so a lookup does not rescan server.js (thousands of names are asked for).
const FN_AT = new Map(), VAR_AT = new Map();
{
  const re = /^(?:async )?function ([A-Za-z_$][A-Za-z0-9_$]*)\(|^(?:var|const|let) ([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=[ \t]*/gm; let m;
  while ((m = re.exec(SRC))) {
    if (m[1] !== undefined) { if (!FN_AT.has(m[1])) FN_AT.set(m[1], m.index); }
    else { if (!VAR_AT.has(m[2])) VAR_AT.set(m[2], []); VAR_AT.get(m[2]).push({ index: m.index, length: m[0].length }); }
  }
}
function definitionOf(name) {
  if (FN_AT.has(name)) { const at = FN_AT.get(name); return SRC.slice(at, s.braceMatch(SRC, SRC.indexOf(") {", at) + 2)); }
  const m = (VAR_AT.get(name) || []).find(v => !SPANS.some(([x, y]) => v.index > x && v.index < y));   // not a local
  if (!m) return null;
  const brk = /;\n/g; brk.lastIndex = m.index + m.length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(m.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "requireAuth",
  "requireActiveSubscription", "requireAdmin", "aiLimiter", "crypto", "Date", "cron", "Anthropic", "getUserPlan", "opsAlerts", "isTestAccount"]);
const uncommented = (code) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
  const have = new Map();
  const looked = new Set();   // each name is looked up once: a miss stays a miss
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name) || looked.has(name)) continue;
    looked.add(name);
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
const LIFTED = closure(routeText("get", "/api/command-center") + "\n\n" + routeText("get", "/api/agents/live/calendar") +
  "\n\n" + routeText("post", "/api/assignments/dispatch") +
  "\n\nthis.__isDue = agentScheduleIsDue; this.__capError = dailyModelCallLimitError; this.__ceilingError = platformDailySpendLimitError;");
// Compiled once, run in a fresh context per fake server: compiling it per server took most of a minute.
const LIFTED_SCRIPT = new vm.Script(LIFTED);

/* The in-memory database: every filter applied, every write recorded and refused. */
function fakeDb(seed) {
  const tables = JSON.parse(JSON.stringify(seed || {}));
  const log = [], writes = [];
  function keep(q, row) {
    return q.filters.every(f => {
      const x = row[f[1]];
      if (f[0] === "eq") return x === f[2];
      if (f[0] === "neq") return x !== f[2];
      if (f[0] === "in") return f[2].indexOf(x) !== -1;
      if (f[0] === "gte") return x !== null && x !== undefined && x >= f[2];
      if (f[0] === "lt") return x !== null && x !== undefined && x < f[2];
      if (f[0] === "is") return x === f[2] || (f[2] === null && x === undefined);
      if (f[0] === "or") return f[1].split(",").some(part => { const [c, op, v] = part.split("."); return op === "eq" ? row[c] === v : row[c] !== null && row[c] !== undefined && row[c] !== v; });
      return true;
    });
  }
  function answer(q) {
    if (q.write) { writes.push({ table: q.table, op: q.write }); return Promise.resolve({ data: null, error: { message: "this check allows no writes" } }); }
    let rows = (tables[q.table] || []).filter(r => keep(q, r));
    const orders = q.filters.filter(f => f[0] === "order");
    for (let i = orders.length - 1; i >= 0; i--) {
      const [, c, o] = orders[i]; const dir = o && o.ascending === false ? -1 : 1;
      rows = rows.slice().sort((a, b) => (a[c] < b[c] ? -1 : a[c] > b[c] ? 1 : 0) * dir);
    }
    const count = q.opts && q.opts.count ? rows.length : null;
    const range = q.filters.find(f => f[0] === "range"); if (range) rows = rows.slice(range[1], range[2] + 1);
    const limit = q.filters.find(f => f[0] === "limit"); if (limit) rows = rows.slice(0, limit[1]);
    if (q.opts && q.opts.head) return Promise.resolve({ data: null, error: null, count });
    if (q.cols && q.cols.trim() !== "*") {
      const want = q.cols.split(",").map(c => c.trim());
      rows = rows.map(r => want.reduce((o, k) => { o[k] = r[k] === undefined ? null : r[k]; return o; }, {}));
    }
    rows = JSON.parse(JSON.stringify(rows));
    if (q.single) return Promise.resolve({ data: rows[0] || null, error: null, count });
    return Promise.resolve({ data: rows, error: null, count });
  }
  function from(table) {
    const q = { table, cols: "*", opts: null, filters: [], single: false, write: null };
    log.push(q);
    const b = { select(cols, opts) { q.cols = cols || "*"; q.opts = opts || null; return b; } };
    ["insert", "update", "upsert", "delete"].forEach(op => { b[op] = function () { q.write = op; return b; }; });
    ["eq", "neq", "in", "gte", "lt", "is", "or", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, writes, client: { from } };
}

const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";   // admin
const USER = "aaaaaaaa-0000-4000-8000-000000000002";    // a member
const LAPSED = "aaaaaaaa-0000-4000-8000-000000000003";  // a member whose subscription lapsed
const ROLES = { [OWNER]: "admin", [USER]: "user", [LAPSED]: "user" };
const DAY_OF = iso => iso.slice(0, 10);
const PLAN_A = "bbbbbbbb-0000-4000-8000-00000000000a", PLAN_B = "bbbbbbbb-0000-4000-8000-00000000000b";
const PLAN_OTHER = "bbbbbbbb-0000-4000-8000-00000000000c", PLAN_NEW = "bbbbbbbb-0000-4000-8000-00000000000d";
const T = n => "cccccccc-0000-4000-8000-" + String(n).padStart(12, "0");
function planRows() {
  const task = (id, agent, taskType, status, minsAgo) => ({ id, user_id: USER, agent_type: agent, task_type: taskType, status, prompt: "x", result: null,
    created_at: ago(minsAgo), completed_at: status === "processing" ? null : ago(minsAgo - 1) });
  const plan = (id, user, goal, minsAgo, assignments) => ({ id, user_id: user, agent_type: "executive", task_type: "executive/plan", status: "completed",
    prompt: goal, output: { goal, assignments }, created_at: ago(minsAgo), completed_at: ago(minsAgo - 1) });
  const a = (id, agent, tool, task, extra) => Object.assign({ id, agent, tool, task, priority: "high", is_dispatchable: true, problems: [], inputs: {} }, extra || {});
  let n = 0;
  const d = (planId, assignmentId, outcome, extra) => Object.assign({ id: ++n, user_id: USER, plan_task_id: planId, assignment_id: assignmentId, outcome,
    refused_reason: null, tool_task_id: null, created_at: ago(40 - n) }, extra || {});
  return {
    ai_tasks: [
      plan(PLAN_A, USER, "Launch the tea shop", 60, [a(1, "seo", "audit", "Audit the shop page"), a(2, "content", "outline", "Outline the launch post"),
        a(3, "email", "sequence", "A welcome sequence"), a(4, "social", "post", "The launch post"), a(5, "ads", "copy", "Launch ad copy")]),
      plan(PLAN_B, USER, "Grow the mailing list", 30, [a(1, "analytics", "kpi-review", "Review sign-ups"),
        a(2, "store", null, "Price the new mugs yourself", { is_dispatchable: false, is_founder_task: true, problems: ["founder work"] }),
        a(3, "rd", "brief", "Brief on list growth"), a(4, "operations", "sop", "A sign-up SOP")]),
      plan(PLAN_OTHER, OWNER, "The owner's own plan", 20, [a(1, "seo", "audit", "Audit")]),
      task(T(1), "seo", "seo/audit", "completed", 55), task(T(2), "content", "content/outline", "completed", 54),
      task(T(3), "email", "email/sequence", "completed", 53), task(T(4), "social", "social/post", "failed", 52),
      task(T(5), "analytics", "analytics/kpi-review", "processing", 5)
    ],
    executive_dispatches: [
      d(PLAN_A, 1, "ran", { tool_task_id: T(1) }), d(PLAN_A, 2, "ran", { tool_task_id: T(2) }), d(PLAN_A, 3, "ran", { tool_task_id: T(3) }),
      d(PLAN_A, 4, "ran", { tool_task_id: T(4) }), d(PLAN_B, 1, "ran", { tool_task_id: T(5) }),
      d(PLAN_B, 3, "refused", { refused_reason: "chaining_disabled" })
    ]
  };
}
function world() {
  const sched = (user, agent, extra) => Object.assign({ user_id: user, agent_type: agent, task_type: agent + "/tool", prompt: "x", cadence: "daily", hour_utc: 9,
    day_of_week: null, day_of_month: null, enabled: true, paused: false, paused_reason: null, consecutive_failures: 0, last_run_on: null,
    created_at: ago(30 * DAY), updated_at: ago(30 * DAY) }, extra || {});
  const schedules = [];
  [USER, LAPSED, OWNER].forEach(u => schedules.push(
    sched(u, "email", { task_type: "email/sequence" }),
    sched(u, "analytics", { task_type: "analytics/kpi-review", cadence: "weekly", hour_utc: 7, day_of_week: 1 }),
    sched(u, "store", { task_type: "store/stock-margin", cadence: "monthly", hour_utc: 6, day_of_month: 31 }),
    sched(u, "operations", { task_type: "operations/sop", hour_utc: 8, paused: true, paused_reason: "Paused after 3 failed runs in a row", consecutive_failures: 3 }),
    sched(u, "ads", { task_type: "ads/copy", enabled: false }),
    sched(u, "seo", { task_type: "seo/audit", hour_utc: 10 })));
  const autonomy = [];
  [USER, LAPSED, OWNER].forEach(u => ["email", "analytics", "store", "operations", "ads"].forEach(a => autonomy.push({ user_id: u, agent_type: a, enabled: true })));
  return {
    agent_schedules: schedules,
    agent_autonomy: autonomy,
    agent_proposals: [{ id: "cc-p1", user_id: USER, title: "List the blue mug", agent_type: "store", status: "pending", created_at: ago(90) }],
    ai_tasks: planRows().ai_tasks, executive_dispatches: planRows().executive_dispatches, email_sequences: [], email_sequence_enrollments: [], social_post_drafts: [], content_library: [],
    model_calls: [
      { id: 1, user_id: USER, agent_type: "seo", model: "claude-haiku-4-5-20251001", input_tokens: 400000, output_tokens: 40000, funded_by: "platform", created_on: DAY_OF(ago(0)) },
      { id: 2, user_id: OWNER, agent_type: "seo", model: "claude-haiku-4-5-20251001", input_tokens: 2000000, output_tokens: 200000, funded_by: "platform", created_on: DAY_OF(ago(0)) }
    ],
    job_runs: [{ job_name: "agent_schedules", last_run_on: DAY_OF(ago(0)), finished_at: ago(20), last_error: null }],
    radar_status: [], users: []
  };
}
function server(seed, o) {
  o = o || {};
  const db = fakeDb(seed || world());
  const ctx = {
    supabase: db.client, JSON, Math, Promise, Object, Array, String, Number, isNaN, Error, Map, Set, RegExp,
    Date: fixedDate(NOW), crypto: require("crypto"), AsyncLocalStorage: require("async_hooks").AsyncLocalStorage,
    require: name => (name === "./lib/agentLive" ? LIVE : require("module").createRequire(path.join(REPO, "server.js"))(name)),
    nowIso: () => new Date(NOW).toISOString(),
    process: { env: Object.assign({ ENABLE_AGENT_SCHEDULES: "true" }, o.env || {}) },
    console: { log() {}, error() {}, warn() {} },
    getUserPlan: async (id) => ({ active: id !== LAPSED }),
    isTestAccount: require(path.join(REPO, "lib/testAccounts")).isTestAccount,
    requireActiveSubscription: function requireActiveSubscription(req, res, next) { next(); },
    aiLimiter: function aiLimiter(req, res, next) { next(); },
    requireAuth: function requireAuth(req, res, next) { req.user = { id: req.headers.user, role: ROLES[req.headers.user] }; next(); }
  };
  const routes = {};
  ctx.app = { get(p, ...h) { routes["get " + p] = h; }, post(p, ...h) { routes["post " + p] = h; }, _router: { stack: [] } };
  vm.createContext(ctx);
  LIFTED_SCRIPT.runInContext(ctx);
  async function call(key, user, query, body) {
    const chain = routes[key];
    if (!chain) throw new Error("route not lifted: " + key);
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    const req = { headers: { user }, params: {}, query: query || {}, body: body || {} };
    let i = 0;
    async function step() {
      const fn = chain[i++]; if (!fn) return;
      let advanced = false;
      await fn(req, res, (e) => { if (e) { res.code = 500; res.body = { error: e.message }; return; } advanced = true; });
      if (advanced) await step();
    }
    await step();
    return res;
  }
  return { db, isDue: ctx.__isDue, center: user => call("get /api/command-center", user),
    calendar: (user, query) => call("get /api/agents/live/calendar", user, query),
    dispatch: (user, body) => call("post /api/assignments/dispatch", user, {}, body),
    capError: ctx.__capError, ceilingError: ctx.__ceilingError };
}

/* ── /api/agents/live: lib/agentLive.js over fixture reads ── */
const IS_DUE = server().isDue;
function liveBody(o) {
  o = o || {};
  const row = (id, agent, status, minsAgo, extra) => Object.assign({ id, agent_type: agent, task_type: agent + "/tool", status, created_at: ago(minsAgo),
    completed_at: status === "processing" ? null : ago(minsAgo - 1), error: status === "failed" ? "The model stopped early." : null }, extra || {});
  const empty = o.empty === true;
  const reads = {
    processing: { rows: empty ? [] : [row("seo-run", "seo", "processing", 2, { task_type: "seo/audit" }), row("content-stuck", "content", "processing", 25, { task_type: "content/outline" })] },
    recent: { rows: empty ? [] : [row("ads-fail", "ads", "failed", DAY, { task_type: "ads/copy" }), row("seo-done", "seo", "completed", 2 * DAY, { task_type: "seo/audit" })] },
    last: { rows: empty ? [] : [row("email-old", "email", "completed", 10 * DAY, { task_type: "email/sequence" })] },
    proposals: { rows: empty ? [] : [
      { id: "p1", agent_type: "store", title: "List the blue mug", created_at: ago(90) },
      { id: "p2", agent_type: "store", title: "Reprice the tea", created_at: ago(180) },
      { id: "p3", agent_type: "social", title: "Post: launch day", created_at: ago(2 * DAY) }] },
    schedules: { rows: empty ? [] : [
      { agent_type: "email", task_type: "email/sequence", cadence: "daily", hour_utc: 9, enabled: true, paused: false, last_run_on: null },
      { agent_type: "operations", task_type: "operations/sop", cadence: "daily", hour_utc: 8, enabled: true, paused: true, paused_reason: "Paused after 3 failed runs in a row", consecutive_failures: 3 },
      { agent_type: "analytics", task_type: "analytics/kpi-review", cadence: "weekly", hour_utc: 7, day_of_week: 1, enabled: true, paused: false }] },
    autonomy: { rows: [{ agent_type: "email", enabled: true }, { agent_type: "operations", enabled: true }, { agent_type: "analytics", enabled: true }] },
    feedback: { rows: empty ? [] : [{ agent_type: "seo", rating: "up" }, { agent_type: "seo", rating: "up" }, { agent_type: "seo", rating: "down", pinned: true }] },
    spend: { rows: [] }
  };
  if (o.idle) reads.processing = { rows: [] };
  return LIVE.buildLive({ types: LIVE.AGENT_KEYS.slice(), now: new Date(NOW), isDue: IS_DUE, costOf: () => ({ usd: 0 }), schedulerOn: true,
    subscriptionActive: o.subscription === undefined ? true : o.subscription, dailyCalls: o.calls || { used: 12, limit: 250 }, reads });
}

/* ── the pages in jsdom ── */
const settle = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };
/* NAMED (Block 3b, Oct 29 2026): before, the hook was the tile's own click line
   ("      b.addEventListener(\"click\", function () { window.location.assign(meta.page); });").
   Every navigation in Headquarters now goes through one go(url), so that is the line hooked. */
const GO_LINE = "  function go(url) { window.location.assign(url); }\n";
function timersFor(w) {
  const timers = new Map(); let n = 0;
  w.setTimeout = (fn, ms) => { timers.set(++n, { fn, ms: ms || 0, cleared: false }); return n; };
  w.clearTimeout = id => { const t = timers.get(id); if (t) t.cleared = true; };
  w.setInterval = (fn, ms) => { timers.set(++n, { fn, ms: ms || 0, cleared: false, interval: true }); return n; };
  w.clearInterval = w.clearTimeout;
  return timers;
}
async function mountHQ(o) {
  o = o || {};
  const srv = o.server || server();
  const user = o.user || USER;
  const html = FILES[EXEC].replace(/<script[\s\S]*?<\/script>/g, "");
  const dom = new JSDOM(html, { url: "https://bizforceai.com/executive-agent.html", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  const timers = timersFor(w);
  let hidden = false, online = true;
  Object.defineProperty(w.document, "hidden", { configurable: true, get: () => hidden });
  Object.defineProperty(w.navigator, "onLine", { configurable: true, get: () => online });
  w.matchMedia = q => ({ matches: !!o.reducedMotion && /reduce/.test(q), addListener() {}, removeListener() {} });
  w.localStorage.setItem("bf_token", "check-token");
  const calls = [];
  let liveReply = o.live || (() => ({ status: 200, body: liveBody() }));
  const decideReply = o.decide || (() => ({ status: 200, body: { proposal: { status: "approved" } } }));
  const queue = o.queue || [];
  const decided = new Set();   // as the server does: a decided proposal is no longer pending
  w.fetch = (url, init) => {
    const u = String(url), method = (init && init.method) || "GET";
    const call = { url: u, method, body: init && typeof init.body === "string" ? JSON.parse(init.body) : null };
    calls.push(call);
    let p;
    const reply = r => Promise.resolve({ ok: r.status >= 200 && r.status < 300, status: r.status,
      json: async () => JSON.parse(JSON.stringify(r.body)), text: async () => (typeof r.body === "string" ? r.body : JSON.stringify(r.body)) });
    if (method === "GET" && /\/api\/agents\/live$/.test(u)) { const r = liveReply(); p = r === "network" ? Promise.reject(new TypeError("Failed to fetch")) : reply(r); }
    else if (method === "GET" && /\/api\/command-center$/.test(u)) p = srv.center(user).then(r => reply({ status: r.code, body: r.body }));
    else if (method === "GET" && /\/api\/proposals\?status=pending$/.test(u)) p = reply({ status: 200, body: { proposals: queue.filter(q => !decided.has(q.id)) } });
    else if (method === "POST" && /\/api\/proposals\/[^/]+\/(approve|reject)$/.test(u)) {
      let release;
      const gate = new Promise(r => { release = r; });
      calls[calls.length - 1].release = release;
      p = (o.holdDecisions ? gate : Promise.resolve()).then(() => { const r = decideReply(u); if (r.status === 200) decided.add(u.split("/").slice(-2)[0]); return reply(r); });
    } else {
      const r = o.api ? o.api(method, u, call.body) : null;
      if (!r) p = Promise.reject(new Error("unplanned request " + method + " " + u));
      else p = (o.holdAct ? new Promise(res => { call.release = res; }) : Promise.resolve()).then(() => reply(r));
    }
    p.catch(() => {});
    return p;
  };
  if (o.speech) w.webkitSpeechRecognition = o.speech;
  const went = [];
  w.__go = url => went.push(url);
  let err = null;
  try {
    if (FILES[HQ].split(GO_LINE).length !== 2) throw new Error("the go() line was not found exactly once");
    w.eval(FILES[PAYWALL]);
    w.eval(FILES[HQ].replace(GO_LINE, GO_LINE.replace("window.location.assign(url)", "window.__go(url)")));
    w.eval(FILES[CC]);
  } catch (e) { err = e; }
  await settle();
  const liveTimer = () => { const P = w.BFHeadquarters && w.BFHeadquarters.poll; const t = P && P.timer ? timers.get(P.timer) : null; return t && !t.cleared ? t : null; };
  const fire = async () => { const t = liveTimer(); if (t) { t.cleared = true; t.fn(); } await settle(); };
  const doc = w.document;
  const tiles = () => [...doc.querySelectorAll("#hqGrid .hq-tile")];
  const rowsOf = t => [...t.querySelectorAll(".hq-row")].map(r => [r.querySelector(".hq-k").textContent, r.querySelector(".hq-v").textContent]);
  return { w, doc, err, calls, went, timers, liveTimer, fire, tiles, rowsOf, srv,
    setLive: f => { liveReply = f; },
    hide: async v => { hidden = v; doc.dispatchEvent(new w.Event("visibilitychange")); await settle(); },
    goOffline: async () => { online = false; w.dispatchEvent(new w.Event("offline")); await settle(); },
    goOnline: async () => { online = true; w.dispatchEvent(new w.Event("online")); await settle(); },
    liveCalls: () => calls.filter(c => /\/api\/agents\/live$/.test(c.url)).length,
    alerts: () => [...doc.querySelectorAll("#hqAlerts .hq-alert")].map(a => ({ text: a.textContent, href: a.getAttribute("href"), alert: a.classList.contains("is-alert") })),
    alertsHead: () => (doc.querySelector("#hqAlerts .hq-alerts-head") || {}).textContent };
}

const WHEN = iso => new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
const NAME = t => LIVE.AGENT_NAMES[t] || t;
const AGENT_PAGES = ["ads-agent.html", "broker-agent.html", "community-agent.html", "email-agent.html", "etsy-agent.html", "executive-agent.html",
  "influencer-agent.html", "operations-agent.html", "publicist-agent.html", "rd-agent.html", "reputation-agent.html", "store-agent.html",
  "vertical-marketing-agent.html", "agents/analytics.html", "agents/content.html", "agents/sales.html", "agents/seo.html", "agents/social.html"];

(async () => {
  console.log("\n══ H1. the grid: all 18 in /live's own words, filters, sorts, links ══");
  const realNow = Date.now();
  const QUEUE = [
    { id: "p1", status: "pending", agent_type: "store", title: "List the blue mug", created_at: new Date(realNow - 30 * 60000).toISOString() },
    { id: "p2", status: "pending", agent_type: "store", title: "Reprice the tea", created_at: new Date(realNow - 180 * 60000).toISOString() },
    { id: "p3", status: "pending", agent_type: "social", title: "Post: launch day", created_at: new Date(realNow - 2 * DAY * 60000).toISOString() }
  ];
  const hq = await mountHQ({ queue: QUEUE });
  check("H1. Headquarters mounted without an error", !hq.err, hq.err && hq.err.stack);
  const body = liveBody();
  const tiles = hq.tiles();
  check("H1. 18 tiles, one per agent, named as /live names them",
    tiles.length === 18 && JSON.stringify(tiles.map(t => t.getAttribute("data-hq-agent")).sort()) === JSON.stringify(LIVE.AGENT_KEYS.slice().sort()) &&
    tiles.every(t => t.querySelector(".hq-name").textContent === body.agents[t.getAttribute("data-hq-agent")].name), tiles.length);
  const tileOf = type => tiles.find(t => t.getAttribute("data-hq-agent") === type);
  const words = type => { const t = tileOf(type); return [t.querySelector(".hq-now").textContent].concat(hq.rowsOf(t).map(r => r.join(": "))); };
  const expect = {
    seo: ["Running", "Last: Completed · " + WHEN(body.agents.seo.runs.last.finished_at), "Next: No schedule", "Approvals: None waiting", "Score: 2 helpful · 1 not helpful"],   // NAMED (Oct 30 2026, no emojis): was "Score: 2 up · 1 down"
    content: ["Stalled", "Last: No runs yet", "Next: No schedule", "Approvals: None waiting", "Score: No ratings yet"],
    ads: ["Idle", "Last: Failed · " + WHEN(body.agents.ads.runs.last.finished_at), "Next: No schedule", "Approvals: None waiting", "Score: No ratings yet"],
    store: ["Idle", "Last: No runs yet", "Next: No schedule", "Approvals: 2 waiting", "Score: No ratings yet"],
    email: ["Idle", "Last: Completed · " + WHEN(body.agents.email.runs.last.finished_at), "Next: " + WHEN("2027-01-21T09:00:00.000Z"), "Approvals: None waiting", "Score: No ratings yet"],
    operations: ["Idle", "Last: No runs yet", "Next: Paused", "Approvals: None waiting", "Score: No ratings yet"],
    analytics: ["Idle", "Last: No runs yet", "Next: " + WHEN("2027-01-25T07:00:00.000Z"), "Approvals: None waiting", "Score: No ratings yet"]
  };
  const wrong = Object.keys(expect).filter(k => JSON.stringify(words(k)) !== JSON.stringify(expect[k]));
  check("H1. each tile says Now, Last, Next, Approvals and Score exactly as /live has them (7 fixtures)", wrong.length === 0,
    wrong.map(k => k + ": " + JSON.stringify(words(k))).join(" | "));
  check("H1. the Next times are /live's own next.at", body.agents.email.next.at === "2027-01-21T09:00:00.000Z" && body.agents.analytics.next.at === "2027-01-25T07:00:00.000Z",
    JSON.stringify([body.agents.email.next, body.agents.analytics.next]));
  const order = () => hq.tiles().map(t => t.getAttribute("data-hq-agent"));
  const byName = list => list.slice().sort((a, b) => NAME(a).localeCompare(NAME(b)));
  const attention = byName(["ads", "content"]).concat(byName(["social", "store"]), ["seo"],
    byName(LIVE.AGENT_KEYS.filter(k => ["ads", "content", "social", "store", "seo"].indexOf(k) === -1)));
  check("H1. attention order: stalled and failed first, then needs approval, then running, then the rest A–Z",
    JSON.stringify(order()) === JSON.stringify(attention), order().join(","));
  hq.doc.getElementById("hqSort").click(); await settle();
  check("H1. \"Sort: A–Z\" orders every tile by name", JSON.stringify(order()) === JSON.stringify(byName(LIVE.AGENT_KEYS)) &&
    hq.doc.getElementById("hqSort").textContent === "Sort: A–Z", order().join(","));
  hq.doc.getElementById("hqSort").click(); await settle();
  const press = async f => { hq.doc.querySelector("[data-hq-filter='" + f + "']").click(); await settle(); return order().slice().sort(); };
  const filters = { running: await press("running"), approval: await press("approval"), failed: await press("failed"), scheduled: await press("scheduled") };
  check("H1. the filters: Running → seo; Needs approval → social, store; Failed in 7 days → ads; Scheduled → analytics, email",
    JSON.stringify(filters) === JSON.stringify({ running: ["seo"], approval: ["social", "store"], failed: ["ads"], scheduled: ["analytics", "email"] }), JSON.stringify(filters));
  await press("all");
  check("H1. \"All\" brings back all 18", hq.tiles().length === 18);
  const idleHq = await mountHQ({ live: () => ({ status: 200, body: liveBody({ empty: true, idle: true }) }) });
  idleHq.doc.querySelector("[data-hq-filter='running']").click(); await settle();
  check("H1. a filter with nothing in it says so, in words", idleHq.tiles().length === 0 && idleHq.doc.getElementById("hqGridEmpty").hidden === false &&
    idleHq.doc.getElementById("hqGridEmpty").textContent === "No agent matches \u201CRunning\u201D right now.", idleHq.doc.getElementById("hqGridEmpty").textContent);

  const AG = (() => { const box = {}; vm.runInNewContext("var out = " + /var AGENTS = (\{[\s\S]*?\n  \});/.exec(FILES[HQ])[1] + ";", box); return box.out; })();
  const pageOf = {}, accentOf = {};
  AGENT_PAGES.forEach(f => { const src = fs.readFileSync(path.join(FRONTEND, f), "utf8"); const t = (/agentType:\s*"([a-z_]+)"/.exec(src) || [])[1];
    pageOf[t] = "/" + f; accentOf[t] = (/accentColor:\s*"([^"]+)"/.exec(src) || [])[1]; });
  const mapWrong = LIVE.AGENT_KEYS.filter(k => !AG[k] || AG[k].page !== pageOf[k] || AG[k].accent !== accentOf[k]);
  check("H1. each tile's page and accent are that agent page's own (its agentType and accentColor)", mapWrong.length === 0 && Object.keys(AG).length === 18, mapWrong.join(","));
  tileOf("store").click();
  check("H1. a tile opens its agent's page", hq.went.length === 1 && hq.went[0] === "/store-agent.html", JSON.stringify(hq.went));
  check("H1. each tile wears its accent", hq.tiles().every(t => t.style.getPropertyValue("--hq-accent") === accentOf[t.getAttribute("data-hq-agent")]));

  console.log("\n══ H2. polling, as the agent panel does it ══");
  const constOf = (src, n) => (new RegExp("var " + n + " = (\\d+);").exec(src) || [])[1];
  check("H2. the same intervals as the agent panel: 60 s idle, 15 s busy, 5 minutes at most",
    constOf(FILES[HQ], "HQ_IDLE_MS") === constOf(FILES[AP], "LIVE_IDLE_MS") && constOf(FILES[HQ], "HQ_BUSY_MS") === constOf(FILES[AP], "LIVE_BUSY_MS") &&
    constOf(FILES[HQ], "HQ_MAX_BACKOFF_MS") === constOf(FILES[AP], "LIVE_MAX_BACKOFF_MS") && constOf(FILES[HQ], "HQ_IDLE_MS") === "60000" &&
    constOf(FILES[HQ], "HQ_BUSY_MS") === "15000" && constOf(FILES[HQ], "HQ_MAX_BACKOFF_MS") === "300000");
  const pl = await mountHQ();
  check("H2. one read of /api/agents/live on load, then 15 s while an agent is running", pl.liveCalls() === 1 && pl.liveTimer() && pl.liveTimer().ms === 15000,
    pl.liveCalls() + " " + (pl.liveTimer() && pl.liveTimer().ms));
  pl.setLive(() => ({ status: 200, body: liveBody({ idle: true }) }));
  await pl.fire();
  check("H2. nothing running: 60 s", pl.liveCalls() === 2 && pl.liveTimer() && pl.liveTimer().ms === 60000, pl.liveTimer() && pl.liveTimer().ms);
  await pl.hide(true);
  const hiddenStatus = pl.doc.getElementById("hqStatus").textContent;
  await pl.fire();
  check("H2. hidden: polling stops, no timer, and the status says so", !pl.liveTimer() && pl.liveCalls() === 2 && hiddenStatus === "Paused while this tab is hidden", hiddenStatus);
  await pl.hide(false);
  check("H2. shown again: one read at once", pl.liveCalls() === 3 && !!pl.liveTimer());
  await pl.goOffline();
  check("H2. offline: stopped, and the status says so", !pl.liveTimer() && pl.doc.getElementById("hqStatus").textContent === "Offline — Headquarters paused");
  await pl.goOnline();
  check("H2. online again: read at once", pl.liveCalls() === 4);
  pl.setLive(() => ({ status: 503, body: { error: "down" } }));
  const waits = [];
  for (let i = 0; i < 4; i++) { await pl.fire(); waits.push(pl.liveTimer() && pl.liveTimer().ms); }
  check("H2. a 5xx backs off 2×, 4×, to the 5-minute cap", JSON.stringify(waits) === JSON.stringify([120000, 240000, 300000, 300000]), JSON.stringify(waits));
  pl.setLive(() => ({ status: 429, body: {} }));
  await pl.fire();
  check("H2. a 429 backs off too", pl.liveTimer() && pl.liveTimer().ms === 300000);
  pl.setLive(() => ({ status: 200, body: liveBody({ idle: true }) }));
  await pl.fire();
  check("H2. a good answer resets to the base interval", pl.liveTimer() && pl.liveTimer().ms === 60000 && pl.w.BFHeadquarters.poll.failures === 0);

  console.log("\n══ H3. alerts, from real fields only ══");
  const ccUser = (await server().center(USER)).body;
  const spend = ccUser.spend.data;
  const money = n => "$" + Number(n).toFixed(2);
  const memberAlerts = hq.alerts();
  /* NAMED BEFORE → AFTER (Oct 30 2026, the Executive command deck). BEFORE: the alerts linked to sections of one long
     page (#commandCenterSection, #hqQueue, #ccSpend, #ccPlatformPanel). AFTER: each links to the deck tab that holds
     where it is fixed: failed runs and approvals to #approvals (the queue and "Needs you"), spend and the platform
     ceiling to #history (the Command Center's Spend and Platform panels). A link lands on a real tab or section. */
  const expectAlerts = [
    { text: "1 failed run in 7 days", href: "#approvals", alert: true },
    { text: "3 approvals waiting", href: "#approvals", alert: true },
    { text: NAME("content") + ": a run has been in progress over 10 minutes", href: "/run.html?id=content-stuck", alert: true },
    { text: NAME("operations") + " schedule paused after 3 failed runs", href: "/operations-agent.html", alert: true },
    { text: "Model calls today: 12 of 250", href: null, alert: false },
    { text: "Subscription active", href: "/billing.html", alert: false },
    { text: "Spend this month: " + money(spend.usd) + " of " + money(spend.monthly_cap_usd), href: "#history", alert: false }
  ];
  check("H3. the member's alerts, each from /live or the Command Center, each linked where it is fixed",
    JSON.stringify(memberAlerts) === JSON.stringify(expectAlerts) && hq.alertsHead() === "4 alerts", JSON.stringify(memberAlerts));
  const targets = memberAlerts.filter(a => a.href && a.href[0] === "#").map(a => a.href.slice(1));
  const landsOn = (doc, id) => !!(doc.getElementById(id) || (doc.getElementById("deckPanel-" + id) && doc.getElementById("deckTab-" + id)));
  check("H3. every in-page link lands on a real deck tab or section", targets.length >= 3 && targets.every(id => landsOn(hq.doc, id)), targets.join(","));
  check("H3. a member sees no platform ceiling: no section, no figure", !("platform" in ccUser) && !/Platform ceiling|\$25\.00/.test(hq.doc.getElementById("hqAlerts").textContent) &&
    hq.doc.getElementById("ccPlatformPanel").style.display === "none", hq.doc.getElementById("hqAlerts").textContent);
  const quiet = await mountHQ({ live: () => ({ status: 200, body: liveBody({ empty: true, idle: true }) }) });
  check("H3. an account with nothing wrong: \"No alerts\", and only the three gauges, none pulsing",
    quiet.alertsHead() === "No alerts — nothing failed, stalled or waiting" && quiet.alerts().length === 3 && quiet.alerts().every(a => !a.alert),
    JSON.stringify(quiet.alerts()));
  const lapsedHq = await mountHQ({ live: () => ({ status: 200, body: liveBody({ empty: true, idle: true, subscription: false, calls: { used: 250, limit: 250 } }) }) });
  check("H3. a lapsed subscription and a spent daily limit are alerts, in their own words",
    lapsedHq.alerts().some(a => a.alert && a.text === "Subscription not active — scheduled runs wait until it is" && a.href === "/billing.html") &&
    lapsedHq.alerts().some(a => a.alert && a.text === "Model calls today: 250 of 250 — the daily limit is reached; it resets at midnight UTC"), JSON.stringify(lapsedHq.alerts()));
  const unreadHq = await mountHQ({ live: () => ({ status: 200, body: Object.assign(liveBody({ empty: true, idle: true }), { daily_calls: { unavailable: "down" } }) }) });
  check("H3. a count that could not be read is an alert, never 0", unreadHq.alerts().some(a => a.alert && a.text === "Model calls today could not be counted") &&
    !unreadHq.alerts().some(a => /Model calls today: 0/.test(a.text)));
  const ccOwner = (await server().center(OWNER)).body;
  const admin = await mountHQ({ user: OWNER });
  const ceil = ccOwner.platform && ccOwner.platform.data && ccOwner.platform.data.ceiling;
  check("H3. an admin's Headquarters shows today's platform ceiling, from the admin-only section",
    !!ceil && admin.alerts().some(a => a.text === "Platform ceiling today: " + money(ceil.spent_usd) + " of " + money(ceil.cap_usd) && a.href === "#history"),
    JSON.stringify([ceil, admin.alerts().map(a => a.text)]));

  console.log("\n══ H4. the approval queue: a click, one request, and nothing without one ══");
  const items = [...hq.doc.querySelectorAll("#hqQueue [data-proposal]")];
  check("H4. the queue lists each pending proposal: its agent, title, age, Approve, Reject and a link to its full view",
    items.length === 3 && items[0].querySelector(".hq-proposal-agent").textContent === NAME("store") &&
    items[0].querySelector(".hq-proposal-title").textContent === "List the blue mug" && items[0].querySelector(".hq-proposal-age").textContent === "30 min ago" &&
    items[1].querySelector(".hq-proposal-age").textContent === "3 h ago" && items[2].querySelector(".hq-proposal-age").textContent === "2 d ago" &&
    items.every(li => li.querySelector("[data-hq-decide='approve']") && li.querySelector("[data-hq-decide='reject']") && li.querySelector("a[href='/proposals.html']")),
    items.map(li => li.textContent).join(" | "));
  for (let i = 0; i < 3; i++) await hq.fire();
  const decisions = m => m.calls.filter(c => c.method === "POST");
  check("H4. loading, rendering and polling three times approve and reject nothing", decisions(hq).length === 0, JSON.stringify(decisions(hq)));
  const held = await mountHQ({ queue: QUEUE, holdDecisions: true });
  const approve = held.doc.querySelector("[data-proposal='p1'] [data-hq-decide='approve']");
  approve.click(); approve.click(); await settle();
  const pending = decisions(held);
  check("H4. Approve: one POST to /api/proposals/p1/approve, both buttons held while it is out, a second click sends nothing",
    pending.length === 1 && /\/api\/proposals\/p1\/approve$/.test(pending[0].url) && approve.disabled &&
    held.doc.querySelector("[data-proposal='p1'] [data-hq-decide='reject']").disabled && approve.textContent === "Approving…", JSON.stringify(pending));
  const before = held.calls.length;
  pending[0].release(); await settle();
  check("H4. after the answer, the queue and the Command Center are read again", held.calls.slice(before).some(c => /status=pending$/.test(c.url)) &&
    held.calls.slice(before).some(c => /\/api\/command-center$/.test(c.url)));
  const rej = await mountHQ({ queue: QUEUE, decide: () => ({ status: 409, body: { error: "Proposal not found or no longer pending" } }) });
  rej.doc.querySelector("[data-proposal='p2'] [data-hq-decide='reject']").click(); await settle();
  check("H4. Reject posts once to /reject; a 409 says the proposal is no longer pending",
    decisions(rej).length === 1 && /\/api\/proposals\/p2\/reject$/.test(decisions(rej)[0].url) &&
    rej.doc.querySelector("[data-proposal='p2'] .hq-proposal-msg").textContent === "This proposal is no longer pending.", JSON.stringify(decisions(rej)));
  const pay = await mountHQ({ queue: QUEUE, decide: () => ({ status: 402, body: { error: "Publishing needs an active subscription.", billing_url: "/billing.html" } }) });
  pay.doc.querySelector("[data-proposal='p3'] [data-hq-decide='approve']").click(); await settle();
  const payMsg = pay.doc.querySelector("[data-proposal='p3'] .hq-proposal-msg");
  check("H4. a 402 keeps it pending and says why, with the Billing link", decisions(pay).length === 1 && /Publishing needs an active subscription\./.test(payMsg.textContent) &&
    !!payMsg.querySelector("a[href='/billing.html']"), payMsg.innerHTML);
  check("H4. the only approve request in the script is inside decide(), and decide() is called only from the click handler",
    (FILES[HQ].match(/decide\(/g) || []).length === 2 && FILES[HQ].indexOf("    if (d) decide(d);\n") !== -1 && (FILES[HQ].match(/\/api\/proposals\//g) || []).length === 1);

  console.log("\n══ H5. the Command Center in Headquarters ══");
  /* NAMED BEFORE → AFTER (Oct 30 2026, the Executive command deck). BEFORE: six panels, ccPlans among them. AFTER:
     five; the deck's Plans tab is the page's one plan board, so the Command Center's "Executive plans" panel is not
     on this page (bf-command-center.js skips a panel that is not there; checkExecutiveDeck D4 asserts plans once). */
  check("H5. the shared script fills every Command Center panel in Headquarters", !hq.doc.getElementById("ccPlans") && ["ccNeedsYou", "ccActivity", "ccAutopilot", "ccOutbound", "ccSpend"]
    .every(id => { const t = hq.doc.getElementById(id).textContent; return t && t !== "Loading…"; }) && /Read /.test(hq.doc.getElementById("ccStatus").textContent),
    hq.doc.getElementById("ccNeedsYou").textContent.slice(0, 120));
  check("H5. ...from scripts/bf-command-center.js, loaded right after the section, with no inline copy",
    FILES[EXEC].indexOf("<script src=\"/scripts/bf-command-center.js\"></script>") > FILES[EXEC].indexOf("<section id=\"commandCenterSection\"") &&
    FILES[EXEC].indexOf("(function commandCenter() {") === -1);

  console.log("\n══ H6. the calendar rule: agentLive's own walk ══");
  const rowOf = (agent, extra) => Object.assign({ agent_type: agent, task_type: agent + "/tool", cadence: "daily", hour_utc: 9, enabled: true, paused: false, last_run_on: null }, extra || {});
  const gates = { isDue: IS_DUE, schedulerOn: true, autonomy: true, subscriptionActive: true };
  const from = new Date("2027-01-20T00:00:00.000Z"), to = new Date("2027-03-05T00:00:00.000Z");
  const daily = rowOf("email"), weekly = rowOf("analytics", { cadence: "weekly", hour_utc: 7, day_of_week: 1 }), monthly = rowOf("store", { cadence: "monthly", hour_utc: 6, day_of_month: 31 });
  const walk = row => LIVE.runsBetween(row, Object.assign({ from, to, now: new Date(NOW) }, gates)).runs;
  const byNextRun = row => { const out = []; let cur = new Date(NOW); for (;;) { const n = LIVE.nextRun(row, Object.assign({ now: cur }, gates)).next; if (!n || Date.parse(n.at) >= to.getTime()) break; out.push(n.at); cur = new Date(n.at); } return out; };
  const agree = [daily, weekly, monthly].map(r => JSON.stringify(walk(r)) === JSON.stringify(byNextRun(r)));
  check("H6. runsBetween agrees with nextRun, slot by slot, for daily, weekly and monthly-31", agree.every(Boolean), JSON.stringify(agree));
  check("H6. monthly on the 31st: 31 January, then 28 February (February has no 31st)",
    JSON.stringify(walk(monthly)) === JSON.stringify(["2027-01-31T06:00:00.000Z", "2027-02-28T06:00:00.000Z"]), JSON.stringify(walk(monthly)));
  check("H6. weekly on Monday at 07:00: 25 January to 1 March, six runs",
    JSON.stringify(walk(weekly)) === JSON.stringify(["2027-01-25", "2027-02-01", "2027-02-08", "2027-02-15", "2027-02-22", "2027-03-01"].map(d => d + "T07:00:00.000Z")), JSON.stringify(walk(weekly)));
  check("H6. daily at 09:00: from tomorrow (today's 09:00 has passed) to 4 March, 43 runs, nothing before now",
    walk(daily).length === 43 && walk(daily)[0] === "2027-01-21T09:00:00.000Z" && walk(daily)[42] === "2027-03-04T09:00:00.000Z", walk(daily).length + " " + walk(daily)[0]);
  const srv = server();
  const cal = await srv.calendar(USER, { from: "2027-01-20", to: "2027-03-05" });
  const sched = t => cal.body.schedules.find(x => x.agent_type === t);
  check("H6. the route gives each schedule the same runs as runsBetween",
    cal.code === 200 && JSON.stringify(sched("email").runs) === JSON.stringify(walk(daily)) && JSON.stringify(sched("analytics").runs) === JSON.stringify(walk(weekly)) &&
    JSON.stringify(sched("store").runs) === JSON.stringify(walk(monthly)), cal.code + " " + JSON.stringify(cal.body).slice(0, 300));
  check("H6. paused, switched off and autonomy off: no runs, each with its reason",
    sched("operations").runs.length === 0 && sched("operations").reason === "paused" && sched("operations").consecutive_failures === 3 &&
    sched("ads").runs.length === 0 && sched("ads").reason === "disabled" && sched("seo").runs.length === 0 && sched("seo").reason === "autonomy_off",
    JSON.stringify([sched("operations"), sched("ads"), sched("seo")]));
  const lapsed = await srv.calendar(LAPSED, { from: "2027-01-20", to: "2027-03-05" });
  check("H6. a lapsed subscription: nothing at all, each \"subscription_inactive\"",
    lapsed.body.schedules.length === 6 && lapsed.body.schedules.every(x => x.runs.length === 0 && (x.reason === "subscription_inactive" || x.reason === "disabled" || x.reason === "paused" || x.reason === "autonomy_off")) &&
    lapsed.body.schedules.filter(x => x.reason === "subscription_inactive").length === 3, JSON.stringify(lapsed.body.schedules.map(x => x.reason)));
  const off = await server(null, { env: { ENABLE_AGENT_SCHEDULES: "" } }).calendar(USER, { from: "2027-01-20", to: "2027-03-05" });
  check("H6. the scheduler off: nothing at all, \"scheduler_off\"", off.body.schedules.every(x => x.runs.length === 0) &&
    off.body.schedules.filter(x => x.reason === "scheduler_off").length === 4, JSON.stringify(off.body.schedules.map(x => x.reason)));
  check("H6. the member's own schedules only, read with user_id", srv.db.log.filter(q => q.table === "agent_schedules" || q.table === "agent_autonomy")
    .every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id")));
  const bad = await srv.calendar(USER, { from: "2027-01-01", to: "2027-06-01" });
  check("H6. more than 62 days is refused with a 400", bad.code === 400);
  check("H6. the route wrote nothing: no calendar_events row, no write of any kind", srv.db.writes.length === 0 && !srv.db.log.some(q => q.table === "calendar_events"),
    JSON.stringify(srv.db.writes));
  check("H6. calendar.html computes no slot of its own: no cadence, hour or day-of-month arithmetic",
    !/hour_utc|day_of_month|day_of_week|getUTCDay|getUTCHours|cadence ===/.test(FILES[CAL]));

  console.log("\n══ H7. calendar.html: the Agent runs layer ══");
  async function mountCal(user, o) {
    o = o || {};
    const csrv = o.server || server();
    const raw = FILES[CAL];
    const inline = []; raw.replace(/<script>([\s\S]*?)<\/script>/g, (m, code) => { inline.push(code); return m; });
    const dom = new JSDOM(raw.replace(/<script[\s\S]*?<\/script>/g, ""), { url: "https://bizforceai.com/calendar.html", runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window;
    timersFor(w);
    w.Date = fixedDate(NOW);
    w.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {} });
    w.localStorage.setItem("bf_token", "check-token");
    const calls = [];
    w.fetch = (url, init) => {
      const u = String(url), method = (init && init.method) || "GET";
      calls.push({ url: u, method });
      const reply = r => Promise.resolve({ ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.body, text: async () => JSON.stringify(r.body) });
      let p;
      const m = /\/api\/agents\/live\/calendar\?from=([0-9-]+)&to=([0-9-]+)$/.exec(u);
      if (m && method === "GET") p = csrv.calendar(user, { from: m[1], to: m[2] }).then(r => reply({ status: r.code, body: r.body }));
      else if (method === "GET" && /\/api\/calendar\/events\?/.test(u)) p = reply({ status: 200, body: { events: [] } });
      else if (method === "GET") p = reply({ status: 200, body: {} });
      else p = reply({ status: 200, body: {} });
      p.catch(() => {});
      return p;
    };
    let err = null;
    try { inline.forEach(code => w.eval(code)); } catch (e) { err = e; }
    await settle();
    return { w, doc: w.document, calls, err, srv: csrv,
      runs: () => [...w.document.querySelectorAll("#calPage .cal-agent-runs")].map(d => ({ jdn: Number(d.closest("[data-jdn]").getAttribute("data-jdn")), title: d.getAttribute("title") })),
      note: () => [...w.document.querySelectorAll("#calAgentRunsNote p")].map(p => p.textContent) };
  }
  const page = await mountCal(USER);
  check("H7. calendar.html runs in jsdom", !page.err, page.err && page.err.stack);
  check("H7. off until pressed: no request for agent runs, no marker", !page.calls.some(c => /live\/calendar/.test(c.url)) && page.runs().length === 0 &&
    page.doc.getElementById("calAgentRunsNote").hidden === true);
  const btn = page.doc.getElementById("calAgentRunsBtn");
  btn.click(); await settle();
  const req = page.calls.filter(c => /live\/calendar/.test(c.url));
  check("H7. pressed: one GET for the visible month with a day either side, and the button says it is on",
    req.length === 1 && /from=2026-12-31&to=2027-02-02$/.test(req[0].url) && btn.getAttribute("aria-pressed") === "true", JSON.stringify(req));
  const jdnOf = iso => { const d = new Date(iso); const y = d.getFullYear(), mo = d.getMonth() + 1, da = d.getDate();
    const a = Math.floor((14 - mo) / 12), yy = y + 4800 - a, mm = mo + 12 * a - 3;
    return da + Math.floor((153 * mm + 2) / 5) + 365 * yy + Math.floor(yy / 4) - Math.floor(yy / 100) + Math.floor(yy / 400) - 32045; };
  const janEnd = new Date("2027-02-01T00:00:00.000Z");
  const expected = {};
  [["email", daily], ["analytics", weekly], ["store", monthly]].forEach(([t, row]) => walk(row).forEach(iso => {
    const d = new Date(iso);
    if (d.getFullYear() === 2027 && d.getMonth() === 0) (expected[jdnOf(iso)] = expected[jdnOf(iso)] || []).push(NAME(t));
  }));
  void janEnd;
  const placed = {};
  page.runs().forEach(r => { placed[r.jdn] = r.title.split(", ").map(l => l.replace(/^\S+ (AM|PM) /, "").replace(/^\d{1,2}:\d{2} /, "")); });
  const sortObj = o => JSON.stringify(Object.keys(o).sort().map(k => [k, o[k].slice().sort()]));
  check("H7. each run sits on its own local day, named by its agent, and only runs still to come", sortObj(placed) === sortObj(expected),
    sortObj(placed).slice(0, 300) + " vs " + sortObj(expected).slice(0, 300));
  const count = Object.keys(expected).reduce((n, k) => n + expected[k].length, 0);
  check("H7. the note says what is shown and why the rest show nothing, in words",
    JSON.stringify(page.note()) === JSON.stringify([
      "Agent runs: " + count + " still to come in this view, from your own schedules. Read-only; past runs are on each agent's page.",
      NAME("ads") + " · ads/copy: nothing shown — the schedule is switched off.",
      NAME("operations") + " · operations/sop: nothing shown — the runner paused it after 3 failed runs.",
      NAME("seo") + " · seo/audit: nothing shown — autonomous mode is off for this agent."]), JSON.stringify(page.note()));
  check("H7. the page sent nothing but GETs, and the route wrote nothing", page.calls.every(c => c.method === "GET") && page.srv.db.writes.length === 0,
    JSON.stringify(page.calls.filter(c => c.method !== "GET")));
  btn.click(); await settle();
  check("H7. pressed again: the markers go and the note hides", page.runs().length === 0 && page.doc.getElementById("calAgentRunsNote").hidden === true && btn.getAttribute("aria-pressed") === "false");
  const lp = await mountCal(LAPSED);
  lp.doc.getElementById("calAgentRunsBtn").click(); await settle();
  check("H7. a lapsed account: no marker, each live schedule \"your subscription is not active\"", lp.runs().length === 0 &&
    lp.note().filter(l => / — your subscription is not active\.$/.test(l)).length === 3 && /^Agent runs: 0 still to come/.test(lp.note()[0]), JSON.stringify(lp.note()));

  console.log("\n══ H8. motion ══");
  const css = (/\/\* ── EXECUTIVE HEADQUARTERS[\s\S]*?<\/style>/.exec(FILES[EXEC]) || [""])[0];
  const animated = [...css.matchAll(/([^{}]+)\{[^{}]*\banimation:\s*hq-[a-z]+/g)].map(m => m[1].trim());
  /* NAMED (Block 3b, Oct 29 2026): before, exactly [".hq-deck::after", ".hq-alert.is-alert", ".hq-tile.is-running .hq-ring"].
     The console adds its caret and the send pulse, which H10 and H13 prove appears on a success only. */
  check("H8. motion only on the scanline, a running tile's ring, a real alert, the console's caret and a successful send",
    JSON.stringify(animated) === JSON.stringify([".hq-deck::after", ".hq-alert.is-alert", ".hq-tile.is-running .hq-ring", ".hq-caret", ".hq-send.is-sent"]), JSON.stringify(animated));
  check("H8. prefers-reduced-motion stops every animation and transition in Headquarters",
    /@media \(prefers-reduced-motion: reduce\) \{\s*\.hq \*, \.hq \*::before, \.hq \*::after, \.hq-deck::after \{ animation: none !important; transition: none !important; \}/.test(css));
  const still = await mountHQ({ reducedMotion: true });
  check("H8. ...and the page marks itself still when the browser asks", still.doc.getElementById("hq").classList.contains("hq--still") &&
    !hq.doc.getElementById("hq").classList.contains("hq--still") && /\.hq\.hq--still \*[^{]*\{ animation: none !important; transition: none !important; \}/.test(css));
  check("H8. the pulse is earned: running ring only on running tiles, is-alert only on real alerts",
    hq.tiles().filter(t => t.classList.contains("is-running")).map(t => t.getAttribute("data-hq-agent")).join() === "seo" &&
    hq.alerts().filter(a => a.alert).length === 4 && quiet.alerts().filter(a => a.alert).length === 0);

  console.log("\n══ H9. keyboard and aria ══");
  const ts = hq.tiles();
  check("H9. every tile is a button with an aria-label naming the agent and what it opens",
    ts.every(t => t.tagName === "BUTTON" && t.type === "button" && t.getAttribute("aria-label").indexOf(t.querySelector(".hq-name").textContent + ": ") === 0 &&
      /Opens the .+ page\.$/.test(t.getAttribute("aria-label"))) && hq.doc.querySelector("#hqGrid .hq-ring").getAttribute("aria-hidden") === "true",
    ts[0] && ts[0].getAttribute("aria-label"));
  const key = async (el, k) => { el.dispatchEvent(new hq.w.KeyboardEvent("keydown", { key: k, bubbles: true })); await settle(); };
  ts[0].focus(); await key(ts[0], "ArrowRight");
  const a1 = hq.doc.activeElement === ts[1];
  await key(ts[1], "End");
  const aEnd = hq.doc.activeElement === ts[17];
  await key(ts[17], "Home");
  const aHome = hq.doc.activeElement === ts[0];
  await key(ts[0], "ArrowLeft");
  check("H9. arrow keys, Home and End move between tiles", a1 && aEnd && aHome && hq.doc.activeElement === ts[0], [a1, aEnd, aHome].join(","));
  hq.doc.querySelector("[data-hq-filter='failed']").click(); await settle();
  check("H9. a filter says it is on (aria-pressed), and only one is",
    [...hq.doc.querySelectorAll("[data-hq-filter]")].map(b => b.getAttribute("aria-pressed")).join() === "false,false,false,true,false");
  hq.doc.querySelector("[data-hq-filter='all']").click(); hq.doc.getElementById("hqSort").click(); await settle();
  check("H9. the sort button says the order it is in", hq.doc.getElementById("hqSort").getAttribute("aria-label") === "Sorted A to Z; press to sort by attention");
  check("H9. the status line is a polite live region; the alerts and queue are labelled regions",
    hq.doc.getElementById("hqStatus").getAttribute("role") === "status" && hq.doc.getElementById("hqStatus").getAttribute("aria-live") === "polite" &&
    hq.doc.getElementById("hqAlerts").getAttribute("role") === "region" && hq.doc.getElementById("hqQueue").getAttribute("aria-labelledby") === "hqQueueTitle");
  check("H9. phones: the grid steps to two columns, then one", /@media \(max-width: 640px\) \{[\s\S]*?\.hq-grid \{ grid-template-columns: 1fr 1fr;/.test(css) &&
    /@media \(max-width: 380px\) \{ \.hq-grid \{ grid-template-columns: 1fr; \} \}/.test(css));

  /* ══ Block 3b: the act side ══════════════════════════════════════════════ */
  console.log("\n══ H10. the command box: one request per Send; an acting tool never from here ══");
  const hqVar = name => {
    const m = new RegExp("var " + name + " = (\\{[\\s\\S]*?\\n  \\});").exec(FILES[HQ]);
    if (!m) return null;
    const box = {}; vm.runInNewContext("var out = " + m[1] + ";", box); return box.out;
  };
  const HQ_TOOLS = hqVar("TOOLS") || {}, HQ_ACTING = hqVar("ACTING") || {};
  const SERVER_ACTING = (() => { const m = /var CHAIN_NON_DISPATCHABLE_TOOLS = \[([\s\S]*?)\];/.exec(SRC); return m ? [...m[1].matchAll(/"([^"]+)"/g)].map(x => x[1]) : []; })();
  const ACT_OK = (method, u, body) => {
    if (method === "POST" && /\/api\/ai\/tasks$/.test(u)) return { status: 202, body: { success: true, queued: true, task: { id: T(99), agent_type: body.agent_type, status: "processing" }, message: "AI task queued successfully." } };
    if (method === "POST" && /\/api\/agents\/executive\/plan$/.test(u)) return { status: 200, body: { task_id: PLAN_NEW, persisted: true, assignments: [
      { id: 1, agent: "seo", tool: "audit", task: "Audit the second shop's page", is_dispatchable: true },
      { id: 2, agent: "store", tool: null, task: "Choose the launch price", is_dispatchable: false }] } };
    if (method === "POST" && /\/api\/assignments\/dispatch$/.test(u)) return { status: 200, body: { ok: true, status: 200, refused_reason: null, detail: null, chain_id: "chain-1", result: { task_id: T(98), persisted: true }, recorded: true } };
    if (method === "PUT" && /\/api\/agent-autonomy$|\/api\/agent-schedules\/[a-z_]+\/(pause|resume)$/.test(u)) return { status: 200, body: { ok: true } };
    return null;
  };
  const posts = m => m.calls.filter(c => c.method !== "GET");
  const pickAgent = async (m, agent, tool) => {
    const sel = m.doc.getElementById("hqAgent");
    sel.value = agent;
    sel.dispatchEvent(new m.w.Event("change", { bubbles: true }));
    if (tool !== undefined) m.doc.getElementById("hqTool").value = tool;
    await settle();
  };
  const typeIn = (m, text) => { m.doc.getElementById("hqCommand").value = text; };
  const said = m => m.doc.getElementById("hqCommandMsg").textContent;
  const sendBtn = m => m.doc.getElementById("hqSend");

  const opts = [...hq.doc.querySelectorAll("#hqAgent option")].map(o => [o.value, o.textContent]);
  check("H10. the agent picker: \"Let the Executive decide\", then the 18 agents by their canonical names",
    opts.length === 19 && opts[0][0] === "decide" && opts[0][1] === "Let the Executive decide" &&
    JSON.stringify(opts.slice(1).map(o => o[0]).sort()) === JSON.stringify(LIVE.AGENT_KEYS.slice().sort()) &&
    opts.slice(1).every(o => o[1] === LIVE.AGENT_NAMES[o[0]]) && hq.doc.querySelectorAll("#hqChips [data-hq-chip]").length === 19, JSON.stringify(opts));
  const MAPV = JSON.parse(FILES[MAP]);
  const mapTools = page => {
    const pg = Object.keys(MAPV.pages).map(k => MAPV.pages[k]).find(p => p.p === page);
    const c = (pg && pg.c) || [];
    return c.map(r => (/^\[data-tool-run="([^"]+)"\]$/.exec(r[0]) || [])[1]).filter(Boolean)
      .map(id => [id, (c.find(r => r[0] === "[data-tool-toggle=\"" + id + "\"]") || [])[1] || null]);
  };
  const toolWrong = LIVE.AGENT_KEYS.filter(k => JSON.stringify(mapTools(AG[k].page)) !== JSON.stringify(HQ_TOOLS[k] || []));
  /* NAMED BEFORE → AFTER (Oct 30 2026, the Executive command deck). BEFORE: 17 agents with tools in the picker, the
     Executive's "Executive Plan" among them. AFTER: 16; on the deck a plan is the box's own "Make a plan" mode, so
     the Executive has no tool to pick, and the app map lists none for its page (lib/appMapBuild.js, deck: true). */
  check("H10. the tool picker's tools are each agent page's tools as the app map lists them", toolWrong.length === 0 && Object.keys(HQ_TOOLS).length === 16 && !HQ_TOOLS.executive,
    toolWrong.map(k => k + ": " + JSON.stringify(mapTools(AG[k].page))).join(" | "));
  check("H10. the acting tools are exactly the server's CHAIN_NON_DISPATCHABLE_TOOLS",
    SERVER_ACTING.length >= 7 && JSON.stringify(Object.keys(HQ_ACTING).sort()) === JSON.stringify(SERVER_ACTING.slice().sort()), JSON.stringify([SERVER_ACTING, Object.keys(HQ_ACTING)]));
  const pageReaches = (page, key) => {
    const html = fs.readFileSync(path.join(FRONTEND, page.slice(1)), "utf8");
    const srcs = [...html.matchAll(/<script src="\/(scripts\/[^"]+\.js)"/g)].map(m => m[1]).filter(f => fs.existsSync(path.join(FRONTEND, f)));
    return [html].concat(srcs.map(f => fs.readFileSync(path.join(FRONTEND, f), "utf8"))).some(t => t.indexOf("/api/agents/" + key) !== -1);
  };
  const unreached = Object.keys(HQ_ACTING).filter(k => !pageReaches(HQ_ACTING[k].page, k));
  check("H10. ...each sent to a page that calls that route itself, through its own approval flow", unreached.length === 0, unreached.join(","));

  const cmd = await mountHQ({ api: ACT_OK, holdAct: true });
  await pickAgent(cmd, "seo", "");
  typeIn(cmd, "Find three quick wins on the shop page");
  const liveBefore = cmd.liveCalls();
  sendBtn(cmd).click(); sendBtn(cmd).click(); await settle();
  const t1 = posts(cmd);
  check("H10. a typed task: one POST /api/ai/tasks with that agent and the words, however many clicks; Send held while it is out",
    t1.length === 1 && /\/api\/ai\/tasks$/.test(t1[0].url) && JSON.stringify(t1[0].body) === JSON.stringify({ agent_type: "seo", prompt: "Find three quick wins on the shop page" }) &&
    sendBtn(cmd).disabled && sendBtn(cmd).textContent === "Sending…", JSON.stringify(t1));
  t1[0].release(); await settle();
  check("H10. the 202 is shown and followed: its run linked, /live read at once so the tile shows it, the box cleared, the send pulse",
    said(cmd) === "Queued (202). SEO Agent has the task; it shows on the agent's tile while it runs. Follow the run" &&
    !!cmd.doc.querySelector("#hqCommandMsg a[href='/run.html?id=" + T(99) + "']") && cmd.liveCalls() === liveBefore + 1 &&
    cmd.doc.getElementById("hqCommand").value === "" && sendBtn(cmd).classList.contains("is-sent") && !sendBtn(cmd).disabled,
    said(cmd) + " | " + cmd.liveCalls() + " vs " + liveBefore);
  sendBtn(cmd).click(); await settle();
  check("H10. an empty box sends nothing and says so", posts(cmd).length === 1 && said(cmd) === "Write the task first." && !sendBtn(cmd).classList.contains("is-sent"), said(cmd));
  await pickAgent(cmd, "email", "sequence");
  typeIn(cmd, "Welcome series");
  sendBtn(cmd).click(); await settle();
  check("H10. a tool opens on its agent's own page with the words to prefill, and nothing is posted",
    cmd.went[cmd.went.length - 1] === "/email-agent.html#tool=sequence&prefill=Welcome%20series" && posts(cmd).length === 1, JSON.stringify(cmd.went));
  const actingSeen = [];
  for (const key of SERVER_ACTING) {
    const [agent, tool] = key.split("/");
    await pickAgent(cmd, agent, tool);
    const chosen = cmd.doc.getElementById("hqTool").value === tool;
    const before = cmd.calls.length, wentBefore = cmd.went.length;
    typeIn(cmd, "Do it now");
    sendBtn(cmd).click(); await settle();
    const okLine = /^This one goes through approval on its own page\. Open .+ on its page$/.test(said(cmd));
    const quiet = cmd.calls.length === before && cmd.went.length === wentBefore;
    const open = cmd.doc.querySelector("#hqCommandMsg [data-hq-open]");
    if (open) open.click();
    actingSeen.push({ key, chosen, okLine, quiet, opened: cmd.went.length === wentBefore + 1 && cmd.went[cmd.went.length - 1] === (HQ_ACTING[key] || {}).page });
  }
  const actingBad = actingSeen.filter(x => !(x.chosen && x.okLine && x.quiet && x.opened));
  check("H10. each acting tool, chosen and sent: no request at all, \"This one goes through approval on its own page.\", and its page only on a press",
    actingSeen.length === SERVER_ACTING.length && actingBad.length === 0, JSON.stringify(actingBad));

  console.log("\n══ H11. Let the Executive decide ══");
  const pl2 = await mountHQ({ api: ACT_OK });
  const ccReads = m => m.calls.filter(c => /\/api\/command-center$/.test(c.url)).length;
  check("H11. the default is \"Let the Executive decide\": the goal, with horizon and constraints, and no tool picker",
    pl2.doc.getElementById("hqAgent").value === "decide" && pl2.doc.getElementById("hqToolWrap").hidden === true &&
    pl2.doc.getElementById("hqPlanExtras").hidden === false && pl2.doc.getElementById("hqCommandLabel").textContent === "The goal");
  typeIn(pl2, "Open a second shop");
  pl2.doc.getElementById("hqHorizon").value = "60 days";
  const ccBefore = ccReads(pl2);
  sendBtn(pl2).click(); await settle();
  const pp = posts(pl2);
  check("H11. one POST /api/agents/executive/plan with the goal and the horizon (empty constraints left out)",
    pp.length === 1 && /\/api\/agents\/executive\/plan$/.test(pp[0].url) && JSON.stringify(pp[0].body) === JSON.stringify({ goal: "Open a second shop", horizon: "60 days" }), JSON.stringify(pp));
  const newPlan = pl2.doc.querySelector("[data-hq-plan='" + PLAN_NEW + "']");
  check("H11. the plan's assignments are on the board at once, and the Command Center is read again",
    // NAMED (Oct 30 2026, the command deck): was "…one at a time, under Plan runner."; the board is the Plans tab, linked #plans.
    said(pl2) === "Plan ready. 2 assignments, 1 of them can run from here, one at a time, on the Plans tab. See the plan" && !!newPlan &&
    !!pl2.doc.querySelector("#hqCommandMsg a[href='#plans']") &&
    newPlan.querySelector(".hq-progress").textContent === "0 of 2 done · 0 failed · 2 waiting" && ccReads(pl2) === ccBefore + 1, said(pl2));

  console.log("\n══ H12. the plan runner: one assignment per click ══");
  const CHAIN_ON = { env: { ENABLE_AGENT_CHAINING: "true" } };
  const rn = await mountHQ({ server: server(null, CHAIN_ON), api: ACT_OK, holdAct: true });
  const planEl = (m, id) => m.doc.querySelector("[data-hq-plan='" + id + "']");
  const cardsOf = (m, id) => [...planEl(m, id).querySelectorAll(".hq-acard")].map(li => [li.getAttribute("data-assignment"), li.closest("[data-col]").getAttribute("data-col"), li.querySelector(".hq-astatus").textContent]);
  check("H12. the board lists each plan from the Command Center, newest first",
    JSON.stringify([...rn.doc.querySelectorAll("[data-hq-plan]")].map(p => p.getAttribute("data-hq-plan"))) === JSON.stringify([PLAN_B, PLAN_A]));
  check("H12. each assignment's status from its dispatch and the run's own ai_tasks status, in Ready, Running and Done",
    JSON.stringify(cardsOf(rn, PLAN_A)) === JSON.stringify([["5", "ready", "Ready"], ["1", "done", "Completed"], ["2", "done", "Completed"], ["3", "done", "Completed"], ["4", "done", "Failed"]]) &&
    JSON.stringify(cardsOf(rn, PLAN_B)) === JSON.stringify([["2", "ready", "Not dispatchable"], ["3", "ready", "Refused: running plans is switched off on the server"], ["4", "ready", "Ready"], ["1", "running", "Running"]]),
    JSON.stringify([cardsOf(rn, PLAN_A), cardsOf(rn, PLAN_B)]));
  check("H12. the progress line: \"3 of 5 done · 1 failed · 1 waiting\" and \"0 of 4 done · 0 failed · 1 running · 3 waiting\"",
    planEl(rn, PLAN_A).querySelector(".hq-progress").textContent === "3 of 5 done · 1 failed · 1 waiting" &&
    planEl(rn, PLAN_B).querySelector(".hq-progress").textContent === "0 of 4 done · 0 failed · 1 running · 3 waiting",
    planEl(rn, PLAN_A).querySelector(".hq-progress").textContent + " | " + planEl(rn, PLAN_B).querySelector(".hq-progress").textContent);
  const P = rn.w.BFHeadquarters.progressOf;
  check("H12. ...and its maths at the edges: no assignments, and a lone not-dispatchable one",
    P({ assignments: [] }) === "0 of 0 done · 0 failed · 0 waiting" && P({ assignments: [{ id: 1, is_dispatchable: false }] }) === "0 of 1 done · 0 failed · 1 waiting");
  const blockedLink = planEl(rn, PLAN_B).querySelector("[data-assignment='2'] a");
  /* NAMED BEFORE → AFTER (Oct 30 2026, the command deck). BEFORE: a done assignment linked to run.html. AFTER: it has
     a "View result" button that opens the deck's result drawer (window.BFExecDeck.openRun), and run.html where no
     deck is loaded, as here; a running one still links to its run. */
  const viewBtn = planEl(rn, PLAN_A).querySelector("[data-assignment='1'] [data-hq-view='" + T(1) + "']");
  const wentBefore = rn.went.length;
  if (viewBtn) { viewBtn.click(); await settle(); }
  check("H12. a not-dispatchable assignment links to its agent's page; a done one has \"View result\", which opens its run",
    !!blockedLink && blockedLink.getAttribute("href") === "/store-agent.html" && blockedLink.textContent === "Open the Store Agent page" &&
    !!viewBtn && viewBtn.textContent === "View result" && rn.went.slice(wentBefore).join() === "/run.html?id=" + T(1) &&
    !planEl(rn, PLAN_A).querySelector("[data-assignment='1'] a[href='/run.html?id=" + T(1) + "']"), rn.went.slice(wentBefore).join());
  const runA = planEl(rn, PLAN_A).querySelector("[data-hq-run-next]");
  check("H12. \"Run next\" names the next ready assignment (a refused one is ready again)",
    runA.getAttribute("aria-label") === "Run next: assignment 5, Ads Agent · copy" && !runA.disabled &&
    planEl(rn, PLAN_B).querySelector("[data-hq-run-next]").getAttribute("aria-label") === "Run next: assignment 3, R&D Agent · brief");
  runA.click(); runA.click(); await settle();
  const dd = posts(rn);
  check("H12. one click, one POST /api/assignments/dispatch for that plan and assignment; a double click is still one",
    dd.length === 1 && /\/api\/assignments\/dispatch$/.test(dd[0].url) && JSON.stringify(dd[0].body) === JSON.stringify({ executive_task_id: PLAN_A, assignment_id: 5 }) &&
    runA.disabled && runA.textContent === "Running…", JSON.stringify(dd));
  const ccAt = ccReads(rn);
  dd[0].release(); await settle();
  for (let i = 0; i < 3; i++) await rn.fire();
  check("H12. after the answer nothing dispatches by itself; the plan says what started; the Command Center is read again",
    posts(rn).length === 1 && planEl(rn, PLAN_A).querySelector(".hq-plan-msg").textContent === "Started. Ads Agent · copy (assignment 5). Follow the run" &&
    !!planEl(rn, PLAN_A).querySelector(".hq-plan-msg a[href='/run.html?id=" + T(98) + "']") && ccReads(rn) > ccAt,
    posts(rn).length + " " + planEl(rn, PLAN_A).querySelector(".hq-plan-msg").textContent);
  const offRuns = [...hq.doc.querySelectorAll("[data-hq-run-next]")];
  check("H12. chaining off on the server: every \"Run next\" is disabled, beside \"Running plans is switched off on the server\"",
    offRuns.length === 2 && offRuns.every(b => b.disabled && b.parentNode.textContent.indexOf("Running plans is switched off on the server") !== -1));
  offRuns[0].click(); await settle();
  check("H12. ...and a press sends nothing", !hq.calls.some(c => /assignments\/dispatch/.test(c.url)));
  const ds = server(null, CHAIN_ON);
  const others = await ds.dispatch(USER, { executive_task_id: PLAN_OTHER, assignment_id: 1 });
  check("H12. the server's own dispatch route refuses another member's plan: plan_not_found, nothing written",
    others.code === 200 && others.body && others.body.ok === false && others.body.refused_reason === "plan_not_found" && ds.db.writes.length === 0, JSON.stringify(others.body));
  const offSrv = server();
  const offD = await offSrv.dispatch(USER, { executive_task_id: PLAN_B, assignment_id: 4 });
  const ccOff = (await offSrv.center(USER)).body, ccOn = (await ds.center(USER)).body;
  check("H12. ...with chaining off it refuses chaining_disabled; the Command Center says chaining_on false, and true when it is on",
    offD.body && offD.body.ok === false && offD.body.refused_reason === "chaining_disabled" && ccOff.chaining_on === false && ccOn.chaining_on === true,
    JSON.stringify([offD.body, ccOff.chaining_on, ccOn.chaining_on]));

  console.log("\n══ H13. refusals, by name ══");
  const capMsg = ds.capError(250, 250, "/api/ai/tasks").message, ceilMsg = ds.ceilingError(25, 25.5, "/api/ai/tasks").message;
  const refuse = async reply => {
    const m = await mountHQ({ api: (method, u) => (method === "POST" && /\/api\/ai\/tasks$/.test(u) ? reply : null) });
    await pickAgent(m, "content", "");
    typeIn(m, "Write the launch outline");
    sendBtn(m).click(); await settle();
    const a = m.doc.querySelector("#hqCommandMsg a");
    return { text: said(m), link: a ? a.getAttribute("href") : null, pulse: sendBtn(m).classList.contains("is-sent"), cls: m.doc.getElementById("hqCommandMsg").className, posts: posts(m).length };
  };
  const r402 = await refuse({ status: 402, body: { error: "Active subscription required", upgrade_required: true, reason: "inactive", message: "Running agents needs an active subscription.", billing_url: "/billing.html" } });
  const rCeil = await refuse({ status: 429, body: { error: ceilMsg, request_id: "r1" } });
  const rCap = await refuse({ status: 429, body: { error: capMsg, request_id: "r2" } });
  const rRate = await refuse({ status: 429, body: "Too many requests, please try again later." });
  check("H13. a 402: \"Subscription required\", the server's words, and the Billing link",
    r402.text === "Subscription required. Running agents needs an active subscription. Open Billing" && r402.link === "/billing.html" && /is-refusal/.test(r402.cls), JSON.stringify(r402));
  check("H13. a 429 PLATFORM_DAILY_SPEND_LIMIT: by name, in the server's own words, with no dollar figure",
    /^BizForce has reached today's AI usage limit/.test(ceilMsg) && rCeil.text === "The platform's daily AI limit is reached. " + ceilMsg && !/\$/.test(rCeil.text), rCeil.text);
  check("H13. a 429 from the daily cap: by name, in the server's own words, linked to today's count",
    /^Daily model-call limit reached/.test(capMsg) && rCap.text === "Your daily model-call cap is reached. " + capMsg + " See today's count" && rCap.link === "#command", rCap.text);   // NAMED (Oct 30 2026): was #hqAlerts; the count is on the Command tab's alerts strip
  check("H13. a 429 from the per-minute limit: by name", rRate.text === "Too many requests. More than 20 AI requests in a minute. Wait a minute, then press it again.", rRate.text);
  check("H13. each: one request, and no send pulse", [r402, rCeil, rCap, rRate].every(r => r.posts === 1 && !r.pulse), JSON.stringify([r402, rCeil, rCap, rRate].map(r => [r.posts, r.pulse])));
  const dispatchSaid = async reply => {
    const m = await mountHQ({ server: server(null, CHAIN_ON), api: (method, u) => (/assignments\/dispatch$/.test(u) ? reply : null) });
    planEl(m, PLAN_A).querySelector("[data-hq-run-next]").click(); await settle();
    const msg = planEl(m, PLAN_A).querySelector(".hq-plan-msg");
    const a = msg.querySelector("a");
    return { text: msg.textContent, link: a ? a.getAttribute("href") : null };
  };
  const dNot = await dispatchSaid({ status: 200, body: { ok: false, status: null, refused_reason: "not_entitled", detail: "getUserPlan says this account is not active.", chain_id: null, result: null, recorded: true } });
  const dOff = await dispatchSaid({ status: 200, body: { ok: false, status: null, refused_reason: "chaining_disabled", detail: "ENABLE_AGENT_CHAINING is not exactly \"true\"; no chain may dispatch.", chain_id: null, result: null, recorded: true } });
  const dCap = await dispatchSaid({ status: 200, body: { ok: false, status: 429, refused_reason: null, detail: capMsg, chain_id: "c", result: { error: capMsg }, recorded: true } });
  const d402 = await dispatchSaid({ status: 402, body: { error: "Active subscription required", message: "Running plans needs an active subscription.", billing_url: "/billing.html" } });
  check("H13. a dispatch refused not_entitled: \"Not entitled\", with the Billing link",
    dNot.text === "Not entitled. The server says this account is not entitled to run it. Open Billing" && dNot.link === "/billing.html", dNot.text);
  check("H13. a dispatch refused chaining_disabled: \"Running plans is switched off on the server\"",
    dOff.text === "Running plans is switched off on the server. ENABLE_AGENT_CHAINING is not on, so nothing was dispatched.", dOff.text);
  check("H13. a dispatched tool that met the daily cap: by name", dCap.text === "Your daily model-call cap is reached. " + capMsg + " See today's count", dCap.text);
  check("H13. a 402 on a dispatch: \"Subscription required\"", d402.text === "Subscription required. Running plans needs an active subscription. Open Billing", d402.text);

  console.log("\n══ H14. voice fills the box, and only that ══");
  check("H14. no speech service in the browser: no Speak button, no note, no error",
    hq.doc.getElementById("hqMic").hidden === true && hq.doc.getElementById("hqMicNote").hidden === true && !hq.err);
  class FakeSR { constructor() { FakeSR.made.push(this); this.started = 0; } start() { this.started += 1; } stop() { if (this.onend) this.onend(); } }
  FakeSR.made = [];
  const vc = await mountHQ({ speech: FakeSR, api: ACT_OK });
  const mic = vc.doc.getElementById("hqMic");
  check("H14. with one: the Speak button, and the one line under it",
    mic.hidden === false && vc.doc.getElementById("hqMicNote").hidden === false &&
    vc.doc.getElementById("hqMicNote").textContent === "Voice only fills the box, through your browser's own speech service; BizForce records and stores nothing, and nothing is sent until you press Send.");
  mic.click(); await settle();
  const rec = FakeSR.made[0];
  check("H14. pressed: the browser's own recogniser starts, and the button says it is listening",
    FakeSR.made.length === 1 && rec.started === 1 && mic.getAttribute("aria-pressed") === "true" && mic.textContent === "Listening… press to stop");
  rec.onresult({ resultIndex: 0, results: [[{ transcript: "plan a spring sale" }]] });
  rec.onend(); await settle();
  for (let i = 0; i < 2; i++) await vc.fire();
  check("H14. what it heard fills the box, and nothing is sent", vc.doc.getElementById("hqCommand").value === "plan a spring sale" && posts(vc).length === 0 &&
    mic.getAttribute("aria-pressed") === "false" && mic.textContent === "Speak", JSON.stringify(posts(vc)));
  sendBtn(vc).click(); await settle();
  check("H14. it goes only when Send is pressed", posts(vc).length === 1 && JSON.stringify(posts(vc)[0].body) === JSON.stringify({ goal: "plan a spring sale" }), JSON.stringify(posts(vc)));
  check("H14. Headquarters stores nothing of it: no storage write anywhere in the script", !/localStorage\.setItem|sessionStorage|indexedDB/.test(FILES[HQ]));

  console.log("\n══ H15. the controls beside each tile ══");
  const ct = await mountHQ({ api: ACT_OK });
  const cardOf = (m, t) => m.doc.querySelector("[data-hq-card='" + t + "']");
  const ctls = (m, t) => [...cardOf(m, t).querySelectorAll("[data-hq-ctl]")].map(b => [b.getAttribute("data-hq-ctl"), b.textContent, b.getAttribute("aria-pressed")]);
  check("H15. each card: \"Automatic\" from /live's autonomy, and Pause or Resume only where a schedule exists",
    JSON.stringify(ctls(ct, "email")) === JSON.stringify([["autonomy", "Automatic: On", "true"], ["pause", "Pause schedule", null]]) &&
    JSON.stringify(ctls(ct, "operations")) === JSON.stringify([["autonomy", "Automatic: On", "true"], ["resume", "Resume schedule", null]]) &&
    JSON.stringify(ctls(ct, "seo")) === JSON.stringify([["autonomy", "Automatic: Off", "false"]]), JSON.stringify([ctls(ct, "email"), ctls(ct, "operations"), ctls(ct, "seo")]));
  check("H15. \"Automatic\" says what it does: \"Lets background passes act for this agent (schedules, store proposals, self-review)\"",
    cardOf(ct, "email").querySelector("[data-hq-ctl='autonomy']").getAttribute("title") === "Lets background passes act for this agent (schedules, store proposals, self-review)" &&
    /^Automatic: lets background passes act for this agent \(schedules, store proposals, self-review\)\./.test(ct.doc.getElementById("hqAutoNote").textContent));
  check("H15. the controls sit beside the tile's button, never inside it", !ct.doc.querySelector(".hq-tile [data-hq-ctl]") && !!cardOf(ct, "email").querySelector(".hq-tile + .hq-controls"));
  const live0 = ct.liveCalls();
  cardOf(ct, "email").querySelector("[data-hq-ctl='autonomy']").click(); await settle();
  const autoSaid = cardOf(ct, "email").querySelector(".hq-ctl-msg").textContent;
  cardOf(ct, "operations").querySelector("[data-hq-ctl='resume']").click(); await settle();
  cardOf(ct, "email").querySelector("[data-hq-ctl='pause']").click(); await settle();
  const cp = posts(ct).map(c => [c.method, c.url.replace(/^https?:\/\/[^/]+/, ""), c.body]);
  check("H15. each press: one call to the existing route, and the tile is not opened",
    JSON.stringify(cp) === JSON.stringify([["PUT", "/api/agent-autonomy", { agent_type: "email", enabled: false }], ["PUT", "/api/agent-schedules/operations/resume", null], ["PUT", "/api/agent-schedules/email/pause", null]]) &&
    ct.went.length === 0, JSON.stringify([cp, ct.went]));
  check("H15. each confirmed inline, and /live read again so the tile follows the server",
    autoSaid === "Automatic is now off." && cardOf(ct, "operations").querySelector(".hq-ctl-msg").textContent === "Schedule resumed." &&
    cardOf(ct, "email").querySelector(".hq-ctl-msg").textContent === "Schedule paused." && ct.liveCalls() === live0 + 3, autoSaid + " | " + ct.liveCalls() + " vs " + live0);
  cardOf(ct, "seo").querySelector(".hq-tile").click();
  check("H15. the tile itself still opens its page", ct.went.length === 1 && ct.went[0] === "/agents/seo.html", JSON.stringify(ct.went));

  console.log("\n══ H16. the agent page opens the tool it was sent to, and runs nothing ══");
  const CONFIG = (/<script>\s*(window\.AGENT_PROFILE_CONFIG = [\s\S]*?)<\/script>/.exec(FILES[EMAIL_PAGE]) || [])[1];
  async function mountAgentPage(hash) {
    const dom = new JSDOM(FILES[EMAIL_PAGE].replace(/<script[\s\S]*?<\/script>/g, ""), { url: "https://bizforceai.com/" + EMAIL_PAGE + hash, runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window;
    timersFor(w);
    w.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {} });
    w.localStorage.setItem("bf_token", "check-token");
    const calls = [];
    w.fetch = (url, init) => {
      calls.push({ url: String(url), method: (init && init.method) || "GET" });
      const p = Promise.resolve({ ok: true, status: 200, json: async () => ({}), text: async () => "{}" });
      p.catch(() => {});
      return p;
    };
    let err = null;
    try {
      w.eval(CONFIG);
      w.eval(FILES[AP]);
      if (w.document.readyState !== "loading" && !w.document.getElementById("apLive")) w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
    } catch (e) { err = e; }
    await settle();
    return { w, doc: w.document, calls, err };
  }
  const cfgBox = {};
  vm.runInNewContext("var window = {};\n" + CONFIG + "\nthis.cfg = window.AGENT_PROFILE_CONFIG;", cfgBox);
  const seqTool = ((cfgBox.cfg && cfgBox.cfg.tools) || []).find(t => t.id === "sequence");
  const firstText = seqTool && (seqTool.fields || []).find(f => f.type === "textarea" || f.type === "text" || !f.type);
  const domId = (tid, suf) => "apTool_" + tid.replace(/[^A-Za-z0-9]/g, "_") + "_" + suf;
  const ap = await mountAgentPage("#tool=sequence&prefill=Welcome%20series");
  const seqBody = ap.doc.getElementById(domId("sequence", "body"));
  const seqField = firstText && ap.doc.getElementById(domId("sequence", "f_" + firstText.name));
  check("H16. email-agent.html#tool=sequence&prefill=…: the tool's section opens, its first text field holds the words",
    !ap.err && !!seqBody && seqBody.hidden === false && !!seqField && seqField.value === "Welcome series",
    ap.err ? ap.err.stack : [!!seqBody, seqBody && seqBody.hidden, firstText && firstText.name, seqField && seqField.value].join(" "));
  check("H16. ...and nothing runs: every request it makes is a read", ap.calls.every(c => c.method === "GET"), JSON.stringify(ap.calls.filter(c => c.method !== "GET")));
  const plainPage = await mountAgentPage("");
  check("H16. without the hash the section stays closed", !!plainPage.doc.getElementById(domId("sequence", "body")) && plainPage.doc.getElementById(domId("sequence", "body")).hidden === true);

  console.log("\n══ H9 (act side). keyboard and aria ══");
  check("H9. the console: every field labelled, chips and Speak say their state, answers in a polite live region, regions labelled",
    ["hqAgent", "hqTool", "hqCommand", "hqHorizon", "hqConstraints"].every(id => !!hq.doc.getElementById(id).closest("label")) &&
    [...hq.doc.querySelectorAll("[data-hq-chip]")].every(c => c.tagName === "BUTTON" && c.type === "button" && /^(true|false)$/.test(c.getAttribute("aria-pressed"))) &&
    hq.doc.querySelectorAll("[data-hq-chip][aria-pressed='true']").length === 1 &&
    hq.doc.getElementById("hqCommandMsg").getAttribute("role") === "status" && hq.doc.getElementById("hqCommandMsg").getAttribute("aria-live") === "polite" &&
    hq.doc.getElementById("hqMic").getAttribute("aria-pressed") === "false" && hq.doc.getElementById("hqPlans").getAttribute("aria-labelledby") === "hqPlansTitle" &&
    hq.doc.getElementById("hqConsole").getAttribute("aria-labelledby") === "hqConsoleTitle");
  hq.doc.querySelector("[data-hq-chip='seo']").click(); await settle();
  check("H9. a chip is a button that picks its agent, and says so", hq.doc.getElementById("hqAgent").value === "seo" &&
    hq.doc.querySelector("[data-hq-chip='seo']").getAttribute("aria-pressed") === "true" && hq.doc.querySelectorAll("[data-hq-chip][aria-pressed='true']").length === 1);
  check("H9. card controls are labelled groups of buttons; plan columns are labelled lists; every answer is a status region",
    [...hq.doc.querySelectorAll(".hq-controls")].every(g => g.getAttribute("role") === "group" && / controls$/.test(g.getAttribute("aria-label"))) &&
    [...hq.doc.querySelectorAll("[data-hq-ctl]")].every(b => b.tagName === "BUTTON" && b.type === "button") &&
    [...hq.doc.querySelectorAll(".hq-acards")].every(u => /^(Ready|Running|Done)$/.test(u.getAttribute("aria-label"))) &&
    [...hq.doc.querySelectorAll(".hq-plan-msg, .hq-ctl-msg")].every(m => m.getAttribute("role") === "status") &&
    [...hq.doc.querySelectorAll("[data-hq-run-next]")].every(b => /^Run next: /.test(b.getAttribute("aria-label"))));
  check("H9. phones: the console's fields and the plan columns stack", /@media \(max-width: 640px\) \{[\s\S]*?\.hq-console-row \{ grid-template-columns: 1fr; gap: 0; \}[\s\S]*?\.hq-cols \{ grid-template-columns: 1fr; \}/.test(css));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
