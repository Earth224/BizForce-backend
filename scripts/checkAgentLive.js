"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkAgentLive — the live activity engine and the panel on every agent page
   say only what the member's own rows say.

   Backend "Live activity for every agent, from real data only" added
   lib/agentLive.js and GET /api/agents/live and /api/agents/:type/live
   (agentLiveBody in server.js); frontend "A live panel on every agent page;
   the mist remembers its place" added the panel to scripts/agent-profile.js.

     L1  the lib: running only while 'processing' and under 10 minutes,
         stalled after; dry_run never activity; next across daily, weekly and
         monthly (day 31 in February clamps to the 28th), and null with its
         reason when disabled, paused, the scheduler is off, autonomy is off,
         or the subscription is inactive or unknown;
     L2  the routes as server.js wires them, against an in-memory database
         that applies every filter: registered before /api/agents/:type,
         login only, every query scoped to the caller, another member's rows
         never returned, no model call;
     L3  a read that fails, or a count that comes back null, is
         { unavailable }, never 0, and fails only its own field;
     L4  the payload: at most 3 KB for one agent and 24 KB for all 18 on a
         worst-case account, lists capped at 5;
     L5  the panel, run in jsdom on all 18 pages with the route's own answers:
         placed under the header, six cells, the empty states in their exact
         words, the links, an empty signature slot;
     L6  polling: 60 s idle, 15 s while running, stopped while hidden and
         fetched again on show, stopped offline, 2× backoff on 429 and 5xx up
         to 5 minutes, reset by a good answer; /live is not a saved offline
         read; prefers-reduced-motion stops every animation.

   No network (fetch is stubbed), no live database rows: the database is a
   fake held in memory.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const SERVER = "server.js", LIB = "lib/agentLive.js", PROFILE = "scripts/agent-profile.js", OFFLINE = "scripts/bf-offline.js";

const MUTATIONS = {
  // the running-tasks read loses its owner filter, so another member's run shows (L2)
  "other-member-row": [[SERVER, '      .eq("user_id", userId)\n      .eq("status", "processing"))', '      .eq("status", "processing"))']],
  // a ratings read that failed answers as zero (L3)
  "failed-read-as-zero": [[LIB, "  if (unavailable(reads.feedback)) out.score = unavailableOf(reads.feedback);", "  if (unavailable(reads.feedback)) out.score = { up: 0, down: 0, pinned: 0 };"]],
  // dry runs are counted as runs, in the read and in the lib (L1, L2)
  "dry-run-counted": [[SERVER, '        .neq("status", "dry_run")\n        .gte("created_at", weekAgo))', '        .gte("created_at", weekAgo))'],
    [LIB, 'return r && r.agent_type === type && r.status !== "dry_run";', "return r && r.agent_type === type;"]],
  // a 'processing' row older than 10 minutes still says running (L1)
  "running-after-10-min": [[LIB, '  return { state: fresh.length ? "running" : "stalled",', '  return { state: "running",']],
  // the panel keeps polling while the tab is hidden (L6)
  "polling-while-hidden": [[PROFILE, '      if (document.hidden) liveStop("hidden");\n      else liveFetch();\n', "      liveFetch();\n"],
    [PROFILE, '    if (document.hidden) { liveStop("hidden"); return; }\n    if (liveOffline())', "    if (liveOffline())"]],
  // /live becomes a saved offline read, so an old copy can answer as live (L6)
  "live-in-saved-reads": [[OFFLINE, "  var SAVED_READS = [\n", '  var SAVED_READS = [\n    { path: /^\\/api\\/agents\\/[a-z_]+\\/live$/, what: "live activity" },\n']],
  // the agent pattern loses its exclusion, so /api/agents/live is saved as if it were an agent (L6)
  "live-all-saved": [[OFFLINE, "agents\\/(?!live$)[a-z_]+$/", "agents\\/[a-z_]+$/"]],
  // the daily-call count is trusted when it comes back null (L3)
  "null-count-trusted": [[SERVER, '    if (typeof counted.count !== "number") throw new Error("model calls today: the count did not come back");\n', ""]],
  // the scheduler switch is ignored, so a next run is promised that will not happen (L1)
  "scheduler-ignored": [[LIB, '  if (opts.schedulerOn !== true) return { next: null, reason: "scheduler_off" };\n', ""]],
  // autonomy off is ignored, though the runner skips that agent (L1)
  "autonomy-ignored": [[LIB, '  if (opts.autonomy !== true) return { next: null, reason: "autonomy_off" };\n', ""]],
  // a run in progress no longer speeds polling up (L6)
  "no-busy-interval": [[PROFILE, '        live.base = data.agent.now && data.agent.now.state === "running" ? LIVE_BUSY_MS : LIVE_IDLE_MS;\n', "        live.base = LIVE_IDLE_MS;\n"]],
  // a 5xx is retried at the normal interval, without backing off (L6)
  "no-backoff": [[PROFILE, "    var wait = Math.min(LIVE_MAX_BACKOFF_MS, live.base * Math.pow(2, live.failures));\n", "    var wait = live.base;\n"]],
  // the live routes are registered after /api/agents/:type, which swallows /api/agents/live (L2)
  "route-after-type": [[SERVER, 'app.get("/api/agents/live", requireAuth, async function (req, res, next) {', 'app.get("/api/agents/:type", requireAuth, async function (req, res, next) {\n});\napp.get("/api/agents/live", requireAuth, async function (req, res, next) {']]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[SERVER, LIB].forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
[PROFILE, OFFLINE].forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.log("    FAIL  frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});

if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* ── the lib, compiled from the (possibly mutated) source ── */
function compileLib() {
  const file = path.join(REPO, LIB);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(FILES[LIB], file);
  return m.exports;
}
let LIVE;
try { LIVE = compileLib(); } catch (e) { console.log("    FAIL  lib/agentLive.js did not load: " + e.message); process.exit(1); }

/* ── the routes and what they call, lifted from server.js ── */
const SRC = FILES[SERVER];
function defOf(name) {
  const d = s.definitionOf(SRC, name);
  if (!d) { console.log("    FAIL  server.js has no definition of " + name); process.exit(1); }
  return d;
}
function routeOf(sig) {
  const at = SRC.indexOf(sig);
  if (at === -1) return null;
  const open = SRC.indexOf("async function (req, res, next) {", at) + "async function (req, res, next) ".length;
  const end = s.braceMatch(SRC, open);
  return SRC.slice(at, end) + ");";
}
const LIVE_ALL = 'app.get("/api/agents/live", requireAuth, async function (req, res, next) {';
const LIVE_ONE = 'app.get("/api/agents/:type/live", requireAuth, async function (req, res, next) {';
const TYPE_ROUTE = 'app.get("/api/agents/:type", requireAuth, async function (req, res, next) {';
const DEFS = ["agentLiveBody", "commandCenterRead", "commandCenterAllRows", "COMMAND_CENTER_PAGE", "AGENT_SCHEDULE_FIELDS",
  "AGENT_SCHEDULE_CARD_FIELDS", "agentScheduleIsDue", "agentScheduleUtcDay", "agentScheduleDaysInUtcMonth",
  "agentScheduleEffectiveMonthDay", "modelCallCostUsd", "MODEL_PRICES_USD_PER_MILLION", "modelSpendMonth",
  "modelCallUtcDay", "modelCallDailyLimit", "MODEL_CALL_DAILY_LIMIT_DEFAULT"];
const ROUTE_SRC = [routeOf(LIVE_ALL), routeOf(LIVE_ONE)];
const LIFTED = DEFS.map(defOf).join("\n\n") + "\n\n" + ROUTE_SRC.filter(Boolean).join("\n\n");
let LIFTED_SCRIPT;
try { LIFTED_SCRIPT = new vm.Script(LIFTED, { filename: "agentLive-lifted.js" }); }
catch (e) { console.log("    FAIL  the lifted routes did not compile: " + e.message); process.exit(1); }

/* ── an in-memory database that applies every filter it is given ── */
function fakeDb(tables, opts) {
  opts = opts || {};
  const log = [];
  function query(table) {
    const q = { table, filters: [], orderBy: [], lim: null, rng: null, cols: "*", count: null, head: false };
    log.push(q);
    const rowsOf = () => (tables[table] || []).filter(r => q.filters.every(([op, c, v]) => {
      const x = r[c];
      if (op === "eq") return x === v;
      if (op === "neq") return x !== v;
      if (op === "in") return v.indexOf(x) !== -1;
      if (op === "gte") return x >= v;
      if (op === "lt") return x < v;
      if (op === "is") return x === v;
      return false;
    }));
    const api = {
      select(cols, o) { q.cols = cols; if (o && o.count) q.count = o.count; if (o && o.head) q.head = true; return api; },
      eq(c, v) { q.filters.push(["eq", c, v]); return api; },
      neq(c, v) { q.filters.push(["neq", c, v]); return api; },
      in(c, v) { q.filters.push(["in", c, v]); return api; },
      gte(c, v) { q.filters.push(["gte", c, v]); return api; },
      lt(c, v) { q.filters.push(["lt", c, v]); return api; },
      is(c, v) { q.filters.push(["is", c, v]); return api; },
      order(c, o) { q.orderBy.push([c, !o || o.ascending !== false]); return api; },
      limit(n) { q.lim = n; return api; },
      range(a, b) { q.rng = [a, b]; return api; },
      then(resolve, reject) {
        let out;
        if ((opts.fail || []).indexOf(table) !== -1) out = { data: null, count: null, error: { message: table + " is down in this check" } };
        else {
          let rows = rowsOf().slice();
          for (let i = q.orderBy.length - 1; i >= 0; i--) {
            const [c, asc] = q.orderBy[i];
            rows.sort((a, b) => (a[c] < b[c] ? -1 : a[c] > b[c] ? 1 : 0) * (asc ? 1 : -1));
          }
          const total = rows.length;
          if (q.rng) rows = rows.slice(q.rng[0], q.rng[1] + 1);
          if (q.lim !== null) rows = rows.slice(0, q.lim);
          const nullCount = (opts.nullCount || []).indexOf(table) !== -1;
          out = { data: q.head ? null : JSON.parse(JSON.stringify(rows)), count: q.count ? (nullCount ? null : total) : null, error: null };
        }
        return Promise.resolve(out).then(resolve, reject);
      }
    };
    return api;
  }
  return { client: { from: query }, log };
}

/* ── a fixed clock for the vm ── */
const NOW = Date.parse("2026-10-29T10:20:00.000Z");   // a Thursday
function fixedDate(ms) {
  const Real = Date;
  function D(...a) { if (!(this instanceof D)) return new Real(ms).toString(); return a.length ? new Real(...a) : new Real(ms); }
  D.prototype = Real.prototype;
  D.now = () => ms; D.parse = Real.parse; D.UTC = Real.UTC;
  return D;
}

/* ── run the lifted routes ── */
function harness(tables, o) {
  o = o || {};
  const db = fakeDb(tables, o);
  const routes = {}, modelCalls = [];
  const libForVm = LIVE;
  const ctx = {
    supabase: db.client,
    console: { log() {}, error() {}, warn() {} },
    process: { env: Object.assign({ ENABLE_AGENT_SCHEDULES: "true" }, o.env || {}) },
    Date: fixedDate(o.now || NOW),
    getUserPlan: async () => { if (o.planThrows) throw new Error("plan read failed"); return o.plan === undefined ? { active: true } : o.plan; },
    require: name => (name === "./lib/agentLive" ? libForVm : require(path.join(REPO, name))),
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {},
    callAnthropicText: async () => { modelCalls.push(1); throw new Error("no model call is allowed here"); },
    app: { get(p, ...h) { routes[p] = { handler: h[h.length - 1], gates: h.slice(0, -1).map(f => f && f.name) }; } },
    JSON, Object, Array, String, Number, Math, Promise, Error, isNaN
  };
  vm.createContext(ctx);
  LIFTED_SCRIPT.runInContext(ctx);
  async function call(p, params, user) {
    const r = routes[p];
    if (!r) return { status: 0, body: null, err: new Error("route " + p + " not registered") };
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    let err = null;
    await r.handler({ user: user || { id: U1 }, params: params || {} }, res, e => { err = e || new Error("next"); });
    return { status: res.statusCode, body: res.body, err };
  }
  return { call, routes, db, modelCalls };
}

/* ── the fixture ── */
const U1 = "11111111-1111-4111-8111-111111111111", U2 = "22222222-2222-4222-8222-222222222222", U3 = "33333333-3333-4333-8333-333333333333";
const ago = m => new Date(NOW - m * 60000).toISOString();
const DAY = 1440;
let tid = 0;
const task = (user, agent, status, minutesAgo, extra) => Object.assign({ id: "t" + (++tid), user_id: user, agent_type: agent, task_type: agent + "/tool", status,
  created_at: ago(minutesAgo), completed_at: status === "processing" ? null : ago(minutesAgo - 1), error: status === "failed" ? "The model stopped early." : null }, extra || {});
function fixture() {
  tid = 0;
  const ai_tasks = [
    task(U1, "seo", "processing", 3, { id: "seo-running" }),
    task(U1, "seo", "completed", 2 * DAY),
    task(U1, "seo", "failed", 1 * DAY, { id: "seo-failed-yesterday" }),
    task(U1, "content", "processing", 25, { id: "content-stalled" }),
    task(U1, "sales", "completed", 10 * DAY, { id: "sales-old-completed" }),
    task(U2, "seo", "processing", 1, { id: "OTHER-MEMBER-RUN" }),
    task(U2, "email", "completed", 30, { id: "OTHER-MEMBER-EMAIL" })
  ];
  for (let i = 0; i < 40; i++) ai_tasks.push(task(U1, "sales", "dry_run", 5 + i, { id: "dry-" + i }));
  return {
    ai_tasks,
    agent_proposals: [
      { id: "p1", user_id: U1, agent_type: "seo", title: "Publish the audit fixes", status: "pending", created_at: ago(60) },
      { id: "p2", user_id: U1, agent_type: "seo", title: "Rewrite the homepage title", status: "pending", created_at: ago(30) },
      { id: "p3", user_id: U1, agent_type: "seo", title: "Already decided", status: "approved", created_at: ago(20) },
      { id: "q1", user_id: U2, agent_type: "seo", title: "OTHER MEMBER PROPOSAL", status: "pending", created_at: ago(10) },
      { id: "q2", user_id: U2, agent_type: "seo", title: "OTHER MEMBER PROPOSAL 2", status: "pending", created_at: ago(11) }
    ],
    agent_schedules: [
      { user_id: U1, agent_type: "seo", task_type: "seo/audit", prompt: "x", cadence: "daily", hour_utc: 7, day_of_week: null, day_of_month: null, enabled: true, paused: false, last_run_on: "2026-10-29" },
      { user_id: U1, agent_type: "content", task_type: "content/outline", prompt: "x", cadence: "weekly", hour_utc: 9, day_of_week: 1, day_of_month: null, enabled: true, paused: false, last_run_on: null },
      { user_id: U1, agent_type: "store", task_type: "store/stock-margin", prompt: "x", cadence: "monthly", hour_utc: 6, day_of_week: null, day_of_month: 31, enabled: true, paused: false, last_run_on: null },
      { user_id: U1, agent_type: "operations", task_type: "operations/sop", prompt: "x", cadence: "daily", hour_utc: 8, enabled: true, paused: true, paused_reason: "Paused after 3 failed runs in a row", consecutive_failures: 3 },
      { user_id: U1, agent_type: "email", task_type: "email/sequence", prompt: "x", cadence: "daily", hour_utc: 8, enabled: false, paused: false },
      { user_id: U1, agent_type: "analytics", task_type: "analytics/kpi-review", prompt: "x", cadence: "daily", hour_utc: 8, enabled: true, paused: false },
      { user_id: U2, agent_type: "ads", task_type: "ads/copy", prompt: "x", cadence: "daily", hour_utc: 11, enabled: true, paused: false }
    ],
    agent_autonomy: [
      { user_id: U1, agent_type: "seo", enabled: true }, { user_id: U1, agent_type: "content", enabled: true }, { user_id: U1, agent_type: "store", enabled: true },
      { user_id: U1, agent_type: "operations", enabled: true }, { user_id: U2, agent_type: "analytics", enabled: true }, { user_id: U2, agent_type: "ads", enabled: true }
    ],
    agent_feedback: [
      { id: "f1", user_id: U1, agent_type: "seo", rating: "up", pinned: true }, { id: "f2", user_id: U1, agent_type: "seo", rating: "up", pinned: false },
      { id: "f3", user_id: U1, agent_type: "seo", rating: "down", pinned: false },
      { id: "g1", user_id: U2, agent_type: "seo", rating: "up", pinned: true }, { id: "g2", user_id: U2, agent_type: "seo", rating: "up", pinned: false }
    ],
    model_calls: [
      { id: 1, user_id: U1, agent_type: "seo", model: "claude-haiku-4-5-20251001", input_tokens: 100000, output_tokens: 20000, funded_by: "platform", created_on: "2026-10-29" },
      { id: 2, user_id: U1, agent_type: "seo", model: "claude-haiku-4-5-20251001", input_tokens: 900000, output_tokens: 900000, funded_by: "user", created_on: "2026-10-28" },
      { id: 3, user_id: U1, agent_type: "seo", model: "claude-haiku-4-5-20251001", input_tokens: 50000, output_tokens: 0, funded_by: "platform", created_on: "2026-09-30" },
      { id: 4, user_id: U2, agent_type: "seo", model: "claude-haiku-4-5-20251001", input_tokens: 999999, output_tokens: 999999, funded_by: "platform", created_on: "2026-10-29" }
    ]
  };
}

const AGENT_PAGES = ["ads-agent.html", "broker-agent.html", "community-agent.html", "email-agent.html", "etsy-agent.html", "executive-agent.html",
  "influencer-agent.html", "operations-agent.html", "publicist-agent.html", "rd-agent.html", "reputation-agent.html", "store-agent.html",
  "vertical-marketing-agent.html", "agents/analytics.html", "agents/content.html", "agents/sales.html", "agents/seo.html", "agents/social.html"];

(async function main() {
  console.log("\n══ L1. the lib: now, next, and what is never activity ══");
  {
    const isDueSrc = ["agentScheduleIsDue", "agentScheduleUtcDay", "agentScheduleDaysInUtcMonth", "agentScheduleEffectiveMonthDay"].map(defOf).join("\n\n");
    const box = {}; vm.createContext(box); vm.runInContext(isDueSrc + "\nthis.isDue = agentScheduleIsDue;", box);
    const isDue = box.isDue;
    check("L1. the 18 agents are the roster's, without general, each with its name from config/brain.js",
      LIVE.AGENT_KEYS.length === 18 && LIVE.AGENT_KEYS.indexOf("general") === -1 && LIVE.AGENT_NAMES.seo === "SEO Agent" && LIVE.AGENT_NAMES.etsy === "Storefront Agent",
      LIVE.AGENT_KEYS.join(","));
    const at = m => ({ id: "x", status: "processing", created_at: new Date(NOW - m * 60000).toISOString() });
    check("L1. 'processing' 9 min 59 s old is running; at 10 min it is stalled",
      LIVE.nowState([at(9 + 59 / 60)], NOW).state === "running" && LIVE.nowState([at(10)], NOW).state === "stalled" && LIVE.nowState([], NOW).state === "idle");
    check("L1. a fresh run wins over a stalled one of the same agent", LIVE.nowState([at(30), at(2)], NOW).state === "running");
    const base = { cadence: "daily", hour_utc: 7, enabled: true, paused: false, last_run_on: null, task_type: "seo/audit" };
    const on = { now: new Date(NOW), isDue, schedulerOn: true, autonomy: true, subscriptionActive: true };
    const nx = (row, extra) => LIVE.nextRun(row, Object.assign({}, on, extra || {}));
    check("L1. daily at 07 UTC, asked at 10:20: tomorrow 07:00", nx(base).next && nx(base).next.at === "2026-10-30T07:00:00.000Z", JSON.stringify(nx(base)));
    check("L1. daily at 11 UTC, not yet run today: today 11:00", nx(Object.assign({}, base, { hour_utc: 11 })).next.at === "2026-10-29T11:00:00.000Z");
    check("L1. daily at 11 UTC, already run today: tomorrow 11:00", nx(Object.assign({}, base, { hour_utc: 11, last_run_on: "2026-10-29" })).next.at === "2026-10-30T11:00:00.000Z");
    check("L1. weekly on Monday (1) at 09: Monday 2 November", nx(Object.assign({}, base, { cadence: "weekly", day_of_week: 1, hour_utc: 9 })).next.at === "2026-11-02T09:00:00.000Z");
    check("L1. monthly on the 31st at 06, from 29 October: 31 October", nx(Object.assign({}, base, { cadence: "monthly", day_of_month: 31, hour_utc: 6 })).next.at === "2026-10-31T06:00:00.000Z");
    const feb = LIVE.nextRun(Object.assign({}, base, { cadence: "monthly", day_of_month: 31, hour_utc: 6 }), Object.assign({}, on, { now: new Date("2027-02-10T12:00:00Z") }));
    check("L1. monthly on the 31st, from 10 February 2027: 28 February (the month's last day)", feb.next && feb.next.at === "2027-02-28T06:00:00.000Z", JSON.stringify(feb));
    const why = (row, extra) => nx(row, extra).next === null ? nx(row, extra).reason : "a next run: " + JSON.stringify(nx(row, extra).next);
    check("L1. null with its reason: no schedule, switched off, paused, scheduler off, autonomy off, lapsed, subscription unknown",
      why(null) === "no_schedule" && why(Object.assign({}, base, { enabled: false })) === "disabled" && why(Object.assign({}, base, { paused: true })) === "paused" &&
      why(base, { schedulerOn: false }) === "scheduler_off" && why(base, { autonomy: false }) === "autonomy_off" &&
      why(base, { subscriptionActive: false }) === "subscription_inactive" && why(base, { subscriptionActive: null }) === "subscription_unknown",
      [why(null), why(base, { schedulerOn: false }), why(base, { autonomy: false }), why(base, { subscriptionActive: false })].join(","));
    check("L1. autonomy that could not be read makes next unavailable, not a promise", nx(base, { autonomy: { unavailable: "x" } }).next.unavailable !== undefined);
    check("L1. slots are replayed for 32 days and no further", LIVE.NEXT_HORIZON_HOURS === 768 &&
      nx(Object.assign({}, base, { cadence: "monthly", day_of_month: 0, hour_utc: 6 })).reason === "no_slot_in_32_days");
    const b = LIVE.buildAgent("sales", { processing: { rows: [] }, recent: { rows: [{ id: "d", agent_type: "sales", status: "dry_run", created_at: ago(5) }] },
      last: { rows: [{ id: "d2", agent_type: "sales", status: "dry_run", created_at: ago(9 * DAY) }] }, autonomy: { rows: [] }, schedules: { rows: [] },
      proposals: { rows: [] }, feedback: { rows: [] }, spend: { rows: [] } }, { now: new Date(NOW), isDue, costOf: () => ({ usd: 0 }), schedulerOn: true, subscriptionActive: true });
    check("L1. dry_run rows handed to the lib are still not runs (defence in depth)", b.runs.runs_7d === 0 && b.runs.last === null, JSON.stringify(b.runs));
  }

  console.log("\n══ L2. the routes, against an in-memory database ══");
  const iLiveAll = SRC.indexOf(LIVE_ALL), iLiveOne = SRC.indexOf(LIVE_ONE), iType = SRC.indexOf(TYPE_ROUTE);
  check("L2. both live routes are registered, and before /api/agents/:type (which would swallow /api/agents/live)",
    iLiveAll > 0 && iLiveOne > 0 && iType > 0 && iLiveAll < iType && iLiveOne < iType && SRC.split(TYPE_ROUTE).length === 2, [iLiveAll, iLiveOne, iType].join(" "));
  check("L2. the live code makes no model call and names no model client",
    ROUTE_SRC.concat([defOf("agentLiveBody"), FILES[LIB]]).every(c => c && !/messages\.create|callAnthropicText|anthropic/i.test(c)));
  const h = harness(fixture());
  check("L2. login only: requireAuth, no subscription gate, on both routes",
    ["/api/agents/live", "/api/agents/:type/live"].every(p => h.routes[p] && JSON.stringify(h.routes[p].gates) === JSON.stringify(["requireAuth"])),
    JSON.stringify(Object.keys(h.routes).map(p => [p, h.routes[p].gates])));
  const all = await h.call("/api/agents/live");
  const A = all.body && all.body.agents;
  check("L2. GET /api/agents/live answers all 18 agents", all.status === 200 && A && Object.keys(A).length === 18 && !all.err, all.err && all.err.message);
  if (!A) { console.log("\nCHECKS FAILED: no answer to work with"); process.exit(1); }
  check("L2. every query is scoped to the caller (user_id = the member)",
    h.db.log.length >= 9 && h.db.log.every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === U1)),
    h.db.log.filter(q => !q.filters.some(f => f[1] === "user_id")).map(q => q.table).join(","));
  const blob = JSON.stringify(all.body);
  check("L2. nothing of another member's comes back: no run, proposal, rating, schedule or spend of theirs",
    blob.indexOf("OTHER-MEMBER") === -1 && blob.indexOf("OTHER MEMBER") === -1 && A.seo.score.up === 2 && A.seo.proposals.pending === 2 &&
    A.ads.schedule === null && A.analytics.autonomy === false, blob.slice(0, 200));
  check("L2. SEO is running (its own 3-minute-old run), Content is stalled at 25 minutes, the rest idle",
    A.seo.now.state === "running" && A.seo.now.task_id === "seo-running" && A.content.now.state === "stalled" && A.content.now.task_id === "content-stalled" &&
    A.email.now.state === "idle", JSON.stringify([A.seo.now, A.content.now]));
  check("L2. Sales's 40 dry runs are not activity: 0 runs in 7 days, and its last run is the real one 10 days ago",
    A.sales.runs.runs_7d === 0 && A.sales.runs.failed_7d === 0 && A.sales.runs.last && A.sales.runs.last.task_id === "sales-old-completed", JSON.stringify(A.sales.runs));
  check("L2. SEO: 3 runs in 7 days, 1 failed; the last is the running one", A.seo.runs.runs_7d === 3 && A.seo.runs.failed_7d === 1 && A.seo.runs.last.task_id === "seo-running",
    JSON.stringify(A.seo.runs));
  check("L2. next runs from the runner's rule: SEO tomorrow 07:00, Content Monday 09:00, Store 31 October 06:00",
    A.seo.next.at === "2026-10-30T07:00:00.000Z" && A.content.next.at === "2026-11-02T09:00:00.000Z" && A.store.next.at === "2026-10-31T06:00:00.000Z",
    JSON.stringify([A.seo.next, A.content.next, A.store.next]));
  check("L2. Operations paused (with its reason), Email switched off, Analytics autonomy off, Ads no schedule",
    A.operations.next === null && A.operations.next_reason === "paused" && A.operations.schedule.paused_reason === "Paused after 3 failed runs in a row" &&
    A.email.next_reason === "disabled" && A.analytics.next_reason === "autonomy_off" && A.ads.next_reason === "no_schedule",
    [A.operations.next_reason, A.email.next_reason, A.analytics.next_reason, A.ads.next_reason].join(","));
  const off = await harness(fixture(), { env: { ENABLE_AGENT_SCHEDULES: "yes" } }).call("/api/agents/live");
  check("L2. scheduler off (ENABLE_AGENT_SCHEDULES not exactly \"true\"): scheduler_on false and no agent has a next run",
    off.body.scheduler_on === false && Object.values(off.body.agents).every(a => a.next === null) && off.body.agents.seo.next_reason === "scheduler_off");
  const lapsed = await harness(fixture(), { plan: { active: false } }).call("/api/agents/live");
  check("L2. a lapsed member still gets an answer, told the schedules wait for the subscription",
    lapsed.status === 200 && lapsed.body.subscription_active === false && lapsed.body.agents.seo.next === null && lapsed.body.agents.seo.next_reason === "subscription_inactive");
  const unknown = await harness(fixture(), { planThrows: true }).call("/api/agents/live");
  check("L2. a plan that cannot be read is null, and nothing is promised", unknown.body.subscription_active === null && unknown.body.agents.seo.next_reason === "subscription_unknown");
  const cost = r => { const p = { "claude-haiku-4-5-20251001": null }; return p; };
  const box2 = {}; vm.createContext(box2);
  vm.runInContext(defOf("MODEL_PRICES_USD_PER_MILLION") + "\n" + defOf("modelCallCostUsd") + "\nthis.c = modelCallCostUsd;", box2);
  const expect = Number(box2.c({ model: "claude-haiku-4-5-20251001", input_tokens: 100000, output_tokens: 20000 }).usd.toFixed(4));
  check("L2. spend this month: the platform-funded row only, priced by modelCallCostUsd (the member's own key and last month are left out)",
    A.seo.spend_month_usd === expect && expect > 0 && A.content.spend_month_usd === 0, A.seo.spend_month_usd + " vs " + expect);
  check("L2. the daily cap: this member's calls today against 250", JSON.stringify(all.body.daily_calls) === JSON.stringify({ used: 1, limit: 250 }), JSON.stringify(all.body.daily_calls));
  const one = await h.call("/api/agents/:type/live", { type: "seo" });
  check("L2. GET /api/agents/seo/live answers that agent alone, with proposal ids", one.status === 200 && one.body.agent && one.body.agent.type === "seo" &&
    !one.body.agents && one.body.agent.proposals.newest[0].id === "p2");
  const nope = await h.call("/api/agents/:type/live", { type: "general" });
  check("L2. an agent without a page (general) or an unknown one is a 404, and reads nothing", nope.status === 404);
  check("L2. no model call was made", h.modelCalls.length === 0);

  console.log("\n══ L3. a read that failed is unavailable, never zero ══");
  const broken = await harness(fixture(), { fail: ["agent_feedback", "agent_proposals"] }).call("/api/agents/live");
  const BA = broken.body.agents;
  check("L3. ratings down: every score is { unavailable }, never 0, and the rest still answers",
    Object.values(BA).every(a => a.score && typeof a.score.unavailable === "string") && BA.seo.now.state === "running", JSON.stringify(BA.seo.score));
  check("L3. proposals down: every proposals field is { unavailable }", Object.values(BA).every(a => a.proposals && typeof a.proposals.unavailable === "string"));
  const tasksDown = await harness(fixture(), { fail: ["ai_tasks"] }).call("/api/agents/:type/live", { type: "seo" });
  check("L3. ai_tasks down: now and runs are { unavailable }; schedule and score still answer",
    tasksDown.body.agent.now.unavailable && tasksDown.body.agent.runs.unavailable && tasksDown.body.agent.next.at && tasksDown.body.agent.score.up === 2,
    JSON.stringify(tasksDown.body.agent).slice(0, 200));
  const nullCount = await harness(fixture(), { nullCount: ["model_calls"] }).call("/api/agents/live");
  check("L3. a count that comes back null (a missing table answers 204 with no error) is unavailable, never 0",
    nullCount.body.daily_calls && typeof nullCount.body.daily_calls.unavailable === "string" && nullCount.body.agents.seo.spend_month_usd.unavailable,
    JSON.stringify(nullCount.body.daily_calls));
  const schedDown = await harness(fixture(), { fail: ["agent_schedules", "agent_autonomy"] }).call("/api/agents/live");
  check("L3. schedules down: next is { unavailable } rather than \"No schedule\"", schedDown.body.agents.seo.next.unavailable && schedDown.body.agents.seo.next_reason === null &&
    schedDown.body.agents.seo.autonomy.unavailable);

  console.log("\n══ L4. the payload budget ══");
  {
    const t = fixture();
    LIVE.AGENT_KEYS.forEach(k => {
      for (let i = 0; i < 9; i++) t.agent_proposals.push({ id: k + "-" + i + "-" + "x".repeat(20), user_id: U1, agent_type: k, title: "T".repeat(200), status: "pending", created_at: ago(i) });
      t.ai_tasks.push(task(U1, k, "failed", 2, { task_type: k + "/" + "a-very-long-tool-name", error: "E".repeat(2000) }));
      t.ai_tasks.push(task(U1, k, "processing", 1));
      t.agent_schedules.push({ user_id: U1, agent_type: k, task_type: "x/" + "y".repeat(40), prompt: "p", cadence: "daily", hour_utc: 23, enabled: true, paused: true, paused_reason: "R".repeat(500), consecutive_failures: 9 });
      t.agent_feedback.push({ id: "fb-" + k, user_id: U1, agent_type: k, rating: "up", pinned: true });
    });
    const H = harness(t);
    const big = await H.call("/api/agents/live");
    const allSize = JSON.stringify(big.body).length;
    const sizes = await Promise.all(LIVE.AGENT_KEYS.map(k => H.call("/api/agents/:type/live", { type: k }).then(r => JSON.stringify(r.body).length)));
    check("L4. a worst-case account: all 18 in at most 24 KB (" + allSize + " bytes)", allSize <= 24 * 1024, allSize);
    check("L4. ... and each agent alone in at most 3 KB (largest " + Math.max.apply(null, sizes) + " bytes)", Math.max.apply(null, sizes) <= 3 * 1024, sizes.join(","));
    check("L4. lists are capped at 5, and the count stays true (9 pending, SEO 11)",
      Object.values(big.body.agents).every(a => a.proposals.pending === (a.type === "seo" ? 11 : 9) && a.proposals.newest.length <= 5),
      JSON.stringify(Object.values(big.body.agents).map(a => [a.type, a.proposals.pending, a.proposals.newest && a.proposals.newest.length])));
  }

  console.log("\n══ L5. the panel on all 18 pages ══");
  const empty = await harness(fixture()).call("/api/agents/live", {}, { id: U3 });
  check("L5. a member with nothing yet: every agent idle, no runs, no schedule, nothing waiting, no ratings, $0",
    Object.values(empty.body.agents).every(a => a.now.state === "idle" && a.runs.last === null && a.next === null && a.next_reason === "no_schedule" &&
      a.proposals.pending === 0 && a.score.up === 0 && a.score.down === 0 && a.spend_month_usd === 0));
  const answers = { empty: empty.body, u1: all.body, lapsed: lapsed.body, broken: broken.body, tasksDown: tasksDown.body };
  const one18 = (body, type) => ({ generated_at: body.generated_at, stall_after_min: body.stall_after_min, scheduler_on: body.scheduler_on,
    subscription_active: body.subscription_active, daily_calls: body.daily_calls, agent: body.agent || body.agents[type] });

  const TAIL = '  document.addEventListener("DOMContentLoaded", inject);\n})();';
  const P = FILES[PROFILE];
  check("L5. agent-profile.js still ends with its boot line", P.lastIndexOf(TAIL) !== -1);
  const hooked = P.slice(0, P.lastIndexOf(TAIL)) + "  window.__apLive = live;\n" + TAIL;

  async function mount(file, answerFor, o) {
    o = o || {};
    const raw = lf(fs.readFileSync(path.join(FRONTEND, file), "utf8"));
    const config = (/<script>\s*(window\.AGENT_PROFILE_CONFIG = [\s\S]*?)<\/script>/.exec(raw) || [])[1];
    const html = raw.replace(/<script[\s\S]*?<\/script>/g, "");
    const dom = new JSDOM(html, { url: "https://bizforceai.com/" + file, runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window;
    const timers = new Map(); let n = 0;
    w.setTimeout = (fn, ms) => { timers.set(++n, { fn, ms: ms || 0, cleared: false }); return n; };
    w.clearTimeout = id => { const t = timers.get(id); if (t) t.cleared = true; };
    w.setInterval = (fn, ms) => { timers.set(++n, { fn, ms: ms || 0, cleared: false, interval: true }); return n; };
    w.clearInterval = w.clearTimeout;
    let hidden = false;
    Object.defineProperty(w.document, "hidden", { configurable: true, get: () => hidden });
    let online = true;
    Object.defineProperty(w.navigator, "onLine", { configurable: true, get: () => online });
    const calls = [];
    let reply = answerFor;
    w.fetch = (url) => {
      const u = String(url);
      let p;
      if (/\/api\/agents\/[a-z_]+\/live$/.test(u)) {
        calls.push(u);
        const r = reply(u);
        p = r === "network" ? Promise.reject(new TypeError("Failed to fetch"))
          : Promise.resolve({ ok: r.status === 200, status: r.status, json: async () => JSON.parse(JSON.stringify(r.body)) });
      } else {
        p = Promise.resolve({ ok: true, status: 200, json: async () => ({}), text: async () => "{}" });
      }
      p.catch(() => {});
      return p;
    };
    w.localStorage.setItem("bf_token", "check-token");
    let err = null;
    try {
      if (!config) throw new Error(file + " has no AGENT_PROFILE_CONFIG");
      w.eval(config);
      w.eval(hooked);
      if (w.document.readyState !== "loading" && !w.document.getElementById("apLive")) w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
    } catch (e) { err = e; }
    const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };
    await flush();
    const liveTimer = () => { const L = w.__apLive; const t = L && L.timer ? timers.get(L.timer) : null; return t && !t.cleared ? t : null; };
    const fire = async () => { const t = liveTimer(); if (t) { t.cleared = true; t.fn(); } await flush(); };
    const text = id => { const el = w.document.getElementById(id); return el ? el.textContent.replace(/\s+/g, " ").trim() : null; };
    return { w, doc: w.document, calls, err, flush, liveTimer, fire, text, setReply: f => { reply = f; },
      hide: async v => { hidden = v; w.document.dispatchEvent(new w.Event("visibilitychange")); await flush(); },
      goOffline: async () => { online = false; w.dispatchEvent(new w.Event("offline")); await flush(); },
      goOnline: async () => { online = true; w.dispatchEvent(new w.Event("online")); await flush(); } };
  }

  const pageType = file => (/agentType:\s*"([a-z_]+)"/.exec(fs.readFileSync(path.join(FRONTEND, file), "utf8")) || [])[1];
  check("L5. the 18 agent pages are exactly the 18 agents", JSON.stringify(AGENT_PAGES.map(pageType).sort()) === JSON.stringify(LIVE.AGENT_KEYS.slice().sort()),
    AGENT_PAGES.map(pageType).join(","));
  const placed = [], emptyWords = [], links = [];
  for (const file of AGENT_PAGES) {
    const type = pageType(file);
    const m = await mount(file, () => ({ status: 200, body: one18(answers.empty, type) }));
    const panel = m.doc.getElementById("apLive");
    const header = m.doc.querySelector(".page .agent-header");
    const cells = panel ? [...panel.querySelectorAll(".ap-live-k")].map(e => e.textContent) : [];
    if (!m.err && panel && header && header.nextElementSibling === panel && JSON.stringify(cells) === JSON.stringify(["Now", "Last", "Next", "Approvals", "Score", "This month"]) &&
      m.doc.getElementById("apLiveSignature") && m.doc.getElementById("apLiveSignature").innerHTML === "" && m.calls.length === 1 && m.calls[0].endsWith("/api/agents/" + type + "/live")) placed.push(file);
    else placed.push("BAD:" + file + (m.err ? ":" + m.err.message : "") + ":" + cells.join("/") + ":" + m.calls.join(","));
    const words = ["now", "last", "next", "approvals", "score", "month"].map(k => m.text("apLive_" + k)).join(" | ");
    emptyWords.push(words);
    links.push([m.doc.querySelector("#apLive_approvals a") && m.doc.querySelector("#apLive_approvals a").getAttribute("href"),
      m.doc.querySelector("#apLive_next a") && m.doc.querySelector("#apLive_next a").getAttribute("href")].join(" "));
  }
  check("L5. on all 18 pages: the panel sits directly under the agent's header, six cells in order, an empty signature slot, one fetch of that agent's /live",
    placed.every(p => p.indexOf("BAD:") !== 0), placed.filter(p => p.indexOf("BAD:") === 0).join(" ; "));
  const EMPTY = "Idle | No runs yet | No schedule | None waiting | No ratings yet | $0.00 model spend";
  check("L5. a member with nothing yet reads, on every page: " + EMPTY, emptyWords.every(w => w === EMPTY), emptyWords[0]);
  check("L5. Approvals opens proposals.html and Next opens the schedule card, on every page", links.every(l => l === "/proposals.html #ap-live-schedule"), links[0]);

  const seo = await mount("agents/seo.html", () => ({ status: 200, body: one18(answers.u1, "seo") }));
  const seoNow = seo.doc.querySelector('[data-live-cell="now"]');
  check("L5. a run in progress: \"Running\", with the pulse class and its task", seo.text("apLive_now") === "Running" && seoNow.classList.contains("is-running") &&
    /seo · tool · since /.test(seo.text("apLive_now_s")), seo.text("apLive_now") + " / " + seo.text("apLive_now_s"));
  const lastA = seo.doc.querySelector("#apLive_last a");
  check("L5. Last opens run.html for that run", lastA && lastA.getAttribute("href") === "/run.html?id=seo-running" && /^In progress · /.test(seo.text("apLive_last")) &&
    seo.text("apLive_last_s") === "3 runs · 1 failed in 7 days", (lastA && lastA.getAttribute("href")) + " " + seo.text("apLive_last_s"));
  check("L5. approvals and score from the member's rows: \"2 waiting\", \"▲ 2 ▼ 1\", \"1 pinned as examples\"",
    seo.text("apLive_approvals") === "2 waiting" && seo.text("apLive_score") === "▲ 2 ▼ 1" && seo.text("apLive_score_s") === "1 pinned as examples",
    seo.text("apLive_approvals") + " / " + seo.text("apLive_score"));
  check("L5. this month: the spend and \"Your model calls today: 1 of 250\"", /^\$0\.\d\d model spend$/.test(seo.text("apLive_month")) && seo.text("apLive_month_s") === "Your model calls today: 1 of 250",
    seo.text("apLive_month") + " / " + seo.text("apLive_month_s"));
  check("L5. the indicator: \"Live · updated 0s ago\", and the heartbeat is on", /^Live · updated \d+s ago$/.test(seo.text("apLiveStatus")) && seo.doc.getElementById("apLive").classList.contains("is-live"),
    seo.text("apLiveStatus"));
  const content = await mount("agents/content.html", () => ({ status: 200, body: one18(answers.u1, "content") }));
  check("L5. a stalled run: \"Stalled — no result after 10 min\"", content.text("apLive_now") === "Stalled — no result after 10 min" &&
    content.doc.querySelector('[data-live-cell="now"]').classList.contains("is-stalled"), content.text("apLive_now"));
  const ops = await mount("operations-agent.html", () => ({ status: 200, body: one18(answers.u1, "operations") }));
  check("L5. a paused schedule: \"Paused\", with the runner's reason", ops.text("apLive_next") === "Paused" && ops.text("apLive_next_s") === "Paused after 3 failed runs in a row",
    ops.text("apLive_next") + " / " + ops.text("apLive_next_s"));
  const lap = await mount("agents/seo.html", () => ({ status: 200, body: one18(answers.lapsed, "seo") }));
  check("L5. a lapsed member: \"Waiting for your subscription\"", lap.text("apLive_next") === "Waiting for your subscription", lap.text("apLive_next"));
  const an = await mount("agents/analytics.html", () => ({ status: 200, body: one18(answers.u1, "analytics") }));
  check("L5. autonomy off: \"Autonomous mode is off\"", an.text("apLive_next") === "Autonomous mode is off", an.text("apLive_next"));
  const brk = await mount("agents/seo.html", () => ({ status: 200, body: one18(answers.broken, "seo") }));
  check("L5. a section the server could not read: \"Could not be read\", never 0 or \"None\"",
    brk.text("apLive_score") === "Could not be read" && brk.text("apLive_approvals") === "Could not be read" && brk.text("apLive_now") === "Running",
    brk.text("apLive_score") + " / " + brk.text("apLive_approvals"));
  const td = await mount("agents/seo.html", () => ({ status: 200, body: one18(answers.tasksDown, "seo") }));
  check("L5. runs unreadable: Now and Last say \"Could not be read\", not \"Idle\" or \"No runs yet\"",
    td.text("apLive_now") === "Could not be read" && td.text("apLive_last") === "Could not be read", td.text("apLive_now") + " / " + td.text("apLive_last"));

  console.log("\n══ L6. polling ══");
  {
    const idle = await mount("agents/content.html", () => ({ status: 200, body: one18(answers.empty, "content") }));
    check("L6. idle: the next fetch is in 60 s", idle.liveTimer() && idle.liveTimer().ms === 60000, idle.liveTimer() && idle.liveTimer().ms);
    await idle.fire();
    check("L6. ... and it fetches when it fires", idle.calls.length === 2);
    const busy = await mount("agents/seo.html", () => ({ status: 200, body: one18(answers.u1, "seo") }));
    check("L6. a run in progress: the next fetch is in 15 s", busy.liveTimer() && busy.liveTimer().ms === 15000, busy.liveTimer() && busy.liveTimer().ms);
    await busy.hide(true);
    check("L6. hidden: no fetch is scheduled, and the indicator says so", busy.liveTimer() === null && busy.text("apLiveStatus") === "Paused while this tab is hidden",
      busy.text("apLiveStatus"));
    const before = busy.calls.length;
    await busy.hide(false);
    check("L6. shown again: it fetches at once", busy.calls.length === before + 1 && busy.liveTimer() && busy.liveTimer().ms === 15000);
    await busy.goOffline();
    check("L6. offline: stopped, with \"Offline — live activity paused\"", busy.liveTimer() === null && busy.text("apLiveStatus") === "Offline — live activity paused" &&
      busy.doc.getElementById("apLive").classList.contains("is-off"), busy.text("apLiveStatus"));
    const c2 = busy.calls.length;
    await busy.goOnline();
    check("L6. back online: it fetches again", busy.calls.length === c2 + 1);

    let status = 503;
    const bo = await mount("agents/content.html", () => (status === 200 ? { status: 200, body: one18(answers.empty, "content") } : { status, body: {} }));
    const waits = [bo.liveTimer() && bo.liveTimer().ms];
    for (let i = 0; i < 3; i++) { await bo.fire(); waits.push(bo.liveTimer() && bo.liveTimer().ms); }
    check("L6. a 503 backs off 2× the interval, then 4×, capped at 5 minutes: 120 s, 240 s, 300 s, 300 s", JSON.stringify(waits) === JSON.stringify([120000, 240000, 300000, 300000]),
      JSON.stringify(waits));
    check("L6. ... and says so: \"Retrying in 300s — the server answered 503\"", bo.text("apLiveStatus") === "Retrying in 300s — the server answered 503", bo.text("apLiveStatus"));
    status = 200; await bo.fire();
    check("L6. a good answer resets it to 60 s", bo.liveTimer() && bo.liveTimer().ms === 60000 && /^Live · updated/.test(bo.text("apLiveStatus")), bo.liveTimer() && bo.liveTimer().ms);
    status = 429; await bo.fire();
    check("L6. a 429 backs off the same way (120 s)", bo.liveTimer() && bo.liveTimer().ms === 120000, bo.liveTimer() && bo.liveTimer().ms);

    const net = await mount("agents/content.html", () => "network");
    check("L6. a request that never completes (online) backs off too", net.liveTimer() && net.liveTimer().ms === 120000 && /did not complete/.test(net.text("apLiveStatus")),
      net.text("apLiveStatus"));

    const SR = (/var SAVED_READS = \[([\s\S]*?)\n  \];/.exec(FILES[OFFLINE]) || [])[1] || "";
    const regs = [...SR.matchAll(/path:\s*(\/.*?\/)\s*,/g)].map(m => { try { return vm.runInNewContext(m[1]); } catch (e) { return null; } }).filter(Boolean);
    check("L6. /live is not one of bf-offline.js's saved reads (" + regs.length + " read), so an offline answer is never an old copy",
      regs.length >= 5 && !regs.some(r => r.test("/api/agents/seo/live") || r.test("/api/agents/live")), regs.map(String).join(" "));

    const css = (/<style>([\s\S]*?)<\/style>/.exec(lf(FILES[PROFILE]).slice(FILES[PROFILE].indexOf("function liveMarkup()"))) || [])[1] || "";
    const animated = [...css.matchAll(/([^{}]+)\{[^{}]*animation:apLive/g)].map(m => m[1].replace(/'\s*\+\s*'/g, "").trim());
    const reduced = (/@media \(prefers-reduced-motion:reduce\)\{([\s\S]*?)\}' \+\s*'\.ap-live-v,\.ap-live-beat\{transition:none\}/.exec(css) || [])[1] || "";
    check("L6. prefers-reduced-motion stops every animation (" + animated.length + ") and the transitions",
      animated.length >= 3 && animated.every(sel => sel.split(",").every(x => reduced.indexOf(x.trim()) !== -1)) && /animation:none/.test(reduced) &&
      /\.ap-live-v,\.ap-live-beat\{transition:none\}/.test(css), JSON.stringify(animated) + " / " + reduced);
  }

  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED (" + passes + ")" : "CHECKS FAILED: " + failures + " failing, " + passes + " passing"));
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.log("    FAIL  harness crashed: " + (e && e.stack || e)); process.exit(1); });
