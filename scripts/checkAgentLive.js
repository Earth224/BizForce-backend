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

   SIGNATURE MODULES (added with backend "Signature live data for Analytics,
   Store, Social, Email, SEO and Sales" and frontend "Signature live modules
   with charts, on six agent pages"; lib/agentSignatures.js and
   agentSignatureReads in server.js):
     S1  Analytics: runs per day and by agent without dry_run; blog arrivals
         on the member's own tracked bl- refs only;
     S2  Store: the member's own items, low stock at their own reorder point,
         margin bands by measureStockAndMargin, store proposals, BizCash trades
         (lib/trades.js, BFC only);
     S3  Social: the connection from named columns, never a secret;
         automation and its latest change; drafts by status, newest 3;
     S4  Email: sequences, enrolments, the next send, the sender's blockers
         exactly as its booleans say;
     S5  SEO: audits (flags, no score, because none is stored), posts,
         arrivals, the latest optimize run;
     S6  Sales: the pipeline; the radar for the credential owner only, YouTube
         on its own row and never in a total;
     S7  the 3 KB budget with signatures, no signature on the all-agents
         answer, Chart.js with the exact SRI tag, textContent only, and each
         module in jsdom with real fixtures and empty states.
   A failed read or a null count is { unavailable } in every module.

   The fake database returns only the columns a query selects, so a column no
   one asked for cannot reach an answer.

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
const SIGLIB = "lib/agentSignatures.js", ANALYTICS_PAGE = "agents/analytics.html";

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
  // Analytics counts dry runs, in the read and in the lib (S1)
  "analytics-dry-run-counted": [[SERVER, "          .neq(\"status\", \"dry_run\")\n          .gte(\"created_at\", windowStart)\n          .order(\"id\", { ascending: true });\n      }, \"runs in the last 30 days\");", "          .gte(\"created_at\", windowStart)\n          .order(\"id\", { ascending: true });\n      }, \"runs in the last 30 days\");"],
    [SIGLIB, "var runs = r.runs30.rows.filter(function (t) { return t && t.status !== \"dry_run\"; });", "var runs = r.runs30.rows;"]],
  // an arrival on any ref is counted: a Lead Radar ref, an untracked post, an unknown ref (S1)
  "non-bl-arrivals-counted": [[SIGLIB, "    return v && typeof v.ref === \"string\" && v.ref.indexOf(\"bl-\") === 0 && tracked[v.ref] === true;\n", "    return v && typeof v.ref === \"string\";\n"]],
  // YouTube is added into the Bluesky and Mastodon total (S6)
  "youtube-summed": [[SIGLIB, "? bl[k] + ma[k] : { unavailable", "? bl[k] + ma[k] + (typeof pair(\"youtube\")[k] === \"number\" ? pair(\"youtube\")[k] : 0) : { unavailable"]],
  // the radar counts are read and sent for every member, not only the owner (S6)
  "radar-to-non-owner": [[SERVER, "    if (OUTREACH_CREDENTIAL_OWNER_ID === userId) {\n      r.radar = {};", "    if (true) {\n      r.radar = {};"],
    [SIGLIB, "  if (opts.isOwner === true && r.radar) {", "  if (r.radar) {"]],
  // the connection row is read whole and passed through, app password and all (S3)
  "bluesky-secret-in-payload": [[SERVER, "        .select(\"handle, status, auto_post, auto_post_changed_at, last_ok_at, last_error_at, last_error_code, created_at\")\n", "        .select(\"*\")\n"],
    [SIGLIB, "    out.connection = c && c.handle ? {\n", "    out.connection = c && c.handle ? Object.assign({}, c, {\n"],
    [SIGLIB, "      last_error_code: c.last_error_code ? cut(c.last_error_code, 60) : null\n    } : { connected: false", "      last_error_code: c.last_error_code ? cut(c.last_error_code, 60) : null\n    }) : { connected: false"]],
  // the inventory read loses its owner filter (S2)
  "other-member-inventory": [[SERVER, "          .select(\"id, name, sku, unit, quantity_on_hand, reorder_point, unit_cost, unit_price, status\", { count: \"exact\" })\n          .eq(\"user_id\", userId)\n", "          .select(\"id, name, sku, unit, quantity_on_hand, reorder_point, unit_cost, unit_price, status\", { count: \"exact\" })\n"]],
  // an inventory read that failed answers as an empty shop (S2)
  "store-failed-read-as-zero": [[SIGLIB, "  if (failed(r.items)) out.stock = unavailableOf(r.items);", "  if (failed(r.items)) out.stock = { items: 0, with_reorder_point: 0, low: { count: 0, named: [] }, margin_bands: {} };"]],
  // Chart.js is loaded on agents/analytics.html without its integrity hash (S7)
  "chartjs-without-sri": [[ANALYTICS_PAGE, " integrity=\"sha384-9nhczxUqK87bcKHh20fSQcTGD4qq5GhayNYSYWqwBkINBhOfQLg/P5HG5lF1urn4\" crossorigin=\"anonymous\"></script>\n  <style>", "></script>\n  <style>"]],
  "route-after-type": [[SERVER, 'app.get("/api/agents/live", requireAuth, async function (req, res, next) {', 'app.get("/api/agents/:type", requireAuth, async function (req, res, next) {\n});\napp.get("/api/agents/live", requireAuth, async function (req, res, next) {']]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[SERVER, LIB, SIGLIB].forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
[PROFILE, OFFLINE, ANALYTICS_PAGE].forEach(f => {
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
function compileLib(rel) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(FILES[rel], file);
  return m.exports;
}
let LIVE, SIGS;
try { LIVE = compileLib(LIB); SIGS = compileLib(SIGLIB); } catch (e) { console.log("    FAIL  lib/agentLive.js or lib/agentSignatures.js did not load: " + e.message); process.exit(1); }

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
  "modelCallUtcDay", "modelCallDailyLimit", "MODEL_CALL_DAILY_LIMIT_DEFAULT",
  // the signature modules' reads and the rules they reuse
  "agentSignature", "agentSignatureReads", "blogRefToken", "measureStockAndMargin", "storeStockFigure", "storeStockCents", "STORE_STOCK_MIN_OUT_MOVEMENTS",
  "emailSequenceEnrollmentRows", "EMAIL_SEQUENCE_CONTACT_PAGE", "emailSequencesEnabled", "emailMarketingDailyCap",
  "EMAIL_MARKETING_DEFAULT_DAILY_CAP", "SEO_OPTIMIZE_TASK_PROMPT_PREFIX", "SALES_LEAD_STATUSES", "OUTREACH_CREDENTIAL_OWNER_ID"];
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
      if (op === "not_is") return x !== v && x !== undefined;
      if (op === "ilike") return typeof x === "string" && x.toLowerCase().indexOf(v.toLowerCase().replace(/%$/, "")) === 0;
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
      not(c, op, v) { if (op !== "is") throw new Error("fake db: not(" + op + ") is not supported"); q.filters.push(["not_is", c, v]); return api; },
      ilike(c, v) { q.filters.push(["ilike", c, v]); return api; },
      // A write is recorded, never applied: the live routes must make none.
      insert() { q.write = "insert"; return api; }, update() { q.write = "update"; return api; },
      upsert() { q.write = "upsert"; return api; }, delete() { q.write = "delete"; return api; },
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
          // Only the columns asked for, so a column nobody selected cannot leak into an answer.
          if (q.cols && q.cols !== "*") {
            const want = q.cols.split(",").map(x => x.trim());
            rows = rows.map(r => want.reduce((o, k) => { if (k in r) o[k] = r[k]; return o; }, {}));
          }
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
    require: name => (name === "./lib/agentLive" ? libForVm : name === "./lib/agentSignatures" ? SIGS : require(path.join(REPO, name))),
    crypto: require("crypto"),
    OWNER_ACCOUNT_ID: o.owner || U1,
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
    // A recording stand-in for Chart.js, and prefers-reduced-motion on request.
    if (o.chart) w.Chart = function Chart(canvas, spec) { (w.__charts = w.__charts || []).push({ canvas, spec }); this.destroy = () => {}; };
    w.matchMedia = q => ({ matches: !!o.reducedMotion && /reduce/.test(q), addListener() {}, removeListener() {} });
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

  /* ══ The signature modules (lib/agentSignatures.js, agentSignatureReads, the renderers) ══ */
  const refBox = {}; vm.createContext(refBox);
  vm.runInContext(defOf("blogRefToken") + "\nthis.ref = blogRefToken;", Object.assign(refBox, { crypto: require("crypto"), String }));
  const REF = (u, slug) => refBox.ref(u, slug);
  const OWNER = U1, U4 = "44444444-4444-4444-8444-444444444444";
  function sigFixture() {
    const t = fixture();
    const extra = [
      task(U1, "content", "completed", 1 * DAY + 30), task(U1, "content", "completed", 1 * DAY + 60), task(U1, "ads", "completed", 20 * DAY),
      task(U1, "seo", "completed", 2 * DAY + 10, { id: "audit-latest", task_type: "seo/audit", output: { flags: [{ id: "F1", basis: "error" }, { id: "F6", basis: "guideline" }, { id: "F9", basis: "guideline" }], measured: { title: "x" } } }),
      task(U1, "seo", "failed", 5 * DAY, { id: "audit-failed", task_type: "seo/audit" }),
      task(U1, "seo", "completed", 50 * DAY, { id: "audit-old", task_type: "seo/audit", output: { flags: [] } }),
      task(U1, "seo", "completed", 1 * DAY, { id: "optimize-latest", task_type: null, prompt: "SEO optimize: https://example.com" }),
      task(U2, "seo", "completed", 1 * DAY, { id: "OTHER-MEMBER-AUDIT", task_type: "seo/audit", output: { flags: [{ basis: "error" }] } })
    ];
    t.ai_tasks = t.ai_tasks.concat(extra);
    const body = (u, slug) => "<p>Read more</p><a href=\"https://bizforceai.net/?ref=" + REF(u, slug) + "\">BizForce</a>";
    t.content_library = [
      { id: "c1", user_id: U1, slug: "launch", status: "published", published_at: ago(3 * DAY), body: body(U1, "launch") },
      { id: "c2", user_id: U1, slug: "notes", status: "published", published_at: ago(10 * DAY), body: "<p>no link</p>" },
      { id: "c3", user_id: U1, slug: "old", status: "published", published_at: ago(40 * DAY), body: "<p>old</p>" },
      { id: "c4", user_id: U1, slug: "draft", status: "draft", published_at: null, body: body(U1, "draft").replace("?ref=", "?nope=") },
      { id: "c5", user_id: U1, slug: null, status: "draft", published_at: null, body: "" },
      { id: "c6", user_id: U2, slug: "launch", status: "published", published_at: ago(2 * DAY), body: body(U2, "launch") }
    ];
    let v = 0;
    const visit = (ref, m) => ({ id: "v" + (++v), ref, created_at: ago(m) });
    t.engine_visits = [
      visit(REF(U1, "launch"), 1 * DAY), visit(REF(U1, "launch"), 1 * DAY + 5), visit(REF(U1, "launch"), 4 * DAY), visit(REF(U1, "launch"), 40 * DAY),
      visit(REF(U2, "launch"), 1 * DAY), visit(REF(U2, "launch"), 2 * DAY), visit(REF(U1, "notes"), 1 * DAY),
      visit("lr-0123456789", 1 * DAY), visit("lr-0123456789", 2 * DAY)
    ];
    t.inventory_items = [
      { id: "i1", user_id: U1, name: "Blue mug", unit: "unit", quantity_on_hand: 2, reorder_point: 5, unit_cost: 4, unit_price: 10, status: "active" },
      { id: "i2", user_id: U1, name: "Red mug", unit: "unit", quantity_on_hand: 10, reorder_point: 3, unit_cost: 8, unit_price: 9, status: "active" },
      { id: "i3", user_id: U1, name: "Tea", unit: "box", quantity_on_hand: 0, reorder_point: 0, unit_cost: 5, unit_price: 4, status: "active" },
      { id: "i4", user_id: U1, name: "Spoon", unit: "unit", quantity_on_hand: 3, reorder_point: null, unit_cost: null, unit_price: 2, status: "active" },
      { id: "i5", user_id: U1, name: "Old stock", unit: "unit", quantity_on_hand: 0, reorder_point: 9, unit_cost: 1, unit_price: 2, status: "archived" },
      { id: "i9", user_id: U2, name: "OTHER MEMBER ITEM", unit: "unit", quantity_on_hand: 0, reorder_point: 10, unit_cost: 1, unit_price: 100, status: "active" }
    ];
    t.agent_proposals.push({ id: "sp1", user_id: U1, agent_type: "store", title: "List the blue mug on BizForce Market", status: "pending", created_at: ago(90) });
    t.marketplace_orders = [
      { id: "o1", buyer_id: U2, seller_id: U1, amount_bfc: 25, listing_title: "Mug", payment_method: "bfc", created_at: ago(3 * DAY) },
      { id: "o2", buyer_id: U1, seller_id: U4, amount_bfc: 10, listing_title: "Tea", payment_method: "bfc", created_at: ago(5 * DAY) },
      { id: "o3", buyer_id: U2, seller_id: U1, amount_bfc: 99, listing_title: "USD sale", payment_method: "usd", created_at: ago(2 * DAY) },
      { id: "o4", buyer_id: U2, seller_id: U1, amount_bfc: 40, listing_title: "Old sale", payment_method: "bfc", created_at: ago(60 * DAY) },
      { id: "o5", buyer_id: U2, seller_id: U4, amount_bfc: 7, listing_title: "Not ours", payment_method: "bfc", created_at: ago(2 * DAY) }
    ];
    t.member_social_connections = [
      { id: "mc1", user_id: U1, platform: "bluesky", handle: "maker.bsky.social", did: "did:plc:SECRETDIDVALUE", app_password_ciphertext: "deadbeefcafe0011",
        app_password_iv: "a1a1a1a1a1a1a1a1a1a1a1a1", app_password_auth_tag: "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2", status: "connected", auto_post: true,
        auto_post_changed_at: ago(2 * DAY), last_ok_at: ago(3 * 60), last_error_at: ago(DAY), last_error_code: "rate_limited", created_at: ago(9 * DAY), updated_at: ago(60) },
      { id: "mc2", user_id: U2, platform: "bluesky", handle: "other.bsky.social", did: "did:plc:OTHER", app_password_ciphertext: "ffff", app_password_iv: "c", app_password_auth_tag: "d",
        status: "connected", auto_post: false, created_at: ago(DAY) }
    ];
    t.member_social_setting_changes = [
      { id: "ch1", user_id: U1, platform: "bluesky", setting: "auto_post", old_value: false, new_value: true, changed_at: ago(2 * DAY) },
      { id: "ch0", user_id: U1, platform: "bluesky", setting: "auto_post", old_value: true, new_value: false, changed_at: ago(5 * DAY) },
      { id: "ch9", user_id: U2, platform: "bluesky", setting: "auto_post", old_value: false, new_value: true, changed_at: ago(60) }
    ];
    t.agent_proposals.push({ id: "pp-wait", user_id: U1, agent_type: "social", title: "Post: launch day", status: "pending", created_at: ago(100) },
      { id: "pp-no", user_id: U1, agent_type: "social", title: "Post: sale", status: "rejected", created_at: ago(200) });
    t.social_post_drafts = [
      { id: "d1", user_id: U1, status: "pending_approval", proposal_id: "pp-wait", content: "Launch day is here <img src=x onerror=alert(1)>", created_at: ago(100), published_at: null },
      { id: "d2", user_id: U1, status: "pending_approval", proposal_id: "pp-no", content: "Big sale", created_at: ago(200), published_at: null },
      { id: "d3", user_id: U1, status: "published", proposal_id: null, content: "We shipped", created_at: ago(300), published_at: ago(290), platform_post_uri: "at://did:plc:abc123/app.bsky.feed.post/3kxyzabc" },
      { id: "d4", user_id: U1, status: "publish_failed", proposal_id: null, content: "Did not go", created_at: ago(400), published_at: null },
      { id: "d5", user_id: U1, status: "not_published", proposal_id: null, content: "Saved", created_at: ago(500), published_at: null },
      { id: "d6", user_id: U1, status: "published", proposal_id: null, content: "Long ago", created_at: ago(40 * DAY), published_at: ago(40 * DAY), platform_post_uri: "at://did:plc:abc123/app.bsky.feed.post/old" },
      { id: "d9", user_id: U2, status: "published", proposal_id: null, content: "OTHER MEMBER DRAFT", created_at: ago(50), published_at: ago(50), platform_post_uri: "at://did:plc:x/app.bsky.feed.post/y" }
    ];
    t.email_sequences = [
      { id: "s1", owner_id: U1, name: "Welcome series", status: "active", created_at: ago(9 * DAY) },
      { id: "s2", owner_id: U1, name: "Winback", status: "draft", created_at: ago(2 * DAY) },
      { id: "s9", owner_id: U2, name: "OTHER MEMBER SEQUENCE", status: "active", created_at: ago(DAY) }
    ];
    t.email_sequence_enrollments = [
      { id: "e1", sequence_id: "s1", status: "active", next_send_at: "2026-10-30T09:00:00.000Z" },
      { id: "e2", sequence_id: "s1", status: "active", next_send_at: "2026-10-29T15:00:00.000Z" },
      { id: "e3", sequence_id: "s1", status: "stopped", stop_reason: "unsubscribed", next_send_at: null },
      { id: "e4", sequence_id: "s1", status: "completed", next_send_at: null },
      { id: "e9", sequence_id: "s9", status: "active", next_send_at: "2026-10-29T11:00:00.000Z" }
    ];
    t.sales_lead_pipeline = [
      { id: "sl1", user_id: U1, lead_post_uri: "at://a", status: "new" }, { id: "sl2", user_id: U1, lead_post_uri: "at://b", status: "new" },
      { id: "sl3", user_id: U1, lead_post_uri: "at://c", status: "contacted" }, { id: "sl9", user_id: U2, lead_post_uri: "at://z", status: "converted" }
    ];
    let L = 0;
    const lead = (source, m) => ({ id: "bl" + (++L), source, status: source === "youtube" ? "signal" : "scored", post_text: "OWNER LEAD TEXT", created_at: ago(m) });
    t.bsky_leads = [lead("bluesky", 60), lead("bluesky", DAY), lead("bluesky", 6 * DAY), lead("bluesky", 8 * DAY), lead("bluesky", 20 * DAY), lead("bluesky", 40 * DAY),
      lead("mastodon", 2 * DAY), lead("youtube", 30), lead("youtube", DAY), lead("youtube", 3 * DAY), lead("youtube", 6 * DAY), lead("youtube", 12 * DAY)];
    return t;
  }
  const SIG_PAGES = { analytics: "agents/analytics.html", store: "store-agent.html", social: "agents/social.html", email: "email-agent.html", seo: "agents/seo.html", sales: "agents/sales.html" };
  const sigCall = async (type, o, user) => {
    const hh = harness(o && o.tables || sigFixture(), o);
    const r = await hh.call("/api/agents/:type/live", { type }, user || { id: U1 });
    return Object.assign(r, { h: hh, sig: r.body && r.body.agent && r.body.agent.signature });
  };

  console.log("\n══ S1. Analytics: runs per day, by agent, and blog arrivals (bl- only) ══");
  {
    const r = await sigCall("analytics");
    const g = r.sig;
    const win = SIGS.windowOf(new Date(NOW));
    const labels = []; for (let i = 0; i < 30; i++) labels.push(new Date(Date.parse(win.days_from + "T00:00:00Z") + i * 86400000).toISOString().slice(0, 10));
    const mine = sigFixture().ai_tasks.filter(t => t.user_id === U1 && t.status !== "dry_run" && labels.indexOf(t.created_at.slice(0, 10)) !== -1);
    const want = labels.map(d => mine.filter(t => t.created_at.slice(0, 10) === d).length);
    check("S1. the window is 30 UTC days ending today, from " + win.days_from, g && g.kind === "analytics" && g.days_from === "2026-09-30" && g.days === 30, g && g.days_from);
    check("S1. runs per day match the member's own non-dry-run rows (" + want.reduce((a, b) => a + b, 0) + " runs)", g && JSON.stringify(g.runs.per_day) === JSON.stringify(want) && g.runs.total === mine.length,
      g && JSON.stringify(g.runs.per_day) + " vs " + JSON.stringify(want));
    check("S1. Sales's 40 dry runs today are not counted: Sales shows its one real run (10 days ago), and today shows only real runs", g && g.runs.by_agent.find(a => a.type === "sales").runs === 1 && g.runs.per_day[29] === want[29],
      g && JSON.stringify(g.runs.by_agent));
    const byAgent = {}; mine.forEach(t => { byAgent[t.agent_type] = (byAgent[t.agent_type] || 0) + 1; });
    check("S1. runs by agent, busiest first, named from config/brain.js without \"Agent\"",
      g && JSON.stringify(g.runs.by_agent.map(a => [a.type, a.runs])) === JSON.stringify(Object.keys(byAgent).sort((a, b) => byAgent[b] - byAgent[a] || (a < b ? -1 : 1)).map(k => [k, byAgent[k]])) &&
      g.runs.by_agent.find(a => a.type === "seo").name === "SEO", g && JSON.stringify(g.runs.by_agent));
    check("S1. blog arrivals: 3, through 1 tracked post, on the right days (2 yesterday, 1 four days ago)",
      g && g.arrivals.total === 3 && g.arrivals.tracked_posts === 1 && g.arrivals.per_day[28] === 2 && g.arrivals.per_day[25] === 1, g && JSON.stringify(g.arrivals));
    const posts = [{ ref: "bl-aaaaaaaaaa", tracked: true }, { ref: "bl-bbbbbbbbbb", tracked: false }, { ref: "lr-cccccccccc", tracked: true }];
    const visits = ["bl-aaaaaaaaaa", "bl-aaaaaaaaaa", "bl-bbbbbbbbbb", "lr-cccccccccc", "lr-dddddddddd", "bl-zzzzzzzzzz"].map(ref => ({ ref, created_at: new Date(NOW - 3600000).toISOString() }));
    const lone = SIGS.blogArrivals({ rows: { posts, visits } }, win);
    check("S1. the lib counts only bl- refs of a tracked post: an lr- (Lead Radar) ref, an untracked post and an unknown ref are not arrivals", lone.total === 2 && lone.tracked_posts === 1, JSON.stringify(lone));
    check("S1. the arrivals read asks engine_visits only for the member's own tracked bl- refs",
      r.h.db.log.filter(q => q.table === "engine_visits").every(q => q.filters.some(f => f[0] === "in" && f[1] === "ref" && JSON.stringify(f[2]) === JSON.stringify([REF(U1, "launch")]))) &&
      r.h.db.log.some(q => q.table === "engine_visits"));
    const none = await sigCall("analytics", null, { id: U3 });
    check("S1. a member with no tracked post: arrivals say why, not 0", none.sig.arrivals.none === SIGS.NO_TRACKED_LINK && none.sig.arrivals.total === undefined && none.sig.runs.total === 0,
      JSON.stringify(none.sig.arrivals));
    const down = await sigCall("analytics", { fail: ["engine_visits"] });
    check("S1. engine_visits down: arrivals { unavailable }, runs still answer", down.sig.arrivals.unavailable && down.sig.runs.total === mine.length, JSON.stringify(down.sig.arrivals));
    const tdown = await sigCall("analytics", { fail: ["ai_tasks"] });
    check("S1. ai_tasks down: runs { unavailable }, never 0", tdown.sig.runs.unavailable && tdown.sig.runs.total === undefined);
  }

  console.log("\n══ S2. Store: the member's own items, reorder points, margins, proposals, BizCash trades ══");
  {
    const r = await sigCall("store");
    const g = r.sig;
    check("S2. 4 active items (the archived one and another member's are not counted)", g && g.stock.items === 4 && JSON.stringify(g).indexOf("OTHER MEMBER") === -1, g && JSON.stringify(g.stock));
    check("S2. low stock at the member's own reorder point: Blue mug (2 ≤ 5) and Tea (0 ≤ 0); Red mug (10 > 3) and Spoon (none set) are not",
      g && g.stock.low.count === 2 && JSON.stringify(g.stock.low.named) === JSON.stringify(["Blue mug", "Tea"]) && g.stock.with_reorder_point === 3, g && JSON.stringify(g.stock.low));
    check("S2. margin bands from stock-margin's arithmetic: Blue 60% (40 and up), Red 11.1% (under 20), Tea −25% (loss), Spoon not priced",
      g && JSON.stringify(g.stock.margin_bands) === JSON.stringify({ loss: 1, under_20: 1, from_20_to_40: 0, from_40: 1, not_priced: 1 }), g && JSON.stringify(g.stock.margin_bands));
    check("S2. inventory is read with user_id = the member", r.h.db.log.filter(q => q.table === "inventory_items").every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === U1)));
    check("S2. store proposals waiting: 1", g && g.pending === 1, g && g.pending);
    check("S2. BizCash trades in 30 days, BFC only: 1 sale · 25 BFC, 1 purchase · 10 BFC (the USD order, the old sale and others' trades are not counted)",
      g && JSON.stringify(g.trades_30d) === JSON.stringify({ purchases: 1, purchases_bfc: 10, sales: 1, sales_bfc: 25 }), g && JSON.stringify(g.trades_30d));
    const empty = await sigCall("store", null, { id: U3 });
    check("S2. no items: items 0, so the page says \"Add inventory\"", empty.sig.stock.items === 0 && empty.sig.trades_30d.sales === 0);
    const down = await sigCall("store", { fail: ["inventory_items", "marketplace_orders"] });
    check("S2. inventory or trades down: { unavailable }, never 0 items", down.sig.stock.unavailable && down.sig.stock.items === undefined && down.sig.trades_30d.unavailable, JSON.stringify(down.sig));
  }

  console.log("\n══ S3. Social: the connection without a secret, automation, drafts ══");
  {
    const r = await sigCall("social");
    const g = r.sig;
    const blob = JSON.stringify(r.body);
    check("S3. connected as @maker.bsky.social, last ok, the last error code",
      g && g.connection.connected === true && g.connection.handle === "@maker.bsky.social" && g.connection.last_error_code === "rate_limited" && g.connection.last_ok_at === ago(180),
      g && JSON.stringify(g.connection));
    check("S3. no secret in the answer: no app password ciphertext, iv, tag or did, under any key or value",
      ["deadbeefcafe0011", "a1a1a1a1a1a1", "b2b2b2b2b2b2", "SECRETDIDVALUE", "app_password", "ciphertext", "auth_tag", "\"did\""].every(x => blob.indexOf(x) === -1), blob.slice(0, 300));
    check("S3. the connection read names its columns and never asks for the password or the did",
      r.h.db.log.filter(q => q.table === "member_social_connections").every(q => q.cols !== "*" && !/app_password|did/.test(q.cols)) &&
      r.h.db.log.some(q => q.table === "member_social_connections"));
    check("S3. automatic posting on, with the latest change from its log (turned on, 2 days ago)",
      g && g.automation.on === true && g.automation.latest && g.automation.latest.to === "on" && g.automation.latest.at === ago(2 * DAY), g && JSON.stringify(g.automation));
    check("S3. drafts in 30 days by status: 1 waiting, 1 published, 1 refused (its proposal was rejected), 1 failed, 1 saved",
      g && ["pending_approval", "published", "refused", "failed", "other"].every(k => g.drafts_30d[k] === 1), g && JSON.stringify(g.drafts_30d));
    check("S3. the newest 3, newest first, with links: proposals.html, then the Bluesky post",
      g && JSON.stringify(g.drafts_30d.newest.map(d => [d.id, d.state, d.href])) === JSON.stringify([["d1", "pending_approval", "/proposals.html"], ["d2", "refused", "/proposals.html"],
        ["d3", "published", "https://bsky.app/profile/did:plc:abc123/post/3kxyzabc"]]), g && JSON.stringify(g.drafts_30d.newest));
    const none = await sigCall("social", null, { id: U3 });
    check("S3. not connected: { connected: false, status: disconnected }, automation off", none.sig.connection.connected === false && none.sig.connection.status === "disconnected" &&
      none.sig.automation.on === false && none.sig.drafts_30d.published === 0);
    const down = await sigCall("social", { fail: ["member_social_connections", "social_post_drafts"] });
    check("S3. connection or drafts down: { unavailable }, never \"not connected\" or 0 drafts", down.sig.connection.unavailable && down.sig.drafts_30d.unavailable, JSON.stringify(down.sig));
  }

  console.log("\n══ S4. Email: sequences, enrolments, the next send, the sender's blockers ══");
  {
    const r = await sigCall("email");
    const g = r.sig;
    check("S4. 2 sequences of the member's own (another member's is not listed)", g && g.sequences.count === 2 && JSON.stringify(g).indexOf("OTHER MEMBER") === -1, g && JSON.stringify(g.sequences));
    check("S4. enrolments: 2 active, 1 stopped; next send the earliest active one (29 Oct 15:00)",
      g && g.sequences.enrolments_active === 2 && g.sequences.enrolments_stopped === 1 && g.sequences.next_send_at === "2026-10-29T15:00:00.000Z" &&
      g.sequences.list[1].name === "Welcome series" && g.sequences.list[1].active === 2, g && JSON.stringify(g.sequences));
    check("S4. sender off and no webhook secret: exactly those two blockers, in the server's words",
      g && g.sender.ready === false && JSON.stringify(g.sender.blockers.map(b => b.key)) === JSON.stringify(["enabled", "webhook_secret_set"]) &&
      g.sender.blockers[1].text === "RESEND_WEBHOOK_SECRET is not set, so bounce and complaint reports cannot be received and marketing mail is held.", g && JSON.stringify(g.sender));
    const ready = await sigCall("email", { env: { ENABLE_EMAIL_SEQUENCES: "true", RESEND_WEBHOOK_SECRET: "set-in-this-check" } });
    check("S4. switched on with the secret set: ready, no blockers, the default daily cap", ready.sig.sender.ready === true && ready.sig.sender.blockers.length === 0 && typeof ready.sig.sender.daily_cap === "number",
      JSON.stringify(ready.sig.sender));
    const badCap = await sigCall("email", { env: { ENABLE_EMAIL_SEQUENCES: "true", RESEND_WEBHOOK_SECRET: "x", EMAIL_MARKETING_DAILY_CAP: "lots" } });
    check("S4. a daily cap that is not a whole number is a blocker", JSON.stringify(badCap.sig.sender.blockers.map(b => b.key)) === JSON.stringify(["daily_cap"]) && badCap.sig.sender.daily_cap === null);
    check("S4. the secret's value never appears in the answer", JSON.stringify(ready.body).indexOf("set-in-this-check") === -1);
    const none = await sigCall("email", null, { id: U3 });
    check("S4. no sequences: count 0", none.sig.sequences.count === 0);
    const down = await sigCall("email", { fail: ["email_sequence_enrollments"] });
    check("S4. enrolments down: sequences { unavailable }, the sender still answers", down.sig.sequences.unavailable && down.sig.sender.blockers.length === 2);
  }

  console.log("\n══ S5. SEO: audits, posts published, arrivals, the latest optimize ══");
  {
    const r = await sigCall("seo");
    const g = r.sig;
    check("S5. audits in 30 days: 2 (1 completed); the 50-day-old one and another member's are not counted", g && g.audits_30d.runs === 2 && g.audits_30d.completed === 1, g && JSON.stringify(g.audits_30d));
    check("S5. the latest audit: its flags (1 error, 2 guidelines), and no score, because none is stored",
      g && g.latest_audit.task_id === "audit-latest" && g.latest_audit.errors === 1 && g.latest_audit.guidelines === 2 && g.latest_audit.score === null &&
      g.latest_audit.score_reason === "An audit stores its flags, not a score", g && JSON.stringify(g.latest_audit));
    check("S5. blog posts published in 30 days: 2", g && g.posts_published_30d === 2, g && g.posts_published_30d);
    check("S5. blog arrivals in 30 days: 3 through 1 tracked post (bl- only)", g && g.arrivals_30d.total === 3 && g.arrivals_30d.tracked_posts === 1, g && JSON.stringify(g.arrivals_30d));
    check("S5. the latest optimize run", g && g.latest_optimize && g.latest_optimize.task_id === "optimize-latest" && g.latest_optimize.status === "completed", g && JSON.stringify(g.latest_optimize));
    const nc = await sigCall("seo", { nullCount: ["content_library"] });
    check("S5. a posts count that comes back null is { unavailable }, never 0", nc.sig.posts_published_30d.unavailable !== undefined, JSON.stringify(nc.sig.posts_published_30d));
    const none = await sigCall("seo", null, { id: U3 });
    check("S5. nothing yet: 0 audits, no latest audit, 0 posts, arrivals cannot be counted, no optimize",
      none.sig.audits_30d.runs === 0 && none.sig.latest_audit === null && none.sig.posts_published_30d === 0 && none.sig.arrivals_30d.none && none.sig.latest_optimize === null);
  }

  console.log("\n══ S6. Sales: the pipeline, and the radar for the owner only ══");
  {
    const r = await sigCall("sales");
    const g = r.sig;
    check("S6. the owner's pipeline by stage: 2 new, 1 contacted (another member's converted lead is not counted)",
      g && JSON.stringify(g.pipeline) === JSON.stringify({ stages: { new: 2, drafted: 0, contacted: 1, replied: 0, converted: 0 }, total: 3 }), g && JSON.stringify(g.pipeline));
    check("S6. the owner's radar finds by source: Bluesky 3 / 5, Mastodon 1 / 1 (7 / 30 days)",
      g && g.radar && JSON.stringify(g.radar.bluesky) === JSON.stringify({ d7: 3, d30: 5 }) && JSON.stringify(g.radar.mastodon) === JSON.stringify({ d7: 1, d30: 1 }), g && JSON.stringify(g.radar));
    check("S6. YouTube in its own row, \"kept 30 days, not combined\": 4 / 5",
      g && g.radar && g.radar.youtube.d7 === 4 && g.radar.youtube.d30 === 5 && g.radar.youtube.note === "kept 30 days, not combined");
    check("S6. the only total is Bluesky + Mastodon (4 / 6); YouTube is never added to it, and no key sums all three",
      g && g.radar && JSON.stringify(g.radar.bluesky_and_mastodon) === JSON.stringify({ d7: 4, d30: 6 }) && Object.keys(g.radar).join(",") === "bluesky,mastodon,bluesky_and_mastodon,youtube",
      g && JSON.stringify(g.radar));
    check("S6. no lead text, uri or id leaves bsky_leads: head counts only", JSON.stringify(r.body).indexOf("OWNER LEAD TEXT") === -1 &&
      r.h.db.log.filter(q => q.table === "bsky_leads").every(q => q.head === true));
    const other = await sigCall("sales", null, { id: U2 });
    check("S6. a member who is not the owner: their own pipeline (1 converted), no radar key at all", other.sig.pipeline.total === 1 && other.sig.radar === undefined &&
      JSON.stringify(other.body).indexOf("youtube") === -1 && JSON.stringify(other.body).indexOf("radar") === -1, JSON.stringify(other.sig));
    check("S6. ... and bsky_leads is not read for them", other.h.db.log.every(q => q.table !== "bsky_leads"));
    const nc = await sigCall("sales", { nullCount: ["bsky_leads"] });
    check("S6. a radar count that comes back null is { unavailable }, and so is the total built on it",
      nc.sig.radar.bluesky.d7.unavailable && nc.sig.radar.bluesky_and_mastodon.d7.unavailable && nc.sig.radar.youtube.d30.unavailable);
  }

  console.log("\n══ S7. the budgets, the all-agents answer, the modules in jsdom ══");
  {
    const big = sigFixture();
    LIVE.AGENT_KEYS.forEach((k, j) => {
      for (let i = 0; i < 9; i++) big.agent_proposals.push({ id: k + "-p" + i + "-" + "x".repeat(20), user_id: U1, agent_type: k, title: "T".repeat(200), status: "pending", created_at: ago(i) });
      big.ai_tasks.push(task(U1, k, "failed", 2 + j, { task_type: k + "/" + "a-very-long-tool-name", error: "E".repeat(2000) }));
    });
    for (let i = 0; i < 9; i++) big.email_sequences.push({ id: "sx" + i, owner_id: U1, name: "N".repeat(120), status: "active", created_at: ago(i) });
    for (let i = 0; i < 9; i++) big.social_post_drafts.push({ id: "dx" + i, user_id: U1, status: "publish_failed", content: "C".repeat(5000), created_at: ago(i), published_at: null });
    big.member_social_connections[0].last_error_code = "X".repeat(60);
    for (let i = 0; i < 30; i++) big.inventory_items.push({ id: "ix" + i, user_id: U1, name: "Item ".repeat(30) + i, quantity_on_hand: 0, reorder_point: 1, unit_cost: 1, unit_price: 2, status: "active" });
    const sizes = {}, writes = [];
    for (const k of SIGS.SIGNATURE_TYPES) {
      const rr = await sigCall(k, { tables: JSON.parse(JSON.stringify(big)) });
      sizes[k] = JSON.stringify(rr.body).length;
      rr.h.db.log.forEach(q => { if (q.write) writes.push(k + ": " + q.write + " " + q.table); });
      if (rr.sig && rr.sig.unavailable !== undefined) writes.push(k + ": the module could not be built: " + rr.sig.unavailable);
    }
    check("S7. the six modules only read: no insert, update, upsert or delete, and every module was built", writes.length === 0, writes.join("; "));
    check("S7. worst case, each of the six with its signature in at most 3 KB (" + JSON.stringify(sizes) + ")", Object.values(sizes).every(n => n <= 3 * 1024), JSON.stringify(sizes));
    const allR = await harness(sigFixture()).call("/api/agents/live");
    check("S7. GET /api/agents/live carries no signature (signature: null for all 18) and says where the modules are",
      Object.values(allR.body.agents).every(a => a.signature === null) && /\/api\/agents\/<type>\/live only/.test(allR.body.signatures) && JSON.stringify(allR.body).length <= 24 * 1024);

    // The exact Chart.js tag, from agents/lead-radar.html
    const LR = lf(fs.readFileSync(path.join(FRONTEND, "agents/lead-radar.html"), "utf8"));
    const TAG = (/<script src="https:\/\/cdn\.jsdelivr\.net\/npm\/chart\.js@4\.4\.1\/dist\/chart\.umd\.min\.js"[^>]*><\/script>/.exec(LR) || [])[0] || "";
    const pageTags = ["agents/sales.html", "analytics-dashboard.html"].map(f => lf(fs.readFileSync(path.join(FRONTEND, f), "utf8"))).concat([FILES[ANALYTICS_PAGE]])
      .map(h => (h.match(/<script[^>]*chart\.js[^>]*><\/script>/g) || []));
    check("S7. Chart.js 4.4.1 on agents/analytics.html with exactly the SRI tag of lead-radar.html, sales.html and analytics-dashboard.html",
      /integrity="sha384-9nhczxUqK87bcKHh20fSQcTGD4qq5GhayNYSYWqwBkINBhOfQLg\/P5HG5lF1urn4" crossorigin="anonymous"/.test(TAG) && pageTags.every(t => t.length === 1 && t[0] === TAG),
      JSON.stringify(pageTags));
    const SIGSRC = FILES[PROFILE].slice(FILES[PROFILE].indexOf("══ SIGNATURE MODULES"), FILES[PROFILE].indexOf("/* ── boot ── */"));
    check("S7. the modules set every string with textContent: no innerHTML or insertAdjacentHTML in them", SIGSRC.length > 5000 && !/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(SIGSRC));
    check("S7. nothing in the modules animates: no animation rule in their styles",
      !/\.ap-sig[^{]*\{[^}]*animation/.test(FILES[PROFILE].slice(FILES[PROFILE].indexOf("function liveMarkup()"), FILES[PROFILE].indexOf("function liveSet("))));

    // jsdom: each page with its own per-agent answer
    const answer = async (type, user, o) => { const rr = await sigCall(type, o, user); return rr.body; };
    const mountSig = async (type, body, o) => {
      o = o || {};
      const m = await mount(SIG_PAGES[type], () => ({ status: 200, body }), o);
      return m;
    };
    const A = {};
    for (const k of SIG_PAGES ? Object.keys(SIG_PAGES) : []) { A[k] = await answer(k); A[k + "_empty"] = await answer(k, { id: U3 }); }
    // The module's words as a reader meets them: each text node apart.
    const slotText = m => {
      const out = [], walk = m.doc.createTreeWalker(m.doc.getElementById("apLiveSignature"), 4);
      while (walk.nextNode()) out.push(walk.currentNode.nodeValue);
      return out.join(" ").replace(/\s+/g, " ").trim();
    };

    const an = await mountSig("analytics", A.analytics, { chart: true });
    const made = an.w.__charts || [];
    check("S7. Analytics in jsdom: three Chart.js charts — runs per day (line), runs by agent (bar), arrivals per day (line)",
      JSON.stringify(made.map(c => [c.canvas.id, c.spec.type])) === JSON.stringify([["apSigRunsDay", "line"], ["apSigByAgent", "bar"], ["apSigArrivals", "line"]]), JSON.stringify(made.map(c => c.canvas.id)));
    check("S7. ... drawn from the answer's own numbers", made.length === 3 && JSON.stringify(made[0].spec.data.datasets[0].data) === JSON.stringify(A.analytics.agent.signature.runs.per_day) &&
      JSON.stringify(made[2].spec.data.datasets[0].data) === JSON.stringify(A.analytics.agent.signature.arrivals.per_day));
    const canvases = [...an.doc.querySelectorAll("#apLiveSignature canvas")];
    const tables = [...an.doc.querySelectorAll("#apLiveSignature figure table")];
    check("S7. each chart has an accessible summary: an aria-label with the numbers, and a table of every value",
      canvases.length === 3 && canvases.every(c => c.getAttribute("role") === "img" && /\d/.test(c.getAttribute("aria-label"))) &&
      /^Arrivals per day\. 3 arrivals in all; the most was 2 on /.test(canvases[2].getAttribute("aria-label")) &&
      tables.length === 3 && tables[0].querySelectorAll("tr").length === 31, canvases.map(c => c.getAttribute("aria-label")).join(" | "));
    check("S7. the chart colours come from the panel's CSS variables", made.length && made[0].spec.data.datasets[0].borderColor === "#22d3ee" && made[1].spec.data.datasets[0].borderColor === "#a855f7",
      made.length && made[0].spec.data.datasets[0].borderColor);
    check("S7. the first draw animates once (400 ms); with prefers-reduced-motion, not at all", made.length && made[0].spec.options.animation && made[0].spec.options.animation.duration === 400);
    const rm = await mountSig("analytics", A.analytics, { chart: true, reducedMotion: true });
    check("S7. ... reduced motion: animation false on every chart", (rm.w.__charts || []).length === 3 && rm.w.__charts.every(c => c.spec.options.animation === false));
    await an.fire();
    check("S7. an unchanged answer on the next poll redraws nothing", (an.w.__charts || []).length === 3);
    const noChart = await mountSig("analytics", A.analytics);
    check("S7. Chart.js not loaded: the numbers are shown as tables, and it says so",
      noChart.doc.querySelectorAll("#apLiveSignature canvas").length === 0 && [...noChart.doc.querySelectorAll("#apLiveSignature table")].every(t => t.className === "ap-sig-table") &&
      /The chart could not load; the numbers are in the table\./.test(slotText(noChart)));
    const anE = await mountSig("analytics", A.analytics_empty, { chart: true });
    check("S7. Analytics empty: \"0 runs\", \"No runs in the last 30 days\", arrivals \"Cannot be counted\", no chart",
      (anE.w.__charts || []).length === 0 && /0 runs/.test(slotText(anE)) && /No runs in the last 30 days, so there is nothing to chart\./.test(slotText(anE)) && /Cannot be counted/.test(slotText(anE)), slotText(anE));

    const st = await mountSig("store", A.store);
    check("S7. Store: 4 items, \"2 at or below reorder point\" (Blue mug, Tea), margin bars, 1 proposal waiting, trades",
      /4 items/.test(slotText(st)) && /2 at or below reorder point Blue mug, Tea/.test(slotText(st)) && st.doc.querySelectorAll("#apLiveSignature .ap-sig-bar").length === 5 &&
      /1 waiting/.test(slotText(st)) && /1 sale · 25 BFC/.test(slotText(st)) && /1 purchase · 10 BFC, last 30 days/.test(slotText(st)), slotText(st));
    const stE = await mountSig("store", A.store_empty);
    const addInv = stE.doc.querySelector("#apLiveSignature a[href='/inventory.html']");
    check("S7. Store empty: \"No inventory yet. Add inventory\", linked to the Inventory page", addInv && addInv.textContent === "Add inventory" && /No inventory yet\./.test(slotText(stE)), slotText(stE));

    const so = await mountSig("social", A.social);
    check("S7. Social: \"Connected as @maker.bsky.social\", the last error code, automatic posting on, the four statuses",
      /Connected as @maker\.bsky\.social/.test(slotText(so)) && /last error rate_limited/.test(slotText(so)) && /Automatic posting On Turned on/.test(slotText(so)) &&
      ["pending_approval", "published", "refused", "failed"].every(k => so.doc.querySelector("#apLiveSignature [data-bar='" + k + "']")), slotText(so));
    check("S7. a draft's text is shown as text: no element is made from it", so.doc.querySelectorAll("#apLiveSignature img").length === 0 && /<img src=x/.test(slotText(so)));
    const soE = await mountSig("social", A.social_empty);
    const conn = soE.doc.querySelector("#apLiveSignature a[href='#bskyConnect']");
    check("S7. Social not connected: \"Not connected. Connect Bluesky\", linked to the connect card", conn && conn.textContent === "Connect Bluesky", slotText(soE));

    const em = await mountSig("email", A.email);
    check("S7. Email: 2 sequences, \"2 active · 1 stopped\", the next send, and \"Blocked\" with both blockers in words",
      /2 sequences/.test(slotText(em)) && /2 active · 1 stopped/.test(slotText(em)) && /Blocked/.test(slotText(em)) &&
      JSON.stringify([...em.doc.querySelectorAll("[data-blocker]")].map(e => e.getAttribute("data-blocker"))) === JSON.stringify(["enabled", "webhook_secret_set"]) &&
      /RESEND_WEBHOOK_SECRET is not set/.test(slotText(em)), slotText(em));
    const emE = await mountSig("email", A.email_empty);
    const prop = emE.doc.querySelector("#apLiveSignature a[href='#esPanel']");
    check("S7. Email empty: \"No sequences yet. Propose one\"", prop && prop.textContent === "Propose one" && /No sequences yet\./.test(slotText(emE)), slotText(emE));

    const se = await mountSig("seo", A.seo);
    const auditLink = se.doc.querySelector("#apLiveSignature a[href='/run.html?id=audit-latest']");
    check("S7. SEO: 2 audits, the latest linked with \"1 error · 2 guidelines · no score: an audit stores its flags\", 2 posts, 3 arrivals, the optimize run",
      auditLink && /2 audits/.test(slotText(se)) && /1 error · 2 guidelines · no score: an audit stores its flags/.test(slotText(se)) && /2 published/.test(slotText(se)) &&
      /3 arrivals/.test(slotText(se)) && se.doc.querySelector("#apLiveSignature a[href='/run.html?id=optimize-latest']"), slotText(se));
    const seE = await mountSig("seo", A.seo_empty);
    check("S7. SEO empty: \"No audit has completed yet\", \"0 published\", \"Cannot be counted\", \"Not run yet\"",
      /No audit has completed yet/.test(slotText(seE)) && /0 published/.test(slotText(seE)) && /Cannot be counted/.test(slotText(seE)) && /Not run yet/.test(slotText(seE)), slotText(seE));

    const sa = await mountSig("sales", A.sales);
    const rows = [...sa.doc.querySelectorAll("#apLiveSignature .ap-sig-radar tr")].map(tr => [...tr.children].map(c => c.textContent));
    check("S7. Sales (owner): the pipeline bars and the radar table — YouTube on its own row, labelled, apart from the total",
      JSON.stringify(rows) === JSON.stringify([["Source", "7 days", "30 days"], ["Bluesky", "3", "5"], ["Mastodon", "1", "1"], ["Bluesky + Mastodon", "4", "6"],
        ["YouTube — kept 30 days, not combined", "4", "5"]]) && sa.doc.querySelectorAll("#apLiveSignature .ap-sig-bar").length === 5, JSON.stringify(rows));
    const saO = await mountSig("sales", await answer("sales", { id: U2 }));
    check("S7. Sales (not the owner): the pipeline only, no radar section", saO.doc.querySelectorAll("#apLiveSignature .ap-sig-radar").length === 0 &&
      !/Lead Radar/.test(slotText(saO)) && /1 lead/.test(slotText(saO)), slotText(saO));
    const saE = await mountSig("sales", A.sales_empty);
    check("S7. Sales empty: \"No leads in your pipeline yet.\"", /No leads in your pipeline yet\./.test(slotText(saE)), slotText(saE));

    const brokenStore = await mountSig("store", await answer("store", null, { fail: ["inventory_items"] }));
    check("S7. a section the server could not read says \"Could not be read\", never 0 items", /Inventory Could not be read/.test(slotText(brokenStore)) && !/0 items/.test(slotText(brokenStore)),
      slotText(brokenStore));
    const other = await mount("ads-agent.html", () => ({ status: 200, body: { generated_at: "x", daily_calls: { used: 0, limit: 250 }, agent: Object.assign({}, A.store.agent, { type: "ads", signature: null }) } }));
    check("S7. an agent without a module keeps the slot empty", other.doc.getElementById("apLiveSignature").innerHTML === "");
  }

  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED (" + passes + ")" : "CHECKS FAILED: " + failures + " failing, " + passes + " passing"));
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.log("    FAIL  harness crashed: " + (e && e.stack || e)); process.exit(1); });
