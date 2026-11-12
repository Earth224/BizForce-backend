"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkOrbitStage2 — orbit stage 2 (Nov 11 2026, orbit stage 2): the weekly
   goal, the pulse, order status, and the orbit's goal ring, satellites, links
   and sparks.

     R  migration 183 as the owner ran it (the header and every line), the
        only 183 and the highest ("the highest" moved here from
        checkAmazonConnect R1); its goal caps are lib/orbitStage2.js's;
     A  AGENT_PORTAL maps every agent in config/brain.js to a portal (a check
        fails if one is unmapped), and the table is printed;
     G  the weekly goal: validateGoal's closed shape, whole numbers for counts,
        each metric's cap, a currency for store sales only, a real time zone;
        PUT /api/user/preferences weekly_goal saves, refuses with a 400,
        clears with null, leaves it alone when absent, and clears the member's
        /top cache; GET answers it;
     W  Monday 00:00 in the goal's time zone, across daylight-saving changes
        and a skipped midnight;
     S  order status: each platform's cancelled and refunded states, and
        storeWeek counts active orders only, in the goal's currency, the
        others listed as not counted and never converted;
     T  GET /api/dashboard/top's goal: tracked visits (bl- and lr- refs),
        store orders and sales (as of the last sync), card visits by UTC day
        (the note), marketplace orders; null when unreadable, never 0; the
        orders read and every reader filter on status active;
     P  GET /api/dashboard/pulse: requireAuth only, 6 a minute per member, 15
        s per member cache, read-only, bounded (each read the member's own,
        since 24 h, newest 20; running from 50), running at most 12 with each
        agent's portal, events after since (24 h at most, none with no since,
        20 at most, newest last), one spark per action, the links;
     D  Your data exports the five goal fields and the order status;
     F  the page (jsdom): the goal ring's figures, arc, "Goal met",
        "Unavailable" and "Set a weekly goal"; the setter; satellites (8 then
        "+N"); links never within the core's r 66; sparks only for events
        after load, never during a turn (the newest 3 wait), highlights only
        under reduced motion; the pulse only while visible and on screen; the
        stars never laid out again by hover or click.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const Module = require("module");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const SERVER = "server.js", S2F = "lib/orbitStage2.js", SSF = "lib/storeSync.js", ORBIT = "scripts/bf-orbit.js", DASH = "dashboard.html";
const MIG = "supabase/migrations/183_weekly_goal_and_order_status.sql";

const MUTATIONS = {
  // a target over the metric's cap is accepted (G)
  "goal-cap-ignored": [[S2F, "if (!Number.isInteger(t) || t < 1 || t > spec.cap) return refuseGoal(", "if (!Number.isInteger(t) || t < 1) return refuseGoal("]],
  // a store sales goal with no currency is accepted (G)
  "sales-without-currency": [[S2F, "if (typeof g.currency !== \"string\" || !/^[A-Z]{3}$/.test(g.currency)) return refuseGoal(", "if (false) return refuseGoal("]],
  // any string is taken as a time zone (G)
  "bad-time-zone-accepted": [[S2F, "if (!gateRules.isTimeZone(g.time_zone)) return refuseGoal(", "if (typeof g.time_zone !== \"string\") return refuseGoal("]],
  // the week starts on Monday 00:00 UTC whatever the goal's zone (W)
  "week-start-utc": [[S2F, "var z = gateRules.isTimeZone(zone) ? zone : \"UTC\";", "var z = \"UTC\";"]],
  // Monday's midnight from today's offset, wrong across a daylight-saving change (W)
  "dst-wrong": [[S2F, "  return localDayStartMs(monday.getUTCFullYear(), monday.getUTCMonth() + 1, monday.getUTCDate(), z);", "  return monday.getTime() - zoneOffsetMs(nowMs, z);"]],
  // a cancelled Shopify order is stored as active (S)
  "cancelled-counted": [[SSF, "    if (o && o.cancelled_at) return \"cancelled\";", "    if (false) return \"cancelled\";"]],
  // a refunded Shopify order is stored as active (S)
  "refunded-counted": [[SSF, "    return s(o && o.financial_status) === \"refunded\" ? \"refunded\" : \"active\";", "    return \"active\";"]],
  // another currency's totals are added to the goal's sales (S, T)
  "other-currency-converted": [[S2F, "    if (currency && c === currency) { if (isFinite(amount)) cents += Math.round(amount * 100); return; }", "    if (currency) { if (isFinite(amount)) cents += Math.round(amount * 100); return; }"]],
  // /top's orders read counts cancelled and refunded orders (T)
  "reader-ignores-status": [[SERVER, ".eq(\"user_id\", userId).eq(\"status\", \"active\").gte(\"ordered_at\", days[0]);", ".eq(\"user_id\", userId).gte(\"ordered_at\", days[0]);"]],
  // the pulse records a task row (P)
  "pulse-writes": [[SERVER, "      body = await dashboardPulseBody(userId, now);\n",
    "      await supabase.from(\"ai_tasks\").insert({ user_id: userId, agent_type: \"analytics\", task_type: \"dashboard/pulse\", status: \"completed\" });\n      body = await dashboardPulseBody(userId, now);\n"]],
  // the pulse reads everything again on every request (P)
  "pulse-uncached": [[SERVER, "    var cached = !!(kept && nowMs - kept.at < DASHBOARD_PULSE_CACHE_MS);", "    var cached = false;"]],
  // an agent left out of AGENT_PORTAL (A)
  "agent-unmapped": [[S2F, "sales: \"sell\", store: \"sell\", etsy: \"sell\", broker: \"sell\",", "sales: \"sell\", store: \"sell\", broker: \"sell\","]],
  // an unreadable goal value shown as 0 (F)
  "null-shown-as-zero": [[ORBIT, "value: n(g.value), store: spec.store, raw: g };", "value: n(g.value) === null ? 0 : n(g.value), store: spec.store, raw: g };"]],
  // the goal's arc drawn with no goal (F)
  "arc-without-goal": [[ORBIT, "    goalArc.style.display = on ? \"\" : \"none\";", "    goalArc.style.display = \"\";"]],
  // a spark starts during a turn (F)
  "spark-mid-turn": [[ORBIT, "    if (state.turn) { pulse.queue.push(e);", "    if (false) { pulse.queue.push(e);"]],
  // an event from before the page loaded sparks (F)
  "spark-for-old-event": [[ORBIT, "    if (!isFinite(t) || t <= pulse.loadedAt || !pulseOn()) return false;", "    if (!isFinite(t) || !pulseOn()) return false;"]],
  // every running agent gets a satellite (F)
  "satellites-uncapped": [[ORBIT, "var shown = rows.slice(0, SAT.max), extra", "var shown = rows.slice(0), extra"]],
  // a moving spark under reduced motion (F)
  "reduced-motion-sparks": [[ORBIT, "    if (reduced()) { lightUp(pair ? linkPath[pair] : null, \"is-lit\", SPARK.litMs);", "    if (false) { lightUp(pair ? linkPath[pair] : null, \"is-lit\", SPARK.litMs);"]],
  // hovering the core lays the stars out again (F)
  "stars-move-on-hover": [[ORBIT, "    core.addEventListener(\"click\", function () { setAllTools(!state.allOpen); });\n",
    "    core.addEventListener(\"click\", function () { setAllTools(!state.allOpen); });\n    core.addEventListener(\"mouseenter\", function () { starsDrawn = \"\"; drawStars(); });\n"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {
  [SERVER]: lf(fs.readFileSync(path.join(REPO, SERVER), "utf8")),
  [S2F]: lf(fs.readFileSync(path.join(REPO, S2F), "utf8")),
  [SSF]: lf(fs.readFileSync(path.join(REPO, SSF), "utf8")),
  [MIG]: lf(fs.readFileSync(path.join(REPO, MIG), "utf8")),
  [ORBIT]: lf(fs.readFileSync(path.join(FRONTEND, ORBIT), "utf8")),
  [DASH]: lf(fs.readFileSync(path.join(FRONTEND, DASH), "utf8"))
};
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 500) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no request is left unhandled", false, (e && e.message) || e));
const J = JSON.stringify;

// The two library files as they are in FILES (so a mutation reaches every caller here).
function fromText(rel) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module); m.filename = file; m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(FILES[rel], file);
  return m.exports;
}
const S2 = fromText(S2F);
const SS = fromText(SSF);

/* ── a clock the check moves: Wednesday 20 January 2027, 10:20 UTC ── */
const NOW = Date.parse("2027-01-20T10:20:00.000Z");
const CLOCK = { t: NOW };
function movableDate() {
  const Real = Date;
  function D(...a) { if (!(this instanceof D)) return new Real(CLOCK.t).toString(); return a.length ? new Real(...a) : new Real(CLOCK.t); }
  D.prototype = Real.prototype;
  D.now = () => CLOCK.t; D.parse = Real.parse; D.UTC = Real.UTC;
  return D;
}
const at = iso => new Date(Date.parse(iso)).toISOString();
const minsAgo = m => new Date(CLOCK.t - m * 60000).toISOString();

/* ── the server, lifted (the same lifting as scripts/checkDashboardTop.js) ── */
const SRC = FILES[SERVER];
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
const FN_AT = new Map(), VAR_AT = new Map();
{
  const re = /^(?:async )?function ([A-Za-z_$][A-Za-z0-9_$]*)\(|^(?:var|const|let) ([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=[ \t]*/gm; let m;
  while ((m = re.exec(SRC))) {
    if (m[1] !== undefined) { if (!FN_AT.has(m[1])) FN_AT.set(m[1], m.index); }
    else { if (!VAR_AT.has(m[2])) VAR_AT.set(m[2], []); VAR_AT.get(m[2]).push({ index: m.index, length: m[0].length }); }
  }
}
function definitionOf(name) {
  if (FN_AT.has(name)) { const a = FN_AT.get(name); return SRC.slice(a, s.braceMatch(SRC, SRC.indexOf(") {", a) + 2)); }
  const m = (VAR_AT.get(name) || []).find(v => !SPANS.some(([x, y]) => v.index > x && v.index < y));
  if (!m) return null;
  const brk = /;\n/g; brk.lastIndex = m.index + m.length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(m.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "requireAuth",
  "requireActiveSubscription", "requireAdmin", "aiLimiter", "crypto", "Date", "rateLimit", "publicCertificationCatalog", "OWNER_ACCOUNT_ID",
  "getUserPlan", "startToolRun", "callAnthropicText", "fetch"]);
const uncommented = code => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
  const have = new Map(), looked = new Set();
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
const ROUTES = [["get", "/api/dashboard/top"], ["get", "/api/dashboard/pulse"], ["get", "/api/user/preferences"], ["put", "/api/user/preferences"]];
let LIFTED;
try { LIFTED = new vm.Script(closure(ROUTES.map(r => routeText(r[0], r[1])).join("\n\n") + "\n\nthis.__topCache = dashboardTopCache;")); }
catch (e) { console.log("    FAIL  the routes could not be lifted: " + e.message); process.exit(1); }

/* ── the in-memory database: every filter applied; user_preferences upserts kept, every other write recorded and refused ── */
function fakeDb(tables) {
  const log = [], writes = [];
  function keep(q, row) {
    return q.filters.every(f => {
      const x = row[f[1]];
      if (f[0] === "eq") return x === f[2];
      if (f[0] === "neq") return x !== f[2];
      if (f[0] === "in") return f[2].indexOf(x) !== -1;
      if (f[0] === "gte") return x !== null && x !== undefined && String(x) >= String(f[2]);
      if (f[0] === "lt") return x !== null && x !== undefined && String(x) < String(f[2]);
      if (f[0] === "not") return f[2] === "is" && f[3] === null ? x !== null && x !== undefined : true;
      return true;
    });
  }
  function answer(q) {
    if (q.write) {
      writes.push({ table: q.table, op: q.write, payload: q.payload });
      if (q.table === "user_preferences" && q.write === "upsert") {
        const t = tables.user_preferences = tables.user_preferences || [];
        const row = t.find(r => r.user_id === q.payload.user_id);
        if (row) Object.assign(row, q.payload); else t.push(Object.assign({}, q.payload));
        return Promise.resolve({ data: null, error: null });
      }
      return Promise.resolve({ data: null, error: { message: "this check allows no writes here" } });
    }
    const t = tables[q.table];
    if (t === "FAIL") return Promise.resolve({ data: null, error: { message: q.table + " is unreachable in this fixture" }, count: null });
    let rows = (Array.isArray(t) ? t : []).filter(r => keep(q, r));
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
    rows = JSON.parse(J(rows));
    if (q.single) return Promise.resolve({ data: rows[0] || null, error: null, count });
    return Promise.resolve({ data: rows, error: null, count });
  }
  function from(table) {
    const q = { table, cols: "*", opts: null, filters: [], single: false, write: null, payload: null };
    log.push(q);
    const b = { select(cols, opts) { q.cols = cols || "*"; q.opts = opts || null; return b; } };
    ["insert", "update", "upsert", "delete"].forEach(op => { b[op] = function (payload) { q.write = op; q.payload = payload; return b; }; });
    ["eq", "neq", "in", "gte", "lt", "not", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, writes, tables, client: { from, rpc() { writes.push({ table: "rpc", op: "rpc" }); return Promise.resolve({ data: null, error: { message: "no rpc" } }); } } };
}

const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const USER = "aaaaaaaa-0000-4000-8000-000000000002";
const OTHER = "aaaaaaaa-0000-4000-8000-000000000003";
const blogRef = (u, slug) => "bl-" + crypto.createHash("sha256").update("blog:" + u + ":" + slug).digest("hex").slice(0, 10);
const outRef = uri => "lr-" + crypto.createHash("sha256").update("leadradar:" + uri).digest("hex").slice(0, 10);
const LA_WEEK = "2027-01-18T08:00:00.000Z";   // Monday 18 January 2027 00:00 in Los Angeles

/* One member's world for /top: in the goal week (from LA_WEEK) and just before it (Monday 07:00 UTC, which is still
   Sunday in Los Angeles but already Monday in UTC). */
function world(goalRow) {
  const t = {};
  let k = 0; const id = p => p + "-" + String(++k).padStart(6, "0");
  const TEA = blogRef(USER, "tea-launch"), LEAD = outRef("at://did:plc:x/post/1");
  t.user_preferences = goalRow ? [Object.assign({ user_id: USER, termaximus_active: true, mist_position: "top-right", notifications_enabled: true, preferred_language: null, agent_card_order: null }, goalRow)] : [];
  t.content_library = [{ id: id("c"), user_id: USER, title: "Tea launch", slug: "tea-launch", status: "published", body: "?ref=" + TEA, created_at: at("2026-12-01T00:00:00Z") }];
  t.outreach_sends = [{ id: id("o"), user_id: USER, lead_post_uri: "at://did:plc:x/post/1" }];
  const visit = (ref, when) => ({ id: id("v"), ref, landing_path: "/", created_at: at(when) });
  t.engine_visits = [visit(TEA, "2027-01-18T09:00:00Z"), visit(TEA, "2027-01-19T12:00:00Z"), visit(LEAD, "2027-01-20T09:00:00Z"),
    visit(TEA, "2027-01-18T07:00:00Z"), visit(LEAD, "2027-01-17T20:00:00Z")];
  t.member_store_connections = [{ id: "conn-1", user_id: USER, platform: "shopify", status: "connected", currency: "USD", last_sync_at: at("2027-01-20T09:55:00Z") }];
  t.inventory_items = [];
  const order = (when, total, currency, status) => ({ id: id("so"), user_id: USER, connection_id: "conn-1", platform: "shopify", ordered_at: at(when), total, currency, status });
  t.store_order_summaries = [order("2027-01-18T10:00:00Z", 500, "USD", "active"), order("2027-01-19T10:00:00Z", 340, "USD", "active"),
    order("2027-01-19T11:00:00Z", 100, "USD", "cancelled"), order("2027-01-19T12:00:00Z", 60, "USD", "refunded"),
    order("2027-01-20T08:00:00Z", 45, "EUR", "active"), order("2027-01-18T07:00:00Z", 999, "USD", "active")];
  t.digital_cards = [{ id: "card-1", user_id: USER }];
  t.card_view_counts = [{ card_id: "card-1", day: "2027-01-18", views: 5 }, { card_id: "card-1", day: "2027-01-19", views: 4 }, { card_id: "card-1", day: "2027-01-17", views: 50 }];
  t.marketplace_orders = [{ id: id("m"), seller_id: USER, created_at: at("2027-01-18T09:00:00Z") }, { id: id("m"), seller_id: USER, created_at: at("2027-01-18T07:00:00Z") }];
  t.ai_tasks = [];
  return t;
}

const LIMITERS = [];
function server(tables) {
  const db = fakeDb(tables);
  const ctx = {
    supabase: db.client, JSON, Math, Promise, Object, Array, String, Number, isNaN, isFinite, Error, Map, Set, RegExp, URL, Intl,
    Date: movableDate(), crypto,
    require: name => name === "./lib/orbitStage2" ? S2 : name === "./lib/storeSync" ? SS : Module.createRequire(path.join(REPO, "server.js"))(name),
    process: { env: {} },
    console: { log() {}, error() {}, warn() {} },
    OWNER_ACCOUNT_ID: OWNER,
    publicCertificationCatalog: require(path.join(REPO, "lib/certificationCatalog")).publicCertificationCatalog,
    rateLimit: function (o) {
      const hits = new Map();
      LIMITERS.push(o);
      return function limiter(req, res, next) {
        const key = o.keyGenerator(req); const now = CLOCK.t;
        const h = (hits.get(key) || []).filter(x => now - x < o.windowMs); h.push(now); hits.set(key, h);
        if (h.length > o.max) return res.status(429).json(o.message);
        next();
      };
    },
    requireActiveSubscription: function requireActiveSubscription(req, res) { return res.status(402).json({ error: "subscription required" }); },
    requireAuth: function requireAuth(req, res, next) {
      if (!req.headers.user) return res.status(401).json({ error: "sign in" });
      req.user = { id: req.headers.user }; next();
    }
  };
  const routes = {};
  const reg = m => (p, ...h) => { routes[m + " " + p] = h; };
  ctx.app = { get: reg("get"), post: reg("post"), put: reg("put"), delete: reg("delete"), patch: reg("patch"), use() {}, _router: { stack: [] } };
  vm.createContext(ctx);
  LIFTED.runInContext(ctx);
  async function call(method, route, user, o) {
    o = o || {};
    const chain = routes[method + " " + route];
    if (!chain) throw new Error(method + " " + route + " not lifted");
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(J(x)); return this; } };
    const req = { headers: user ? { user } : {}, params: {}, query: o.query || {}, body: o.body || {} };
    let i = 0;
    async function step() {
      const fn = chain[i++]; if (!fn) return;
      let advanced = false;
      await fn(req, res, e => { if (e) { res.code = 500; res.body = { error: e.message }; return; } advanced = true; });
      if (advanced) await step();
    }
    await step();
    return res;
  }
  return { db, call, chain: (m, r) => routes[m + " " + r] || [], ctx };
}
const goalCols = g => ({ goal_metric: g.metric, goal_weekly_target: g.target, goal_currency: g.currency || null, goal_time_zone: g.zone, goal_set_at: "2027-01-10T00:00:00.000Z" });

(async () => {
  /* ── R. migration 183 ── */
  console.log("\n══ R. migration 183 as run ══");
  const SQL_LINES = [
    "ALTER TABLE public.user_preferences",
    "  ADD COLUMN IF NOT EXISTS goal_metric        text,",
    "  ADD COLUMN IF NOT EXISTS goal_weekly_target numeric(14,2),",
    "  ADD COLUMN IF NOT EXISTS goal_currency      text,",
    "  ADD COLUMN IF NOT EXISTS goal_time_zone     text,",
    "  ADD COLUMN IF NOT EXISTS goal_set_at        timestamptz;",
    "ALTER TABLE public.user_preferences ADD CONSTRAINT user_preferences_goal_check CHECK (",
    "ALTER TABLE public.store_order_summaries",
    "  ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';",
    "ALTER TABLE public.store_order_summaries ADD CONSTRAINT store_order_summaries_status_check",
    "  CHECK (status IN ('active', 'cancelled', 'refunded'));",
    "REVOKE ALL ON public.user_preferences FROM anon, authenticated;"
  ];
  const M = FILES[MIG];
  check("R. 183 as run: the owner's header first, then every statement", M.indexOf("-- Applied by the owner by hand in the Supabase SQL editor on Nov 11, 2026. This file is the text as run.\n") === 0 &&
    SQL_LINES.every(l => M.indexOf(l) !== -1) && /BEGIN;[\s\S]*COMMIT;\s*$/.test(M), SQL_LINES.filter(l => M.indexOf(l) === -1)[0]);
  const migFiles = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(x => /^\d{3}_.*\.sql$/.test(x));
  const highest = migFiles.map(x => Number(x.slice(0, 3))).reduce((a, x) => Math.max(a, x), 0);
  check("R1. 183_weekly_goal_and_order_status.sql is the highest migration, and the only 183", highest === 183 && migFiles.filter(x => /^183_/.test(x)).join() === "183_weekly_goal_and_order_status.sql", highest);
  const capOf = metric => { const m = new RegExp("goal_metric = '" + metric + "'[^\\n]*?BETWEEN 1 AND (\\d+)").exec(M) || new RegExp("goal_metric = '" + metric + "'[^\\n]*?<= (\\d+)").exec(M); return m ? Number(m[1]) : null; };
  check("R2. the goal caps are migration 183's (counts 100000, marketplace 10000, sales 100000000)",
    S2.GOAL_METRIC_KEYS.every(k => S2.GOAL_METRICS[k].cap === capOf(k)) && S2.GOAL_METRICS.store_sales.cap === 100000000 && S2.GOAL_METRICS.marketplace_orders.cap === 10000,
    J(S2.GOAL_METRIC_KEYS.map(k => [k, S2.GOAL_METRICS[k].cap, capOf(k)])));

  /* ── A. AGENT_PORTAL ── */
  console.log("\n══ A. every agent has a portal ══");
  const brain = require(path.join(REPO, "config/brain.js"));
  const agents = brain.PLATFORM_KNOWLEDGE.agents.map(a => a.key);
  const unmapped = agents.filter(a => !Object.prototype.hasOwnProperty.call(S2.AGENT_PORTAL, a));
  console.log("    AGENT_PORTAL: " + S2.PORTAL_KEYS.map(p => p + " = " + Object.keys(S2.AGENT_PORTAL).filter(a => S2.AGENT_PORTAL[a] === p).join(", ")).filter(x => !/= $/.test(x)).join("; "));
  check("A1. every agent in config/brain.js is in AGENT_PORTAL (" + agents.length + "), each to a portal", agents.length >= 19 && unmapped.length === 0 &&
    Object.keys(S2.AGENT_PORTAL).every(a => ["grow", "sell", "connect", "agents"].indexOf(S2.AGENT_PORTAL[a]) !== -1), unmapped.join(", "));
  check("A2. the architect's table: Sell sales, store, broker (and etsy); Connect social, email, community, influencer, publicist, reputation; Grow seo, content, analytics, ads, rd, vertical_marketing; Agents executive, operations, any other",
    ["sales", "store", "broker", "etsy"].every(a => S2.AGENT_PORTAL[a] === "sell") && ["social", "email", "community", "influencer", "publicist", "reputation"].every(a => S2.AGENT_PORTAL[a] === "connect") &&
    ["seo", "content", "analytics", "ads", "rd", "vertical_marketing"].every(a => S2.AGENT_PORTAL[a] === "grow") && ["executive", "operations", "general"].every(a => S2.AGENT_PORTAL[a] === "agents") &&
    S2.portalOfAgent("someone_new") === "agents", J(S2.AGENT_PORTAL));
  check("A3. the links are the six portal pairs an event can use", J(S2.linkPairs().slice().sort()) === J(["connect|agents", "grow|agents", "grow|connect", "grow|sell", "sell|agents", "sell|connect"]), J(S2.linkPairs()));

  /* ── G. the weekly goal ── */
  console.log("\n══ G. the weekly goal ══");
  const v = g => S2.validateGoal(g);
  const okGoal = { metric: "tracked_visits", weekly_target: 50, time_zone: "America/Los_Angeles" };
  check("G1. a count goal: whole, 1 to its cap; 100000 visits allowed, 100001 refused with the cap; 10000 marketplace orders, 10001 refused",
    !v(okGoal).error && !v(Object.assign({}, okGoal, { weekly_target: 100000 })).error && v(Object.assign({}, okGoal, { weekly_target: 100001 })).cap === 100000 &&
    !v({ metric: "marketplace_orders", weekly_target: 10000, time_zone: "UTC" }).error && !!v({ metric: "marketplace_orders", weekly_target: 10001, time_zone: "UTC" }).error &&
    !!v(Object.assign({}, okGoal, { weekly_target: 2.5 })).error && !!v(Object.assign({}, okGoal, { weekly_target: 0 })).error, J(v(Object.assign({}, okGoal, { weekly_target: 100001 }))));
  check("G2. store sales: a three-letter currency is required, at most 100000000 in two decimals; a count goal with a currency is refused",
    !v({ metric: "store_sales", weekly_target: 2000.5, currency: "USD", time_zone: "UTC" }).error && !!v({ metric: "store_sales", weekly_target: 2000, time_zone: "UTC" }).error &&
    !!v({ metric: "store_sales", weekly_target: 2000, currency: "usd", time_zone: "UTC" }).error && !!v({ metric: "store_sales", weekly_target: 100000001, currency: "USD", time_zone: "UTC" }).error &&
    !!v({ metric: "store_sales", weekly_target: 1.234, currency: "USD", time_zone: "UTC" }).error && !!v(Object.assign({}, okGoal, { currency: "USD" })).error,
    J(v({ metric: "store_sales", weekly_target: 2000, time_zone: "UTC" })));
  check("G3. the time zone must be real (UTC or a name such as America/New_York); unknown fields and metrics are refused",
    !!v(Object.assign({}, okGoal, { time_zone: "Mars/Olympus" })).error && !!v(Object.assign({}, okGoal, { time_zone: "" })).error && !v(Object.assign({}, okGoal, { time_zone: "UTC" })).error &&
    !!v(Object.assign({}, okGoal, { extra: 1 })).error && !!v(Object.assign({}, okGoal, { metric: "followers" })).error && v(Object.assign({}, okGoal, { metric: "followers" })).valid_goal_metrics.length === 5,
    J(v(Object.assign({}, okGoal, { time_zone: "Mars/Olympus" }))));
  {
    const sv = server({ user_preferences: [] });
    const r1 = await sv.call("put", "/api/user/preferences", USER, { body: { weekly_goal: { metric: "store_sales", weekly_target: 2000, currency: "USD", time_zone: "America/Los_Angeles" } } });
    const row = (sv.db.tables.user_preferences || [])[0] || {};
    check("G4. PUT weekly_goal saves the five columns (set_at now)", r1.code === 200 && row.goal_metric === "store_sales" && row.goal_weekly_target === 2000 && row.goal_currency === "USD" &&
      row.goal_time_zone === "America/Los_Angeles" && row.goal_set_at === new Date(CLOCK.t).toISOString(), J([r1, row]));
    const g = await sv.call("get", "/api/user/preferences", USER);
    check("G5. GET answers it as weekly_goal", J(g.body.weekly_goal) === J({ metric: "store_sales", weekly_target: 2000, currency: "USD", time_zone: "America/Los_Angeles", set_at: row.goal_set_at }), J(g.body.weekly_goal));
    const bad = [{ metric: "tracked_visits", weekly_target: 100001, time_zone: "UTC" }, { metric: "store_sales", weekly_target: 10, time_zone: "UTC" }, { metric: "tracked_visits", weekly_target: 5, time_zone: "Nowhere/Here" }];
    const refusals = [];
    for (const b of bad) refusals.push(await sv.call("put", "/api/user/preferences", USER, { body: { weekly_goal: b } }));
    check("G6. a refused goal is a 400 naming the field, and the stored goal is unchanged", refusals.every(r => r.code === 400 && typeof r.body.error === "string" && r.body.field) &&
      sv.db.tables.user_preferences[0].goal_metric === "store_sales" && sv.db.tables.user_preferences[0].goal_weekly_target === 2000, J(refusals.map(r => [r.code, r.body && r.body.field])));
    await sv.call("put", "/api/user/preferences", USER, { body: { notifications_enabled: false } });
    check("G7. a PUT without weekly_goal leaves it alone", sv.db.tables.user_preferences[0].goal_metric === "store_sales", J(sv.db.tables.user_preferences[0]));
    sv.ctx.__topCache.set(USER, { at: CLOCK.t, body: { x: 1 } }); sv.ctx.__topCache.set(OTHER, { at: CLOCK.t, body: { x: 2 } });
    await sv.call("put", "/api/user/preferences", USER, { body: { weekly_goal: null } });
    const cleared = sv.db.tables.user_preferences[0];
    check("G8. weekly_goal null clears all five columns, and clears this member's /top cache (no one else's)",
      ["goal_metric", "goal_weekly_target", "goal_currency", "goal_time_zone", "goal_set_at"].every(c => cleared[c] === null) && !sv.ctx.__topCache.has(USER) && sv.ctx.__topCache.has(OTHER), J(cleared));
    const g2 = await sv.call("get", "/api/user/preferences", USER);
    check("G9. GET then answers weekly_goal null", g2.body.weekly_goal === null, J(g2.body));
  }

  /* ── W. Monday 00:00 in the goal's zone ── */
  console.log("\n══ W. the week's start ══");
  const ws = (zone, iso) => new Date(S2.weekStartMs(zone, Date.parse(iso))).toISOString();
  const WEEKS = [
    ["America/Los_Angeles", "2027-01-20T10:20:00Z", "2027-01-18T08:00:00.000Z", "a winter week"],
    ["America/Los_Angeles", "2027-03-14T19:00:00Z", "2027-03-08T08:00:00.000Z", "Sunday after the spring change: the week began in standard time"],
    ["America/Los_Angeles", "2027-03-17T19:00:00Z", "2027-03-15T07:00:00.000Z", "the first week in daylight time"],
    ["America/Los_Angeles", "2026-11-01T20:00:00Z", "2026-10-26T07:00:00.000Z", "Sunday after the autumn change: the week began in daylight time"],
    ["America/Los_Angeles", "2026-11-04T20:00:00Z", "2026-11-02T08:00:00.000Z", "the first week back in standard time"],
    ["Asia/Tokyo", "2027-01-17T16:00:00Z", "2027-01-17T15:00:00.000Z", "Tokyo: Monday 01:00 local is still Sunday in UTC"],
    ["Pacific/Auckland", "2027-01-20T10:20:00Z", "2027-01-17T11:00:00.000Z", "Auckland in summer time (+13)"],
    ["UTC", "2027-01-20T10:20:00Z", "2027-01-18T00:00:00.000Z", "UTC"],
    ["Not/AZone", "2027-01-20T10:20:00Z", "2027-01-18T00:00:00.000Z", "an unknown zone is UTC"]
  ];
  WEEKS.forEach(([zone, now, want, what]) => check("W. " + zone + ", " + what + ": Monday 00:00 is " + want, ws(zone, now) === want, ws(zone, now)));
  const santiago = new Date(S2.localDayStartMs(2026, 9, 6, "America/Santiago")).toISOString();
  check("W. a skipped midnight (Santiago, 6 September 2026): the day starts at its first hour, 01:00 (04:00 UTC)", santiago === "2026-09-06T04:00:00.000Z", santiago);

  /* ── S. order status ── */
  console.log("\n══ S. order status ══");
  const st = SS.orderStatusOf;
  const STATUS_CASES = [
    ["shopify", { cancelled_at: "2027-01-19T00:00:00Z", financial_status: "PAID" }, "cancelled"], ["shopify", { cancelled_at: null, financial_status: "REFUNDED" }, "refunded"],
    ["shopify", { cancelled_at: null, financial_status: "PARTIALLY_REFUNDED" }, "active"], ["shopify", { cancelled_at: null, financial_status: "PAID" }, "active"],
    ["woocommerce", { status: "cancelled" }, "cancelled"], ["woocommerce", { status: "failed" }, "cancelled"], ["woocommerce", { status: "refunded" }, "refunded"], ["woocommerce", { status: "completed" }, "active"],
    ["etsy", { status: "Canceled" }, "cancelled"], ["etsy", { status: "Fully Refunded" }, "refunded"], ["etsy", { status: "Partially Refunded" }, "active"], ["etsy", { status: "Completed" }, "active"],
    ["amazon", { order_status: "Canceled" }, "cancelled"], ["amazon", { order_status: "Shipped" }, "active"]
  ];
  const wrong = STATUS_CASES.filter(c => st(c[0], c[1]) !== c[2]);
  check("S1. each platform's states: Shopify cancelledAt and REFUNDED, WooCommerce cancelled, failed and refunded, Etsy Canceled and Fully Refunded, Amazon Canceled; anything else active",
    wrong.length === 0 && SS.ORDER_STATUSES.join() === "active,cancelled,refunded", J(wrong.map(c => c.concat([st(c[0], c[1])]))));
  const wk = S2.storeWeek([{ ordered_at: "2027-01-19T00:00:00Z", total: 500, currency: "USD", status: "active" }, { ordered_at: "2027-01-19T00:00:00Z", total: 340, currency: "USD", status: "active" },
    { ordered_at: "2027-01-19T00:00:00Z", total: 100, currency: "USD", status: "cancelled" }, { ordered_at: "2027-01-19T00:00:00Z", total: 60, currency: "USD", status: "refunded" },
    { ordered_at: "2027-01-19T00:00:00Z", total: 45, currency: "EUR", status: "active" }], Date.parse(LA_WEEK), "USD");
  check("S2. storeWeek counts active orders only, sums only the goal's currency (840 USD), and lists the rest as not counted, never converted",
    wk.orders === 3 && wk.sales === 840 && J(wk.not_counted) === J([{ currency: "EUR", orders: 1, total: 45 }]), J(wk));

  /* ── T. /top's goal ── */
  console.log("\n══ T. GET /api/dashboard/top's goal ══");
  const topFor = async (goal, tweak) => { const t = world(goal ? goalCols(goal) : null); if (tweak) tweak(t); const sv = server(t); const r = await sv.call("get", "/api/dashboard/top", USER); return { r, sv }; };
  let T = await topFor({ metric: "tracked_visits", target: 50, zone: "America/Los_Angeles" });
  check("T1. tracked visits from bl- and lr- refs since Monday 00:00 in Los Angeles: 3 (the 07:00 UTC Monday visit is still Sunday there)",
    T.r.code === 200 && T.r.body.goal.set === true && T.r.body.goal.value === 3 && T.r.body.goal.target === 50 && T.r.body.goal.week_start === LA_WEEK && T.r.body.goal.time_zone === "America/Los_Angeles", J(T.r.body.goal));
  check("T2. the goal answer names the suggested metric, the store's currencies and the stores (id, platform, currency, last sync)",
    T.r.body.goal.suggested === "store_sales" && J(T.r.body.goal.store_currencies) === J(["USD"]) && J(T.r.body.goal.stores) === J([{ id: "conn-1", platform: "shopify", currency: "USD", last_sync_at: "2027-01-20T09:55:00.000Z" }]), J(T.r.body.goal));
  T = await topFor({ metric: "store_sales", target: 2000, currency: "USD", zone: "America/Los_Angeles" });
  check("T3. store sales: 840 USD (cancelled and refunded not counted), the EUR order listed as not counted, as of the last sync",
    T.r.body.goal.value === 840 && J(T.r.body.goal.not_counted) === J([{ currency: "EUR", orders: 1, total: 45 }]) && T.r.body.goal.as_of === "2027-01-20T09:55:00.000Z" && T.r.body.store.as_of === "2027-01-20T09:55:00.000Z", J(T.r.body.goal));
  const orderRead = T.sv.db.log.find(q => q.table === "store_order_summaries");
  check("T4. the orders read asks for status active (every reader counts only active orders)", !!orderRead && orderRead.filters.some(f => f[0] === "eq" && f[1] === "status" && f[2] === "active"), J(orderRead && orderRead.filters));
  const activeIn14 = world(null).store_order_summaries.filter(o => o.status === "active").length;
  check("T5. the orders figures count active orders only (" + activeIn14 + " in the 14 days, not the cancelled or refunded)", T.r.body.store.orders_per_day.reduce((a, b) => a + b, 0) === activeIn14, J(T.r.body.store));
  T = await topFor({ metric: "store_orders", target: 10, zone: "America/Los_Angeles" });
  check("T6. store orders: 3 active orders this week in Los Angeles", T.r.body.goal.value === 3 && T.r.body.goal.as_of === "2027-01-20T09:55:00.000Z", J(T.r.body.goal));
  T = await topFor({ metric: "card_visits", target: 100, zone: "America/Los_Angeles" });
  check("T7. card visits by UTC day from the one the week begins in (18 January): 9, with the note word for word",
    T.r.body.goal.value === 9 && T.r.body.goal.note === "Card visits are counted by UTC day, so this week's count starts with the UTC day your week begins in.", J(T.r.body.goal));
  T = await topFor({ metric: "marketplace_orders", target: 5, zone: "America/Los_Angeles" });
  check("T8. marketplace orders since Monday 00:00 in Los Angeles: 1", T.r.body.goal.value === 1, J(T.r.body.goal));
  T = await topFor({ metric: "tracked_visits", target: 50, zone: "America/Los_Angeles" }, t => { t.engine_visits = "FAIL"; });
  check("T9. a goal whose figure could not be read is null, never 0, and named in _unreadable", T.r.body.goal.set === true && T.r.body.goal.value === null && T.r.body._unreadable.indexOf("goal") !== -1, J([T.r.body.goal, T.r.body._unreadable]));
  T = await topFor(null);
  check("T10. no goal: set false, no value, the suggestion", T.r.body.goal.set === false && T.r.body.goal.value === null && T.r.body.goal.suggested === "store_sales", J(T.r.body.goal));
  T = await topFor(null, t => { t.user_preferences = "FAIL"; });
  check("T11. the goal row unreadable: goal null (the page then offers no setter), the rest still answered", T.r.body.goal === null && T.r.body.visits && T.r.body.visits.this_week !== null, J(T.r.body.goal));

  /* ── P. the pulse ── */
  console.log("\n══ P. GET /api/dashboard/pulse ══");
  const AGENTS = Object.keys(S2.AGENT_PORTAL).filter(a => a !== "general");
  const pulseWorld = () => {
    const t = {};
    t.ai_tasks = AGENTS.slice(0, 13).map((a, i) => ({ id: "run-" + i, user_id: USER, agent_type: a, task_type: a + "/x", status: "processing", created_at: minsAgo(2 + i * 0.1) }))
      .concat([{ id: "done-1", user_id: USER, agent_type: "seo", task_type: "seo/audit", status: "completed", created_at: minsAgo(30), completed_at: minsAgo(6) },
        { id: "done-old", user_id: USER, agent_type: "seo", task_type: "seo/audit", status: "completed", created_at: minsAgo(2000), completed_at: minsAgo(30 * 60) },
        { id: "theirs", user_id: OTHER, agent_type: "sales", task_type: "x", status: "processing", created_at: minsAgo(1) }]);
    t.agent_proposals = [{ id: "p1", user_id: USER, agent_type: "social", action_type: "publish_social_post", status: "executed", executed_at: minsAgo(5) },
      { id: "p2", user_id: USER, agent_type: "email", action_type: "send_email_sequence", status: "executed", executed_at: minsAgo(4.5) }];
    t.store_change_log = [{ id: "sc1", user_id: USER, executed_at: minsAgo(4) }];
    t.card_leads = [{ id: "cl1", user_id: USER, created_at: minsAgo(3) }];
    t.social_post_drafts = [{ id: "sd1", user_id: USER, status: "published", published_at: minsAgo(2) }];
    t.instagram_posts = []; t.facebook_posts = []; t.member_videos = [];
    t.content_library = [{ id: "a1", user_id: USER, published_at: minsAgo(1), external_published_at: null }];
    return t;
  };
  let sv = server(pulseWorld());
  const chain = sv.chain("get", "/api/dashboard/pulse").map(f => f.name);
  check("P1. requireAuth and a 6-a-minute per-member limiter, and NOT requireActiveSubscription", chain[0] === "requireAuth" && chain.indexOf("requireActiveSubscription") === -1 &&
    LIMITERS.some(o => o.max === 6 && o.windowMs === 60000 && o.keyGenerator({ user: { id: USER } }) === "dashboard-pulse:" + USER), J(chain));
  const unauth = await sv.call("get", "/api/dashboard/pulse", null);
  check("P2. signed out: 401", unauth.code === 401, unauth.code);
  let p = await sv.call("get", "/api/dashboard/pulse", USER);
  check("P3. read-only: no write of any kind", sv.db.writes.length === 0, J(sv.db.writes));
  check("P4. no since: no events (the page's first pulse sparks nothing old), and the running agents", p.code === 200 && p.body.events.length === 0 && p.body.since === new Date(CLOCK.t).toISOString(), J(p.body).slice(0, 300));
  check("P5. running: at most 12, each the member's own agent with its portal and start", p.body.running.length === 12 && p.body.running.every(r => S2.portalOfAgent(r.agent) === r.portal && typeof r.started_at === "string") &&
    p.body.running.every(r => AGENTS.indexOf(r.agent) !== -1), J(p.body.running).slice(0, 300));
  const reads = sv.db.log.filter(q => !q.write);
  console.log("    the pulse's reads: " + reads.length + " (" + reads.map(q => q.table).join(", ") + ")");
  check("P6. bounded: every read is the member's own, limited (running from 50, events the newest 20) and, for events, within 24 hours",
    reads.length === 12 && reads.every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === USER) && q.filters.some(f => f[0] === "limit" && f[1] <= 50)) &&
    reads.filter(q => q.filters.some(f => f[0] === "limit" && f[1] === 20)).length === 11 &&
    reads.filter(q => q.filters.some(f => f[0] === "limit" && f[1] === 20)).every(q => q.filters.some(f => f[0] === "gte" && String(f[2]) >= new Date(CLOCK.t - 86400000).toISOString())),
    J(reads.map(q => [q.table, q.filters])).slice(0, 400));
  check("P7. links: the six pairs", J(p.body.links.slice().sort()) === J(S2.linkPairs().slice().sort()), J(p.body.links));
  CLOCK.t += 1000;
  const before = sv.db.log.length;
  p = await sv.call("get", "/api/dashboard/pulse", USER, { query: { since: minsAgo(4.6) } });
  check("P8. cached 15 s per member: a second pulse reads nothing", p.body.cached === true && sv.db.log.length === before, J([p.body.cached, sv.db.log.length - before]));
  const other = await sv.call("get", "/api/dashboard/pulse", OTHER);
  check("P9. another member's pulse is their own (never this member's cache)", other.body.cached === false && other.body.running.length === 1 && other.body.running[0].agent === "sales", J(other.body.running));
  const types = p.body.events.map(e => e.type);
  check("P10. events after since, oldest first: the email proposal (agent to its channel's portal), the store change, the card lead, the post, the article; the Bluesky publish proposal once, as its post",
    J(types) === J(["proposal_executed", "store_change", "card_lead", "post_published", "article_published"]) &&
    J(p.body.events.map(e => [e.portal_from, e.portal_to])) === J([["connect", S2.portalOfAction("send_email_sequence")], ["agents", "sell"], ["core", "connect"], ["core", "connect"], ["core", "grow"]]) &&
    p.body.events.every((e, i, a) => i === 0 || a[i - 1].at <= e.at), J(p.body.events));
  CLOCK.t += 16000;
  p = await sv.call("get", "/api/dashboard/pulse", USER, { query: { since: new Date(CLOCK.t - 3 * 86400000).toISOString() } });
  check("P11. after 15 s it reads again; since is at most 24 hours back (the 30-hour-old run is not an event)", p.body.cached === false && p.body.since === new Date(CLOCK.t - 86400000).toISOString() &&
    p.body.events.filter(e => e.type === "agent_run").length === 1 && p.body.events.length === 6, J([p.body.since, p.body.events.map(e => e.type)]));
  const lead = i => ({ id: "cl-x" + i, user_id: USER, created_at: minsAgo(60 + i) });
  const busy = pulseWorld(); busy.card_leads = Array.from({ length: 25 }, (_, i) => lead(i));
  sv = server(busy);
  p = await sv.call("get", "/api/dashboard/pulse", USER, { query: { since: minsAgo(23 * 60) } });
  check("P12. at most 20 events, the newest last", p.body.events.length === 20 && p.body.events[19].at === minsAgo(1) && p.body.events.every((e, i, a) => i === 0 || a[i - 1].at <= e.at), p.body.events.length);
  const lim = server(pulseWorld()); const codes = [];
  for (let i = 0; i < 7; i++) { CLOCK.t += 5000; codes.push((await lim.call("get", "/api/dashboard/pulse", USER)).code); }
  check("P13. the seventh pulse in a minute is refused (429)", codes.slice(0, 6).every(c => c === 200) && codes[6] === 429, J(codes));
  CLOCK.t = NOW;

  /* ── D. Your data ── */
  console.log("\n══ D. Your data ══");
  const YD = require(path.join(REPO, "lib/yourData.js"));
  const prefs = (YD.DATA || []).find(e => e.table === "user_preferences"), sums = (YD.DATA || []).find(e => e.table === "store_order_summaries");
  check("D1. the export carries the weekly goal's five fields and each order's status", !!prefs && ["goal_metric", "goal_weekly_target", "goal_currency", "goal_time_zone", "goal_set_at"].every(c => prefs.select.indexOf(c) !== -1) &&
    !!sums && /\bstatus\b/.test(sums.select), J([prefs && prefs.select, sums && sums.select]));
  // The "what" sentence builds privacy.html (checkLegalPages A1), so stage 2 leaves it as published: the owner words any change.
  check("D2. the order summaries' description is the published one (privacy.html unchanged)", !!sums && sums.what.indexOf("its date, total and currency, and its items as SKU and quantity") !== -1, sums && sums.what);

  /* ── F. the page ── */
  console.log("\n══ F. the page (jsdom) ══");
  let JSDOM;
  try { ({ JSDOM } = require("jsdom")); } catch (e) { check("jsdom could be loaded", false, e.message); return finish(); }
  const a0 = FILES[DASH].indexOf("<style id=\"orbitStyle\">"), b0 = FILES[DASH].indexOf("</template>") + "</template>".length;
  const MARKUP = FILES[DASH].slice(a0, b0);
  const TOP = goal => ({ generated_at: "2027-01-20T10:20:00.000Z", visits: { per_day: Array(14).fill(1), this_week: 29, last_week: 6, tracked: true },
    store: { connected: true, low_stock: { count: 0, names: [] }, orders_this_week: 3, orders_per_day: Array(14).fill(0), as_of: "2027-01-20T09:55:00.000Z" },
    proposals_pending: 0, counts: {}, agents: { running_now: [] }, _unreadable: [], cached: false,
    goal: goal === undefined ? { set: false, suggested: "store_sales", store_currencies: ["USD"], stores: [{ id: "conn-1", platform: "shopify", currency: "USD", last_sync_at: "2027-01-20T09:55:00.000Z" }] } : goal });
  const GOAL = (o) => Object.assign({ set: true, metric: "tracked_visits", target: 50, currency: null, time_zone: "UTC", value: 12, suggested: "store_sales", store_currencies: ["USD"], stores: [{ id: "conn-1", platform: "shopify", currency: "USD", last_sync_at: null }] }, o);
  function page(o) {
    o = o || {};
    const dom = new JSDOM("<!DOCTYPE html><html><head></head><body>" + MARKUP + "</body></html>", { url: "https://bizforceai.net/dashboard.html", runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window;
    try { w.localStorage.setItem("bf_token", "check-token"); } catch (e) { /* none */ }
    const fetches = [];
    w.API_URL = "https://api.test";
    w.fetch = (url, init) => {
      fetches.push({ url: String(url), method: (init && init.method) || "GET", body: init && init.body });
      const u = String(url);
      const body = /\/api\/dashboard\/pulse/.test(u) ? (o.pulse ? o.pulse() : {}) : /\/api\/dashboard\/top/.test(u) ? JSON.parse(J(o.top || TOP())) : { ok: true };
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
    };
    const frames = [];
    w.requestAnimationFrame = cb => { frames.push(cb); return frames.length; };
    w.cancelAnimationFrame = () => {};
    w.matchMedia = q => ({ matches: (/reduced-motion: reduce/.test(q) && !!o.reduce) || (/max-width: 640px/.test(q) && !!o.narrow), addEventListener() {}, addListener() {} });
    Object.defineProperty(w.HTMLElement.prototype, "clientWidth", { configurable: true, get() { return this.id === "orbitStage" ? 680 : 0; } });
    const io = [];
    w.IntersectionObserver = function (cb) { io.push(cb); this.observe = () => {}; this.disconnect = () => {}; };
    let hidden = false;
    Object.defineProperty(w.document, "hidden", { configurable: true, get: () => hidden });
    let err = null;
    try { w.eval(FILES[ORBIT]); } catch (e) { err = e; }
    let clock = 0;
    function run(ms) { const end = clock + ms; while (clock < end) { clock += 16; const q = frames.splice(0); if (!q.length) { clock = end; break; } q.forEach(cb => cb(clock)); } }
    return { w, d: w.document, O: w.BFOrbit, fetches, err, run, io, setHidden: x => { hidden = !!x; }, close: () => w.close() };
  }
  const settle = () => new Promise(r => setTimeout(r, 30));
  const coreOf = d => {
    const c = d.getElementById("orbitCore"), a = d.querySelector(".orbit-goal-arc"), deco = d.querySelector(".orbit-core-arc");
    return { figure: c.querySelector(".orbit-core-figure").hidden ? "" : c.querySelector(".orbit-core-figure").textContent, unit: c.querySelector(".orbit-core-unit").textContent,
      met: !c.querySelector(".orbit-core-met").hidden, asof: c.querySelector(".orbit-core-asof").hidden ? "" : c.querySelector(".orbit-core-asof").textContent,
      arc: a.style.display !== "none", dash: a.getAttribute("stroke-dasharray"), deco: deco.style.display !== "none", btn: d.getElementById("orbitGoalSet").textContent,
      btnHidden: d.getElementById("orbitGoalSet").hidden, title: c.getAttribute("title") || "" };
  };
  let P = page({ top: TOP(GOAL()) }); await settle();
  let c = coreOf(P.d);
  check("F1. a goal of 12 of 50: 12, \"of 50 tracked visits\", the arc at 24 of 100, the fixed arc gone, \"Edit weekly goal\"", !P.err && c.figure === "12" && c.unit === "of 50 tracked visits" && c.arc && c.dash === "24 100" && !c.deco && !c.met && c.btn === "Edit weekly goal", J(c) + (P.err ? P.err.message : ""));
  P.close();
  P = page({ top: TOP(GOAL({ value: null })) }); await settle();
  c = coreOf(P.d);
  check("F2. a goal whose value is null: \"Unavailable\", no number, no arc (never 0)", c.figure === "" && c.unit === "Unavailable" && !c.arc && !c.deco, J(c));
  P.close();
  P = page({ top: TOP() }); await settle();
  c = coreOf(P.d);
  check("F3. no goal: the core as before (29 tracked visits), the fixed arc, no goal arc, \"Set a weekly goal\"", c.figure === "29" && c.unit === "tracked visits" && c.deco && !c.arc && c.btn === "Set a weekly goal" && !c.btnHidden, J(c));
  P.close();
  P = page({ top: TOP(GOAL({ value: 60 })) }); await settle();
  c = coreOf(P.d);
  check("F4. 60 of 50: the arc whole (100 of 100) and \"Goal met\"", c.dash === "100 100" && c.met && c.arc, J(c));
  P.close();
  P = page({ top: TOP(GOAL({ metric: "store_sales", target: 2000, currency: "USD", value: 840, not_counted: [{ currency: "EUR", orders: 1, total: 45 }], as_of: "2027-01-20T09:55:00.000Z" })) }); await settle();
  c = coreOf(P.d);
  const storeBox = P.d.querySelector("#orbitMain [data-card=\"store\"]");
  check("F5. store sales: 840 \"of 2000 USD\", 42 of 100, \"As of\", the not-counted line on the core and in the Store box with Sync now",
    c.figure === "840" && c.unit === "of 2000 USD" && c.dash === "42 100" && /^As of /.test(c.asof) && c.title === "Other currencies not counted: 1 order in EUR (45.00)" &&
    !!storeBox && (storeBox.querySelector(".orbit-not-counted") || {}).textContent === c.title && (storeBox.querySelector(".orbit-sync") || {}).textContent === "Sync now", J(c));
  P.close();
  P = page({ top: TOP(GOAL({ metric: "card_visits", target: 100, value: 9, note: S2.CARD_VISITS_NOTE })) }); await settle();
  check("F6. card visits: the note as the core's tooltip", P.d.getElementById("orbitCore").getAttribute("title") === S2.CARD_VISITS_NOTE);
  P.close();

  // The setter.
  P = page({ top: TOP() }); await settle();
  P.O.openGoal();
  const dlg = P.d.getElementById("orbitGoalDialog"), box = dlg && dlg.querySelector("[role=dialog]");
  const radios = box ? Array.from(box.querySelectorAll("input[name=orbitGoalMetric]")) : [];
  check("F7. the setter: an ARIA modal dialog, the five metrics by plain name, the suggested one chosen, the week's reset in this device's zone",
    !!box && !dlg.hidden && box.getAttribute("aria-modal") === "true" && radios.map(r => r.parentNode.querySelector(".orbit-goal-name").textContent).join() === "Tracked visits,Store orders,Store sales,Card visits,Marketplace orders" &&
    (radios.find(r => r.checked) || {}).value === "store_sales" && /^Week resets Monday 00:00, \S+$/.test(box.querySelector("#orbitGoalWeek").textContent), box && box.textContent);
  radios[0].checked = true; box.querySelector("#orbitGoalTarget").value = "7.5";
  const r1 = P.O.readGoalForm();
  box.querySelector("#orbitGoalTarget").value = "7";
  const r2 = P.O.readGoalForm();
  check("F8. a count target must be whole; a whole one becomes { metric, weekly_target, time_zone }", !!r1.error && !r2.error && r2.goal.metric === "tracked_visits" && r2.goal.weekly_target === 7 && typeof r2.goal.time_zone === "string" && !("currency" in r2.goal), J([r1, r2]));
  box.dispatchEvent(new P.w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  check("F9. Escape closes it", dlg.hidden === true);
  P.close();
  P = page({ top: Object.assign(TOP(), { store: { connected: false }, goal: { set: false, suggested: "tracked_visits", store_currencies: [], stores: [] } }) }); await settle();
  P.O.openGoal();
  const dis = Array.from(P.d.querySelectorAll("input[name=orbitGoalMetric]")).filter(r => r.disabled).map(r => r.value);
  const hints = Array.from(P.d.querySelectorAll(".orbit-goal-hint")).filter(h => !h.hidden).map(h => h.textContent);
  check("F10. with no store the store metrics are disabled, each with \"Connect a store first\"", dis.join() === "store_orders,store_sales" && hints.join() === "Connect a store first,Connect a store first", J([dis, hints]));
  P.close();

  // Satellites.
  P = page({ top: TOP() }); await settle();
  P.O.drawSatellites(["seo", "sales", "social"].map((a, i) => ({ agent: a, started_at: "2027-01-20T10:00:00Z", portal: ["grow", "sell", "connect"][i] })));
  const sats3 = Array.from(P.d.querySelectorAll(".orbit-sat")).map(g => [g.getAttribute("data-portal"), g.querySelector("circle").getAttribute("cx")]);
  check("F11. a satellite for each running agent, on r 58, coloured by its portal", J(sats3) === J([["grow", "58"], ["sell", "58"], ["connect", "58"]]) && P.O.SAT.r === 58, J(sats3));
  P.O.drawSatellites(Array.from({ length: 11 }, (_, i) => ({ agent: "a" + i, started_at: "2027-01-20T10:00:00Z", portal: "agents" })));
  const live = Array.from(P.d.querySelectorAll(".orbit-sat")).filter(g => !g.getAttribute("data-leaving")).length;
  check("F12. 11 running: 8 satellites and \"+3\"; the Agents disc counts 11", live === 8 && P.d.querySelector(".orbit-sats-more").textContent === "+3" && P.d.getElementById("orbitSatCount").textContent === "11", J([live, P.d.querySelector(".orbit-sats-more").textContent]));
  P.close();

  // Links never within the core's r 66 (the ring's frame squashed to the ellipse).
  P = page({ top: TOP() }); await settle();
  const V = P.O.VIEW, k = V.ry / V.rx;
  const minR = (pts) => { let best = 1e9; for (let i = 1; i < pts.length; i++) for (let s2 = 0; s2 <= 200; s2++) { const f = s2 / 200, x = pts[i - 1][0] + (pts[i][0] - pts[i - 1][0]) * f, y = pts[i - 1][1] + (pts[i][1] - pts[i - 1][1]) * f; best = Math.min(best, Math.hypot(x, k * y)); } return best; };
  const linkMins = S2.linkPairs().map(pr => [pr, +minR(P.O.linkPoints(pr.split("|")[0], pr.split("|")[1])).toFixed(1)]);
  check("F13. every link bends through r 175 and keeps out of the core's r 66 (the stars' clearance) at every turn of the ring", P.O.LINK_BEND_R === 175 && P.O.CORE_KEEP_R === 66 && linkMins.every(m => m[1] > 66), J(linkMins));
  check("F14. the stars keep r 66 round the core (the satellites' r 58 and their dots)", /g\.circles\.push\(\{ x: ox \+ VIEW\.cx \* scale, y: oy \+ VIEW\.cy \* scale, r: CORE_KEEP_R \* scale \}\);/.test(FILES[ORBIT]));
  P.close();

  // Sparks.
  const NOWE = () => new Date(Date.now() + 5000).toISOString();
  P = page({ top: TOP() }); await settle();
  await P.O.pulse(); await settle();
  const old = { type: "card_lead", agent: null, portal_from: "core", portal_to: "connect", at: new Date(Date.now() - 3600000).toISOString() };
  P.O.sparkFor(old);
  check("F15. an event from before the page loaded sends no spark", P.d.querySelectorAll(".orbit-link-spark").length === 0);
  P.O.sparkFor({ type: "proposal_executed", agent: "seo", portal_from: "grow", portal_to: "connect", at: NOWE() });
  const sp = P.d.querySelector(".orbit-link-spark");
  check("F16. an event after load sends a spark from Grow to Connect", !!sp && sp.getAttribute("data-link") === "grow|connect", sp && sp.outerHTML.slice(0, 200));
  P.run(1400);
  check("F17. about 1.2 s later it is gone", P.d.querySelectorAll(".orbit-link-spark").length === 0);
  const far = ["grow", "sell", "connect", "agents", "oracle"].filter(x => x !== P.O.state.open)[1];
  P.O.open(far);
  const turning = !!P.O.state.turn;
  for (let i = 0; i < 5; i++) P.O.sparkFor({ type: "store_change", agent: null, portal_from: "agents", portal_to: "sell", at: new Date(Date.now() + 6000 + i).toISOString() });
  const during = P.d.querySelectorAll(".orbit-link-spark").length, queued = P.O.pulseState.queue.length;
  P.run(700);
  const afterTurn = P.d.querySelectorAll(".orbit-link-spark").length;
  check("F18. never during a turn: 5 events wait as the newest 3, and fly when the turn ends", turning && during === 0 && queued === 3 && afterTurn === 3, J([turning, during, queued, afterTurn]));
  P.close();
  P = page({ top: TOP(), reduce: true }); await settle();
  await P.O.pulse(); await settle();
  P.d.querySelector(".orbit-links").appendChild(P.d.createElementNS("http://www.w3.org/2000/svg", "path")).setAttribute("data-link", "x");
  P.O.sparkFor({ type: "proposal_executed", agent: "seo", portal_from: "grow", portal_to: "connect", at: NOWE() });
  check("F19. reduced motion: no moving spark, the portal highlighted instead", P.d.querySelectorAll(".orbit-link-spark").length === 0 && P.d.querySelector(".orbit-portal[data-portal=\"connect\"]").classList.contains("is-lit"));
  P.close();

  // The pulse: only while visible and on the screen.
  P = page({ top: TOP() }); await settle();
  const pulses = () => P.fetches.filter(f => /\/api\/dashboard\/pulse/.test(f.url)).length;
  const p0 = pulses();
  P.setHidden(true); await P.O.pulse(); await settle();
  const p1 = pulses();
  P.setHidden(false); P.io.forEach(cb => cb([{ isIntersecting: false }])); await P.O.pulse(); await settle();
  const p2 = pulses();
  P.io.forEach(cb => cb([{ isIntersecting: true }])); await settle(); await P.O.pulse(); await settle();
  const p3 = pulses();
  check("F20. the pulse is read on load, never while the tab is hidden or the orbit off the screen, and again when it is back",
    p0 === 1 && p1 === 1 && p2 === 1 && p3 >= 2 && P.O.PULSE_MS === 30000, J([p0, p1, p2, p3]));
  P.close();

  // The stars: never laid out again by hover or click.
  P = page({ top: TOP(GOAL()) }); await settle();
  const starsNow = () => Array.from(P.d.getElementById("orbitStars").childNodes);
  const s0 = starsNow();
  ["orbitCore", "orbitGoalSet"].forEach(idn => { const n = P.d.getElementById(idn); ["mouseenter", "mouseover", "focus"].forEach(t => n.dispatchEvent(new P.w.MouseEvent(t, { bubbles: t === "mouseover" }))); });
  P.d.getElementById("orbitGoalSet").click();
  P.d.getElementById("orbitGoalDialog").querySelector("[role=dialog]").dispatchEvent(new P.w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  P.d.querySelector(".orbit-portal[data-portal=\"grow\"]").click(); P.run(700);
  P.O.drawSatellites([{ agent: "seo", started_at: "2027-01-20T10:00:00Z", portal: "grow" }]);
  const s1 = starsNow();
  check("F21. hovering the core and the goal button, the dialog, a portal's turn and satellites leave the stars' nodes as they were", s0.length > 0 && s1.length === s0.length && s1.every((n, i) => n === s0[i]), J([s0.length, s1.length]));
  P.close();

  /* ── no new package, env var or CDN ── */
  console.log("\n══ nothing new outside the code ══");
  const changed = (() => { try { return execFileSync("git", ["diff", "--name-only", "HEAD", "--", "package.json", "package-lock.json"], { cwd: REPO }).toString().trim(); } catch (e) { return "git failed"; } })();
  check("N1. no new package (package.json and package-lock.json as committed)", changed === "", changed);
  check("N2. no new environment variable: lib/orbitStage2.js reads none, and the new server code reads none",
    !/process\.env/.test(FILES[S2F]) && !/process\.env/.test(routeText("get", "/api/dashboard/pulse") + (definitionOf("dashboardPulseBody") || "")), "");
  finish();
})();

function finish() {
  if (failures) { console.log("\nCHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("\nALL " + passes + " CHECKS PASSED");
  process.exit(0);
}
