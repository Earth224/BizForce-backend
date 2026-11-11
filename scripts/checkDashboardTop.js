"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkDashboardTop — GET /api/dashboard/top (Nov 10 2026, orbit top half).

   The dashboard's orbit, main boxes and portal grid draw their live figures
   from ONE read-only route. This check lifts the route out of server.js (with
   every server.js helper it calls) into a vm over an in-memory database, on a
   fixed clock, and proves:

     A  the guards: requireAuth and a 60-a-minute per-member limiter, and NOT
        requireActiveSubscription: a lapsed member gets their own figures;
     B  read-only: no write of any kind, no task row, no model or external call;
     C  scoped: every query is the caller's own rows; Lead Radar's bsky_leads
        (no owner column) is read for the owner account only;
     D  bounded: every list read is paged with a cap or limited; counts are
        head counts;
     E  visits: 14 UTC days through the member's own refs, blog AND outreach,
        this week against last week, tracked;
     F  store: connected, low stock over EVERY inventory row (names capped at
        5), and orders from store_order_summaries by ordered_at;
     G  cards in ONE card_view_counts read; certifications, wallet,
        marketplace, self-reviews, counts, media, agents running now;
     H  null when unreadable, never 0, with the reason in _unreadable;
     I  the mailbox is { connected } and nothing else: no unread count;
     J  the 60-second cache is per member.

   MUTATE=<name> edits server.js IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const SERVER = "server.js";
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the route records an ai_tasks row, like POST /api/agents/analytics/arrivals (B)
  "top-starts-a-task": [[SERVER, "    var body = await dashboardTopBody(userId, now);\n",
    "    await supabase.from(\"ai_tasks\").insert({ user_id: userId, agent_type: \"analytics\", task_type: \"dashboard/top\", status: \"completed\" });\n    var body = await dashboardTopBody(userId, now);\n"]],
  // the running-now read loses its cap (D)
  "top-unbounded": [[SERVER, "      .limit(DASHBOARD_TOP_RUNNING_CAP), \"running now\").data || [];", "      , \"running now\").data || [];"]],
  // Lead Radar's leads read for every member (C)
  "top-other-member": [[SERVER, "  if (userId === OUTREACH_CREDENTIAL_OWNER_ID) {\n    counts.leads = await figure(", "  if (true) {\n    counts.leads = await figure("]],
  // the outreach refs left out of visits (E)
  "visits-blog-only": [[SERVER, "    [loaded.posts, loaded.sends, loaded.visits].forEach(function (part) { if (part.reason) throw new Error(part.reason); });\n",
    "    [loaded.posts, loaded.sends, loaded.visits].forEach(function (part) { if (part.reason) throw new Error(part.reason); });\n" +
    "    var blogOnly = {}; loaded.posts.rows.forEach(function (p) { if (p.tracked) blogOnly[p.ref] = true; });\n" +
    "    loaded.visits.rows = loaded.visits.rows.filter(function (v) { return blogOnly[v.ref] === true; });\n"]],
  // orders counted from the marketplace instead of the member's store (F)
  "orders-from-wrong-table": [[SERVER, "      return supabase.from(\"store_order_summaries\").select(\"id, ordered_at\").eq(\"user_id\", userId).gte(\"ordered_at\", days[0]);",
    "      return supabase.from(\"marketplace_orders\").select(\"id, created_at\").eq(\"seller_id\", userId).gte(\"created_at\", days[0]);"],
    [SERVER, "    return dashboardTopPerDay(rows.map(function (r) { return r.ordered_at; }), days);", "    return dashboardTopPerDay(rows.map(function (r) { return r.created_at; }), days);"]],
  // low stock read from the first page only (F)
  "low-stock-paged-miss": [[SERVER, "    var items = await arrivalsReadAll(\"inventory_items\", function () {\n      return supabase.from(\"inventory_items\")",
    "    var items = await (async function (b) { return commandCenterRead(await b().order(\"id\", { ascending: true }).range(0, 999), \"inventory\").data || []; })(function () {\n      return supabase.from(\"inventory_items\")"]],
  // one card_view_counts read per card (G)
  "cards-per-card-requests": [[SERVER, "    var viewRows = commandCenterRead(await supabase\n      .from(\"card_view_counts\")\n      .select(\"card_id, day, views\")\n      .in(\"card_id\", ids)\n      .gte(\"day\", weekFrom)\n      .limit(DASHBOARD_TOP_VIEW_ROW_CAP), \"card views\").data || [];",
    "    var viewRows = [];\n    for (var ci = 0; ci < ids.length; ci++) viewRows = viewRows.concat(commandCenterRead(await supabase\n      .from(\"card_view_counts\")\n      .select(\"card_id, day, views\")\n      .eq(\"card_id\", ids[ci])\n      .gte(\"day\", weekFrom)\n      .limit(DASHBOARD_TOP_VIEW_ROW_CAP), \"card views\").data || []);"]],
  // a failed read becomes 0 (H)
  "null-becomes-zero": [[SERVER, "read failed for \" + userId + \": \" + message);\n      unreadable.push(name);\n      return null;\n",
    "read failed for \" + userId + \": \" + message);\n      unreadable.push(name);\n      return 0;\n"]],
  // the mailbox claims an unread count (I)
  "unread-claimed": [[SERVER, "    return { connected: mail.length > 0 && mail[0].status === \"connected\" };",
    "    return { connected: mail.length > 0 && mail[0].status === \"connected\", unread: 0 };"]],
  // one cache entry for everyone (J)
  "cache-crosses-users": [[SERVER, "    var kept = dashboardTopCache.get(userId);", "    var kept = dashboardTopCache.get(\"everyone\");"],
    [SERVER, "    dashboardTopCache.set(userId, { at: now.getTime(), body: body });", "    dashboardTopCache.set(\"everyone\", { at: now.getTime(), body: body });"]],
  // the route needs a subscription (A)
  "subscription-gated": [[SERVER, "app.get(\"/api/dashboard/top\", requireAuth, dashboardTopLimiter,", "app.get(\"/api/dashboard/top\", requireAuth, requireActiveSubscription, dashboardTopLimiter,"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = { [SERVER]: lf(fs.readFileSync(path.join(REPO, SERVER), "utf8")) };
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no request is left unhandled", false, (e && e.message) || e));

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
const DAY_MS = 86400000;
const dayAgo = (n, hh) => new Date(Date.UTC(2027, 0, 20) - n * DAY_MS + (hh === undefined ? 9 : hh) * 3600000).toISOString();
const dateAgo = n => dayAgo(n).slice(0, 10);
const minsAgo = m => new Date(NOW - m * 60000).toISOString();

/* ── the server, lifted ── */
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
  if (FN_AT.has(name)) { const at = FN_AT.get(name); return SRC.slice(at, s.braceMatch(SRC, SRC.indexOf(") {", at) + 2)); }
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
const uncommented = (code) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
  const have = new Map();
  const looked = new Set();
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
let ROUTE, LIFTED_SCRIPT;
try {
  ROUTE = routeText("get", "/api/dashboard/top");
  LIFTED_SCRIPT = new vm.Script(closure(ROUTE + "\n\nthis.__blogRef = blogRefToken; this.__outRef = outreachRefToken;"));
} catch (e) {
  console.log("    FAIL  the route could not be lifted: " + e.message);
  process.exit(1);
}

/* ── the in-memory database: every filter applied, every write recorded and refused ── */
function fakeDb(seed) {
  const tables = seed;
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
    if (q.write) { writes.push({ table: q.table, op: q.write }); return Promise.resolve({ data: null, error: { message: "this check allows no writes" } }); }
    const t = tables[q.table];
    if (t === "FAIL") return Promise.resolve({ data: null, error: { message: q.table + " is unreachable in this fixture" }, count: null });
    if (t === "NOCOUNT" && q.opts && q.opts.head) return Promise.resolve({ data: null, error: null, count: null });
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
    rows = JSON.parse(JSON.stringify(rows));
    if (q.single) return Promise.resolve({ data: rows[0] || null, error: null, count });
    return Promise.resolve({ data: rows, error: null, count });
  }
  function from(table) {
    const q = { table, cols: "*", opts: null, filters: [], single: false, write: null };
    log.push(q);
    const b = { select(cols, opts) { q.cols = cols || "*"; q.opts = opts || null; return b; } };
    ["insert", "update", "upsert", "delete"].forEach(op => { b[op] = function () { q.write = op; return b; }; });
    ["eq", "neq", "in", "gte", "lt", "not", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, writes, client: { from, rpc() { writes.push({ table: "rpc", op: "rpc" }); return Promise.resolve({ data: null, error: { message: "no rpc" } }); } } };
}

const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";   // the owner account (Lead Radar's credential owner)
const USER = "aaaaaaaa-0000-4000-8000-000000000002";    // a member with figures everywhere
const OTHER = "aaaaaaaa-0000-4000-8000-000000000003";   // another member, with no store
const LAPSED = "aaaaaaaa-0000-4000-8000-000000000004";  // a member whose subscription lapsed
const CERTS = require(path.join(REPO, "lib/certificationCatalog")).publicCertificationCatalog;
const MEDIA_CAP = require(path.join(REPO, "lib/memberMedia")).MEMBER_MEDIA_BYTES;
const blogRef = (u, slug) => "bl-" + crypto.createHash("sha256").update("blog:" + u + ":" + slug).digest("hex").slice(0, 10);
const outRef = uri => "lr-" + crypto.createHash("sha256").update("leadradar:" + uri).digest("hex").slice(0, 10);

function world() {
  const t = {};
  let n = 0; const id = p => p + "-" + String(++n).padStart(6, "0");
  const repeat = (k, f) => Array.from({ length: k }, (_, i) => f(i));
  const TEA = blogRef(USER, "tea-launch"), QUIET = blogRef(USER, "quiet-post"), LEAD = outRef("at://did:plc:x/post/1"), OTHERS = blogRef(OTHER, "theirs");
  t.content_library = [
    { id: id("c"), user_id: USER, title: "Tea launch", slug: "tea-launch", status: "published", body: "<a href=\"https://bizforceai.net/?ref=" + TEA + "\">x</a>", created_at: dayAgo(30) },
    { id: id("c"), user_id: USER, title: "Quiet", slug: "quiet-post", status: "published", body: "no tracked link", created_at: dayAgo(30) },
    { id: id("c"), user_id: OTHER, title: "Theirs", slug: "theirs", status: "published", body: "?ref=" + OTHERS, created_at: dayAgo(30) }
  ];
  t.outreach_sends = [{ id: id("o"), user_id: USER, lead_post_uri: "at://did:plc:x/post/1" }];
  const visit = (ref, ago, k) => repeat(k, () => ({ id: id("v"), ref, landing_path: "/", created_at: dayAgo(ago) }));
  t.engine_visits = [].concat(visit(TEA, 0, 3), visit(TEA, 3, 5), visit(TEA, 9, 4), visit(TEA, 20, 7), visit(QUIET, 0, 9),
    visit(LEAD, 0, 1), visit(LEAD, 10, 2), visit(OTHERS, 0, 50));
  t.member_store_connections = [{ id: id("s"), user_id: USER, platform: "shopify", status: "connected" }];
  // 1003 items, the low ones after the first 1000 by id; one archived low item is not counted.
  t.inventory_items = repeat(1000, i => ({ id: "i-" + String(i).padStart(6, "0"), user_id: USER, name: "Mug " + i, quantity_on_hand: 50, reorder_point: 5, status: "active", source: "manual" }))
    .concat(repeat(7, i => ({ id: "i-9" + String(i).padStart(5, "0"), user_id: USER, name: "Low " + i, quantity_on_hand: 1, reorder_point: 5, status: "active", source: "shopify" })))
    .concat([{ id: "i-999999", user_id: USER, name: "Gone", quantity_on_hand: 0, reorder_point: 5, status: "archived", source: "manual" },
      { id: "i-000000x", user_id: OTHER, name: "Theirs low", quantity_on_hand: 0, reorder_point: 9, status: "active", source: "manual" }]);
  const order = (u, ago) => ({ id: id("so"), user_id: u, connection_id: "conn", platform: "shopify", ordered_at: dayAgo(ago), total: 10 });
  t.store_order_summaries = [].concat(repeat(2, () => order(USER, 0)), repeat(3, () => order(USER, 1)), [order(USER, 5)], repeat(4, () => order(USER, 8)),
    repeat(4, () => order(USER, 12)), [order(USER, 20)], repeat(9, () => order(LAPSED, 0)));
  t.agent_proposals = [].concat(repeat(2, () => ({ id: id("p"), user_id: USER, status: "pending" })), [{ id: id("p"), user_id: USER, status: "approved" }],
    repeat(5, () => ({ id: id("p"), user_id: OTHER, status: "pending" })));
  t.digital_cards = [1, 2, 3].map(k => ({ id: "card-" + k, user_id: USER })).concat([{ id: "card-other", user_id: OTHER }]);
  t.card_view_counts = [
    { card_id: "card-1", day: dateAgo(0), views: 5 }, { card_id: "card-2", day: dateAgo(0), views: 4 }, { card_id: "card-3", day: dateAgo(0), views: 3 },
    { card_id: "card-1", day: dateAgo(2), views: 6 }, { card_id: "card-2", day: dateAgo(8), views: 100 }, { card_id: "card-other", day: dateAgo(0), views: 50 }];
  t.user_certifications = [{ user_id: USER, cert_id: "sales-1", passed: true }, { user_id: USER, cert_id: "sales-1", passed: true },
    { user_id: USER, cert_id: "marketing-1", passed: true }, { user_id: USER, cert_id: "analytics-1", passed: false }, { user_id: OTHER, cert_id: "x", passed: true }];
  t.user_wallets = [{ user_id: USER, balance: 240 }, { user_id: OTHER, balance: 9999 }];
  t.marketplace_orders = [{ id: id("m"), seller_id: USER, buyer_id: OTHER, created_at: dayAgo(1) }, { id: id("m"), seller_id: USER, buyer_id: OTHER, created_at: dayAgo(3) },
    { id: id("m"), seller_id: USER, buyer_id: OTHER, created_at: dayAgo(10) }].concat(repeat(3, () => ({ id: id("m"), seller_id: OTHER, buyer_id: USER, created_at: dayAgo(4) })));
  t.self_reviews = [{ user_id: USER, created_at: dayAgo(9) }, { user_id: USER, created_at: dayAgo(2) }, { user_id: OTHER, created_at: dayAgo(0) }];
  t.member_email_connections = [{ user_id: USER, status: "connected", provider: "gmail" }];
  t.crm_customers = repeat(18, () => ({ id: id("cr"), user_id: USER })).concat(repeat(4, () => ({ id: id("cr"), user_id: OTHER })));
  t.prospects = repeat(3, () => ({ id: id("pr"), user_id: USER }));
  t.sms_subscribers = repeat(5, () => ({ id: id("sm"), user_id: USER }));
  t.crowdfunding_campaigns = [{ id: id("cf"), owner_id: USER }, { id: id("cf"), owner_id: OTHER }];
  t.routines = repeat(2, () => ({ id: id("r"), user_id: USER }));
  t.saved_prompts = repeat(4, () => ({ id: id("sp"), user_id: USER }));
  t.bizdoc_documents = [{ id: id("b"), owner_id: USER }];
  t.bsky_leads = repeat(6, () => ({ id: id("l"), status: "scored", intent_score: 80 })).concat([{ id: id("l"), status: "scored", intent_score: null }]);
  t.member_media = [{ id: id("mm"), user_id: USER, bytes: 100, created_at: dayAgo(5) }, { id: id("mm"), user_id: USER, bytes: 200, created_at: dayAgo(4) },
    { id: id("mm"), user_id: OTHER, bytes: 5000, created_at: dayAgo(4) }];
  t.ai_tasks = [
    { id: id("t"), user_id: USER, agent_type: "seo", task_type: "seo/audit", status: "processing", created_at: minsAgo(3) },
    { id: id("t"), user_id: USER, agent_type: "content", task_type: "content/outline", status: "processing", created_at: minsAgo(30) },
    { id: id("t"), user_id: USER, agent_type: "email", task_type: "email/sequence", status: "completed", created_at: minsAgo(5) },
    { id: id("t"), user_id: OTHER, agent_type: "sales", task_type: "sales/x", status: "processing", created_at: minsAgo(1) }];
  return t;
}

const LIMITERS = [];
function server(seed) {
  const db = fakeDb(seed || world());
  const ctx = {
    supabase: db.client, JSON, Math, Promise, Object, Array, String, Number, isNaN, isFinite, Error, Map, Set, RegExp, URL,
    Date: movableDate(), crypto,
    require: name => require("module").createRequire(path.join(REPO, "server.js"))(name),
    process: { env: {} },
    console: { log() {}, error() {}, warn() {} },
    OWNER_ACCOUNT_ID: OWNER,
    publicCertificationCatalog: CERTS,
    rateLimit: function (o) {
      const hits = new Map();
      LIMITERS.push(o);
      return function dashboardLimiter(req, res, next) {
        const k = o.keyGenerator(req); const now = CLOCK.t;
        const h = (hits.get(k) || []).filter(x => now - x < o.windowMs); h.push(now); hits.set(k, h);
        if (h.length > o.max) return res.status(429).json(o.message);
        next();
      };
    },
    requireActiveSubscription: function requireActiveSubscription(req, res, next) {
      if (req.user.id === LAPSED) return res.status(402).json({ error: "subscription required" });
      next();
    },
    requireAuth: function requireAuth(req, res, next) {
      if (!req.headers.user) return res.status(401).json({ error: "sign in" });
      req.user = { id: req.headers.user }; next();
    }
  };
  const routes = {};
  ctx.app = { get(p, ...h) { routes["get " + p] = h; }, post(p, ...h) { routes["post " + p] = h; }, put() {}, delete() {}, patch() {}, use() {}, _router: { stack: [] } };
  vm.createContext(ctx);
  LIFTED_SCRIPT.runInContext(ctx);
  async function call(user) {
    const chain = routes["get /api/dashboard/top"];
    if (!chain) throw new Error("route not lifted");
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    const req = { headers: { user }, params: {}, query: {}, body: {} };
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
  return { db, call, chain: () => routes["get /api/dashboard/top"] };
}

const sum = a => a.reduce((x, y) => x + y, 0);
const keysDeep = (o, out) => { out = out || []; if (o && typeof o === "object") Object.keys(o).forEach(k => { out.push(k); keysDeep(o[k], out); }); return out; };

(async () => {
  /* ── A. the guards ── */
  console.log("\n══ A. login-only, limited, not subscription-gated ══");
  const line = SRC.slice(SRC.indexOf("app.get(\"/api/dashboard/top\","), SRC.indexOf("async function", SRC.indexOf("app.get(\"/api/dashboard/top\",")));
  check("the route is app.get(\"/api/dashboard/top\", requireAuth, dashboardTopLimiter, …)", line === "app.get(\"/api/dashboard/top\", requireAuth, dashboardTopLimiter, ", line);
  check("no requireActiveSubscription in front of it", !/requireActiveSubscription/.test(line), line);
  let srv = server();
  const lapsed = await srv.call(LAPSED);
  check("a lapsed member gets 200 and their own figures", lapsed.code === 200 && lapsed.body && lapsed.body.proposals_pending === 0, JSON.stringify(lapsed.body).slice(0, 200));
  const anon = await srv.call(null);
  check("no session is refused (401)", anon.code === 401);
  const lim = LIMITERS[LIMITERS.length - 1];
  check("the limiter allows 60 in a minute, keyed by the member", !!lim && lim.windowMs === 60000 && lim.max === 60 && lim.keyGenerator({ user: { id: USER } }) !== lim.keyGenerator({ user: { id: OTHER } }),
    lim && JSON.stringify({ w: lim.windowMs, m: lim.max }));
  {
    const s2 = server();
    let last = null;
    for (let k = 0; k < 61; k++) last = await s2.call(USER);
    const other = await s2.call(OTHER);
    check("the 61st read in a minute is refused (429); another member is not", last.code === 429 && other.code === 200, last.code + " / " + other.code);
  }

  /* ── B. read-only ── */
  console.log("\n══ B. no write, no task, no model or external call ══");
  srv = server();
  const r = await srv.call(USER);
  check("the member's read answers 200", r.code === 200, JSON.stringify(r.body).slice(0, 300));
  const b = r.body || {};
  check("nothing is written (no insert, update, upsert, delete or rpc)", srv.db.writes.length === 0, JSON.stringify(srv.db.writes));
  check("no ai_tasks row is started: ai_tasks is only read", srv.db.log.filter(q => q.table === "ai_tasks").every(q => !q.write));
  const own = uncommented(ROUTE + "\n" + (definitionOf("dashboardTopBody") || "")).split("dashboardTopCache.delete(").join("");
  check("the route and its body call no startToolRun, model, fetch or write", !/startToolRun|callAnthropic|messages\.create|fetch\(|\.insert\(|\.upsert\(|\.update\(|\.delete\(|\.rpc\(/.test(own));

  /* ── C. scoped ── */
  console.log("\n══ C. the caller's own rows only ══");
  const SCOPE = { content_library: "user_id", outreach_sends: "user_id", member_store_connections: "user_id", inventory_items: "user_id", store_order_summaries: "user_id",
    agent_proposals: "user_id", digital_cards: "user_id", user_certifications: "user_id", user_wallets: "user_id", self_reviews: "user_id", member_email_connections: "user_id",
    crm_customers: "user_id", prospects: "user_id", sms_subscribers: "user_id", crowdfunding_campaigns: "owner_id", routines: "user_id", saved_prompts: "user_id",
    bizdoc_documents: "owner_id", member_media: "user_id", ai_tasks: "user_id" };
  const scopedFor = (log, user, cards, refs) => log.filter(q => {
    if (q.table === "marketplace_orders") return !q.filters.some(f => f[0] === "eq" && (f[1] === "seller_id" || f[1] === "buyer_id") && f[2] === user);
    if (q.table === "card_view_counts") return !q.filters.some(f => f[0] === "in" && f[1] === "card_id" && f[2].every(x => cards.indexOf(x) !== -1));
    if (q.table === "engine_visits") return !q.filters.some(f => f[0] === "in" && f[1] === "ref" && f[2].every(x => refs.indexOf(x) !== -1));
    const col = SCOPE[q.table];
    return !col || !q.filters.some(f => f[0] === "eq" && f[1] === col && f[2] === user);
  }).map(q => q.table);
  const userRefs = [blogRef(USER, "tea-launch"), outRef("at://did:plc:x/post/1")];
  const unscoped = scopedFor(srv.db.log, USER, ["card-1", "card-2", "card-3"], userRefs);
  check("every query the member's read makes is scoped to the member (" + srv.db.log.length + " queries)", unscoped.length === 0, unscoped.join(", "));
  check("a member never reads bsky_leads (it has no owner column)", !srv.db.log.some(q => q.table === "bsky_leads"));
  check("a member's leads are null, with the reason listed", b.counts && b.counts.leads === null && (b._unreadable || []).some(x => /^counts\.leads/.test(x)), JSON.stringify(b._unreadable));
  const so = server();
  const ro = await so.call(OWNER);
  check("the owner account reads its Lead Radar leads as a head count (6 scored with a score)", ro.body && ro.body.counts && ro.body.counts.leads === 6 &&
    so.db.log.filter(q => q.table === "bsky_leads").every(q => q.opts && q.opts.head), ro.body && JSON.stringify(ro.body.counts));
  check("another member's figures are not in the member's answer (wallet 240, not 9999; 2 pending, not 7)", b.wallet && b.wallet.balance === 240 && b.proposals_pending === 2,
    JSON.stringify([b.wallet, b.proposals_pending]));

  /* ── D. bounded ── */
  console.log("\n══ D. every read bounded ══");
  const unbounded = srv.db.log.filter(q => !(q.opts && q.opts.head) && !q.filters.some(f => f[0] === "limit" || f[0] === "range") && !q.single).map(q => q.table);
  check("every list read is paged or limited; every count a head count", unbounded.length === 0, unbounded.join(", "));
  check("the counts are exact head counts", ["crm_customers", "prospects", "sms_subscribers", "crowdfunding_campaigns", "routines", "saved_prompts", "bizdoc_documents", "agent_proposals"]
    .every(t => srv.db.log.some(q => q.table === t && q.opts && q.opts.head && q.opts.count === "exact")));

  /* ── E. visits ── */
  console.log("\n══ E. visits: 14 days through the member's own refs, blog and outreach ══");
  const v = b.visits || {};
  check("days: 14 UTC days, the last today", Array.isArray(b.days) && b.days.length === 14 && b.days[13] === "2027-01-20" && b.days[0] === "2027-01-07", JSON.stringify(b.days));
  check("per_day has 14 entries", Array.isArray(v.per_day) && v.per_day.length === 14, JSON.stringify(v));
  check("today counts the blog AND the outreach arrivals (3 + 1), not the untracked post's or another member's", v.per_day && v.per_day[13] === 4, v.per_day && v.per_day[13]);
  check("3 days ago 5, 9 days ago 4, 10 days ago 2 (outreach), 20 days ago left out", v.per_day && v.per_day[10] === 5 && v.per_day[4] === 4 && v.per_day[3] === 2 && sum(v.per_day) === 15,
    JSON.stringify(v.per_day));
  check("this_week 9 and last_week 6", v.this_week === 9 && v.last_week === 6, JSON.stringify([v.this_week, v.last_week]));
  check("tracked is true", v.tracked === true);
  {
    const w = world(); w.content_library = w.content_library.filter(p => p.user_id !== USER); w.outreach_sends = [];
    const s3 = server(w); const x = (await s3.call(USER)).body;
    check("with no tracked post and no outreach send: tracked false, and every day a real 0", x.visits && x.visits.tracked === false && sum(x.visits.per_day) === 0 && x.visits.this_week === 0,
      JSON.stringify(x.visits));
  }

  /* ── F. store ── */
  console.log("\n══ F. store: connected, low stock over every row, orders by ordered_at ══");
  const st = b.store || {};
  check("connected is true for the member with a connected store", st.connected === true);
  check("low stock counts all 7 rows past the first 1000, not the archived one, not another member's", st.low_stock && st.low_stock.count === 7, JSON.stringify(st.low_stock));
  check("low stock names at most 5", st.low_stock && Array.isArray(st.low_stock.names) && st.low_stock.names.length === 5 && st.low_stock.names[0] === "Low 0", JSON.stringify(st.low_stock));
  check("orders_per_day: 14 days from store_order_summaries (2 today, 3 yesterday, 1, 4, 4)", Array.isArray(st.orders_per_day) && st.orders_per_day.length === 14 &&
    st.orders_per_day[13] === 2 && st.orders_per_day[12] === 3 && st.orders_per_day[8] === 1 && st.orders_per_day[5] === 4 && st.orders_per_day[1] === 4 && sum(st.orders_per_day) === 14,
    JSON.stringify(st.orders_per_day));
  check("orders_this_week is 6", st.orders_this_week === 6, st.orders_this_week);
  check("orders are read from store_order_summaries by ordered_at", srv.db.log.some(q => q.table === "store_order_summaries" && q.filters.some(f => f[0] === "gte" && f[1] === "ordered_at")));
  {
    const so2 = server(); const x = (await so2.call(OTHER)).body;
    check("a member with no store: connected false, 0 orders, and manual inventory still counted", x.store && x.store.connected === false && x.store.orders_this_week === 0 &&
      x.store.low_stock && x.store.low_stock.count === 1, JSON.stringify(x.store));
  }

  /* ── G. the other figures ── */
  console.log("\n══ G. cards, certifications, wallet, marketplace, self-reviews, counts, media, agents ══");
  check("cards: 3 cards, 12 views today, 18 in 7 days (100 eight days ago and another member's 50 left out)", b.cards && b.cards.count === 3 && b.cards.views_today === 12 && b.cards.views_7d === 18,
    JSON.stringify(b.cards));
  check("card views are ONE card_view_counts read across every card", srv.db.log.filter(q => q.table === "card_view_counts").length === 1,
    srv.db.log.filter(q => q.table === "card_view_counts").length);
  check("certifications: 2 distinct earned of the catalog's " + CERTS().length, b.certifications && b.certifications.earned === 2 && b.certifications.total === CERTS().length,
    JSON.stringify(b.certifications));
  check("wallet balance 240", b.wallet && b.wallet.balance === 240 && b.wallet.exists === true);
  check("marketplace: 2 orders this week as seller (not the older one, not purchases)", b.marketplace && b.marketplace.orders_this_week === 2, JSON.stringify(b.marketplace));
  check("self_reviews.latest_at is the newest review", b.self_reviews && b.self_reviews.latest_at === dayAgo(2), JSON.stringify(b.self_reviews));
  const cn = b.counts || {};
  check("counts: 18 customers, 3 prospects, 5 subscribers, 1 campaign, 2 routines, 4 prompts, 3 purchases, 1 document",
    cn.crm_customers === 18 && cn.prospects === 3 && cn.sms_subscribers === 5 && cn.campaigns === 1 && cn.routines === 2 && cn.saved_prompts === 4 && cn.purchases === 3 && cn.bizdoc_documents === 1,
    JSON.stringify(cn));
  check("media: 300 bytes used of the library cap", b.media && b.media.used_bytes === 300 && b.media.cap_bytes === MEDIA_CAP, JSON.stringify(b.media));
  check("agents running now: seo only (content is stalled, email finished, sales is another member's)", b.agents && JSON.stringify(b.agents.running_now) === JSON.stringify(["seo"]),
    JSON.stringify(b.agents));
  check("nothing unreadable but the member's leads", JSON.stringify(b._unreadable) === JSON.stringify(["counts.leads (Lead Radar reads the owner account's leads only)"]), JSON.stringify(b._unreadable));

  /* ── H. null, never 0 ── */
  console.log("\n══ H. a figure that could not be read is null, with its reason ══");
  {
    const w = world(); w.prospects = "NOCOUNT"; w.store_order_summaries = "FAIL"; w.user_wallets = "FAIL"; w.engine_visits = "FAIL"; w.card_view_counts = "FAIL";
    const s4 = server(w); const x = (await s4.call(USER));
    const xb = x.body || {};
    check("the read still answers 200", x.code === 200, JSON.stringify(xb).slice(0, 200));
    check("a head count that did not come back is null, not 0", xb.counts && xb.counts.prospects === null, xb.counts && xb.counts.prospects);
    check("orders unreadable: orders_per_day and orders_this_week null; low stock still read", xb.store && xb.store.orders_per_day === null && xb.store.orders_this_week === null &&
      xb.store.low_stock && xb.store.low_stock.count === 7, JSON.stringify(xb.store));
    check("wallet, visits and cards unreadable are null", xb.wallet === null && xb.visits === null && xb.cards === null, JSON.stringify([xb.wallet, xb.visits, xb.cards]));
    const un = xb._unreadable || [];
    check("each is named in _unreadable", ["counts.prospects", "store.orders", "wallet", "visits", "cards"].every(n => un.indexOf(n) !== -1), JSON.stringify(un));
    check("the readable ones are unchanged (18 customers, 2 pending)", xb.counts && xb.counts.crm_customers === 18 && xb.proposals_pending === 2);
  }

  /* ── I. no unread claim ── */
  console.log("\n══ I. the mailbox is connected or not, never an unread count ══");
  check("mailbox is exactly { connected: true }", JSON.stringify(b.mailbox) === JSON.stringify({ connected: true }), JSON.stringify(b.mailbox));
  check("no key anywhere in the answer names an unread count", !keysDeep(b).some(k => /unread|unseen/i.test(k) && k !== "_unreadable"), keysDeep(b).filter(k => /unread/i.test(k)).join(","));
  check("no IMAP or mailbox read: member_email_connections is read for its status only", srv.db.log.filter(q => q.table === "member_email_connections").every(q => q.cols === "status"));

  /* ── J. the cache is per member ── */
  console.log("\n══ J. 60 seconds, per member ══");
  {
    const s5 = server();
    CLOCK.t = NOW;
    const a1 = await s5.call(USER); const n1 = s5.db.log.length;
    const a2 = await s5.call(USER); const n2 = s5.db.log.length;
    check("a second read within 60 s is the cached answer, with no query", a1.body.cached === false && a2.body.cached === true && n2 === n1, n1 + " vs " + n2);
    const o1 = await s5.call(OTHER);
    check("another member is never served the first member's answer (0 pending of their own... 5)", o1.body.cached === false && o1.body.proposals_pending === 5 && o1.body.wallet.balance === 9999,
      JSON.stringify([o1.body.cached, o1.body.proposals_pending]));
    CLOCK.t = NOW + 61000;
    const a3 = await s5.call(USER);
    check("after 60 s the member's figures are read again", a3.body.cached === false && s5.db.log.length > n2 + 10);
    CLOCK.t = NOW;
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.stack) || e)); process.exit(1); });
