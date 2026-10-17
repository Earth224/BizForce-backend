"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkStoreStockMargin — the Store agent's Stock & Margin tool measures the
   caller's own inventory in code, never fills a missing figure with 0, and
   never calls a model; Termaximus's Store stock section never reads a failed
   read as "0 items".

   POST /api/agents/store/stock-margin, requireActiveSubscription and
   buildOracleAgentRecords are lifted from server.js with everything they call,
   and run in a vm against an in-memory Supabase (failures injected per table)
   with every model entry point stubbed to record a call. TEST ROWS ARE
   ISOLATED BY CONSTRUCTION: no database, no network, no model and no email is
   reached, so the owner's live data is never read and nothing is written
   anywhere. Every fixture row belongs to one of two made-up accounts.

   WHAT THIS PROVES
     A. Ownership: every inventory_items read filters on the caller's user_id,
        every inventory_movements read asks only for the caller's item ids, and
        nothing of another account's appears in the response.
     B. Exact arithmetic on a known three-item fixture (plus one archived
        item, and an 'out' movement older than the window): item counts, the
        missing-figure counts, both stock values, unit margin and margin %,
        the reorder listing, units out, the daily rate, days of cover, and the
        count corrections.
     C. A missing cost or price is excluded and counted, never 0; with no cost
        anywhere the value at cost is null with its reason. Every null in the
        response has a "<key>_reason" beside it.
     D. The reorder listing names only items that have a reorder point.
     E. Days of cover is null with a reason under 3 'out' movements, and
        correct at 3 and more.
     F. window_days 0, 6, 366, "30", true (and 7.5, "") are each a 400 naming
        the field; absent is 30; 7 and 365 are accepted.
     G. No items: a 200 with items 0 and a note naming the Inventory page,
        and no screen of zeros.
     H. No model call on any path, and none reachable from the route.
     I. Without an active subscription: a 402, and nothing is read.
     J. Termaximus's Store stock section: the right lines from the caller's
        rows only; "0 items" for a real empty read; "could not be read just
        now" for a failed one, never "0 items".
     K. The pricing_strategy instruction works from the request and the
        Business Profile and no longer claims to hold the user's costs.
     L. A failed read is a 500 through next(), never an empty inventory.

   MUTATE=<name> edits server.js IN MEMORY (nothing on disk is touched).
   MUTATE=all runs each in its own process; an unmatched search text is an
   ERROR, never a catch (scripts/_shared.js).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), crypto = require("crypto"), net = require("net"), dns = require("dns");
const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
const s = MUT;

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkStoreStockMargin: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkStoreStockMargin: no network"); };

const SERVER = "server.js";
const MUTATIONS = {
  // a missing unit cost is treated as 0
  "missing-cost-as-zero": [[SERVER, "    var cost = storeStockFigure(it.unit_cost);\n", "    var cost = storeStockFigure(it.unit_cost) || 0;\n"]],
  // the items read loses its user_id filter
  "drop-user-filter": [[SERVER, "    .select(\"id, name, sku, unit, quantity_on_hand, reorder_point, unit_cost, unit_price, status\")\n    .eq(\"user_id\", userId)\n",
    "    .select(\"id, name, sku, unit, quantity_on_hand, reorder_point, unit_cost, unit_price, status\")\n"]],
  // days of cover is computed from one or two movements
  "cover-under-three": [[SERVER, "    if (outs.length < STORE_STOCK_MIN_OUT_MOVEMENTS) {\n", "    if (outs.length < 1) {\n"]],
  // the route loses its subscription gate
  "ungate": [[SERVER, "app.post(\"/api/agents/store/stock-margin\", requireAuth, requireActiveSubscription, aiLimiter,",
    "app.post(\"/api/agents/store/stock-margin\", requireAuth, aiLimiter,"]],
  // Termaximus reads a failed inventory read as an empty one, "0 items"
  "termaximus-failure-zero": [[SERVER, "    var rows = must(await supabase\n      .from(\"inventory_items\")\n", "    var read = await supabase\n      .from(\"inventory_items\")\n"],
    [SERVER, "      .limit(L.inventory));\n    return oracleStoreStockLines(rows, L.inventory);", "      .limit(L.inventory);\n    var rows = read.data || [];\n    return oracleStoreStockLines(rows, L.inventory);"]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

let SRC = fs.readFileSync(path.join(REPO, SERVER), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [, from, to] of edits) SRC = MUT.replaceOnce(SRC, from, to, MUTATE + " in " + SERVER);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* ── lifting ──────────────────────────────────────────────────────────────── */
const MODEL_ENTRY = ["callAnthropicText", "toolGenerateWithOneRetry", "callAnthropic", "callClaude", "Anthropic", "anthropic"];
const STUBS = new Set(["supabase", "console", "process", "require", "module", "app", "requireAuth", "aiLimiter", "getUserPlan",
  "Buffer", "URL", "setTimeout", "setImmediate", "fetch", "crypto"].concat(MODEL_ENTRY));
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
  return { code: [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root, names: [...have.keys()] };
}
const SIG = 'app.post("/api/agents/store/stock-margin",';
const routeStart = SRC.indexOf(SIG);
if (routeStart < 0) { console.log("    FAIL  POST /api/agents/store/stock-margin not found"); process.exit(1); }
const ROUTE = SRC.slice(routeStart, s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", routeStart))) + 3);
const LIFT = closure(ROUTE + "\n\nthis.__api = { buildOracleAgentRecords: buildOracleAgentRecords, requireActiveSubscription: requireActiveSubscription, " +
  "measureStockAndMargin: measureStockAndMargin };");

/* ── the fake database ────────────────────────────────────────────────────── */
function fakeDb(seed, fail) {
  const tables = {};
  Object.keys(seed).forEach(t => { tables[t] = seed[t].map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  function keep(q, row) {
    return q.filters.every(([op, col, val, extra]) => {
      const v = row[col];
      if (op === "eq") return v === val;
      if (op === "neq") return v !== val;
      if (op === "in") return val.indexOf(v) !== -1;
      if (op === "is") return val === null ? v == null : v === val;
      if (op === "not") return extra === null && val === "is" ? v != null : true;
      if (op === "gte") return v != null && String(v) >= String(val);
      if (op === "lte") return v != null && String(v) <= String(val);
      if (op === "gt") return v != null && String(v) > String(val);
      if (op === "lt") return v != null && String(v) < String(val);
      return true;
    });
  }
  function answer(q) {
    log.push(q);
    const injected = fail && fail(q);
    if (injected === "throw") return Promise.reject(new Error("the connection dropped"));
    if (injected) return Promise.resolve({ data: null, count: null, error: injected });
    const rows = tables[q.table] || (tables[q.table] = []);
    if (q.op === "insert" || q.op === "upsert") {
      const payload = [].concat(q.payload).map(p => Object.assign({ id: crypto.randomUUID() }, JSON.parse(JSON.stringify(p))));
      rows.push(...payload);
      return Promise.resolve({ data: q.single ? payload[0] : payload, error: null });
    }
    if (q.op === "update") {
      const hit = rows.filter(r => keep(q, r)); hit.forEach(r => Object.assign(r, q.payload));
      return Promise.resolve({ data: hit, error: null });
    }
    if (q.op === "delete") return Promise.resolve({ data: null, error: null });
    let hits = rows.filter(r => keep(q, r));
    const count = hits.length;
    const order = q.mods.find(m => m[0] === "order");
    if (order) hits = hits.slice().sort((a, b) => (a[order[1]] < b[order[1]] ? -1 : a[order[1]] > b[order[1]] ? 1 : 0) * (order[2] && order[2].ascending === false ? -1 : 1));
    const limit = q.mods.find(m => m[0] === "limit"); if (limit) hits = hits.slice(0, limit[1]);
    if (q.opts && q.opts.head) return Promise.resolve({ data: null, count, error: null });
    const copies = hits.map(r => JSON.parse(JSON.stringify(r)));
    if (q.single) {
      if (copies.length > 1) return Promise.resolve({ data: null, error: { message: "multiple rows" } });
      if (!copies.length && q.single === "single") return Promise.resolve({ data: null, error: { code: "PGRST116", message: "no rows" } });
      return Promise.resolve({ data: copies[0] || null, error: null });
    }
    return Promise.resolve({ data: copies, count: q.opts && q.opts.count ? count : null, error: null });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, opts: null, payload: null, filters: [], mods: [], single: false };
    const b = {
      select(cols, opts) { if (q.op === "select") { q.cols = cols || "*"; q.opts = opts || null; } return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      upsert(p) { q.op = "upsert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      delete() { q.op = "delete"; return b; },
      not(col, op, val) { q.filters.push(["not", col, op, val]); return b; },
      single() { q.single = "single"; return answer(q); },
      maybeSingle() { q.single = "maybe"; return answer(q); },
      then(res, rej) { return answer(q).then(res, rej); }
    };
    ["eq", "neq", "in", "is", "gte", "lte", "gt", "lt"].forEach(op => { b[op] = function (col, val) { q.filters.push([op, col, val]); return b; }; });
    ["order", "limit", "range"].forEach(op => { b[op] = function () { q.mods.push([op].concat([].slice.call(arguments))); return b; }; });
    return b;
  }
  return { tables, log, client: { from, rpc: () => Promise.resolve({ data: null, error: { message: "no rpc" } }) } };
}

/* ── fixtures ─────────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-0000000000a1";
const OTHER = "bbbbbbbb-0000-4000-8000-0000000000b2";
const MARK = "ZZOTHERACCOUNT";
const NOW = Date.now();
const day = (n) => new Date(NOW - n * 86400000).toISOString();
const IT = { widget: "11111111-0000-4000-8000-000000000001", gadget: "11111111-0000-4000-8000-000000000002",
  gizmo: "11111111-0000-4000-8000-000000000003", old: "11111111-0000-4000-8000-000000000004", other: "22222222-0000-4000-8000-000000000009" };
function item(id, user, name, extra) {
  return Object.assign({ id, user_id: user, name, sku: null, unit: "unit", quantity_on_hand: 0, reorder_point: null, reorder_quantity: null,
    unit_cost: null, unit_price: null, status: "active", created_at: day(90) }, extra);
}
const mv = (itemId, direction, quantity, ago, counted) => ({ id: crypto.randomUUID(), item_id: itemId, direction, quantity,
  counted_quantity: counted === undefined ? null : counted, occurred_at: day(ago), created_at: day(ago) });
function world() {
  return {
    inventory_items: [
      item(IT.widget, OWNER, "Widget", { sku: "W-1", quantity_on_hand: 10, unit_cost: 2.5, unit_price: 6, reorder_point: 12 }),
      item(IT.gadget, OWNER, "Gadget", { quantity_on_hand: 4, unit_price: 9.99 }),
      item(IT.gizmo, OWNER, "Gizmo", { quantity_on_hand: 7, unit_cost: 1.1, reorder_point: 7 }),
      item(IT.old, OWNER, "Old stock", { quantity_on_hand: 3, unit_cost: 1, unit_price: 2, status: "archived" }),
      item(IT.other, OTHER, MARK, { quantity_on_hand: 1000, unit_cost: 100, unit_price: 100, reorder_point: 5000 })
    ],
    inventory_movements: [
      mv(IT.widget, "out", 4, 2), mv(IT.widget, "out", 5, 9), mv(IT.widget, "out", 6, 20), mv(IT.widget, "out", 100, 45),
      mv(IT.widget, "adjust", 2, 5, 10), mv(IT.widget, "adjust", 0, 3, 10), mv(IT.widget, "in", 20, 25),
      mv(IT.gadget, "out", 1, 4), mv(IT.gadget, "out", 1, 6),
      mv(IT.old, "out", 1, 1), mv(IT.old, "out", 1, 2), mv(IT.old, "out", 1, 3),
      mv(IT.other, "out", 50, 1), mv(IT.other, "out", 50, 2), mv(IT.other, "out", 50, 3), mv(IT.other, "adjust", 9, 1, 991)
    ],
    ai_tasks: []
  };
}

/* ── the harness ──────────────────────────────────────────────────────────── */
function context(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed, o.fail);
  const modelCalls = [];
  const logs = [];
  const handlers = {};
  const record = (name) => function () { modelCalls.push(name); throw new Error("checkStoreStockMargin: " + name + " must not be called"); };
  const rq = require("module").createRequire(path.join(REPO, "server.js"));
  const ctx = {
    supabase: db.client, require: rq, module: {}, Date, Buffer, URL, setImmediate, crypto,
    setTimeout: () => 0, fetch: record("fetch"),
    process: { env: Object.assign({ ENABLE_EMAIL_SEQUENCES: "false" }, o.env || {}) },
    console: { log: (...a) => logs.push(a.join(" ")), error: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")) },
    getUserPlan: async () => (o.plan || { active: true, plan: "pro", subscription: { status: "active" }, config: {}, exempt: false, access_reason: "subscribed" }),
    app: { post(p) { handlers[p] = [].slice.call(arguments, 1); }, get() {}, use() {} }
  };
  MODEL_ENTRY.forEach(n => { ctx[n] = record(n); });
  ctx.requireAuth = function requireAuth(req, res, next) { next(); };
  ctx.aiLimiter = function aiLimiter(req, res, next) { next(); };
  vm.createContext(ctx);
  vm.runInContext(LIFT.code, ctx);
  return { ctx, db, modelCalls, logs, handlers };
}

// One request down the route's real middleware chain, as registered.
async function post(body, opts) {
  const h = context((opts && opts.seed) || world(), opts);
  const chain = h.handlers["/api/agents/store/stock-margin"] || [];
  const req = { user: { id: OWNER, role: "user" }, body, method: "POST", route: { path: "/api/agents/store/stock-margin" }, headers: {} };
  const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
  let error = null;
  for (let i = 0; i < chain.length; i++) {
    let advanced = false;
    await chain[i](req, res, (e) => { if (e) error = e; else advanced = true; });
    if (error || !advanced) break;
  }
  return { status: error ? 500 : res.statusCode, body: res.body, error, h, chain };
}

(async function main() {
  check("the route, requireActiveSubscription and buildOracleAgentRecords were lifted",
    ["requireActiveSubscription", "buildOracleAgentRecords", "measureStockAndMargin", "loadStockAndMargin", "startToolRun", "toolProvenance"].every(n => LIFT.names.indexOf(n) !== -1),
    LIFT.names.join(","));

  /* ── A + B. the three-item fixture ───────────────────────────────────── */
  console.log("\n══ A, B. ownership and exact arithmetic on a known fixture ══");
  const r = await post({});
  const m = (r.body && r.body.measured) || {};
  const by = {}; (m.stock || []).forEach(x => { by[x.name] = x; });
  check("200 with a measured block", r.status === 200 && !!r.body && r.body.success === true, r.status + " " + (r.error && r.error.message));
  const itemReads = r.h.db.log.filter(q => q.table === "inventory_items");
  const mvReads = r.h.db.log.filter(q => q.table === "inventory_movements");
  check("A. every inventory_items read filters on the caller's user_id", itemReads.length > 0 &&
    itemReads.every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === OWNER)), JSON.stringify(itemReads.map(q => q.filters)));
  const askedIds = [].concat(...mvReads.map(q => (q.filters.find(f => f[0] === "in" && f[1] === "item_id") || [0, 0, ["(no item filter)"]])[2]));
  check("A. every inventory_movements read asks only for the caller's own active item ids", mvReads.length > 0 &&
    askedIds.length === 3 && askedIds.every(id => [IT.widget, IT.gadget, IT.gizmo].indexOf(id) !== -1), JSON.stringify(askedIds));
  check("A. nothing of another account's is in the response", JSON.stringify(r.body).indexOf(MARK) === -1 && JSON.stringify(r.body).indexOf("991") === -1);
  check("A. nothing was written but the tool run's own ai_tasks row", r.h.db.log.filter(q => q.op !== "select").every(q => q.table === "ai_tasks"));
  check("B. window_days defaults to 30", m.window_days === 30, m.window_days);
  check("B. 3 active items measured, 1 archived item left out", m.items === 3 && m.archived_items_not_measured === 1 && !by["Old stock"], m.items + "/" + m.archived_items_not_measured);
  check("B. missing figures counted separately: 1 without a cost, 1 without a price, 1 without a reorder point",
    m.items_missing_unit_cost === 1 && m.items_missing_unit_price === 1 && m.items_missing_reorder_point === 1,
    [m.items_missing_unit_cost, m.items_missing_unit_price, m.items_missing_reorder_point].join(","));
  check("B. stock value at cost = 10×2.50 + 7×1.10 = 32.70, over 2 items", m.stock_value_at_cost === 32.7 && m.stock_value_at_cost_items === 2, m.stock_value_at_cost);
  check("B. stock value at price = 10×6.00 + 4×9.99 = 99.96, over 2 items", m.stock_value_at_price === 99.96 && m.stock_value_at_price_items === 2, m.stock_value_at_price);
  check("B. Widget: unit margin 3.50 and margin 58.3%", by.Widget && by.Widget.unit_margin === 3.5 && by.Widget.margin_percent === 58.3, JSON.stringify(by.Widget));
  check("B. units out in the window: Widget 15 (the 45-day-old 100 left out), Gadget 2, Gizmo 0; 17 in all over 5 movements",
    by.Widget && by.Widget.units_out_in_window === 15 && by.Gadget.units_out_in_window === 2 && by.Gizmo.units_out_in_window === 0 &&
    m.units_out_in_window === 17 && m.out_movements_in_window === 5, [by.Widget && by.Widget.units_out_in_window, m.units_out_in_window, m.out_movements_in_window].join(","));
  check("B. Widget: daily out rate 15/30 = 0.5 and days of cover 10/0.5 = 20", by.Widget && by.Widget.daily_out_rate === 0.5 && by.Widget.days_of_cover === 20,
    JSON.stringify(by.Widget));
  check("B. count corrections: Widget, 2 counts, 1 that disagreed, 2 units corrected; the count that agreed is not a discrepancy",
    JSON.stringify(m.count_discrepancies) === JSON.stringify([{ name: "Widget", counts_in_window: 2, counts_that_disagreed: 1, units_corrected: 2 }]), JSON.stringify(m.count_discrepancies));

  /* ── C. missing figures ──────────────────────────────────────────────── */
  console.log("\n══ C. a missing cost or price is excluded and counted, never 0 ══");
  check("C. Gadget has no cost: unit_cost null with its reason, and no margin, with its reason",
    by.Gadget && by.Gadget.unit_cost === null && /no unit cost/.test(by.Gadget.unit_cost_reason || "") &&
    by.Gadget.unit_margin === null && /no unit cost/.test(by.Gadget.unit_margin_reason || "") && by.Gadget.margin_percent === null, JSON.stringify(by.Gadget));
  check("C. Gizmo has no price: unit_price null with its reason, and no margin", by.Gizmo && by.Gizmo.unit_price === null &&
    /no unit price/.test(by.Gizmo.unit_price_reason || "") && by.Gizmo.unit_margin === null, JSON.stringify(by.Gizmo));
  check("C. the note says the missing figures were left out, not counted as 0", /not counted as 0/.test(m.note || ""), m.note);
  const noCost = world(); noCost.inventory_items.forEach(x => { if (x.user_id === OWNER) x.unit_cost = null; });
  const rc = await post({}, { seed: noCost });
  const mc = (rc.body && rc.body.measured) || {};
  check("C. with no cost anywhere, the value at cost is null with its reason, not 0", mc.stock_value_at_cost === null &&
    typeof mc.stock_value_at_cost_reason === "string" && mc.stock_value_at_cost_reason.length > 10 && mc.items_missing_unit_cost === 3, JSON.stringify(mc).slice(0, 300));
  const unreasoned = [];
  (function walk(v, where) {
    if (Array.isArray(v)) return v.forEach((x, i) => walk(x, where + "[" + i + "]"));
    if (!v || typeof v !== "object") return;
    Object.keys(v).forEach(k => {
      if (v[k] === null && !(typeof v[k + "_reason"] === "string" && v[k + "_reason"].trim())) unreasoned.push(where + "." + k);
      walk(v[k], where + "." + k);
    });
  })([m, mc], "measured");
  check("C. every null in the measured block has a <key>_reason beside it", unreasoned.length === 0, unreasoned.join(", "));

  /* ── D. reorder ──────────────────────────────────────────────────────── */
  console.log("\n══ D. the reorder listing ══");
  check("D. at or below the reorder point: Widget (10 ≤ 12) and Gizmo (7 ≤ 7), named; Gadget, with none, is not listed",
    JSON.stringify(m.items_at_or_below_reorder_point_named) === JSON.stringify(["Widget", "Gizmo"]) && m.items_at_or_below_reorder_point === 2 &&
    m.items_with_a_reorder_point === 2, JSON.stringify(m.items_at_or_below_reorder_point_named));
  check("D. Gadget's reorder check is null with its reason, never false", by.Gadget && by.Gadget.at_or_below_reorder_point === null &&
    /no reorder point/.test(by.Gadget.at_or_below_reorder_point_reason || ""), JSON.stringify(by.Gadget));
  const noPoints = world(); noPoints.inventory_items.forEach(x => { x.reorder_point = null; x.quantity_on_hand = 0; });
  const rp = await post({}, { seed: noPoints });
  check("D. with no reorder point set, nothing is listed even at 0 on hand", rp.body && rp.body.measured.items_at_or_below_reorder_point === 0 &&
    rp.body.measured.items_at_or_below_reorder_point_named.length === 0, JSON.stringify(rp.body && rp.body.measured.items_at_or_below_reorder_point_named));

  /* ── E. days of cover ────────────────────────────────────────────────── */
  console.log("\n══ E. days of cover needs 3 'out' movements ══");
  check("E. Gadget (2 'out' movements): daily rate and days of cover null, each with the reason", by.Gadget && by.Gadget.days_of_cover === null &&
    by.Gadget.daily_out_rate === null && /2 'out' movement\(s\)/.test(by.Gadget.days_of_cover_reason || "") && /3 are needed/.test(by.Gadget.days_of_cover_reason || ""),
    JSON.stringify(by.Gadget));
  check("E. Gizmo (0 'out' movements): days of cover null with the reason", by.Gizmo && by.Gizmo.days_of_cover === null && /^0 'out'/.test(by.Gizmo.days_of_cover_reason || ""));
  const three = world(); three.inventory_movements.push(mv(IT.gadget, "out", 4, 5));
  const r3 = await post({ window_days: 7 }, { seed: three });
  const g3 = ((r3.body && r3.body.measured.stock) || []).find(x => x.name === "Gadget") || {};
  check("E. at 3 movements in a 7-day window: Gadget's rate is 6/7 = 0.86 and its cover 4/(6/7) = 4.7", g3.daily_out_rate === 0.86 && g3.days_of_cover === 4.7, JSON.stringify(g3));
  const w3 = ((r3.body && r3.body.measured.stock) || []).find(x => x.name === "Widget") || {};
  check("E. in that 7-day window Widget has 1 movement left, so its cover is null with the reason", w3.days_of_cover === null && /^1 'out'/.test(w3.days_of_cover_reason || ""), JSON.stringify(w3));

  /* ── F. window_days ──────────────────────────────────────────────────── */
  console.log("\n══ F. window_days is refused, never coerced ══");
  for (const bad of [0, 6, 366, "30", true, 7.5, ""]) {
    const rb = await post({ window_days: bad });
    check("F. window_days " + JSON.stringify(bad) + " is a 400 naming the field, and nothing is read or recorded",
      rb.status === 400 && rb.body && rb.body.field === "window_days" && /window_days/.test(rb.body.error || "") &&
      rb.h.db.log.filter(q => q.table !== "users").length === 0, rb.status + " " + JSON.stringify(rb.body));
  }
  for (const good of [7, 365]) {
    const rg = await post({ window_days: good });
    check("F. window_days " + good + " is accepted", rg.status === 200 && rg.body.measured.window_days === good, rg.status);
  }

  /* ── G. no items ─────────────────────────────────────────────────────── */
  console.log("\n══ G. no items ══");
  const empty = world(); empty.inventory_items = empty.inventory_items.filter(x => x.user_id !== OWNER);
  const re = await post({}, { seed: empty });
  const me = (re.body && re.body.measured) || {};
  check("G. 200 with items 0", re.status === 200 && me.items === 0, re.status + " " + JSON.stringify(me));
  check("G. the note names the Inventory page as the place to add items", /Inventory page/.test(me.note || "") && /Add your items/.test(me.note || ""), me.note);
  check("G. no screen of zeros: only window_days, items and the note", JSON.stringify(Object.keys(me).sort()) === JSON.stringify(["items", "note", "window_days"]), Object.keys(me).join(","));
  check("G. another account's items are still not read", JSON.stringify(re.body).indexOf(MARK) === -1);

  /* ── H. no model ─────────────────────────────────────────────────────── */
  console.log("\n══ H. no model call ══");
  const all = [r, rc, rp, r3, re];
  check("H. no model entry point or network call was made on any path", all.every(x => x.h.modelCalls.length === 0) && NETWORK.length === 0,
    all.map(x => x.h.modelCalls.join("+")).join(" | ") + " " + NETWORK.join(","));
  const lifted = closure(ROUTE);
  const reach = MODEL_ENTRY.filter(n => new RegExp("\\b" + n + "\\b").test(uncommented(lifted.code)));
  check("H. no model entry point is reachable from the route", reach.length === 0, reach.join(","));
  check("H. the provenance says model_call_made: false and measures from the caller's own entries",
    r.body.provenance && r.body.provenance.model_call_made === false && r.body.provenance.inferred_by_model.length === 0 &&
    /Source: your own inventory entries\. Model called: no\./.test(r.body.provenance.caveat), JSON.stringify(r.body.provenance).slice(0, 300));
  check("H. not_measured names sales revenue, supplier lead times, demand forecasting and what was not entered",
    r.body.limitations && ["Sales revenue", "Supplier lead times", "Demand forecasting", "Anything you did not enter"].every(p =>
      r.body.limitations.not_measured.some(x => x.indexOf(p) === 0)), JSON.stringify(r.body.limitations));

  /* ── I. the gate ─────────────────────────────────────────────────────── */
  console.log("\n══ I. no free tier ══");
  const ri = await post({}, { plan: { active: false, plan: null, subscription: null, config: null, exempt: false, access_reason: "no_subscription" } });
  check("I. without an active subscription: 402", ri.status === 402, ri.status + " " + JSON.stringify(ri.body).slice(0, 200));
  check("I. and nothing was read or recorded", ri.h.db.log.filter(q => /^inventory_|^ai_tasks$/.test(q.table)).length === 0, ri.h.db.log.map(q => q.table).join(","));
  check("I. the gate in front of the handler is the real requireActiveSubscription", r.chain.some(f => f === r.h.ctx.__api.requireActiveSubscription));

  /* ── J. Termaximus ───────────────────────────────────────────────────── */
  console.log("\n══ J. Termaximus's Store stock section ══");
  async function records(seed, fail) {
    const h = context(seed, { fail });
    const failed = [];
    const text = await h.ctx.__api.buildOracleAgentRecords(OWNER, (what) => failed.push(what));
    const i = text.indexOf("Store stock (active items on the Inventory page)");
    const j = text.indexOf("\nLatest self-review", i);
    return { text, section: i === -1 ? "" : text.slice(i, j === -1 ? undefined : j), failed, log: h.db.log };
  }
  const t1 = await records(world());
  check("J. with items: 3 active items, value at cost 32.70 over 2 (1 left out), 2 of the 2 with a reorder point at or below it",
    /- 3 active item\(s\)/.test(t1.section) && /stock value at cost: 32\.70 .*over the 2 item\(s\) with a unit cost; 1 left out/.test(t1.section) &&
    /at or below their reorder point: 2 of the 2 item\(s\) that have one/.test(t1.section), t1.section);
  check("J. the section reads only the caller's active items", t1.section.indexOf(MARK) === -1 &&
    t1.log.filter(q => q.table === "inventory_items").every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === OWNER)) &&
    t1.log.some(q => q.table === "inventory_items" && q.mods.some(md => md[0] === "limit")));
  const t0 = await records(empty);
  check("J. a real empty read says 0 items", /- 0 items entered on the Inventory page/.test(t0.section), t0.section);
  for (const how of ["error", "throw"]) {
    const tf = await records(world(), q => q.table === "inventory_items" ? (how === "throw" ? "throw" : { message: "permission denied" }) : null);
    check("J. a failed read (" + how + ") says it could not be read, never 0 items",
      /^Store stock \(active items on the Inventory page\): could not be read just now\./.test(tf.section) && !/0 items/.test(tf.section) &&
      tf.failed.some(f => /Store stock/.test(f)), tf.section || tf.text.slice(-300));
  }

  /* ── K. pricing_strategy ─────────────────────────────────────────────── */
  console.log("\n══ K. the pricing_strategy instruction ══");
  const ti = SRC.slice(SRC.indexOf("var taskInstructions = {"), SRC.indexOf("\n};", SRC.indexOf("var taskInstructions = {")) + 3);
  const tctx = {}; vm.createContext(tctx); vm.runInContext(ti + "\nthis.t = taskInstructions;", tctx);
  const ps = tctx.t.pricing_strategy || "";
  check("K. it works only from the request and the Business Profile", ps.indexOf("Work only from the costs and prices given in the request and the Business Profile") !== -1, ps);
  check("K. it says the task reads no inventory, catalogue or sales records", ps.indexOf("this task reads no inventory, catalogue or sales records") !== -1);
  check("K. it no longer claims the platform holds the user's costs", !/holds the user's own costs/.test(ps) && !/holds the user's own costs/.test(SRC));
  check("K. a missing figure is marked [FIGURE NEEDED]", ps.indexOf("[FIGURE NEEDED]") !== -1);

  /* ── L. a failed read ────────────────────────────────────────────────── */
  console.log("\n══ L. a failed read is an error, never an empty inventory ══");
  for (const table of ["inventory_items", "inventory_movements"]) {
    const rf = await post({}, { fail: q => q.table === table ? { message: "permission denied" } : null });
    check("L. a failed " + table + " read is a 500 through next(), with no measured body", rf.status === 500 && !rf.body && !!rf.error, rf.status + " " + JSON.stringify(rf.body).slice(0, 120));
  }

  console.log("\n" + (failures ? failures + " FAILED, " + passes + " passed" : "ALL " + passes + " CHECKS PASSED"));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack)); process.exit(1); });
