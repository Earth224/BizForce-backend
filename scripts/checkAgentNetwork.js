/* ═══════════════════════════════════════════════════════════════════════════
   checkAgentNetwork.js — the agent network (intelligence layer B6 and B7)

   WHAT THIS PROVES

     A. THE GRAPH, built from server.js's own TOOL_INPUT_SPECS and
        CHAIN_NON_DISPATCHABLE_TOOLS: 18 nodes, the 18 declared links exactly,
        no problems; every dispatch tool is in the specs and not on the
        non-dispatchable list; every agent with a dispatchable tool gets an
        Executive link and no other agent does; the approval-only link's tool
        IS on the list; validateGraph refuses each kind of bad edge.
     B. agent_collaborations IS NEVER DRAWN: no edge names it, the lib never
        reads it, and a database full of its rows changes no count.
     C. COUNTS COME ONLY FROM RECORDED ROWS, SCOPED TO THE MEMBER: two members'
        rows of every source, in and out of the window, refused and failed
        dispatches, look-alike tasks; each count is the hand count for that
        member; every read names the member's user_id; a read that fails is a
        null count, never 0.
     D. THE EDGE ROUTE: its runs paged 20, newest first, each with run.html
        and "Why?"; an undeclared pair is 404; windows are validated.
     E. THE SWITCH ROUTE: requireAuth, requireActiveSubscription, the limiter;
        a member cannot add an undeclared link (link_not_declared, nothing
        written); the closed body; only the caller's row is written.
     F. A SWITCHED-OFF LINK REFUSES with link_disabled_by_member and is
        recorded as G26, on all four carriers: the plan dispatch (and its
        executive_dispatches row), the Executive-to-Sales handoff, approving
        an SEO post, and R&D demand signals. Nothing runs.
     G. EVERY OTHER PATH IS UNCHANGED, old (PRE_NETWORK) against new:
        dispatchToolCall over the refusal matrix (with and without fromAgent,
        links on, switches unreadable), the assignment route, the approve
        route; byte proofs that each carrier is the old text plus exactly its
        one inserted block; the chain limits identical.
     H. EXPORT, DELETION, BACKUP and MIGRATION 161, run on lib/yourData.js.
     U. THE MAP in jsdom: 18 nodes, 18 edges; a lit edge pulses, thicker by
        count; a 0 or unreadable edge is dim and never animated; under reduced
        motion nothing pulses and counts show; the text list equals the map;
        nodes and edges take keyboard focus; Enter opens a link's runs with
        "Open run" and "Why?"; the switch confirms before it writes; refresh
        only while visible.
     S. No emoji in any new or edited file.

   MUTATIONS — MUTATE=<name> applies one in memory; MUTATE=all runs each:
     animate-unlit                  a 0-run edge pulses                     -> U
     counts-from-another-member     the dispatch read drops its user_id     -> C
     undeclared-link-accepted       the switch accepts any pair            -> E
     switched-off-still-dispatching the dispatcher ignores the switch       -> F
     refusal-not-recorded           the G26 dispatch record is not written -> F
     refreshing-while-hidden        the map refreshes while hidden         -> U
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const { execFileSync } = require("child_process");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const read = p => fs.readFileSync(path.join(REPO, p), "utf8").replace(/\r\n/g, "\n");
const readFe = p => fs.readFileSync(path.join(FRONTEND, p), "utf8").replace(/\r\n/g, "\n");
const PRE_NETWORK = "ff7821e";

const MUTATIONS = {
  "animate-unlit": ["ui",
    "var pulse = lit(e) && !calm ?", "var pulse = !calm ?"],
  "counts-from-another-member": ["lib",
    ".eq(\"user_id\", userId).eq(\"outcome\", \"ran\")", ".eq(\"outcome\", \"ran\")"],
  "undeclared-link-accepted": ["lib",
    "  if (!isDeclared(graph, body.from, body.to)) {", "  if (false) {"],
  "switched-off-still-dispatching": ["server",
    "  if (dispatchOpts.fromAgent && await memberLinkOff(", "  if (false && await memberLinkOff("],
  "refusal-not-recorded": ["server",
    "    recordGateDecision(dispatchOpts.userId, \"dispatch\", dispatchTarget, { G26: { result: \"fail\", code: \"link_disabled_by_member\" } },\n      { gates: [\"G26\", \"G19\", \"G12\"], facts: { agent: linkTo } });\n", ""],
  "refreshing-while-hidden": ["ui",
    "  function shown() { return !!S.box && !document.hidden && !(S.box.closest && S.box.closest(\"[hidden]\")); }",
    "  function shown() { return !!S.box; }"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 500) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = {
  lib: read("lib/agentNetwork.js"),
  server: read("server.js"),
  gates: read("lib/gates.js"),
  migration: read("supabase/migrations/161_member_links.sql"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  ui: readFe("scripts/bf-network.js"),
  execHtml: readFe("executive-agent.html"),
  hq: readFe("scripts/bf-hq.js"),
  offline: readFe("scripts/bf-offline.js"),
  guide: readFe("scripts/termaximus-guide.js")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}
const OLD = execFileSync("git", ["show", PRE_NETWORK + ":server.js"], { cwd: REPO, maxBuffer: 64 << 20 }).toString("utf8").replace(/\r\n/g, "\n");
const NEW = FILES.server;

const J = JSON.stringify;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const GATES = realRequire("./lib/gates");
const RULES = realRequire("./lib/gateRules");
function compileLib(src) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require"], { filename: "lib/agentNetwork.js" });
  fn(m, m.exports, function (r) { return realRequire(r.replace(/^\.\//, "./lib/")); });
  return m.exports;
}
const NET = compileLib(FILES.lib);
function libRequire(p) {
  if (p === "./lib/agentNetwork") return NET;
  if (p === "./lib/gates") return GATES;
  if (p === "./lib/gateRules") return RULES;
  if (p.indexOf("./") === 0) return realRequire(p);
  return realRequire(p);
}

/* ── lifting, as checkGates lifts: an index of top-level definitions, a closure ── */
function braceMatch(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}
function indexDefs(src) {
  const defs = new Map(), spans = [];
  defs.pos = new Map();
  const fre = /^(?:async )?function ([A-Za-z_$][A-Za-z0-9_$]*)\(/gm; let m;
  while ((m = fre.exec(src))) {
    const end = braceMatch(src, src.indexOf(") {", m.index) + 2);
    if (end < 0) continue;
    spans.push([m.index, end]);
    if (!defs.has(m[1])) { defs.set(m[1], src.slice(m.index, end)); defs.pos.set(m[1], m.index); }
  }
  const are = /^app[.][a-z]+[(]/gm;
  while ((m = are.exec(src))) { const end = braceMatch(src, src.indexOf("{", m.index)); if (end > 0) spans.push([m.index, end]); }
  const inside = idx => spans.some(s => idx > s[0] && idx < s[1]);
  const vre = /^(?:var|const|let) ([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=[ \t]*/gm;
  while ((m = vre.exec(src))) {
    if (defs.has(m[1]) || inside(m.index)) continue;
    const brk = /;\r?\n/g; brk.lastIndex = m.index + m[0].length; let b;
    while ((b = brk.exec(src))) {
      const nextCh = src[b.index + b[0].length];
      if (nextCh === undefined || nextCh === "\n" || /[^\s]/.test(nextCh)) { defs.set(m[1], src.slice(m.index, b.index + 1)); defs.pos.set(m[1], m.index); break; }
    }
  }
  return defs;
}
const DEFS = { old: indexDefs(OLD), new: indexDefs(NEW) };
const SRC = { old: OLD, new: NEW };
const BASE_STUBS = ["supabase", "console", "process", "require", "module", "nowIso", "Date", "Math", "JSON", "Object", "Number", "String",
  "Array", "Promise", "Error", "app", "setImmediate", "setTimeout", "OWNER_ACCOUNT_ID", "isTestAccount", "requireAuth", "opsAlerts", "AsyncLocalStorage",
  "requireActiveSubscription", "aiLimiter", "rateLimit", "express", "crypto"];
function closure(which, rootCode, stubs) {
  const defs = DEFS[which]; const skip = new Set(BASE_STUBS.concat(stubs || []));
  const have = new Map(); const queue = [...new Set(rootCode.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || skip.has(name)) continue;
    const def = defs.get(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !skip.has(id)) queue.push(id); });
  }
  return [...have.keys()].sort((a, b) => defs.pos.get(a) - defs.pos.get(b)).map(k => have.get(k)).join("\n\n") + "\n\n" + rootCode;
}
function routeSource(which, sig) {
  const src = SRC[which]; const start = src.indexOf(sig);
  if (start < 0) throw new Error("route not found in " + which + ": " + sig);
  const fnAt = src.indexOf("function (req, res", start);
  const end = braceMatch(src, src.indexOf("{", fnAt));
  return src.slice(start, end) + ");";
}
const SCRIPTS = new Map();
function script(which, key, rootCode, stubs, exportsExpr) {
  const k = which + "|" + key;
  if (!SCRIPTS.has(k)) SCRIPTS.set(k, new vm.Script(closure(which, rootCode, stubs) + "\n;this.__api = { " + exportsExpr + " };", { filename: which + "-" + key + ".js" }));
  return SCRIPTS.get(k);
}

/* ── an in-memory database: filters, pages, upserts, a log, faults ──────── */
function UUID(n) { return "00000000-0000-4000-8000-" + String(n).padStart(12, "0"); }
function makeDb(seed, faults) {
  const tables = JSON.parse(J(seed || {}));
  const log = [];
  const fail = faults || {};
  let auto = 9000;
  function cmp(a, b) { const x = String(a), y = String(b); return x < y ? -1 : x > y ? 1 : 0; }
  function matches(r, f) {
    const [k, c, v] = f; const val = r[c];
    if (k === "eq") return val === v || (val != null && v != null && String(val) === String(v));
    if (k === "neq") return !(val === v || String(val) === String(v));
    if (k === "gt") return val != null && cmp(val, v) > 0;
    if (k === "gte") return val != null && cmp(val, v) >= 0;
    if (k === "lt") return val != null && cmp(val, v) < 0;
    if (k === "lte") return val != null && cmp(val, v) <= 0;
    if (k === "in") return v.some(x => String(x) === String(val));
    if (k === "like") return typeof val === "string" && (v.endsWith("%") ? val.indexOf(v.slice(0, -1)) === 0 : val === v);
    if (k === "is") return v === null ? val === null || val === undefined : val === v;
    return false;
  }
  class Q {
    constructor(t) { this.t = t; this.op = "select"; this.f = []; this.opts = {}; this.payload = null; this.ord = null; this.rng = null; this.lim = null; this.mode = null; this.sel = false; this.conflict = null; }
    select(cols, opts) { if (this.op === "select") { this.cols = cols; this.opts = opts || {}; } else this.sel = true; return this; }
    insert(p) { this.op = "insert"; this.payload = p; return this; }
    upsert(p, o) { this.op = "upsert"; this.payload = p; this.conflict = o && o.onConflict; return this; }
    update(p) { this.op = "update"; this.payload = p; return this; }
    delete() { this.op = "delete"; return this; }
    eq(c, v) { this.f.push(["eq", c, v]); return this; }
    neq(c, v) { this.f.push(["neq", c, v]); return this; }
    gt(c, v) { this.f.push(["gt", c, v]); return this; }
    gte(c, v) { this.f.push(["gte", c, v]); return this; }
    lt(c, v) { this.f.push(["lt", c, v]); return this; }
    lte(c, v) { this.f.push(["lte", c, v]); return this; }
    in(c, v) { this.f.push(["in", c, v.slice()]); return this; }
    like(c, v) { this.f.push(["like", c, v]); return this; }
    ilike(c, v) { this.f.push(["like", c, v]); return this; }
    is(c, v) { this.f.push(["is", c, v]); return this; }
    not(c, op, v) { return this; }
    order(c, o) { this.ord = [c, !(o && o.ascending === false)]; return this; }
    range(a, b) { this.rng = [a, b]; return this; }
    limit(n) { this.lim = n; return this; }
    maybeSingle() { this.mode = "maybe"; return this; }
    single() { this.mode = "single"; return this; }
    then(res, rej) { return Promise.resolve().then(() => this.exec()).then(res, rej); }
    exec() {
      log.push({ table: this.t, op: this.op, filters: this.f.map(x => x.slice()), payload: this.payload === null ? null : JSON.parse(J(this.payload)) });
      const fk = this.t + ":" + this.op;
      if (fail[fk] === "throw") throw new Error(this.t + " threw");
      if (fail[fk]) return { data: null, error: { message: this.t + " down", code: fail[fk] === true ? "XX000" : fail[fk] } };
      const rows = tables[this.t] || (tables[this.t] = []);
      const match = r => this.f.every(x => matches(r, x));
      if (this.op === "select") {
        let hit = rows.filter(match);
        const count = hit.length;
        if (this.ord) { const [c, asc] = this.ord; hit = hit.slice().sort((x, y) => (asc ? 1 : -1) * cmp(x[c], y[c])); }
        if (this.rng) hit = hit.slice(this.rng[0], this.rng[1] + 1);
        if (this.lim != null) hit = hit.slice(0, this.lim);
        const data = this.opts.head ? null : hit.map(r => Object.assign({}, r));
        if (this.mode === "maybe") return { data: data && data.length ? data[0] : null, error: null, count };
        if (this.mode === "single") return data && data.length === 1 ? { data: data[0], error: null } : { data: null, error: { message: "not one row", code: "PGRST116" } };
        return { data, error: null, count };
      }
      if (this.op === "insert" || this.op === "upsert") {
        const list = Array.isArray(this.payload) ? this.payload : [this.payload];
        const made = [];
        for (const p of list) {
          let row = null;
          if (this.op === "upsert" && this.conflict) {
            const keys = this.conflict.split(",");
            row = rows.filter(r => keys.every(k => r[k] === p[k]))[0] || null;
            if (row) Object.assign(row, p);
          }
          if (!row) { row = Object.assign({}, p); if (!row.id) row.id = UUID(++auto); rows.push(row); }
          made.push(Object.assign({}, row));
        }
        if (this.mode === "single") return { data: made[0], error: null };
        return { data: this.sel ? made : null, error: null };
      }
      if (this.op === "update") {
        const hit = rows.filter(match);
        hit.forEach(r => Object.assign(r, this.payload));
        const data = hit.map(r => Object.assign({}, r));
        if (this.mode === "maybe") return { data: data[0] || null, error: null };
        if (this.mode === "single") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { message: "not one row", code: "PGRST116" } };
        return { data: this.sel ? data : null, error: null };
      }
      if (this.op === "delete") {
        const keep = [], gone = [];
        rows.forEach(r => (match(r) ? gone : keep).push(r));
        tables[this.t] = keep;
        return { data: this.sel ? gone : null, error: null };
      }
      return { data: null, error: { message: "unknown op" } };
    }
  }
  const from = t => {
    if (fail[t + ":from"] === "throw") throw new Error(t + " from threw");
    return new Q(t);
  };
  return { client: { from: from }, tables, log, fail };
}

/* ── contexts, a request and a response ──────────────────────────────────── */
const FIXED = Date.parse("2026-11-01T12:00:00.000Z");
class FixedDate extends Date {
  constructor(...a) { if (a.length === 0) super(FIXED); else super(...a); }
  static now() { return FIXED; }
}
function makeCtx(db, globals, env) {
  const logs = [];
  const line = k => function () { logs.push(k + " " + Array.prototype.map.call(arguments, a => (a && a.message) ? a.message : (typeof a === "object" ? J(a) : String(a))).join(" ")); };
  const sandbox = Object.assign({
    supabase: db.client,
    console: { log: line("log"), warn: line("warn"), error: line("error"), info: line("info") },
    process: { env: Object.assign({ ENABLE_AGENT_CHAINING: "true" }, env || {}) },
    require: libRequire,
    OWNER_ACCOUNT_ID: OWNER,
    isTestAccount: () => false,
    nowIso: () => new FixedDate().toISOString(),
    Date: FixedDate,
    crypto: { randomUUID: (function () { let n = 700; return () => UUID(++n); })() },
    setImmediate: setImmediate, setTimeout: setTimeout, clearTimeout: clearTimeout, Buffer: Buffer, URL: URL,
    encodeURIComponent: encodeURIComponent,
    AsyncLocalStorage: require("async_hooks").AsyncLocalStorage,
    rateLimit: () => function (req, res, next) { next(); },
    requireAuth: function requireAuth(req, res, next) { next(); },
    requireActiveSubscription: function requireActiveSubscription(req, res, next) { next(); },
    aiLimiter: function aiLimiter(req, res, next) { next(); }
  }, globals || {});
  vm.createContext(sandbox);
  return { sandbox, logs, db };
}
function appStub() {
  const routes = {};
  const reg = m => function (p) { routes[m + " " + p] = Array.prototype.slice.call(arguments, 1); };
  return { get: reg("get"), put: reg("put"), post: reg("post"), delete: reg("delete"), routes };
}
function makeRes() {
  return {
    statusCode: 200, body: undefined, sent: 0,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(J(b === undefined ? null : b)); this.sent++; return this; }
  };
}
async function runRoute(handlers, req) {
  const res = makeRes();
  let err = null;
  await new Promise(resolve => {
    const fin = handlers[handlers.length - 1];
    Promise.resolve(fin(req, res, e => { err = e; resolve(); })).then(resolve, e => { err = e; resolve(); });
  });
  await settle();
  return { status: res.statusCode, body: res.body, err: err ? (err.message || String(err)) : null };
}
const tick = () => new Promise(r => setImmediate(r));
async function settle() { for (let i = 0; i < 6; i++) await tick(); }

const A = UUID(1), B = UUID(2), OWNER = realRequire("./lib/ownerAccount").OWNER_ACCOUNT_ID;
const H = 3600000, D = 24 * H;
const ago = ms => new Date(FIXED - ms).toISOString();

/* ── the server's own lists ──────────────────────────────────────────────── */
const SPEC_CTX = { toolField: function () { return {}; } };
vm.createContext(SPEC_CTX);
vm.runInContext(DEFS.new.get("TOOL_INPUT_SPECS").replace(/^var /, "this.") + "\n" + DEFS.new.get("CHAIN_NON_DISPATCHABLE_TOOLS").replace(/^var /, "this."), SPEC_CTX);
const SPEC_KEYS = Object.keys(SPEC_CTX.TOOL_INPUT_SPECS);
const ACTS = SPEC_CTX.CHAIN_NON_DISPATCHABLE_TOOLS.slice();

/* ── the network routes, lifted into one context per database ────────────── */
const ROUTE_SIGS = ['app.get("/api/agents/network", ', 'app.get("/api/agents/network/edge", ', 'app.put("/api/agents/network/links", '];
function networkApp(db, env) {
  const app = appStub();
  const c = makeCtx(db, { app: app, networkLimiter: function networkLimiter(req, res, next) { next(); } }, env);
  const root = ROUTE_SIGS.map(s => routeSource("new", s)).join("\n");
  script("new", "network", root, ["networkLimiter"], "x: 1").runInContext(c.sandbox);
  return { app, c };
}
async function getNetwork(db, user, query) {
  const n = networkApp(db);
  return runRoute(n.app.routes["get /api/agents/network"], { user: { id: user }, query: query || {} });
}

(async function main() {
  try {
  /* ═══ A. the graph ═══════════════════════════════════════════════════════ */
  console.log("\n== A. the declared graph, from the server's own lists ==");
  const G = NET.buildGraph(SPEC_KEYS, ACTS);
  const WANT_EDGES = ["executive>ads", "executive>analytics", "executive>broker", "executive>community", "executive>content", "executive>email",
    "executive>etsy", "executive>influencer", "executive>operations", "executive>publicist", "executive>rd", "executive>reputation", "executive>seo",
    "executive>social", "executive>vertical_marketing", "executive>sales", "seo>content", "sales>rd"];
  check("A1. 18 nodes, the Executive first (the centre)", G.nodes.length === 18 && G.nodes[0] === "executive" && NET.CENTRE === "executive" && new Set(G.nodes).size === 18, J(G.nodes));
  check("A2. exactly the 18 declared links", J(G.edges.map(e => e.id)) === J(WANT_EDGES), J(G.edges.map(e => e.id)));
  check("A3. the graph validates: no problems", G.problems.length === 0 && NET.validateGraph(G, SPEC_KEYS, ACTS).length === 0, J(G.problems));
  const dispatchTools = [].concat(...G.edges.map(e => e.sources.filter(s => s.kind === "dispatch").map(s => s.tools)).flat());
  check("A4. every dispatch tool is in TOOL_INPUT_SPECS and none is on the non-dispatchable list",
    dispatchTools.length > 0 && dispatchTools.every(t => SPEC_KEYS.indexOf(t) !== -1 && ACTS.indexOf(t) === -1), J(dispatchTools));
  const withTools = G.nodes.filter(k => k !== "executive" && SPEC_KEYS.some(t => t.indexOf(k + "/") === 0 && ACTS.indexOf(t) === -1));
  const dispatchTo = G.edges.filter(e => e.sources.some(s => s.kind === "dispatch")).map(e => e.to).sort();
  check("A5. an Executive dispatch link exists exactly for the agents with a dispatchable tool (not sales, store or the Executive itself)",
    J(dispatchTo) === J(withTools.slice().sort()) && dispatchTo.indexOf("sales") === -1 && dispatchTo.indexOf("store") === -1 && dispatchTo.indexOf("executive") === -1, J(dispatchTo));
  const execDispatch = G.edges.filter(e => e.from === "executive" && e.sources.some(s => s.kind === "dispatch"));
  check("A6. each dispatch link carries every dispatchable tool of its agent, and only those",
    execDispatch.every(e => J(e.sources[0].tools) === J(SPEC_KEYS.filter(t => t.indexOf(e.to + "/") === 0 && ACTS.indexOf(t) === -1).sort())));
  check("A7. the approval-only link's tool (seo/generate-post) is on the non-dispatchable list; the signals tool is a spec",
    ACTS.indexOf("seo/generate-post") !== -1 && SPEC_KEYS.indexOf("rd/demand-signals") !== -1 &&
    J(G.edges.filter(e => e.id === "seo>content")[0].sources.map(s => s.kind)) === J(["proposal"]) &&
    J(G.edges.filter(e => e.id === "sales>rd")[0].sources.map(s => s.kind)) === J(["signals"]) &&
    J(G.edges.filter(e => e.id === "executive>sales")[0].sources.map(s => s.kind)) === J(["handoff"]));
  const bad = (edges) => NET.validateGraph({ nodes: G.nodes, edges: edges }, SPEC_KEYS, ACTS);
  const one = (id, from, to, kind, tools) => ({ id, from, to, sources: [{ kind, tools: tools || [] }] });
  check("A8. validateGraph refuses an acting tool as a dispatch", bad([one("executive>seo", "executive", "seo", "dispatch", ["seo/generate-post"])]).length > 0);
  check("A8. ... a tool not in the specs", bad([one("executive>seo", "executive", "seo", "dispatch", ["seo/nothing"])]).length > 0);
  check("A8. ... a self link, an unknown agent, a duplicate, a dispatch not from the Executive",
    bad([one("seo>seo", "seo", "seo", "handoff")]).length > 0 && bad([one("executive>general", "executive", "general", "handoff")]).length > 0 &&
    bad([one("seo>content", "seo", "content", "handoff"), one("seo>content", "seo", "content", "handoff")]).length > 0 &&
    bad([one("seo>content", "seo", "content", "dispatch", ["content/audit"])]).length > 0);
  check("A8. ... a source of an unknown kind, a link with no source, an id that is not from>to",
    bad([one("seo>content", "seo", "content", "collaboration")]).length > 0 && bad([{ id: "seo>content", from: "seo", to: "content", sources: [] }]).length > 0 &&
    bad([one("x", "seo", "content", "handoff")]).length > 0);
  const broken = NET.buildGraph(SPEC_KEYS.filter(k => k !== "seo/generate-post"), ACTS);
  check("A9. a link whose tool left the specs is dropped and named, never guessed", broken.edges.every(e => e.id !== "seo>content") && broken.problems.some(p => /seo>content/.test(p)), J(broken.problems));
  const moved = NET.buildGraph(SPEC_KEYS, ACTS.concat(["ads/copy", "ads/policy-check"]));
  check("A9. an agent whose tools all move onto the non-dispatchable list loses its dispatch link", moved.edges.every(e => e.id !== "executive>ads"));
  check("A10. the existing chain limits are unchanged (chainLimit, the three limits, the rate, the list)",
    ["chainLimit", "chainMaxDepth", "chainMaxFanout", "chainMaxCalls", "dispatchPerMinuteLimit", "CHAIN_NON_DISPATCHABLE_TOOLS", "chainFanoutNote", "dispatchToolCallSteps"]
      .every(n => DEFS.old.get(n) && DEFS.old.get(n) === DEFS.new.get(n)));

  /* ═══ B. agent_collaborations ════════════════════════════════════════════ */
  console.log("\n== B. agent_collaborations is never drawn ==");
  check("B1. no edge, source or label names a collaboration", !/collaboration/i.test(J(G.edges)));
  check("B2. lib/agentNetwork.js never reads agent_collaborations", !/from\("agent_collaborations"\)/.test(FILES.lib) && !/\.from\(\s*["']agent_collaborations/.test(FILES.lib));
  check("B3. the routes read nothing of it", ROUTE_SIGS.every(s => routeSource("new", s).indexOf("agent_collaborations") === -1));

  /* ═══ C. counts from records, scoped ═════════════════════════════════════ */
  console.log("\n== C. counts come only from recorded rows, scoped to the member ==");
  let n = 100;
  const seed = { executive_dispatches: [], ai_tasks: [], agent_proposals: [], agent_collaborations: [], member_links: [], gate_decisions: [] };
  const dsp = (u, to, outcome, at) => seed.executive_dispatches.push({ id: UUID(++n), user_id: u, plan_task_id: UUID(50), assignment_id: 1, agent_type: to, tool: "x", outcome, tool_task_id: UUID(n + 5000), chain_id: UUID(n + 7000), created_at: at });
  [1, 2, 3].forEach(h => dsp(A, "seo", "ran", ago(h * H - 60000)));              // 3 in 24h, 1 in 1h... (h=1 is 59 min ago)
  dsp(A, "seo", "ran", ago(3 * D));                                               // 7d only
  dsp(A, "seo", "refused", ago(H));                                               // refused: not a flow
  dsp(A, "seo", "failed", ago(H));                                                // failed: not a flow
  dsp(A, "content", "ran", ago(10 * D));                                          // outside 7d
  dsp(A, "content", "ran", ago(2 * H));
  for (let i = 0; i < 9; i++) dsp(B, "seo", "ran", ago(H));                      // the other member's
  const task = (u, agent, extra, at) => seed.ai_tasks.push(Object.assign({ id: UUID(++n), user_id: u, agent_type: agent, prompt: "x", status: "completed", task_type: "general", created_at: at }, extra));
  task(A, "sales", { prompt: "Executive handoff: grow" }, ago(30 * 60000));
  task(A, "sales", { prompt: "Executive handoff: more" }, ago(5 * D));
  task(A, "sales", { prompt: "Not a handoff" }, ago(H));
  task(A, "content", { prompt: "Executive handoff: wrong agent" }, ago(H));
  task(B, "sales", { prompt: "Executive handoff: theirs" }, ago(H));
  task(OWNER, "rd", { task_type: "rd/demand-signals" }, ago(2 * H));
  task(OWNER, "rd", { task_type: "rd/demand-signals", status: "failed" }, ago(2 * H));
  task(OWNER, "rd", { task_type: "rd/brief" }, ago(2 * H));
  task(A, "rd", { task_type: "rd/demand-signals" }, ago(3 * H));
  const prop = (u, agent, action, status, at) => seed.agent_proposals.push({ id: UUID(++n), user_id: u, agent_type: agent, action_type: action, status, executed_at: at });
  prop(A, "seo", "publish_blog_post", "executed", ago(4 * H));
  prop(A, "seo", "publish_blog_post", "executed", ago(6 * D));
  prop(A, "seo", "publish_blog_post", "pending", null);
  prop(A, "store", "update_listing", "executed", ago(H));
  prop(B, "seo", "publish_blog_post", "executed", ago(H));
  for (let i = 0; i < 13; i++) seed.agent_collaborations.push({ id: UUID(++n), user_id: A, source_agent: "seo", target_agent: "content", status: "pending", created_at: ago(H) });
  const countOf = (body, id) => (body.edges.filter(e => e.id === id)[0] || {}).count;
  const want = {
    "1h":  { "executive>seo": 1, "executive>content": 0, "executive>sales": 1, "seo>content": 0, "sales>rd": 0 },
    "24h": { "executive>seo": 3, "executive>content": 1, "executive>sales": 1, "seo>content": 1, "sales>rd": 1 },
    "7d":  { "executive>seo": 4, "executive>content": 1, "executive>sales": 2, "seo>content": 2, "sales>rd": 1 }
  };
  for (const w of ["1h", "24h", "7d"]) {
    const db = makeDb(seed);
    const r = await getNetwork(db, A, { window: w });
    const got = {}; Object.keys(want[w]).forEach(id => { got[id] = r.body && countOf(r.body, id); });
    check("C1. member A, last " + w + ": each count is the hand count of A's own recorded runs", r.status === 200 && J(got) === J(want[w]), J(got) + " " + J(r.err));
    const reads = db.log.filter(l => l.op === "select" && l.table !== "member_links");
    check("C2. " + w + ": every read names A's user_id", reads.length > 0 && reads.every(l => l.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === A)), J(reads.filter(l => !l.filters.some(f => f[1] === "user_id")).slice(0, 2)));
    check("C3. " + w + ": nothing is written, and agent_collaborations is never read", db.log.every(l => l.op === "select") && db.log.every(l => l.table !== "agent_collaborations"));
    check("C4. " + w + ": every other link is 0, and every count is a number", r.body.edges.every(e => typeof e.count === "number") &&
      r.body.edges.filter(e => !Object.prototype.hasOwnProperty.call(want[w], e.id)).every(e => e.count === 0));
  }
  {
    const r = await getNetwork(makeDb(seed), B, { window: "24h" });
    check("C5. member B sees only B's runs (9 dispatches, 1 handoff, 1 post)", countOf(r.body, "executive>seo") === 9 && countOf(r.body, "executive>sales") === 1 && countOf(r.body, "seo>content") === 1 && countOf(r.body, "sales>rd") === 0, J(r.body && r.body.edges.filter(e => e.count)));
    const o = await getNetwork(makeDb(seed), OWNER, { window: "24h" });
    check("C6. the owner's demand-signal runs count on sales>rd: completed ones only", countOf(o.body, "sales>rd") === 1);
    const failing = makeDb(seed, { "executive_dispatches:select": true });
    const f = await getNetwork(failing, A, { window: "24h" });
    check("C7. a read that fails is a null count with a reason, never 0; the other links still count",
      f.status === 200 && f.body.edges.filter(e => e.kinds.indexOf("dispatch") !== -1).every(e => e.count === null && typeof e.unavailable === "string") &&
      countOf(f.body, "seo>content") === 1, J(f.body && f.body.edges.slice(0, 2)));
    const bigSeed = JSON.parse(J(seed));
    for (let i = 0; i < 1203; i++) bigSeed.executive_dispatches.push({ id: UUID(20000 + i), user_id: A, agent_type: "email", tool: "sequence", outcome: "ran", tool_task_id: null, chain_id: null, created_at: ago(2 * H) });
    const big = await getNetwork(makeDb(bigSeed), A, { window: "24h" });
    check("C8. counts read every page (1203 rows across two pages)", countOf(big.body, "executive>email") === 1203, countOf(big.body, "executive>email"));
    const badW = await getNetwork(makeDb(seed), A, { window: "40d" });
    const badW2 = await getNetwork(makeDb(seed), A, { window: "1w" });
    check("C9. a window over 30 days, or not minutes/hours/days, is 400", badW.status === 400 && badW2.status === 400 && badW.body.field === "window");
    const mins = await getNetwork(makeDb(seed), A, { window: "120m" });
    check("C9. a window in minutes works (120m: 2 dispatches to SEO, at 59 and 119 minutes)", mins.status === 200 && countOf(mins.body, "executive>seo") === 2, countOf(mins.body, "executive>seo"));
    check("C10. the answer carries the chain limits as the server reads them, the window and what is not drawn",
      mins.body.chain_limits && mins.body.chain_limits.depth === 2 && mins.body.chain_limits.fanout === 3 && mins.body.chain_limits.calls === 10 &&
      mins.body.window === "120m" && Array.isArray(mins.body.not_drawn) && mins.body.not_drawn.some(x => x.what === "agent_collaborations"));
  }

  /* ═══ D. the edge route ══════════════════════════════════════════════════ */
  console.log("\n== D. one link's runs ==");
  {
    const s2 = JSON.parse(J(seed));
    for (let i = 0; i < 25; i++) s2.executive_dispatches.push({ id: UUID(30000 + i), user_id: A, agent_type: "ads", tool: "copy", outcome: "ran", tool_task_id: UUID(31000 + i), chain_id: UUID(32000 + i), created_at: ago((i + 1) * 60000) });
    const na = networkApp(makeDb(s2));
    const edge = q => runRoute(na.app.routes["get /api/agents/network/edge"], { user: { id: A }, query: q });
    const p1 = await edge({ from: "executive", to: "ads", window: "24h" });
    const p2 = await edge({ from: "executive", to: "ads", window: "24h", page: "2" });
    check("D1. 25 runs: 20 on page 1, 5 on page 2, 2 pages, newest first", p1.body.runs.length === 20 && p2.body.runs.length === 5 && p1.body.total === 25 && p1.body.pages === 2 &&
      p1.body.runs[0].at > p1.body.runs[1].at, J(p1.body && [p1.body.total, p1.body.pages]));
    const r0 = p1.body.runs[0];
    check("D2. a run opens run.html at its tool's task, with Why? on that task, and carries the chain id",
      r0.href === "/run.html?id=" + r0.task_id && r0.why === "ai_task:" + r0.task_id && /^0{8}-/.test(r0.chain_id), J(r0));
    const post = await edge({ from: "seo", to: "content", window: "7d" });
    check("D3. a published post's run has Why? on its proposal and no run page", post.body.runs.length === 2 && post.body.runs.every(r => r.href === null && /^proposal:/.test(r.why)));
    const nope = await edge({ from: "content", to: "seo", window: "24h" });
    const nope2 = await edge({ from: "executive", to: "store", window: "24h" });
    check("D4. an undeclared pair is 404 link_not_declared", nope.status === 404 && nope2.status === 404 && nope.body.reason === "link_not_declared");
    const badPage = await edge({ from: "executive", to: "ads", page: "0" });
    check("D5. the page is validated", badPage.status === 400);
    const fd = networkApp(makeDb(s2, { "executive_dispatches:select": true }));
    const fr = await runRoute(fd.app.routes["get /api/agents/network/edge"], { user: { id: A }, query: { from: "executive", to: "ads" } });
    check("D6. runs that cannot be read are 503, never an empty list", fr.status === 503 && fr.body.reason === "runs_unreadable");
    check("D7. another member's runs never appear", p1.body.runs.length + p2.body.runs.length === 25);
  }

  /* ═══ E. the switch route ════════════════════════════════════════════════ */
  console.log("\n== E. switching a link ==");
  {
    const sig = 'app.put("/api/agents/network/links", requireAuth, requireActiveSubscription, networkLimiter, async function (req, res, next) {';
    check("E0. the switch is requireAuth, requireActiveSubscription, networkLimiter; the reads requireAuth and networkLimiter",
      NEW.indexOf(sig) !== -1 && NEW.indexOf('app.get("/api/agents/network", requireAuth, networkLimiter, async function (req, res, next) {') !== -1 &&
      NEW.indexOf('app.get("/api/agents/network/edge", requireAuth, networkLimiter, async function (req, res, next) {') !== -1 &&
      /const networkLimiter = rateLimit\(\{\n  windowMs: 10 \* 60 \* 1000,\n  max: 120,\n  keyGenerator: function \(req\) \{ return "network:" \+ \(req\.user && req\.user\.id\); \},/.test(NEW));
    check("E0. registered above /api/agents/:type, which would swallow /api/agents/network", NEW.indexOf('app.get("/api/agents/network", ') < NEW.indexOf('app.get("/api/agents/:type", '));
    const db = makeDb({ member_links: [{ id: UUID(77), user_id: B, from_agent: "executive", to_agent: "seo", enabled: false }] });
    const na = networkApp(db);
    const put = (u, body) => runRoute(na.app.routes["put /api/agents/network/links"], { user: { id: u }, body: body });
    const writes = () => db.log.filter(l => l.op !== "select");
    const und = await put(A, { from: "content", to: "seo", enabled: true });
    const und2 = await put(A, { from: "executive", to: "general", enabled: false });
    const und3 = await put(A, { from: "store", to: "store", enabled: false });
    check("E1. a member cannot add an undeclared link: 400 link_not_declared, nothing written",
      und.status === 400 && und.body.reason === "link_not_declared" && und2.status === 400 && und3.status === 400 && writes().length === 0, J(und.body));
    const extra = await put(A, { from: "executive", to: "seo", enabled: false, user_id: B });
    const notBool = await put(A, { from: "executive", to: "seo", enabled: "false" });
    const arr = await put(A, [1]);
    check("E2. the closed body: an extra field, a non-boolean, an array are refused, nothing written",
      extra.status === 400 && extra.body.field === "user_id" && notBool.status === 400 && arr.status === 400 && writes().length === 0);
    const off = await put(A, { from: "executive", to: "seo", enabled: false });
    check("E3. switching a declared link off writes the caller's own row only", off.status === 200 && off.body.link.enabled === false &&
      db.tables.member_links.filter(r => r.user_id === A).length === 1 && db.tables.member_links.filter(r => r.user_id === B)[0].enabled === false &&
      writes().every(w => w.payload.user_id === A), J(off.body));
    const on = await put(A, { from: "executive", to: "seo", enabled: true });
    check("E4. switching it on again updates the same row (one row per link)", on.status === 200 && on.body.link.enabled === true &&
      db.tables.member_links.filter(r => r.user_id === A).length === 1 && db.tables.member_links.filter(r => r.user_id === A)[0].enabled === true);
    const g = await runRoute(na.app.routes["get /api/agents/network"], { user: { id: B }, query: {} });
    check("E5. the map says which links the member switched off", g.body.edges.filter(e => e.id === "executive>seo")[0].enabled === false &&
      g.body.edges.filter(e => e.id !== "executive>seo").every(e => e.enabled === true));
    const down = networkApp(makeDb({}, { "member_links:upsert": true }));
    const d = await runRoute(down.app.routes["put /api/agents/network/links"], { user: { id: A }, body: { from: "seo", to: "content", enabled: false } });
    check("E6. a write that fails is 503 and says nothing changed", d.status === 503 && /Nothing was changed/.test(d.body.error));
    check("E7. validateSwitch names every field it refuses", NET.validateSwitch({ from: "x", to: "seo", enabled: true }, G).field === "from" &&
      NET.validateSwitch({ from: "seo", to: "x", enabled: true }, G).field === "to");
  }

  /* ═══ F. a switched-off link refuses, and is recorded ════════════════════ */
  console.log("\n== F. a switched-off link refuses with link_disabled_by_member, recorded as G26 ==");
  const OFF = (u, f, t) => ({ id: UUID(880), user_id: u, from_agent: f, to_agent: t, enabled: false });
  const SPECS_STUB = [
    { key: "seo/audit", path: "/api/agents/seo/audit", spec: [{ name: "url", required: true }] },
    { key: "content/outline", path: "/api/agents/content/outline", spec: [{ name: "topic", required: true }] }
  ];
  function dispatchGlobals(calls) {
    return {
      agentToolRoutes: () => SPECS_STUB,
      resolveToolRouteHandler: function (p) {
        return function (req, res) { calls.push(p); res.status(200).json({ ok: true, task_id: UUID(4242) }); };
      },
      agentChainScope: { run: function (ctxv, fn) { return fn(); } },
      getUserPlan: async function () { return { active: true }; }
    };
  }
  const PLAN = UUID(600);
  function planSeed(extra) {
    return Object.assign({
      ai_tasks: [{ id: PLAN, user_id: A, task_type: "executive/plan", status: "completed", output: { assignments: [
        { id: 1, agent: "seo", tool: "audit", is_dispatchable: true, inputs: { url: "https://example.com" } },
        { id: 2, agent: "content", tool: "outline", is_dispatchable: false, problems: ["x"] }] } }],
      executive_dispatches: [], gate_decisions: [], member_links: []
    }, extra || {});
  }
  const ASSIGN_SIG = 'app.post("/api/assignments/dispatch", ';
  async function assignRun(which, seedObj, body, env, faults) {
    const calls = [];
    const db = makeDb(seedObj, faults);
    const app = appStub();
    const c = makeCtx(db, Object.assign({ app: app }, dispatchGlobals(calls)), env);
    script(which, "assign", routeSource(which, ASSIGN_SIG), ["agentToolRoutes", "resolveToolRouteHandler", "agentChainScope", "getUserPlan", "runScheduledAgentTask", "handleAiTaskRequest"], "x: 1").runInContext(c.sandbox);
    const r = await runRoute(app.routes["post /api/assignments/dispatch"], { user: { id: A }, body: body });
    return { r, db, calls, logs: c.logs };
  }
  {
    const f = await assignRun("new", planSeed({ member_links: [OFF(A, "executive", "seo")] }), { executive_task_id: PLAN, assignment_id: 1 });
    check("F1. a plan dispatch along a switched-off link is refused link_disabled_by_member, ok false, and the tool never runs",
      f.r.status === 200 && f.r.body.ok === false && f.r.body.refused_reason === "link_disabled_by_member" && f.calls.length === 0, J(f.r));
    const ed = f.db.tables.executive_dispatches;
    check("F2. its executive_dispatches row says refused, link_disabled_by_member", ed.length === 1 && ed[0].outcome === "refused" && ed[0].refused_reason === "link_disabled_by_member" && f.r.body.recorded === true, J(ed));
    const gd = f.db.tables.gate_decisions;
    check("F3. one gate decision: dispatch, blocked, G26 failed first, G19 and G12 not reached",
      gd.length === 1 && gd[0].action === "dispatch" && gd[0].outcome === "blocked" && gd[0].target === "tool:seo/audit" &&
      J(gd[0].results) === J([{ gate: "G26", result: "fail", code: "link_disabled_by_member" }, { gate: "G19", result: "not_reached" }, { gate: "G12", result: "not_reached" }]) &&
      gd[0].facts && gd[0].facts.agent === "seo", J(gd));
    check("F4. the decision explains itself with G26's registered name and sentence",
      gd.length === 1 && GATES.explain(gd[0]).gates[0].name === "Member links" && GATES.explain(gd[0]).gates[0].reason === GATES.REASONS.link_disabled_by_member);
    const otherOff = await assignRun("new", planSeed({ member_links: [OFF(A, "executive", "content"), OFF(B, "executive", "seo")] }), { executive_task_id: PLAN, assignment_id: 1 });
    check("F5. another link off, or another member's switch, changes nothing: it runs", otherOff.r.body.ok === true && otherOff.calls.length === 1 && otherOff.db.tables.executive_dispatches[0].outcome === "ran", J(otherOff.r.body));
    const realErr = console.error, said = [];
    console.error = function () { said.push(Array.prototype.join.call(arguments, " ")); };
    let unread;
    try { unread = await assignRun("new", planSeed({ member_links: [OFF(A, "executive", "seo")] }), { executive_task_id: PLAN, assignment_id: 1 }, null, { "member_links:select": true }); }
    finally { console.error = realErr; }
    check("F6. a switch that cannot be read leaves the platform's decision standing (it runs) and is logged",
      unread.r.body.ok === true && said.some(l => /\[member-links\] not read/.test(l)), J(said));
  }
  // the handoff
  async function handoffRun(which, links, faults) {
    const db = makeDb({ business_profiles: [{ id: UUID(3), user_id: A }], agent_memory: [], ai_tasks: [], gate_decisions: [], member_links: links || [] }, faults);
    const model = [];
    const c = makeCtx(db, {
      callAnthropicText: async function (p, max, u, x, ledger) { model.push(ledger && ledger.route); return { text: "sales pass" }; },
      getLiveStats: async () => ({}), buildAgentSystemPrompt: () => "prompt", resolvePreferredLanguage: async () => "en",
      buildLanguageInstruction: () => "", SALES_AGENT_BRAIN: "brain"
    });
    script(which, "handoff", DEFS[which].get("orchestrateAgentWorkflow"), ["callAnthropicText", "getLiveStats", "buildAgentSystemPrompt", "resolvePreferredLanguage", "buildLanguageInstruction", "SALES_AGENT_BRAIN"], "orchestrateAgentWorkflow").runInContext(c.sandbox);
    const out = await c.sandbox.__api.orchestrateAgentWorkflow({ userId: A, assignment: { id: UUID(9), agent_type: "executive", mission: "m" }, resultText: "the plan" });
    await settle();
    return { out, db, model, logs: c.logs };
  }
  {
    const h = await handoffRun("new", [OFF(A, "executive", "sales")]);
    check("F7. the Executive-to-Sales handoff along a switched-off link: no Sales pass, no model call, no sales task",
      h.model.length === 0 && h.out.sales_call_result === null && h.db.tables.ai_tasks.length === 0, J(h.out));
    const gd = h.db.tables.gate_decisions;
    check("F8. ... recorded once: dispatch, blocked, G26 link_disabled_by_member, target link:executive/sales",
      gd.length === 1 && gd[0].outcome === "blocked" && gd[0].target === "link:executive/sales" && J(gd[0].results) === J([{ gate: "G26", result: "fail", code: "link_disabled_by_member" }]), J(gd));
    const on = await handoffRun("new", []);
    check("F9. with the link on, the Sales pass runs as before (one model call, one sales task)", on.model.length === 1 && on.db.tables.ai_tasks.length === 1 && on.db.tables.gate_decisions.length === 0);
  }
  // approving an SEO post
  const APPROVE_SIG = 'app.post("/api/proposals/:id/approve", ';
  async function approveRun(which, proposal, links, faults) {
    const db = makeDb({ agent_proposals: [proposal], gate_decisions: [], member_links: links || [], member_gates: [] }, faults);
    const app = appStub();
    const executed = [];
    const c = makeCtx(db, {
      app: app,
      PROPOSAL_EXECUTORS: { publish_blog_post: async p => { executed.push(p.id); return { published: true }; }, update_listing: async p => { executed.push(p.id); return { ok: 1 }; } },
      refuseUnlessSubscribed: async () => false
    });
    script(which, "approve", routeSource(which, APPROVE_SIG), ["PROPOSAL_EXECUTORS", "refuseUnlessSubscribed"], "x: 1").runInContext(c.sandbox);
    const r = await runRoute(app.routes["post /api/proposals/:id/approve"], { user: { id: A }, params: { id: proposal.id }, body: {} });
    return { r, db, executed, logs: c.logs };
  }
  const seoPost = () => ({ id: UUID(500), user_id: A, agent_type: "seo", action_type: "publish_blog_post", status: "pending", payload: {} });
  {
    const a = await approveRun("new", seoPost(), [OFF(A, "seo", "content")]);
    check("F10. approving an SEO post along the switched-off seo>content link: 403 link_disabled_by_member, the executor never runs",
      a.r.status === 403 && a.r.body.code === "link_disabled_by_member" && a.executed.length === 0, J(a.r));
    check("F11. ... the proposal is back to pending, approvable again", a.db.tables.agent_proposals[0].status === "pending" && a.db.tables.agent_proposals[0].decided_at === null, J(a.db.tables.agent_proposals[0]));
    const gd = a.db.tables.gate_decisions;
    check("F12. ... recorded once on the proposal: G3 and G1 passed (a post is subscription-gated), then G26 failed",
      gd.length === 1 && gd[0].action === "proposal_approve" && gd[0].target === "proposal:" + UUID(500) && gd[0].outcome === "blocked" &&
      J(gd[0].results) === J([{ gate: "G3", result: "pass" }, { gate: "G1", result: "pass", code: "approved" }, { gate: "G26", result: "fail", code: "link_disabled_by_member" }]), J(gd));
  }
  // demand signals
  async function signalsRun(which, links) {
    const db = makeDb({ gate_decisions: [], member_links: links || [], bsky_leads: [] });
    const app = appStub();
    const c = makeCtx(db, { app: app, startToolRun: async () => { throw new Error("reached the run"); } });
    script(which, "signals", routeSource(which, 'app.post("/api/agents/rd/demand-signals", '), ["startToolRun"], "x: 1").runInContext(c.sandbox);
    const r = await runRoute(app.routes["post /api/agents/rd/demand-signals"], { user: { id: OWNER, role: "admin" }, body: { theme: "nothing-valid" } });
    return { r, db };
  }
  {
    const s = await signalsRun("new", [OFF(OWNER, "sales", "rd")]);
    check("F13. demand signals along the switched-off sales>rd link: 403 link_disabled_by_member, before anything is read",
      s.r.status === 403 && s.r.body.reason === "link_disabled_by_member" && s.db.log.every(l => l.table !== "bsky_leads"), J(s.r));
    const gd = s.db.tables.gate_decisions;
    check("F14. ... recorded once: route_access, blocked, G26, target link:sales/rd", gd.length === 1 && gd[0].action === "route_access" && gd[0].target === "link:sales/rd" &&
      J(gd[0].results) === J([{ gate: "G26", result: "fail", code: "link_disabled_by_member" }]), J(gd));
    const on = await signalsRun("new", []);
    const old = await signalsRun("old", []);
    check("F15. with the link on, the route answers exactly as before (here: the theme refused)", on.r.status === 400 && J(on.r) === J(old.r), J(on.r) + " | " + J(old.r));
  }

  /* ═══ G. every other path, old against new ═══════════════════════════════ */
  console.log("\n== G. every other dispatch path is unchanged (" + PRE_NETWORK + " against today) ==");
  const strip = log => log.filter(l => l.table !== "member_links");
  async function dispatchRun(which, calls, env, links, faults) {
    const db = makeDb({ gate_decisions: [], member_links: links || [] }, faults);
    const ran = [];
    const c = makeCtx(db, dispatchGlobals(ran), env);
    script(which, "dispatch", DEFS[which].get("dispatchToolCall"), ["agentToolRoutes", "resolveToolRouteHandler", "agentChainScope", "getUserPlan", "runScheduledAgentTask", "handleAiTaskRequest"], "dispatchToolCall").runInContext(c.sandbox);
    const outs = [];
    for (const call of calls) {
      try { outs.push({ returned: await c.sandbox.__api.dispatchToolCall(JSON.parse(J(call))) }); } catch (e) { outs.push({ thrown: e.message }); }
    }
    await settle();
    return { outs, log: strip(db.log), gates: db.tables.gate_decisions, ran, logs: c.logs.filter(l => !/member-links/.test(l)) };
  }
  const call = o => Object.assign({ userId: A, agentType: "seo", tool: "audit", body: { url: "https://example.com" }, chain: { id: "chain-1", depth: 0, callsSoFar: 0 } }, o || {});
  const MATRIX = [
    ["ran", [call()], null],
    ["chaining disabled", [call()], { ENABLE_AGENT_CHAINING: "false" }],
    ["no chain id", [call({ chain: { depth: 0, callsSoFar: 0 } })], null],
    ["the depth limit", [call({ chain: { id: "c", depth: 2, callsSoFar: 0 } })], null],
    ["the total call limit", [call({ chain: { id: "c", depth: 0, callsSoFar: 10 } })], null],
    ["an external-action tool", [call({ tool: "generate-post" })], null],
    ["a tool not in the router", [call({ tool: "nothing" })], null],
    ["a body missing a field", [call({ body: {} })], null],
    ["the fan-out limit", [call(), call()], { CHAIN_MAX_FANOUT: "1" }],
    ["a routine step (sequence)", [call({ chain: { id: "r", depth: 0, callsSoFar: 0, sequence: true } })], null],
    ["no user", [call({ userId: null })], null]
  ];
  for (const [label, calls, env] of MATRIX) {
    const o = await dispatchRun("old", calls, env);
    const nw = await dispatchRun("new", calls, env);
    check("G1. dispatchToolCall, " + label + ", no fromAgent: answer, reads, writes, records and logs identical", J(o) === J(nw), J(o.outs) + " | " + J(nw.outs));
    const from = calls.map(x => Object.assign({}, x, { fromAgent: "executive" }));
    const withOn = await dispatchRun("new", from, env, [{ id: UUID(1), user_id: A, from_agent: "executive", to_agent: "seo", enabled: true }]);
    check("G2. ... with fromAgent and the link on (a row saying enabled): identical", J(o) === J(withOn), J(withOn.outs));
    const withOther = await dispatchRun("new", from, env, [OFF(A, "executive", "content"), OFF(B, "executive", "seo")]);
    check("G3. ... with other links off, or another member's switch: identical", J(o) === J(withOther), J(withOther.outs));
    const unreadable = await dispatchRun("new", from, env, [], { "member_links:select": true });
    check("G4. ... with the switches unreadable: identical (the platform's decision stands)", J(o) === J(unreadable), J(unreadable.outs));
  }
  const ASSIGN_CASES = [
    ["ran", { executive_task_id: PLAN, assignment_id: 1 }, null],
    ["not dispatchable", { executive_task_id: PLAN, assignment_id: 2 }, null],
    ["no such assignment", { executive_task_id: PLAN, assignment_id: 7 }, null],
    ["no such plan", { executive_task_id: UUID(601), assignment_id: 1 }, null],
    ["a malformed id", { executive_task_id: "nope", assignment_id: 1 }, null],
    ["chaining off", { executive_task_id: PLAN, assignment_id: 1 }, { ENABLE_AGENT_CHAINING: "false" }]
  ];
  for (const [label, body, env] of ASSIGN_CASES) {
    const o = await assignRun("old", planSeed(), body, env);
    const nw = await assignRun("new", planSeed(), body, env);
    const shape = x => ({ r: x.r, log: strip(x.db.log), calls: x.calls, tables: { executive_dispatches: x.db.tables.executive_dispatches, gate_decisions: x.db.tables.gate_decisions } });
    check("G5. POST /api/assignments/dispatch, " + label + ", every link on: identical", J(shape(o)) === J(shape(nw)), J(o.r) + " | " + J(nw.r));
  }
  const APPROVE_CASES = [
    ["an SEO post, link on", seoPost(), []],
    ["an SEO post, another link off", seoPost(), [OFF(A, "executive", "seo")]],
    ["a store listing, seo>content off", { id: UUID(501), user_id: A, agent_type: "store", action_type: "update_listing", status: "pending", payload: {} }, [OFF(A, "seo", "content")]],
    ["not pending", Object.assign(seoPost(), { status: "executed" }), []],
    ["no executor", { id: UUID(502), user_id: A, agent_type: "email", action_type: "nothing_known", status: "pending", payload: {} }, []]
  ];
  for (const [label, p, links] of APPROVE_CASES) {
    const o = await approveRun("old", p, links), nw = await approveRun("new", p, links);
    const shape = x => ({ r: x.r, log: strip(x.db.log), executed: x.executed, tables: { agent_proposals: x.db.tables.agent_proposals, gate_decisions: x.db.tables.gate_decisions } });
    check("G6. POST /api/proposals/:id/approve, " + label + ": identical", J(shape(o)) === J(shape(nw)), J(o.r) + " | " + J(nw.r));
  }
  /* G7. Each carrier is its old text plus exactly one inserted block. */
  function lessOnce(text, block) { const i = text.indexOf(block); if (i < 0 || text.indexOf(block, i + 1) !== -1) return null; return text.slice(0, i) + text.slice(i + block.length); }
  const BLOCKS = [
    ["dispatchToolCall", DEFS.new.get("dispatchToolCall"), DEFS.old.get("dispatchToolCall"), [
      "  /* B6/B7: a dispatch that names the agent it comes from (fromAgent) travels a\n     link of the agent network, and a link the member switched off is refused\n     first, before anything is counted or spent, as G26. A dispatch without\n     fromAgent (a routine's steps) is exactly as before. */\n  if (dispatchOpts.fromAgent && await memberLinkOff(dispatchOpts.userId, dispatchOpts.fromAgent, dispatchOpts.agentType)) {\n    var linkTo = String(dispatchOpts.agentType || \"\").toLowerCase().trim();\n    recordGateDecision(dispatchOpts.userId, \"dispatch\", dispatchTarget, { G26: { result: \"fail\", code: \"link_disabled_by_member\" } },\n      { gates: [\"G26\", \"G19\", \"G12\"], facts: { agent: linkTo } });\n    return chainRefusal(\"link_disabled_by_member\", memberLinkSentence(String(dispatchOpts.fromAgent), linkTo));\n  }\n"]],
    ["the assignment route", routeSource("new", ASSIGN_SIG), routeSource("old", ASSIGN_SIG), ["          fromAgent: \"executive\",\n"]],
    ["orchestrateAgentWorkflow", DEFS.new.get("orchestrateAgentWorkflow"), DEFS.old.get("orchestrateAgentWorkflow"), [
      "  } else if (targetAgent === \"sales\" && await memberLinkOff(userId, agentType, \"sales\")) {\n    /* B6/B7: the member switched this link off on the Network map. No Sales\n       pass runs; the refusal is recorded as G26. */\n    recordGateDecision(userId, \"dispatch\", \"link:\" + agentType + \"/sales\", { G26: { result: \"fail\", code: \"link_disabled_by_member\" } },\n      { gates: [\"G26\"], facts: { agent: \"sales\" } });\n    console.log(\"AGENT ORCHESTRATOR HANDOFF REFUSED\", {\n      user_id: userId,\n      assignment_id: assignmentId,\n      source_agent: agentType,\n      reason: \"link_disabled_by_member\"\n    });\n"]],
    ["the demand-signals route", routeSource("new", 'app.post("/api/agents/rd/demand-signals", '), routeSource("old", 'app.post("/api/agents/rd/demand-signals", '), [
      "      /* B6/B7: these runs read the Sales agent's Lead Radar posts, the\n         sales>rd link. Switched off by the member, refused as G26. */\n      if (await memberLinkOff(userId, \"sales\", \"rd\")) {\n        recordGateDecision(userId, \"route_access\", \"link:sales/rd\", { G26: { result: \"fail\", code: \"link_disabled_by_member\" } },\n          { gates: [\"G26\"], facts: { agent: \"rd\" } });\n        return res.status(403).json({ error: memberLinkSentence(\"sales\", \"rd\"), reason: \"link_disabled_by_member\" });\n      }\n"]]
  ];
  for (const [label, now, was, blocks] of BLOCKS) {
    let t = now; blocks.forEach(b => { t = t === null ? null : lessOnce(t, b); });
    check("G7. " + label + " is the " + PRE_NETWORK + " text plus exactly its one inserted block", t !== null && t === was, t === null ? "a block was not found once" : "differs");
  }
  {
    const now = routeSource("new", APPROVE_SIG), was = routeSource("old", APPROVE_SIG);
    const i = now.indexOf("    /* B6/B7: an SEO post goes into the content library along the seo>content\n");
    const j = now.indexOf("    recordGateDecision(req.user.id, \"proposal_approve\", \"proposal:\" + req.params.id, { G3: approveG3, G1: { result: \"pass\", code: \"approved\" } },\n      { facts: approveFacts });");
    check("G7. the approve route is the " + PRE_NETWORK + " text plus exactly its one inserted block", i > 0 && j > i && now.slice(0, i) + now.slice(j) === was);
  }
  check("G8. every gate in ACTION_GATES and every other reason is as it was, and G26 is registered once",
    J(GATES.ACTION_GATES) === J(realRequire("./lib/gates").ACTION_GATES) && GATES.GATES.filter(g => g.id === "G26").length === 1 &&
    GATES.GATES.filter(g => g.id === "G26")[0].kind === "member" && GATES.REASONS.link_disabled_by_member === "You switched off this link between two agents, so nothing passed along it." &&
    J(GATES.ACTION_GATES.dispatch) === J(["G19", "G12"]));
  {
    const oldGates = execFileSync("git", ["show", PRE_NETWORK + ":lib/gates.js"], { cwd: REPO }).toString("utf8").replace(/\r\n/g, "\n");
    const m = { exports: {} }; vm.runInNewContext("(function (module, exports) {\n" + oldGates + "\n})")(m, m.exports);
    const O = m.exports;
    check("G9. lib/gates.js: G1 to G25, ACTIONS, ACTION_GATES and every old reason are exactly as at " + PRE_NETWORK,
      J(O.GATES) === J(GATES.GATES.filter(g => g.id !== "G26")) && J(O.ACTIONS) === J(GATES.ACTIONS) && J(O.ACTION_GATES) === J(GATES.ACTION_GATES) &&
      Object.keys(O.REASONS).every(k => O.REASONS[k] === GATES.REASONS[k]) && Object.keys(GATES.REASONS).length === Object.keys(O.REASONS).length + 1);
  }

  /* ═══ H. export, deletion, backup, migration ═════════════════════════════ */
  console.log("\n== H. export, deletion, backup and migration 161 ==");
  const YD = realRequire("./lib/yourData");
  const entry = YD.DATA.filter(e => e.table === "member_links");
  check("H1. member_links is in DATA once: group agents, owner user_id, onDelete delete, paged by id", entry.length === 1 && entry[0].group === "agents" &&
    J(entry[0].owner) === J(["user_id"]) && entry[0].onDelete === "delete" && !entry[0].key);
  check("H2. it is in DELETE_ORDER once", YD.DELETE_ORDER.filter(t => t === "member_links").length === 1);
  check("H3. lib/backup.js backs it up", /\n  "member_links",/.test(FILES.backup));
  {
    const rows = [{ id: UUID(11), user_id: A, from_agent: "executive", to_agent: "seo", enabled: false, updated_at: ago(H) },
      { id: UUID(12), user_id: A, from_agent: "seo", to_agent: "content", enabled: true, updated_at: ago(H) },
      { id: UUID(13), user_id: B, from_agent: "executive", to_agent: "seo", enabled: false, updated_at: ago(H) }];
    const db = makeDb({ member_links: rows });
    let out = "";
    await YD.exportAccountData({ supabase: db.client, userId: A, write: s => { out += s; }, now: new Date(FIXED) });
    let parsed = null; try { parsed = JSON.parse(out); } catch (e) { parsed = null; }
    const mine = parsed && parsed.tables && parsed.tables.member_links;
    check("H4. the export holds both of A's switch rows and none of B's", Array.isArray(mine) && mine.length === 2 && mine.every(r => r.user_id === A || r.user_id === "you"), J(mine));
    const del = db.log.filter(l => l.op === "delete");
    let deleted = [];
    try {
      const ddb = makeDb({ member_links: rows });
      for (const t of YD.DELETE_ORDER.filter(x => x === "member_links")) {
        const r = await ddb.client.from(t).delete().eq("user_id", A);
        if (r.error) throw r.error;
      }
      deleted = ddb.tables.member_links;
    } catch (e) { deleted = null; }
    check("H5. deleting the account removes A's rows and keeps B's (the delete the order runs)", Array.isArray(deleted) && deleted.length === 1 && deleted[0].user_id === B && del.length === 0);
  }
  const mig = FILES.migration;
  /* NAMED (B8/B9, Nov 1 2026): BEFORE "the only migration numbered 161, and the highest" (every number <= 161). AFTER
     162_plan_cycles.sql follows it, so the pin is "the only one numbered 161, and every one before it is lower"; the
     ordering it guarded (no migration numbered above 161 when 161 was written) is now checkPlanCycles A1's, for 162.
     NAMED (store connections, Nov 3 2026): BEFORE only 162_plan_cycles.sql was allowed above 161. AFTER the migrations
     allowed above 161 are 162_plan_cycles.sql and 163_store_connections.sql; "the highest" is checkStoreConnections L9's.
     NAMED (the Bluesky Mentions inbox, Nov 3 2026): BEFORE 162 and 163 were allowed above 161. AFTER 162_plan_cycles.sql,
     163_store_connections.sql and 164_bluesky_reply_refs.sql; "the highest" is checkBlueskyMentions M3's.
     NAMED (Connect Mastodon, Nov 3 2026): BEFORE 162, 163 and 164 were allowed above 161. AFTER 162_plan_cycles.sql,
     163_store_connections.sql, 164_bluesky_reply_refs.sql and 165_member_mastodon_connections.sql; "the highest" is
     checkMastodonConnect M3's.
     NAMED (campaign sharing, Nov 4 2026): BEFORE 162 to 165 were allowed above 161. AFTER 162 to 165 and
     166_campaign_sharing.sql; "the highest" is checkCampaignSharing M2's. */
  check("H6. 161_member_links.sql is the only migration numbered 161, and every earlier one is lower", fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^161_/.test(f)).length === 1 &&
    // NAMED (Nov 4 2026, the Media Library, migration 167): the allowlist adds 167_member_media.sql; "the highest" is checkMediaLibrary M2's.
    // NAMED (Nov 5 2026, images in social posts, migration 168): the allowlist adds 168_social_post_images.sql; "the highest" is checkSocialImages M2's.
    // NAMED (Nov 5 2026, mailbox connection, migration 169): the allowlist adds 169_member_email_connections.sql; "the highest" is checkMailboxConnect M2's.
    fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f)).filter(f => !/^(162_plan_cycles|163_store_connections|164_bluesky_reply_refs|165_member_mastodon_connections|166_campaign_sharing|167_member_media|168_social_post_images|169_member_email_connections)\.sql$/.test(f)).every(f => Number(f.split("_")[0]) <= 161));
  check("H7. the table: user_id cascading, from_agent, to_agent, enabled, updated_at, one row per link, no self link",
    /user_id     uuid NOT NULL REFERENCES public\.users\(id\) ON DELETE CASCADE,/.test(mig) && /from_agent  text NOT NULL/.test(mig) && /to_agent    text NOT NULL/.test(mig) &&
    /enabled     boolean NOT NULL DEFAULT true,/.test(mig) && /updated_at  timestamptz NOT NULL DEFAULT now\(\),/.test(mig) &&
    /UNIQUE \(user_id, from_agent, to_agent\),/.test(mig) && /CHECK \(from_agent <> to_agent\)/.test(mig));
  check("H8. row level security on, no policy, no grant", /ALTER TABLE public\.member_links ENABLE ROW LEVEL SECURITY;/.test(mig) && !/CREATE POLICY|GRANT /i.test(mig));
  check("H9. the upsert's conflict key is the table's unique key", /onConflict: "user_id,from_agent,to_agent"/.test(FILES.lib));

  /* ═══ U. the map in jsdom ════════════════════════════════════════════════ */
  console.log("\n== U. the map ==");
  const { JSDOM } = realRequire("jsdom");
  function netBody(win, overrides) {
    const g = NET.buildGraph(SPEC_KEYS, ACTS);
    const counts = Object.assign({ "executive>seo": 5, "executive>content": 1, "seo>content": 0, "sales>rd": null }, overrides || {});
    return {
      window: win, since: ago(D), centre: "executive",
      nodes: g.nodes.map(k => ({ key: k, name: NET.name(k) })),
      edges: g.edges.map(e => ({ id: e.id, from: e.from, to: e.to, kinds: e.sources.map(s => s.kind), labels: e.sources.map(s => s.label), tools: [],
        enabled: e.id !== "executive>email", count: Object.prototype.hasOwnProperty.call(counts, e.id) ? counts[e.id] : 0, unavailable: counts[e.id] === null ? "x" : null })),
      not_drawn: [], problems: [], chain_limits: { depth: 2, fanout: 3, calls: 10 }
    };
  }
  function mountMap(opts) {
    const o = opts || {};
    const html = '<!doctype html><html><head></head><body><div id="panel"' + (o.panelHidden ? " hidden" : "") + '><div id="deckNetwork" role="region" aria-label="Agent network"></div></div></body></html>';
    const dom = new JSDOM(html, { runScripts: "outside-only", url: "https://bizforce.example/executive-agent.html", pretendToBeVisual: true });
    const w = dom.window;
    const calls = [];
    let hidden = !!o.docHidden;
    Object.defineProperty(w.document, "hidden", { configurable: true, get: () => hidden });
    w.matchMedia = q => ({ matches: !!o.still && /reduce/.test(q), addEventListener() {}, removeEventListener() {} });
    w.localStorage.setItem("bf_token", "t");
    w.fetch = function (url, init) {
      calls.push({ url: String(url), method: (init && init.method) || "GET", body: init && init.body });
      let body = {};
      if (/\/api\/agents\/network\/edge/.test(url)) body = { edge: {}, runs: [{ at: ago(H), kind: "dispatch", tool: "seo/audit", task_id: UUID(5), href: "/run.html?id=" + UUID(5), why: "ai_task:" + UUID(5) }, { at: ago(2 * H), kind: "proposal", tool: "seo/generate-post", task_id: null, href: null, why: "proposal:" + UUID(6) }], page: 1, pages: 1, total: 2 };
      else if (/\/api\/agents\/network\/links/.test(url)) { const b = JSON.parse(init.body); body = { link: { from: b.from, to: b.to, enabled: b.enabled } }; }
      else if (/\/api\/agents\/network/.test(url)) body = netBody(/window=([^&]+)/.exec(url)[1], o.counts);
      const p = Promise.resolve({ status: 200, ok: true, json: () => Promise.resolve(body) });
      p.catch(() => {});
      return p;
    };
    w.eval(FILES.ui);
    return { dom, w, calls, setHidden: v => { hidden = v; w.document.dispatchEvent(new w.Event("visibilitychange")); } };
  }
  const wait = async () => { for (let i = 0; i < 8; i++) await tick(); };
  {
    const m = mountMap();
    await wait();
    const doc = m.w.document;
    const edges = Array.from(doc.querySelectorAll("[data-bfn-edge].bfn-edge"));
    const nodes = Array.from(doc.querySelectorAll("[data-bfn-node]"));
    check("U1. an SVG map of the 18 agents and the 18 declared links", doc.querySelector("svg.bfn-svg") && nodes.length === 18 && edges.length === 18, nodes.length + " " + edges.length);
    const pos = m.w.BFNetwork.positions(netBody("24h").nodes, "executive");
    const ex = doc.querySelector('[data-bfn-node="executive"] circle');
    check("U2. the Executive is in the middle, the rest on one ring", ex.getAttribute("cx") === "320" && ex.getAttribute("cy") === "320" &&
      Object.keys(pos).filter(k => k !== "executive").every(k => Math.abs(Math.hypot(pos[k].x - 320, pos[k].y - 320) - 250) < 1));
    check("U3. each node in its own accent", doc.querySelector('[data-bfn-node="content"] circle').getAttribute("fill") === "#34d399" && doc.querySelector('[data-bfn-node="ads"] circle').getAttribute("fill") === "#818cf8");
    const edge = id => doc.querySelector('.bfn-edge[data-bfn-edge="' + id + '"]');
    check("U4. a link with runs lights: a flowing pulse, thicker by count", edge("executive>seo").querySelector(".bfn-pulse") && edge("executive>content").querySelector(".bfn-pulse") &&
      Number(edge("executive>seo").querySelector(".bfn-line").getAttribute("stroke-width")) > Number(edge("executive>content").querySelector(".bfn-line").getAttribute("stroke-width")));
    const unlit = edges.filter(e => !/executive>(seo|content)$/.test(e.getAttribute("data-bfn-edge")));
    check("U5. every link with 0 runs, or an unreadable count, is dim and never animated (no pulse element at all)",
      unlit.length === 16 && unlit.every(e => e.classList.contains("bfn-dim") && !e.querySelector(".bfn-pulse")) && doc.querySelectorAll(".bfn-pulse").length === 2, unlit.filter(e => e.querySelector(".bfn-pulse")).map(e => e.getAttribute("data-bfn-edge")).join(","));
    check("U6. a link the member switched off is dashed", edge("executive>email").classList.contains("bfn-off") && doc.querySelectorAll(".bfn-off").length === 1);
    check("U7. nodes and links take keyboard focus", nodes.every(n => n.getAttribute("tabindex") === "0") && edges.every(e => e.getAttribute("tabindex") === "0" && e.getAttribute("role") === "button"));
    const items = Array.from(doc.querySelectorAll(".bfn-list [data-bfn-item]"));
    const fromMap = edges.map(e => [e.getAttribute("data-bfn-edge"), e.getAttribute("aria-label").replace(/\. Press to see its runs\.$/, "")]);
    const fromList = items.map(li => [li.getAttribute("data-bfn-item"), li.querySelector("span").textContent]);
    check("U8. the text list matches the map, link by link (the same links, order, counts and switch state)", J(fromMap) === J(fromList) && items.length === 18, J(fromList.slice(0, 3)));
    check("U9. ... and says the counts in words", /Executive Agent to SEO Agent: 5 runs in the last 24 hours$/.test(fromList.filter(x => x[0] === "executive>seo")[0][1]) &&
      /runs could not be read/.test(fromList.filter(x => x[0] === "sales>rd")[0][1]) && /switched off by you/.test(fromList.filter(x => x[0] === "executive>email")[0][1]));
    const before = m.calls.length;
    edge("executive>seo").dispatchEvent(new m.w.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await wait();
    const edgeCall = m.calls.slice(before).filter(c => /network\/edge/.test(c.url));
    check("U10. Enter on a link opens its runs (one read of the edge route)", edgeCall.length === 1 && /from=executive&to=seo&window=24h&page=1/.test(edgeCall[0].url), J(m.calls.slice(before)));
    const det = doc.querySelector(".bfn-detail");
    check("U11. each run has Open run (run.html) and Why?", det && det.querySelector('a[href="/run.html?id=' + UUID(5) + '"]') && det.querySelectorAll("[data-bf-why]").length === 2 &&
      det.querySelector('[data-bf-why="proposal:' + UUID(6) + '"]'));
    const nPut = () => m.calls.filter(c => c.method === "PUT").length;
    doc.querySelector('.bfn-list [data-bfn-toggle="executive>seo"]').click();
    await wait();
    check("U12. Switch off asks first, and writes nothing yet", nPut() === 0 && doc.querySelector('[data-bfn-confirm="executive>seo"]') && /Switch off this link\?/.test(doc.querySelector(".bfn-confirm").textContent));
    doc.querySelector('[data-bfn-cancel="executive>seo"]').click();
    await wait();
    check("U13. Cancel writes nothing", nPut() === 0 && !doc.querySelector("[data-bfn-confirm]"));
    doc.querySelector('.bfn-list [data-bfn-toggle="executive>seo"]').click();
    await wait();
    doc.querySelector('[data-bfn-confirm="executive>seo"]').click();
    await wait();
    const put = m.calls.filter(c => c.method === "PUT");
    check("U14. Yes writes once: PUT /api/agents/network/links { from, to, enabled: false }", put.length === 1 && /\/api\/agents\/network\/links$/.test(put[0].url) &&
      J(JSON.parse(put[0].body)) === J({ from: "executive", to: "seo", enabled: false }));
    const off = doc.querySelector('.bfn-list [data-bfn-toggle="executive>email"]');
    check("U15. a link already off offers Switch on", off && off.textContent === "Switch on");
    const went = [];
    m.w.BFNetwork.go = u => { went.push(u); };
    doc.querySelector('[data-bfn-node="content"]').dispatchEvent(new m.w.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    doc.querySelector('[data-bfn-node="executive"]').dispatchEvent(new m.w.MouseEvent("click", { bubbles: true }));
    check("U16. Enter or a click on an agent opens that agent's page", J(went) === J(["/agents/content.html", "/executive-agent.html"]), J(went));
    // the window buttons
    const b7 = doc.querySelector('[data-bfn-window="7d"]');
    b7.click(); await wait();
    check("U17. 7d asks the server for the 7-day window, and the button says it is pressed", m.calls.some(c => /network\?window=7d$/.test(c.url)) && doc.querySelector('[data-bfn-window="7d"]').getAttribute("aria-pressed") === "true");
    // refresh only while visible
    m.w.BFNetwork.stop();
    const c0 = m.calls.length;
    m.setHidden(true);
    m.w.BFNetwork.tick();
    await wait();
    check("U18. hidden: refresh stops (no timer, no read)", !m.w.BFNetwork.timerActive() && m.calls.length === c0);
    m.setHidden(false);
    await wait();
    check("U19. visible again: it reads at once and keeps a timer", m.calls.length === c0 + 1 && m.w.BFNetwork.timerActive());
    m.w.BFNetwork.stop();
    m.dom.window.close();
  }
  {
    const m = mountMap({ panelHidden: true });
    await wait();
    const reads = m.calls.filter(c => /\/api\/agents\/network/.test(c.url)).length;
    check("U20. on another tab (the panel hidden) nothing is read, though the timer waits for the tab", reads === 0 && m.w.BFNetwork.timerActive(), reads);
    m.w.document.getElementById("panel").hidden = false;
    m.w.BFNetwork.tick(); await wait();
    check("U21. ... and it reads once the Agents tab is open", m.calls.filter(c => /\/api\/agents\/network/.test(c.url)).length === 1);
    m.w.BFNetwork.stop(); m.dom.window.close();
  }
  {
    const m = mountMap({ docHidden: true });
    await wait();
    check("U22. a page loaded hidden reads nothing and keeps no timer", m.calls.length === 0 && !m.w.BFNetwork.timerActive());
    m.dom.window.close();
  }
  {
    const m = mountMap({ still: true });
    await wait();
    const doc = m.w.document;
    check("U23. under reduced motion nothing pulses, and every link shows its count instead",
      doc.querySelectorAll(".bfn-pulse").length === 0 && doc.querySelectorAll(".bfn-count").length === 18 &&
      doc.querySelector('.bfn-edge[data-bfn-edge="executive>seo"] .bfn-count').textContent === "5" &&
      doc.querySelector('.bfn-edge[data-bfn-edge="sales>rd"] .bfn-count').textContent === "?");
    check("U24. the CSS also stops the pulse under prefers-reduced-motion", /@media \(prefers-reduced-motion: reduce\)\{\.bfn-pulse\{animation:none\}\}/.test(FILES.ui));
    m.w.BFNetwork.stop(); m.dom.window.close();
  }
  {
    const m = mountMap({ counts: { "executive>seo": 0, "executive>content": 0 } });
    await wait();
    check("U25. a window with no runs at all: nothing is animated", m.w.document.querySelectorAll(".bfn-pulse").length === 0 && m.w.document.querySelectorAll(".bfn-lit").length === 0);
    m.w.BFNetwork.stop(); m.dom.window.close();
  }
  check("U26. HQ mounts it on the Agents tab and loads the script; HQ names the refusal; offline never keeps the network",
    FILES.execHtml.indexOf('<p class="hq-empty" id="hqGridEmpty" hidden></p>\n          <div id="deckNetwork" role="region" aria-label="Agent network"></div>') !== -1 &&
    FILES.execHtml.indexOf('<script src="/scripts/bf-triggers.js"></script>\n<script src="/scripts/bf-network.js"></script>') !== -1 &&
    FILES.hq.indexOf('link_disabled_by_member: "you switched off this link on the Network map (Agents tab)",') !== -1 &&
    /\(\?!live\$\|network\$\)/.test(FILES.offline));
  {
    const re = /\{ path: (\/\^.*\$\/), what: "your agents and their last runs" \}/g; let mm; const pats = [];
    while ((mm = re.exec(FILES.offline))) pats.push(vm.runInNewContext(mm[1]));
    check("U27. the offline copy matches /api/agents/seo but neither /api/agents/live nor /api/agents/network", pats.some(p => p.test("/api/agents/seo")) &&
      !pats.some(p => p.test("/api/agents/network")) && !pats.some(p => p.test("/api/agents/live")));
  }
  check("U28. the guide's executive entry names the Network map", /"Network\\" lights only real flow\./.test(FILES.guide) || /\\"Network\\" lights only real flow/.test(FILES.guide));

  /* ═══ S. no emoji ════════════════════════════════════════════════════════ */
  console.log("\n== S. no emoji ==");
  // By code point, and the escaped forms built from parts, so this check holds none itself (checkNoEmoji scans it too).
  const BS = String.fromCharCode(92);
  const ESCAPED = ["&#" + "x1F", BS + "u{1F", BS + "uD83", BS + "uFE0F"];
  function hasEmoji(text) {
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if ((cp >= 0x1F000 && cp <= 0x1FAFF) || (cp >= 0x2600 && cp <= 0x27BF) || cp === 0xFE0F || cp === 0x200D) return true;
    }
    return ESCAPED.some(e => text.indexOf(e) !== -1);
  }
  const scanned = [["lib/agentNetwork.js", FILES.lib], ["migration 161", FILES.migration], ["bf-network.js", FILES.ui], ["executive-agent.html", FILES.execHtml],
    ["lib/gates.js", FILES.gates], ["this check", fs.readFileSync(__filename, "utf8")]];
  check("S1. no emoji in lib/agentNetwork.js, migration 161, bf-network.js, executive-agent.html, lib/gates.js or this check",
    scanned.every(([, t]) => !hasEmoji(t)), scanned.filter(([, t]) => hasEmoji(t)).map(x => x[0]).join(","));
  check("S2. the scan itself finds one (a vector built from a code point)", hasEmoji("a" + String.fromCodePoint(0x1F600)) && hasEmoji("&#" + "x1F600;"));

  if (UNHANDLED.length) check("Z. no unhandled rejection", false, UNHANDLED.map(e => (e && e.stack) || String(e)).join(" | ").slice(0, 600));
  } catch (crash) {
    check("the harness ran to the end", false, (crash && crash.stack) || String(crash));
  }
  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED (" + passes + ")" : failures + " FAILED, " + passes + " passed"));
  process.exit(failures === 0 ? 0 : 1);
})();
