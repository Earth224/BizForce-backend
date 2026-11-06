/* ═══════════════════════════════════════════════════════════════════════════
   checkPlanCycles.js — learning cycles (intelligence layer B8 and B9)

   WHAT THIS PROVES (the model is stubbed: no external call is made)

     A. MIGRATION 162: plan_cycles (its columns, its four statuses, one cycle
        per member and plan, RLS on with no policy), agent_preferences.source
        widened to 'lesson', self_reviews.by_agent and .lessons; the next free
        number.
     B. MEASURED, against hand counts: dispatches ran/refused/failed by agent,
        the tool runs completed/failed, proposals approved/rejected/published
        (outcomesFrom), arrivals since the plan, the Helpful share only where 5
        or more ratings exist; every failed read is null and named, never 0,
        and what depends on it is null too; every read is the member's own.
     C. THE VERIFIER drops every sentence holding a number (digits or words)
        that is not in measured, and keeps every other sentence; 300
        generated sentences agree with an independent oracle.
     D. THE REVIEW ROUTE, with the real callAnthropicText: one model call per
        review (Haiku, ledgered in model_calls, recorded as a model_call
        decision), refused by G9, G11 and G10 when capped (no call, the day
        given back), at most one review per cycle per day (also when two
        arrive at once), stored as review_drafted with only verified text.
     E. APPROVAL AND THE PLAN ROUTE: approve only a drafted review; the next
        plan starts ONLY from an approved cycle and only through POST
        /api/agents/executive/plan, which takes the approved draft as its goal,
        links the run and opens the next cycle; old (PRE_CYCLES) against new
        with no cycle_id: the same answer, reads, writes and calls; byte proof
        that the route is its old text plus exactly two blocks; no timer.
     F. LESSONS BY RULE: the per-agent breakdown against hand counts; each
        rule and its boundaries; the weekly review makes exactly its one
        narrative model call and saves no preference; the panel offers the
        lessons; one is saved, with source 'lesson', only when accepted, only
        while offered, within PREF_CAP; it then reaches the guidance block word
        for word; a failed read is null (GET) or 503 (POST), nothing written.
     G. THE HISTORY: arrows up, down, level and none, each cycle against the
        one before.
     H. THE HONEST COPY, word for word, in the lib, every route answer and
        every cycle view.
     I. OWNERSHIP: another member's cycle is 404 on every route, and its rows
        are never read into an answer.
     K. EXPORT AND DELETION of plan_cycles; backup.
     L. lib/selfReview.js's header no longer says it is unwired.
     U. THE PLANS TAB (bf-cycles.js) and the lessons on the agent page, in
        jsdom.
     S. No emoji in any new or edited file.

   MUTATIONS — MUTATE=<name> applies one in memory; MUTATE=all runs each:
     verifier-keeps-invented          every number is allowed               -> C, D
     next-plan-without-approval       a cycle not approved still starts     -> E
     second-review-same-day           the once-a-day rule is skipped        -> D
     lesson-saved-without-acceptance  the weekly review saves its lessons   -> F
     model-call-for-lessons           lessons ask the model                 -> F
     honest-copy-removed              the cycle view's fixed line is gone   -> H, U
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
const PRE_CYCLES = "8326a8f";
const PRE_FRONTEND = "014c390";

const LESSON_ANCHOR = "      var lessonRows = LESSONS.lessonsFrom(breakdown.by_agent);\n";
const MUTATIONS = {
  "verifier-keeps-invented": ["lib",
    "    return isFinite(v) && allowed[String(v)] === true;", "    return true;"],
  "next-plan-without-approval": ["server",
    "  if (row.status !== \"approved\") return refuse(409, \"cycle_not_approved\",", "  if (false) return refuse(409, \"cycle_not_approved\","],
  "second-review-same-day": ["lib",
    "  if (isFinite(last) && nowMs - last < REVIEW_GAP_MS && last <= nowMs) {", "  if (false) {"],
  "lesson-saved-without-acceptance": ["selfReview", LESSON_ANCHOR, LESSON_ANCHOR +
    "      for (var la in (lessonRows || {})) { for (var li = 0; li < lessonRows[la].length; li++) { await supabase.from(\"agent_preferences\").insert({ user_id: userId, agent_type: la, text: lessonRows[la][li].text, source: \"lesson\" }); } }\n"],
  "model-call-for-lessons": ["selfReview", LESSON_ANCHOR,
    "      await callAnthropicText(\"Derive lessons from this breakdown\", 300);\n" + LESSON_ANCHOR],
  "honest-copy-removed": ["ui",
    "  var CYCLE_COPY = \"Each cycle builds on recorded results. The AI model itself does not change.\";", "  var CYCLE_COPY = \"\";"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 600) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = {
  lib: read("lib/planCycle.js"),
  lessons: read("lib/lessons.js"),
  selfReview: read("lib/selfReview.js"),
  server: read("server.js"),
  migration: read("supabase/migrations/162_plan_cycles.sql"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  ui: readFe("scripts/bf-cycles.js"),
  profile: readFe("scripts/agent-profile.js"),
  execHtml: readFe("executive-agent.html"),
  guide: readFe("scripts/termaximus-guide.js")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}
const OLD = execFileSync("git", ["show", PRE_CYCLES + ":server.js"], { cwd: REPO, maxBuffer: 64 << 20 }).toString("utf8").replace(/\r\n/g, "\n");
const OLD_SELF_REVIEW = execFileSync("git", ["show", PRE_CYCLES + ":lib/selfReview.js"], { cwd: REPO, maxBuffer: 16 << 20 }).toString("utf8").replace(/\r\n/g, "\n");
const NEW = FILES.server;

const J = JSON.stringify;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const LEARNING = realRequire("./lib/learningLoop");
function compile(src, filename, req) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require"], { filename: filename });
  fn(m, m.exports, req);
  return m.exports;
}
const libReq = r => {
  if (r === "./learningLoop") return LEARNING;
  if (r === "./lessons") return LESSONS;
  return realRequire(r.replace(/^\.\//, "./lib/"));
};
let LESSONS = null;
LESSONS = compile(FILES.lessons, "lib/lessons.js", libReq);
const PC = compile(FILES.lib, "lib/planCycle.js", libReq);
const SR = compile(FILES.selfReview, "lib/selfReview.js", libReq);

/* ── lifting, as checkAgentNetwork lifts: an index of top-level definitions, a closure ── */
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
  "requireActiveSubscription", "aiLimiter", "rateLimit", "express", "crypto", "PLAN_CYCLE", "LESSONS", "LEARNING", "Anthropic", "resolveAnthropicKey",
  "recordGateDecision", "loadArrivals", "cycleLimiter", "fetch"];
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

/* ── an in-memory database: filters (with payload->>key paths), pages, upserts, a log, faults ── */
function UUID(n) { return "00000000-0000-4000-8000-" + String(n).padStart(12, "0"); }
function makeDb(seed, faults) {
  const tables = JSON.parse(J(seed || {}));
  const log = [];
  const fail = faults || {};
  let auto = 9000;
  function cmp(a, b) { const x = String(a), y = String(b); return x < y ? -1 : x > y ? 1 : 0; }
  function valueOf(r, c) {
    if (c.indexOf("->>") !== -1) { const [a, b] = c.split("->>"); return r[a] && typeof r[a] === "object" && r[a][b] != null ? String(r[a][b]) : undefined; }
    return r[c];
  }
  function matches(r, f) {
    const [k, c, v] = f; const val = valueOf(r, c);
    if (k === "eq") return val === v || (val != null && v != null && String(val) === String(v));
    if (k === "neq") return !(val === v || String(val) === String(v));
    if (k === "gt") return val != null && cmp(val, v) > 0;
    if (k === "gte") return val != null && cmp(val, v) >= 0;
    if (k === "lt") return val != null && cmp(val, v) < 0;
    if (k === "lte") return val != null && cmp(val, v) <= 0;
    if (k === "in") return v.some(x => String(x) === String(val));
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
    is(c, v) { this.f.push(["is", c, v]); return this; }
    not() { return this; }
    or() { return this; }
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
      if (fail[fk]) return { data: null, error: { message: this.t + " down", code: "XX000" }, count: null };
      const rows = tables[this.t] || (tables[this.t] = []);
      const match = r => this.f.every(x => matches(r, x));
      if (this.op === "select") {
        let hit = rows.filter(match);
        const count = hit.length;
        if (this.ord) { const [c, asc] = this.ord; hit = hit.slice().sort((x, y) => (asc ? 1 : -1) * cmp(x[c], y[c])); }
        if (this.rng) hit = hit.slice(this.rng[0], this.rng[1] + 1);
        if (this.lim != null) hit = hit.slice(0, this.lim);
        const data = this.opts.head ? null : hit.map(r => JSON.parse(J(r)));
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
            if (row) Object.assign(row, JSON.parse(J(p)));
          }
          if (!row) { row = JSON.parse(J(p)); if (!row.id) row.id = UUID(++auto); if (!row.created_at) row.created_at = new Date(FIXED).toISOString(); rows.push(row); }
          made.push(JSON.parse(J(row)));
        }
        if (this.mode === "single") return { data: made[0], error: null };
        return { data: this.sel ? made : null, error: null };
      }
      if (this.op === "update") {
        const hit = rows.filter(match);
        hit.forEach(r => Object.assign(r, JSON.parse(J(this.payload))));
        const data = hit.map(r => JSON.parse(J(r)));
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
  return { client: { from: t => new Q(t), rpc: async () => ({ data: null, error: { message: "no rpc here" } }) }, tables, log, fail };
}

/* ── contexts, a request and a response ──────────────────────────────────── */
const FIXED = Date.parse("2026-11-01T12:00:00.000Z");
class FixedDate extends Date {
  constructor(...a) { if (a.length === 0) super(FIXED); else super(...a); }
  static now() { return FIXED; }
}
const A = UUID(1), B = UUID(2), OWNER = realRequire("./lib/ownerAccount").OWNER_ACCOUNT_ID;
const H = 3600000, D = 24 * H;
const ago = ms => new Date(FIXED - ms).toISOString();
function makeCtx(db, globals, env) {
  const logs = [], models = [], gates = [];
  const line = k => function () { logs.push(k + " " + Array.prototype.map.call(arguments, a => (a && a.message) ? a.message : (typeof a === "object" ? J(a) : String(a))).join(" ")); };
  function Anthropic() { this.messages = { create: async req => { models.push(JSON.parse(J(req))); return sandbox.__reply(req); } }; }
  const sandbox = Object.assign({
    supabase: db.client,
    console: { log: line("log"), warn: line("warn"), error: line("error"), info: line("info") },
    process: { env: Object.assign({}, env || {}) },
    require: realRequire,
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
    aiLimiter: function aiLimiter(req, res, next) { next(); },
    cycleLimiter: function cycleLimiter(req, res, next) { next(); },
    PLAN_CYCLE: PC, LESSONS: LESSONS, LEARNING: LEARNING,
    Anthropic: Anthropic,
    resolveAnthropicKey: { withSource: async () => ({ key: "stub-key", source: "platform", reason: "no_stored_key" }) },
    recordGateDecision: function (userId, action, target, observed, extra) { gates.push({ userId, action, target, observed: JSON.parse(J(observed || {})), extra: extra || null }); return Promise.resolve(true); },
    loadArrivals: async function (userId, isOwner) { sandbox.__arrivalCalls.push([userId, isOwner]); return sandbox.__arrivals(userId); },
    __arrivalCalls: [],
    __arrivals: () => ({ posts: { rows: [] }, sends: { rows: [] }, visits: { rows: [] } }),
    __reply: () => ({ model: "claude-haiku-4-5-20251001", content: [{ type: "text", text: "REVIEW:\nNothing to say.\nNEXT PLAN:\nKeep going." }],
      usage: { input_tokens: 100, output_tokens: 50, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 } })
  }, globals || {});
  vm.createContext(sandbox);
  return { sandbox, logs, db, models, gates };
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
const tick = () => new Promise(r => setImmediate(r));
async function settle() { for (let i = 0; i < 6; i++) await tick(); }
async function runRoute(handlers, req) {
  const res = makeRes();
  let err = null;
  await new Promise(resolve => {
    const fin = handlers[handlers.length - 1];
    Promise.resolve(fin(req, res, e => { err = e; resolve(); })).then(resolve, e => { err = e; resolve(); });
  });
  await settle();
  if (err && res.sent === 0) { res.statusCode = err.status || err.statusCode || 500; res.body = { error: err.message, code: err.code || null, thrown: true }; }
  return { status: res.statusCode, body: res.body, err: err ? (err.message || String(err)) : null };
}

/* ── the cycle routes, lifted into one context per database ──────────────── */
const CYCLE_SIGS = ['app.get("/api/executive/cycles", ', 'app.post("/api/executive/cycles", ', 'app.post("/api/executive/cycles/:id/review", ',
  'app.put("/api/executive/cycles/:id", ', 'app.post("/api/executive/cycles/:id/approve", ', 'app.post("/api/executive/cycles/:id/discard", ',
  'app.post("/api/executive/cycles/:id/supersede", '];
function cyclesApp(db, env, reply) {
  const app = appStub();
  const c = makeCtx(db, { app: app }, env);
  if (reply) c.sandbox.__reply = reply;
  const root = CYCLE_SIGS.map(s => routeSource("new", s)).join("\n");
  script("new", "cycles", root, [], "PLATFORM_SPEND_STATE: typeof PLATFORM_SPEND_STATE !== 'undefined' ? PLATFORM_SPEND_STATE : null, planCycleMeasure: planCycleMeasure").runInContext(c.sandbox);
  if (c.sandbox.__api.PLATFORM_SPEND_STATE) c.sandbox.__api.PLATFORM_SPEND_STATE.raise = function () { return Promise.resolve(); };
  const call = (m, p, user, body, params) => runRoute(app.routes[m + " " + p], { user: { id: user }, body: body === undefined ? {} : body, params: params || {}, query: {} });
  return { app, c, call };
}
const replyText = text => () => ({ model: "claude-haiku-4-5-20251001", content: [{ type: "text", text: text }],
  usage: { input_tokens: 400, output_tokens: 120, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 } });

/* ── the plan route, lifted with its heavy parts stubbed (the same stubs, old and new) ── */
const PLAN_SIG = 'app.post("/api/agents/executive/plan", requireAuth, requireActiveSubscription, aiLimiter,';
const PLAN_STUBS = ["startToolRun", "agentToolCatalogue", "agentToolRoutes", "loadProfileForTool", "AGENT_SYSTEM_PROMPTS", "CHAIN_NON_DISPATCHABLE_TOOLS",
  "buildAgentSystemPrompt", "resolvePreferredLanguage", "buildLanguageInstruction", "toolGenerateWithOneRetry", "toolBlockShapeCorrection", "toolProvenance"];
const PLAN_RAW = "ID: 1\nAGENT: seo\nTOOL: audit\nTASK: Audit the blog\nINPUTS:\n  url = https://example.com\nDEPENDS_ON: NONE\nSUCCESS_SIGNAL: the audit lists every page\nPRIORITY: high\n---\n" +
  "ID: 2\nAGENT: you\nTOOL: NONE\nTASK: Call five customers\nDEPENDS_ON: 1\nSUCCESS_SIGNAL: five notes written\nPRIORITY: medium";
function planApp(which, db, opts) {
  const o = opts || {};
  const app = appStub();
  const runs = [], prompts = [];
  let n = 500;
  const c = makeCtx(db, {
    app: app,
    startToolRun: async (req, spec) => {
      const run = { taskId: UUID(++n), spec: JSON.parse(J(spec)), completed: null, failed: null };
      runs.push(run);
      return { taskId: run.taskId, complete: async (body) => { run.completed = JSON.parse(J(body)); return o.persisted !== false; }, fail: async (e) => { run.failed = String(e && e.message); } };
    },
    agentToolCatalogue: () => ({ seo: ["audit"] }),
    agentToolRoutes: () => [{ key: "seo/audit", spec: [{ name: "url", type: "string", required: true, description: "the site" }] }],
    loadProfileForTool: async () => ({}),
    AGENT_SYSTEM_PROMPTS: { seo: "", executive: "", content: "" },
    CHAIN_NON_DISPATCHABLE_TOOLS: [],
    buildAgentSystemPrompt: () => "SYSTEM",
    resolvePreferredLanguage: async () => "en",
    buildLanguageInstruction: () => "",
    toolGenerateWithOneRetry: async (g) => { prompts.push(g.prompt); g.parse(PLAN_RAW); return { raw: PLAN_RAW, completionExtra: {}, failureDetails: null }; },
    toolBlockShapeCorrection: () => null,
    toolProvenance: (a, b, note, flags) => ({ measured: a, generated: b, note: note, flags: flags || null })
  });
  script(which, "plan", routeSource(which, PLAN_SIG), PLAN_STUBS, "x: 1").runInContext(c.sandbox);
  const call = (user, body) => runRoute(app.routes["post /api/agents/executive/plan"], { user: { id: user }, body: body || {}, params: {}, query: {} });
  return { app, c, call, runs, prompts };
}

/* ── the learning routes, lifted ─────────────────────────────────────────── */
const LEARN_SIGS = ['app.get("/api/agents/:agentType/learning", ', 'app.post("/api/agents/:agentType/preferences", '];
function learnApp(which, db) {
  const app = appStub();
  const c = makeCtx(db, { app: app });
  script(which, "learn", LEARN_SIGS.map(s => routeSource(which, s)).join("\n"), [], "memberGuidanceFor: memberGuidanceFor").runInContext(c.sandbox);
  const get = (user, agent) => runRoute(app.routes["get /api/agents/:agentType/learning"], { user: { id: user }, params: { agentType: agent }, query: {}, body: {} });
  const post = (user, agent, body) => runRoute(app.routes["post /api/agents/:agentType/preferences"], { user: { id: user }, params: { agentType: agent }, query: {}, body: body });
  return { app, c, get, post, guidance: (u, a) => c.sandbox.__api.memberGuidanceFor(u, a) };
}

/* ── fixtures: one finished plan of A's, with B's look-alikes beside it ──── */
const P1 = UUID(100), PB = UUID(200);
const T = n => UUID(100 + n);           // A's tool runs: T(1) .. T(9)
const TB = UUID(201);                   // B's tool run
function planOutput(goal) {
  return { goal: goal, assignments: [{ id: 1, agent: "seo", tool: "audit", task: "Audit the blog" }, { id: 2, agent: "content", tool: "draft", task: "Write two posts" }] };
}
function seed() {
  return {
    users: [{ id: A, email: "member-a@bizforce.example" }, { id: B, email: "member-b@bizforce.example" }],
    ai_tasks: [
      { id: P1, user_id: A, agent_type: "executive", task_type: "executive/plan", status: "completed", created_at: ago(5 * D), output: planOutput("Grow the newsletter") },
      { id: PB, user_id: B, agent_type: "executive", task_type: "executive/plan", status: "completed", created_at: ago(5 * D), output: planOutput("B's plan") },
      { id: T(1), user_id: A, agent_type: "seo", status: "completed", created_at: ago(4 * D) },
      { id: T(2), user_id: A, agent_type: "seo", status: "failed", created_at: ago(4 * D) },
      { id: T(5), user_id: A, agent_type: "seo", status: "completed", created_at: ago(4 * D) },
      { id: T(6), user_id: A, agent_type: "seo", status: "completed", created_at: ago(4 * D) },
      { id: T(7), user_id: A, agent_type: "seo", status: "completed", created_at: ago(4 * D) },
      { id: T(3), user_id: A, agent_type: "content", status: "completed", created_at: ago(4 * D) },
      { id: T(4), user_id: A, agent_type: "analytics", status: "processing", created_at: ago(4 * D) },
      { id: T(9), user_id: A, agent_type: "content", status: "completed", created_at: ago(4 * D) },
      { id: TB, user_id: B, agent_type: "seo", status: "completed", created_at: ago(4 * D) }
    ],
    executive_dispatches: [
      ...[1, 2, 5, 6, 7].map(i => ({ id: UUID(300 + i), user_id: A, plan_task_id: P1, assignment_id: 1, agent_type: "seo", outcome: "ran", tool_task_id: T(i), created_at: ago(4 * D) })),
      { id: UUID(303), user_id: A, plan_task_id: P1, assignment_id: 2, agent_type: "content", outcome: "ran", tool_task_id: T(3), created_at: ago(4 * D) },
      { id: UUID(304), user_id: A, plan_task_id: P1, assignment_id: 3, agent_type: "content", outcome: "refused", refused_reason: "chain_depth", tool_task_id: null, created_at: ago(4 * D) },
      { id: UUID(308), user_id: A, plan_task_id: P1, assignment_id: 4, agent_type: "email", outcome: "failed", tool_task_id: null, created_at: ago(4 * D) },
      { id: UUID(309), user_id: A, plan_task_id: P1, assignment_id: 5, agent_type: "analytics", outcome: "ran", tool_task_id: T(4), created_at: ago(4 * D) },
      // look-alikes: B's row naming A's plan, B's own plan, and an A row of another plan
      { id: UUID(310), user_id: B, plan_task_id: P1, assignment_id: 1, agent_type: "seo", outcome: "ran", tool_task_id: TB, created_at: ago(4 * D) },
      { id: UUID(311), user_id: B, plan_task_id: PB, assignment_id: 1, agent_type: "seo", outcome: "ran", tool_task_id: TB, created_at: ago(4 * D) },
      { id: UUID(312), user_id: A, plan_task_id: UUID(199), assignment_id: 1, agent_type: "content", outcome: "ran", tool_task_id: T(9), created_at: ago(4 * D) }
    ],
    agent_proposals: [
      { id: UUID(401), user_id: A, agent_type: "seo", status: "executed", decided_at: ago(D), executed_at: ago(D), payload: { source_task_id: T(1) } },
      { id: UUID(402), user_id: A, agent_type: "content", status: "rejected", decided_at: ago(D), payload: { source_task_id: T(3) } },
      { id: UUID(403), user_id: A, agent_type: "content", status: "approved", decided_at: ago(2 * D), payload: { source_task_id: T(3) } },
      { id: UUID(404), user_id: A, agent_type: "content", status: "approved", decided_at: ago(D), payload: { source_task_id: T(9) } },
      { id: UUID(405), user_id: B, agent_type: "seo", status: "rejected", decided_at: ago(D), payload: { source_task_id: T(1) } },
      { id: UUID(406), user_id: A, agent_type: "seo", status: "pending", decided_at: null, payload: { source_task_id: T(5) } }
    ],
    agent_feedback: [
      ...[[1, "up"], [2, "down"], [5, "up"], [6, "up"], [7, "down"], [3, "up"]].map(([i, r]) => ({ task_id: T(i), user_id: A, agent_type: i === 3 ? "content" : "seo", rating: r, updated_at: ago(D) })),
      { task_id: T(1), user_id: B, agent_type: "seo", rating: "down", updated_at: ago(D) }
    ],
    plan_cycles: [],
    model_calls: [],
    agent_preferences: [],
    self_reviews: []
  };
}
const VISITS = { posts: { rows: [] }, sends: { rows: [] }, visits: { rows: [ago(4 * D), ago(3 * D), ago(H), ago(6 * D), ago(9 * D)].map(t => ({ ref: "r", created_at: t })) } };
const WANT_TOTALS = { dispatches_ran: 7, dispatches_refused: 1, dispatches_failed: 1, tool_tasks_completed: 5, tool_tasks_failed: 1,
  proposals_approved: 2, proposals_rejected: 1, published: 1, arrivals: 3 };

(async function main() {
  try {
  /* ═══ A. migration 162 ═══════════════════════════════════════════════════ */
  console.log("\n== A. migration 162 ==");
  const mig = FILES.migration;
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  /* NAMED (store connections, Nov 3 2026): BEFORE "the only migration numbered 162, and the highest" (every number <= 162).
     AFTER 163_store_connections.sql follows it, so the pin is "the only one numbered 162, every other one but 163 is lower,
     and 161 came before it"; "the highest" is now checkStoreConnections L9's, for 163.
     NAMED (the Bluesky Mentions inbox, Nov 3 2026): BEFORE only 163_store_connections.sql was allowed above 162. AFTER
     163_store_connections.sql and 164_bluesky_reply_refs.sql; "the highest" is checkBlueskyMentions M3's, for 164.
     NAMED (Connect Mastodon, Nov 3 2026): BEFORE 163 and 164 were allowed above 162. AFTER 163_store_connections.sql,
     164_bluesky_reply_refs.sql and 165_member_mastodon_connections.sql; "the highest" is checkMastodonConnect M3's, for 165.
     NAMED (campaign sharing, Nov 4 2026): BEFORE 163 to 165 were allowed above 162. AFTER 163 to 165 and
     166_campaign_sharing.sql; "the highest" is checkCampaignSharing M2's, for 166. */
  check("A1. 162_plan_cycles.sql is the only migration numbered 162, every one before it is lower (161 was the last before it)",
    // NAMED (Nov 4 2026, the Media Library, migration 167): the allowlist adds 167_member_media.sql; "the highest" is checkMediaLibrary M2's.
    // NAMED (Nov 5 2026, images in social posts, migration 168): BEFORE 163 to 167 allowed above 162. AFTER 168_social_post_images.sql
    // too; "the highest" is checkSocialImages M2's.
    // NAMED (Nov 5 2026, mailbox connection, migration 169): the allowlist adds 169_member_email_connections.sql; "the highest" is checkMailboxConnect M2's.
    migFiles.filter(f => /^162_/.test(f)).length === 1 && migFiles.filter(f => !/^(163_store_connections|164_bluesky_reply_refs|165_member_mastodon_connections|166_campaign_sharing|167_member_media|168_social_post_images|169_member_email_connections)\.sql$/.test(f)).every(f => Number(f.split("_")[0]) <= 162) && migFiles.some(f => /^161_/.test(f)));
  check("A2. plan_cycles: every column the design names, user_id and plan_task_id cascading, previous and next nullable",
    /id                 uuid PRIMARY KEY DEFAULT gen_random_uuid\(\),/.test(mig) &&
    /user_id            uuid NOT NULL REFERENCES public\.users\(id\) ON DELETE CASCADE,/.test(mig) &&
    /plan_task_id       uuid NOT NULL REFERENCES public\.ai_tasks\(id\) ON DELETE CASCADE,/.test(mig) &&
    /previous_cycle_id  uuid REFERENCES public\.plan_cycles\(id\) ON DELETE SET NULL,/.test(mig) &&
    /measured           jsonb,/.test(mig) && /review_text        text /.test(mig) && /next_plan_draft    text /.test(mig) &&
    /next_plan_task_id  uuid REFERENCES public\.ai_tasks\(id\) ON DELETE SET NULL,/.test(mig) && /model              text,/.test(mig) &&
    /approved_at        timestamptz,/.test(mig) && /created_at         timestamptz NOT NULL DEFAULT now\(\),/.test(mig));
  check("A3. status is one of open, review_drafted, approved, superseded (default open), matching the lib",
    /CHECK \(status IN \('open', 'review_drafted', 'approved', 'superseded'\)\)/.test(mig) && /status             text NOT NULL DEFAULT 'open'/.test(mig) &&
    J(PC.STATUSES) === J(["open", "review_drafted", "approved", "superseded"]));
  check("A4. one cycle per member and plan; RLS on, no policy, no grant",
    /UNIQUE \(user_id, plan_task_id\)/.test(mig) && /ALTER TABLE public\.plan_cycles ENABLE ROW LEVEL SECURITY;/.test(mig) && !/CREATE POLICY|GRANT /i.test(mig));
  check("A5. agent_preferences.source gains 'lesson' (151 already had the column, with 'member' and 'suggestion'; default stays 'member')",
    /ADD CONSTRAINT agent_preferences_source_check\n  CHECK \(source IN \('member', 'suggestion', 'lesson'\)\);/.test(mig) &&
    /source      text        NOT NULL DEFAULT 'member',/.test(read("supabase/migrations/151_learning_loop.sql")));
  check("A6. self_reviews gains by_agent and lessons", /ALTER TABLE public\.self_reviews ADD COLUMN IF NOT EXISTS by_agent jsonb;/.test(mig) &&
    /ALTER TABLE public\.self_reviews ADD COLUMN IF NOT EXISTS lessons jsonb;/.test(mig));
  check("A7. the review and next-plan limits agree with the lib", /char_length\(review_text\) <= 4000/.test(mig) && /char_length\(next_plan_draft\) <= 2000/.test(mig) &&
    PC.REVIEW_TEXT_MAX === 4000 && PC.NEXT_PLAN_MAX === 2000);

  /* ═══ B. measured ════════════════════════════════════════════════════════ */
  console.log("\n== B. measured, against hand counts ==");
  const S0 = seed();
  const mine = (t, u) => S0[t].filter(r => r.user_id === u);
  const plan = S0.ai_tasks[0];
  const input = {
    plan: plan, nowMs: FIXED, arrivals: 3,
    dispatches: mine("executive_dispatches", A).filter(r => r.plan_task_id === P1),
    toolTasks: mine("ai_tasks", A), proposals: mine("agent_proposals", A), ratings: mine("agent_feedback", A)
  };
  const M = PC.measuredFrom(input);
  check("B1. the totals are the hand counts (7 ran, 1 refused, 1 failed; 5 completed, 1 failed; 2 approved, 1 rejected, 1 published; 3 arrivals)",
    J(M.totals) === J(WANT_TOTALS), J(M.totals));
  check("B2. by agent: seo ran 5 (4 completed, 1 failed), content ran 1 and refused 1, email failed 1, analytics ran 1 (still running)",
    J(M.by_agent.seo.dispatches) === J({ ran: 5, refused: 0, failed: 0 }) && J(M.by_agent.seo.tool_tasks) === J({ completed: 4, failed: 1, running: 0 }) &&
    J(M.by_agent.content.dispatches) === J({ ran: 1, refused: 1, failed: 0 }) && J(M.by_agent.email.dispatches) === J({ ran: 0, refused: 0, failed: 1 }) &&
    J(M.by_agent.analytics.tool_tasks) === J({ completed: 0, failed: 0, running: 1 }) && Object.keys(M.by_agent).sort().join() === "analytics,content,email,seo", J(M.by_agent));
  check("B3. proposals by agent through outcomesFrom: seo 1 approved and published; content 1 approved, 1 rejected; a run outside the plan and a pending one are not counted",
    J(M.by_agent.seo.proposals) === J({ approved: 1, rejected: 0, published: 1 }) && J(M.by_agent.content.proposals) === J({ approved: 1, rejected: 1, published: 0 }));
  check("B4. the Helpful share only where 5 ratings exist: seo 60% of 5; content 1 rating, no share",
    J(M.by_agent.seo.helpful) === J({ rated: 5, percent: 60 }) && J(M.by_agent.content.helpful) === J({ rated: 1, percent: null }) && LEARNING.MIN_RATINGS === 5);
  check("B5. nothing is unreadable when every read answered; the plan and its time are stated", M.unreadable.length === 0 && M.plan_task_id === P1 && M.since === plan.created_at);
  const N1 = PC.measuredFrom(Object.assign({}, input, { proposals: null, arrivals: null }));
  check("B6. a failed proposals read: the three proposal totals and every agent's proposals are null and named, the rest are counted",
    N1.totals.proposals_approved === null && N1.totals.proposals_rejected === null && N1.totals.published === null && N1.totals.dispatches_ran === 7 &&
    Object.keys(N1.by_agent).every(a => N1.by_agent[a].proposals === null) && N1.unreadable.some(u => u.field === "proposals") && N1.totals.arrivals === null &&
    N1.unreadable.some(u => u.field === "arrivals"), J(N1.unreadable));
  const N2 = PC.measuredFrom(Object.assign({}, input, { dispatches: null }));
  check("B7. a failed dispatch read: every total but arrivals is null (never 0), by_agent is null, and the dependants are named with why",
    PC.TOTAL_KEYS.filter(k => k !== "arrivals").every(k => N2.totals[k] === null) && N2.totals.arrivals === 3 && N2.by_agent === null &&
    J(N2.unreadable.map(u => u.field)) === J(["dispatches", "tool_tasks", "proposals", "helpful"]) && /needs the dispatch records/.test(N2.unreadable[1].reason), J(N2));
  const N3 = PC.measuredFrom(Object.assign({}, input, { toolTasks: null, ratings: null }));
  check("B8. failed runs and ratings reads: those are null and named; dispatches and proposals still counted",
    N3.totals.tool_tasks_completed === null && N3.totals.tool_tasks_failed === null && N3.by_agent.seo.tool_tasks === null && N3.by_agent.seo.helpful === null &&
    N3.totals.dispatches_ran === 7 && N3.totals.proposals_approved === 2 && J(N3.unreadable.map(u => u.field)) === J(["tool_tasks", "helpful"]));
  {
    const db = makeDb(seed());
    const ca = cyclesApp(db);
    ca.c.sandbox.__arrivals = () => VISITS;
    const m = await ca.c.sandbox.__api.planCycleMeasure(A, plan);
    check("B9. the server's reads give the same measured (B's look-alike rows, another plan, the run outside it: none counted)", J(m.totals) === J(WANT_TOTALS) && J(m.by_agent) === J(M.by_agent), J(m.totals));
    const reads = db.log.filter(l => l.op === "select");
    check("B10. every read names the member's user_id; nothing is written", reads.length === 4 && reads.every(l => l.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === A)) &&
      db.log.every(l => l.op === "select"), J(reads.map(l => l.table)));
    check("B11. the dispatch read is this plan's; arrivals come from the member's own refs (loadArrivals(member, false)), since the plan",
      reads[0].table === "executive_dispatches" && reads[0].filters.some(f => f[1] === "plan_task_id" && f[2] === P1) && J(ca.c.sandbox.__arrivalCalls) === J([[A, false]]));
    const fdb = makeDb(seed(), { "agent_proposals:select": true });
    const fa = cyclesApp(fdb);
    fa.c.sandbox.__arrivals = () => ({ posts: { rows: null }, sends: { rows: [] }, visits: { rows: [] } });
    const fm = await fa.c.sandbox.__api.planCycleMeasure(A, plan);
    check("B12. through the server: a failed proposals read and an unreadable arrivals ledger are null and named, never 0",
      fm.totals.proposals_approved === null && fm.totals.arrivals === null && fm.unreadable.map(u => u.field).join() === "proposals,arrivals" && fm.totals.dispatches_ran === 7, J(fm.unreadable));
  }

  /* ═══ C. the verifier ════════════════════════════════════════════════════ */
  console.log("\n== C. the verifier ==");
  const sample = "Seven assignments ran. The SEO agent completed 4 runs and 1 failed. Proposals were approved 2 times and 1 was rejected. " +
    "Arrivals rose by 12 visitors. The SEO agent was rated 60% helpful. Revenue reached 1,500 dollars. Thirteen people replied. " +
    "About a hundred readers came. The rate was 3.5 a day. We should keep going.";
  const v = PC.verifyNumbers(sample, M);
  check("C1. every sentence with a number not in measured is dropped: 12, 1,500, thirteen, a hundred, 3.5",
    J(v.dropped) === J(["Arrivals rose by 12 visitors.", "Revenue reached 1,500 dollars.", "Thirteen people replied.", "About a hundred readers came.", "The rate was 3.5 a day."]), J(v.dropped));
  check("C2. and every other sentence is kept, in order: numbers in measured (digits, words, a percent), and a sentence with none",
    v.text === "Seven assignments ran. The SEO agent completed 4 runs and 1 failed. Proposals were approved 2 times and 1 was rejected. The SEO agent was rated 60% helpful. We should keep going." && v.kept === 5, v.text);
  check("C3. a sentence is dropped whole when only one of its numbers is unknown", PC.verifyNumbers("Seven ran and 8 failed.", M).text === "");
  check("C4. the numbers allowed are exactly measured's numeric values", J(Object.keys(PC.numbersOf(M)).map(Number).sort((a, b) => a - b)) ===
    J([...new Set(JSON.stringify(M).match(/(?<=[:\[,])-?\d+(?:\.\d+)?(?=[,}\]])/g).map(Number))].sort((a, b) => a - b)));
  {
    // An independent oracle over 300 generated sentences.
    const allowed = new Set();
    (function walk(x) { if (typeof x === "number") allowed.add(x); else if (x && typeof x === "object") Object.values(x).forEach(walk); })(M);
    const WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"];
    let seedN = 7; const rnd = n => { seedN = (seedN * 1103515245 + 12345) % 2147483648; return seedN % n; };
    let agree = 0; const bad = [];
    const parts = [];
    for (let i = 0; i < 300; i++) {
      const k = 1 + rnd(3); const nums = []; let s = "";
      const words = [];
      for (let j = 0; j < k; j++) {
        const n = rnd(70);
        nums.push(n);
        words.push(rnd(4) === 0 && n <= 10 ? WORDS[n] : String(n));
      }
      s = "The plan recorded " + words.join(" and ") + " items.";
      const want = nums.every(n => allowed.has(n));
      const got = PC.verifyNumbers(s, M).kept === 1;
      if (want === got) agree++; else bad.push(s);
      parts.push([s, want]);
    }
    check("C5. 300 generated sentences: the verifier keeps exactly those whose every number is in measured", agree === 300, bad.slice(0, 3).join(" | "));
    const joined = parts.map(p => p[0]).join(" ");
    check("C6. ... and over them all at once it keeps those, in order", PC.verifyNumbers(joined, M).text === parts.filter(p => p[1]).map(p => p[0]).join(" "));
  }
  {
    const raw = "REVIEW:\nSeven assignments ran. Arrivals tripled to 9.\nNEXT PLAN:\nPublish 2 posts a week and reach 500 readers. Keep the SEO audit.";
    const d = PC.draftFrom(raw, M);
    check("C7. draftFrom verifies both parts: the review and the next plan lose their invented numbers", d.review_text === "Seven assignments ran." &&
      d.next_plan_draft === "Keep the SEO audit." && d.dropped.length === 2, J(d));
  }

  /* ═══ D. the review route ════════════════════════════════════════════════ */
  console.log("\n== D. the review route ==");
  const OPEN = (id, user, planId, extra) => Object.assign({ id: id, user_id: user, plan_task_id: planId, previous_cycle_id: null, status: "open", measured: null,
    review_text: null, next_plan_draft: null, next_plan_task_id: null, model: null, reviewed_at: null, approved_at: null, created_at: ago(H) }, extra || {});
  const C1 = UUID(601), CB = UUID(602);
  function reviewDb(extraCycles, faults) {
    const s = seed();
    s.plan_cycles = [OPEN(C1, A, P1), OPEN(CB, B, PB)].concat(extraCycles || []);
    return makeDb(s, faults);
  }
  const REPLY = "REVIEW:\nSeven assignments ran and 1 was refused. The SEO agent was rated 60% helpful. Arrivals doubled to 6.\n" +
    "NEXT PLAN:\nRun the SEO audit again and write 2 posts from what it finds. Aim for 40 new readers.";
  {
    const db = reviewDb();
    const ca = cyclesApp(db, {}, replyText(REPLY));
    ca.c.sandbox.__arrivals = () => VISITS;
    const r = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 });
    check("D1. a review answers 200 with the stored draft", r.status === 200 && r.body.cycle && r.body.cycle.status === "review_drafted", J(r));
    check("D2. exactly one model call: Haiku, its own token budget, the plan's goal and measured lines in the prompt",
      ca.c.models.length === 1 && ca.c.models[0].model === "claude-haiku-4-5-20251001" && ca.c.models[0].max_tokens === 900 &&
      /Grow the newsletter/.test(ca.c.models[0].messages[0].content[0].text) && /Assignments run: 7/.test(ca.c.models[0].messages[0].content[0].text), J(ca.c.models.map(m => m.model)));
    const ledger = db.tables.model_calls.filter(x => x.route === "POST /api/executive/cycles/:id/review");
    check("D3. the call is ledgered in model_calls, under the member, the Executive and the review route", ledger.length === 1 && ledger[0].user_id === A && ledger[0].agent_type === "executive", J(db.tables.model_calls));
    const decided = ca.c.gates.filter(g => g.action === "model_call");
    check("D4. the platform's model gates ran first and were recorded (G9, G11, G10 pass)", decided.length === 1 && decided[0].observed.G9.result === "pass" &&
      decided[0].observed.G11.result === "pass" && decided[0].observed.G10.result === "pass" && decided[0].target === "route:POST /api/executive/cycles/:id/review", J(decided));
    const row = db.tables.plan_cycles.filter(c => c.id === C1)[0];
    check("D5. stored: review_drafted, measured, and only verified sentences (\"doubled to 6\" and \"40 new readers\" are gone)",
      row.status === "review_drafted" && J(row.measured.totals) === J(WANT_TOTALS) &&
      row.review_text === "Seven assignments ran and 1 was refused. The SEO agent was rated 60% helpful." &&
      row.next_plan_draft === "Run the SEO audit again and write 2 posts from what it finds." && row.model === "claude-haiku-4-5-20251001" && row.reviewed_at === new Date(FIXED).toISOString(), J(row));
    check("D6. the answer says how many sentences the verifier left out", r.body.verifier && r.body.verifier.dropped === 2 && r.body.verifier.kept === 3, J(r.body.verifier));
    check("D7. nothing runs from a review: no ai_tasks row, no dispatch", db.log.filter(l => l.op !== "select" && l.table !== "plan_cycles" && l.table !== "model_calls").length === 0,
      J(db.log.filter(l => l.op !== "select").map(l => l.table + ":" + l.op)));
    const again = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 });
    check("D8. a second review the same day is refused (429 review_once_a_day) and the model is not asked", again.status === 429 && again.body.code === "review_once_a_day" && ca.c.models.length === 1, J(again));
    db.tables.plan_cycles.filter(c => c.id === C1)[0].reviewed_at = ago(25 * H);
    const later = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 });
    check("D9. after 24 hours a drafted review can be written again (one more call)", later.status === 200 && ca.c.models.length === 2, J(later));
    const dis = await ca.call("post", "/api/executive/cycles/:id/discard", A, {}, { id: C1 });
    const after = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 });
    check("D10. a discarded draft is open again, but the day's review stays used", dis.status === 200 && dis.body.cycle.status === "open" && dis.body.cycle.review_text === null &&
      after.status === 429 && ca.c.models.length === 2, J(after));
  }
  {
    const db = reviewDb();
    const ca = cyclesApp(db, {}, replyText(REPLY));
    const both = await Promise.all([ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 }), ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 })]);
    check("D11. two reviews arriving at once: one is written, the other refused, one model call",
      both.map(x => x.status).sort().join() === "200,429" && ca.c.models.length === 1, both.map(x => x.status).join());
  }
  const day = "2026-11-01";
  {
    // G9: claude-sonnet-5 at $10 per million output tokens; $25, the default ceiling, is 2,500,000.
    const db = reviewDb();
    db.tables.model_calls.push({ id: 1, user_id: "someone", route: "callAnthropicText", model: "claude-sonnet-5", input_tokens: 0, output_tokens: 2500000, funded_by: "platform", created_on: day });
    const ca = cyclesApp(db, {}, replyText(REPLY));
    const r = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 });
    const row = db.tables.plan_cycles.filter(c => c.id === C1)[0];
    check("D12. G9, the platform's daily spend ceiling, refuses (429) before the model is asked, and the day is given back",
      r.status === 429 && ca.c.models.length === 0 && row.reviewed_at === null && row.status === "open" &&
      ca.c.gates.some(g => g.action === "model_call" && g.observed.G9 && g.observed.G9.result === "fail"), J(r) + " " + J(ca.c.gates));
  }
  {
    const db = reviewDb();
    for (let i = 0; i < 3; i++) db.tables.model_calls.push({ id: 10 + i, user_id: A, route: "x", model: "claude-haiku-4-5-20251001", input_tokens: 1, output_tokens: 1, funded_by: "platform", created_on: day });
    const ca = cyclesApp(db, { MODEL_CALLS_DAILY_LIMIT_PER_USER: "3" }, replyText(REPLY));
    const r = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 });
    check("D13. G11, the member's daily model-call cap, refuses (429) before the model is asked; nothing is stored",
      r.status === 429 && ca.c.models.length === 0 && db.tables.plan_cycles.filter(c => c.id === C1)[0].reviewed_at === null &&
      ca.c.gates.some(g => g.action === "model_call" && g.observed.G11 && g.observed.G11.result === "fail"), J(r));
  }
  {
    const db = reviewDb();
    db.tables.model_calls.push({ id: 20, user_id: A, route: "x", model: "claude-sonnet-5", input_tokens: 0, output_tokens: 2000000, funded_by: "platform", created_on: day });
    const ca = cyclesApp(db, { MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER: "5" }, replyText(REPLY));
    const r = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 });
    check("D14. G10, the member's monthly spend cap, refuses (429) before the model is asked",
      r.status === 429 && ca.c.models.length === 0 && ca.c.gates.some(g => g.action === "model_call" && g.observed.G10 && g.observed.G10.result === "fail"), J(r) + " " + J(ca.c.gates.map(g => g.observed)));
  }
  {
    const db = reviewDb([OPEN(UUID(603), A, UUID(198), { status: "approved" }), OPEN(UUID(604), A, UUID(197), { status: "superseded" })]);
    const ca = cyclesApp(db, {}, replyText(REPLY));
    const a1 = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: UUID(603) });
    const a2 = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: UUID(604) });
    const a3 = await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: "not-a-uuid" });
    check("D15. an approved or set-aside cycle is not reviewed (409), a bad id is 404, and the model is not asked",
      a1.status === 409 && a2.status === 409 && a3.status === 404 && ca.c.models.length === 0, [a1.status, a2.status, a3.status].join());
  }
  check("D16. the review route: requireAuth, requireActiveSubscription, aiLimiter, in that order; the others are rate-limited by cycleLimiter",
    NEW.indexOf('app.post("/api/executive/cycles/:id/review", requireAuth, requireActiveSubscription, aiLimiter, async function') !== -1 &&
    ['app.get("/api/executive/cycles", requireAuth, cycleLimiter,', 'app.post("/api/executive/cycles", requireAuth, requireActiveSubscription, cycleLimiter,',
      'app.put("/api/executive/cycles/:id", requireAuth, requireActiveSubscription, cycleLimiter,', 'app.post("/api/executive/cycles/:id/approve", requireAuth, requireActiveSubscription, cycleLimiter,',
      'app.post("/api/executive/cycles/:id/discard", requireAuth, requireActiveSubscription, cycleLimiter,', 'app.post("/api/executive/cycles/:id/supersede", requireAuth, requireActiveSubscription, cycleLimiter,']
      .every(s => NEW.split(s).length === 2) && /const cycleLimiter = rateLimit\(\{\n  windowMs: 10 \* 60 \* 1000,\n  max: 60,/.test(NEW));
  check("D17. the review's one call is the only model call in the cycle routes", (() => {
    const block = CYCLE_SIGS.map(s => routeSource("new", s)).join("\n");
    return (block.match(/callAnthropicText\(/g) || []).length === 1 && !/callAnthropicWithTools|callAnthropicJson|startToolRun|toolGenerate/.test(block);
  })());

  /* ═══ E. approval and the plan route ═════════════════════════════════════ */
  console.log("\n== E. approval, and the next plan through the plan route ==");
  const DRAFTED = (id, user, planId, extra) => OPEN(id, user, planId, Object.assign({ status: "review_drafted", measured: M, review_text: "Seven assignments ran.",
    next_plan_draft: "Run the SEO audit again.", reviewed_at: ago(H), model: "claude-haiku-4-5-20251001" }, extra || {}));
  {
    const db = reviewDb([DRAFTED(UUID(611), A, UUID(196)), DRAFTED(UUID(612), A, UUID(195), { next_plan_draft: null })]);
    const ca = cyclesApp(db);
    const e0 = await ca.call("post", "/api/executive/cycles/:id/approve", A, {}, { id: C1 });
    check("E1. approving a cycle with no drafted review is refused (409)", e0.status === 409, J(e0));
    const e1 = await ca.call("post", "/api/executive/cycles/:id/approve", A, {}, { id: UUID(612) });
    check("E2. approving with no next plan is refused (400), nothing changed", e1.status === 400 && db.tables.plan_cycles.filter(c => c.id === UUID(612))[0].status === "review_drafted", J(e1));
    const e2 = await ca.call("post", "/api/executive/cycles/:id/approve", A, { extra: 1 }, { id: UUID(611) });
    check("E3. the body is closed: only review_text and next_plan_draft (400 otherwise)", e2.status === 400);
    const ed = await ca.call("put", "/api/executive/cycles/:id", A, { next_plan_draft: "Run the SEO audit again, then write one post." }, { id: UUID(611) });
    check("E4. the member edits the draft (PUT), and it stays a draft", ed.status === 200 && ed.body.cycle.status === "review_drafted" && ed.body.cycle.next_plan_draft === "Run the SEO audit again, then write one post.");
    const before = db.log.length;
    const ap = await ca.call("post", "/api/executive/cycles/:id/approve", A, { review_text: "My own review." }, { id: UUID(611) });
    const row = db.tables.plan_cycles.filter(c => c.id === UUID(611))[0];
    check("E5. approve: approved, approved_at set, the member's edits kept; no plan is started and no model is asked",
      ap.status === 200 && row.status === "approved" && row.approved_at === new Date(FIXED).toISOString() && row.review_text === "My own review." &&
      row.next_plan_draft === "Run the SEO audit again, then write one post." && row.next_plan_task_id === null && ca.c.models.length === 0 &&
      db.log.slice(before).every(l => l.table === "plan_cycles"), J(ap));
    const sup = await ca.call("post", "/api/executive/cycles/:id/supersede", A, {}, { id: C1 });
    check("E6. an open cycle can be set aside (superseded); an approved one cannot", sup.status === 200 && sup.body.cycle.status === "superseded" &&
      (await ca.call("post", "/api/executive/cycles/:id/supersede", A, {}, { id: UUID(611) })).status === 409);
  }
  {
    const cycles = [DRAFTED(UUID(621), A, UUID(194)), OPEN(UUID(622), A, UUID(193)), OPEN(UUID(623), A, UUID(192), { status: "superseded" }),
      DRAFTED(UUID(624), A, P1, { status: "approved", approved_at: ago(H), next_plan_draft: "Run the SEO audit again, then write one post." }),
      DRAFTED(UUID(625), A, UUID(191), { status: "approved", next_plan_task_id: UUID(190) })];
    const db = reviewDb(cycles);
    const pa = planApp("new", db);
    const refused = [];
    for (const id of [UUID(621), UUID(622), UUID(623)]) refused.push(await pa.call(A, { goal: "Anything", cycle_id: id }));
    check("E7. the plan route refuses a cycle that is drafted, open or set aside (409 cycle_not_approved): nothing started, no model asked",
      refused.every(r => r.status === 409 && r.body.code === "cycle_not_approved") && pa.runs.length === 0 && pa.prompts.length === 0, J(refused.map(r => r.body)));
    const started = await pa.call(A, { goal: "Anything", cycle_id: UUID(625) });
    const bad = await pa.call(A, { goal: "Anything", cycle_id: "x" });
    const other = await pa.call(B, { goal: "Anything", cycle_id: UUID(624) });
    check("E8. ... a cycle whose next plan already started (409), a bad id (400), another member's cycle (404)",
      started.status === 409 && started.body.code === "cycle_already_started" && bad.status === 400 && other.status === 404 && pa.runs.length === 0, [started.status, bad.status, other.status].join());
    const go = await pa.call(A, { goal: "Something the page sent", cycle_id: UUID(624) });
    const linked = db.tables.plan_cycles.filter(c => c.id === UUID(624))[0];
    const nextCycle = db.tables.plan_cycles.filter(c => c.previous_cycle_id === UUID(624))[0];
    check("E9. an approved cycle starts its next plan: one run of executive/plan, the approved draft as THE GOAL (not the body's)",
      go.status === 200 && pa.runs.length === 1 && pa.runs[0].spec.taskType === "executive/plan" && pa.prompts.length === 1 &&
      pa.prompts[0].indexOf("THE GOAL:\nRun the SEO audit again, then write one post.") !== -1 && pa.prompts[0].indexOf("Something the page sent") === -1 && go.body.goal === "Run the SEO audit again, then write one post.", J(go.body && go.body.goal));
    check("E10. the run is linked to the cycle and the next cycle opens on it, building on this one",
      linked.next_plan_task_id === pa.runs[0].taskId && nextCycle && nextCycle.plan_task_id === pa.runs[0].taskId && nextCycle.status === "open" && nextCycle.user_id === A &&
      go.body.cycle && go.body.cycle.linked === true && go.body.cycle.next_cycle_id === nextCycle.id, J(go.body.cycle));
    const twice = await pa.call(A, { goal: "Anything", cycle_id: UUID(624) });
    check("E11. starting it a second time is refused (409 cycle_already_started)", twice.status === 409 && twice.body.code === "cycle_already_started" && pa.runs.length === 1);
    const db2 = reviewDb([DRAFTED(UUID(626), A, UUID(189), { status: "approved" })]);
    const pa2 = planApp("new", db2, { persisted: false });
    const np = await pa2.call(A, { cycle_id: UUID(626) });
    check("E12. a run whose record was not saved is not linked, and the answer says so", np.status === 200 && np.body.cycle.linked === false &&
      db2.tables.plan_cycles.filter(c => c.id === UUID(626))[0].next_plan_task_id === null && db2.tables.plan_cycles.length === 3, J(np.body.cycle));
  }
  {
    // OLD (PRE_CYCLES) against NEW, with no cycle_id: the same answer, the same reads and writes, the same calls.
    const bodies = [{ goal: "Grow the newsletter", horizon: "30 days" }, { goal: "" }, { goal: "Grow", constraints: "No ads" }, { goal: "Grow", cycle_id: null }];
    const same = [];
    for (const body of bodies) {
      const dbO = reviewDb(), dbN = reviewDb();
      const o = planApp("old", dbO), n = planApp("new", dbN);
      const ro = await o.call(A, body), rn = await n.call(A, body);
      same.push(J(ro) === J(rn) && J(o.runs) === J(n.runs) && J(o.prompts) === J(n.prompts) && J(dbO.log) === J(dbN.log) && J(o.c.logs) === J(n.c.logs));
    }
    check("E13. without a cycle_id the plan route is unchanged: " + bodies.length + " requests, old and new, identical answers, records and calls", same.every(Boolean), J(same));
    const at = s => s.indexOf(PLAN_SIG);
    const oldRoute = routeSource("old", PLAN_SIG), newRoute = routeSource("new", PLAN_SIG);
    const block1 = newRoute.slice(newRoute.indexOf("      /* A LEARNING CYCLE'S NEXT PLAN."), newRoute.indexOf("      if (!goal) {"));
    const block2 = newRoute.slice(newRoute.indexOf("      if (cycleStart) {\n        var cycleLink"), newRoute.indexOf("      return res.json(Object.assign({}, responseBody, {\n        task_id: run.taskId,"));
    check("E14. byte proof: the plan route is its old text plus exactly two blocks (the cycle check before anything is spent, the link after the run is recorded)",
      at(OLD) !== -1 && block1.length > 200 && block2.length > 100 && newRoute.replace(block1, "").replace(block2, "") === oldRoute &&
      newRoute.indexOf(block1) < newRoute.indexOf("var run = await startToolRun(req, {"));
  }
  {
    const blockStart = NEW.indexOf("// LEARNING CYCLES: review a finished plan, approve the next (B8 and B9).");
    const blockEnd = NEW.indexOf("// Set a cycle aside: superseded, and nothing more happens to it.");
    const outside = [];
    const re = /plan_cycles|planCycle[A-Z][A-Za-z]*\(/g; let mm;
    while ((mm = re.exec(NEW))) if (mm.index < blockStart || mm.index > blockEnd + 1200) outside.push(NEW.slice(mm.index - 40, mm.index + 40).replace(/\n/g, " "));
    check("E15. nothing else touches cycles: outside the cycle block only the plan route's two calls (planCycleStartCheck, planCycleLinkNext); no timer, no cron",
      outside.length === 2 && /planCycleStartCheck\(/.test(outside[0]) && /planCycleLinkNext\(/.test(outside[1]) &&
      !/setInterval|cron|Tick\(/.test(NEW.slice(blockStart, blockEnd)), J(outside));
  }

  /* ═══ F. lessons by rule ═════════════════════════════════════════════════ */
  console.log("\n== F. lessons, by rule ==");
  check("F1. the reason rule: 3 Not helpful for one reason gives a lesson with the count; 2 does not; \"Other\" never does",
    J(LESSONS.lessonsFrom({ content: { not_helpful: { "Too long": 3, "Wrong tone": 2, "Other": 9 } } })) ===
    J({ content: [{ rule: "reason", evidence: "Not helpful: Too long, 3 times", text: "Not helpful: Too long, 3 times. Keep it shorter." }] }));
  check("F2. the rejected rule: 2 of 4 rejected (at least half of 2 or more decided) gives one; 1 of 3 does not",
    J(LESSONS.lessonsFrom({ seo: { proposals: { approved: 2, rejected: 2, published: 0 } } }).seo) === J([{ rule: "rejected", evidence: "2 of 4 proposals rejected", text: "2 of 4 proposals rejected. Propose only what fits my brief." }]) &&
    J(LESSONS.lessonsFrom({ seo: { proposals: { approved: 2, rejected: 1, published: 0 } } })) === J({}));
  check("F3. the approved rule: 3 of 3 approved, none rejected, gives one; 2 of 2 does not",
    J(LESSONS.lessonsFrom({ email: { proposals: { approved: 3, rejected: 0, published: 1 } } }).email) === J([{ rule: "approved", evidence: "3 of 3 proposals approved", text: "3 of 3 proposals approved. Keep proposing the same way." }]) &&
    J(LESSONS.lessonsFrom({ email: { proposals: { approved: 2, rejected: 0, published: 0 } } })) === J({}));
  check("F4. an unreadable breakdown gives no lessons (null), an unreadable part gives none from that part; every lesson fits a preference (80)",
    LESSONS.lessonsFrom(null) === null && J(LESSONS.lessonsFrom({ seo: { proposals: null, not_helpful: null } })) === J({}) &&
    LESSONS.lessonsFrom({ x: { not_helpful: { "Inaccurate": 1000000000 } } }).x === undefined &&
    LESSONS.lessonsFrom({ x: { not_helpful: { "Inaccurate": 3 } } }).x[0].text.length <= LEARNING.PREF_MAX);
  check("F5. lib/lessons.js asks no model and reads no database (no require but the learning loop)",
    !/callAnthropic|supabase|fetch\(|messages\.create/.test(FILES.lessons.replace(/\/\*[\s\S]*?\*\//g, "")) &&
    (FILES.lessons.match(/require\("([^"]+)"\)/g) || []).join() === 'require("./learningLoop")');
  // The weekly review, with the model stubbed: 2026-11-01 is a Sunday, so the week is Oct 19 to Oct 26.
  const IN = "2026-10-21T10:00:00.000Z", OUT = "2026-10-27T10:00:00.000Z";
  function weekSeed() {
    const s = { users: [{ id: A, email: "member-a@bizforce.example" }, { id: B, email: "member-b@bizforce.example" }], self_reviews: [], agent_preferences: [], ai_tasks: [], agent_proposals: [], agent_feedback: [] };
    [["content", "completed", 3], ["content", "failed", 1], ["seo", "completed", 2], ["seo", "processing", 1]].forEach(([a, st, n]) => { for (let i = 0; i < n; i++) s.ai_tasks.push({ user_id: A, agent_type: a, status: st, created_at: IN }); });
    s.ai_tasks.push({ user_id: B, agent_type: "content", status: "completed", created_at: IN }, { user_id: A, agent_type: "content", status: "completed", created_at: OUT });
    [["content", "rejected", 2], ["content", "approved", 1], ["seo", "executed", 3]].forEach(([a, st, n]) => { for (let i = 0; i < n; i++) s.agent_proposals.push({ user_id: A, agent_type: a, status: st, decided_at: IN, created_at: IN }); });
    s.agent_proposals.push({ user_id: B, agent_type: "content", status: "rejected", decided_at: IN, created_at: IN }, { user_id: A, agent_type: "content", status: "rejected", decided_at: OUT, created_at: OUT });
    [["content", "Too long", 3], ["content", "Other", 4], ["seo", "Wrong tone", 2]].forEach(([a, r, n]) => { for (let i = 0; i < n; i++) s.agent_feedback.push({ user_id: A, agent_type: a, rating: "down", reason: r, updated_at: IN }); });
    for (let i = 0; i < 3; i++) s.agent_feedback.push({ user_id: B, agent_type: "seo", rating: "down", reason: "Too long", updated_at: IN });
    s.agent_feedback.push({ user_id: A, agent_type: "seo", rating: "up", reason: null, updated_at: IN });
    return s;
  }
  const WANT_BY_AGENT = {
    content: { tasks: { completed: 3, failed: 1, other: 0 }, proposals: { approved: 1, rejected: 2, published: 0 }, not_helpful: { "Too long": 3, "Other": 4 } },
    seo: { tasks: { completed: 2, failed: 0, other: 1 }, proposals: { approved: 3, rejected: 0, published: 3 }, not_helpful: { "Wrong tone": 2 } }
  };
  const WANT_LESSONS = {
    content: [{ rule: "reason", evidence: "Not helpful: Too long, 3 times", text: "Not helpful: Too long, 3 times. Keep it shorter." },
      { rule: "rejected", evidence: "2 of 3 proposals rejected", text: "2 of 3 proposals rejected. Propose only what fits my brief." }],
    seo: [{ rule: "approved", evidence: "3 of 3 proposals approved", text: "3 of 3 proposals approved. Keep proposing the same way." }]
  };
  {
    const db = makeDb(weekSeed());
    const b = await SR.gatherAgentBreakdown({ supabase: db.client, userId: A, start: new Date("2026-10-19T00:00:00Z"), end: new Date("2026-10-26T00:00:00Z") });
    check("F6. the per-agent breakdown is the hand count (B's rows and rows outside the week are not counted)", J(b.by_agent) === J(WANT_BY_AGENT) && b.unreadable.length === 0, J(b));
    check("F7. every breakdown read is the member's own, in the week", db.log.length === 3 && db.log.every(l => l.filters.some(f => f[1] === "user_id" && f[2] === A) &&
      l.filters.some(f => f[0] === "gte") && l.filters.some(f => f[0] === "lt")));
    const fdb = makeDb(weekSeed(), { "agent_proposals:select": true });
    const fb = await SR.gatherAgentBreakdown({ supabase: fdb.client, userId: A, start: new Date("2026-10-19T00:00:00Z"), end: new Date("2026-10-26T00:00:00Z") });
    check("F8. a failed proposals read: every agent's proposals are null and named, never 0; the rest are counted",
      fb.by_agent.content.proposals === null && fb.by_agent.seo.proposals === null && J(fb.by_agent.content.tasks) === J(WANT_BY_AGENT.content.tasks) &&
      J(fb.unreadable) === J(["by_agent.proposals"]), J(fb));
  }
  async function weekly(periodType, faults) {
    const db = makeDb(weekSeed(), faults);
    const calls = [];
    const origError = console.error; const errs = [];
    console.error = function () { errs.push(Array.prototype.join.call(arguments, " ")); };
    let row = null;
    try {
      row = await SR.generateSelfReview({ supabase: db.client, userId: A, periodType: periodType, now: new Date(FIXED),
        callAnthropicText: async (p, n) => { calls.push(p); return { text: "A steady week.", model: "claude-haiku-4-5-20251001" }; } });
    } finally { console.error = origError; }
    return { db, calls, row, errs };
  }
  {
    const w = await weekly("weekly");
    const stored = w.db.tables.self_reviews[0];
    check("F9. the weekly review stores its per-agent breakdown and the lessons by rule", stored && J(stored.by_agent) === J(WANT_BY_AGENT) && J(stored.lessons) === J(WANT_LESSONS), J(stored && stored.lessons));
    check("F10. ... with exactly one model call, the narrative (no model call for lessons)", w.calls.length === 1 && w.row && w.row.narrative === "A steady week.", w.calls.length);
    check("F11. ... and saves no preference: a lesson is never saved by being derived", w.db.tables.agent_preferences.length === 0 && !w.db.log.some(l => l.table === "agent_preferences"));
    const m = await weekly("monthly");
    check("F12. a monthly review is unchanged: no breakdown, no lessons, one call", m.calls.length === 1 && m.db.tables.self_reviews[0].by_agent === undefined && m.db.tables.self_reviews[0].lessons === undefined);
    const f = await weekly("weekly", { "self_reviews:update": true });
    check("F13. when the breakdown cannot be stored (before 162), it is logged and the review is otherwise unchanged (its metrics, its one call)",
      f.calls.length === 1 && f.db.tables.self_reviews[0].metrics && f.errs.some(e => /per-agent breakdown could not be stored/.test(e)));
    const genOf = src => src.slice(src.indexOf("async function generateSelfReview("), src.indexOf("\nmodule.exports = {"));
    const oldGen = genOf(OLD_SELF_REVIEW), newGen = genOf(FILES.selfReview);
    const ins = newGen.slice(newGen.indexOf("  /* ── A weekly review's per-agent breakdown"), newGen.indexOf("  var prompt = buildNarrativePrompt("));
    check("F14. byte proof: generateSelfReview is its old text plus exactly the one weekly block, gatherReviewMetrics is byte-identical, and the exports only gain gatherAgentBreakdown",
      ins.length > 300 && newGen.replace(ins, "") === oldGen &&
      SR.gatherReviewMetrics.toString() === compile(OLD_SELF_REVIEW, "old-selfReview.js", libReq).gatherReviewMetrics.toString() &&
      OLD_SELF_REVIEW.trimEnd().endsWith("\nmodule.exports = { computePeriodBounds, gatherReviewMetrics, generateSelfReview };") &&
      FILES.selfReview.trimEnd().endsWith("\nmodule.exports = { computePeriodBounds, gatherReviewMetrics, gatherAgentBreakdown, generateSelfReview };"));
  }
  {
    // The panel offers them; one is saved only when accepted.
    const w = await weekly("weekly");
    const s = JSON.parse(J(w.db.tables));
    const db = makeDb(Object.assign({}, s, { agent_preferences: [{ id: UUID(801), user_id: A, agent_type: "content", text: "Use short paragraphs", source: "member", created_at: ago(9 * D) }] }));
    const la = learnApp("new", db);
    const g = await la.get(A, "content");
    check("F15. GET learning offers the content agent's two lessons and when they come from; nothing is written by showing them",
      g.status === 200 && J(g.body.lessons) === J(WANT_LESSONS.content) && g.body.lessons_from && g.body.lessons_from.period_start === "2026-10-19T00:00:00.000Z" &&
      db.log.every(l => l.op === "select"), J(g.body.lessons));
    const notOffered = await la.post(A, "content", { text: "Never mention prices.", source: "lesson" });
    check("F16. a text the review does not offer is refused as a lesson (400), nothing written", notOffered.status === 400 && db.tables.agent_preferences.length === 1);
    const other = await la.post(B, "content", { text: WANT_LESSONS.content[0].text, source: "lesson" });
    check("F17. another member cannot accept A's lesson (B has no review offering it)", other.status === 400 && db.tables.agent_preferences.length === 1);
    const ok = await la.post(A, "content", { text: WANT_LESSONS.content[0].text, source: "lesson" });
    const saved = db.tables.agent_preferences.filter(p => p.source === "lesson");
    check("F18. accepting a lesson saves it once, as a preference with source 'lesson', for that member and agent",
      ok.status === 200 && saved.length === 1 && saved[0].user_id === A && saved[0].agent_type === "content" && saved[0].text === WANT_LESSONS.content[0].text, J(ok));
    const g2 = await la.get(A, "content");
    check("F19. it is no longer offered, and it is in the preferences with its source", J(g2.body.lessons) === J([WANT_LESSONS.content[1]]) &&
      g2.body.preferences.some(p => p.text === WANT_LESSONS.content[0].text && p.source === "lesson"));
    const guidance = await la.guidance(A, "content");
    check("F20. it reaches the prompt through the existing guidance block, word for word, and the panel shows that block",
      guidance.indexOf("- " + WANT_LESSONS.content[0].text + "\n") !== -1 && g2.body.guidance === guidance && guidance.indexOf(LEARNING.GUIDANCE_HEADER) === 0);
    const seo = await la.get(A, "seo");
    check("F21. each agent is offered only its own lessons", J(seo.body.lessons) === J(WANT_LESSONS.seo));
    for (let i = 0; i < 6; i++) db.tables.agent_preferences.push({ id: UUID(820 + i), user_id: A, agent_type: "content", text: "Preference " + i, source: "member", created_at: ago(D) });
    const full = await la.post(A, "content", { text: WANT_LESSONS.content[1].text, source: "lesson" });
    check("F22. within PREF_CAP: with 8 preferences the next lesson is refused (400), nothing written",
      full.status === 400 && db.tables.agent_preferences.filter(p => p.user_id === A && p.agent_type === "content").length === LEARNING.PREF_CAP && LEARNING.PREF_CAP === 8, J(full));
    const fdb = makeDb(Object.assign({}, s), { "self_reviews:select": true });
    const fl = learnApp("new", fdb);
    const fg = await fl.get(A, "content");
    const fp = await fl.post(A, "content", { text: WANT_LESSONS.content[0].text, source: "lesson" });
    check("F23. a review that cannot be read: GET says lessons null (not none), POST is 503, nothing written",
      fg.status === 200 && fg.body.lessons === null && fp.status === 503 && fdb.tables.agent_preferences.length === 0, J([fg.status, fg.body.lessons, fp.status]));
  }
  {
    // Old against new on every other path of the two learning routes.
    const cases = [[A, "content", { text: "Keep it tight", source: "member" }], [A, "content", { text: "Keep it shorter", source: "suggestion" }], [A, "content", { text: "" }],
      [A, "general!", { text: "x" }], [B, "content", { text: "Plain words please" }]];
    const same = [];
    for (const [u, a, body] of cases) {
      const dbO = makeDb(weekSeed()), dbN = makeDb(weekSeed());
      const ro = await learnApp("old", dbO).post(u, a, body), rn = await learnApp("new", dbN).post(u, a, body);
      same.push(J(ro) === J(rn) && J(dbO.log) === J(dbN.log));
    }
    check("F24. POST preferences for a member's own words or a suggestion is unchanged, old against new (" + cases.length + " cases)", same.every(Boolean), J(same));
    const dbO = makeDb(weekSeed()), dbN = makeDb(weekSeed());
    const go = await learnApp("old", dbO).get(A, "content"), gn = await learnApp("new", dbN).get(A, "content");
    const stripped = Object.assign({}, gn.body); delete stripped.lessons; delete stripped.lessons_from;
    check("F25. GET learning answers what it did before, plus lessons and lessons_from (and one read of the latest weekly review)",
      J(go.body) === J(stripped) && J(dbN.log.filter(l => l.table !== "self_reviews")) === J(dbO.log) && dbN.log.filter(l => l.table === "self_reviews").length === 1);
  }

  /* ═══ G. the history ═════════════════════════════════════════════════════ */
  console.log("\n== G. the history ==");
  {
    const now = { totals: Object.assign({}, WANT_TOTALS, { arrivals: null }) };
    const prev = { totals: Object.assign({}, WANT_TOTALS, { dispatches_ran: 4, dispatches_failed: 3, tool_tasks_completed: 5 }) };
    const rows = PC.arrowsAgainst(now, prev);
    const by = k => rows.filter(r => r.key === k)[0];
    check("G1. up, down and level as an agent's score shows them; none where either side is unknown",
      by("dispatches_ran").arrow === "↑" && by("dispatches_ran").change === 3 && by("dispatches_failed").arrow === "↓" && by("dispatches_failed").change === -2 &&
      by("tool_tasks_completed").arrow === "→" && by("arrivals").arrow === null && by("arrivals").change === null && rows.length === PC.TOTAL_KEYS.length, J(rows));
    const sc = LEARNING.scoreFrom([], FIXED);
    check("G2. the same three arrow characters scoreFrom uses", FILES.lib.indexOf('arrow: change === null ? null : (change > 0 ? "↑" : (change < 0 ? "↓" : "→"))') !== -1 &&
      read("lib/learningLoop.js").indexOf('arrow = change > 0 ? "↑" : (change < 0 ? "↓" : "→");') !== -1 && sc.arrow === null);
    const first = OPEN(UUID(631), A, P1, { status: "approved", measured: prev, next_plan_task_id: UUID(190), created_at: ago(3 * D) });
    const second = OPEN(UUID(632), A, UUID(190), { previous_cycle_id: UUID(631), status: "review_drafted", measured: now, created_at: ago(H) });
    const db = makeDb({ plan_cycles: [first, second, OPEN(UUID(633), B, PB)] });
    const ca = cyclesApp(db);
    const r = await ca.call("get", "/api/executive/cycles", A);
    check("G3. GET cycles: the member's cycles newest first, each against the one before; the first has nothing to compare",
      r.status === 200 && r.body.cycles.map(c => c.id).join() === [UUID(632), UUID(631)].join() && r.body.cycles[0].against_previous &&
      r.body.cycles[0].against_previous.filter(x => x.key === "dispatches_ran")[0].arrow === "↑" && r.body.cycles[1].against_previous === null, J(r.body));
    const f = await cyclesApp(makeDb({}, { "plan_cycles:select": true })).call("get", "/api/executive/cycles", A);
    check("G4. a history that cannot be read is 503, never an empty list", f.status === 503 && !f.body.cycles && /not an empty history/.test(f.body.error));
  }

  /* ═══ H. the honest copy ═════════════════════════════════════════════════ */
  console.log("\n== H. the honest copy ==");
  const COPY = "Each cycle builds on recorded results. The AI model itself does not change.";
  check("H1. the lib's fixed line, word for word", PC.CYCLE_COPY === COPY);
  {
    const db = reviewDb([DRAFTED(UUID(641), A, UUID(188))]);
    const ca = cyclesApp(db, {}, replyText(REPLY));
    const answers = [await ca.call("get", "/api/executive/cycles", A), await ca.call("post", "/api/executive/cycles", A, { plan_task_id: P1 }),
      await ca.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 }), await ca.call("put", "/api/executive/cycles/:id", A, { review_text: "Mine." }, { id: UUID(641) }),
      await ca.call("post", "/api/executive/cycles/:id/approve", A, {}, { id: UUID(641) })];
    check("H2. every cycle every route answers carries it", answers.every(x => x.status === 200) &&
      answers[0].body.copy === COPY && answers[0].body.cycles.every(c => c.copy === COPY) && answers.slice(1).every(x => x.body.cycle.copy === COPY), J(answers.map(x => x.status)));
  }
  check("H3. the Plans tab's script carries the same line", FILES.ui.indexOf('  var CYCLE_COPY = "' + COPY + '";') !== -1);

  /* ═══ I. ownership ═══════════════════════════════════════════════════════ */
  console.log("\n== I. ownership ==");
  {
    const db = reviewDb([DRAFTED(UUID(651), A, UUID(187))]);
    const ca = cyclesApp(db, {}, replyText(REPLY));
    const tries = [await ca.call("post", "/api/executive/cycles/:id/review", B, {}, { id: C1 }), await ca.call("put", "/api/executive/cycles/:id", B, { review_text: "x" }, { id: UUID(651) }),
      await ca.call("post", "/api/executive/cycles/:id/approve", B, {}, { id: UUID(651) }), await ca.call("post", "/api/executive/cycles/:id/discard", B, {}, { id: UUID(651) }),
      await ca.call("post", "/api/executive/cycles/:id/supersede", B, {}, { id: C1 }), await ca.call("post", "/api/executive/cycles", B, { plan_task_id: P1 })];
    check("I1. another member's cycle or plan is 404 on every route, nothing changed, no model asked", tries.every(x => x.status === 404) && ca.c.models.length === 0 &&
      db.log.every(l => l.op === "select"), J(tries.map(x => x.status)));
    const list = await ca.call("get", "/api/executive/cycles", B);
    check("I2. B's history holds only B's cycle", list.body.cycles.length === 1 && list.body.cycles[0].id === CB);
    const writes = db.log.concat((await (async () => { const d2 = reviewDb(); const c2 = cyclesApp(d2, {}, replyText(REPLY)); await c2.call("post", "/api/executive/cycles/:id/review", A, {}, { id: C1 }); return d2.log; })()));
    const cyc = writes.filter(l => l.table === "plan_cycles");
    check("I3. every plan_cycles read and write carries the caller's user_id", cyc.length > 0 && cyc.every(l => l.op === "insert" ? l.payload.user_id : l.filters.some(f => f[0] === "eq" && f[1] === "user_id")));
    const open = await ca.call("post", "/api/executive/cycles", A, { plan_task_id: P1 });
    const again = await ca.call("post", "/api/executive/cycles", A, { plan_task_id: P1 });
    const notPlan = await ca.call("post", "/api/executive/cycles", A, { plan_task_id: T(1) });
    check("I4. a cycle opens only on the member's own executive/plan, once (the second answer is the same cycle)",
      open.status === 200 && open.body.existing === true && again.body.cycle.id === C1 && notPlan.status === 404);
  }

  /* ═══ K. export, deletion, backup ════════════════════════════════════════ */
  console.log("\n== K. export, deletion and backup ==");
  {
    const YD = realRequire("./lib/yourData");
    const entry = YD.DATA.filter(e => e.table === "plan_cycles");
    check("K1. plan_cycles is in the export once: group agents, owner user_id, deleted with the account", entry.length === 1 && entry[0].group === "agents" &&
      J(entry[0].owner) === J(["user_id"]) && entry[0].onDelete === "delete");
    check("K2. it is deleted before ai_tasks, which it references", YD.DELETE_ORDER.filter(t => t === "plan_cycles").length === 1 &&
      YD.DELETE_ORDER.indexOf("plan_cycles") < YD.DELETE_ORDER.indexOf("ai_tasks"));
    check("K3. lib/backup.js backs it up; agent_preferences (with its lessons) and self_reviews still are", /\n  "plan_cycles",/.test(FILES.backup) &&
      /\n  "agent_preferences",/.test(FILES.backup) && /\n  "self_reviews",/.test(FILES.backup));
    const rows = [OPEN(UUID(661), A, P1), OPEN(UUID(662), A, UUID(186), { status: "approved" }), OPEN(UUID(663), B, PB)];
    const db = makeDb({ plan_cycles: rows });
    let out = "";
    await YD.exportAccountData({ supabase: db.client, userId: A, write: s => { out += s; }, now: new Date(FIXED) });
    let parsed = null; try { parsed = JSON.parse(out); } catch (e) { parsed = null; }
    const got = parsed && parsed.tables && parsed.tables.plan_cycles;
    check("K4. the export holds A's two cycles and none of B's", Array.isArray(got) && got.length === 2 && got.every(r => r.user_id === A || r.user_id === "you"), J(got));
    const ddb = makeDb({ plan_cycles: rows });
    await ddb.client.from("plan_cycles").delete().eq("user_id", A);
    check("K5. deleting the account's rows removes A's and keeps B's", ddb.tables.plan_cycles.length === 1 && ddb.tables.plan_cycles[0].user_id === B);
  }

  /* ═══ L. the self-review header ══════════════════════════════════════════ */
  console.log("\n== L. lib/selfReview.js says it is wired ==");
  const head = FILES.selfReview.slice(0, FILES.selfReview.indexOf("const { isUncountedAccount }"));
  check("L1. the header no longer says \"UNWIRED ON PURPOSE\" or \"Nothing imports this yet\"", !/UNWIRED ON PURPOSE/.test(head) && !/Nothing imports this yet/.test(head) &&
    /UNWIRED ON PURPOSE\. Nothing imports this yet/.test(OLD_SELF_REVIEW));
  check("L2. what it says instead is true: server.js requires it and calls generateSelfReview from the run route and selfReviewTick",
    /^\/\/ WIRED\. server\.js requires computePeriodBounds and generateSelfReview from/m.test(head) &&
    NEW.indexOf('const { computePeriodBounds, generateSelfReview } = require("./lib/selfReview");') !== -1 &&
    (NEW.match(/await generateSelfReview\(\{/g) || []).length === 2 && NEW.indexOf('app.post("/api/self-reviews/run", requireAuth') !== -1 && /async function selfReviewTick\(\)/.test(NEW));

  /* ═══ U. the Plans tab and the agent page, in jsdom ══════════════════════ */
  console.log("\n== U. the Plans tab and the lessons, in jsdom ==");
  const { JSDOM } = realRequire("jsdom");
  const wait = async () => { for (let i = 0; i < 10; i++) await tick(); };
  function stepOf(a) {
    const d = a.latest_dispatch;
    if (!d) return { key: "ready" };
    if (d.outcome === "ran" && d.tool_task_status === "completed") return { key: "completed" };
    if (d.outcome === "ran" && !d.tool_task_status) return { key: "running" };
    return { key: d.outcome };
  }
  function mountCycles(opts) {
    const o = opts || {};
    const html = '<!doctype html><html><head></head><body><div id="hqPlans"></div><div id="deckCycles" role="region" aria-label="Plan cycles"></div></body></html>';
    const dom = new JSDOM(html, { runScripts: "outside-only", url: "https://bizforce.example/executive-agent.html", pretendToBeVisual: true });
    const w = dom.window;
    const calls = [];
    w.localStorage.setItem("bf_token", "t");
    const planRow = { id: P1, goal: "Grow the newsletter", assignments: o.assignments || [{ id: 1, latest_dispatch: { outcome: "ran", tool_task_status: "completed" } }, { id: 2, latest_dispatch: { outcome: "refused" } }] };
    w.BFHeadquarters = { view: { cc: { plans: { ok: true, data: [planRow] } }, planPick: P1 }, stepOf: stepOf, refresh() { calls.push({ url: "refresh", method: "-" }); } };
    const cycles = o.cycles || [];
    const drafted = Object.assign(PC.cycleOut(DRAFTED(C1, A, P1, { review_text: "Seven assignments ran.", next_plan_draft: "Run the SEO audit again." }), null));
    w.fetch = function (url, init) {
      const method = (init && init.method) || "GET";
      calls.push({ url: String(url), method: method, body: init && init.body });
      let body = {}, status = 200;
      if (/\/api\/executive\/cycles$/.test(url) && method === "GET") { if (o.failList) { status = 503; body = { error: "down" }; } else body = { copy: COPY, cycles: cycles }; }
      else if (/\/api\/executive\/cycles$/.test(url)) body = { cycle: PC.cycleOut(OPEN(C1, A, P1), null) };
      else if (/\/review$/.test(url)) body = { cycle: drafted, verifier: { kept: 1, dropped: 2 } };
      else if (/\/approve$/.test(url)) body = { cycle: Object.assign({}, drafted, { status: "approved", approved_at: ago(0) }) };
      else if (/\/discard$/.test(url)) body = { cycle: Object.assign({}, drafted, { status: "open", review_text: null, next_plan_draft: null }) };
      else if (/\/api\/executive\/cycles\/[^/]+$/.test(url) && method === "PUT") body = { cycle: Object.assign({}, drafted, JSON.parse(init.body)) };
      else if (/\/api\/agents\/executive\/plan$/.test(url)) body = { task_id: UUID(901), cycle: { linked: true } };
      const p = Promise.resolve({ status: status, ok: status < 400, json: () => Promise.resolve(body) });
      p.catch(() => {});
      return p;
    };
    w.eval(FILES.ui);
    return { dom, w, calls };
  }
  {
    const m = mountCycles({ assignments: [{ id: 1, latest_dispatch: { outcome: "ran", tool_task_status: "completed" } }, { id: 2, latest_dispatch: null }] });
    await wait();
    const btn = m.w.document.querySelector("[data-bfc-review]");
    check("U1. a plan with an assignment still waiting: \"Review this plan\" is shown disabled, with why", btn && btn.disabled && btn.textContent === "Review this plan" &&
      /once nothing in the plan is running or waiting/.test(m.w.document.getElementById("deckCycles").textContent));
    m.dom.window.close();
  }
  {
    const m = mountCycles();
    await wait();
    const doc = m.w.document;
    const btn = doc.querySelector('[data-bfc-review="' + P1 + '"]');
    check("U2. a finished plan (every assignment ran, failed or was refused): \"Review this plan\" is enabled", btn && !btn.disabled);
    m.calls.length = 0;
    btn.click(); await wait();
    const seq = m.calls.filter(c => c.url !== "refresh").map(c => c.method + " " + c.url.replace(/^https:\/\/[^/]+/, ""));
    check("U3. pressing it opens the cycle, then asks for the review; nothing else (no plan is started)",
      J(seq) === J(["POST /api/executive/cycles", "POST /api/executive/cycles/" + C1 + "/review"]) && JSON.parse(m.calls[0].body).plan_task_id === P1, J(seq));
    const rv = doc.getElementById("bfcReview"), nx = doc.getElementById("bfcNext");
    check("U4. the draft review and next plan are shown, read-only until Edit, with Approve and start, Edit and Discard",
      rv && nx && rv.value === "Seven assignments ran." && nx.value === "Run the SEO audit again." && rv.hasAttribute("readonly") &&
      doc.querySelector("[data-bfc-approve]").textContent === "Approve and start" && doc.querySelector("[data-bfc-edit]").textContent === "Edit" &&
      doc.querySelector("[data-bfc-discard]").textContent === "Discard");
    check("U5. it says how many sentences the verifier left out", /2 sentences were left out because a number in them is not in the measured results/.test(doc.getElementById("deckCycles").textContent));
    doc.querySelector("[data-bfc-edit]").click(); await wait();
    check("U6. Edit makes both editable and becomes Save edits", !doc.getElementById("bfcReview").hasAttribute("readonly") && doc.querySelector("[data-bfc-edit]").textContent === "Save edits");
    doc.getElementById("bfcNext").value = "Run the audit, then write one post.";
    m.calls.length = 0;
    doc.querySelector("[data-bfc-edit]").click(); await wait();
    const put = m.calls.filter(c => c.method === "PUT");
    check("U7. Save edits sends one PUT with the two texts", put.length === 1 && J(JSON.parse(put[0].body)) === J({ review_text: "Seven assignments ran.", next_plan_draft: "Run the audit, then write one post." }), J(put));
    m.calls.length = 0;
    doc.querySelector("[data-bfc-approve]").click(); await wait();
    const seq2 = m.calls.filter(c => c.url !== "refresh").map(c => c.method + " " + c.url.replace(/^https:\/\/[^/]+/, "").replace(/\?.*$/, ""));
    const planCall = m.calls.filter(c => /\/api\/agents\/executive\/plan$/.test(c.url))[0];
    check("U8. Approve and start: approve first, then the plan route with the cycle's id (and the board refreshes)",
      seq2[0] === "POST /api/executive/cycles/" + C1 + "/approve" && seq2[1] === "POST /api/agents/executive/plan" && planCall && JSON.parse(planCall.body).cycle_id === C1 &&
      m.calls.some(c => c.url === "refresh"), J(seq2));
    m.dom.window.close();
  }
  {
    const m = mountCycles({ cycles: [PC.cycleOut(DRAFTED(C1, A, P1), null)] });
    await wait();
    m.calls.length = 0;
    m.w.document.querySelector("[data-bfc-discard]").click(); await wait();
    check("U9. Discard posts discard and starts nothing", m.calls.length === 1 && /\/discard$/.test(m.calls[0].url) && m.calls[0].method === "POST");
    m.dom.window.close();
  }
  {
    const prev = OPEN(UUID(671), A, UUID(185), { status: "approved", measured: { totals: Object.assign({}, WANT_TOTALS, { dispatches_ran: 2 }), unreadable: [] },
      review_text: "The first review.", next_plan_draft: "Grow the newsletter", next_plan_task_id: P1, approved_at: ago(2 * D), created_at: ago(3 * D) });
    const cur = OPEN(UUID(672), A, P1, { previous_cycle_id: UUID(671), status: "approved", measured: { totals: Object.assign({}, WANT_TOTALS, { arrivals: null }),
      unreadable: [{ field: "arrivals", reason: "the arrivals on your tracked links could not be read" }] }, review_text: "The second review.", next_plan_draft: "Write two posts.", approved_at: ago(H), created_at: ago(H) });
    const m = mountCycles({ cycles: [PC.cycleOut(cur, prev), PC.cycleOut(prev, null)] });
    await wait();
    const doc = m.w.document;
    const items = Array.from(doc.querySelectorAll("[data-bfc-cycle]"));
    const first = items[0];
    check("U10. the Cycles history lists each cycle with its measured results against the one before",
      items.length === 2 && first.querySelector('[data-bfc-key="dispatches_ran"]').textContent === "Assignments run: 7 ↑ (was 2)" &&
      first.querySelector('[data-bfc-key="arrivals"]').textContent === "Arrivals on your tracked links: could not be read" &&
      /Could not be read, and not counted as zero: arrivals/.test(first.textContent), first && first.textContent);
    check("U11. ... the review text and the approved plan", /Review: The second review\./.test(first.textContent) && /Approved plan: Write two posts\./.test(first.textContent) &&
      /The first cycle: there is no earlier cycle to compare with/.test(items[1].textContent));
    check("U12. the fixed line is on the plan's view and on every cycle in the history",
      doc.querySelector("[data-bfc-plan] .bfc-copy").textContent === COPY && items.every(li => li.querySelector(".bfc-copy").textContent === COPY));
    m.dom.window.close();
  }
  {
    const m = mountCycles({ failList: true });
    await wait();
    const t = m.w.document.getElementById("deckCycles").textContent;
    check("U13. a history that cannot be read says so, never \"No cycles yet\"", /Your cycles could not be read/.test(t) && !/No cycles yet/.test(t));
    m.dom.window.close();
  }
  check("U14. HQ's Plans tab mounts it under the board and loads the script", FILES.execHtml.indexOf('<div id="hqPlans" role="region" aria-labelledby="hqPlansTitle"></div>\n          <div id="deckCycles" role="region" aria-label="Plan cycles"></div>') !== -1 &&
    FILES.execHtml.indexOf('<script src="/scripts/bf-network.js"></script>\n<script src="/scripts/bf-cycles.js"></script>') !== -1);
  check("U15. the guide's executive entry names \"Review this plan\"", FILES.guide.indexOf('\\"Review this plan\\" starts nothing until you approve.') !== -1);
  {
    const LEARN_BODY = { agent_type: "email", copy: LEARNING.HONEST_COPY, score: LEARNING.scoreFrom([], FIXED), outcomes: null, examples: [], preferences: [], suggestions: [],
      lessons: WANT_LESSONS.content, lessons_from: { period_start: "2026-10-19T00:00:00.000Z", period_end: "2026-10-26T00:00:00.000Z" }, guidance: "", limits: { preferences: 8 } };
    async function page(body) {
      const dom = new JSDOM('<!doctype html><html><head></head><body><div class="page"></div></body></html>', { url: "https://bizforceai.net/email-agent.html", runScripts: "outside-only" });
      const w = dom.window; const calls = [];
      w.localStorage.setItem("bf_token", "tok");
      w.fetch = function (u, init) {
        calls.push({ url: String(u), method: (init && init.method) || "GET", body: init && init.body });
        const b = /\/learning$/.test(String(u)) ? body : {};
        const p = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(b) }); p.catch(() => {}); return p;
      };
      w.AGENT_PROFILE_CONFIG = { agentType: "email", agentLabel: "Email Agent", taskTypes: [{ value: "general", label: "General" }] };
      w.eval(FILES.profile);
      for (let i = 0; i < 20; i++) await new Promise(res => setTimeout(res, 0));
      return { dom, w, calls };
    }
    const p = await page(LEARN_BODY);
    const box = p.w.document.getElementById("apLearnLessons");
    check("U16. the agent's panel offers its lessons, with where they come from, and posts nothing by showing them",
      box && /Lessons from your weekly review/.test(box.textContent) && box.querySelectorAll("[data-accept-lesson]").length === 2 &&
      box.textContent.indexOf(WANT_LESSONS.content[0].text) !== -1 && /Nothing is saved unless you add it/.test(box.textContent) &&
      !p.calls.some(c => c.method === "POST"), box && box.textContent);
    p.calls.length = 0;
    box.querySelector('[data-accept-lesson="' + WANT_LESSONS.content[1].text + '"]').click();
    await new Promise(res => setTimeout(res, 0));
    const posted = p.calls.filter(c => c.method === "POST" && /\/preferences$/.test(c.url));
    check("U17. Add it posts that lesson once, with source \"lesson\"", posted.length === 1 && J(JSON.parse(posted[0].body)) === J({ text: WANT_LESSONS.content[1].text, source: "lesson" }));
    p.dom.window.close();
    const q = await page(Object.assign({}, LEARN_BODY, { lessons: null }));
    const qb = q.w.document.getElementById("apLearnLessons");
    check("U18. lessons that could not be read say so; none offered shows nothing", qb && /could not be read/.test(qb.textContent) && !qb.querySelector("[data-accept-lesson]"));
    q.dom.window.close();
    const r = await page(Object.assign({}, LEARN_BODY, { lessons: [] }));
    check("U19. ... and with no lessons the section is empty", r.w.document.getElementById("apLearnLessons").textContent === "");
    r.dom.window.close();
  }

  /* ═══ S. no emoji ════════════════════════════════════════════════════════ */
  console.log("\n== S. no emoji ==");
  const BS = String.fromCharCode(92);
  const ESCAPED = ["&#" + "x1F", BS + "u{1F", BS + "uD83", BS + "uFE0F"];
  function hasEmoji(text) {
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if ((cp >= 0x1F000 && cp <= 0x1FAFF) || (cp >= 0x2600 && cp <= 0x27BF) || cp === 0xFE0F || cp === 0x200D) return true;
    }
    return ESCAPED.some(e => text.indexOf(e) !== -1);
  }
  // The three long-lived frontend files hold older check marks that checkNoEmoji allows; only the lines this work added are scanned there.
  const added = (file, now) => {
    const old = new Set(execFileSync("git", ["show", PRE_FRONTEND + ":" + file], { cwd: FRONTEND, maxBuffer: 16 << 20 }).toString("utf8").replace(/\r\n/g, "\n").split("\n"));
    return now.split("\n").filter(l => !old.has(l)).join("\n");
  };
  const scanned = [["lib/planCycle.js", FILES.lib], ["lib/lessons.js", FILES.lessons], ["lib/selfReview.js", FILES.selfReview], ["migration 162", FILES.migration],
    ["bf-cycles.js", FILES.ui], ["agent-profile.js (added lines)", added("scripts/agent-profile.js", FILES.profile)],
    ["executive-agent.html (added lines)", added("executive-agent.html", FILES.execHtml)], ["termaximus-guide.js (added lines)", added("scripts/termaximus-guide.js", FILES.guide)],
    ["this check", fs.readFileSync(__filename, "utf8")]];
  check("S0. the added lines were found (the new lessons section, the cycles mount, the new tip)", /function lessonsHtml/.test(scanned[5][1]) && /deckCycles/.test(scanned[6][1]) && /Review this plan/.test(scanned[7][1]));
  const withEmoji = scanned.filter(s => hasEmoji(s[1])).map(s => s[0]);
  check("S1. no emoji in any new or edited file (by code point)", withEmoji.length === 0, withEmoji.join(", "));
  check("S2. nothing in this run reached the network or an unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(e => e && e.message).join(" | "));
  } catch (e) {
    failures++;
    console.log("    FAIL  the check threw: " + (e && e.stack || e));
  }
  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED — " + passes + " passed, 0 failed" : failures + " FAILED, " + passes + " passed"));
  process.exit(failures === 0 ? 0 : 1);
})();
