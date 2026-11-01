/* ═══════════════════════════════════════════════════════════════════════════
   checkGates.js — one gate evaluator, one record per decision, and every
   refusal byte-identical to what it was before (intelligence layer B1).

   WHAT THIS PROVES

     A. THE REGISTRY. Every gate in the design report's section 1.1 inventory,
        G1 to G25, is registered under its id with a name, a kind and an effect.
        The B1 set (G1, G2, G9 to G12, G19, G20) is exactly the gates marked b1.
        Every action's gate list names registered gates only.
     B. THE EVALUATOR. lib/gates.js evaluate() stops at the first fail and marks
        every later gate not_reached; a gate nothing was observed for is
        not_reached; a bypass stays a bypass; G2's fail holds for approval
        (held_for_approval) where every other fail blocks. It is pure: it runs in
        an empty vm context with no require, no process and no console.
     C. OLD VS NEW, BY OUTPUT. Each adapted function is lifted twice, from
        server.js at PRE_GATES (73a149a, the commit before B1) and from today's
        server.js, and both are driven through the same fake database with the
        same inputs. For every failing condition and every passing path, the
        status, body, headers, thrown error (class, message, code, status and
        every own property), logs and database writes (gate_decisions aside)
        are identical:
          C1  model calls: G9, G11 and G10 (enforceDailyModelCallLimit)
          C2  route entitlement: G12 (requireActiveSubscription)
          C3  proposal approval: G3 and G1 (POST /api/proposals/:id/approve)
          C4  the high-risk task hold: G2 (handleAiTaskRequest)
          C5  chain dispatch: G19, and G12 inside it (dispatchToolCall)
          C6  marketing email: G20 (sendMarketingEmail)
     D. ONE RECORD PER DECISION. In every run of C, exactly one gate_decisions
        row is written when there is a member to file it under (none without),
        with the deciding member's user_id, the action, a clean target, the
        expected outcome and the expected compact results.
     E. THE OWNER PASS. The owner's model calls record G9 as bypass (owner_pass),
        never pass; the owner's and an admin's routes record G12 as bypass.
     F. A FAILED RECORD WRITE NEVER CHANGES THE DECISION. With the insert
        answering an error, rejecting, throwing synchronously, or lib/gates.js
        not loadable, every path answers exactly what PRE_GATES answered, and
        "[gates] record not written" is logged.
     G. EXPORT AND DELETION. gate_decisions is in lib/yourData.js DATA (group
        agents, owner user_id, onDelete delete) and DELETE_ORDER; the foreign
        key cascades; lib/backup.js names it. (checkYourData proves DATA end to
        end.)
     H. NO MEMBER READS ANOTHER'S DECISIONS. Migration 158 enables row level
        security and creates no policy and no grant; server.js never reads the
        table; two members deciding in turn each get a row under their own id.
     I. THE MIGRATION. 158_gate_decisions.sql has the columns, the closed action
        and outcome lists (equal to lib/gates.js), both indexes, and says that
        retention is 90 days with the sweep in B2.

   MUTATIONS — MUTATE=<name> applies one in memory; MUTATE=all runs each:
     refusal-message-changed     the approve route's 409 message changes   → C3
     record-missing-no-executor  the 501 path writes no record              → D
     evaluate-continues          evaluate() keeps going after a fail         → B, D
     record-failure-flips        a failed record write refuses the call     → F
     owner-bypass-as-pass        the owner's G9 is recorded as pass         → E, D
     route-bypass-as-pass        the owner's G12 is recorded as pass        → E, D
     unobserved-as-pass          an unobserved gate is recorded as pass     → B, D
     held-as-blocked             G2's hold is recorded as blocked           → B, D
     dispatch-entitlement-misfiled  not_entitled is filed under G19         → D
     target-unclean              a target is stored unchecked               → D
     record-user-swapped         the record is filed under the owner        → H, D

   Usage: node scripts/checkGates.js   (no database, no network)
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { execFileSync } = require("child_process");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const PRE_GATES = "73a149a";

const MUTATIONS = {
  "refusal-message-changed": ["server",
    "{ G3: approveG3, G1: { result: \"fail\", code: \"not_pending\" } });\n      return res.status(409).json({ error: \"Proposal not found or no longer pending\" });",
    "{ G3: approveG3, G1: { result: \"fail\", code: \"not_pending\" } });\n      return res.status(409).json({ error: \"Proposal not found\" });"],
  "record-missing-no-executor": ["server",
    "      recordGateDecision(req.user.id, \"proposal_approve\", \"proposal:\" + req.params.id, { G3: approveG3, G1: { result: \"fail\", code: \"no_executor\" } });\n", ""],
  "evaluate-continues": ["gates",
    "    if (stopped) return { gate: id, result: \"not_reached\", code: null, reason: reasonFor(\"not_reached\", null) };\n", ""],
  "record-failure-flips": ["server",
    "  recordGateDecision(userId, \"model_call\", modelCallTarget, modelCallGateObservations(userId, null));\n  return allowed;",
    "  if (!(await recordGateDecision(userId, \"model_call\", modelCallTarget, modelCallGateObservations(userId, null)))) throw unreadableModelCallLimitError(\"record\");\n  return allowed;"],
  "owner-bypass-as-pass": ["server",
    "var platform = isOwnerAccount(userId) ? { result: \"bypass\", code: \"owner_pass\" }",
    "var platform = isOwnerAccount(userId) ? { result: \"pass\", code: \"owner_pass\" }"],
  "route-bypass-as-pass": ["server",
    "if (planState && planState.access_reason === \"owner\") return { result: \"bypass\", code: \"owner_pass\" };",
    "if (planState && planState.access_reason === \"owner\") return { result: \"pass\", code: \"owner_pass\" };"],
  "unobserved-as-pass": ["gates",
    "seen.result : \"not_reached\";", "seen.result : \"pass\";"],
  "held-as-blocked": ["gates",
    "outcome = stopped.effect === \"require_approval\" ? \"held_for_approval\" : \"blocked\";", "outcome = \"blocked\";"],
  "dispatch-entitlement-misfiled": ["server",
    "    return { G19: { result: \"pass\" }, G12: { result: \"fail\", code: refusedReason } };",
    "    return { G19: { result: \"fail\", code: refusedReason } };"],
  "target-unclean": ["server",
    "      target: gateLib.cleanTarget(target),", "      target: String(target),"],
  "record-user-swapped": ["server",
    "      user_id: userId,\n      action: action,", "      user_id: OWNER_ACCOUNT_ID,\n      action: action,"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
process.on("unhandledRejection", function (e) { check("no unhandled rejection", false, (e && e.stack) || e); });

const read = p => fs.readFileSync(path.join(REPO, p), "utf8").replace(/\r\n/g, "\n");
const FILES = {
  server: read("server.js"),
  gates: read("lib/gates.js"),
  migration: read("supabase/migrations/158_gate_decisions.sql"),
  backup: read("lib/backup.js")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}
const OLD = execFileSync("git", ["show", PRE_GATES + ":server.js"], { cwd: REPO, maxBuffer: 64 << 20 }).toString("utf8").replace(/\r\n/g, "\n");
const NEW = FILES.server;

/* lib/gates.js, compiled from FILES.gates in an EMPTY context: no require, no
   process, no console. That it loads and evaluates there is the purity proof. */
function loadGates(src) {
  const sandbox = {};
  vm.createContext(sandbox);
  const fn = vm.runInContext("(function (module, exports) {\n" + src + "\n})", sandbox);
  const m = { exports: {} };
  fn(m, m.exports);
  return m.exports;
}
const GATES = loadGates(FILES.gates);
const OWNER_ID = require(path.join(REPO, "lib/ownerAccount")).OWNER_ACCOUNT_ID;
const MEMBER = "a0000000-0000-4000-8000-0000000000aa";
const MEMBER_B = "b0000000-0000-4000-8000-0000000000bb";

/* ── lifting: a one-pass index of top-level definitions, then a closure ──── */
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
  "Array", "Promise", "Error", "app", "setImmediate", "setTimeout", "OWNER_ACCOUNT_ID", "isTestAccount", "requireAuth", "opsAlerts", "AsyncLocalStorage"];
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
  // In source order, so a const is defined before the consts that read it.
  return [...have.keys()].sort((a, b) => defs.pos.get(a) - defs.pos.get(b)).map(k => have.get(k)).join("\n\n") + "\n\n" + rootCode;
}
function routeSource(which, sig) {
  const src = SRC[which]; const start = src.indexOf(sig);
  if (start < 0) throw new Error("route not found in " + which + ": " + sig);
  const end = braceMatch(src, src.indexOf("{", start));
  return src.slice(start, end) + ");";
}
const SCRIPTS = new Map();
function script(which, key, rootCode, stubs, exportsExpr) {
  const k = which + "|" + key;
  if (!SCRIPTS.has(k)) SCRIPTS.set(k, new vm.Script(closure(which, rootCode, stubs) + "\n;this.__api = { " + exportsExpr + " };", { filename: which + "-" + key + ".js" }));
  return SCRIPTS.get(k);
}

/* ── the fake database: one scripted responder, every write recorded ─────── */
function fakeDb(respond, gateWrite) {
  const writes = [], gateRows = [];
  function from(table) {
    if (table === "gate_decisions" && gateWrite === "throw") {
      return { insert() { throw new Error("insert threw synchronously"); } };
    }
    const q = { table: table, op: "select", filters: [], cols: null, opts: null, payload: null, shape: null, range: null };
    let ran = null;
    function run() {
      if (ran) return ran;
      if (q.op !== "select") {
        if (table === "gate_decisions") gateRows.push(JSON.parse(JSON.stringify(q.payload)));
        else writes.push({ table: table, op: q.op, payload: JSON.parse(JSON.stringify(q.payload || null)), filters: q.filters.slice() });
      }
      if (table === "gate_decisions") {
        if (gateWrite === "error") ran = Promise.resolve({ data: null, error: { message: "relation \"public.gate_decisions\" does not exist" } });
        else if (gateWrite === "reject") ran = Promise.reject(new Error("network down"));
        else ran = Promise.resolve({ data: null, error: null });
        return ran;
      }
      ran = Promise.resolve().then(() => respond(q)).then(r => r || defaultResult(q));
      return ran;
    }
    const b = {
      select(cols, opts) { if (q.op === "select") { q.cols = cols; q.opts = opts || null; } return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      upsert(p) { q.op = "upsert"; q.payload = p; return b; },
      delete() { q.op = "delete"; return b; }
    };
    ["eq", "neq", "in", "gte", "lte", "gt", "lt", "like", "ilike", "is", "not", "or", "contains"].forEach(f => {
      b[f] = function (c, v) { q.filters.push([f, c, v]); return b; };
    });
    b.order = function () { return b; };
    b.limit = function (n) { q.limit = n; return b; };
    b.range = function (a, z) { q.range = [a, z]; return b; };
    b.maybeSingle = function () { q.shape = "maybeSingle"; return run(); };
    b.single = function () { q.shape = "single"; return run(); };
    b.then = function (res, rej) { return run().then(res, rej); };
    return b;
  }
  return { client: { from: from }, writes: writes, gateRows: gateRows };
}
function defaultResult(q) {
  if (q.op !== "select") return { data: q.shape ? q.payload : [q.payload], error: null };
  if (q.opts && q.opts.head) return { data: null, count: 0, error: null };
  if (q.shape) return { data: null, error: null };
  return { data: [], count: 0, error: null };
}
const has = (q, f, c, v) => q.filters.some(x => x[0] === f && x[1] === c && (v === undefined || x[2] === v));

/* ── contexts ─────────────────────────────────────────────────────────────── */
const FIXED = Date.parse("2026-10-15T15:30:00.000Z");
class FixedDate extends Date {
  constructor(...a) { if (a.length === 0) super(FIXED); else super(...a); }
  static now() { return FIXED; }
}
function makeCtx(o) {
  const logs = [];
  const db = fakeDb(o.respond || (() => null), o.gateWrite || "ok");
  const line = k => function () { logs.push(k + " " + Array.prototype.map.call(arguments, a => (a && a.message) ? a.message : String(a)).join(" ")); };
  const sandbox = Object.assign({
    supabase: db.client,
    console: { log: line("log"), warn: line("warn"), error: line("error"), info: line("info") },
    process: { env: Object.assign({}, o.env || {}) },
    require: function (p) {
      if (p === "./lib/gates") {
        if (o.gateWrite === "nolib") throw new Error("Cannot find module './lib/gates'");
        return GATES;
      }
      if (p === "./lib/legal" && o.legal) return o.legal;
      if (p.indexOf("./") === 0) return require(path.join(REPO, p));
      return require(p);
    },
    OWNER_ACCOUNT_ID: OWNER_ID,
    isTestAccount: () => false,
    nowIso: () => new FixedDate().toISOString(),
    Date: FixedDate,
    setImmediate: setImmediate, setTimeout: setTimeout, clearTimeout: clearTimeout, Buffer: Buffer, URL: URL,
    AsyncLocalStorage: require("async_hooks").AsyncLocalStorage
  }, o.globals || {});
  vm.createContext(sandbox);
  return { sandbox: sandbox, logs: logs, db: db };
}
const tick = () => new Promise(r => setImmediate(r));
async function settle() { for (let i = 0; i < 4; i++) await tick(); }

function errShape(e) {
  if (e === null || (typeof e !== "object" && typeof e !== "function")) return { thrown: String(e) };
  const o = { thrown: true, ctor: e.constructor && e.constructor.name, message: e.message };
  Object.keys(e).sort().forEach(k => { o["own:" + k] = e[k]; });
  return o;
}
async function capture(fn) {
  try { return { returned: await fn() }; } catch (e) { return errShape(e); }
}
function makeRes() {
  return {
    statusCode: 200, body: undefined, headers: {}, sent: 0,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(JSON.stringify(b === undefined ? null : b)); this.sent++; return this; },
    send(b) { this.body = b; this.sent++; return this; },
    set(k, v) { this.headers[String(k).toLowerCase()] = v; return this; },
    setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
    header(k, v) { this.headers[String(k).toLowerCase()] = v; return this; }
  };
}
const resShape = r => ({ status: r.statusCode, body: r.body, headers: r.headers, sent: r.sent });
const J = x => JSON.stringify(x);
const notGates = logs => logs.filter(l => l.indexOf("[gates]") === -1);

/* Compares one scenario's PRE_GATES and today's runs, and checks its record. */
function compare(section, label, oldRun, newRun, expect) {
  const o = { out: oldRun.out, logs: oldRun.logs, writes: oldRun.writes, extra: oldRun.extra };
  const n = { out: newRun.out, logs: notGates(newRun.logs), writes: newRun.writes, extra: newRun.extra };
  check(section + " " + label + ": identical to " + PRE_GATES, J(o) === J(n), "old " + J(o).slice(0, 600) + " | new " + J(n).slice(0, 600));
  if (expect === undefined) return;
  const rows = newRun.gateRows;
  if (expect === null) {
    check("D " + label + ": no member, so no record", rows.length === 0, J(rows));
    return;
  }
  check("D " + label + ": exactly one record", rows.length === 1, rows.length + " " + J(rows));
  const row = rows[0] || {};
  const want = { user_id: expect.user, action: expect.action, target: expect.target, outcome: expect.outcome,
    results: expect.results.map(r => Object.assign({ gate: r[0], result: r[1] }, r[2] ? { code: r[2] } : {})) };
  const got = { user_id: row.user_id, action: row.action, target: row.target, outcome: row.outcome, results: row.results };
  check("D " + label + ": the record is " + expect.outcome + " " + J(want.results), J(got) === J(want), "got " + J(got) + " want " + J(want));
  check("D " + label + ": nothing logged as unwritten", newRun.logs.every(l => l.indexOf("[gates]") === -1), J(newRun.logs.filter(l => l.indexOf("[gates]") !== -1)));
}

(async function main() {
  /* ═══ A. the registry ═══════════════════════════════════════════════════ */
  console.log("\n══ A. every inventory gate is registered ══");
  const ids = GATES.GATES.map(g => g.id);
  const want = []; for (let i = 1; i <= 25; i++) want.push("G" + i);
  check("A1. G1 to G25 are registered, in order, each once", J(ids) === J(want), J(ids));
  check("A2. each gate has a name, a kind and an effect", GATES.GATES.every(g => typeof g.name === "string" && g.name.length > 2 &&
    ["platform", "pass"].indexOf(g.kind) !== -1 && ["block", "require_approval", "bypass"].indexOf(g.effect) !== -1));
  check("A3. the B1 adapters are G1, G2, G9, G10, G11, G12, G19, G20", J(GATES.GATES.filter(g => g.b1).map(g => g.id)) === J(["G1", "G2", "G9", "G10", "G11", "G12", "G19", "G20"]));
  check("A4. G2 holds for approval, G15 is the owner pass, every other gate blocks",
    GATES.GATES.every(g => g.effect === (g.id === "G2" ? "require_approval" : g.id === "G15" ? "bypass" : "block")));
  check("A5. every action's gates are registered", Object.keys(GATES.ACTION_GATES).every(a => GATES.ACTIONS.indexOf(a) !== -1 && GATES.ACTION_GATES[a].every(GATES.isGate)));
  check("A6. the model-call order is G9, G11, G10", J(GATES.ACTION_GATES.model_call) === J(["G9", "G11", "G10"]));
  check("A7. the registry is frozen", Object.isFrozen(GATES.GATES) && GATES.GATES.every(Object.isFrozen) && Object.isFrozen(GATES.REASONS));
  check("A8. no reason sentence is empty or carries a placeholder", Object.keys(GATES.REASONS).every(k => /^[A-Z].{8,}\.$/.test(GATES.REASONS[k]) && !/[{}$<>]/.test(GATES.REASONS[k])));

  /* ═══ B. the evaluator ══════════════════════════════════════════════════ */
  console.log("\n══ B. evaluate(): first fail ends it, bypass stays bypass, pure ══");
  const ev = (a, obs, g) => GATES.evaluate(a, { observed: obs }, g);
  const short = d => d.outcome + " " + d.results.map(r => r.gate + ":" + r.result + (r.code ? "/" + r.code : "")).join(",");
  let d = ev("model_call", { G9: { result: "fail", code: "PLATFORM_DAILY_SPEND_LIMIT" }, G11: { result: "pass" }, G10: { result: "pass" } });
  check("B1. after G9 fails, G11 and G10 are not_reached whatever was observed", short(d) === "blocked G9:fail/PLATFORM_DAILY_SPEND_LIMIT,G11:not_reached,G10:not_reached", short(d));
  d = ev("model_call", { G9: { result: "pass" }, G11: { result: "fail", code: "DAILY_MODEL_CALL_LIMIT" }, G10: { result: "fail", code: "MONTHLY_MODEL_SPEND_LIMIT" } });
  check("B2. only the first fail is a fail", short(d) === "blocked G9:pass,G11:fail/DAILY_MODEL_CALL_LIMIT,G10:not_reached", short(d));
  d = ev("model_call", { G9: { result: "bypass", code: "owner_pass" }, G11: { result: "pass" }, G10: { result: "pass" } });
  check("B3. the owner pass is a bypass and the action ran", short(d) === "ran G9:bypass/owner_pass,G11:pass,G10:pass", short(d));
  d = ev("model_call", { G11: { result: "fail", code: "DAILY_MODEL_CALL_LIMIT_MISCONFIGURED" } });
  check("B4. a gate nothing was observed for is not_reached", short(d) === "blocked G9:not_reached,G11:fail/DAILY_MODEL_CALL_LIMIT_MISCONFIGURED,G10:not_reached", short(d));
  d = ev("task_run", { G2: { result: "fail", code: "high_risk" } });
  check("B5. G2's fail holds for approval", short(d) === "held_for_approval G2:fail/high_risk", short(d));
  d = ev("dispatch", { G19: { result: "pass" }, G12: { result: "pass" } });
  check("B6. every gate passing is ran", short(d) === "ran G19:pass,G12:pass", short(d));
  d = ev("marketing_email", { G20: { result: "fail", code: "suppressed to someone@example.com" } });
  check("B7. a code that is not a short token is dropped, never stored", d.results[0].code === null && d.results[0].reason === GATES.reasonFor("fail", null), J(d.results[0]));
  check("B8. each result carries the fixed sentence for its code", ev("marketing_email", { G20: { result: "fail", code: "cap_reached" } }).results[0].reason === GATES.REASONS.cap_reached);
  let threw = false; try { ev("launch_rocket", {}); } catch (e) { threw = true; }
  check("B9. an action outside the closed list is refused", threw);
  threw = false; try { ev("dispatch", {}, ["G99"]); } catch (e) { threw = true; }
  check("B10. a gate outside the registry is refused", threw);
  const again = ev("model_call", { G9: { result: "pass" }, G11: { result: "pass" }, G10: { result: "fail", code: "MONTHLY_MODEL_SPEND_LIMIT" } });
  check("B11. pure: the same input gives the same output", J(again) === J(ev("model_call", { G9: { result: "pass" }, G11: { result: "pass" }, G10: { result: "fail", code: "MONTHLY_MODEL_SPEND_LIMIT" } })));
  check("B12. pure: lib/gates.js names no require, process, console, supabase, fetch or clock",
    !/\brequire\(|\bprocess\.|\bconsole\.|supabase|\bfetch\(|Date\.now|new Date/.test(FILES.gates.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "")));
  check("B13. toRecord keeps gate, result and code only", J(GATES.toRecord(again)) === J([{ gate: "G9", result: "pass" }, { gate: "G11", result: "pass" }, { gate: "G10", result: "fail", code: "MONTHLY_MODEL_SPEND_LIMIT" }]));
  check("B14. cleanTarget keeps a kind and an id, and cuts anything else to its kind",
    GATES.cleanTarget("proposal:3f1c") === "proposal:3f1c" && GATES.cleanTarget("route:post /api/x/:id") === "route:post /api/x/:id" &&
    GATES.cleanTarget("contact:<b>x@y.z</b>") === "contact" && GATES.cleanTarget("") === "unknown");

  /* ═══ C1. model calls ════════════════════════════════════════════════════ */
  console.log("\n══ C1. model calls: G9, G11, G10 — old vs new ══");
  const priced = Object.keys(vm.runInNewContext("(" + DEFS.new.get("MODEL_PRICES_USD_PER_MILLION").replace(/^(var|const|let) MODEL_PRICES_USD_PER_MILLION\s*=\s*/, "").replace(/;\s*$/, "") + ")"))[0];
  const prices = vm.runInNewContext("(" + DEFS.new.get("MODEL_PRICES_USD_PER_MILLION").replace(/^(var|const|let) MODEL_PRICES_USD_PER_MILLION\s*=\s*/, "").replace(/;\s*$/, "") + ")");
  const perUsd = 1e6 / prices[priced].output;   // output tokens that cost $1
  const spendRows = (usd, user) => usd ? [{ id: 1, user_id: user || "someone", model: priced, input_tokens: 0, output_tokens: Math.round(usd * perUsd), funded_by: "platform" }] : [];
  function modelResponder(s) {
    return function (q) {
      if (q.table === "users") return { data: [], error: null };
      if (q.table !== "model_calls") return null;
      if (q.opts && q.opts.head) {
        if (s.countThrows) throw new Error("socket hang up");
        if (s.countError) return { data: null, count: null, error: { message: "count timed out" } };
        return { data: null, count: s.used || 0, error: null };
      }
      if (has(q, "eq", "user_id")) {
        if (s.monthError) return { data: null, count: null, error: { message: "month read failed" } };
        const rows = spendRows(s.month || 0, q.filters[0][2]); return { data: rows, count: rows.length, error: null };
      }
      if (s.platformError) return { data: null, count: null, error: { message: "platform read failed" } };
      const rows = spendRows(s.platform || 0); return { data: rows, count: rows.length, error: null };
    };
  }
  async function modelRun(which, s, gateWrite) {
    const c = makeCtx({ respond: modelResponder(s), env: s.env, gateWrite: gateWrite });
    script(which, "model", DEFS[which].get("enforceDailyModelCallLimit"), [], "enforceDailyModelCallLimit, PLATFORM_SPEND_STATE").runInContext(c.sandbox);
    const out = await capture(() => c.sandbox.__api.enforceDailyModelCallLimit(s.user, "business-chat"));
    await settle();
    return { out: out, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows };
  }
  const MC = [
    { label: "a member's call within every limit", s: { user: MEMBER, used: 3, month: 1 }, rec: ["ran", [["G9", "pass"], ["G11", "pass"], ["G10", "pass"]]] },
    { label: "the owner's call", s: { user: OWNER_ID, used: 3, month: 1 }, rec: ["ran", [["G9", "bypass", "owner_pass"], ["G11", "pass"], ["G10", "pass"]]], owner: true },
    { label: "the daily limit misconfigured (503)", s: { user: MEMBER, env: { MODEL_CALLS_DAILY_LIMIT_PER_USER: "lots" } },
      rec: ["blocked", [["G9", "not_reached"], ["G11", "fail", "DAILY_MODEL_CALL_LIMIT_MISCONFIGURED"], ["G10", "not_reached"]]] },
    { label: "the platform ceiling misconfigured, a member (503)", s: { user: MEMBER, env: { PLATFORM_DAILY_SPEND_CAP_USD: "none" } },
      rec: ["blocked", [["G9", "fail", "PLATFORM_DAILY_SPEND_LIMIT_MISCONFIGURED"], ["G11", "not_reached"], ["G10", "not_reached"]]] },
    { label: "the platform ceiling misconfigured, the owner", s: { user: OWNER_ID, env: { PLATFORM_DAILY_SPEND_CAP_USD: "none" } },
      rec: ["ran", [["G9", "bypass", "owner_pass"], ["G11", "pass"], ["G10", "pass"]]], owner: true },
    { label: "platform spend unreadable, a member (503)", s: { user: MEMBER, platformError: true },
      rec: ["blocked", [["G9", "fail", "PLATFORM_SPEND_UNREADABLE"], ["G11", "not_reached"], ["G10", "not_reached"]]] },
    { label: "platform spend unreadable, the owner", s: { user: OWNER_ID, platformError: true },
      rec: ["ran", [["G9", "bypass", "owner_pass"], ["G11", "pass"], ["G10", "pass"]]], owner: true },
    { label: "the platform ceiling reached, a member (429)", s: { user: MEMBER, platform: 30 },
      rec: ["blocked", [["G9", "fail", "PLATFORM_DAILY_SPEND_LIMIT"], ["G11", "not_reached"], ["G10", "not_reached"]]] },
    { label: "the platform ceiling reached, the owner", s: { user: OWNER_ID, platform: 30 },
      rec: ["ran", [["G9", "bypass", "owner_pass"], ["G11", "pass"], ["G10", "pass"]]], owner: true },
    { label: "the daily call limit reached (429)", s: { user: MEMBER, used: 250 },
      rec: ["blocked", [["G9", "pass"], ["G11", "fail", "DAILY_MODEL_CALL_LIMIT"], ["G10", "not_reached"]]] },
    { label: "the call count unreadable (fails open)", s: { user: MEMBER, countError: true, month: 1 }, rec: ["ran", [["G9", "pass"], ["G11", "pass"], ["G10", "pass"]]] },
    { label: "the call count throwing (fails open)", s: { user: MEMBER, countThrows: true, month: 1 }, rec: ["ran", [["G9", "pass"], ["G11", "pass"], ["G10", "pass"]]] },
    { label: "the monthly spend limit reached (429)", s: { user: MEMBER, used: 3, month: 61 },
      rec: ["blocked", [["G9", "pass"], ["G11", "pass"], ["G10", "fail", "MONTHLY_MODEL_SPEND_LIMIT"]]] },
    { label: "the monthly limit misconfigured (503)", s: { user: MEMBER, used: 3, env: { MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER: "x" } },
      rec: ["blocked", [["G9", "pass"], ["G11", "pass"], ["G10", "fail", "MONTHLY_MODEL_SPEND_LIMIT_MISCONFIGURED"]]] },
    { label: "the monthly spend unreadable (fails open)", s: { user: MEMBER, used: 3, monthError: true }, rec: ["ran", [["G9", "pass"], ["G11", "pass"], ["G10", "pass"]]] },
    { label: "no user id (uncapped, logged)", s: { user: null }, rec: null }
  ];
  const statuses = new Set();
  for (const t of MC) {
    const o = await modelRun("old", t.s), n = await modelRun("new", t.s);
    if (o.out.thrown) statuses.add(o.out["own:status"] + " " + o.out["own:code"]);
    compare("C1", t.label, o, n, t.rec === null ? null : { user: t.s.user, action: "model_call", target: "route:business-chat", outcome: t.rec[0], results: t.rec[1] });
    if (t.owner) check("E " + t.label + ": G9 is recorded as bypass, never pass", (n.gateRows[0] || { results: [] }).results.some(r => r.gate === "G9" && r.result === "bypass"), J(n.gateRows));
  }
  check("C1. every refusal the gate can make was exercised", ["503 DAILY_MODEL_CALL_LIMIT_MISCONFIGURED", "503 PLATFORM_DAILY_SPEND_LIMIT_MISCONFIGURED",
    "503 PLATFORM_SPEND_UNREADABLE", "429 PLATFORM_DAILY_SPEND_LIMIT", "429 DAILY_MODEL_CALL_LIMIT", "429 MONTHLY_MODEL_SPEND_LIMIT",
    "503 MONTHLY_MODEL_SPEND_LIMIT_MISCONFIGURED"].every(x => statuses.has(x)), J([...statuses]));

  /* ═══ C2. route entitlement ══════════════════════════════════════════════ */
  console.log("\n══ C2. route entitlement: G12 — old vs new ══");
  async function routeGateRun(which, plan, user, gateWrite, routeKey) {
    const c = makeCtx({ gateWrite: gateWrite, globals: { getUserPlan: async () => { if (plan === "throws") throw new Error("plan read failed"); return JSON.parse(JSON.stringify(plan)); } } });
    script(which, "g12", DEFS[which].get("requireActiveSubscription"), ["getUserPlan"], "requireActiveSubscription").runInContext(c.sandbox);
    const rk = (routeKey || "post /api/agents/:type/run").split(" ");
    const req = { method: rk[0].toUpperCase(), route: { path: rk[1] }, user: { id: user || MEMBER, role: "user" } };
    const res = makeRes(); const nexts = [];
    await c.sandbox.__api.requireActiveSubscription(req, res, function (e) { nexts.push(e === undefined ? "next()" : errShape(e)); });
    await settle();
    const fields = {}; ["subscription", "plan", "planConfig", "planExempt", "planAccessReason"].forEach(k => { if (k in req) fields[k] = req[k]; });
    return { out: { res: resShape(res), next: nexts }, extra: fields, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows };
  }
  const reasonsSrc = DEFS.new.get("SUBSCRIPTION_REFUSAL_MESSAGES") || "";
  const routeKeys = (reasonsSrc.match(/^\s+"([a-z]+ \/[^"]+)":/gm) || []).map(x => x.trim().slice(1, -2));
  check("C2. every route with its own refusal sentence was read from server.js", routeKeys.length >= 6, J(routeKeys));
  const inactive = r => ({ active: false, expired: r === "expired", inactive_reason: r, plan: null, config: null, subscription: null });
  const G12 = routeKeys.concat(["post /api/agents/:type/run"]).map(k => ({ label: "refused at " + k + " (402)", route: k, plan: inactive("no_subscription"),
    rec: ["blocked", [["G12", "fail", "subscription_required"]]] }));
  ["past_due", "expired", "canceled", "some_new_reason", null].forEach(r => G12.push({ label: "refused, inactive_reason " + r + " (402)", plan: inactive(r),
    rec: ["blocked", [["G12", "fail", "subscription_required"]]] }));
  G12.push({ label: "the owner", user: OWNER_ID, plan: { active: true, exempt: true, access_reason: "owner", plan: "all_access", config: { x: 1 }, subscription: null },
    rec: ["ran", [["G12", "bypass", "owner_pass"]]], owner: true });
  G12.push({ label: "an exempt admin", plan: { active: true, exempt: true, access_reason: "admin", plan: "all_access", config: { x: 1 }, subscription: null },
    rec: ["ran", [["G12", "bypass", "admin_exempt"]]] });
  G12.push({ label: "a subscriber", plan: { active: true, exempt: false, access_reason: "subscription", plan: "all_access", config: { x: 1 }, subscription: { status: "active" } },
    rec: ["ran", [["G12", "pass"]]] });
  G12.push({ label: "the plan read throwing (next(error))", plan: "throws", rec: ["blocked", [["G12", "fail", "plan_unreadable"]]] });
  for (const t of G12) {
    const o = await routeGateRun("old", t.plan, t.user, "ok", t.route), n = await routeGateRun("new", t.plan, t.user, "ok", t.route);
    const wantOut = t.rec[0] === "ran" ? "next() once, nothing sent" : t.plan === "throws" ? "next(error)" : "402 sent once";
    check("C2 " + t.label + ": " + wantOut, t.rec[0] === "ran" ? (J(o.out.next) === J(["next()"]) && o.out.res.sent === 0)
      : t.plan === "throws" ? (o.out.next.length === 1 && o.out.next[0].message === "plan read failed" && o.out.res.sent === 0)
      : (o.out.res.status === 402 && o.out.res.sent === 1 && o.out.next.length === 0), J(o.out));
    compare("C2", t.label, o, n, { user: t.user || MEMBER, action: "route_access", target: "route:" + (t.route || "post /api/agents/:type/run"), outcome: t.rec[0], results: t.rec[1] });
    if (t.owner) check("E " + t.label + ": G12 is recorded as bypass, never pass", (n.gateRows[0] || { results: [] }).results[0] && n.gateRows[0].results[0].result === "bypass", J(n.gateRows));
  }

  /* ═══ C3. proposal approval ══════════════════════════════════════════════ */
  console.log("\n══ C3. proposal approval: G3, G1 — old vs new ══");
  const APPROVE = "app.post(\"/api/proposals/:id/approve\", requireAuth, async function (req, res, next) {";
  const PID = "c0000000-0000-4000-8000-0000000000cc";
  async function approveRun(which, s, gateWrite) {
    const c = makeCtx({
      gateWrite: gateWrite,
      respond: function (q) {
        if (q.table === "agent_proposals" && q.op === "select") return s.pendingError ? { data: null, error: { message: "read failed" } } : { data: s.pending || null, error: null };
        if (q.table === "agent_proposals" && q.op === "update" && q.payload.status === "executing") return { data: s.claim || null, error: null };
        if (q.table === "agent_proposals" && q.op === "update") return { data: Object.assign({}, s.claim, q.payload), error: null };
        if (q.table === "ai_agents" && q.op === "select") return { data: { id: "agent-1", tasks_completed: 4 }, error: null };
        return null;
      },
      globals: {
        getUserPlan: async () => ({ active: !!s.subscribed, inactive_reason: s.subscribed ? null : "no_subscription" }),
        requireAuth: function requireAuth() {},
        PROPOSAL_EXECUTORS: {
          publish_blog_post: async row => ({ published: true, slug: "post-" + row.id.slice(0, 4) }),
          broken_type: async () => { throw new Error("executor broke"); }
        },
        app: { post: function () { c.handler = arguments[arguments.length - 1]; } }
      }
    });
    c.sandbox.app.post = function () { c.handler = arguments[arguments.length - 1]; };
    script(which, "approve", routeSource(which, APPROVE), ["getUserPlan", "PROPOSAL_EXECUTORS"], "x: 1").runInContext(c.sandbox);
    const req = { params: { id: PID }, user: { id: MEMBER, role: "user" }, body: { note: "ignored" } };
    const res = makeRes(); const nexts = [];
    await c.handler(req, res, function (e) { nexts.push(e === undefined ? "next()" : errShape(e)); });
    await settle();
    return { out: { res: resShape(res), next: nexts }, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows };
  }
  const row = t => ({ id: PID, user_id: MEMBER, agent_type: "seo", action_type: t, status: "executing", payload: {} });
  const AP = [
    { label: "not found or no longer pending (409)", s: {}, rec: ["blocked", [["G3", "not_reached"], ["G1", "fail", "not_pending"]]] },
    { label: "a gated action, not subscribed (402)", s: { pending: { action_type: "publish_blog_post" } }, rec: ["blocked", [["G3", "fail", "subscription_required"], ["G1", "not_reached"]]] },
    { label: "publish_listing, not subscribed (402)", s: { pending: { action_type: "publish_listing" } }, rec: ["blocked", [["G3", "fail", "subscription_required"], ["G1", "not_reached"]]] },
    { label: "update_listing, not subscribed (402)", s: { pending: { action_type: "update_listing" } }, rec: ["blocked", [["G3", "fail", "subscription_required"], ["G1", "not_reached"]]] },
    { label: "send_email_sequence, not subscribed (402, the default sentence)", s: { pending: { action_type: "send_email_sequence" } }, rec: ["blocked", [["G3", "fail", "subscription_required"], ["G1", "not_reached"]]] },
    { label: "a gated action, subscribed, claimed by another approval (409)", s: { pending: { action_type: "publish_blog_post" }, subscribed: true },
      rec: ["blocked", [["G3", "pass"], ["G1", "fail", "not_pending"]]] },
    { label: "a gated action, subscribed, executed (200)", s: { pending: { action_type: "publish_blog_post" }, subscribed: true, claim: row("publish_blog_post") },
      rec: ["ran", [["G3", "pass"], ["G1", "pass", "approved"]]] },
    { label: "no executor for the type (501)", s: { pending: { action_type: "mystery_type" }, claim: row("mystery_type") },
      rec: ["blocked", [["G3", "not_reached"], ["G1", "fail", "no_executor"]]] },
    { label: "the executor throwing (500)", s: { pending: { action_type: "broken_type" }, claim: row("broken_type") },
      rec: ["ran", [["G3", "not_reached"], ["G1", "pass", "approved"]]] },
    { label: "the pending read failing (next(error))", s: { pendingError: true }, rec: undefined }
  ];
  for (const t of AP) {
    const o = await approveRun("old", t.s), n = await approveRun("new", t.s);
    const wantStatus = Number((/\((\d{3})/.exec(t.label) || [])[1]) || null;
    if (wantStatus) check("C3 " + t.label + ": answered " + wantStatus, o.out.res.status === wantStatus && o.out.res.sent === 1, J(o.out));
    else check("C3 " + t.label + ": passed to next(error)", o.out.next.length === 1 && o.out.next[0].thrown === true, J(o.out));
    compare("C3", t.label, o, n, t.rec && { user: MEMBER, action: "proposal_approve", target: "proposal:" + PID, outcome: t.rec[0], results: t.rec[1] });
  }

  /* ═══ C4. the high-risk task hold ════════════════════════════════════════ */
  console.log("\n══ C4. the high-risk task hold: G2 — old vs new ══");
  const TASK_STUBS = ["processAiTask", "getLiveStats", "fetchSpecialistNotes", "memberGuidanceFor", "buildAgentSystemPrompt", "resolvePreferredLanguage",
    "buildLanguageInstruction", "agentBrains", "taskInstructions", "AGENT_SYSTEM_PROMPTS", "warnUnknownTaskType", "callAnthropicText", "orchestrateAgentWorkflow"];
  async function taskRun(which, prompt) {
    const queued = [];
    const c = makeCtx({
      respond: function (q) {
        if (q.table === "ai_tasks" && q.op === "insert") return { data: Object.assign({ id: "d0000000-0000-4000-8000-0000000000dd", created_at: "2026-10-15T15:30:00.000Z" }, q.payload), error: null };
        if (q.table === "business_profiles") return { data: { business_name: "Biz" }, error: null };
        return null;
      },
      globals: {
        processAiTask: async function () { queued.push(Array.prototype.slice.call(arguments)); },
        getLiveStats: async () => ({}), fetchSpecialistNotes: async () => [], memberGuidanceFor: async () => "",
        buildAgentSystemPrompt: () => "SYSTEM", resolvePreferredLanguage: async () => null, buildLanguageInstruction: () => "",
        agentBrains: { general: "brain", seo: "seo brain" }, taskInstructions: { general: "do it" }, AGENT_SYSTEM_PROMPTS: { seo: "x", general: "x" },
        warnUnknownTaskType: () => {}, callAnthropicText: async () => { throw new Error("no model in this check"); }, orchestrateAgentWorkflow: async () => null,
        setImmediate: function (fn) { setImmediate(fn); }
      }
    });
    script(which, "task", DEFS[which].get("handleAiTaskRequest"), TASK_STUBS, "handleAiTaskRequest").runInContext(c.sandbox);
    const req = { user: { id: MEMBER, role: "user" }, body: { agent_type: "seo", task_type: "general", prompt: prompt } };
    const res = makeRes(); const nexts = [];
    await c.sandbox.__api.handleAiTaskRequest(req, res, function (e) { nexts.push(e === undefined ? "next()" : errShape(e)); });
    await settle();
    return { out: { res: resShape(res), next: nexts }, extra: queued, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows };
  }
  const TK = [
    { label: "an advisory prompt (202)", prompt: "Write three taglines for a candle shop", rec: ["ran", [["G2", "pass"]]] },
    { label: "a high-risk prompt (202, held)", prompt: "Please publish the launch post and buy ads", rec: ["held_for_approval", [["G2", "fail", "high_risk"]]] },
    { label: "a missing prompt (400)", prompt: "", rec: undefined }
  ];
  for (const t of TK) {
    const o = await taskRun("old", t.prompt), n = await taskRun("new", t.prompt);
    compare("C4", t.label, o, n, t.rec && { user: MEMBER, action: "task_run", target: "ai_task:d0000000-0000-4000-8000-0000000000dd", outcome: t.rec[0], results: t.rec[1] });
    if (!t.rec) check("D " + t.label + ": no decision was reached, so no record", n.gateRows.length === 0, J(n.gateRows));
    if (t.rec) check("C4 " + t.label + ": the task was queued with requiresApproval " + (t.rec[0] !== "ran"), n.extra.length === 1 && n.extra[0][5] === (t.rec[0] !== "ran"), J(n.extra));
  }

  /* ═══ C5. chain dispatch ═════════════════════════════════════════════════ */
  console.log("\n══ C5. chain dispatch: G19 and G12 — old vs new ══");
  const ROUTES = [
    { key: "seo/audit", path: "/api/agents/seo/audit", spec: [{ name: "url", required: true }] },
    { key: "content/outline", path: "/api/agents/content/outline", spec: [{ name: "topic", required: true }] },
    { key: "rd/brief", path: "/api/agents/rd/brief", spec: null },
    { key: "ads/ghost", path: "/api/agents/ads/ghost", spec: [] }
  ];
  async function dispatchRun(which, calls, plan, env, gateWrite) {
    const c = makeCtx({
      gateWrite: gateWrite,
      env: Object.assign({ ENABLE_AGENT_CHAINING: "true" }, env || {}),
      globals: {
        agentToolRoutes: () => ROUTES,
        resolveToolRouteHandler: function (p) {
          if (p === "/api/agents/seo/audit") return function (req, res) { res.status(200).json({ ok: true, task_id: "t-1", got: req.body }); };
          if (p === "/api/agents/content/outline") return function (req, res, next) { next(new Error("tool broke")); };
          return null;
        },
        agentChainScope: { run: function (ctxv, fn) { return fn(); } },
        getUserPlan: async function () { if (plan === "throws") throw new Error("plan read failed"); return plan || { active: true }; }
      }
    });
    script(which, "dispatch", DEFS[which].get("dispatchToolCall"), ["agentToolRoutes", "resolveToolRouteHandler", "agentChainScope", "getUserPlan",
      "aiLimiter", "runScheduledAgentTask", "handleAiTaskRequest", "express", "rateLimit"], "dispatchToolCall").runInContext(c.sandbox);
    const outs = [];
    for (const call of calls) outs.push(await capture(() => c.sandbox.__api.dispatchToolCall(JSON.parse(JSON.stringify(call)))));
    await settle();
    return { out: outs, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows };
  }
  const call = (o) => Object.assign({ userId: MEMBER, agentType: "seo", tool: "audit", body: { url: "https://example.com" }, chain: { id: "chain-1", depth: 0, callsSoFar: 0 } }, o || {});
  const blocked = (code) => ["blocked", [["G19", "fail", code], ["G12", "not_reached"]]];
  const DP = [
    { label: "chaining disabled", calls: [call()], env: { ENABLE_AGENT_CHAINING: "false" }, rec: blocked("chaining_disabled") },
    { label: "no chain id", calls: [call({ chain: { depth: 0, callsSoFar: 0 } })], rec: blocked("chain_id_missing") },
    { label: "a bad depth", calls: [call({ chain: { id: "c", depth: -1, callsSoFar: 0 } })], rec: blocked("chain_depth_invalid") },
    { label: "a bad call count", calls: [call({ chain: { id: "c", depth: 0, callsSoFar: 1.5 } })], rec: blocked("chain_calls_invalid") },
    { label: "the total call limit", calls: [call({ chain: { id: "c", depth: 0, callsSoFar: 10 } })], rec: blocked("chain_total_calls_reached") },
    { label: "the depth limit", calls: [call({ chain: { id: "c", depth: 2, callsSoFar: 0 } })], rec: blocked("chain_depth_reached") },
    { label: "an external-action tool", calls: [call({ agentType: "seo", tool: "generate-post" })], rec: blocked("tool_takes_external_action") },
    { label: "a tool not in the router", calls: [call({ agentType: "seo", tool: "nothing" })], rec: blocked("tool_not_in_router") },
    { label: "a tool with no spec", calls: [call({ agentType: "rd", tool: "brief" })], rec: blocked("tool_has_no_spec") },
    { label: "a tool name that is not a token (the target is cut to its kind)", calls: [call({ agentType: "seo", tool: "x@y.z <b>" })], rec: blocked("tool_not_in_router"), target: "tool" },
    { label: "a body missing a required field", calls: [call({ body: {} })], rec: blocked("body_missing_required_fields") },
    { label: "no handler mounted", calls: [call({ agentType: "ads", tool: "ghost", body: {} })], rec: blocked("handler_not_found") },
    { label: "the plan unreadable", calls: [call()], plan: "throws", rec: ["blocked", [["G19", "pass"], ["G12", "fail", "entitlement_unknown"]]] },
    { label: "not entitled", calls: [call()], plan: { active: false, inactive_reason: "expired" }, rec: ["blocked", [["G19", "pass"], ["G12", "fail", "not_entitled"]]] },
    { label: "ran", calls: [call()], rec: ["ran", [["G19", "pass"], ["G12", "pass"]]] },
    { label: "ran, and the tool failed (handler_error)", calls: [call({ agentType: "content", tool: "outline", body: { topic: "x" } })], rec: ["ran", [["G19", "pass"], ["G12", "pass"]]] },
    { label: "no user", calls: [call({ userId: null })], rec: null }
  ];
  for (const t of DP) {
    const o = await dispatchRun("old", t.calls, t.plan, t.env), n = await dispatchRun("new", t.calls, t.plan, t.env);
    const wantReason = t.rec && t.rec[0] === "blocked" ? (t.rec[1][0][2] || t.rec[1][1][2]) : t.label.indexOf("handler_error") !== -1 ? "handler_error" : t.rec ? null : "user_missing";
    check("C5 " + t.label + ": answered refused_reason " + wantReason, o.out[0].returned && o.out[0].returned.refused_reason === wantReason &&
      (wantReason !== null || o.out[0].returned.ok === true), J(o.out));
    compare("C5", t.label, o, n, t.rec === null ? null : { user: MEMBER, action: "dispatch", target: t.target || "tool:" + t.calls[0].agentType + "/" + t.calls[0].tool, outcome: t.rec[0], results: t.rec[1] });
  }
  // Two decisions in a row each get their own record: the fan-out and the rate limits.
  for (const t of [
    { label: "the fan-out limit, second dispatch", env: { CHAIN_MAX_FANOUT: "1" }, calls: [call(), call()], code: "chain_fanout_reached" },
    { label: "the rate limit, second dispatch", env: { ROUTINE_STEPS_PER_MINUTE: "1" }, calls: [call(), call({ chain: { id: "chain-2", depth: 0, callsSoFar: 0 } })], code: "dispatch_rate_reached" }
  ]) {
    const o = await dispatchRun("old", t.calls, null, t.env), n = await dispatchRun("new", t.calls, null, t.env);
    check("C5 " + t.label + ": identical to " + PRE_GATES, J({ out: o.out, logs: o.logs }) === J({ out: n.out, logs: notGates(n.logs) }), J(o.out) + " | " + J(n.out));
    check("C5 " + t.label + ": refused " + t.code, n.out[1].returned && n.out[1].returned.refused_reason === t.code, J(n.out[1]));
    check("D " + t.label + ": two decisions, two records, ran then blocked",
      n.gateRows.length === 2 && n.gateRows[0].outcome === "ran" && n.gateRows[1].outcome === "blocked" && J(n.gateRows[1].results) === J([{ gate: "G19", result: "fail", code: t.code }, { gate: "G12", result: "not_reached" }]),
      J(n.gateRows));
  }

  /* ═══ C6. marketing email ════════════════════════════════════════════════ */
  console.log("\n══ C6. marketing email: G20 — old vs new ══");
  const CONTACT = "e0000000-0000-4000-8000-0000000000ee";
  const realLegal = require(path.join(REPO, "lib/legal"));
  async function mailRun(which, s, gateWrite) {
    const sent = [];
    const c = makeCtx({
      gateWrite: gateWrite,
      env: Object.assign({ RESEND_WEBHOOK_SECRET: "whsec_check", UNSUBSCRIBE_SECRET: "unsub-check-secret", JWT_SECRET: "jwt-check-secret" }, s.env || {}),
      legal: s.noPostal ? Object.assign({}, realLegal, { POSTAL_ADDRESS: "" }) : null,
      respond: function (q) {
        if (q.table === "consent_events") return s.consentError ? { data: null, error: { message: "consent read failed" } } : { data: s.consent ? [{ action: s.consent }] : [], error: null };
        if (q.table === "contacts") return s.contactError ? { data: null, error: { message: "contact read failed" } } : { data: s.contact === undefined ? { id: CONTACT, email: "Reader@Example.com", owner_id: MEMBER } : s.contact, error: null };
        if (q.table === "email_sends" && q.opts && q.opts.head) return s.countError ? { data: null, count: null, error: { message: "count failed" } } : { data: null, count: s.count || 0, error: null };
        if (q.table === "email_sends") return s.historyError ? { data: null, error: { message: "history failed" } } : { data: has(q, "eq", "contact_id") ? (s.history || []) : [], error: null };
        return null;
      },
      globals: { sendEmail: async function (o) { sent.push(o); if (s.sendThrows) throw new Error("resend down"); return { sent: true, id: "msg-1" }; } }
    });
    script(which, "mail", DEFS[which].get("sendMarketingEmail"), ["sendEmail"], "sendMarketingEmail").runInContext(c.sandbox);
    const opts = Object.assign({ contactId: CONTACT, subject: "News", html: "<p>Hi</p>", text: "Hi", template: "news", ownerId: MEMBER }, s.opts || {});
    const out = await capture(() => c.sandbox.__api.sendMarketingEmail(opts));
    await settle();
    return { out: out, extra: sent, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows };
  }
  const refused = code => ["blocked", [["G20", "fail", code]]];
  const ML = [
    { label: "no contact id", s: { opts: { contactId: null } }, rec: refused("no_contact"), target: "contact:none" },
    { label: "no subject", s: { opts: { subject: " " } }, rec: refused("invalid") },
    { label: "no text body", s: { opts: { text: "" } }, rec: refused("invalid") },
    { label: "a bad template name", s: { opts: { template: "News!" } }, rec: refused("invalid") },
    { label: "no postal address", s: { noPostal: true }, rec: refused("no_postal_address") },
    { label: "no webhook secret", s: { env: { RESEND_WEBHOOK_SECRET: "" } }, rec: refused("no_webhook_secret") },
    { label: "consent unreadable", s: { consentError: true }, rec: refused("lookup_failed") },
    { label: "granted but not confirmed", s: { consent: "granted" }, rec: refused("not_confirmed") },
    { label: "no consent", s: { consent: "withdrawn" }, rec: refused("no_consent") },
    { label: "the contact unreadable", s: { consent: "confirmed", contactError: true }, rec: refused("lookup_failed") },
    { label: "the contact missing", s: { consent: "confirmed", contact: null }, rec: refused("no_contact") },
    { label: "the contact has no owner", s: { consent: "confirmed", contact: { id: CONTACT, email: "a@b.co", owner_id: null } }, rec: refused("no_owner") },
    { label: "history unreadable", s: { consent: "confirmed", historyError: true }, rec: refused("lookup_failed") },
    { label: "a spam complaint", s: { consent: "confirmed", history: [{ id: 7, to_email: "reader@example.com", status: "complained", error_message: null }] }, rec: refused("suppressed") },
    { label: "a permanent bounce", s: { consent: "confirmed", history: [{ id: 8, to_email: "reader@example.com", status: "bounced", error_message: "[bounce type=Permanent subtype=General] gone" }] }, rec: refused("suppressed") },
    { label: "the cap unreadable", s: { consent: "confirmed", env: { EMAIL_MARKETING_DAILY_CAP: "many" } }, rec: refused("cap_unreadable") },
    { label: "the count failing", s: { consent: "confirmed", countError: true }, rec: refused("count_failed") },
    { label: "the cap reached", s: { consent: "confirmed", count: 50 }, rec: refused("cap_reached") },
    { label: "sent", s: { consent: "confirmed" }, rec: ["ran", [["G20", "pass"]]] },
    { label: "sent past a temporary bounce", s: { consent: "confirmed", history: [{ id: 9, to_email: "reader@example.com", status: "bounced", error_message: "[bounce type=Transient subtype=MailboxFull] later" }] }, rec: ["ran", [["G20", "pass"]]] },
    { label: "passed, then the send failed", s: { consent: "confirmed", sendThrows: true }, rec: ["ran", [["G20", "pass"]]] },
    { label: "an early refusal with no owner named", s: { opts: { subject: "", ownerId: undefined } }, rec: null }
  ];
  const reasonsSeen = new Set();
  for (const t of ML) {
    const o = await mailRun("old", t.s), n = await mailRun("new", t.s);
    if (o.out["own:reason"]) reasonsSeen.add(o.out["own:reason"]);
    const wantMail = t.rec && t.rec[0] === "blocked" ? "refused " + t.rec[1][0][2] : t.s.sendThrows ? "threw resend down" : t.rec ? "sent" : "refused invalid";
    check("C6 " + t.label + ": " + wantMail, wantMail === "sent" ? (o.out.returned && o.out.returned.sent === true && o.extra.length === 1)
      : wantMail === "threw resend down" ? (o.out.message === "resend down" && o.extra.length === 1)
      : (o.out["own:code"] === "marketing_refused" && "refused " + o.out["own:reason"] === wantMail && o.extra.length === 0), J(o.out));
    compare("C6", t.label, o, n, t.rec === null ? null : { user: MEMBER, action: "marketing_email", target: t.target || "contact:" + CONTACT, outcome: t.rec[0], results: t.rec[1] });
  }
  check("C6. all twelve marketing refusals were exercised", ["no_contact", "invalid", "no_postal_address", "no_webhook_secret", "lookup_failed", "not_confirmed",
    "no_consent", "no_owner", "suppressed", "cap_unreadable", "count_failed", "cap_reached"].every(r => reasonsSeen.has(r)), J([...reasonsSeen]));
  {
    // The contact's owner, once read, is who the record is filed under, whatever the caller named.
    const n = await mailRun("new", { consent: "confirmed", count: 50, opts: { ownerId: MEMBER_B } });
    check("D the contact's owner, not the caller's guess, is filed once the contact is read", n.gateRows.length === 1 && n.gateRows[0].user_id === MEMBER, J(n.gateRows));
  }

  /* ═══ F. a failed record write ═══════════════════════════════════════════ */
  console.log("\n══ F. a failed record write never changes the decision ══");
  const FAILING = [
    { label: "a refused model call", run: (w, g) => modelRun(w, { user: MEMBER, used: 250 }, g) },
    { label: "a passing model call", run: (w, g) => modelRun(w, { user: MEMBER, used: 3, month: 1 }, g) },
    { label: "the owner's model call", run: (w, g) => modelRun(w, { user: OWNER_ID, platform: 30 }, g) },
    { label: "a 402 route", run: (w, g) => routeGateRun(w, { active: false, inactive_reason: "no_subscription" }, MEMBER, g) },
    { label: "a subscriber's route", run: (w, g) => routeGateRun(w, { active: true, exempt: false, access_reason: "subscription", plan: "all_access", config: {} }, MEMBER, g) },
    { label: "a 501 approval", run: (w, g) => approveRun(w, { pending: { action_type: "mystery_type" }, claim: row("mystery_type") }, g) },
    { label: "a refused dispatch", run: (w, g) => dispatchRun(w, [call({ chain: { id: "c", depth: 2, callsSoFar: 0 } })], null, null, g) },
    { label: "a dispatch that ran", run: (w, g) => dispatchRun(w, [call()], null, null, g) },
    { label: "a refused marketing email", run: (w, g) => mailRun(w, { consent: "confirmed", count: 50 }, g) },
    { label: "a sent marketing email", run: (w, g) => mailRun(w, { consent: "confirmed" }, g) }
  ];
  for (const mode of ["error", "reject", "throw", "nolib"]) {
    for (const t of FAILING) {
      const o = await t.run("old", "ok"), n = await t.run("new", mode);
      const same = J({ out: o.out, logs: o.logs, writes: o.writes, extra: o.extra }) === J({ out: n.out, logs: notGates(n.logs), writes: n.writes, extra: n.extra });
      const logged = n.logs.filter(l => l.indexOf("[gates] record not written") !== -1).length === 1;
      check("F " + t.label + ", the write " + (mode === "nolib" ? "unable to load lib/gates.js" : mode === "throw" ? "throwing" : mode === "reject" ? "rejecting" : "answering an error") +
        ": same answer, logged once", same && logged, (same ? "" : "old " + J(o.out).slice(0, 300) + " new " + J(n.out).slice(0, 300)) + (logged ? "" : " logs " + J(n.logs.filter(l => l.indexOf("[gates]") !== -1))));
    }
  }

  /* ═══ G. export and deletion ═════════════════════════════════════════════ */
  console.log("\n══ G. the decisions are exported and deleted with the account ══");
  const yourData = require(path.join(REPO, "lib/yourData"));
  const entry = yourData.DATA.filter(e => e.table === "gate_decisions");
  check("G1. gate_decisions is in DATA once: group agents, owner user_id, onDelete delete",
    entry.length === 1 && entry[0].group === "agents" && J(entry[0].owner) === J(["user_id"]) && entry[0].onDelete === "delete", J(entry));
  check("G2. the export text says what it is and how long it is kept", entry.length === 1 && /90 days/.test(entry[0].what) && !/[<>]/.test(entry[0].what), entry[0] && entry[0].what);
  check("G3. gate_decisions is in DELETE_ORDER once", yourData.DELETE_ORDER.filter(t => t === "gate_decisions").length === 1);
  check("G4. the foreign key cascades with the account", /user_id\s+uuid NOT NULL REFERENCES public\.users\(id\) ON DELETE CASCADE/.test(FILES.migration));
  check("G5. lib/backup.js names the table (skipped: a 90-day log)", /\n  gate_decisions:\s+"[^"]*90-day/.test(FILES.backup));

  /* ═══ H. isolation ═══════════════════════════════════════════════════════ */
  console.log("\n══ H. no member's decision is readable by another ══");
  const sqlCode = FILES.migration.replace(/--[^\n]*/g, "");
  check("H1. row level security is enabled on gate_decisions", /ALTER TABLE public\.gate_decisions ENABLE ROW LEVEL SECURITY;/.test(sqlCode));
  check("H2. the migration creates no policy and grants nothing", !/CREATE POLICY|GRANT /i.test(sqlCode));
  const usesOfTable = (NEW.match(/["']gate_decisions["']/g) || []).length;
  check("H3. server.js touches gate_decisions in one place, an insert, and never reads it",
    usesOfTable === 1 && /supabase\.from\("gate_decisions"\)\.insert\(gateRow\)/.test(NEW) && !/from\("gate_decisions"\)\s*\.select/.test(NEW), usesOfTable);
  check("H4. no route serves gate_decisions yet", !/app\.(get|post|put|delete)\("\/api\/gate-decisions/.test(NEW));
  {
    const a = await routeGateRun("new", { active: false, inactive_reason: "no_subscription" }, MEMBER);
    const b = await routeGateRun("new", { active: true, exempt: false, access_reason: "subscription", plan: "all_access", config: {} }, MEMBER_B);
    const m1 = await modelRun("new", { user: MEMBER_B, used: 250 });
    const m2 = await modelRun("new", { user: MEMBER, used: 3, month: 1 });
    check("H5. two members deciding in turn: each record is filed under its own member",
      a.gateRows.length === 1 && a.gateRows[0].user_id === MEMBER && a.gateRows[0].outcome === "blocked" &&
      b.gateRows.length === 1 && b.gateRows[0].user_id === MEMBER_B && b.gateRows[0].outcome === "ran" &&
      m1.gateRows[0].user_id === MEMBER_B && m1.gateRows[0].outcome === "blocked" && m2.gateRows[0].user_id === MEMBER && m2.gateRows[0].outcome === "ran",
      J([a.gateRows, b.gateRows, m1.gateRows, m2.gateRows]));
    const all = [a, b, m1, m2].map(r => J(r.gateRows)).join(" ");
    check("H6. a record holds no address, prompt or amount", !/@|\$|prompt|Reader|candle/i.test(all), all);
  }

  /* ═══ I. the migration ═══════════════════════════════════════════════════ */
  console.log("\n══ I. migration 158 ══");
  const dir = fs.readdirSync(path.join(REPO, "supabase/migrations"));
  check("I1. 158_gate_decisions.sql exists and is the only migration numbered 158", dir.filter(f => /^158_/.test(f)).length === 1 && dir.indexOf("158_gate_decisions.sql") !== -1);
  const listIn = (col) => { const m = new RegExp(col + "\\s+text NOT NULL CHECK \\(" + col + " IN \\(([^)]*)\\)\\)").exec(sqlCode); return m ? m[1].match(/'[a-z_]+'/g).map(x => x.slice(1, -1)) : null; };
  check("I2. the action list equals lib/gates.js ACTIONS", J(listIn("action")) === J(GATES.ACTIONS.slice()), J(listIn("action")));
  check("I3. the outcome list equals lib/gates.js OUTCOMES", J(listIn("outcome")) === J(GATES.OUTCOMES.slice()), J(listIn("outcome")));
  check("I4. the columns are id, user_id, action, target, outcome, results, created_at",
    ["id         uuid PRIMARY KEY DEFAULT gen_random_uuid()", "user_id    uuid NOT NULL", "action     text NOT NULL", "target     text NOT NULL",
      "outcome    text NOT NULL", "results    jsonb NOT NULL CHECK (jsonb_typeof(results) = 'array' AND pg_column_size(results) <= 2048)",
      "created_at timestamptz NOT NULL DEFAULT now()"].every(x => sqlCode.indexOf(x) !== -1));
  check("I5. the per-member recent index", /CREATE INDEX IF NOT EXISTS gate_decisions_user_recent_idx\s+ON public\.gate_decisions \(user_id, created_at DESC\);/.test(sqlCode));
  check("I6. the per-action index", /CREATE INDEX IF NOT EXISTS gate_decisions_user_action_idx\s+ON public\.gate_decisions \(user_id, action, created_at DESC\);/.test(sqlCode));
  check("I7. retention: 90 days, the sweep in block B2", /RETENTION\. 90 days/.test(FILES.migration) && /comes in block B2/.test(FILES.migration) && GATES.RETENTION_DAYS === 90);

  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED (" + passes + ")" : "CHECKS FAILED: " + failures + " failing, " + passes + " passing"));
  process.exit(failures === 0 ? 0 : 1);
})().catch(function (e) {
  console.log("    FAIL  the check itself crashed: " + ((e && e.stack) || e));
  process.exit(1);
});
