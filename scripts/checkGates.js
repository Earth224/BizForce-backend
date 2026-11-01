/* ═══════════════════════════════════════════════════════════════════════════
   checkGates.js — one gate evaluator, one record per decision, and every
   refusal byte-identical to what it was before (intelligence layer B1); every
   remaining gate recorded, member gates that can only add restrictions, and
   "Why?" answered from the records (intelligence layer B2).

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

   BLOCK B2 (baseline B1_HEAD, b096831, the commit before B2):
     J. OLD VS NEW, BY OUTPUT, for every B2 adapter, each recording its
        decision: G3 (automatic posting on, a listing edit), G14 (making an
        agent), G8 and G7 (filing a Bluesky post), G23 and G22 (outreach: the
        convert route's 422 and convertSingleLead), G24 (bfcSendWithinLimits,
        whose body is b096831's byte for byte under a new name, and a wrapper
        proved transparent), G25 (the guide route, its handler wrapped and
        proved transparent), G18, G16 and G13 (the schedule pass) and G17
        (autoExecuteFiledProposal).
     K. THE LANGUAGE (lib/gateRules.js) refuses unknown fields and comparators,
        a field outside its scope, a mismatched comparator, free text, objects
        and code as values, trees deeper than 4 or wider than 12, lists over
        10, rules over 4096 bytes, and names with markup; it evaluates nothing
        as code, and a missing fact is never a yes.
     L. PROPERTY: over thousands of random decisions and rules, a member gate
        never turns a platform fail into a pass; it blocks a pass under its
        own name, and blocks exactly when its rule is not shown to hold.
     M. A MEMBER GATE BLOCKS WITH ITS OWN NAME: the approve route (403, the
        proposal back to pending, nothing executed), the schedule pass
        (skipped_member_gate, no attempt spent) and an automatic run (nothing
        claimed); a holding, disabled, other-scope or other member's gate
        changes nothing; an unreadable one leaves the platform's decision; and
        platform refusals with random member gates present are identical.
     N. THE ROUTES: CRUD validated and scoped to the caller; the Decisions list
        pages 20 at a time newest first and filters by agent and outcome; one
        decision and a target's decisions are the caller's own, explained by
        lib/gates.js explain(); the 30-day preview only reads.
     O. THE SWEEP deletes only rows older than 90 days, in batches of 500,
        under its own job_runs claim, at 04:30 UTC, with no boot run.
     P. "WHY?" in jsdom: each result kind (pass, fail, bypass, not_reached)
        and the member gate shown from the record only; the Decisions list
        pages and filters; the builder's summary equals the library's on
        random rules; its test sends one read; the links are on the pages.
     Q. member_gates is exported, deleted with the account and backed up.
     R. Migration 159.   S. No emoji in what B2 added.

   B2 MUTATIONS:
     member-gate-flips-fail      withMemberGate turns a platform fail into ran  → L
     unknown-field-accepted      the language accepts a field it does not know  → K, N
     b2-refusal-message-changed  the over-300-graphemes message changes         → J4
     sweep-deletes-recent        the sweep's cutoff is one day, not 90          → O
     why-invents-reason          the panel writes its own sentence for a fail   → P

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
// The commit before block B2: every B2 adapter is compared with it.
const B1_HEAD = "b096831";
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");

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
    "      user_id: userId,\n      action: action,", "      user_id: OWNER_ACCOUNT_ID,\n      action: action,"],
  // B2: a member gate turns a platform fail into a pass
  "member-gate-flips-fail": ["gates",
    "  if (!decision || decision.outcome !== \"ran\" || !block) return decision;\n",
    "  if (!decision || !block) return decision;\n  if (decision.outcome !== \"ran\") return Object.assign({}, decision, { outcome: \"ran\" });\n"],
  // B2: the language accepts a field it does not know
  "unknown-field-accepted": ["rules",
    "    if (typeof node.field !== \"string\" || !own(FIELDS, node.field)) return refuse(",
    "    if (typeof node.field === \"string\" && !own(FIELDS, node.field)) return { ok: true, rule: { field: node.field, op: node.op, value: node.value } };\n    if (typeof node.field !== \"string\") return refuse("],
  // B2: a refusal's wording changes (the over-limit Bluesky post)
  "b2-refusal-message-changed": ["server",
    "\". It cannot be published as written. Nothing was filed.\"",
    "\". It cannot be published. Nothing was filed.\""],
  // B2: the sweep deletes rows a day old
  "sweep-deletes-recent": ["sweep",
    "  return new Date(nowMs - GATE_DECISIONS_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();",
    "  return new Date(nowMs - 1 * 24 * 60 * 60 * 1000).toISOString();"],
  // B2: the Why panel writes its own sentence for a fail instead of the record's
  "why-invents-reason": ["why",
    "'<span class=\"bf-why-reason\">' + esc(g.reason) + '</span></li>';",
    "'<span class=\"bf-why-reason\">' + esc(g.result === \"fail\" ? \"A platform rule stopped this.\" : g.reason) + '</span></li>';"]
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
  backup: read("lib/backup.js"),
  rules: read("lib/gateRules.js"),
  sweep: read("lib/gateDecisionsSweep.js"),
  migration159: read("supabase/migrations/159_member_gates.sql"),
  why: fs.readFileSync(path.join(FRONTEND, "scripts/bf-why.js"), "utf8").replace(/\r\n/g, "\n"),
  agentProfile: fs.readFileSync(path.join(FRONTEND, "scripts/agent-profile.js"), "utf8").replace(/\r\n/g, "\n"),
  hq: fs.readFileSync(path.join(FRONTEND, "scripts/bf-hq.js"), "utf8").replace(/\r\n/g, "\n"),
  deck: fs.readFileSync(path.join(FRONTEND, "scripts/bf-exec-deck.js"), "utf8").replace(/\r\n/g, "\n"),
  execHtml: fs.readFileSync(path.join(FRONTEND, "executive-agent.html"), "utf8").replace(/\r\n/g, "\n")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}
const OLD = execFileSync("git", ["show", PRE_GATES + ":server.js"], { cwd: REPO, maxBuffer: 64 << 20 }).toString("utf8").replace(/\r\n/g, "\n");
const NEW = FILES.server;
const B1_SRC = execFileSync("git", ["show", B1_HEAD + ":server.js"], { cwd: REPO, maxBuffer: 64 << 20 }).toString("utf8").replace(/\r\n/g, "\n");

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
// lib/gateRules.js, the same way: it too needs nothing from outside.
const RULES = loadGates(FILES.rules);
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
      if (table === "gate_decisions" && q.op !== "select") {
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
    b.order = function (c, o) { q.order = [c, o || null]; return b; };
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
      if (p === "./lib/gateRules") return RULES;
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
  /* NAMED BEFORE → AFTER (B2, Nov 1 2026). BEFORE H3 "server.js touches gate_decisions in one place, an insert, and never
     reads it" (1 use) and H4 "no route serves gate_decisions yet". AFTER the "Why?" reads exist: 6 uses, the insert, its
     one retry without the B2 columns, and four reads, each in a route that filters on the caller's user_id (N proves it
     by output), and three routes serve it. */
  const readsOfTable = NEW.split("from(\"gate_decisions\")").length - 1;
  check("H3. server.js touches gate_decisions in six places: the insert, its one retry, and four reads, each naming the caller",
    usesOfTable === 6 && /supabase\.from\("gate_decisions"\)\.insert\(gateRow\)/.test(NEW) && /supabase\.from\("gate_decisions"\)\.insert\(plainRow\)/.test(NEW) &&
    readsOfTable === 6 && (NEW.match(/\.eq\("user_id", req\.user\.id\)/g) || []).length >= 4, usesOfTable + " uses, " + readsOfTable + " from() calls");
  check("H4. exactly three routes serve gate_decisions, all signed in and rate-limited",
    (NEW.match(/app\.(get|post|put|delete)\("\/api\/gate-decisions/g) || []).length === 3 &&
    (NEW.match(/app\.get\("\/api\/gate-decisions[^"]*", requireAuth, gateDecisionsLimiter, /g) || []).length === 3);
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

  /* ═══════════════════════════════════════════════════════════════════════
     BLOCK B2: every remaining gate recorded, member gates, "Why?", the sweep
     ═══════════════════════════════════════════════════════════════════════ */
  DEFS.b1 = indexDefs(B1_SRC); SRC.b1 = B1_SRC;
  const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
  const UUID = n => "a" + String(n).padStart(7, "0") + "-0000-4000-8000-" + String(n).padStart(12, "0");
  const MEMBER_C = "c0000000-0000-4000-8000-0000000000c1", MEMBER_D = "d0000000-0000-4000-8000-0000000000d1";
  const ROUTE_STUBS = ["requireActiveSubscription", "aiLimiter", "memberGatesLimiter", "gateDecisionsLimiter", "rateLimit", "express"];
  const noMw = { requireActiveSubscription: function requireActiveSubscription() {}, aiLimiter: function aiLimiter() {},
    memberGatesLimiter: function memberGatesLimiter() {}, gateDecisionsLimiter: function gateDecisionsLimiter() {}, requireAuth: function requireAuth() {} };

  /* An in-memory table set behind the scripted fake: eq, neq, in, gte, gt, lt, lte, order, range, limit, head counts. */
  function memStore(tables) {
    const T = tables; let seq = 0;
    const val = (r, c) => { if (c.indexOf("->>") !== -1) { const p = c.split("->>"); return r[p[0]] && r[p[0]][p[1]] !== undefined ? String(r[p[0]][p[1]]) : null; } return r[c]; };
    const match = (r, q) => q.filters.every(x => {
      const f = x[0], c = x[1], v = x[2];
      if (f === "eq") return val(r, c) === v;
      if (f === "neq") return val(r, c) !== v;
      if (f === "in") return v.indexOf(val(r, c)) !== -1;
      if (f === "gte") return val(r, c) >= v;
      if (f === "gt") return val(r, c) > v;
      if (f === "lt") return val(r, c) < v;
      if (f === "lte") return val(r, c) <= v;
      throw new Error("memStore: the filter " + f + " is not modelled");
    });
    return function (q) {
      if (!T[q.table]) T[q.table] = [];
      const rows = T[q.table];
      if (q.op === "insert") {
        const list = (Array.isArray(q.payload) ? q.payload : [q.payload]).map(p => Object.assign({ id: "f0000000-0000-4000-8000-" + String(++seq).padStart(12, "0") }, JSON.parse(JSON.stringify(p))));
        list.forEach(r => rows.push(r));
        return { data: q.shape ? list[0] : list, error: null };
      }
      const hit = rows.filter(r => match(r, q));
      if (q.op === "update") { hit.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(q.payload)))); return { data: q.shape ? (hit[0] || null) : hit, error: null }; }
      if (q.op === "delete") { T[q.table] = rows.filter(r => hit.indexOf(r) === -1); return { data: hit, error: null }; }
      if (q.opts && q.opts.head) return { data: null, count: hit.length, error: null };
      let out = hit.slice();
      if (q.order) { const k = q.order[0], dir = q.order[1] && q.order[1].ascending === false ? -1 : 1; out.sort((a, b) => (a[k] < b[k] ? -1 : a[k] > b[k] ? 1 : 0) * dir); }
      const count = out.length;
      if (q.range) out = out.slice(q.range[0], q.range[1] + 1);
      if (q.limit) out = out.slice(0, q.limit);
      if (q.shape) return { data: out[0] || null, error: null };
      return { data: JSON.parse(JSON.stringify(out)), count: count, error: null };
    };
  }

  /* One route, lifted from `which` (b1 = the commit before B2, new = today), run once. */
  async function runRoute(which, key, sig, stubs, o, req) {
    const c = makeCtx(Object.assign({}, o, { globals: Object.assign({}, noMw, o.globals || {}) }));
    const grab = function () { c.handler = arguments[arguments.length - 1]; };
    c.sandbox.app = { get: grab, post: grab, put: grab, delete: grab };
    script(which, key, routeSource(which, sig), ROUTE_STUBS.concat(stubs || []), "x: 1").runInContext(c.sandbox);
    const res = makeRes(); const nexts = [];
    const thrown = await capture(() => c.handler(JSON.parse(JSON.stringify(req)), res, function (e) { nexts.push(e === undefined ? "next()" : errShape(e)); }));
    await flush();
    return { out: { res: resShape(res), next: nexts, thrown: thrown.thrown ? thrown : null }, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows, extra: o.extra ? o.extra() : undefined };
  }
  const recordOf = r => ({ user_id: r.user_id, action: r.action, target: r.target, outcome: r.outcome, results: r.results,
    facts: r.facts === undefined ? null : r.facts, member_gate_name: r.member_gate_name === undefined ? null : r.member_gate_name });
  const res3 = list => list.map(x => Object.assign({ gate: x[0], result: x[1] }, x[2] ? { code: x[2] } : {}));
  /* B1_HEAD and today's runs compared; then today's records, exactly. */
  function compareB2(section, label, o, n, records) {
    const strip = logs => notGates(logs).filter(l => l.indexOf("[member-gates]") === -1);
    const a = { out: o.out, logs: o.logs, writes: o.writes, extra: o.extra };
    const b = { out: n.out, logs: strip(n.logs), writes: n.writes, extra: n.extra };
    check(section + " " + label + ": identical to " + B1_HEAD, J(a) === J(b), "old " + J(a).slice(0, 500) + " | new " + J(b).slice(0, 500));
    if (records === undefined) return;
    const want = records.map(r => ({ user_id: r.user || MEMBER, action: r.action, target: r.target, outcome: r.outcome, results: res3(r.results),
      facts: r.facts === undefined ? null : r.facts, member_gate_name: r.member === undefined ? null : r.member }));
    const got = n.gateRows.map(recordOf);
    check("D " + label + ": " + (want.length ? want.length + " record(s), " + want.map(w => w.outcome + " " + w.results.map(x => x.gate + ":" + x.result + (x.code ? "/" + x.code : "")).join(",")).join("; ") : "no record"),
      J(got) === J(want), "got " + J(got).slice(0, 600) + " want " + J(want).slice(0, 600));
    check("D " + label + ": nothing logged as unwritten", n.logs.every(l => l.indexOf("[gates]") === -1), J(n.logs.filter(l => l.indexOf("[gates]") !== -1)));
  }

  /* ═══ J. the B2 adapters, old vs new ═════════════════════════════════════ */
  console.log("\n══ J. the B2 adapters: G3, G14, G8, G7, G23, G22, G24, G25, G18, G16, G13, G17 — old vs new ══");
  check("J0. the B2 adapters are G3, G7, G8, G13, G14, G18, G22, G23, G24, G25",
    J(GATES.GATES.filter(g => g.b2).map(g => g.id)) === J(["G3", "G7", "G8", "G13", "G14", "G18", "G22", "G23", "G24", "G25"]));
  const planOf = p => async function () { if (p === "throws") throw new Error("plan read failed"); return JSON.parse(JSON.stringify(p)); };
  const SUBSCRIBED = { active: true, exempt: false, access_reason: "subscription", plan: "all_access", config: { allowedAgents: ["seo", "sales", "content", "social"], maxAgents: 3 }, subscription: { status: "active" } };
  const LAPSED = { active: false, inactive_reason: "no_subscription", plan: null, config: null, subscription: null };

  /* J1. G3: turning automatic Bluesky posting on. */
  {
    const SIG = "app.put(\"/api/social/bluesky/automation\", requireAuth, async function (req, res, next) {";
    const T = "route:put /api/social/bluesky/automation";
    const run = (w, s) => runRoute(w, "auto", SIG, ["getUserPlan", "blueskyAutomationState"], {
      respond: function (q) {
        if (q.table === "member_social_connections" && q.op === "select") return { data: s.conn === undefined ? { status: "connected", auto_post: false } : s.conn, error: null };
        if (q.table === "member_social_connections" && q.op === "update") return { data: [{ id: 1 }], error: null };
        return null;
      },
      globals: { getUserPlan: planOf(s.plan || SUBSCRIBED), blueskyAutomationState: async () => ({ auto_post: "state" }) }
    }, { user: { id: MEMBER, role: "user" }, body: s.body });
    const CASES = [
      { label: "auto_post not a boolean (400)", s: { body: { auto_post: "yes" } }, rec: [] },
      { label: "turning it on, not connected (400)", s: { body: { auto_post: true }, conn: null }, rec: [] },
      { label: "turning it on, the connection needs reconnecting (409)", s: { body: { auto_post: true }, conn: { status: "needs_reconnect", auto_post: false } }, rec: [] },
      { label: "turning it on, not subscribed (402)", s: { body: { auto_post: true }, plan: LAPSED }, rec: [{ action: "route_access", target: T, outcome: "blocked", results: [["G3", "fail", "subscription_required"]] }] },
      { label: "turning it on, the plan unreadable (402)", s: { body: { auto_post: true }, plan: "throws" }, rec: [{ action: "route_access", target: T, outcome: "blocked", results: [["G3", "fail", "subscription_required"]] }] },
      { label: "turning it on, subscribed (200)", s: { body: { auto_post: true } }, rec: [{ action: "route_access", target: T, outcome: "ran", results: [["G3", "pass"]] }] },
      { label: "turning it off, never gated (200)", s: { body: { auto_post: false }, plan: LAPSED, conn: { status: "connected", auto_post: true } }, rec: [] }
    ];
    for (const t of CASES) {
      const o = await run("b1", t.s), n = await run("new", t.s);
      const want = Number((/\((\d{3})\)/.exec(t.label) || [])[1]);
      check("J1 " + t.label + ": answered " + want, o.out.res.status === want && o.out.res.sent === 1, J(o.out));
      compareB2("J1", t.label, o, n, t.rec);
    }
  }

  /* J2. G3: editing a public listing (a pause is never gated). */
  {
    const SIG = "app.put(\"/api/marketplace/listings/:id\", requireAuth, async function (req, res, next) {";
    const T = "route:put /api/marketplace/listings/:id";
    const run = (w, s) => runRoute(w, "listing", SIG, ["getUserPlan"], {
      respond: function (q) {
        if (q.table === "marketplace_listings" && q.op === "select") return { data: s.missing ? null : { price_bfc: 10, status: "active" }, error: null };
        if (q.table === "marketplace_listings" && q.op === "update") return { data: Object.assign({ id: "l-1" }, q.payload), error: null };
        return null;
      },
      globals: { getUserPlan: planOf(s.plan || SUBSCRIBED) }
    }, { user: { id: MEMBER, role: "user" }, params: { id: "l-1" }, body: s.body });
    const CASES = [
      { label: "a pause, not subscribed (200)", s: { body: { status: "paused" }, plan: LAPSED }, rec: [] },
      { label: "a title edit, not subscribed (402)", s: { body: { title: "New" }, plan: LAPSED }, rec: [{ action: "route_access", target: T, outcome: "blocked", results: [["G3", "fail", "subscription_required"]] }] },
      { label: "a title edit, the plan unreadable (402)", s: { body: { title: "New" }, plan: "throws" }, rec: [{ action: "route_access", target: T, outcome: "blocked", results: [["G3", "fail", "subscription_required"]] }] },
      { label: "a title edit, subscribed (200)", s: { body: { title: "New" } }, rec: [{ action: "route_access", target: T, outcome: "ran", results: [["G3", "pass"]] }] },
      { label: "a title edit, subscribed, no such listing (404)", s: { body: { title: "New" }, missing: true }, rec: [{ action: "route_access", target: T, outcome: "ran", results: [["G3", "pass"]] }] }
    ];
    for (const t of CASES) {
      const o = await run("b1", t.s), n = await run("new", t.s);
      const want = Number((/\((\d{3})\)/.exec(t.label) || [])[1]);
      check("J2 " + t.label + ": answered " + want, o.out.res.status === want && o.out.res.sent === 1, J(o.out));
      compareB2("J2", t.label, o, n, t.rec);
    }
  }

  /* J3. G14: making an agent. */
  {
    const SIG = "app.post(\"/api/agents\", requireAuth, requireActiveSubscription, async function (req, res, next) {";
    const T = "route:post /api/agents";
    const run = (w, s) => runRoute(w, "agents", SIG, ["getUserPlan", "AGENT_SYSTEM_PROMPTS"], {
      respond: function (q) {
        if (q.table === "ai_agents" && q.opts && q.opts.head) return s.countError ? { data: null, count: null, error: { message: "count failed" } } : { data: null, count: s.count || 0, error: null };
        return null;
      },
      globals: { getUserPlan: planOf(s.plan || SUBSCRIBED), AGENT_SYSTEM_PROMPTS: { seo: "x", sales: "x", content: "x", social: "x", ads: "x" } }
    }, { user: { id: MEMBER, role: "user" }, body: Object.assign({ type: "seo", display_name: "Mine" }, s.body || {}) });
    const rec = (outcome, code, facts) => [{ action: "route_access", target: T, outcome: outcome, results: [code ? ["G14", "fail", code] : ["G14", "pass"]], facts: facts }];
    const CASES = [
      { label: "an unknown agent type (400)", s: { body: { type: "ghost" } }, rec: [] },
      { label: "not subscribed (403)", s: { plan: LAPSED }, rec: rec("blocked", "subscription_required", { agent: "seo" }) },
      { label: "not in the plan (403)", s: { body: { type: "ads" } }, rec: rec("blocked", "not_in_plan", { agent: "ads" }) },
      { label: "the agent limit reached (403)", s: { count: 3 }, rec: rec("blocked", "agent_limit_reached", { agent: "seo" }) },
      { label: "the count unreadable (next(error))", s: { countError: true }, rec: [{ action: "route_access", target: T, outcome: "blocked", results: [["G14", "fail", "gate_error"]] }] },
      { label: "made (201)", s: {}, rec: rec("ran", null, { agent: "seo" }) }
    ];
    for (const t of CASES) {
      const o = await run("b1", t.s), n = await run("new", t.s);
      const want = Number((/\((\d{3})\)/.exec(t.label) || [])[1]) || null;
      check("J3 " + t.label + ": " + (want ? "answered " + want : "passed to next(error)"), want ? o.out.res.status === want && o.out.res.sent === 1 : o.out.next.length === 1 && o.out.next[0].thrown === true, J(o.out));
      compareB2("J3", t.label, o, n, t.rec);
    }
  }

  /* J4. G8 and G7: filing a Bluesky post. */
  const PROPOSE_SIG = "app.post(\"/api/agents/social/propose-post\", requireAuth, requireActiveSubscription, aiLimiter,";
  {
    const TASK = "d1000000-0000-4000-8000-0000000000d1";
    const SEG = new Intl.Segmenter("en", { granularity: "grapheme" });
    const run = (w, s) => runRoute(w, "propose", PROPOSE_SIG, ["blueskyPostingAccount", "GRAPHEME_SEGMENTER", "autoExecuteFiledProposal", "PROPOSAL_EXECUTORS"], {
      respond: function (q) {
        if (q.table === "ai_tasks") return { data: s.task === undefined ? { id: TASK, task_type: "social/post", status: "completed", output: { platform: "bluesky", post: s.text || "A calm morning at the shop." } } : s.task, error: null };
        if (q.table === "social_post_drafts" && q.op === "insert") return { data: null, error: { message: "drafts refused in this check" } };
        return null;
      },
      globals: { blueskyPostingAccount: async () => ({ kind: s.account || "member", row: { auto_post: false }, handle: "me.bsky.social" }), GRAPHEME_SEGMENTER: s.noSegmenter ? null : SEG,
        autoExecuteFiledProposal: async () => { throw new Error("not reached in this check"); }, PROPOSAL_EXECUTORS: {} }
    }, { user: { id: MEMBER, role: "user" }, body: { task_id: s.taskId || TASK } });
    const facts = { action_type: "publish_social_post", agent: "social", channel: "bluesky", approved: false };
    const rec = (results, target) => [{ action: "social_post", target: target || "ai_task:" + TASK, outcome: results.some(r => r[1] === "fail") ? "blocked" : "ran", results: results, facts: facts }];
    const CASES = [
      { label: "no account to post from (403)", s: { account: "none" }, rec: [] },
      { label: "the account needs reconnecting (409)", s: { account: "needs_reconnect" }, rec: [] },
      { label: "graphemes cannot be counted (503)", s: { noSegmenter: true }, rec: rec([["G8", "fail", "graphemes_uncountable"], ["G7", "not_reached"]], "ai_task:none") },
      { label: "no such run (404)", s: { task: null }, rec: [] },
      { label: "over 300 graphemes (400)", s: { text: "a".repeat(301) }, rec: rec([["G8", "fail", "over_grapheme_limit"], ["G7", "not_reached"]]) },
      { label: "the claims screen refuses (400)", s: { text: "This tea cures cancer and diabetes, guaranteed." }, rec: rec([["G8", "pass"], ["G7", "fail", "claims_screen"]]), claims: true },
      { label: "both pass, then the draft write fails (next(error))", s: {}, rec: rec([["G8", "pass"], ["G7", "pass"]]) }
    ];
    for (const t of CASES) {
      const o = await run("b1", t.s), n = await run("new", t.s);
      const want = Number((/\((\d{3})\)/.exec(t.label) || [])[1]) || null;
      check("J4 " + t.label + ": " + (want ? "answered " + want : "passed to next(error)") + (t.claims ? " with code claims_screen" : ""),
        (want ? o.out.res.status === want && o.out.res.sent === 1 : o.out.next.length === 1) && (!t.claims || (o.out.res.body && o.out.res.body.code === "claims_screen")), J(o.out).slice(0, 300));
      compareB2("J4", t.label, o, n, t.rec);
    }
  }

  /* J5. G23 and G22: outreach. */
  {
    const constOf = name => vm.runInNewContext("(" + DEFS.new.get(name).replace(new RegExp("^(var|const|let) " + name + "\\s*=\\s*"), "").replace(/;\s*$/, "") + ")");
    const BOOK = constOf("OUTREACH_BOOK_PRODUCT");
    const lead = { author_handle: "reader.bsky.social", post_uri: "at://x/1", suggested_product: BOOK, post_text: "Any book on this?", outreach_safe: true };
    const runLead = async (w, s) => {
      const c = makeCtx({ globals: { canSendOutreach: async () => JSON.parse(JSON.stringify(s.gate)), callAnthropicText: async () => { throw new Error("no model in this check"); } } });
      script(w, "lead", DEFS[w].get("convertSingleLead"), ["canSendOutreach", "callAnthropicText"], "convertSingleLead").runInContext(c.sandbox);
      const out = await capture(() => c.sandbox.__api.convertSingleLead(MEMBER, JSON.parse(JSON.stringify(s.lead || lead)), "SYSTEM", s.dryRun === true));
      await flush();
      return { out: out, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows };
    };
    const facts = { agent: "sales" };
    const LEADS = [
      { label: "a lead with no offer (skipped first)", s: { lead: Object.assign({}, lead, { suggested_product: "nothing" }), gate: { allowed: true } }, rec: [] },
      { label: "a dry run (never gated)", s: { dryRun: true, gate: { allowed: false, reason: "daily_cap_reached" } }, rec: [] },
      { label: "the daily cap reached (skipped)", s: { gate: { allowed: false, reason: "daily_cap_reached" } },
        rec: [{ action: "outreach_send", target: "lead", outcome: "blocked", results: [["G23", "pass"], ["G22", "fail", "daily_cap_reached"]], facts: facts }] },
      { label: "already contacted (skipped)", s: { gate: { allowed: false, reason: "already_contacted" } },
        rec: [{ action: "outreach_send", target: "lead", outcome: "blocked", results: [["G23", "pass"], ["G22", "fail", "already_contacted"]], facts: facts }] },
      { label: "allowed, then drafting", s: { gate: { allowed: true } }, rec: [{ action: "outreach_send", target: "lead", outcome: "ran", results: [["G23", "pass"], ["G22", "pass"]], facts: facts }] }
    ];
    for (const t of LEADS) { const o = await runLead("b1", t.s), n = await runLead("new", t.s); compareB2("J5", t.label, o, n, t.rec); }
    const SIG = "app.post(\"/api/agents/sales/convert\", requireAuth, requireActiveSubscription, aiLimiter, async function (req, res, next) {";
    const fresh = new FixedDate(FIXED - 2 * 24 * 3600 * 1000).toISOString();
    const leadRow = o => Object.assign({ post_uri: "at://x/2", intent_score: 8, intent_reason: "asked", status: "scored", post_created_at: fresh, outreach_safe: true, reply_invited: true }, o);
    const runConvert = (w, s) => runRoute(w, "convert", SIG, ["convertSingleLead"], {
      respond: function (q) { if (q.table === "bsky_leads") return { data: s.lead, error: null }; return null; },
      globals: { convertSingleLead: async () => ({ conversion: null, sent: false, send_reason: "stubbed", skipped: true }) }
    }, { user: { id: s.user || OWNER_ID, role: "admin" }, body: { lead_post_uri: "at://x/2" } });
    const CONVERT = [
      { label: "the convert route, not the credential owner (403)", s: { user: MEMBER, lead: leadRow({}) }, rec: [] },
      { label: "the convert route, a lead never screened (422)", s: { lead: leadRow({ outreach_safe: null }) },
        rec: [{ user: OWNER_ID, action: "outreach_send", target: "lead", outcome: "blocked", results: [["G23", "fail", "not_screened"], ["G22", "not_reached"]], facts: facts }] },
      { label: "the convert route, an unsuitable recipient (422)", s: { lead: leadRow({ outreach_safe: false }) },
        rec: [{ user: OWNER_ID, action: "outreach_send", target: "lead", outcome: "blocked", results: [["G23", "fail", "unsafe_recipient"], ["G22", "not_reached"]], facts: facts }] },
      { label: "the convert route, suitable but replies not invited (422)", s: { lead: leadRow({ reply_invited: false }) }, rec: [] }
    ];
    for (const t of CONVERT) {
      const o = await runConvert("b1", t.s), n = await runConvert("new", t.s);
      const want = Number((/\((\d{3})\)/.exec(t.label) || [])[1]);
      check("J5 " + t.label + ": answered " + want, o.out.res.status === want && o.out.res.sent === 1, J(o.out).slice(0, 300));
      compareB2("J5", t.label, o, n, t.rec);
    }
  }

  /* J6. G24: BizCash transfers and support. The body that decides is the old one, renamed. */
  {
    const oldBody = DEFS.b1.get("bfcSendWithinLimits"), newBody = DEFS.new.get("bfcSendWithinLimitsSteps") || "";
    check("J6. bfcSendWithinLimitsSteps is " + B1_HEAD + "'s bfcSendWithinLimits, byte for byte, under a new name",
      !!oldBody && newBody.replace("async function bfcSendWithinLimitsSteps(", "async function bfcSendWithinLimits(") === oldBody);
    const calls = s => (s.match(/bfcSendWithinLimits\(/g) || []).length;
    check("J6. every caller still calls bfcSendWithinLimits, as many as before", calls(B1_SRC) === calls(NEW), calls(B1_SRC) + " vs " + calls(NEW));
    const STEPS = [
      { label: "a limit refusal (429)", support: false, fn: (req, res) => { res.status(429).json({ error: "Daily limit reached.", reason: "daily_limit_reached" }); },
        rec: [["G24", "fail", "daily_limit_reached"]], outcome: "blocked" },
      { label: "a support refusal (403)", support: true, fn: (req, res) => { res.status(403).json({ error: "Support is off.", reason: "support_disabled" }); },
        rec: [["G24", "fail", "support_disabled"]], outcome: "blocked" },
      { label: "sent (200)", support: false, fn: (req, res) => { res.json({ ok: true, transfer_id: 7 }); return "done"; }, rec: [["G24", "pass"]], outcome: "ran" },
      { label: "the steps throwing", support: false, fn: () => { throw new Error("rpc down"); }, rec: [["G24", "fail", "gate_error"]], outcome: "blocked" }
    ];
    for (const t of STEPS) {
      const direct = async () => { const res = makeRes(); const ownBefore = Object.prototype.hasOwnProperty.call(res, "json"); const jsonBefore = res.json;
        const r = await capture(() => t.fn({ user: { id: MEMBER } }, res, { support: t.support })); return { r: r, res: resShape(res), restored: ownBefore && res.json === jsonBefore }; };
      const c = makeCtx({ globals: { bfcSendWithinLimitsSteps: async (req, res, send) => t.fn(req, res, send) } });
      script("new", "bfc", DEFS.new.get("bfcSendWithinLimits"), ["bfcSendWithinLimitsSteps"], "bfcSendWithinLimits").runInContext(c.sandbox);
      const res = makeRes(); const jsonBefore = res.json;
      const r = await capture(() => c.sandbox.__api.bfcSendWithinLimits({ user: { id: MEMBER } }, res, { support: t.support }));
      await flush();
      const o = await direct();
      check("J6 " + t.label + ": the wrapper answers, returns and throws exactly what the steps do, and puts res.json back",
        J({ r: o.r, res: o.res }) === J({ r: r, res: resShape(res) }) && res.json === jsonBefore && o.restored, J(o) + " | " + J({ r: r, res: resShape(res) }));
      const want = [{ user_id: MEMBER, action: "bfc_transfer", target: "wallet:" + (t.support ? "support" : "transfer"), outcome: t.outcome, results: res3(t.rec), facts: null, member_gate_name: null }];
      check("D J6 " + t.label + ": one record, " + t.outcome, J(c.db.gateRows.map(recordOf)) === J(want), J(c.db.gateRows));
    }
  }

  /* J7. G25: the guide's own refusals, recorded around its unchanged handler. */
  {
    const reg = s => { const i = s.indexOf("app.post(\"/api/guide/ask\""); return i < 0 ? "" : s.slice(i, s.indexOf(");\n", i) + 2); };
    check("J7. the guide route is " + B1_HEAD + "'s, with the handler wrapped by guideAskRecorded and nothing else changed",
      reg(B1_SRC).length > 0 && reg(NEW).replace("guideAskRecorded(guideAsk.createGuideAskHandler({", "guideAsk.createGuideAskHandler({").replace("})));", "}));") === reg(B1_SRC), reg(NEW).slice(0, 200));
    const T = "route:post /api/guide/ask";
    const HANDLERS = [
      { label: "the guide's daily limit (429)", fn: (req, res) => { res.status(429).json({ error: "You have asked the guide enough today.", reason: "guide_daily_limit" }); }, rec: [["G25", "fail", "guide_daily_limit"]] },
      { label: "the guide's count unreadable (503)", fn: (req, res) => { res.status(503).json({ error: "The guide could not count.", reason: "guide_count_unreadable" }); }, rec: [["G25", "fail", "guide_count_unreadable"]] },
      { label: "an answer with steps (200)", fn: (req, res) => { res.json({ known: true, steps: [{ page: "/billing.html" }] }); }, rec: [["G25", "pass"]] },
      { label: "no known answer (200)", fn: (req, res) => { res.json({ known: false, steps: [] }); }, rec: [["G25", "pass"]] },
      { label: "a model-call limit after the guide let it through (429)", fn: (req, res) => { res.status(429).json({ error: "Daily limit.", reason: "DAILY_MODEL_CALL_LIMIT" }); }, rec: [["G25", "pass"]] },
      { label: "an unreadable question (400)", fn: (req, res) => { res.status(400).json({ error: "Ask a question." }); }, rec: null },
      { label: "the handler throwing", fn: () => { throw new Error("guide broke"); }, rec: null },
      { label: "the handler passing an error on", fn: (req, res, next) => { next(new Error("guide failed")); }, rec: null },
      { label: "no signed-in user", fn: (req, res) => { res.status(429).json({ error: "x", reason: "guide_daily_limit" }); }, rec: null, noUser: true }
    ];
    for (const t of HANDLERS) {
      const req = t.noUser ? { body: { q: "where is billing" } } : { user: { id: MEMBER }, body: { q: "where is billing" } };
      const runOld = async () => { const res = makeRes(); const nexts = []; const r = await capture(() => t.fn(req, res, e => nexts.push(errShape(e)))); return { r: r, res: resShape(res), next: nexts }; };
      const c = makeCtx({});
      script("new", "guide", DEFS.new.get("guideAskRecorded"), [], "guideAskRecorded").runInContext(c.sandbox);
      const res = makeRes(); const jsonBefore = res.json; const nexts = [];
      const r = await capture(() => c.sandbox.__api.guideAskRecorded(async (a, b, cnext) => t.fn(a, b, cnext))(req, res, e => nexts.push(errShape(e))));
      await flush();
      const o = await runOld();
      check("J7 " + t.label + ": the answer, the error and next() are exactly the handler's, and res.json is put back",
        J(o) === J({ r: r, res: resShape(res), next: nexts }) && res.json === jsonBefore, J(o) + " | " + J({ r: r, res: resShape(res), next: nexts }));
      const want = t.rec ? [{ user_id: MEMBER, action: "route_access", target: T, outcome: t.rec[0][1] === "fail" ? "blocked" : "ran", results: res3(t.rec), facts: null, member_gate_name: null }] : [];
      check("D J7 " + t.label + ": " + (t.rec ? "one record" : "no record"), J(c.db.gateRows.map(recordOf)) === J(want), J(c.db.gateRows));
    }
  }

  /* J8. G18, G16, G13: the schedule pass. */
  const NOW = new FixedDate("2026-10-15T15:00:00.000Z");
  const sched = (n, user, agent, o) => Object.assign({ id: UUID(n), user_id: user, agent_type: agent, task_type: "general", prompt: "Plan the week", cadence: "daily", hour_utc: 15,
    day_of_week: null, day_of_month: null, enabled: true, last_run_on: null, paused: false, consecutive_failures: 0 }, o || {});
  const PLANS = { [MEMBER]: SUBSCRIBED, [MEMBER_B]: SUBSCRIBED, [MEMBER_C]: "throws", [MEMBER_D]: LAPSED,
    [OWNER_ID]: { active: true, exempt: true, access_reason: "owner", plan: "all_access", config: {} } };
  async function passRun(w, s) {
    const ran = [];
    const store = memStore({ member_gates: JSON.parse(JSON.stringify(s.gates || [])) });
    const c = makeCtx({
      respond: function (q) {
        if (q.table === "agent_schedules" && q.op === "select") return { data: JSON.parse(JSON.stringify(s.rows)), error: null };
        if (q.table === "agent_autonomy") return { data: s.autonomy, error: null };
        if (q.table === "member_gates") return s.gatesError ? { data: null, error: { message: "relation \"public.member_gates\" does not exist" } } : store(q);
        return null;
      },
      globals: {
        getUserPlan: async function (u) { const p = PLANS[u]; if (p === "throws") throw new Error("plan read failed"); return JSON.parse(JSON.stringify(p || LAPSED)); },
        runScheduledAgentTask: async function (row) { ran.push(row.id); return row.agent_type === "content" ? { ok: false, error: new Error("queue full") } : { ok: true, payload: { task: { id: "t-" + row.id.slice(-2) } } }; },
        opsAlerts: { scheduleAutoPaused: async () => {} },
        AGENT_SYSTEM_PROMPTS: { seo: "x", sales: "x", content: "x" }
      }
    });
    script(w, "pass", DEFS[w].get("runAgentSchedulePass"), ["getUserPlan", "runScheduledAgentTask", "AGENT_SYSTEM_PROMPTS"], "runAgentSchedulePass").runInContext(c.sandbox);
    const out = await capture(() => c.sandbox.__api.runAgentSchedulePass(NOW, s.max || 10));
    await flush();
    return { out: out, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows, extra: ran };
  }
  const autonomyAll = [MEMBER, MEMBER_B, MEMBER_C, MEMBER_D, OWNER_ID].reduce((a, u) => a.concat(["seo", "sales", "content", "ghost"].map(t => ({ user_id: u, agent_type: t }))), []);
  const sfacts = agent => ({ action_type: "agent_task", agent: agent, channel: "agent", approved: false });
  const PASS_ROWS = [
    sched(1, MEMBER, "seo", { paused: true }),
    sched(2, MEMBER_B, "seo"),
    sched(3, MEMBER, "ghost"),
    sched(4, MEMBER_C, "seo"),
    sched(5, MEMBER_D, "seo"),
    sched(6, MEMBER, "seo"),
    sched(7, OWNER_ID, "sales"),
    sched(8, MEMBER, "content"),
    sched(9, MEMBER, "sales", { hour_utc: 9 })
  ];
  const AUT = autonomyAll.filter(a => !(a.user_id === MEMBER_B && a.agent_type === "seo"));
  const passRecords = [
    { user: MEMBER, action: "schedule_run", target: "schedule:" + UUID(1), outcome: "blocked", results: [["G18", "fail", "schedule_paused"], ["G16", "not_reached"], ["G13", "not_reached"]], facts: sfacts("seo") },
    { user: MEMBER_B, action: "schedule_run", target: "schedule:" + UUID(2), outcome: "blocked", results: [["G18", "pass"], ["G16", "fail", "autonomy_off"], ["G13", "not_reached"]], facts: sfacts("seo") },
    { user: MEMBER_C, action: "schedule_run", target: "schedule:" + UUID(4), outcome: "blocked", results: [["G18", "pass"], ["G16", "pass"], ["G13", "fail", "entitlement_unknown"]], facts: sfacts("seo") },
    { user: MEMBER_D, action: "schedule_run", target: "schedule:" + UUID(5), outcome: "blocked", results: [["G18", "pass"], ["G16", "pass"], ["G13", "fail", "not_entitled"]], facts: sfacts("seo") },
    { user: MEMBER, action: "schedule_run", target: "schedule:" + UUID(6), outcome: "ran", results: [["G18", "pass"], ["G16", "pass"], ["G13", "pass"]], facts: sfacts("seo") },
    { user: OWNER_ID, action: "schedule_run", target: "schedule:" + UUID(7), outcome: "ran", results: [["G18", "pass"], ["G16", "pass"], ["G13", "bypass", "owner_pass"]], facts: sfacts("sales") },
    { user: MEMBER, action: "schedule_run", target: "schedule:" + UUID(8), outcome: "ran", results: [["G18", "pass"], ["G16", "pass"], ["G13", "pass"]], facts: sfacts("content") }
  ];
  {
    const o = await passRun("b1", { rows: PASS_ROWS, autonomy: AUT }), n = await passRun("new", { rows: PASS_ROWS, autonomy: AUT });
    check("J8 the pass: three runs started (6, 7, 8) and the summary counts every skip", J(o.extra) === J([UUID(6), UUID(7), UUID(8)]) && o.out.returned && o.out.returned.launched === 2, J(o.out) + " " + J(o.extra));
    compareB2("J8", "a pass reaching every gate: paused, autonomy off, invalid, plan unreadable, lapsed, ran, the owner, a failing run, not this hour", o, n, passRecords);
    const twoRows = [sched(6, MEMBER, "seo"), sched(10, MEMBER, "sales")];
    const o2 = await passRun("b1", { rows: twoRows, autonomy: AUT, max: 1 }), n2 = await passRun("new", { rows: twoRows, autonomy: AUT, max: 1 });
    compareB2("J8", "the ceiling: the second schedule is never reached, so never recorded", o2, n2, [passRecords[4]]);
    const o3 = await passRun("b1", { rows: PASS_ROWS, autonomy: AUT }), n3 = await passRun("new", { rows: PASS_ROWS, autonomy: AUT, gatesError: true });
    compareB2("J8", "the member gates unreadable: the pass is unchanged", o3, n3, passRecords);
    check("J8 the member gates unreadable: logged as not read, the platform's decision standing", n3.logs.some(l => /\[member-gates\] not read \(schedule_run\): .*The platform's decision stands\./.test(l)), J(n3.logs.filter(l => /member/.test(l))));
  }

  /* J9. G17: a proposal carried out automatically. */
  const PROPOSAL = { id: PID, user_id: MEMBER, agent_type: "social", action_type: "publish_social_post", cost_amount: 0, status: "pending", payload: { text: "hi" } };
  async function autoRun(w, s) {
    const seen = [];
    const store = memStore({ member_gates: JSON.parse(JSON.stringify(s.gates || [])) });
    const c = makeCtx({
      respond: function (q) {
        if (q.table === "member_gates") return store(q);
        if (q.table === "agent_proposals" && q.op === "update" && q.payload.status === "executing") return { data: s.claimed === false ? null : Object.assign({}, PROPOSAL, { status: "executing" }), error: null };
        if (q.table === "agent_proposals" && q.op === "update") return { data: Object.assign({}, PROPOSAL, q.payload), error: null };
        return null;
      }
    });
    script(w, "autoexec", DEFS[w].get("autoExecuteFiledProposal"), [], "autoExecuteFiledProposal").runInContext(c.sandbox);
    const exec = async row => { seen.push(row.id); if (s.execThrows) throw new Error("bluesky down"); return { uri: "at://post/1" }; };
    const out = await capture(() => c.sandbox.__api.autoExecuteFiledProposal(JSON.parse(JSON.stringify(PROPOSAL)), exec));
    await flush();
    return { out: out, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows, extra: seen };
  }
  const autoFacts = { action_type: "publish_social_post", agent: "social", channel: "bluesky", approved: false };
  {
    const rec = [{ action: "proposal_auto_execute", target: "proposal:" + PID, outcome: "ran", results: [["G17", "pass", "automation_on"]], facts: autoFacts }];
    for (const t of [{ label: "carried out", s: {} }, { label: "no longer pending", s: { claimed: false } }, { label: "the executor throwing", s: { execThrows: true } }]) {
      const o = await autoRun("b1", t.s), n = await autoRun("new", t.s);
      compareB2("J9", t.label, o, n, rec);
    }
  }

  /* ═══ K. the rule language refuses everything outside it ═════════════════ */
  console.log("\n══ K. lib/gateRules.js: a closed language ══");
  {
    const v = (rule, scope) => RULES.validateRule(rule, scope || "any");
    const leaf = (f, op, value) => ({ field: f, op: op, value: value });
    const refusedAt = (label, rule, scope, pathRe) => { const r = v(rule, scope); check("K " + label + ": refused", r.ok === false && typeof r.error === "string" && (!pathRe || pathRe.test(r.path)), J(r)); };
    refusedAt("an unknown field (price)", leaf("price", "eq", 5), "proposal_approve", /\.field$/);
    refusedAt("an unknown field (__proto__)", JSON.parse("{\"field\":\"__proto__\",\"op\":\"eq\",\"value\":1}"), "any", /\.field$/);
    refusedAt("a field outside its scope (amount on a schedule)", leaf("amount", "lt", 5), "schedule_run", /\.field$/);
    refusedAt("an unknown comparator (like)", leaf("agent", "like", "seo"), "any", /\.op$/);
    refusedAt("an unknown comparator (regex)", leaf("agent", "regex", "^s"), "any", /\.op$/);
    refusedAt("a comparator that does not fit (approved below)", leaf("approved", "lt", true), "any", /\.op$/);
    refusedAt("free text as a value (agent \"seo; drop table\")", leaf("agent", "eq", "seo; drop table"), "any", /\.value$/);
    refusedAt("an object as a value ($regex)", leaf("agent", "eq", { $regex: "s.*" }), "any", /\.value$/);
    refusedAt("code as a value (a function)", leaf("hour", "eq", function () { return 1; }), "any", /\.value$/);
    refusedAt("a string as the rule", "approved == true", "any");
    refusedAt("an array as the rule", [leaf("approved", "eq", true)], "any");
    refusedAt("a condition with a fourth key", Object.assign(leaf("approved", "eq", true), { note: "x" }), "any");
    refusedAt("a group with a second key", { all: [leaf("approved", "eq", true)], any: [leaf("approved", "eq", true)] }, "any");
    refusedAt("an empty group", { all: [] }, "any");
    refusedAt("an hour of 24", leaf("hour", "eq", 24), "any", /\.value$/);
    refusedAt("an hour of 1.5", leaf("hour", "eq", 1.5), "any", /\.value$/);
    refusedAt("between, high first", leaf("hour", "between", [20, 9]), "any", /\.value$/);
    refusedAt("a list naming a value twice", leaf("weekday", "in", ["mon", "mon"]), "any", /\.value\[1\]$/);
    refusedAt("a list of 11", leaf("hour", "in", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), "any", /\.value$/);
    let deep = leaf("approved", "eq", true); for (let i = 0; i < 4; i++) deep = { not: deep };
    refusedAt("five levels deep", deep, "any");
    let ok4 = leaf("approved", "eq", true); for (let i = 0; i < 3; i++) ok4 = { not: ok4 };
    check("K four levels deep: accepted", v(ok4).ok === true, J(v(ok4)));
    const wide = n => ({ all: Array.from({ length: n }, (x, i) => leaf("hour", "neq", i)) });
    refusedAt("13 conditions in one group", wide(13), "any");
    check("K 12 conditions: accepted", v(wide(12)).ok === true);
    refusedAt("13 conditions across groups", { any: [wide(7), wide(6)] }, "any");
    refusedAt("over 4096 bytes", { all: [leaf("weekday", "in", ["mon"])].concat([{ field: "agent", op: "in", value: ["seo"], pad: "x".repeat(5000) }]) }, "any");
    refusedAt("an unknown scope", leaf("approved", "eq", true), "everything", /^scope$/);
    const good = { all: [leaf("approved", "eq", true), leaf("weekday", "in", ["mon", "tue", "wed", "thu", "fri"]), { not: leaf("hour", "gt", 21) }] };
    const g = v(good);
    check("K a good rule is accepted as a clean copy", g.ok === true && J(g.rule) === J(good) && g.rule !== good && g.rule.all[1].value !== good.all[1].value);
    check("K its summary: \"Go ahead only if approved AND on a weekday AND NOT after 22:00\"", RULES.summarize(good, "any") === "Go ahead only if approved AND on a weekday AND NOT after 22:00", RULES.summarize(good, "any"));
    check("K a summary is empty for a rule that does not validate", RULES.summarize(leaf("price", "eq", 1), "any") === "");
    check("K names: letters, digits, spaces and . , ' ( ) & : - only, 1 to 60",
      RULES.validateName("Weekdays only").ok && RULES.validateName("  Trim me  ").name === "Trim me" && !RULES.validateName("<script>").ok && !RULES.validateName("").ok &&
      !RULES.validateName("x".repeat(61)).ok && RULES.validateName("x".repeat(60)).ok && !RULES.validateName("Stop \"now\"").ok && !RULES.validateName(42).ok);
    check("K time zones: UTC and known IANA names only",
      RULES.isTimeZone("UTC") && RULES.isTimeZone("America/New_York") && !RULES.isTimeZone("Mars/Olympus") && !RULES.isTimeZone("UTC; drop") && !RULES.isTimeZone(""));
    const code = FILES.rules.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
    check("K nothing in the language is evaluated as code or a pattern: no eval, Function, new RegExp, require, process or with",
      !/\beval\(|\bFunction\(|new RegExp|\brequire\(|\bprocess\.|\bwith \(/.test(code));
    check("K evaluation is three-valued: a missing fact is never read as yes",
      RULES.evaluateRule(leaf("amount", "lt", 5), {}) === null && RULES.evaluateRule({ not: leaf("amount", "lt", 5) }, {}) === null &&
      RULES.evaluateRule({ any: [leaf("amount", "lt", 5), leaf("approved", "eq", true)] }, { approved: true }) === true);
    const blk = RULES.firstBlock([{ id: "g1", name: "Needs an amount", scope: "proposal_approve", rule: leaf("amount", "lt", 5), time_zone: "UTC", enabled: true }], "proposal_approve", {}, FIXED);
    check("K a gate whose fact is missing blocks (act only if shown to hold)", blk && blk.name === "Needs an amount", J(blk));
    check("K the language served is exactly the library's", J(RULES.language().fields.hour) === J({ type: "int", label: "the hour (your time zone)", min: 0, max: 23, comparators: ["eq", "neq", "in", "not_in", "lt", "lte", "gt", "gte", "between"] }));
  }

  /* ═══ L. PROPERTY: a member gate never turns a fail into a pass ══════════ */
  console.log("\n══ L. PROPERTY: random rules and decisions; a member gate only adds restrictions ══");
  function rng(seed) { let a = seed >>> 0; return function () { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
  const pick = (r, list) => list[Math.floor(r() * list.length)];
  function randomLeaf(r, scope) {
    const f = pick(r, RULES.SCOPE_FIELDS[scope]); const spec = RULES.FIELDS[f];
    const op = pick(r, Object.keys(RULES.COMPARATORS).filter(c => RULES.COMPARATORS[c].types.indexOf(spec.type) !== -1));
    const one = () => spec.type === "enum" ? pick(r, spec.values) : spec.type === "bool" ? r() < 0.5 : spec.type === "int" ? Math.floor(r() * 24) : Math.floor(r() * 1000);
    if (op === "in" || op === "not_in") { const out = []; const n = 1 + Math.floor(r() * 3); for (let i = 0; i < n; i++) { const x = one(); if (out.indexOf(x) === -1) out.push(x); } return { field: f, op: op, value: out }; }
    if (op === "between") { const a = one(), b = one(); return { field: f, op: op, value: [Math.min(a, b), Math.max(a, b)] }; }
    return { field: f, op: op, value: one() };
  }
  function randomRule(r, scope, depth) {
    if (depth >= 3 || r() < 0.35) return randomLeaf(r, scope);
    const k = r(); if (k < 0.2) return { not: randomRule(r, scope, depth + 1) };
    const parts = []; const n = 1 + Math.floor(r() * 3); for (let i = 0; i < n; i++) parts.push(randomRule(r, scope, depth + 1));
    return k < 0.6 ? { all: parts } : { any: parts };
  }
  function randomFacts(r) {
    const f = {};
    if (r() < 0.9) f.action_type = pick(r, RULES.ACTION_TYPES);
    if (r() < 0.9) f.agent = pick(r, RULES.AGENTS);
    if (r() < 0.9) f.channel = pick(r, RULES.CHANNELS);
    if (r() < 0.9) f.approved = r() < 0.5;
    if (r() < 0.7) f.amount = Math.floor(r() * 1000);
    return f;
  }
  {
    const r = rng(20261101);
    let platformFails = 0, flipped = 0, ranBlocked = 0, wrongName = 0, unchangedWithout = 0, total = 0;
    const actions = Object.keys(GATES.ACTION_GATES);
    for (let i = 0; i < 4000; i++) {
      const action = pick(r, actions); const obs = {};
      GATES.ACTION_GATES[action].forEach(g => { const k = r(); if (k < 0.55) obs[g] = { result: "pass" }; else if (k < 0.8) obs[g] = { result: "fail", code: "x_" + Math.floor(r() * 9) }; else if (k < 0.9) obs[g] = { result: "bypass", code: "owner_pass" }; });
      const d = GATES.evaluate(action, { observed: obs });
      const scope = pick(r, RULES.SCOPES);
      const rule = randomRule(r, scope, 1);
      const gate = { id: "g" + i, name: "Gate " + i, scope: scope, rule: rule, time_zone: pick(r, ["UTC", "America/New_York", "Asia/Tokyo"]), enabled: true };
      const block = RULES.firstBlock([gate], scope, randomFacts(r), FIXED + Math.floor(r() * 7 * 24) * 3600000);
      const m = GATES.withMemberGate(d, block);
      total++;
      if (d.outcome !== "ran") { platformFails++; if (J(m) !== J(d)) flipped++; }
      else if (block) { ranBlocked++; if (m.outcome !== "blocked" || !m.member || m.member.name !== block.name || J(m.results) !== J(d.results)) wrongName++; }
      else if (J(m) !== J(d)) unchangedWithout++;
    }
    check("L1. over " + total + " random decisions and rules: a platform fail (" + platformFails + " of them) is returned exactly as it was, never ran", flipped === 0 && platformFails > 500, flipped + " changed");
    check("L2. a pass a member gate stops (" + ranBlocked + ") becomes blocked under that gate's own name, the platform results untouched", wrongName === 0 && ranBlocked > 100, wrongName + " wrong");
    check("L3. with no member gate blocking, the decision is unchanged", unchangedWithout === 0);
    let agree = 0, disagree = 0, invalid = 0;
    for (let i = 0; i < 3000; i++) {
      const scope = pick(r, RULES.SCOPES); const rule = randomRule(r, scope, 1); const checked = RULES.validateRule(rule, scope);
      if (!checked.ok) { invalid++; continue; }
      const facts = randomFacts(r); const ms = FIXED + Math.floor(r() * 7 * 24) * 3600000;
      const holds = RULES.evaluateRule(checked.rule, Object.assign({}, facts, RULES.factsAt(ms, "UTC")));
      const b = RULES.firstBlock([{ id: "x", name: "X", scope: scope, rule: rule, time_zone: "UTC", enabled: true }], scope, facts, ms);
      if ((holds === true) === (b === null)) agree++; else disagree++;
    }
    check("L4. a gate blocks exactly when its rule is not shown to hold (" + agree + " random rules, " + invalid + " too large and refused)", disagree === 0 && agree > 1500, disagree + " disagreed");
    const neverRan = GATES.withMemberGate({ action: "dispatch", outcome: "blocked", results: [] }, { id: "g", name: "Always" });
    check("L5. a blocked decision with a blocking gate stays blocked with no member named", neverRan.outcome === "blocked" && !neverRan.member);
    const held = GATES.withMemberGate({ action: "task_run", outcome: "held_for_approval", results: [] }, { id: "g", name: "Always" });
    check("L6. a held decision stays held", held.outcome === "held_for_approval" && !held.member);
  }

  /* ═══ M. a member gate blocks under its own name ═════════════════════════ */
  console.log("\n══ M. a member gate blocks with its own name, and only after the platform let it through ══");
  const WEEKENDS = { id: UUID(901), user_id: MEMBER, name: "Weekends only", scope: "proposal_approve", rule: { field: "weekday", op: "in", value: ["sat", "sun"] }, time_zone: "UTC", enabled: true, created_at: "2026-10-01T00:00:00Z" };
  const THURSDAYS = Object.assign({}, WEEKENDS, { id: UUID(902), name: "Thursdays fine", rule: { field: "weekday", op: "eq", value: "thu" } });
  async function approveB2(w, s) {
    const executed = [];
    const store = memStore({ member_gates: JSON.parse(JSON.stringify(s.gates || [])) });
    const c = makeCtx({
      respond: function (q) {
        if (q.table === "member_gates") return s.gatesError ? { data: null, error: { message: "read failed" } } : store(q);
        if (q.table === "agent_proposals" && q.op === "select") return { data: s.pending || null, error: null };
        if (q.table === "agent_proposals" && q.op === "update" && q.payload.status === "executing") return { data: s.claim || null, error: null };
        if (q.table === "agent_proposals" && q.op === "update") return { data: Object.assign({}, s.claim, q.payload), error: null };
        if (q.table === "ai_agents" && q.op === "select") return { data: { id: "agent-1", tasks_completed: 4 }, error: null };
        return null;
      },
      globals: {
        getUserPlan: async () => ({ active: !!s.subscribed, inactive_reason: s.subscribed ? null : "no_subscription" }),
        requireAuth: function requireAuth() {},
        PROPOSAL_EXECUTORS: { publish_blog_post: async row => { executed.push(row.id); return { published: true }; }, calendar_type: async row => { executed.push(row.id); return { ok: 1 }; } }
      }
    });
    const grab = function () { c.handler = arguments[arguments.length - 1]; };
    c.sandbox.app = { post: grab };
    script(w, "approveB2", routeSource(w, APPROVE), ["getUserPlan", "PROPOSAL_EXECUTORS"], "x: 1").runInContext(c.sandbox);
    const res = makeRes(); const nexts = [];
    await c.handler({ params: { id: PID }, user: { id: MEMBER, role: "user" }, body: {} }, res, function (e) { nexts.push(e === undefined ? "next()" : errShape(e)); });
    await flush();
    return { out: { res: resShape(res), next: nexts }, logs: c.logs, writes: c.db.writes, gateRows: c.db.gateRows, extra: executed };
  }
  const claimRow = { id: PID, user_id: MEMBER, agent_type: "seo", action_type: "publish_blog_post", status: "executing", payload: {} };
  const approvedFacts = { action_type: "publish_blog_post", agent: "seo", channel: "blog", approved: true };
  {
    const ok = { pending: { action_type: "publish_blog_post" }, subscribed: true, claim: claimRow };
    const n = await approveB2("new", Object.assign({ gates: [WEEKENDS] }, ok));
    const sentence = "Your own gate \"Weekends only\" stopped this (Carry out an approved proposal only if at the weekend). Nothing was done.";
    check("M1. approving on a Thursday with \"Weekends only\": 403, the gate's own name and its plain-English rule",
      n.out.res.status === 403 && J(n.out.res.body) === J({ error: sentence, code: "member_gate", gate: "Weekends only" }), J(n.out));
    check("M1. nothing was carried out, and the proposal went back to pending", n.extra.length === 0 &&
      n.writes.some(x => x.table === "agent_proposals" && x.payload.status === "pending" && x.payload.decided_at === null && x.filters.some(f => f[0] === "eq" && f[1] === "status" && f[2] === "executing")), J(n.writes));
    check("M1. the record: blocked, the platform's G3 and G1 passes kept, the member gate named",
      J(n.gateRows.map(recordOf)) === J([{ user_id: MEMBER, action: "proposal_approve", target: "proposal:" + PID, outcome: "blocked", results: res3([["G3", "pass"], ["G1", "pass", "approved"]]),
        facts: approvedFacts, member_gate_name: "Weekends only" }]) && n.gateRows[0].member_gate_id === WEEKENDS.id, J(n.gateRows));
    const o2 = await approveB2("b1", ok), n2 = await approveB2("new", Object.assign({ gates: [THURSDAYS, Object.assign({}, WEEKENDS, { enabled: false }), Object.assign({}, WEEKENDS, { id: UUID(903), scope: "schedule_run" })] }, ok));
    compareB2("M2", "a gate that holds, a disabled gate and a gate for another scope change nothing", o2, n2,
      [{ action: "proposal_approve", target: "proposal:" + PID, outcome: "ran", results: [["G3", "pass"], ["G1", "pass", "approved"]], facts: approvedFacts }]);
    const o3 = await approveB2("b1", ok), n3 = await approveB2("new", Object.assign({ gatesError: true, gates: [WEEKENDS] }, ok));
    compareB2("M3", "member gates unreadable: the platform's decision stands", o3, n3,
      [{ action: "proposal_approve", target: "proposal:" + PID, outcome: "ran", results: [["G3", "pass"], ["G1", "pass", "approved"]], facts: approvedFacts }]);
    check("M3. …and it says so", n3.logs.some(l => /\[member-gates\] not read \(proposal_approve\): read failed\. The platform's decision stands\./.test(l)), J(n3.logs));
    const other = Object.assign({}, WEEKENDS, { user_id: MEMBER_B });
    const o4 = await approveB2("b1", ok), n4 = await approveB2("new", Object.assign({ gates: [other] }, ok));
    compareB2("M4", "another member's gate is never asked", o4, n4,
      [{ action: "proposal_approve", target: "proposal:" + PID, outcome: "ran", results: [["G3", "pass"], ["G1", "pass", "approved"]], facts: approvedFacts }]);
    // PROPERTY, on the route: every platform refusal is byte-identical with any random member gate present, and names no member gate.
    const r = rng(1101);
    const FAILS = [{ label: "not pending (409)", s: {} }, { label: "not subscribed (402)", s: { pending: { action_type: "publish_blog_post" } } },
      { label: "claimed by another approval (409)", s: { pending: { action_type: "publish_blog_post" }, subscribed: true } },
      { label: "no executor (501)", s: { pending: { action_type: "mystery_type" }, claim: Object.assign({}, claimRow, { action_type: "mystery_type" }) } }];
    let same = 0, diff = [];
    for (let i = 0; i < 24; i++) {
      const t = FAILS[i % FAILS.length];
      const gates = [Object.assign({}, WEEKENDS, { id: UUID(950 + i), name: "Random " + i, rule: randomRule(r, "proposal_approve", 1), scope: pick(r, ["proposal_approve", "any"]) }), WEEKENDS];
      const o = await approveB2("b1", t.s), n = await approveB2("new", Object.assign({ gates: gates }, t.s));
      const ok1 = J({ out: o.out, writes: o.writes, extra: o.extra }) === J({ out: n.out, writes: n.writes, extra: n.extra }) && n.gateRows.every(x => x.member_gate_name === undefined && x.outcome === "blocked");
      if (ok1) same++; else diff.push(t.label);
    }
    check("M5. PROPERTY: 24 platform refusals with random blocking member gates present are identical to " + B1_HEAD + ", and stay the platform's refusal", same === 24, J(diff));
  }
  {
    const gate = { id: UUID(910), user_id: MEMBER, name: "No SEO runs", scope: "schedule_run", rule: { field: "agent", op: "neq", value: "seo" }, time_zone: "UTC", enabled: true, created_at: "2026-10-01T00:00:00Z" };
    const rows = [sched(6, MEMBER, "seo"), sched(10, MEMBER, "sales")];
    const n = await passRun("new", { rows: rows, autonomy: AUT, max: 1, gates: [gate] });
    check("M6. a schedule the member's gate stops is not run, and the next one still runs under a ceiling of 1", J(n.extra) === J([UUID(10)]), J(n.extra));
    const wrote = n.writes.filter(x => x.table === "agent_schedules" && x.filters.some(f => f[2] === UUID(6)));
    check("M6. its row says skipped_member_gate, in the gate's own words, and last_run_on is not set",
      wrote.length === 1 && wrote[0].payload.last_run_status === "skipped_member_gate" && wrote[0].payload.last_error === "Your own gate \"No SEO runs\" stopped this (Run a schedule only if the agent is not seo). Nothing was done." &&
      !("last_run_on" in wrote[0].payload), J(wrote));
    check("M6. the records: the stopped run blocked under \"No SEO runs\", the next one ran",
      J(n.gateRows.map(recordOf)) === J([
        { user_id: MEMBER, action: "schedule_run", target: "schedule:" + UUID(6), outcome: "blocked", results: res3([["G18", "pass"], ["G16", "pass"], ["G13", "pass"]]), facts: sfacts("seo"), member_gate_name: "No SEO runs" },
        { user_id: MEMBER, action: "schedule_run", target: "schedule:" + UUID(10), outcome: "ran", results: res3([["G18", "pass"], ["G16", "pass"], ["G13", "pass"]]), facts: sfacts("sales"), member_gate_name: null }]), J(n.gateRows));
    const lapsedGate = Object.assign({}, gate, { user_id: MEMBER_D, rule: { field: "agent", op: "eq", value: "nothing" } });
    const o2 = await passRun("b1", { rows: PASS_ROWS, autonomy: AUT }), n2 = await passRun("new", { rows: PASS_ROWS, autonomy: AUT, gates: [lapsedGate, Object.assign({}, lapsedGate, { user_id: MEMBER_C }), Object.assign({}, lapsedGate, { user_id: MEMBER_B })] });
    compareB2("M7", "the pass with always-blocking gates on members the platform already stopped", o2, n2, passRecords);
  }
  {
    const gate = { id: UUID(920), user_id: MEMBER, name: "Approve posts myself", scope: "proposal_auto_execute", rule: { field: "approved", op: "eq", value: true }, time_zone: "UTC", enabled: true, created_at: "2026-10-01T00:00:00Z" };
    const n = await autoRun("new", { gates: [gate] });
    check("M8. an automatic run the member's gate stops: nothing claimed, nothing carried out, it waits for approval",
      n.writes.length === 0 && n.extra.length === 0 && n.out.returned && n.out.returned.ok === false &&
      n.out.returned.error === "your own gate \"Approve posts myself\" stopped it (Act automatically only if approved); it waits for your approval", J(n.out) + J(n.writes));
    check("M8. the record: blocked under \"Approve posts myself\"", J(n.gateRows.map(recordOf)) === J([{ user_id: MEMBER, action: "proposal_auto_execute", target: "proposal:" + PID, outcome: "blocked",
      results: res3([["G17", "pass", "automation_on"]]), facts: autoFacts, member_gate_name: "Approve posts myself" }]), J(n.gateRows));
  }

  /* ═══ N. the routes ══════════════════════════════════════════════════════ */
  console.log("\n══ N. the member-gates and gate-decisions routes ══");
  const MG = {
    lang: "app.get(\"/api/member-gates/language\", requireAuth, function (req, res) {",
    list: "app.get(\"/api/member-gates\", requireAuth, requireActiveSubscription, memberGatesLimiter, async function (req, res, next) {",
    make: "app.post(\"/api/member-gates\", requireAuth, requireActiveSubscription, memberGatesLimiter, async function (req, res, next) {",
    edit: "app.put(\"/api/member-gates/:id\", requireAuth, requireActiveSubscription, memberGatesLimiter, async function (req, res, next) {",
    drop: "app.delete(\"/api/member-gates/:id\", requireAuth, requireActiveSubscription, memberGatesLimiter, async function (req, res, next) {",
    preview: "app.post(\"/api/member-gates/preview\", requireAuth, requireActiveSubscription, memberGatesLimiter, async function (req, res, next) {",
    decisions: "app.get(\"/api/gate-decisions\", requireAuth, gateDecisionsLimiter, async function (req, res, next) {",
    forTarget: "app.get(\"/api/gate-decisions/for\", requireAuth, gateDecisionsLimiter, async function (req, res, next) {",
    one: "app.get(\"/api/gate-decisions/:id\", requireAuth, gateDecisionsLimiter, async function (req, res, next) {"
  };
  Object.keys(MG).forEach(k => check("N0. " + k + " is mounted as declared" + (/member-gates", requireAuth, requireActiveSubscription|member-gates\/:id|preview/.test(MG[k]) ? ", with requireActiveSubscription and its limiter" : ""), NEW.indexOf(MG[k]) !== -1));
  const queries = [];
  const T = { member_gates: [], gate_decisions: [] };
  const store = memStore(T);
  async function mgCall(key, req) {
    const c = makeCtx({ respond: function (q) { queries.push(q); return store(q); }, globals: noMw });
    const grab = function () { c.handler = arguments[arguments.length - 1]; };
    c.sandbox.app = { get: grab, post: grab, put: grab, delete: grab };
    script("new", "mg-" + key, routeSource("new", MG[key]), ROUTE_STUBS, "x: 1").runInContext(c.sandbox);
    const res = makeRes(); const nexts = [];
    await c.handler(Object.assign({ user: { id: MEMBER, role: "user" }, params: {}, query: {}, body: {} }, JSON.parse(JSON.stringify(req || {}))), res, e => nexts.push(errShape(e)));
    await flush();
    return { status: res.statusCode, body: res.body, next: nexts, writes: c.db.writes, gateRows: c.db.gateRows };
  }
  {
    const lang = await mgCall("lang");
    check("N1. the language route serves lib/gateRules.js language()", J(lang.body) === J(RULES.language()));
    const rule = { all: [{ field: "approved", op: "eq", value: true }, { field: "weekday", op: "in", value: ["mon", "tue", "wed", "thu", "fri"] }] };
    const made = await mgCall("make", { body: { name: "Weekdays, approved", scope: "any", rule: rule } });
    check("N2. a valid gate is saved (201) under the caller, with its summary", made.status === 201 && made.body.gate.name === "Weekdays, approved" && made.body.gate.summary === "Go ahead only if approved AND on a weekday" &&
      T.member_gates.length === 1 && T.member_gates[0].user_id === MEMBER && T.member_gates[0].time_zone === "UTC" && T.member_gates[0].enabled === true, J(made.body));
    const refusals = [
      ["an unknown key", { name: "A", scope: "any", rule: rule, user_id: MEMBER_B }, "user_id"],
      ["an unknown field in the rule", { name: "A", scope: "any", rule: { field: "price", op: "eq", value: 1 } }, "rule.field"],
      ["an unknown comparator", { name: "A", scope: "any", rule: { field: "agent", op: "like", value: "seo" } }, "rule.op"],
      ["free text in the rule", { name: "A", scope: "any", rule: { field: "agent", op: "eq", value: "anything at all" } }, "rule.value"],
      ["a name with markup", { name: "<b>x</b>", scope: "any", rule: rule }, "name"],
      ["an unknown scope", { name: "A", scope: "all", rule: rule }, "scope"],
      ["an unknown time zone", { name: "A", scope: "any", rule: rule, time_zone: "Moon/Base" }, "time_zone"],
      ["enabled not a boolean", { name: "A", scope: "any", rule: rule, enabled: "yes" }, "enabled"],
      ["an array body", [1], "body"]
    ];
    for (const x of refusals) {
      const r = await mgCall("make", { body: x[1] });
      check("N2. refused (400), nothing saved: " + x[0], r.status === 400 && r.body.field === x[2] && /Nothing was saved\.$/.test(r.body.error) && T.member_gates.length === 1, J(r.body));
    }
    for (let i = 0; i < 19; i++) T.member_gates.push({ id: UUID(300 + i), user_id: MEMBER, name: "G" + i, scope: "any", rule: rule, time_zone: "UTC", enabled: true, created_at: "2026-10-02T00:00:" + String(i).padStart(2, "0") + "Z" });
    const full = await mgCall("make", { body: { name: "One more", scope: "any", rule: rule } });
    check("N2. the 21st gate is refused (400 too_many_gates)", full.status === 400 && full.body.reason === "too_many_gates" && T.member_gates.length === 20, J(full.body));
    T.member_gates.splice(1);
    T.member_gates.push({ id: UUID(400), user_id: MEMBER_B, name: "Theirs", scope: "any", rule: rule, time_zone: "UTC", enabled: true, created_at: "2026-10-03T00:00:00Z" });
    const listed = await mgCall("list");
    check("N3. the list is the caller's own gates only", listed.status === 200 && listed.body.gates.length === 1 && listed.body.gates[0].name === "Weekdays, approved", J(listed.body));
    const theirs = await mgCall("edit", { params: { id: UUID(400) }, body: { enabled: false } });
    check("N3. another member's gate cannot be changed (404), and is unchanged", theirs.status === 404 && T.member_gates[1].enabled === true, J(theirs.body));
    const mineId = T.member_gates[0].id;
    const partial = await mgCall("edit", { params: { id: mineId }, body: { enabled: false } });
    check("N3. a partial edit keeps the rest and validates the whole gate again", partial.status === 200 && partial.body.gate.enabled === false && J(partial.body.gate.rule) === J(rule), J(partial.body));
    const badEdit = await mgCall("edit", { params: { id: mineId }, body: { rule: { field: "hour", op: "eq", value: 25 } } });
    check("N3. an edit to an invalid rule is refused (400), nothing changed", badEdit.status === 400 && /Nothing was changed\.$/.test(badEdit.body.error) && J(T.member_gates[0].rule) === J(rule), J(badEdit.body));
    const dropTheirs = await mgCall("drop", { params: { id: UUID(400) } });
    check("N3. another member's gate cannot be deleted (404)", dropTheirs.status === 404 && T.member_gates.length === 2);
    const dropMine = await mgCall("drop", { params: { id: mineId } });
    check("N3. the caller's own gate is deleted", dropMine.status === 200 && dropMine.body.deleted === true && T.member_gates.length === 1);
    check("N4. every member_gates query names the caller's user_id", queries.filter(q => q.table === "member_gates" && q.op !== "insert").every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === MEMBER)),
      J(queries.filter(q => q.table === "member_gates").map(q => q.filters)));
  }
  {
    const base = Date.parse("2026-10-15T12:00:00.000Z");
    const agents = ["seo", "sales", "content"], outcomes = ["ran", "blocked", "held_for_approval"];
    for (let i = 0; i < 45; i++) T.gate_decisions.push({ id: UUID(500 + i), user_id: MEMBER, action: i % 2 ? "proposal_approve" : "schedule_run", target: "proposal:" + UUID(500 + i), outcome: outcomes[i % 3],
      results: [{ gate: "G3", result: "pass" }, { gate: "G1", result: i % 3 === 1 ? "fail" : "pass", code: i % 3 === 1 ? "not_pending" : "approved" }], facts: { agent: agents[i % 3], approved: i % 2 === 1 },
      member_gate_name: null, created_at: new Date(base - i * 3600000).toISOString() });
    for (let i = 0; i < 5; i++) T.gate_decisions.push({ id: UUID(600 + i), user_id: MEMBER_B, action: "schedule_run", target: "schedule:" + UUID(600), outcome: "ran", results: [], facts: { agent: "seo" }, created_at: new Date(base).toISOString() });
    queries.length = 0;
    const p1 = await mgCall("decisions", { query: {} });
    const ids = r => (r.body.decisions || []).map(d => d.id);
    check("N5. the Decisions list: 20 a page, newest first, 45 in all, 3 pages", p1.status === 200 && p1.body.decisions.length === 20 && p1.body.total === 45 && p1.body.pages === 3 && p1.body.per_page === 20 &&
      J(ids(p1)) === J(Array.from({ length: 20 }, (x, i) => UUID(500 + i))), J(ids(p1)).slice(0, 200));
    const p3 = await mgCall("decisions", { query: { page: "3" } });
    check("N5. page 3 is the last five", p3.body.decisions.length === 5 && J(ids(p3)) === J([40, 41, 42, 43, 44].map(i => UUID(500 + i))), J(ids(p3)));
    const seo = await mgCall("decisions", { query: { agent: "seo" } });
    check("N5. filtered by agent: seo only (15)", seo.body.total === 15 && seo.body.decisions.every(d => d.agent === "seo"), J(seo.body.total));
    const blk = await mgCall("decisions", { query: { outcome: "blocked", agent: "sales" } });
    check("N5. filtered by outcome and agent together", blk.body.total === 15 && blk.body.decisions.every(d => d.outcome === "blocked" && d.agent === "sales"), J(blk.body.total));
    for (const [label, q] of [["page 0", { page: "0" }], ["page 2.5", { page: "2.5" }], ["page 501", { page: "501" }], ["an unknown agent", { agent: "hacker" }], ["an unknown outcome", { outcome: "maybe" }]]) {
      const r = await mgCall("decisions", { query: q });
      check("N5. refused (400): " + label, r.status === 400, J(r.body));
    }
    check("N5. no other member's decision is ever listed", [p1, p3, seo, blk].every(r => r.body.decisions.every(d => Number(d.id.slice(-12)) < 600)));
    const forT = await mgCall("forTarget", { query: { target: "proposal:" + UUID(501) } });
    check("N6. the decisions for one proposal: only that target's, the caller's own", forT.status === 200 && forT.body.decisions.length === 1 && forT.body.decisions[0].id === UUID(501), J(forT.body).slice(0, 300));
    const forBad = await mgCall("forTarget", { query: { target: "contact:someone@example.com" } });
    check("N6. a target that is not proposal:, ai_task: or schedule: and an id is refused (400)", forBad.status === 400, J(forBad.body));
    const forTheirs = await mgCall("forTarget", { query: { target: "schedule:" + UUID(600) } });
    check("N6. another member's schedule: nothing", forTheirs.status === 200 && forTheirs.body.decisions.length === 0, J(forTheirs.body));
    const one = await mgCall("one", { params: { id: UUID(501) } });
    check("N7. one decision, explained from its record by lib/gates.js explain()", one.status === 200 && J(one.body.decision) === J(Object.assign(GATES.explain(T.gate_decisions[1]), { agent: "sales" })), J(one.body).slice(0, 300));
    const oneTheirs = await mgCall("one", { params: { id: UUID(600) } });
    check("N7. another member's decision is not found (404)", oneTheirs.status === 404);
    check("N7. every gate_decisions read names the caller's user_id", queries.filter(q => q.table === "gate_decisions").every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === MEMBER)));
    check("N7. the decision reads wrote nothing", queries.filter(q => q.op !== "select").length === 0);
    // The preview reads only.
    queries.length = 0;
    const before = J(T);
    const pv = await mgCall("preview", { body: { scope: "any", rule: { field: "weekday", op: "in", value: ["sat", "sun"] }, time_zone: "UTC" } });
    check("N8. the 30-day preview counts what the rule would have stopped", pv.status === 200 && pv.body.window_days === 30 && pv.body.read === 45 && pv.body.considered === 15 && pv.body.already_stopped === 30 &&
      pv.body.would_block === 15 && pv.body.would_pass === 0 && pv.body.summary === "Go ahead only if at the weekend", J(pv.body));
    const pv2 = await mgCall("preview", { body: { scope: "proposal_approve", rule: { field: "amount", op: "lt", value: 10 } } });
    check("N8. a fact the records never hold (an amount) is \"could not judge\", never a guess", pv2.status === 200 && pv2.body.could_not_judge === pv2.body.considered && pv2.body.would_block === 0 && pv2.body.would_pass === 0, J(pv2.body));
    const pv3 = await mgCall("preview", { body: { scope: "any", rule: { field: "price", op: "eq", value: 1 } } });
    check("N8. an invalid rule is refused (400)", pv3.status === 400, J(pv3.body));
    check("N8. THE PREVIEW ONLY READS: no insert, update, delete or upsert on any table, no decision recorded, the tables unchanged",
      queries.every(q => q.op === "select") && queries.length === 2 && pv.writes.length === 0 && pv.gateRows.length === 0 && pv2.writes.length === 0 && J(T) === before, J(queries.map(q => q.table + " " + q.op)));
    check("N8. the preview reads only the caller's decisions of the last 30 days", queries.every(q => q.table === "gate_decisions" && q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === MEMBER) &&
      q.filters.some(f => f[0] === "gte" && f[1] === "created_at" && f[2] === new FixedDate(FIXED - 30 * 24 * 3600 * 1000).toISOString())), J(queries.map(q => q.filters)));
  }

  /* ═══ O. the sweep ═══════════════════════════════════════════════════════ */
  console.log("\n══ O. the daily sweep: only rows older than 90 days, under its own claim ══");
  {
    const sweepLogs = [];
    const sandbox = { console: { log: (...a) => sweepLogs.push(a.join(" ")), error: (...a) => sweepLogs.push("ERR " + a.join(" ")) }, process: { env: {} } };
    vm.createContext(sandbox);
    const m = { exports: {} };
    vm.runInContext("(function (module, exports) {\n" + FILES.sweep + "\n})", sandbox)(m, m.exports);
    const SW = m.exports;
    const DAY = 24 * 3600 * 1000;
    const now = Date.parse("2026-11-01T04:30:00.000Z");
    function sweepDb(rows, jobRows) {
      const db = { gate_decisions: rows, job_runs: jobRows || [], touched: new Set(), deletes: [] };
      function from(table) {
        db.touched.add(table);
        const q = { table: table, op: "select", filters: [], payload: null, limit: null };
        const b = {
          select() { return b; }, insert(p) { q.op = "insert"; q.payload = p; return b; }, update(p) { q.op = "update"; q.payload = p; return b; }, delete() { q.op = "delete"; return b; },
          eq(c, v) { q.filters.push(["eq", c, v]); return b; }, lt(c, v) { q.filters.push(["lt", c, v]); return b; }, in(c, v) { q.filters.push(["in", c, v]); return b; },
          or(s) { q.filters.push(["or", s]); return b; }, order() { return b; }, limit(n) { q.limit = n; return b; },
          then(res, rej) { return Promise.resolve().then(run).then(res, rej); }
        };
        function ok(r) { return q.filters.every(f => f[0] === "eq" ? r[f[1]] === f[2] : f[0] === "lt" ? r[f[1]] < f[2] : f[0] === "in" ? f[2].indexOf(r[f[1]]) !== -1 :
          f[0] === "or" ? (r.last_run_on === null || r.last_run_on !== f[1].split("neq.")[1]) : true); }
        function run() {
          const list = db[table];
          if (q.op === "insert") { if (list.some(r => r.job_name === q.payload.job_name)) return { data: null, error: { code: "23505", message: "duplicate" } }; list.push(Object.assign({}, q.payload)); return { data: [{ job_name: q.payload.job_name }], error: null }; }
          const hit = list.filter(ok);
          if (q.op === "update") { hit.forEach(r => Object.assign(r, q.payload)); return { data: hit.map(r => ({ job_name: r.job_name })), error: null }; }
          if (q.op === "delete") { db.deletes.push(q.filters.slice()); db[table] = list.filter(r => hit.indexOf(r) === -1); return { data: hit.map(r => ({ id: r.id })), error: null }; }
          const sorted = hit.slice().sort((a, b) => a.created_at < b.created_at ? -1 : 1);
          return { data: (q.limit ? sorted.slice(0, q.limit) : sorted).map(r => ({ id: r.id })), error: null };
        }
        return b;
      }
      db.client = { from: from };
      return db;
    }
    const at = (days, n) => ({ id: "row-" + n, user_id: MEMBER, created_at: new Date(now - days * DAY).toISOString() });
    const ages = [0, 1, 30, 89.99, 90, 90.0001, 120, 400];
    const db = sweepDb(ages.map((d, i) => at(d, i)), [{ job_name: "nightly_backup", last_run_on: "2026-11-01" }]);
    const first = await SW.gateDecisionsSweepTick(db.client, now);
    check("O1. the sweep deletes only rows created more than 90 days ago (a row exactly 90 days old waits a day)",
      first.claimed === true && J(db.gate_decisions.map(r => r.id).sort()) === J(["row-0", "row-1", "row-2", "row-3", "row-4"]) && first.summary.rows_deleted === 3, J(db.gate_decisions.map(r => r.id)) + " " + J(first));
    check("O1. every delete repeats the cutoff, so it can never reach a recent row whatever ids it is handed",
      db.deletes.length >= 1 && db.deletes.every(f => f.some(x => x[0] === "lt" && x[1] === "created_at" && x[2] === new Date(now - 90 * DAY).toISOString()) && f.some(x => x[0] === "in")), J(db.deletes));
    check("O2. its own claim: one job_runs row, gate_decisions_sweep, for the UTC day, closed with finished_at", db.job_runs.filter(r => r.job_name === "gate_decisions_sweep").length === 1 &&
      db.job_runs.find(r => r.job_name === "gate_decisions_sweep").last_run_on === "2026-11-01" && !!db.job_runs.find(r => r.job_name === "gate_decisions_sweep").finished_at, J(db.job_runs));
    check("O2. no other job's row is touched", J(db.job_runs.find(r => r.job_name === "nightly_backup")) === J({ job_name: "nightly_backup", last_run_on: "2026-11-01" }));
    check("O2. it touches gate_decisions and job_runs only", J([...db.touched].sort()) === J(["gate_decisions", "job_runs"]));
    db.gate_decisions.push(at(200, 99));
    const again = await SW.gateDecisionsSweepTick(db.client, now + 3600000);
    check("O3. a second tick the same UTC day finds the day claimed and deletes nothing", again.claimed === false && db.gate_decisions.some(r => r.id === "row-99"), J(again));
    const nextDay = await SW.gateDecisionsSweepTick(db.client, now + DAY);
    check("O3. the next UTC day claims again and sweeps (the 90-day row, now 91, goes too)", nextDay.claimed === true && !db.gate_decisions.some(r => r.id === "row-99" || r.id === "row-4"), J(nextDay));
    const big = sweepDb(Array.from({ length: 1201 }, (x, i) => at(100 + i / 1000, i)).concat([at(10, "recent")]));
    const bigRun = await SW.runGateDecisionsSweepPass(big.client, now);
    check("O4. in batches of 500: 1201 old rows in 3 batches, the recent row kept", bigRun.batches === 3 && bigRun.rows_deleted === 1201 && big.gate_decisions.length === 1 && big.gate_decisions[0].id === "row-recent", J(bigRun));
    check("O5. on by default; only ENABLE_GATE_DECISIONS_SWEEP exactly \"false\" turns it off",
      SW.gateDecisionsSweepEnabled({}) === true && SW.gateDecisionsSweepEnabled({ ENABLE_GATE_DECISIONS_SWEEP: "False" }) === true && SW.gateDecisionsSweepEnabled({ ENABLE_GATE_DECISIONS_SWEEP: "false" }) === false);
    const cronAt = NEW.indexOf("    cron.schedule(\"30 4 * * *\", function () {\n      require(\"./lib/gateDecisionsSweep\").gateDecisionsSweepTick(supabase).catch(");
    const listenAt = NEW.indexOf("shutdownControl.setServer(app.listen(PORT, function () {");
    check("O6. server.js schedules it at 04:30 UTC inside the startup callback, gated by gateDecisionsSweepEnabled",
      cronAt > listenAt && listenAt > 0 && NEW.slice(cronAt, cronAt + 400).indexOf("timezone: \"UTC\"") !== -1 &&
      NEW.lastIndexOf("if (require(\"./lib/gateDecisionsSweep\").gateDecisionsSweepEnabled(process.env)) {", cronAt) > listenAt);
    check("O6. no boot-time run: the tick is called only from the cron callback", (NEW.match(/gateDecisionsSweepTick\(/g) || []).length === 1);
    check("O7. the sweep reads the module's own constants: 90 days, batches of 500, job gate_decisions_sweep",
      SW.GATE_DECISIONS_RETENTION_DAYS === 90 && SW.GATE_DECISIONS_SWEEP_BATCH === 500 && SW.GATE_DECISIONS_SWEEP_JOB_NAME === "gate_decisions_sweep" && GATES.RETENTION_DAYS === 90);
  }

  /* ═══ P. the Why panel and the Decisions list, in jsdom ══════════════════ */
  console.log("\n══ P. \"Why?\": each result from the record only; the Decisions list pages and filters ══");
  let JSDOM = null; try { JSDOM = require("jsdom").JSDOM; } catch (e) { JSDOM = null; }
  check("P0. jsdom is available", !!JSDOM);
  if (JSDOM) {
    function page(html, answer) {
      const dom = new JSDOM("<!doctype html><html><body>" + html + "</body></html>", { runScripts: "outside-only", url: "https://bizforceai.net/executive-agent.html" });
      const calls = [];
      dom.window.fetch = function (url, init) {
        const u = String(url).replace("https://dynamic-prosperity-production-5382.up.railway.app", "");
        calls.push({ method: (init && init.method) || "GET", url: u, body: init && init.body ? JSON.parse(init.body) : undefined });
        const a = answer(u, init || {});
        return Promise.resolve({ status: a.status || 200, ok: (a.status || 200) < 400, json: () => Promise.resolve(JSON.parse(J(a.body))) });
      };
      dom.window.eval(FILES.why);
      return { dom: dom, w: dom.window, d: dom.window.document, calls: calls };
    }
    const LANG = JSON.parse(J(RULES.language()));
    const row = { id: UUID(700), action: "proposal_approve", target: "proposal:" + PID, outcome: "blocked", created_at: "2026-10-15T12:00:00.000Z", facts: { agent: "seo" },
      results: [{ gate: "G3", result: "pass" }, { gate: "G15", result: "bypass", code: "owner_pass" }, { gate: "G1", result: "fail", code: "not_pending" }, { gate: "G12", result: "not_reached" }],
      member_gate_name: "Weekends only" };
    const explained = Object.assign(GATES.explain(row), { agent: "seo" });
    const P = page("", u => u.indexOf("/api/gate-decisions/for") === 0 ? { body: { target: "proposal:" + PID, decisions: [explained] } } : { body: LANG });
    const btn = P.d.createElement("button"); btn.setAttribute("data-bf-why", "proposal:" + PID); P.d.body.appendChild(btn);
    btn.click(); await flush();
    const panel = P.d.querySelector(".bf-why-panel");
    check("P1. a \"Why?\" click reads GET /api/gate-decisions/for for that target", P.calls.some(c => c.method === "GET" && c.url === "/api/gate-decisions/for?target=" + encodeURIComponent("proposal:" + PID)), J(P.calls));
    check("P1. the panel says \"Why did this run, or not run?\"", panel && !panel.hidden && P.d.getElementById("bfWhyTitle").textContent === "Why did this run, or not run?");
    const lis = [...panel.querySelectorAll(".bf-why-gate")];
    check("P2. each gate is shown in the record's order, one per result", J(lis.map(l => l.getAttribute("data-gate"))) === J(["G3", "G15", "G1", "G12"]));
    const kinds = { pass: "Pass", bypass: "Bypass", fail: "Fail", not_reached: "Not reached" };
    row.results.forEach((r, i) => {
      const li = lis[i]; const g = GATES.GATES.find(x => x.id === r.gate);
      check("P2. " + r.result + ": shown as \"" + kinds[r.result] + "\" with " + r.gate + "'s registered name and the REASONS sentence for its stored code",
        !!li && li.getAttribute("data-result") === r.result && li.querySelector(".bf-why-result").textContent === kinds[r.result] &&
        li.querySelector(".bf-why-gate-name").textContent === g.name && li.querySelector(".bf-why-reason").textContent === GATES.reasonFor(r.result, r.code || null),
        li ? li.textContent : "missing");
    });
    const mem = panel.querySelector(".bf-why-member");
    check("P3. the member gate that blocked it, by its own name, with the member_gate sentence", !!mem && mem.querySelector(".bf-why-member-name").textContent === "Weekends only" &&
      mem.querySelector(".bf-why-reason").textContent === GATES.REASONS.member_gate, mem ? mem.textContent : "missing");
    const reasonsShown = [...panel.querySelectorAll(".bf-why-reason")].map(x => x.textContent);
    check("P4. FROM RECORDS ONLY: every sentence shown is one the record's results and member gate produce, and nothing else",
      J(reasonsShown) === J(explained.gates.map(x => x.reason).concat([explained.member.reason])), J(reasonsShown));
    const P2 = page("", u => u.indexOf("/for") !== -1 ? { body: { decisions: [] } } : { body: LANG });
    P2.w.BFWhy.open("ai_task:" + PID); await flush();
    check("P5. no record: \"No decision was recorded for this. Decisions are kept for 90 days.\"", P2.d.querySelector(".bf-why-body").textContent === "No decision was recorded for this. Decisions are kept for 90 days.");
    const noMember = Object.assign({}, explained, { member: null });
    const P3 = page("", () => ({ body: LANG }));
    const frag = P3.d.createElement("div"); frag.innerHTML = P3.w.BFWhy.decisionHtml(noMember);
    check("P5. a record that names no member gate shows none", !frag.querySelector(".bf-why-member"));
    const hostile = GATES.explain({ id: "x", action: "dispatch", outcome: "blocked", results: [{ gate: "G99", result: "boom", code: "<img src=x onerror=alert(1)>" }], member_gate_name: "<b>x</b>" });
    frag.innerHTML = P3.w.BFWhy.decisionHtml(hostile);
    check("P5. a malformed record is shown as not_reached with the generic sentence, and nothing in it becomes markup",
      frag.querySelectorAll("img,b").length === 0 && frag.querySelector(".bf-why-gate").getAttribute("data-result") === "not_reached" &&
      frag.querySelector(".bf-why-reason").textContent === GATES.reasonFor("not_reached", null), frag.innerHTML.slice(0, 300));
    // The Decisions list.
    const all = Array.from({ length: 45 }, (x, i) => ({ id: UUID(800 + i), action: "schedule_run", target: "schedule:" + UUID(800 + i), outcome: ["ran", "blocked", "held_for_approval"][i % 3],
      created_at: new Date(Date.parse("2026-10-15T12:00:00Z") - i * 3600000).toISOString(), facts: { agent: ["seo", "sales", "content"][i % 3] }, results: [{ gate: "G18", result: "pass" }], member_gate_name: null }));
    const serve = u => {
      if (u.indexOf("/api/member-gates/language") === 0) return { body: LANG };
      const q = new URL("https://x" + u).searchParams; const pg = Number(q.get("page"));
      const hit = all.filter(r => (!q.get("agent") || r.facts.agent === q.get("agent")) && (!q.get("outcome") || r.outcome === q.get("outcome")));
      return { body: { decisions: hit.slice((pg - 1) * 20, pg * 20).map(r => Object.assign(GATES.explain(r), { agent: r.facts.agent })), page: pg, per_page: 20, total: hit.length, pages: Math.max(1, Math.ceil(hit.length / 20)) } };
    };
    const L = page("<div id=\"deckDecisions\"></div>", serve);
    await flush();
    const items = () => [...L.d.querySelectorAll("#bfWhyList .bf-why-item")];
    const lists = () => L.calls.filter(c => c.url.indexOf("/api/gate-decisions") === 0).map(c => c.url);
    check("P6. the Decisions list mounts on HQ (#deckDecisions): \"Decisions\", page 1 of 3, 20 rows, Prev disabled",
      L.d.getElementById("bfWhyDecisionsTitle").textContent === "Decisions" && items().length === 20 && L.d.getElementById("bfWhyAt").textContent === "Page 1 of 3" &&
      L.d.getElementById("bfWhyPrev").disabled === true && L.d.getElementById("bfWhyNext").disabled === false && J(lists()) === J(["/api/gate-decisions?page=1"]), J(lists()));
    L.d.getElementById("bfWhyNext").click(); await flush();
    L.d.getElementById("bfWhyNext").click(); await flush();
    check("P6. Next pages through: page 3 has the last 5, Next disabled", items().length === 5 && L.d.getElementById("bfWhyAt").textContent === "Page 3 of 3" && L.d.getElementById("bfWhyNext").disabled === true &&
      J(lists().slice(-2)) === J(["/api/gate-decisions?page=2", "/api/gate-decisions?page=3"]));
    L.d.getElementById("bfWhyPrev").click(); await flush();
    check("P6. Prev goes back a page", L.d.getElementById("bfWhyAt").textContent === "Page 2 of 3" && lists().slice(-1)[0] === "/api/gate-decisions?page=2");
    const agentSel = L.d.getElementById("bfWhyAgent");
    check("P7. the agent filter lists every agent the language knows", [...agentSel.options].slice(1).map(o => o.value).join() === RULES.AGENTS.join());
    agentSel.value = "seo"; agentSel.dispatchEvent(new L.w.Event("change", { bubbles: true })); await flush();
    check("P7. choosing an agent asks for page 1 of that agent's decisions", lists().slice(-1)[0] === "/api/gate-decisions?page=1&agent=seo" && items().length === 15 && L.d.getElementById("bfWhyAt").textContent === "Page 1 of 1");
    const outSel = L.d.getElementById("bfWhyOutcome");
    outSel.value = "held_for_approval"; outSel.dispatchEvent(new L.w.Event("change", { bubbles: true })); await flush();
    check("P7. and the outcome filter narrows it further", lists().slice(-1)[0] === "/api/gate-decisions?page=1&agent=seo&outcome=held_for_approval" && items().length === 0 &&
      L.d.getElementById("bfWhyListNote").textContent === "No decisions match.");
    outSel.value = ""; outSel.dispatchEvent(new L.w.Event("change", { bubbles: true })); await flush();
    items()[0].querySelector("[data-bf-why-decision]").click(); await flush();
    check("P8. a row's \"Why?\" opens that decision from the list's own record, with no other read", L.d.querySelector(".bf-why-panel .bf-why-decision").getAttribute("data-decision") === UUID(800) &&
      lists().slice(-1)[0] === "/api/gate-decisions?page=1&agent=seo");
    // The builder's summary is the library's.
    const r = rng(77);
    let agreeS = 0, wrongS = [];
    for (let i = 0; i < 600; i++) {
      const scope = pick(r, RULES.SCOPES); const checked = RULES.validateRule(randomRule(r, scope, 1), scope);
      if (!checked.ok) continue;
      const front = P3.w.BFWhy.summarize(JSON.parse(J(checked.rule)), scope, LANG);
      if (front === RULES.summarize(checked.rule, scope)) agreeS++; else if (wrongS.length < 3) wrongS.push(front + " | " + RULES.summarize(checked.rule, scope));
    }
    check("P9. the builder's live plain-English summary equals lib/gateRules.js summarize() on " + agreeS + " random rules", wrongS.length === 0 && agreeS > 300, J(wrongS));
    // The builder: Settings, and its test only reads.
    const Bd = page("<div id=\"deckMemberGates\"></div>", u => u.indexOf("/language") !== -1 ? { body: LANG } : u.indexOf("/preview") !== -1 ? { body: { window_days: 30, read: 4, considered: 3, would_block: 1, would_pass: 2, could_not_judge: 0, already_stopped: 1, summary: "x", capped: false } } : { body: { gates: [] } });
    await flush();
    check("P10. the rule builder mounts on Settings (#deckMemberGates): \"Your gates\" and the only-adds sentence",
      Bd.d.getElementById("bfGateTitle").textContent === "Your gates" && Bd.d.getElementById("deckMemberGates").textContent.indexOf("A gate you set can only stop an action the platform's own checks let through. It never lets through anything they refused.") !== -1);
    const before = Bd.calls.length;
    Bd.d.getElementById("bfGateTest").click(); await flush();
    const after = Bd.calls.slice(before);
    check("P10. \"Test against my last 30 days\" sends one POST to /api/member-gates/preview and nothing else", after.length === 1 && after[0].method === "POST" && after[0].url === "/api/member-gates/preview" &&
      RULES.validateRule(after[0].body.rule, after[0].body.scope).ok, J(after));
    check("P10. the builder offers AND, OR and NOT", /value="all"/.test(Bd.d.getElementById("deckMemberGates").innerHTML) && /value="any"/.test(Bd.d.getElementById("deckMemberGates").innerHTML) && /NOT/.test(Bd.d.getElementById("deckMemberGates").textContent));
  }
  check("P11. \"Why?\" sits beside runs and proposals on the agent page, and beside a schedule run that did not go ahead",
    FILES.agentProfile.indexOf("whyLinkHtml(\"ai_task:\" + t.id)") !== -1 && FILES.agentProfile.indexOf("whyLinkHtml(\"proposal:\" + d.proposal_id)") !== -1 &&
    FILES.agentProfile.indexOf("why.setAttribute(\"data-bf-why\", \"schedule:\" + row.id);") !== -1 && FILES.agentProfile.indexOf("s.src = \"/scripts/bf-why.js\";") !== -1);
  check("P11. …and in the HQ queues: approvals by proposal, the run history by task",
    FILES.hq.indexOf("why.setAttribute(\"data-bf-why\", \"proposal:\" + p.id);") !== -1 && FILES.deck.indexOf("why.setAttribute(\"data-bf-why\", \"ai_task:\" + task.id);") !== -1 &&
    FILES.execHtml.indexOf("<script src=\"/scripts/bf-why.js\"></script>") !== -1);

  /* ═══ Q. export, deletion and backup ═════════════════════════════════════ */
  console.log("\n══ Q. member_gates is exported, deleted with the account and backed up ══");
  {
    const yd = require(path.join(REPO, "lib/yourData"));
    const e = yd.DATA.filter(x => x.table === "member_gates");
    check("Q1. member_gates is in DATA once: group agents, owner user_id, onDelete delete", e.length === 1 && e[0].group === "agents" && J(e[0].owner) === J(["user_id"]) && e[0].onDelete === "delete", J(e));
    check("Q2. member_gates is in DELETE_ORDER once", yd.DELETE_ORDER.filter(t => t === "member_gates").length === 1);
    check("Q3. the foreign key cascades with the account", /user_id\s+uuid NOT NULL REFERENCES public\.users\(id\) ON DELETE CASCADE/.test(FILES.migration159));
    const bk = require(path.join(REPO, "lib/backup"));
    check("Q4. lib/backup.js backs it up", Array.isArray(bk.BACKUP_TABLES) && bk.BACKUP_TABLES.indexOf("member_gates") !== -1);
  }

  /* ═══ R. migration 159 ═══════════════════════════════════════════════════ */
  console.log("\n══ R. migration 159 ══");
  {
    const files = fs.readdirSync(path.join(REPO, "supabase/migrations"));
    const sql = FILES.migration159.replace(/--[^\n]*/g, "");
    check("R1. 159_member_gates.sql exists and is the only migration numbered 159", files.filter(f => /^159_/.test(f)).length === 1 && files.indexOf("159_member_gates.sql") !== -1);
    check("R2. member_gates: id, user_id, name (1 to 60), scope, rule (a jsonb object of at most 4096 bytes), time_zone, enabled, created_at, updated_at",
      ["id          uuid PRIMARY KEY DEFAULT gen_random_uuid()", "name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60)",
        "rule        jsonb NOT NULL CHECK (jsonb_typeof(rule) = 'object' AND pg_column_size(rule) <= 4096)", "enabled     boolean NOT NULL DEFAULT true",
        "created_at  timestamptz NOT NULL DEFAULT now()", "updated_at  timestamptz NOT NULL DEFAULT now()"].every(x => sql.indexOf(x) !== -1) && RULES.LIMITS.NAME_MAX === 60 && RULES.LIMITS.MAX_BYTES === 4096);
    const scopes = (/scope\s+text NOT NULL CHECK \(scope IN \(([^)]*)\)\)/.exec(sql) || [])[1];
    check("R3. the scope list equals lib/gateRules.js SCOPES", !!scopes && J(scopes.match(/'[a-z_]+'/g).map(x => x.slice(1, -1))) === J(RULES.SCOPES.slice()), scopes);
    check("R4. row level security on, with no policy and no grant", /ALTER TABLE public\.member_gates ENABLE ROW LEVEL SECURITY;/.test(sql) && !/CREATE POLICY|GRANT /i.test(sql));
    check("R5. gate_decisions gains facts (an object of at most 512 bytes), member_gate_id and member_gate_name, all nullable",
      /ADD COLUMN IF NOT EXISTS facts jsonb\s+CHECK \(facts IS NULL OR \(jsonb_typeof\(facts\) = 'object' AND pg_column_size\(facts\) <= 512\)\)/.test(sql) &&
      /ADD COLUMN IF NOT EXISTS member_gate_id uuid,/.test(sql) && /ADD COLUMN IF NOT EXISTS member_gate_name text/.test(sql));
    check("R6. the sweep's index on created_at", /CREATE INDEX IF NOT EXISTS gate_decisions_created_idx\s+ON public\.gate_decisions \(created_at\);/.test(sql));
    const m143 = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^143_/.test(f)).map(f => read("supabase/migrations/" + f)).join("\n");
    const statusList = s => { const m = /last_run_status IS NULL OR last_run_status IN \(([^)]*)\)/i.exec(s); return m ? m[1].match(/'[a-z_]+'/g).map(x => x.slice(1, -1)) : null; };
    check("R7. last_run_status gains skipped_member_gate, keeping every value migration 143 allowed",
      !!statusList(m143) && J(statusList(sql)) === J(statusList(m143).concat(["skipped_member_gate"])), J(statusList(sql)) + " vs " + J(statusList(m143)));
    check("R8. the migration only creates, alters and indexes: no DROP TABLE, DELETE, UPDATE or TRUNCATE", !/DROP TABLE|DELETE FROM|UPDATE public|TRUNCATE/i.test(sql));
  }

  /* ═══ S. no emoji in anything B2 added ═══════════════════════════════════ */
  {
    const EMOJI = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}]/u;
    const named = { "lib/gateRules.js": FILES.rules, "lib/gateDecisionsSweep.js": FILES.sweep, "159_member_gates.sql": FILES.migration159, "scripts/bf-why.js": FILES.why, "lib/gates.js": FILES.gates };
    check("S1. no emoji in lib/gateRules.js, lib/gateDecisionsSweep.js, migration 159, bf-why.js or lib/gates.js", Object.keys(named).every(k => !EMOJI.test(named[k])),
      Object.keys(named).filter(k => EMOJI.test(named[k])).join(", "));
  }

  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED (" + passes + ")" : "CHECKS FAILED: " + failures + " failing, " + passes + " passing"));
  process.exit(failures === 0 ? 0 : 1);
})().catch(function (e) {
  console.log("    FAIL  the check itself crashed: " + ((e && e.stack) || e));
  process.exit(1);
});
