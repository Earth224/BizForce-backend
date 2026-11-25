"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   _p21Harness.js — what the five P2-1 checks share (Nov 19 2026):
   checkAppShell, checkInbox, checkHandles, checkHomeStarter, checkProfileShell.

   FILES      the files a check reads, by name: "@server.js" and "@lib/..." are
              the backend's, anything else the frontend's; CRLF read as LF.
   MUTATE     a check's MUTATIONS are applied IN MEMORY, each search text
              exactly once (s.replaceOnce: else a MUTATION ANCHOR ERROR);
              MUTATE=all runs each in its own process (s.runAllMutations).
   libRequire "./lib/<x>" answered from FILES when the check holds that file,
              so a mutation of lib/handles.js reaches the route that requires
              it; any other name is the real require.
   route      a route's handler from server.js text, run in a vm with the
              server's top-level definitions it names (s.closureFor) and the
              stubs the check gives: never the real database, never the network.
   fakeDb     a supabase-shaped fake: every query is recorded (table, the
              operation, its payload, its filters) and answered by the check's
              function for that table.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");

function setup(filename, mutations, names) {
  const MUTATE = process.env.MUTATE || "";
  if (MUTATE === "all") s.runAllMutations(filename, Object.keys(mutations));
  if (MUTATE && !mutations[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(mutations).join(", ")); process.exit(2); }
  const FILES = {};
  const read = (f) => {
    const p = f.charAt(0) === "@" ? path.join(REPO, f.slice(1)) : path.join(FRONTEND, f);
    try { return fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n"); } catch (e) { return null; }
  };
  names.forEach(f => { FILES[f] = read(f); });
  Object.keys(mutations).forEach(k => mutations[k].forEach(([f]) => { if (!(f in FILES)) FILES[f] = read(f); }));
  if (MUTATE) {
    for (const [file, from, to] of mutations[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
    console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
  }
  let passes = 0, failures = 0;
  function check(name, ok, detail) {
    if (ok) { passes++; console.log("    pass  " + name); }
    else { failures++; console.log("    FAIL  " + name + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
  }
  function finish() {
    if (failures) { console.log("\nCHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
    console.log("\nALL CHECKS PASSED (" + passes + ")");
    process.exit(0);
  }
  process.on("unhandledRejection", e => check("no request is left unhandled", false, (e && e.message) || e));

  const libCache = {};
  function libRequire(name) {
    // NAMED (Nov 20 2026, P2-2): also "./<name>", a lib file's require of its neighbour (lib/moderation.js requires "./safety")
    // NAMED (Nov 25 2026, LR-4): AND a generated neighbour, "./publicShells.generated" (lib/publicPages.js); BEFORE letters, digits and _ only
    const m = /^\.\/(?:lib\/)?([a-zA-Z0-9_]+(?:\.generated)?)(?:\.js)?$/.exec(name);
    const key = m ? "@lib/" + m[1] + ".js" : null;
    if (key && typeof FILES[key] === "string") {
      if (!libCache[key]) {
        const mod = { exports: {} };
        libCache[key] = mod;
        new vm.Script("(function (module, exports, require) {" + FILES[key] + "\n})", { filename: key }).runInThisContext()(mod, mod.exports, libRequire);
      }
      return libCache[key].exports;
    }
    return require(m ? path.join(REPO, "lib", m[1]) : name);
  }
  return { FILES, MUTATE, check, finish, libRequire, J: v => JSON.stringify(v),
    has: (t, x) => typeof t === "string" && t.indexOf(x) !== -1,
    count: (t, x) => typeof t === "string" ? t.split(x).length - 1 : 0 };
}

/* The whole `app.<method>("<path>", ...);` statement, or null. */
function routeStatement(src, method, routePath) {
  const sig = "app." + method + "(\"" + routePath + "\",";
  const at = String(src || "").indexOf(sig);
  if (at < 0) return null;
  const open = src.indexOf("async function (req, res, next) {", at);
  if (open < 0) return null;
  const end = s.braceMatch(src, src.indexOf("{", open));
  if (end < 0 || src.slice(end, end + 2) !== ");") return null;
  return src.slice(at, end + 2);
}

/* Runs a route's statement in a vm and returns its handler: (req) => { status, body, err }. */
function route(src, method, routePath, stubs, libRequire) {
  const stmt = routeStatement(src, method, routePath);
  if (!stmt) return null;
  let handler = null;
  /* NAMED (Nov 21 2026, P3-1B): a route that asks the tier (POST /api/messages: starting a conversation is for members;
     postDeps().tierOf) reads getUserPlan, whose closure is the whole billing reader. Unless the check stubs it, every
     account here is a member (active), so the older checks keep their meaning; checkInbox and checkFreeAccount stub a free one. */
  if (!stubs || !Object.prototype.hasOwnProperty.call(stubs, "getUserPlan")) stubs = Object.assign({ getUserPlan: async function () { return { active: true, plan: "all_access", inactive_reason: null }; } }, stubs || {});
  const ctx = Object.assign({
    console: { log() {}, warn() {}, error() {} }, process: { env: {} }, Promise, Date, Math, JSON, Number, String, Object, Array, Set, Map, RegExp, Error,
    require: libRequire, nowIso: () => "2026-11-19T12:00:00.000Z", requireAuth: 0, requireActiveSubscription: 0, setTimeout, setImmediate
  }, stubs || {});
  const reg = function () { if (arguments[0] === routePath) handler = arguments[arguments.length - 1]; };
  ctx.app = { get: reg, put: reg, post: reg, delete: reg, patch: reg, use() {} };
  vm.createContext(ctx);
  /* NAMED (Nov 20 2026, P2-2): a route that screens text (policyScreen, lib/contentPolicy.js) runs the server's health-claims
     screen, which reads COMPLIANCE_PROFILES and COMPLIANCE_DISCLAIMER; _shared.js lists both as stubs, so the closure never
     carries them. Their real definitions from server.js are loaded here, unless the check stubs them. */
  const compliance = (stubs && (stubs.COMPLIANCE_PROFILES || stubs.COMPLIANCE_DISCLAIMER)) ? { names: [], code: "" } : s.complianceCode(src);
  if (compliance.code) vm.runInContext(compliance.code, ctx);
  // the check's stubs are not pulled in from server.js (nor what only they need); nor what the compliance code above defined
  const added = Object.keys(stubs || {}).concat(compliance.names).filter(k => !s.STUBS.has(k));
  added.forEach(k => s.STUBS.add(k));
  let code;
  try { code = s.closureFor(src, stmt); } catch (e) { code = stmt; } finally { added.forEach(k => s.STUBS.delete(k)); }
  vm.runInContext(code, ctx);
  // a server function the closure defined (ownerPagePublic, ...) gives way to the check's stub of the same name
  Object.keys(stubs || {}).forEach(k => { ctx[k] = stubs[k]; });
  if (!handler) return null;
  return async function (req) {
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    let err = null;
    // NAMED (Nov 20 2026, P3-1): the signed-in member has confirmed their email (lib/emailVerification.js); checkEmailVerified runs the unconfirmed one.
    await handler(Object.assign({ user: { id: "11111111-1111-4111-8111-111111111111", email_verified_at: "2026-10-01T10:00:00.000Z" }, body: {}, params: {}, query: {}, headers: {} }, req), res, (e) => { err = e || new Error("next"); });
    return { status: res.statusCode, body: res.body, err };
  };
}

/* A supabase-shaped fake. answer(table, q) returns { data, error, count }; q is the recorded query. */
function fakeDb(answer) {
  const log = [];
  const client = {
    from(table) {
      const q = { table, op: "select", cols: null, payload: null, opts: null, filters: [], terminal: null, head: false };
      log.push(q);
      const run = () => Promise.resolve(answer(table, q) || { data: null, error: null });
      const b = {};
      ["eq", "neq", "in", "is", "not", "lt", "lte", "gt", "gte", "ilike", "like", "order", "limit", "range", "or", "filter", "match", "contains"].forEach(m => {
        b[m] = function () { q.filters.push([m].concat([].slice.call(arguments))); return b; };
      });
      b.select = function (cols, opts) { if (q.op === "select") q.cols = cols; else q.returning = cols; if (opts && opts.head) q.head = true; if (opts && opts.count) q.countMode = opts.count; return b; };
      ["insert", "update", "upsert", "delete"].forEach(m => { b[m] = function (p, o) { q.op = m; q.payload = p; q.opts = o || null; return b; }; });
      b.single = function () { q.terminal = "single"; return run(); };
      b.maybeSingle = function () { q.terminal = "maybeSingle"; return run(); };
      b.then = function (res, rej) { return run().then(res, rej); };
      return b;
    }
  };
  return { client, log };
}
// filterVal(q, "eq", "user_id") is the value of that filter; with no column (limit, or) it is the filter's one argument
const filterVal = (q, m, col) => {
  if (col === undefined) { const f = q.filters.find(x => x[0] === m); return f ? f[1] : undefined; }
  const f = q.filters.find(x => x[0] === m && x[1] === col); return f ? f[2] : undefined;
};

/* NAMED (Nov 20 2026, P2-2): every `app.<method>("<path>", ...)` statement of server.js whose text holds needle, as
   "METHOD /path" in file order (the P2-2 checks compare where a guard is called with the list they own). */
function routesWith(src, needle) {
  const re = /\napp\.(get|post|put|delete|patch)\("([^"]+)",/g, out = [];
  let m;
  while ((m = re.exec(src)) !== null) {
    // the handler: `function (...) {` or an arrow `=> {`, whichever comes first
    const fn = src.indexOf("function", m.index + 1), arrow = src.indexOf("=> {", m.index + 1);
    const open = src.indexOf("{", arrow !== -1 && (fn === -1 || arrow < fn) ? arrow : fn);
    const end = s.braceMatch(src, open);
    if (end > open && src.slice(m.index, end).indexOf(needle) !== -1) out.push(m[1].toUpperCase() + " " + m[2]);
  }
  return out;
}

module.exports = { setup, route, routeStatement, routesWith, fakeDb, filterVal, REPO, FRONTEND };
