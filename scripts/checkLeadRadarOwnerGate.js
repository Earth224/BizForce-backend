/* ═══════════════════════════════════════════════════════════════════════════
   checkLeadRadarOwnerGate.js — the owner's old leads are the owner's, and each
   member's Lead Radar reads only that member's leads.

   WHAT WAS WRONG (2026). bsky_leads has no owner column: every row was the
   owner's. GET /api/leads and GET /api/agents/sales/leads once returned it to
   ANY account; the fix put an owner test inside each handler, ahead of its
   first query (LEAD_RADAR_UNAVAILABLE, code lead_radar_unavailable).

   NAMED (Nov 23 2026, LR-2): BEFORE this ran four, then five, owner-only lead
   routes in server.js against the live database: a non-owner got 403
   lead_radar_unavailable with zero Supabase calls, and the owner got the
   table back row for row. AFTER LR-2 removed those routes and
   LEAD_RADAR_UNAVAILABLE (the original is in git, 65c0825): Lead Radar is
   every member's (lib/leadRoutes.js, route group M) over member_leads, which
   carries user_id; the owner's old table is read by one route, GET
   /api/leads/archive, owner-only in its handler. The same two guarantees are
   proved on the new routes, with no database at all (a counting fake).

   WHAT THIS PROVES:
     1. The archive: a non-owner (even an admin) gets 403 owner_only with ZERO
        database calls; the owner gets the old leads and their pipeline, read
        only (two reads, no write), with read_only true.
     2. Routing: the archive is in route group A and in ADMIN_IN_HANDLER (its
        owner test is in the handler); the Lead Radar routes are M; the old
        owner-only routes are in no group and have no handler in server.js.
     3. Every member_leads query in lib/leadRoutes.js is scoped to the caller
        (user_id), so no member can read another's leads.
     4. The one owner literal in lib/ownerAccount.js agrees with the residue
        guard's own copy, which is deliberately not derived from it.

   MUTATIONS (MUTATE=<name> edits lib/leadRoutes.js IN MEMORY; MUTATE=all):
     unguard-archive  the archive's owner test is if (false)            → 1
     guard-late       the owner test runs after the reads              → 1
     unscoped-list    GET /api/leads drops its user_id filter          → 3
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs"), path = require("path"), Module = require("module");
const REPO = path.join(__dirname, "..");
const MUT = require("./_shared");
const MUTATE = process.env.MUTATE || "";
const { OWNER_ACCOUNT_ID } = require(path.join(REPO, "lib", "ownerAccount.js"));
const { OWNER_ACCOUNT_ID: RESIDUE_OWNER_ID } = require("./checkRunResidue");

const RT = "lib/leadRoutes.js";
const GUARD = '      if (req.user.id !== deps.ownerId) return res.status(403).json({ error: "The lead archive is the owner\'s.", code: "owner_only" });\n';
const MUTATIONS = {
  "unguard-archive": [[RT, '      if (req.user.id !== deps.ownerId) return res.status(403)', '      if (false) return res.status(403)']],
  "guard-late": [[RT, GUARD + "      var r = await Promise.all([", "      var r = await Promise.all(["], [RT, "      r.forEach(function (x) { if (x.error) throw x.error; });\n      return res.json({ leads: r[0].data",
    GUARD + "      r.forEach(function (x) { if (x.error) throw x.error; });\n      return res.json({ leads: r[0].data"]],
  "unscoped-list": [[RT, 'var q = deps.sb.from("member_leads").select(LEAD_FIELDS).eq("user_id", userId).not(', 'var q = deps.sb.from("member_leads").select(LEAD_FIELDS).not(']]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));
const FILES = {};
[RT, "server.js"].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = MUT.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}
function load(rel) {
  const m = new Module(path.join(REPO, rel), module);
  m.filename = path.join(REPO, rel);
  m.paths = Module._nodeModulePaths(path.dirname(m.filename));
  m._compile(FILES[rel], m.filename);
  return m.exports;
}
let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const J = JSON.stringify;

(async function main() {
  console.log("\n══ 1. the archive is the owner's ══");
  const R = load(RT);
  const handlers = {};
  const app = { get(p) { handlers["get " + p] = arguments[arguments.length - 1]; }, put() {}, post() {} };
  let calls = [];
  const sb = { from(t) { const c = { table: t, ops: [] }; calls.push(c);
    const b = new Proxy({}, { get(_, k) { if (k === "then") return (res, rej) => Promise.resolve({ data: [{ table: t }], error: null }).then(res, rej);
      return (...a) => { c.ops.push(k); return b; }; } }); return b; } };
  R.mountLeadRoutes(app, { sb, requireAuth() {}, requireActiveSubscription() {}, ownerId: OWNER_ACCOUNT_ID, siteOrigin: "https://bizforceai.net" });
  const run = async (user) => { calls = []; const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    await handlers["get /api/leads/archive"]({ user, query: {}, params: {} }, res, (e) => { res.statusCode = 500; res.body = String(e); }); return { res, calls }; };
  for (const [label, user] of [["a member", { id: "a0000000-0000-4000-8000-0000000000aa", role: "user" }], ["an admin who is not the owner", { id: "a0000000-0000-4000-8000-0000000000ab", role: "admin" }]]) {
    const o = await run(user);
    check(label + ": 403 owner_only, with zero database calls", o.res.statusCode === 403 && o.res.body.code === "owner_only" && o.calls.length === 0, J({ s: o.res.statusCode, b: o.res.body, calls: o.calls.length }));
  }
  const own = await run({ id: OWNER_ACCOUNT_ID, role: "admin" });
  check("the owner: the old leads and their pipeline, read only (two reads, no write)",
    own.res.statusCode === 200 && own.res.body.read_only === true && J(own.calls.map(c => c.table)) === J(["bsky_leads", "sales_lead_pipeline"]) &&
    own.calls.every(c => c.ops.indexOf("select") === 0 && !c.ops.some(op => /insert|update|upsert|delete/.test(op))), J(own.calls));

  console.log("\n══ 2. routing ══");
  const RA = require(path.join(REPO, "lib", "routeAccess.js"));
  check("the archive is in group A and its owner test is in the handler (ADMIN_IN_HANDLER)", RA.ADMIN.indexOf("get /api/leads/archive") !== -1 && RA.ADMIN_IN_HANDLER.indexOf("get /api/leads/archive") !== -1);
  const LEADS = ["get /api/leads", "get /api/leads/fingerprint", "put /api/leads/fingerprint", "get /api/leads/summary", "post /api/leads/:id/status", "post /api/leads/:id/draft", "post /api/leads/:id/send"];
  check("the Lead Radar routes are members-only (M)", LEADS.every(k => RA.MEMBER.indexOf(k) !== -1), J(LEADS.filter(k => RA.MEMBER.indexOf(k) === -1)));
  const OLD = ["get /api/agents/sales/leads", "post /api/agents/sales/lead-status", "get /api/agents/sales/pipeline", "get /api/leads/youtube-signals", "post /api/leads/draft-reply"];
  const all = [].concat(RA.PUBLIC, RA.FREE, RA.MEMBER, RA.ADMIN);
  const routeIn = k => { const [m, p] = k.split(" "); return FILES["server.js"].indexOf("app." + m + "(\"" + p + "\"") !== -1; };
  check("the old owner-only routes are in no group and have no handler", OLD.every(k => all.indexOf(k) === -1 && !routeIn(k)), J(OLD.filter(k => all.indexOf(k) !== -1 || routeIn(k))));
  check("LEAD_RADAR_UNAVAILABLE, the old refusal, is gone", FILES["server.js"].indexOf("const LEAD_RADAR_UNAVAILABLE") === -1);

  console.log("\n══ 3. a member reads only their own leads ══");
  const src = FILES[RT];
  const stmts = [];
  let at = -1;
  while ((at = src.indexOf('.from("member_leads")', at + 1)) !== -1) stmts.push(src.slice(at, src.indexOf(";", at)));
  const unscoped = stmts.filter(t => !/\.eq\("user_id", (userId|req\.user\.id)\)/.test(t));
  check("every member_leads query in lib/leadRoutes.js (" + stmts.length + ") is scoped to the caller's user_id", stmts.length >= 8 && unscoped.length === 0, J(unscoped.map(t => t.slice(0, 120))));

  console.log("\n══ 4. one owner ══");
  console.log("    lib/ownerAccount.js      : " + OWNER_ACCOUNT_ID);
  console.log("    checkRunResidue.js       : " + RESIDUE_OWNER_ID);
  check("the application's owner id and the residue guard's owner id agree", OWNER_ACCOUNT_ID === RESIDUE_OWNER_ID);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
