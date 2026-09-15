/* ══════════════════════════════════════════════════════════════════════════
   checkCollaborationsRemoved.js — the agent_collaborations mechanism is gone,
   the table is not, and the one handoff that did real work still does it.

   WHAT WAS REMOVED. orchestrateAgentWorkflow wrote an agent_collaborations
   row on every handoff — 'completed' after the executive→sales branch,
   'pending' for every other pair — and four /api/collaborations routes
   listed, read and deleted them. Nothing consumed the rows and nothing called
   the routes. Chaining (dispatchToolCall, POST /api/assignments/dispatch)
   superseded the idea on 2026-09-11. The inserts, the routes and their
   constants are gone; the table and its 13 inert rows are intentionally
   kept.

   WHAT THIS PROVES, against the live database:

     1. POST /api/assignments/:id/start still returns 200, and its
        `orchestration` object has exactly the two keys memory_created and
        sales_call_result — no collaboration_created.
     2. A start writes NO agent_collaborations row: the client server.js reads
        with is wrapped and every .from() during the handler is counted, and
        the table's row count and full contents are compared before and after.
     3. The executive→sales branch still runs: with the SDK stubbed, an
        executive start produces a sales_call_result, an ai_tasks row and an
        agent_memory row for the subject, all read back and then removed.
     4. The 13 existing rows are byte-for-byte untouched.
     5. The four removed routes answer 404 over real HTTP, and are absent from
        the router.

   WHO IT RUNS AS. The subject account named in BIZFORCE_CHECK_USER_ID, which
   the residue guard refuses to let be the owner. The owner's 13 rows are
   only ever read. requireActiveSubscription is skipped on the start route
   because the subject is unentitled by design; that gate is
   checkEntitlementGate's job, and the question here is what the handler
   does past it.

   MUTATION. MUTATE=revive does three things at once: puts an
   agent_collaborations insert back into the handoff block at compile, puts
   collaboration_created back on the result object, and re-mounts
   GET /api/collaborations after boot. The no-row, well-formed and 404 checks
   must go red; the row the mutation writes is the subject's and the residue
   guard removes it. Run it after any edit to this file.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount, OWNER_ACCOUNT_ID } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const path = require("path");
const http = require("http");
const Module = require("module");
const REPO = path.join(__dirname, "..");
const SERVER_PATH = path.join(REPO, "server.js");
const MUTATING = process.env.MUTATE === "revive";
const PORT = Number(process.env.CHECK_PORT || 4787);

/* ── the SDK, stubbed ───────────────────────────────────────────────────── */
const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);
let modelCallsAttempted = [];
function FakeAnthropic(options) {
  const instance = new RealAnthropic(options);
  instance.messages = {
    create: async function (args) {
      modelCallsAttempted.push((args && args.model) || "unknown");
      return {
        id: "msg_check_stub",
        model: (args && args.model) || "claude-sonnet-4-5",
        content: [{ type: "text", text: "CHECK STUB SALES PASS — written by scripts/checkCollaborationsRemoved.js; no model was called." }],
        usage: { input_tokens: 10, output_tokens: 5 }
      };
    }
  };
  return instance;
}
Object.keys(RealAnthropic).forEach(function (k) { FakeAnthropic[k] = RealAnthropic[k]; });
require.cache[SDK_PATH].exports = FakeAnthropic;

/* ── the Supabase client server.js builds, counted ──────────────────────── */
const SUPABASE_PATH = require.resolve("@supabase/supabase-js", { paths: [REPO] });
const realSupabase = require(SUPABASE_PATH);
const realCreateClient = realSupabase.createClient;
const dbCalls = [];
function callerFrame() { return (String(new Error().stack || "").split("\n")[3] || ""); }
require.cache[SUPABASE_PATH].exports = Object.assign({}, realSupabase, {
  createClient: function () {
    const client = realCreateClient.apply(this, arguments);
    if (callerFrame().indexOf("server.js") === -1) return client;
    const realFrom = client.from.bind(client);
    client.from = function (table) {
      dbCalls.push({ table: table, stack: String(new Error().stack || "").split("\n").slice(2, 5).join(" | ") });
      return realFrom(table);
    };
    return client;
  }
});

/* ── the mutation, at compile ───────────────────────────────────────────── */
const INSERT_ANCHOR = '    console.log("AGENT ORCHESTRATOR HANDOFF NOT RECORDED", {';
const RESULT_ANCHOR = "  var orchestrationResult = {\n    memory_created: false,\n    sales_call_result: null\n  };";
let mutationApplied = false;
if (MUTATING) {
  const realCompile = Module.prototype._compile;
  Module.prototype._compile = function (content, filename) {
    if (path.resolve(filename) === path.resolve(SERVER_PATH)) {
      [INSERT_ANCHOR, RESULT_ANCHOR].forEach(function (needle) {
        const hits = content.split(needle).length - 1;
        if (hits !== 1) { console.error("MUTATION REFUSED: expected exactly one anchor, found " + hits + ": " + needle.slice(0, 60)); process.exit(1); }
      });
      content = content
        .replace(INSERT_ANCHOR,
          '    await supabase.from("agent_collaborations").insert({ user_id: userId, source_agent: agentType, target_agent: targetAgent, ' +
          'collaboration_type: "handoff", payload: { note: "MUTATION FIXTURE — scripts/checkCollaborationsRemoved.js" }, status: "pending" });\n' +
          INSERT_ANCHOR)
        .replace(RESULT_ANCHOR, "  var orchestrationResult = {\n    memory_created: false,\n    collaboration_created: false,\n    sales_call_result: null\n  };");
      mutationApplied = true;
      console.log("\n!! MUTATION: a pending-row insert is back in the handoff block, collaboration_created is back on the result, and GET /api/collaborations will be re-mounted — the checks below must fail.");
    }
    return realCompile.call(this, content, filename);
  };
}

const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () { const made = realExpress.apply(this, arguments); if (!app) app = made; return made; };
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;

process.env.PORT = String(PORT);
require(SERVER_PATH);

const supabase = realCreateClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);

const residue = createResidueGuard({
  supabase: supabase,
  name: "collaborationsRemoved",
  subject: SUBJECT_USER_ID,
  tables: ["ai_tasks", "model_calls", "agent_memory", "agent_collaborations"]
});
residue.install();

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const START_ROUTE = { path: "/api/assignments/:id/start", method: "post" };
const REMOVED = [
  { method: "GET",    path: "/api/collaborations" },
  { method: "POST",   path: "/api/collaborations" },
  { method: "GET",    path: "/api/collaborations/00000000-0000-4000-8000-000000000000" },
  { method: "DELETE", path: "/api/collaborations/00000000-0000-4000-8000-000000000000" }
];

function layerFor(routePath, method) {
  const found = app._router.stack.filter(function (l) { return l.route && l.route.path === routePath && l.route.methods[method]; });
  if (!found.length) throw new Error("route not mounted: " + method.toUpperCase() + " " + routePath);
  return found[0];
}

async function runRoute(route, user, params, body, skip) {
  const stack = layerFor(route.path, route.method).route.stack;
  const names = stack.map(function (l) { return l.handle.name || "(anonymous)"; });
  const skipping = ["requireAuth"].concat(skip || []);
  const req = { user: user, body: body || {}, params: params || {}, query: {}, headers: {}, ip: "127.0.0.1",
    method: route.method.toUpperCase(), originalUrl: route.path, get: function () { return undefined; } };
  let sent = null;
  const res = {
    statusCode: 200, headersSent: false,
    status: function (c) { this.statusCode = c; return this; }, set: function () { return this; }, setHeader: function () { return this; },
    json: function (p) { sent = { status: this.statusCode, body: p }; this.headersSent = true; return this; },
    send: function (p) { sent = { status: this.statusCode, body: p }; this.headersSent = true; return this; },
    end: function () { this.headersSent = true; return this; }
  };
  const mark = dbCalls.length;
  let thrown = null;
  for (let i = 0; i < stack.length; i++) {
    const handle = stack[i].handle;
    if (skipping.indexOf(handle.name) !== -1) continue;
    let nextErr = null;
    await new Promise(function (resolve) {
      let done = false; const fin = function () { if (!done) { done = true; resolve(); } };
      try { Promise.resolve(handle(req, res, function (err) { nextErr = err || null; fin(); })).then(fin, function (err) { nextErr = err; fin(); }); }
      catch (err) { nextErr = err; fin(); }
    });
    if (nextErr) { thrown = nextErr; break; }
    if (sent) break;
  }
  return { sent: sent, thrown: thrown, dbCalls: dbCalls.slice(mark), layers: names };
}

function httpStatus(method, routePath) {
  return new Promise(function (resolve) {
    const req = http.request({ host: "127.0.0.1", port: PORT, method: method, path: routePath, headers: { "Content-Type": "application/json" }, timeout: 10000 },
      function (res) { let body = ""; res.on("data", function (d) { body += d; }); res.on("end", function () { resolve({ status: res.statusCode, body: body.slice(0, 160) }); }); });
    req.on("error", function (e) { resolve({ status: null, body: String(e.message) }); });
    req.on("timeout", function () { req.destroy(); resolve({ status: null, body: "timeout" }); });
    req.end(method === "POST" ? "{}" : undefined);
  });
}

async function waitForListen() {
  for (let i = 0; i < 100; i++) {
    const r = await httpStatus("GET", "/health");
    if (r.status) return true;
    await new Promise(function (res) { setTimeout(res, 200); });
  }
  return false;
}

async function collabSnapshot() {
  const r = await supabase.from("agent_collaborations").select("*").order("created_at", { ascending: true });
  if (r.error) throw r.error;
  return r.data || [];
}
function fingerprint(rows) {
  return rows.map(function (r) { return [r.id, r.user_id, r.source_agent, r.target_agent, r.status, r.updated_at, JSON.stringify(r.payload)].join("|"); }).join("\n");
}

async function subjectRowsSince(table, sinceIso) {
  const r = await supabase.from(table).select("*").eq("user_id", SUBJECT_USER_ID).gte("created_at", sinceIso).order("created_at", { ascending: true });
  return r.error ? [] : (r.data || []);
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);
  const { data: highest } = await supabase.from("model_calls").select("id").order("id", { ascending: false }).limit(1).maybeSingle();
  residue.setLedgerMark(highest ? highest.id : 0);
  const runStart = new Date(Date.now() - 2000).toISOString();

  if (MUTATING) {
    check("the mutation was applied to server.js at compile", mutationApplied === true);
    app.get("/api/collaborations", function (req, res) { res.json({ ok: true, revived: true }); });
    /* app.get appends after the 404 catch-all, which would answer first. Move
       the revived layer up to sit with the other routes, as the real one did. */
    const revived = app._router.stack.pop();
    let lastRouteIdx = -1;
    app._router.stack.forEach(function (l, i) { if (l.route) lastRouteIdx = i; });
    app._router.stack.splice(lastRouteIdx + 1, 0, revived);
  }

  const subjectResult = await supabase.from("users").select("id, email, role, banned_at, created_at").eq("id", SUBJECT_USER_ID).maybeSingle();
  const subject = subjectResult.data;
  if (!subject) { console.error("The subject account " + SUBJECT_USER_ID + " is not in users."); process.exit(1); }
  console.log("\n══ subject ══\n    " + subject.id + "  (" + subject.email + ", role " + subject.role + ")");

  /* ── the table, before ────────────────────────────────────────────────── */
  const before = await collabSnapshot();
  const beforePrint = fingerprint(before);
  console.log("\n══ agent_collaborations BEFORE ══");
  console.log("    rows: " + before.length + "   owner's: " + before.filter(function (r) { return r.user_id === OWNER_ACCOUNT_ID; }).length +
    "   subject's: " + before.filter(function (r) { return r.user_id === SUBJECT_USER_ID; }).length);
  before.forEach(function (r) {
    console.log("    " + r.created_at.slice(0, 19) + "  " + r.source_agent.padEnd(10) + " -> " + r.target_agent.padEnd(10) + " " + r.status.padEnd(9) + " updated " + r.updated_at.slice(0, 19));
  });
  check("the table holds exactly 13 rows before the run", before.length === 13, before.length + " rows");
  check("all 13 are the owner's", before.every(function (r) { return r.user_id === OWNER_ACCOUNT_ID; }));

  /* ── 1. a non-sales start: seo → content ──────────────────────────────── */
  console.log("\n══ POST /api/assignments/asg_…/start — agent_type seo (handoff rule: content) ══");
  {
    const r = await runRoute(START_ROUTE, subject, { id: "asg_check_seo_" + Date.now() },
      { agent_type: "seo", mission: "Check fixture — scripts/checkCollaborationsRemoved.js", priority: "low", timeline: "none" },
      ["requireActiveSubscription"]);
    const body = (r.sent && r.sent.body) || {};
    console.log("    layers: " + r.layers.join(" → "));
    console.log("    read-back: " + (r.sent ? (r.sent.status + " " + JSON.stringify({ ok: body.ok, executed: body.executed, orchestration: body.orchestration })) : ("nothing sent; thrown=" + (r.thrown && r.thrown.message))));
    check("the start returns 200", !!r.sent && r.sent.status === 200, r.sent ? String(r.sent.status) : "nothing sent");
    check("ok true, executed false (a template, not a run)", body.ok === true && body.executed === false);
    const keys = body.orchestration ? Object.keys(body.orchestration).sort() : [];
    check("orchestration has exactly memory_created and sales_call_result", keys.join(",") === "memory_created,sales_call_result", keys.join(","));
    check("no collaboration_created key", !body.orchestration || !("collaboration_created" in body.orchestration));
    check("memory_created is true for seo", body.orchestration && body.orchestration.memory_created === true);
    check("sales_call_result is null — seo hands to content, not sales", body.orchestration && body.orchestration.sales_call_result === null);
    const collabCalls = r.dbCalls.filter(function (c) { return c.table === "agent_collaborations"; });
    check("the handler made zero calls to agent_collaborations", collabCalls.length === 0, collabCalls.map(function (c) { return c.stack; }).join(" || "));
    console.log("    tables touched by the handler: " + r.dbCalls.map(function (c) { return c.table; }).join(", "));
    check("no model call was made for a non-sales handoff", modelCallsAttempted.length === 0, modelCallsAttempted.join(", "));
  }

  /* ── 2. the executive → sales branch ──────────────────────────────────── */
  console.log("\n══ POST /api/assignments/asg_…/start — agent_type executive (handoff rule: sales) ══");
  {
    const r = await runRoute(START_ROUTE, subject, { id: "asg_check_exec_" + Date.now() },
      { agent_type: "executive", mission: "Check fixture — scripts/checkCollaborationsRemoved.js", priority: "low", timeline: "none" },
      ["requireActiveSubscription"]);
    const body = (r.sent && r.sent.body) || {};
    const orch = body.orchestration || {};
    console.log("    read-back: " + (r.sent ? (r.sent.status + " " + JSON.stringify({ ok: body.ok, executed: body.executed,
      orchestration: { memory_created: orch.memory_created, sales_call_result: typeof orch.sales_call_result === "string" ? orch.sales_call_result.slice(0, 60) + "…" : orch.sales_call_result } })) : ("nothing sent; thrown=" + (r.thrown && r.thrown.message))));
    check("the start returns 200", !!r.sent && r.sent.status === 200, r.sent ? String(r.sent.status) : "nothing sent");
    const keys = Object.keys(orch).sort();
    check("orchestration has exactly memory_created and sales_call_result", keys.join(",") === "memory_created,sales_call_result", keys.join(","));
    check("the sales branch ran: sales_call_result is the stub's text", typeof orch.sales_call_result === "string" && orch.sales_call_result.indexOf("CHECK STUB SALES PASS") === 0,
      JSON.stringify(orch.sales_call_result).slice(0, 80));
    check("exactly one model call, to the stub", modelCallsAttempted.length === 1, modelCallsAttempted.join(", "));
    const collabCalls = r.dbCalls.filter(function (c) { return c.table === "agent_collaborations"; });
    check("the handler made zero calls to agent_collaborations", collabCalls.length === 0, collabCalls.map(function (c) { return c.stack; }).join(" || "));
    check("the handler wrote ai_tasks", r.dbCalls.some(function (c) { return c.table === "ai_tasks"; }));
    check("the handler wrote agent_memory", r.dbCalls.some(function (c) { return c.table === "agent_memory"; }));
    console.log("    tables touched by the handler: " + r.dbCalls.map(function (c) { return c.table; }).join(", "));
  }

  /* ── what the two starts wrote for the subject, read back ─────────────── */
  console.log("\n══ subject rows written by the two starts ══");
  const tasks = await subjectRowsSince("ai_tasks", runStart);
  const memories = await subjectRowsSince("agent_memory", runStart);
  tasks.forEach(function (t) { residue.record("ai_tasks", t.id); console.log("    ai_tasks     " + JSON.stringify({ id: t.id, agent_type: t.agent_type, status: t.status, prompt: String(t.prompt).slice(0, 50) })); });
  memories.forEach(function (m) { residue.record("agent_memory", m.id); console.log("    agent_memory " + JSON.stringify({ id: m.id, agent_type: m.agent_type, title: m.title })); });
  const ledger = await supabase.from("model_calls").select("id, user_id, route, model").eq("user_id", SUBJECT_USER_ID).gt("id", highest ? highest.id : 0);
  (ledger.data || []).forEach(function (row) { residue.record("model_calls", row.id); console.log("    model_calls  " + JSON.stringify(row)); });
  check("one ai_tasks row: the sales conversion pass", tasks.length === 1 && tasks[0].agent_type === "sales", tasks.length + " rows");
  check("three agent_memory rows: seo start, executive start, sales handoff",
    memories.length === 3 && memories.some(function (m) { return m.agent_type === "sales" && /handoff/i.test(m.title || ""); }),
    memories.length + " rows: " + memories.map(function (m) { return m.agent_type + ":" + m.title; }).join("; "));
  check("one ledger row, for the handoff route", (ledger.data || []).length === 1 && /handoff executive -> sales/.test(ledger.data[0].route), JSON.stringify(ledger.data));

  /* ── the table, after ─────────────────────────────────────────────────── */
  console.log("\n══ agent_collaborations AFTER ══");
  const after = await collabSnapshot();
  const subjectCollab = after.filter(function (r) { return r.user_id === SUBJECT_USER_ID; });
  subjectCollab.forEach(function (r) { residue.record("agent_collaborations", r.id); });
  console.log("    rows: " + after.length + "   owner's: " + after.filter(function (r) { return r.user_id === OWNER_ACCOUNT_ID; }).length + "   subject's: " + subjectCollab.length);
  check("the table still holds exactly 13 rows", after.length === 13, after.length + " rows (" + subjectCollab.length + " written for the subject)");
  check("no row was written for the subject", subjectCollab.length === 0, JSON.stringify(subjectCollab.map(function (r) { return r.source_agent + "->" + r.target_agent + " " + r.status; })));
  check("the 13 existing rows are byte-for-byte unchanged", fingerprint(after.filter(function (r) { return r.user_id === OWNER_ACCOUNT_ID; })) === beforePrint);

  /* ── 5. the four routes ───────────────────────────────────────────────── */
  console.log("\n══ the four removed routes ══");
  const mounted = app._router.stack.filter(function (l) { return l.route && /^\/api\/collaborations/.test(l.route.path); })
    .map(function (l) { return Object.keys(l.route.methods).join("|").toUpperCase() + " " + l.route.path; });
  check("no /api/collaborations route is in the router", mounted.length === 0, mounted.join(", "));
  const listening = await waitForListen();
  check("the server is listening on " + PORT, listening);
  for (const r of REMOVED) {
    const got = await httpStatus(r.method, r.path);
    console.log("    " + r.method.padEnd(6) + " " + r.path + "  →  " + got.status + " " + got.body);
    check(r.method + " " + r.path + " answers 404 over HTTP", got.status === 404, String(got.status));
  }

  console.log("");
  const cleanupResult = await residue.cleanup("end of run");
  if (cleanupResult.leftovers.length) failures++;

  const final = await collabSnapshot();
  console.log("\n══ agent_collaborations after cleanup ══\n    rows: " + final.length);
  check("13 rows after cleanup", final.length === 13, String(final.length));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("checkCollaborationsRemoved crashed:", err && (err.stack || err.message) || err);
  residue.cleanup("crash").then(function () { process.exit(1); }, function () { process.exit(1); });
});
