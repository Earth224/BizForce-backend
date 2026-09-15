/* ══════════════════════════════════════════════════════════════════════════
   checkLeadRadarOwnerGate.js — the four lead routes that handed every account
   the owner's leads, and the proof they now refuse before reading anything.

   WHAT WAS WRONG. bsky_leads has no owner column: every one of its ~7,000
   rows was captured by the owner's keyword list, scored against the owner's
   three products and paid for with the owner's key. GET /api/leads and
   GET /api/agents/sales/leads returned the top of that table to ANY account
   with a valid token, paid or free. POST /api/agents/sales/lead-status let
   any account pull any of those rows into its own pipeline by post_uri, and
   GET /api/agents/sales/pipeline joined them back. A second customer opened
   Lead Radar and saw the first customer's leads, presented as their own,
   with a Convert button that then answered 403.

   WHAT THIS PROVES, against the live database:

     1. A non-owner account gets 403 with code "lead_radar_unavailable" from
        all four routes, and the handler makes ZERO Supabase calls on the way
        to that refusal — measured, not assumed: the client server.js reads
        with is wrapped before server.js loads and every .from() is counted.
     2. The refusal is a statement of fact with no timeline in it.
     3. The owner still gets their leads, unchanged: what the route returns is
        compared row for row against the same query run directly.
     4. POST /api/leads/draft-reply is NOT gated by owner. A non-owner runs it
        to a 200 with the SDK stubbed, so nothing is spent; the ledger row it
        writes is read back and then removed by the residue guard.
     5. The one owner literal in lib/ownerAccount.js agrees with the residue
        guard's own copy, which is deliberately not derived from it.

   WHO IT RUNS AS. The non-owner is the subject account named in
   BIZFORCE_CHECK_USER_ID, which the residue guard refuses to let be the
   owner. The owner's account is only ever READ here — three GETs and one
   POST with an empty body that stops at validation — and the residue guard
   is pointed at the subject, never at the owner.

   WHY THE HANDLERS RUN AND NOT JUST THE MIDDLEWARE. The guard under test is
   inside each handler, ahead of its first query, because that is where the
   convert route already had it. So the route's real layer stack is walked
   with requireAuth replaced by the users row it would have attached, and the
   handler itself runs. For the four lead routes that is safe for both
   subjects: a refusal touches nothing, and the owner's three reads are
   reads. The owner's lead-status call is made with no body so the route
   answers 400 at validation, which proves the guard let the owner past it
   without writing a pipeline row.

   MUTATION. MUTATE=unguard-leads rewrites server.js as it is compiled so the
   guard on GET /api/leads is `if (false)`. The refusal, zero-read and row
   checks for that route must go red and every other route must stay green.
   Run it after any edit to this file.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount, OWNER_ACCOUNT_ID: RESIDUE_OWNER_ID } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const path = require("path");
const Module = require("module");
const REPO = path.join(__dirname, "..");
const { OWNER_ACCOUNT_ID } = require(path.join(REPO, "lib", "ownerAccount.js"));

const MUTATING = process.env.MUTATE === "unguard-leads";

/* ── the SDK, stubbed ─────────────────────────────────────────────────────
   Only draft-reply is expected to reach a model call, and it reaches this
   instead: a canned reply with a usage block, so the handler's own ledger
   write runs against a call that cost nothing. Any call from any other route
   is a failure, and the route is named in it. */
const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);
let modelCallsAttempted = [];
let currentRoute = "(none)";

function FakeAnthropic(options) {
  const instance = new RealAnthropic(options);
  instance.messages = {
    create: async function (args) {
      modelCallsAttempted.push({ route: currentRoute, model: (args && args.model) || "unknown" });
      return {
        id: "msg_check_stub",
        model: (args && args.model) || "claude-haiku-4-5-20251001",
        content: [{ type: "text", text: "CHECK STUB REPLY — written by scripts/checkLeadRadarOwnerGate.js, no model was called." }],
        usage: { input_tokens: 10, output_tokens: 5 }
      };
    }
  };
  return instance;
}
Object.keys(RealAnthropic).forEach(function (k) { FakeAnthropic[k] = RealAnthropic[k]; });
require.cache[SDK_PATH].exports = FakeAnthropic;

/* ── the Supabase client, counted ─────────────────────────────────────────
   createClient is wrapped so that the client server.js builds at load has its
   .from() recorded: table, and the stack it was called from. Only the client
   whose createClient call site is server.js is recorded — leadRadar.js and
   the two other radars build their own and start ticking in the listen
   callback, and their reads are not what is being measured. */
const SUPABASE_PATH = require.resolve("@supabase/supabase-js", { paths: [REPO] });
const realSupabase = require(SUPABASE_PATH);
const realCreateClient = realSupabase.createClient;
const dbCalls = [];

function callerFile() {
  const lines = String(new Error().stack || "").split("\n");
  /* [0] "Error", [1] this function, [2] the wrapper, [3] the caller. */
  return lines[3] || "";
}

const wrappedSupabase = Object.assign({}, realSupabase, {
  createClient: function () {
    const client = realCreateClient.apply(this, arguments);
    const creator = callerFile();
    if (creator.indexOf("server.js") === -1) return client;
    const realFrom = client.from.bind(client);
    client.from = function (table) {
      dbCalls.push({ table: table, stack: String(new Error().stack || "").split("\n").slice(2, 6).join(" | "), at: Date.now() });
      return realFrom(table);
    };
    return client;
  }
});
require.cache[SUPABASE_PATH].exports = wrappedSupabase;

/* ── the mutation, applied at compile ─────────────────────────────────────
   The guard is inline in the handler, so there is no layer to splice out.
   Instead server.js is rewritten as Node compiles it: the first
   `req.user.id !== OUTREACH_CREDENTIAL_OWNER_ID` in the file is the GET
   /api/leads guard (the other three compare a local `userId`), and it becomes
   `false`. Exactly one replacement is required, or the mutation is refused —
   a mutation that silently hit nothing would leave a green run claiming to
   have been tested red. */
const SERVER_PATH = path.join(REPO, "server.js");
const NEEDLE = "if (req.user.id !== OUTREACH_CREDENTIAL_OWNER_ID) {";
let mutationApplied = false;
if (MUTATING) {
  const realCompile = Module.prototype._compile;
  Module.prototype._compile = function (content, filename) {
    if (path.resolve(filename) === path.resolve(SERVER_PATH)) {
      const hits = content.split(NEEDLE).length - 1;
      if (hits !== 1) {
        console.error("MUTATION REFUSED: expected exactly one `" + NEEDLE + "` in server.js, found " + hits + ".");
        process.exit(1);
      }
      content = content.replace(NEEDLE, "if (false) {");
      mutationApplied = true;
      console.log("\n!! MUTATION: the owner guard on GET /api/leads is now `if (false)` — that route's refusal checks below must fail.");
    }
    return realCompile.call(this, content, filename);
  };
}

const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () {
  const made = realExpress.apply(this, arguments);
  if (!app) app = made;
  return made;
};
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;

process.env.PORT = process.env.CHECK_PORT || "0";
require(SERVER_PATH);

/* This script's own client: built here, after the wrapper, from a call site
   that is not server.js, so its reads are not counted against any route. */
const supabase = realCreateClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

const residue = createResidueGuard({
  supabase: supabase,
  name: "leadRadarOwnerGate",
  subject: SUBJECT_USER_ID,
  tables: ["ai_tasks", "model_calls"]
});
residue.install();

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const LEAD_ROUTES = [
  { path: "/api/leads",                    method: "get"  },
  { path: "/api/agents/sales/leads",       method: "get"  },
  { path: "/api/agents/sales/lead-status", method: "post" },
  { path: "/api/agents/sales/pipeline",    method: "get"  }
];
const DRAFT_ROUTE = { path: "/api/leads/draft-reply", method: "post" };

/* Words that turn a statement of fact into a promise. The refusal is read by a
   paying customer, and this product has shipped enough interfaces that
   promised what nothing delivered. */
const PROMISE_WORDS = /\b(yet|soon|until|coming|will be|planned|later)\b/i;

function layerFor(routePath, method) {
  const found = app._router.stack.filter(function (l) {
    return l.route && l.route.path === routePath && l.route.methods[method];
  });
  if (!found.length) throw new Error("route not mounted: " + method.toUpperCase() + " " + routePath);
  return found[0];
}

function chainNames(routePath, method) {
  return layerFor(routePath, method).route.stack.map(function (l) {
    return l.handle.name || "(anonymous)";
  });
}

/* Runs the route's real layers with requireAuth replaced by the users row it
   would have attached, plus any further layers named in `skip`. Returns what
   was sent, which layer sent it, and every server.js Supabase call made while
   it ran. */
async function runRoute(route, user, body, skip) {
  const layer = layerFor(route.path, route.method);
  const stack = layer.route.stack;
  const names = chainNames(route.path, route.method);
  const skipping = ["requireAuth"].concat(skip || []);

  const req = {
    user: user,
    body: body || {},
    params: {},
    query: {},
    headers: {},
    ip: "127.0.0.1",
    method: route.method.toUpperCase(),
    originalUrl: route.path,
    get: function () { return undefined; }
  };

  let sent = null;
  let stoppedAt = null;
  const res = {
    statusCode: 200,
    headersSent: false,
    status: function (code) { this.statusCode = code; return this; },
    set: function () { return this; },
    setHeader: function () { return this; },
    json: function (payload) { sent = { status: this.statusCode, body: payload }; this.headersSent = true; return this; },
    send: function (payload) { sent = { status: this.statusCode, body: payload }; this.headersSent = true; return this; },
    end: function () { this.headersSent = true; return this; }
  };

  currentRoute = route.method.toUpperCase() + " " + route.path;
  const mark = dbCalls.length;
  let thrown = null;

  for (let i = 0; i < stack.length; i++) {
    const handle = stack[i].handle;
    if (skipping.indexOf(handle.name) !== -1) continue;

    let nextErr = null;
    await new Promise(function (resolve) {
      let done = false;
      const fin = function () { if (!done) { done = true; resolve(); } };
      try {
        Promise.resolve(handle(req, res, function (err) { nextErr = err || null; fin(); }))
          .then(fin, function (err) { nextErr = err; fin(); });
      } catch (err) { nextErr = err; fin(); }
    });

    if (nextErr) { thrown = nextErr; stoppedAt = names[i]; break; }
    if (sent) { stoppedAt = names[i]; break; }
  }

  currentRoute = "(none)";
  return { sent: sent, stoppedAt: stoppedAt, thrown: thrown, dbCalls: dbCalls.slice(mark), layers: names };
}

async function userRow(id) {
  const r = await supabase.from("users").select("id, email, role, banned_at, created_at").eq("id", id).maybeSingle();
  if (r.error) throw r.error;
  return r.data;
}

async function subjectCounts(userId) {
  const out = {};
  for (const t of ["ai_tasks", "model_calls", "sales_lead_pipeline", "agent_memory"]) {
    const r = await supabase.from(t).select("id", { count: "exact", head: true }).eq("user_id", userId);
    out[t] = r.error ? ("ERR " + r.error.message) : r.count;
  }
  return out;
}

function idSet(rows) { return (rows || []).map(function (r) { return r.id; }).sort(); }
function sameSet(a, b) { return a.length === b.length && a.every(function (v, i) { return v === b[i]; }); }
function leadLine(l) {
  return JSON.stringify({ id: l.id, source: l.source, intent_score: l.intent_score, status: l.status,
    author_handle: l.author_handle, sales_status: l.sales_status });
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  const { data: highest } = await supabase.from("model_calls").select("id").order("id", { ascending: false }).limit(1).maybeSingle();
  residue.setLedgerMark(highest ? highest.id : 0);

  if (MUTATING) check("the mutation was applied to server.js at compile", mutationApplied === true);

  console.log("\n══ the one literal, and the guard's own copy ══");
  console.log("    lib/ownerAccount.js      : " + OWNER_ACCOUNT_ID);
  console.log("    checkRunResidue.js       : " + RESIDUE_OWNER_ID);
  check("the application's owner id and the residue guard's owner id agree", OWNER_ACCOUNT_ID === RESIDUE_OWNER_ID);
  check("the subject account is not the owner", SUBJECT_USER_ID !== OWNER_ACCOUNT_ID.toLowerCase());

  console.log("\n══ subjects ══");
  const subject = await userRow(SUBJECT_USER_ID);
  const owner = await userRow(OWNER_ACCOUNT_ID);
  if (!subject) { console.error("The subject account " + SUBJECT_USER_ID + " is not in users."); process.exit(1); }
  if (!owner) { console.error("The owner account " + OWNER_ACCOUNT_ID + " is not in users."); process.exit(1); }
  console.log("    non-owner : " + subject.id + "  (" + subject.email + ", role " + subject.role + ")");
  console.log("    owner     : " + owner.id + "  (" + owner.email + ", role " + owner.role + ")");

  const before = await subjectCounts(subject.id);
  console.log("\n══ non-owner row counts BEFORE ══\n    " + JSON.stringify(before));

  /* ── 1. every lead route refuses the non-owner before reading ─────────── */
  for (const route of LEAD_ROUTES) {
    const label = route.method.toUpperCase() + " " + route.path;
    console.log("\n══ " + label + " — non-owner ══");

    const layer = layerFor(route.path, route.method);
    const handlerSrc = layer.route.stack[layer.route.stack.length - 1].handle.toString();
    const guardAt = handlerSrc.indexOf("OUTREACH_CREDENTIAL_OWNER_ID");
    const firstQueryAt = handlerSrc.indexOf("supabase");
    console.log("    layers: " + chainNames(route.path, route.method).join(" → "));
    check("the handler compares against OUTREACH_CREDENTIAL_OWNER_ID", guardAt !== -1);
    check("and does so before its first reference to supabase", guardAt !== -1 && firstQueryAt !== -1 && guardAt < firstQueryAt,
      "guard at " + guardAt + ", first supabase at " + firstQueryAt);

    const r = await runRoute(route, subject, { lead_post_uri: "at://check/does-not-exist", status: "contacted" });
    const body = (r.sent && r.sent.body) || {};
    console.log("    read-back: " + (r.sent ? (r.sent.status + " " + JSON.stringify(r.sent.body)) : ("nothing sent; thrown=" + (r.thrown && r.thrown.message))));
    check("a non-owner account is refused with 403", !!r.sent && r.sent.status === 403,
      r.sent ? ("status " + r.sent.status) : "nothing was sent");
    check("the refusal carries code lead_radar_unavailable", body.code === "lead_radar_unavailable", JSON.stringify(body));
    check("the refusal has a message", typeof body.error === "string" && body.error.length > 20);
    check("the message is a statement of fact, not a promise", typeof body.error === "string" && !PROMISE_WORDS.test(body.error),
      typeof body.error === "string" ? (body.error.match(PROMISE_WORDS) || [])[0] : "no message");
    check("zero Supabase calls were made by the handler", r.dbCalls.length === 0,
      r.dbCalls.map(function (c) { return c.table + " @ " + c.stack; }).join(" || "));
    check("no lead rows came back", !Array.isArray(body.leads) || body.leads.length === 0,
      Array.isArray(body.leads) ? (body.leads.length + " rows") : "");
  }

  /* ── 2. the owner is unaffected ───────────────────────────────────────── */
  console.log("\n══ GET /api/leads — owner ══");
  {
    const r = await runRoute(LEAD_ROUTES[0], owner);
    const leads = (r.sent && r.sent.body && r.sent.body.leads) || [];
    const direct = await supabase.from("bsky_leads").select("id").eq("status", "scored")
      .order("intent_score", { ascending: false }).limit(100);
    check("the owner gets 200", !!r.sent && r.sent.status === 200, r.sent && (r.sent.status + " " + JSON.stringify(r.sent.body).slice(0, 200)));
    check("the owner gets rows", leads.length > 0, leads.length + " rows");
    check("the route read bsky_leads", r.dbCalls.some(function (c) { return c.table === "bsky_leads"; }),
      r.dbCalls.map(function (c) { return c.table; }).join(", "));
    check("exactly the rows the same query returns directly (" + (direct.data || []).length + ")",
      !direct.error && sameSet(idSet(leads), idSet(direct.data)),
      direct.error ? direct.error.message : (leads.length + " via route vs " + (direct.data || []).length + " direct"));
    console.log("    read-back (first 3 of " + leads.length + "):");
    leads.slice(0, 3).forEach(function (l) { console.log("      " + leadLine(l)); });
  }

  console.log("\n══ GET /api/agents/sales/leads — owner ══");
  {
    const r = await runRoute(LEAD_ROUTES[1], owner);
    const leads = (r.sent && r.sent.body && r.sent.body.leads) || [];
    const direct = await supabase.from("bsky_leads").select("id").eq("status", "scored")
      .order("intent_score", { ascending: false }).limit(200);
    check("the owner gets 200", !!r.sent && r.sent.status === 200, r.sent && (r.sent.status + " " + JSON.stringify(r.sent.body).slice(0, 200)));
    check("the owner gets rows", leads.length > 0, leads.length + " rows");
    check("exactly the rows the same query returns directly (" + (direct.data || []).length + ")",
      !direct.error && sameSet(idSet(leads), idSet(direct.data)),
      direct.error ? direct.error.message : (leads.length + " via route vs " + (direct.data || []).length + " direct"));
    check("every row is annotated with the owner's pipeline status",
      leads.length > 0 && leads.every(function (l) { return typeof l.sales_status === "string"; }));
    const tracked = leads.filter(function (l) { return l.sales_status !== "new"; });
    console.log("    read-back (first 3 of " + leads.length + "; " + tracked.length + " carry a pipeline status other than new):");
    leads.slice(0, 3).forEach(function (l) { console.log("      " + leadLine(l)); });
  }

  console.log("\n══ GET /api/agents/sales/pipeline — owner ══");
  {
    const r = await runRoute(LEAD_ROUTES[3], owner);
    const grouped = (r.sent && r.sent.body && r.sent.body.pipeline) || {};
    const total = Object.keys(grouped).reduce(function (n, k) { return n + grouped[k].length; }, 0);
    const direct = await supabase.from("sales_lead_pipeline").select("id", { count: "exact", head: true }).eq("user_id", owner.id);
    check("the owner gets 200", !!r.sent && r.sent.status === 200, r.sent && (r.sent.status + " " + JSON.stringify(r.sent.body).slice(0, 200)));
    check("the board holds every pipeline row the owner has (" + direct.count + ")", !direct.error && total === direct.count,
      total + " on the board vs " + direct.count + " in the table");
    const counts = {};
    Object.keys(grouped).forEach(function (k) { counts[k] = grouped[k].length; });
    console.log("    read-back: " + JSON.stringify(counts));
  }

  console.log("\n══ POST /api/agents/sales/lead-status — owner, empty body ══");
  {
    const pipeBefore = await supabase.from("sales_lead_pipeline").select("id", { count: "exact", head: true }).eq("user_id", owner.id);
    const r = await runRoute(LEAD_ROUTES[2], owner, {});
    const pipeAfter = await supabase.from("sales_lead_pipeline").select("id", { count: "exact", head: true }).eq("user_id", owner.id);
    console.log("    read-back: " + (r.sent ? (r.sent.status + " " + JSON.stringify(r.sent.body)) : "nothing sent"));
    check("the owner passes the guard and stops at validation (400)", !!r.sent && r.sent.status === 400,
      r.sent ? ("status " + r.sent.status + " " + JSON.stringify(r.sent.body)) : "nothing was sent");
    check("the refusal is not the owner guard", !r.sent || !r.sent.body || r.sent.body.code !== "lead_radar_unavailable");
    check("nothing was written to the owner's pipeline", pipeBefore.count === pipeAfter.count, pipeBefore.count + " → " + pipeAfter.count);
    check("zero Supabase calls were made", r.dbCalls.length === 0, r.dbCalls.map(function (c) { return c.table; }).join(", "));
  }

  /* ── 3. draft-reply is not owner-gated ────────────────────────────────── */
  console.log("\n══ POST /api/leads/draft-reply — non-owner ══");
  {
    const names = chainNames(DRAFT_ROUTE.path, DRAFT_ROUTE.method);
    console.log("    layers: " + names.join(" → "));
    const handlerSrc = layerFor(DRAFT_ROUTE.path, DRAFT_ROUTE.method).route.stack.slice(-1)[0].handle.toString();
    check("the handler has no owner comparison in it", handlerSrc.indexOf("OUTREACH_CREDENTIAL_OWNER_ID") === -1);
    check("it is still entitlement-gated (that gate is checkEntitlementGate's job)", names.indexOf("requireActiveSubscription") !== -1);

    /* requireActiveSubscription is skipped here on purpose: the subject
       account is unentitled by design, and the question this block asks is
       whether the HANDLER serves a non-owner, not whether the gate lets an
       unpaid account through. The SDK is stubbed, so the 200 below costs
       nothing; the ledger row it writes is the subject's and is removed. */
    const r = await runRoute(DRAFT_ROUTE, subject,
      { post_text: "anyone tried tongkat ali? (check fixture, scripts/checkLeadRadarOwnerGate.js)", suggested_product: "Tongkat Ali" },
      ["requireActiveSubscription"]);
    console.log("    read-back: " + (r.sent ? (r.sent.status + " " + JSON.stringify(r.sent.body)) : ("nothing sent; thrown=" + (r.thrown && r.thrown.message))));
    check("a non-owner gets 200", !!r.sent && r.sent.status === 200, r.sent ? ("status " + r.sent.status + " " + JSON.stringify(r.sent.body)) : "nothing was sent");
    check("with a reply", !!r.sent && r.sent.body && typeof r.sent.body.reply === "string" && r.sent.body.reply.indexOf("CHECK STUB REPLY") === 0);
    check("the model call went to the stub, from this route only",
      modelCallsAttempted.length === 1 && modelCallsAttempted[0].route === "POST /api/leads/draft-reply",
      JSON.stringify(modelCallsAttempted));

    const ledger = await supabase.from("model_calls").select("id, user_id, route, model, input_tokens, output_tokens")
      .eq("user_id", subject.id).gt("id", highest ? highest.id : 0).order("id", { ascending: false });
    (ledger.data || []).forEach(function (row) { residue.record("model_calls", row.id); });
    check("one ledger row was written for the non-owner", !ledger.error && (ledger.data || []).length === 1,
      ledger.error ? ledger.error.message : ((ledger.data || []).length + " rows"));
    (ledger.data || []).forEach(function (row) { console.log("    ledger read-back: " + JSON.stringify(row)); });
  }

  /* ── 4. the non-owner's tables ────────────────────────────────────────── */
  console.log("\n══ non-owner row counts AFTER ══");
  const after = await subjectCounts(subject.id);
  console.log("    " + JSON.stringify(after));
  check("zero sales_lead_pipeline rows written for the non-owner", after.sales_lead_pipeline === before.sales_lead_pipeline,
    before.sales_lead_pipeline + " → " + after.sales_lead_pipeline);
  check("zero agent_memory rows written for the non-owner", after.agent_memory === before.agent_memory,
    before.agent_memory + " → " + after.agent_memory);
  check("zero ai_tasks rows written for the non-owner", after.ai_tasks === before.ai_tasks,
    before.ai_tasks + " → " + after.ai_tasks);
  check("exactly one model_calls row written for the non-owner (draft-reply's, removed below)",
    after.model_calls === before.model_calls + 1, before.model_calls + " → " + after.model_calls);

  console.log("");
  const cleanupResult = await residue.cleanup("end of run");
  const leftovers = cleanupResult.leftovers.map(function (l) { return l.table + ": " + l.ids.join(", "); });
  if (leftovers.length) failures++;

  const final = await subjectCounts(subject.id);
  console.log("\n══ non-owner row counts after cleanup ══\n    " + JSON.stringify(final));
  check("the ledger row is gone", final.model_calls === before.model_calls, before.model_calls + " → " + final.model_calls);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("checkLeadRadarOwnerGate crashed:", err && (err.stack || err.message) || err);
  residue.cleanup("crash").then(function () { process.exit(1); }, function () { process.exit(1); });
});
