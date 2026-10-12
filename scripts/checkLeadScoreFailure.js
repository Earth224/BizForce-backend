"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkLeadScoreFailure — a failed score is not a score.

   THE DEFECT. When scoring a lead failed three times, leadRadar.js wrote
   intent_score 0 with status "scored" and intent_reason "scoring failed after
   3 attempts". 1,589 live rows carried it: a judgement nobody made, stored as a
   real low score, sorted and counted with the real ones.

   scoreNewLeads (leadRadar.js) and the five bsky_leads consumers in server.js —
   GET /api/leads, GET /api/agents/sales/leads, GET /api/agents/sales/pipeline,
   POST /api/agents/sales/convert and runSalesAutoConvert — are lifted and run
   in a vm against a fake Supabase that applies the filters and Postgres's own
   ordering rule (a descending sort puts nulls FIRST unless told otherwise).
   Anthropic is a stub class; convertSingleLead is a spy that drafts nothing.
   No network, no model, no database.

   WHAT THIS PROVES
     1. Three failed scorings: the first two leave the lead "new" with its
        attempt count; the third writes intent_score null (written, not
        omitted), status "score_failed" and the failure reason. The scorer
        never picks it up again. A successful scoring is unchanged: the score
        and status "scored".
     2. GET /api/leads and GET /api/agents/sales/leads show only real scores —
        no null, no failed row, no legacy 0-with-the-failure-reason — even when
        the database hands those rows back; each query asks for a non-null
        score and orders it with nulls last.
     3. The pipeline keeps a failed lead's row but shows no number: intent_score
        null and score_label "scoring failed".
     4. runSalesAutoConvert drafts only for real scores, even when the database
        returns failed and null-score rows; its query excludes null scores and
        orders nulls last.
     5. POST /api/agents/sales/convert refuses a named failed lead (not_scored)
        and its segment path drafts only real scores.

   MUTATE=<name> edits the lifted source (nothing on disk is touched).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly once
   is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkLeadScoreFailure: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkLeadScoreFailure: no network"); };

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const SERVER = "server.js", RADAR = "leadRadar.js";

const MUTATIONS = {
  // the failure path writes a number again
  "write-zero-on-failure": [[RADAR, "            intent_score:   null,\n            intent_reason:  LEAD_SCORE_FAILED_REASON,\n",
    "            intent_score:   0,\n            intent_reason:  LEAD_SCORE_FAILED_REASON,\n"]],
  // the failure path keeps status "scored"
  "keep-scored-on-failure": [[RADAR, "            status:         \"score_failed\"\n", "            status:         \"scored\"\n"]],
  // GET /api/leads orders without nulls last
  "drop-nulls-last": [[SERVER, "      .order(\"intent_score\", { ascending: false, nullsFirst: false })\n      .limit(100);",
    "      .order(\"intent_score\", { ascending: false })\n      .limit(100);"]],
  // auto-convert takes whatever rows the database returns
  "auto-convert-takes-null-score": [[SERVER,
    "          .filter(leadHasRealScore)\n          .filter(function (lead) { return excludedUris.indexOf(lead.post_uri) === -1; })\n          .slice(0, 5);",
    "          .filter(function (lead) { return excludedUris.indexOf(lead.post_uri) === -1; })\n          .slice(0, 5);"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[SERVER, RADAR].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── lifting ────────────────────────────────────────────────────────────── */
const uncommented = (code) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function lifter(SRC, STUBS) {
  const SPANS = [];
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
  function definitionOf(name) {
    let d = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
    if (d) return SRC.slice(d.index, s.braceMatch(SRC, SRC.indexOf(") {", d.index) + 2));
    const r2 = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
    while ((d = r2.exec(SRC)) && SPANS.some(([x, y]) => d.index > x && d.index < y)) { /* a local */ }
    if (!d) return null;
    const brk = /;\n/g; brk.lastIndex = d.index + d[0].length;
    let b;
    while ((b = brk.exec(SRC))) {
      const next = SRC[b.index + b[0].length];
      if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(d.index, b.index + 1);
    }
    return null;
  }
  return function closure(root) {
    const have = new Map();
    const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
    while (queue.length) {
      const name = queue.shift();
      if (have.has(name) || STUBS.has(name)) continue;
      const def = definitionOf(name);
      if (!def) continue;
      // A module import is the process's, never the lifted code's: skipped.
      if (/^(?:var|const|let) [^=]*=[^;]*\brequire\(/.test(def)) continue;
      try { new vm.Script(def); } catch (e) { continue; }
      have.set(name, def);
      new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
    }
    return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
  };
}
function routeText(SRC, method, route) {
  const sig = "app." + method + "(\"" + route + "\",";
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}

const SERVER_STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch",
  "requireAuth", "requireActiveSubscription", "aiLimiter", "OUTREACH_CREDENTIAL_OWNER_ID", "OWNER_ACCOUNT_ID", "convertSingleLead",
  "getLiveStats", "buildAgentSystemPrompt", "createPassEntitlementCache", "SALES_AGENT_BRAIN", "Date"]);
const serverClosure = lifter(FILES[SERVER], SERVER_STUBS);
/* Five column-0 constants the outreach code reads, taken verbatim by a direct
   extractor: the closure's "is this a local inside a function" test misreads
   them, so they would otherwise not be lifted at all. A one-line constant runs
   to the end of its line; an immediately-invoked one to its closing "})();". */
function constantText(SRC, name) {
  const start = SRC.search(new RegExp("^(?:var|const) " + name + " = ", "m"));
  if (start < 0) throw new Error(name + " not found in server.js");
  const line = SRC.slice(start, SRC.indexOf("\n", start));
  if (/= \(function \(\) \{$/.test(line)) return SRC.slice(start, SRC.indexOf("\n})();", start) + 6);
  if (!/;$/.test(line)) throw new Error(name + " is not a one-line or immediately-invoked constant");
  return line;
}
const OUTREACH_CONSTANTS = ["OUTREACH_MIN_INTENT", "OUTREACH_SENDABLE_SOURCES", "OUTREACH_MAX_POST_AGE_DAYS", "SALES_ENGAGED_STATUSES", "DRAFT_ATTEMPT_CEILING"];
OUTREACH_CONSTANTS.forEach(n => SERVER_STUBS.add(n));
const SERVER_LIFTED = OUTREACH_CONSTANTS.map(n => constantText(FILES[SERVER], n)).join("\n\n") + "\n\n" + serverClosure([
  routeText(FILES[SERVER], "get", "/api/leads"), routeText(FILES[SERVER], "get", "/api/agents/sales/leads"),
  routeText(FILES[SERVER], "get", "/api/agents/sales/pipeline"), routeText(FILES[SERVER], "post", "/api/agents/sales/convert")
].join("\n\n") + "\n\nthis.api = { runSalesAutoConvert: runSalesAutoConvert, leadHasRealScore: leadHasRealScore };");

const RADAR_STUBS = new Set(["supabase", "SCORING_ACCOUNT_ID", "console", "process", "require", "module", "Anthropic", "resolveAnthropicKey", "setTimeout", "Date"]);
const RADAR_LIFTED = lifter(FILES[RADAR], RADAR_STUBS)("this.scoreNewLeads = scoreNewLeads;");

/* ── the fake database, with Postgres's ordering ───────────────────────── */
function fakeDb(seed, raw) {
  const tables = {};
  Object.keys(seed).forEach(t => { tables[t] = seed[t].map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  const copy = v => JSON.parse(JSON.stringify(v));
  function keep(q, row) {
    return q.filters.every(f => {
      const [op, col, a, b] = f;
      if (op === "eq") return row[col] === a;
      if (op === "neq") return row[col] !== a && row[col] != null;
      if (op === "in") return a.indexOf(row[col]) !== -1;
      if (op === "gte") return row[col] != null && row[col] >= a;
      if (op === "not" && a === "is" && b === null) return row[col] != null;
      if (op === "not" && a === "in") return true;
      return true;
    });
  }
  function ordered(q, rows) {
    const orders = q.filters.filter(f => f[0] === "order");
    if (!orders.length) return rows;
    const [, col, opts] = orders[0];
    const asc = !opts || opts.ascending !== false;
    const nullsFirst = opts && typeof opts.nullsFirst === "boolean" ? opts.nullsFirst : !asc;   // Postgres's default
    return rows.slice().sort((x, y) => {
      const a = x[col], b = y[col];
      if (a == null && b == null) return 0;
      if (a == null) return nullsFirst ? -1 : 1;
      if (b == null) return nullsFirst ? 1 : -1;
      return (a < b ? -1 : a > b ? 1 : 0) * (asc ? 1 : -1);
    });
  }
  function answer(q) {
    const rows = tables[q.table] || [];
    if (q.op === "update") {
      const hit = rows.filter(r => keep(q, r));
      hit.forEach(r => Object.assign(r, copy(q.payload)));
      return Promise.resolve({ data: null, error: null });
    }
    let hits = raw && raw[q.table] ? raw[q.table].map(copy) : ordered(q, rows.filter(r => keep(q, r)));
    const limit = q.filters.find(f => f[0] === "limit");
    if (limit && !(raw && raw[q.table])) hits = hits.slice(0, limit[1]);
    if (q.single) return Promise.resolve({ data: hits[0] ? copy(hits[0]) : null, error: null });
    return Promise.resolve({ data: hits.map(copy), error: null });
  }
  function from(table) {
    const q = { table, op: "select", payload: null, filters: [], single: false };
    log.push(q);
    const b = {
      select() { return b; },
      update(p) { q.op = "update"; q.payload = p; return b; }
    };
    ["eq", "neq", "in", "not", "gte", "order", "limit", "range"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { tables, log, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const OWNER = "ea887c6e-e278-4a15-b7e9-cd78a9949b78";
const FAILED = "scoring failed after 3 attempts";
const fresh = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
const lead = (k, extra) => Object.assign({ id: "lead-" + k, post_uri: "at://did:plc:x/app.bsky.feed.post/" + k, author_handle: "h" + k + ".bsky.social",
  post_text: "post " + k, source: "bluesky", post_created_at: fresh, outreach_safe: true, reply_invited: true,
  suggested_product: "Tongkat Ali", matched_keyword: "anyone tried tongkat ali" }, extra);
const L = {
  good80: lead("good80", { status: "scored", intent_score: 80, intent_reason: "asks the room" }),
  good65: lead("good65", { status: "scored", intent_score: 65, intent_reason: "asks for help" }),
  legacy: lead("legacy", { status: "scored", intent_score: 0, intent_reason: FAILED, outreach_safe: true, reply_invited: true }),
  failed: lead("failed", { status: "score_failed", intent_score: null, intent_reason: FAILED }),
  nullScored: lead("nullScored", { status: "scored", intent_score: null, intent_reason: "no number" })
};
const ALL = [L.legacy, L.nullScored, L.good65, L.failed, L.good80];
const realOnly = (rows) => rows.every(r => Number.isInteger(r.intent_score) && r.status === "scored" && r.intent_reason !== FAILED);

function server(seed, raw) {
  const db = fakeDb(seed, raw);
  const drafted = [];
  const ctx = {
    supabase: db.client, JSON, Math, Promise, Date, Number, Object, Array, String,
    nowIso: () => new Date().toISOString(),
    process: { env: { SALES_AUTOLOOP_DRY_RUN: "true" } },
    console: { log() {}, error() {}, warn() {} },
    OUTREACH_CREDENTIAL_OWNER_ID: OWNER, OWNER_ACCOUNT_ID: OWNER, SALES_AGENT_BRAIN: "BRAIN",
    requireAuth: function requireAuth(req, res, next) { next(); },
    requireActiveSubscription: function requireActiveSubscription(req, res, next) { next(); },
    aiLimiter: function aiLimiter(req, res, next) { next(); },
    convertSingleLead: async (userId, l) => { drafted.push(l.id); return { skipped: false, draft: "d" }; },
    getLiveStats: async () => ({}), buildAgentSystemPrompt: () => "SYSTEM",
    createPassEntitlementCache: () => async () => ({ plan: { active: true } })
  };
  const routes = {};
  const reg = (m) => function (p) { routes[m + " " + p] = [].slice.call(arguments, 1); };
  ctx.app = { get: reg("get"), post: reg("post") };
  vm.createContext(ctx);
  vm.runInContext(SERVER_LIFTED, ctx);
  async function call(key, body, query) {
    const chain = routes[key];
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    const req = { user: { id: OWNER, role: "admin" }, params: {}, query: query || {}, body: body || {} };
    let i = 0;
    async function step() {
      const fn = chain[i++];
      if (!fn) return;
      let advanced = false;
      await fn(req, res, (e) => { if (e) { res.code = 500; res.body = { error: String(e.message || e) }; return; } advanced = true; });
      if (advanced) await step();
    }
    await step();
    return { status: res.code, body: res.body };
  }
  return { db, ctx, call, drafted, api: ctx.api };
}
const leadsQuery = (db) => db.log.filter(q => q.table === "bsky_leads" && q.op === "select");
const ordersNullsLast = (q) => q.filters.some(f => f[0] === "order" && f[1] === "intent_score" && f[2] && f[2].ascending === false && f[2].nullsFirst === false);
const excludesNull = (q) => q.filters.some(f => f[0] === "not" && f[1] === "intent_score" && f[2] === "is" && f[3] === null);

(async function main() {
  /* ── 1. the scorer ────────────────────────────────────────────────────── */
  console.log("\n══ 1. scoreNewLeads ══");
  async function radar(rows, modelReply) {
    const db = fakeDb({ bsky_leads: rows });
    const writes = [];
    const realFrom = db.client.from;
    db.client.from = (t) => { const b = realFrom(t); const u = b.update; b.update = (p) => { writes.push(JSON.parse(JSON.stringify(p))); return u(p); }; return b; };
    let modelCalls = 0;
    class Anthropic { constructor() { this.messages = { create: async () => { modelCalls++; if (modelReply instanceof Error) throw modelReply; return { content: [{ type: "text", text: modelReply }] }; } }; } }
    const ctx = { supabase: db.client, Anthropic, resolveAnthropicKey: async () => null, SCORING_ACCOUNT_ID: OWNER, JSON, Math, Promise, Date, Number, Object, Array, String,
      process: { env: { ANTHROPIC_API_KEY: "sk-ant-stub" } }, console: { log() {}, error() {}, warn() {} }, setTimeout: (fn) => { fn(); return 0; } };
    vm.createContext(ctx);
    vm.runInContext(RADAR_LIFTED, ctx);
    return { db, writes, run: () => ctx.scoreNewLeads(), calls: () => modelCalls };
  }
  const newLead = lead("new1", { status: "new", score_attempts: 0, intent_score: null, intent_reason: null, outreach_safe: null, reply_invited: null, created_at: "2026-10-01T00:00:00Z" });
  const r = await radar([newLead], new Error("upstream timeout"));
  await r.run();
  let row = r.db.tables.bsky_leads[0];
  check("failure 1: still new, attempt 1, no score", row.status === "new" && row.score_attempts === 1 && row.intent_score === null, JSON.stringify(row));
  await r.run();
  row = r.db.tables.bsky_leads[0];
  check("failure 2: still new, attempt 2, no score", row.status === "new" && row.score_attempts === 2 && row.intent_score === null, JSON.stringify(row));
  await r.run();
  row = r.db.tables.bsky_leads[0];
  const last = r.writes[r.writes.length - 1] || {};
  check("failure 3: status score_failed", row.status === "score_failed", row.status);
  check("failure 3: intent_score null, written explicitly rather than omitted", row.intent_score === null && Object.prototype.hasOwnProperty.call(last, "intent_score") && last.intent_score === null, JSON.stringify(last));
  check("failure 3: the reason says scoring failed, attempt 3", row.intent_reason === FAILED && row.score_attempts === 3, JSON.stringify(row));
  check("failure 3: no suitability or invitation judgement is written", !("outreach_safe" in last) && !("reply_invited" in last), JSON.stringify(last));
  const before = r.calls();
  await r.run();
  check("a score_failed lead is never picked up by the scorer again", r.calls() === before, r.calls() - before);

  const ok = await radar([lead("new2", { status: "new", score_attempts: 0, intent_score: null, intent_reason: null, outreach_safe: null, reply_invited: null, created_at: "2026-10-01T00:00:00Z" })],
    JSON.stringify({ score: 72, reason: "asks the room what helps", product: "Tongkat Ali", safety: "SAFE", invitation: "INVITED" }));
  await ok.run();
  row = ok.db.tables.bsky_leads[0];
  check("a successful scoring is unchanged: score 72, status scored", row.status === "scored" && row.intent_score === 72 && row.intent_reason === "asks the room what helps", JSON.stringify(row));

  /* ── 2. the owner's lists ─────────────────────────────────────────────── */
  console.log("\n══ 2. GET /api/leads and GET /api/agents/sales/leads ══");
  for (const key of ["get /api/leads", "get /api/agents/sales/leads"]) {
    const sv = server({ bsky_leads: ALL, sales_lead_pipeline: [] });
    const res = await sv.call(key);
    const leads = (res.body && res.body.leads) || [];
    check(key + ": only real scores, highest first (80, 65)", res.status === 200 && JSON.stringify(leads.map(l => l.intent_score)) === "[80,65]", JSON.stringify(leads.map(l => [l.id, l.intent_score])));
    const q = leadsQuery(sv.db)[0];
    check(key + ": the query excludes a null score", q && excludesNull(q), q && JSON.stringify(q.filters));
    check(key + ": the query orders by score with nulls last", q && ordersNullsLast(q), q && JSON.stringify(q.filters));
    const raw = server({ bsky_leads: [], sales_lead_pipeline: [] }, { bsky_leads: ALL });
    const rres = await raw.call(key);
    const rleads = (rres.body && rres.body.leads) || [];
    check(key + ": even when the database returns failed and null rows, none is shown", rleads.length === 2 && realOnly(rleads), JSON.stringify(rleads.map(l => l.id)));
  }

  /* ── 3. the pipeline ──────────────────────────────────────────────────── */
  console.log("\n══ 3. GET /api/agents/sales/pipeline ══");
  {
    const pipe = [L.legacy, L.failed, L.good80].map(l => ({ user_id: OWNER, lead_post_uri: l.post_uri, status: "new", last_draft: null, updated_at: fresh }));
    const sv = server({ bsky_leads: ALL, sales_lead_pipeline: pipe });
    const res = await sv.call("get /api/agents/sales/pipeline");
    const items = ((res.body && res.body.pipeline && res.body.pipeline.new) || []);
    const byUri = {}; items.forEach(it => { byUri[it.lead_post_uri] = it.lead; });
    check("a score_failed lead: no number, labelled scoring failed",
      byUri[L.failed.post_uri] && byUri[L.failed.post_uri].intent_score === null && byUri[L.failed.post_uri].score_label === "scoring failed", JSON.stringify(byUri[L.failed.post_uri]));
    check("a legacy 0 with the failure reason: no number, labelled scoring failed",
      byUri[L.legacy.post_uri] && byUri[L.legacy.post_uri].intent_score === null && byUri[L.legacy.post_uri].score_label === "scoring failed", JSON.stringify(byUri[L.legacy.post_uri]));
    check("a real score keeps its number and no label",
      byUri[L.good80.post_uri] && byUri[L.good80.post_uri].intent_score === 80 && !("score_label" in byUri[L.good80.post_uri]), JSON.stringify(byUri[L.good80.post_uri]));
  }

  /* ── 4. auto-convert ──────────────────────────────────────────────────── */
  console.log("\n══ 4. runSalesAutoConvert ══");
  {
    const sv = server({ bsky_leads: ALL, sales_lead_pipeline: [], business_profiles: [{ user_id: OWNER }], agent_memory: [] });
    await sv.api.runSalesAutoConvert();
    const q = leadsQuery(sv.db)[0];
    check("its query excludes a null score", q && excludesNull(q), q && JSON.stringify(q.filters));
    check("its query orders by score with nulls last", q && ordersNullsLast(q), q && JSON.stringify(q.filters));
    check("it drafts only real scores, highest first", JSON.stringify(sv.drafted) === JSON.stringify(["lead-good80", "lead-good65"]), JSON.stringify(sv.drafted));
    const raw = server({ bsky_leads: [], sales_lead_pipeline: [], business_profiles: [{ user_id: OWNER }], agent_memory: [] },
      { bsky_leads: [L.nullScored, L.failed, L.legacy, L.good80] });
    await raw.api.runSalesAutoConvert();
    check("even when the database returns null, failed and legacy rows, it drafts none of them", JSON.stringify(raw.drafted) === JSON.stringify(["lead-good80"]), JSON.stringify(raw.drafted));
  }

  /* ── 5. convert ───────────────────────────────────────────────────────── */
  console.log("\n══ 5. POST /api/agents/sales/convert ══");
  for (const [label, l] of [["a score_failed lead", L.failed], ["a legacy 0 with the failure reason", L.legacy]]) {
    const sv = server({ bsky_leads: ALL, sales_lead_pipeline: [], business_profiles: [], agent_memory: [] });
    const res = await sv.call("post /api/agents/sales/convert", { lead_post_uri: l.post_uri });
    check("named " + label + ": 422 not_scored, nothing drafted",
      res.status === 422 && (res.body.reasons || []).some(x => x.code === "not_scored") && /Scoring this lead failed/.test(res.body.error) && sv.drafted.length === 0,
      res.status + " " + JSON.stringify(res.body));
  }
  {
    const sv = server({ bsky_leads: ALL, sales_lead_pipeline: [], business_profiles: [], agent_memory: [] });
    const res = await sv.call("post /api/agents/sales/convert", { lead_post_uri: L.good80.post_uri });
    check("named, a real score: drafted", res.status === 200 && JSON.stringify(sv.drafted) === "[\"lead-good80\"]", res.status + " " + JSON.stringify(sv.drafted));
    const seg = server({ bsky_leads: ALL, sales_lead_pipeline: [], business_profiles: [], agent_memory: [] });
    await seg.call("post /api/agents/sales/convert", { segment: {} });
    const q = leadsQuery(seg.db)[0];
    check("segment: the query excludes a null score and orders nulls last", q && excludesNull(q) && ordersNullsLast(q), q && JSON.stringify(q.filters));
    check("segment: only real scores are drafted", JSON.stringify(seg.drafted) === JSON.stringify(["lead-good80", "lead-good65"]), JSON.stringify(seg.drafted));
    const raw = server({ bsky_leads: [], sales_lead_pipeline: [], business_profiles: [], agent_memory: [] }, { bsky_leads: ALL });
    await raw.call("post /api/agents/sales/convert", { segment: {} });
    check("segment: even when the database returns failed and null rows, only real scores are drafted",
      raw.drafted.length === 2 && raw.drafted.indexOf("lead-legacy") === -1 && raw.drafted.indexOf("lead-failed") === -1 && raw.drafted.indexOf("lead-nullScored") === -1, JSON.stringify(raw.drafted));
  }

  /* ── 6. Postgres's rule, and every ordering ───────────────────────────── */
  console.log("\n══ 6. nulls last ══");
  {
    const db = fakeDb({ t: [{ v: 1 }, { v: null }, { v: 3 }] });
    const plain = await db.client.from("t").select("*").order("v", { ascending: false });
    const last = await db.client.from("t").select("*").order("v", { ascending: false, nullsFirst: false });
    check("the fake follows Postgres: a plain descending sort puts the null first; nullsFirst false puts it last",
      plain.data[0].v === null && last.data[2].v === null, JSON.stringify([plain.data, last.data]));
    const orders = (FILES[SERVER].match(/\.order\("intent_score", \{[^}]*\}\)/g) || []);
    check("every ordering by intent_score in server.js says nullsFirst: false (" + orders.length + ")",
      orders.length === 4 && orders.every(o => /ascending: false, nullsFirst: false/.test(o)), JSON.stringify(orders));
  }

  check("zero network", NETWORK.length === 0, JSON.stringify(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
