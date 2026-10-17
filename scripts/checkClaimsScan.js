"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkClaimsScan — the Vertical Marketing agent's Claims Scan runs the two
   claim rulebooks this server already has, over pasted copy and the caller's
   own stored copy, with no model call; and Termaximus's Claims Scan section
   carries counts only and never reads a failed read as a fact.

   POST /api/agents/vertical_marketing/claims-scan, requireActiveSubscription
   and buildOracleAgentRecords are lifted from server.js with everything they
   call and run in a vm against an in-memory Supabase (failures injected per
   query), with every model entry point and fetch stubbed to record a call.
   TEST ROWS ARE ISOLATED BY CONSTRUCTION: no database, network or model is
   reached, so the owner's live data is never read and nothing is written
   anywhere. Every fixture row belongs to one of two made-up accounts.

   WHAT THIS PROVES
     A. "blurred vision" and "blood sugar" are caught (fda_disease_claims, the
        FDA's group in the policy-check rulebook, authority FDA), at their
        exact positions, with the missing disclaimer reported.
     B. Six lawful structure/function phrases are NOT caught. The negative
        tests b587f77 describes ("six lawful structure/function claims are
        asserted NOT to") were run against stubs and never committed, so the
        six here are taken from this code's own permitted examples: the
        fda_disease_claims comments ("supports healthy circulation", "helps
        maintain normal energy levels", "supports immune function") and the
        supplement profile's permitted functions (stamina, confidence, general
        wellbeing).
     C. A span both rulebooks match is ONE finding listing both; the
        disclaimer itself is never a finding, and copy carrying it is not
        listed as missing it.
     D. A stored scan reads only the caller's rows in all four tables, by each
        table's own owner column, with each finding's table, row id and field.
     E. The 200-row cap per table is applied and the rows not scanned are
        reported.
     F. Each 400 names its field: neither input, an empty text with no stored
        scan, a string boolean, an unknown or absent profile, a non-string
        text, text over the policy check's 6,000 characters (never cut).
     G. 402 without an active subscription, and nothing is read.
     H. No model call on any path, and none reachable from the route.
     I. A clean result says "no rule matched" and never "compliant" or
        "approved"; it carries the not-approval statement.
     J. Termaximus's Latest Claims Scan section: counts only, no matched text;
        a failed read is "could not be read just now", never a count.
     K. Rulebook reuse: the route holds no claim pattern of its own.

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
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkClaimsScan: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkClaimsScan: no network"); };

const SERVER = "server.js";
const MUTATIONS = {
  // profile_products is read without its owner filter
  "drop-user-filter-one-table": [[SERVER, "    query = query.eq(src.owner, userId);\n", "    if (src.table !== \"profile_products\") query = query.eq(src.owner, userId);\n"]],
  // a span both rulebooks match is reported once per rulebook
  "double-report-shared-span": [[SERVER, "    var key = position + \":\" + matched.length;\n", "    var key = rulebook + \":\" + position + \":\" + matched.length;\n"]],
  // a clean result is called compliant
  "clean-says-compliant": [[SERVER, "    notes.push(\"No rule matched in \" + items.length + \" item(s). That is not approval: see the statement below.\");",
    "    notes.push(\"Compliant: no rule matched in \" + items.length + \" item(s).\");"]],
  // an unknown profile quietly becomes the supplement profile
  "default-unknown-profile": [[SERVER, "Object.prototype.hasOwnProperty.call(COMPLIANCE_PROFILES, body.profile) ? body.profile : null;",
    "Object.prototype.hasOwnProperty.call(COMPLIANCE_PROFILES, body.profile) ? body.profile : \"supplement_vitality\";"]],
  // the route loses its subscription gate
  "ungate": [[SERVER, "app.post(\"/api/agents/vertical_marketing/claims-scan\", requireAuth, requireActiveSubscription, aiLimiter,",
    "app.post(\"/api/agents/vertical_marketing/claims-scan\", requireAuth, aiLimiter,"]]
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
const SIG = 'app.post("/api/agents/vertical_marketing/claims-scan",';
const routeStart = SRC.indexOf(SIG);
if (routeStart < 0) { console.log("    FAIL  POST /api/agents/vertical_marketing/claims-scan not found"); process.exit(1); }
const ROUTE = SRC.slice(routeStart, s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", routeStart))) + 3);
const LIFT = closure(ROUTE + "\n\nthis.__api = { buildOracleAgentRecords: buildOracleAgentRecords, requireActiveSubscription: requireActiveSubscription, " +
  "AD_POLICY_NOT_APPROVAL: AD_POLICY_NOT_APPROVAL, COMPLIANCE_DISCLAIMER: COMPLIANCE_DISCLAIMER };");

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
      if (op === "not") return extra === null && val === "is" ? v != null : true;
      if (op === "gte") return v != null && String(v) >= String(val);
      if (op === "lte") return v != null && String(v) <= String(val);
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
      const payload = [].concat(q.payload).map(p => Object.assign({ id: crypto.randomUUID(), created_at: new Date().toISOString() }, JSON.parse(JSON.stringify(p))));
      rows.push(...payload);
      return Promise.resolve({ data: q.single ? payload[0] : payload, error: null });
    }
    if (q.op === "update") {
      const hit = rows.filter(r => keep(q, r)); hit.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(q.payload))));
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
    ["eq", "neq", "in", "gte", "lte"].forEach(op => { b[op] = function (col, val) { q.filters.push([op, col, val]); return b; }; });
    ["order", "limit", "range"].forEach(op => { b[op] = function () { q.mods.push([op].concat([].slice.call(arguments))); return b; }; });
    return b;
  }
  return { tables, log, client: { from, rpc: () => Promise.resolve({ data: null, error: { message: "no rpc" } }) } };
}

/* ── fixtures ─────────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-0000000000c1";
const OTHER = "bbbbbbbb-0000-4000-8000-0000000000c2";
const MARK = "ZZOTHERACCOUNT";
const NOW = Date.now();
const day = (n) => new Date(NOW - n * 86400000).toISOString();
let DISCLAIMER = "";
const OWNER_TABLES = { content_library: "user_id", marketplace_listings: "seller_id", profile_products: "user_id", social_post_drafts: "user_id" };
function world(opts) {
  const o = opts || {};
  const w = {
    content_library: [
      { id: "cl-1", user_id: OWNER, title: "Spring tonic", body: "Our tonic cures diabetes. " + DISCLAIMER, status: "published", created_at: day(1) },
      { id: "cl-2", user_id: OWNER, title: "Clean post", body: "Supports healthy circulation.", status: "draft", created_at: day(2) },
      { id: "cl-x", user_id: OTHER, title: MARK, body: MARK + " cures cancer", created_at: day(0) }
    ],
    marketplace_listings: [
      { id: "ml-1", seller_id: OWNER, title: "Vitality drops", description: "Clinically proven energy.", tags: ["herbal", "viagra"], created_at: day(1) },
      { id: "ml-x", seller_id: OTHER, title: MARK, description: MARK + " cures everything", tags: [], created_at: day(0) }
    ],
    profile_products: [
      { id: "pp-1", user_id: OWNER, name: "War Horse", description: "No side effects.", created_at: day(1) },
      { id: "pp-x", user_id: OTHER, name: MARK, description: MARK + " no side effects", created_at: day(0) }
    ],
    social_post_drafts: [
      { id: "sp-1", user_id: OWNER, platform: "bluesky", content: "Helps with blood sugar.", created_at: day(1) },
      { id: "sp-x", user_id: OTHER, platform: "bluesky", content: MARK + " blood sugar", created_at: day(0) }
    ],
    ai_tasks: []
  };
  if (o.manyContent) {
    for (let i = 0; i < o.manyContent; i++) w.content_library.push({ id: "cl-m" + i, user_id: OWNER, title: "Filler " + i, body: "Plain text.", created_at: day(10 + i) });
  }
  return w;
}

/* ── the harness ──────────────────────────────────────────────────────────── */
function context(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed, o.fail);
  const modelCalls = [];
  const handlers = {};
  const record = (name) => function () { modelCalls.push(name); throw new Error("checkClaimsScan: " + name + " must not be called"); };
  const rq = require("module").createRequire(path.join(REPO, "server.js"));
  const ctx = {
    supabase: db.client, require: rq, module: {}, Date, Buffer, URL, setImmediate, crypto,
    setTimeout: () => 0, fetch: record("fetch"),
    process: { env: Object.assign({ ENABLE_EMAIL_SEQUENCES: "false" }, o.env || {}) },
    console: { log() {}, error() {}, warn() {} },
    getUserPlan: async () => (o.plan || { active: true, plan: "pro", subscription: { status: "active" }, config: {}, exempt: false, access_reason: "subscribed" }),
    app: { post(p) { handlers[p] = [].slice.call(arguments, 1); }, get() {}, use() {} }
  };
  MODEL_ENTRY.forEach(n => { ctx[n] = record(n); });
  ctx.requireAuth = function requireAuth(req, res, next) { next(); };
  ctx.aiLimiter = function aiLimiter(req, res, next) { next(); };
  vm.createContext(ctx);
  vm.runInContext(LIFT.code, ctx);
  return { ctx, db, modelCalls, handlers };
}
async function post(body, opts) {
  const h = context((opts && opts.seed) || world(), opts);
  const chain = h.handlers["/api/agents/vertical_marketing/claims-scan"] || [];
  const req = { user: { id: OWNER, role: "user" }, body, method: "POST", route: { path: "/api/agents/vertical_marketing/claims-scan" }, headers: {} };
  const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
  let error = null;
  for (let i = 0; i < chain.length; i++) {
    let advanced = false;
    await chain[i](req, res, (e) => { if (e) error = e; else advanced = true; });
    if (error || !advanced) break;
  }
  return { status: error ? 500 : res.statusCode, body: res.body, error, h, chain };
}
const P = "supplement_vitality";

(async function main() {
  check("the route, requireActiveSubscription and buildOracleAgentRecords were lifted, with both rulebooks",
    ["requireActiveSubscription", "buildOracleAgentRecords", "claimsScanText", "measureClaimsScan", "loadClaimsScanItems", "scanAdPolicy", "AD_POLICY_RULES",
      "COMPLIANCE_PROFILES", "complianceRequiredTextPresent", "startToolRun", "toolProvenance"].every(n => LIFT.names.indexOf(n) !== -1), LIFT.names.join(","));
  DISCLAIMER = context(world()).ctx.__api.COMPLIANCE_DISCLAIMER;

  /* ── A. the label phrases ────────────────────────────────────────────── */
  console.log("\n══ A. the two label phrases ══");
  const TEXT = "Helps with blurred vision and blood sugar";
  const a = await post({ text: TEXT, profile: P });
  const ma = (a.body && a.body.measured) || {};
  const fa = ma.findings || [];
  const at = (t) => fa.find(f => f.matched_text === t);
  check("A. 200 with a measured block", a.status === 200 && a.body.success === true, a.status + " " + (a.error && a.error.message));
  check("A. \"blurred vision\" is caught at position 11", !!at("blurred vision") && at("blurred vision").position === 11 && at("blurred vision").source === "pasted text", JSON.stringify(fa));
  check("A. \"blood sugar\" is caught at position 30", !!at("blood sugar") && at("blood sugar").position === 30, JSON.stringify(fa));
  check("A. both by fda_disease_claims, in the policy-check rulebook, with the FDA as the authority",
    ["blurred vision", "blood sugar"].every(t => at(t) && at(t).rules.some(r => r.rule_id === "fda_disease_claims" && r.rulebook === "ad-platform rules" && r.authority === "FDA")));
  check("A. each finding carries rulebook, rule, exact text, position, context and source",
    fa.length > 0 && fa.every(f => Array.isArray(f.rulebooks) && f.rulebooks.length && f.rules.every(r => r.rulebook && r.rule) && typeof f.matched_text === "string" &&
      typeof f.position === "number" && TEXT.substr(f.position, f.matched_text.length) === f.matched_text && /blurred vision|blood sugar/.test(f.context) && f.source === "pasted text"));
  check("A. the missing disclaimer is reported", ma.items_missing_disclaimer === 1 && JSON.stringify(ma.items_missing_disclaimer_named) === '["pasted text"]', JSON.stringify(ma));
  check("A. counts: 1 item scanned (pasted), 1 with findings, 0 clean, findings per rulebook",
    JSON.stringify(ma.items_scanned) === '{"pasted_text":1}' && ma.items_with_findings === 1 && ma.items_clean === 0 && ma.findings_total === fa.length &&
    ma.findings_per_rulebook["ad-platform rules"] === fa.length && Array.isArray(ma.findings_per_rule) && ma.findings_per_rule.length > 0, JSON.stringify(ma).slice(0, 300));

  /* ── B. lawful phrases ───────────────────────────────────────────────── */
  console.log("\n══ B. six lawful structure/function phrases ══");
  const LAWFUL = ["Supports healthy circulation.", "Helps maintain normal energy levels.", "Supports immune function.",
    "Supports stamina.", "Supports confidence.", "Promotes general wellbeing."];
  for (const phrase of LAWFUL) {
    const r = await post({ text: phrase + " " + DISCLAIMER, profile: P });
    check("B. not caught by either rulebook: \"" + phrase + "\"", r.status === 200 && r.body.measured.findings_total === 0 && r.body.measured.items_missing_disclaimer === 0,
      JSON.stringify(r.body && r.body.measured.findings));
  }

  /* ── C. shared spans and the disclaimer ──────────────────────────────── */
  console.log("\n══ C. one finding per span ══");
  const c = await post({ text: "Clinically proven, with no side effects, like Viagra.", profile: P });
  const fc = c.body.measured.findings;
  const span = (t) => fc.filter(f => f.matched_text.toLowerCase() === t);
  check("C. \"Clinically proven\", \"no side effects\" and \"Viagra\" are each ONE finding listing both rulebooks",
    ["clinically proven", "no side effects", "viagra"].every(t => span(t).length === 1 && span(t)[0].rulebooks.length === 2 &&
      span(t)[0].rulebooks.indexOf("FDA/FTC supplement rules") !== -1 && span(t)[0].rulebooks.indexOf("ad-platform rules") !== -1), JSON.stringify(fc.map(f => [f.matched_text, f.rulebooks])));
  check("C. no two findings share a span", new Set(fc.map(f => f.position + ":" + f.matched_text.length)).size === fc.length);
  check("C. findings matched by both rulebooks are counted, and counted under each", c.body.measured.findings_matched_by_both_rulebooks >= 3 &&
    c.body.measured.findings_per_rulebook["FDA/FTC supplement rules"] >= 3 && c.body.measured.findings_per_rulebook["ad-platform rules"] >= 3);
  const d = await post({ text: "Supports healthy circulation. " + DISCLAIMER, profile: P });
  check("C. the disclaimer's own \"treat, cure, or prevent any disease\" is never a finding, and copy carrying it is not missing it",
    d.body.measured.findings_total === 0 && d.body.measured.items_missing_disclaimer === 0, JSON.stringify(d.body.measured.findings));

  /* ── D. stored scan ──────────────────────────────────────────────────── */
  console.log("\n══ D. the stored scan reads only the caller's rows ══");
  const st = await post({ scan_stored: true, profile: P });
  const ms = (st.body && st.body.measured) || {};
  const reads = st.h.db.log.filter(q => OWNER_TABLES[q.table]);
  check("D. all four tables are read, each filtered on its own owner column = the caller",
    Object.keys(OWNER_TABLES).every(t => reads.some(q => q.table === t && q.filters.some(f => f[0] === "eq" && f[1] === OWNER_TABLES[t] && f[2] === OWNER))) &&
    reads.every(q => q.filters.some(f => f[0] === "eq" && f[1] === OWNER_TABLES[q.table] && f[2] === OWNER)), JSON.stringify(reads.map(q => [q.table, q.filters])));
  check("D. items scanned per table are the caller's own counts", JSON.stringify(ms.items_scanned) ===
    JSON.stringify({ content_library: 2, marketplace_listings: 1, profile_products: 1, social_post_drafts: 1 }), JSON.stringify(ms.items_scanned));
  check("D. nothing of another account's is in the response", JSON.stringify(st.body).indexOf(MARK) === -1 && JSON.stringify(st.body).indexOf("-x\"") === -1);
  const src = (t, f) => (ms.findings || []).filter(x => x.source && x.source.table === t && x.source.field === f);
  check("D. findings name table, row id and field: cures diabetes in content_library cl-1 body, viagra in marketplace_listings ml-1 tags, " +
    "no side effects in profile_products pp-1 description, blood sugar in social_post_drafts sp-1 content",
    src("content_library", "body").some(x => x.source.row_id === "cl-1" && /cures diabetes|diabetes/.test(x.matched_text)) &&
    src("marketplace_listings", "tags").some(x => x.source.row_id === "ml-1" && /viagra/i.test(x.matched_text)) &&
    src("profile_products", "description").some(x => x.source.row_id === "pp-1" && /no side effects/i.test(x.matched_text)) &&
    src("social_post_drafts", "content").some(x => x.source.row_id === "sp-1" && x.matched_text === "blood sugar"), JSON.stringify((ms.findings || []).map(x => [x.source, x.matched_text])));
  check("D. per item: cl-1 carries the disclaimer and is not listed as missing it; cl-2 does not", ms.items_missing_disclaimer_named &&
    ms.items_missing_disclaimer_named.indexOf("content_library cl-1") === -1 && ms.items_missing_disclaimer_named.indexOf("content_library cl-2") !== -1 &&
    ms.items_missing_disclaimer === 4, JSON.stringify(ms.items_missing_disclaimer_named));
  check("D. items with findings and items clean add up (cl-2 is the one clean item)", ms.items_with_findings === 4 && ms.items_clean === 1, ms.items_with_findings + "/" + ms.items_clean);
  check("D. the provenance says the stored copy was read and no model was called", st.body.provenance.stored_copy_read === true && st.body.provenance.model_call_made === false);

  /* ── E. the cap ──────────────────────────────────────────────────────── */
  console.log("\n══ E. 200 rows per table ══");
  const capped = await post({ scan_stored: true, profile: P }, { seed: world({ manyContent: 205 }) });
  const mcap = capped.body.measured;
  check("E. content_library: 200 scanned, 7 not scanned (207 owned), and the note says so",
    mcap.items_scanned.content_library === 200 && mcap.items_not_scanned_over_cap.content_library === 7 && /not scanned: content_library 7/.test(mcap.note), JSON.stringify([mcap.items_scanned, mcap.items_not_scanned_over_cap, mcap.note]));
  check("E. the other tables report 0 not scanned", ["marketplace_listings", "profile_products", "social_post_drafts"].every(t => mcap.items_not_scanned_over_cap[t] === 0));
  check("E. every stored read is limited to 200", capped.h.db.log.filter(q => OWNER_TABLES[q.table]).every(q => q.mods.some(m => m[0] === "limit" && m[1] === 200)));

  /* ── F. 400s ─────────────────────────────────────────────────────────── */
  console.log("\n══ F. each refusal names its field ══");
  const BAD = [
    [{ profile: P }, "text", "neither input"],
    [{ text: "   ", scan_stored: false, profile: P }, "text", "an empty text and no stored scan"],
    [{ text: "x", scan_stored: "true", profile: P }, "scan_stored", "scan_stored as the string \"true\""],
    [{ text: "x", scan_stored: 1, profile: P }, "scan_stored", "scan_stored as 1"],
    [{ text: "x", profile: "pharma" }, "profile", "an unknown profile"],
    [{ text: "x" }, "profile", "no profile"],
    [{ text: 42, profile: P }, "text", "a non-string text"],
    [{ text: "a".repeat(6001), profile: P }, "text", "text over 6,000 characters"]
  ];
  for (const [body, field, what] of BAD) {
    const r = await post(body);
    check("F. " + what + ": 400 naming " + field + ", and nothing read or recorded", r.status === 400 && r.body && r.body.field === field &&
      new RegExp(field).test(r.body.error) && r.h.db.log.length === 0, r.status + " " + JSON.stringify(r.body));
  }
  const unknown = await post({ text: "x", profile: "pharma" });
  check("F. the unknown-profile refusal lists the valid profiles", JSON.stringify(unknown.body && unknown.body.valid_profiles) === '["supplement_vitality"]');
  const maxOk = await post({ text: "a".repeat(6000), profile: P });
  check("F. exactly 6,000 characters is accepted, the cap ads/policy-check reads copy with",
    maxOk.status === 200 && /safeText\(req\.body\.copy \|\| req\.body\.ad_copy \|\| req\.body\.text, 6000\)/.test(SRC) && /var CLAIMS_SCAN_TEXT_MAX = 6000;/.test(SRC));

  /* ── G. the gate ─────────────────────────────────────────────────────── */
  console.log("\n══ G. no free tier ══");
  const g = await post({ text: TEXT, profile: P }, { plan: { active: false, plan: null, subscription: null, config: null, exempt: false, access_reason: "no_subscription" } });
  check("G. without an active subscription: 402", g.status === 402, g.status + " " + JSON.stringify(g.body).slice(0, 160));
  check("G. and nothing was read or recorded", g.h.db.log.length === 0, g.h.db.log.map(q => q.table).join(","));
  check("G. the gate in front of the handler is the real requireActiveSubscription", a.chain.some(f => f === a.h.ctx.__api.requireActiveSubscription));

  /* ── H. no model ─────────────────────────────────────────────────────── */
  console.log("\n══ H. no model call ══");
  const all = [a, c, d, st, capped, maxOk];
  check("H. no model entry point or network call was made on any path", all.every(x => x.h.modelCalls.length === 0) && NETWORK.length === 0,
    all.map(x => x.h.modelCalls.join("+")).join(" | ") + " " + NETWORK.join(","));
  const routeOnly = closure(ROUTE);
  const reach = MODEL_ENTRY.filter(n => new RegExp("\\b" + n + "\\b").test(uncommented(routeOnly.code)));
  check("H. no model entry point is reachable from the route", reach.length === 0, reach.join(","));
  check("H. provenance: model_call_made false and nothing inferred by a model", a.body.provenance.model_call_made === false && a.body.provenance.inferred_by_model.length === 0);

  /* ── I. clean results ────────────────────────────────────────────────── */
  console.log("\n══ I. a clean result is \"no rule matched\" ══");
  check("I. a clean result's note says no rule matched", /^No rule matched in 1 item\(s\)\./.test(d.body.measured.note), d.body.measured.note);
  check("I. a clean result never says compliant or approved, anywhere in the response", !/\bcompliant\b|\bapproved\b/i.test(JSON.stringify(d.body)),
    (JSON.stringify(d.body).match(/.{0,40}\b(compliant|approved)\b.{0,20}/i) || [""])[0]);
  check("I. it carries the not-approval statement and clean_scan_is_not_approval", d.body.statement === d.h.ctx.__api.AD_POLICY_NOT_APPROVAL &&
    /^A CLEAN SCAN IS NOT APPROVAL FROM ANYBODY\./.test(d.body.statement) && d.body.clean_scan_is_not_approval === true);
  check("I. not_measured names regulator and platform approval, off-platform copy, images, and that over-flagging is deliberate",
    ["Approval by the FDA, the FTC, any ad platform or any payment processor", "Shopify, WordPress", "Images", "over-match on purpose"].every(p =>
      d.body.limitations.not_measured.some(x => x.indexOf(p) !== -1)), JSON.stringify(d.body.limitations));

  /* ── J. Termaximus ───────────────────────────────────────────────────── */
  console.log("\n══ J. Termaximus's Latest Claims Scan section ══");
  const seed = world();
  seed.ai_tasks = st.h.db.tables.ai_tasks.map(r => Object.assign({}, r, { created_at: day(0) }))
    .concat([{ id: "t-other", user_id: OTHER, task_type: "vertical_marketing/claims-scan", output: { measured: { items_scanned_total: 999, findings_total: 999, items_missing_disclaimer: 999 } }, created_at: day(0) }]);
  async function records(fail) {
    const h = context(seed, { fail });
    const failed = [];
    const text = await h.ctx.__api.buildOracleAgentRecords(OWNER, (what) => failed.push(what));
    const i = text.indexOf("Latest Claims Scan (counts only)");
    const j = text.indexOf("\nLatest self-review", i);
    return { text, section: i === -1 ? "" : text.slice(i, j === -1 ? undefined : j), failed };
  }
  const r1 = await records();
  check("J. the section gives the date and counts of the caller's latest scan: 5 items, its findings, 4 missing the disclaimer",
    new RegExp("- \\d{4}-\\d{2}-\\d{2}: 5 item\\(s\\) scanned, " + ms.findings_total + " finding\\(s\\), 4 item\\(s\\) missing the disclaimer").test(r1.section), r1.section);
  check("J. no matched text, context or row id reaches the records block", !/blood sugar|viagra|no side effects|diabetes|cl-1|sp-1|999/i.test(r1.section), r1.section);
  const r0 = await records(q => q.table === "ai_tasks" && q.filters.some(f => f[1] === "task_type" && f[2] === "vertical_marketing/claims-scan") ? { message: "permission denied" } : null);
  check("J. a failed read says it could not be read, never a count", /^Latest Claims Scan \(counts only\): could not be read just now\./.test(r0.section) &&
    !/\d+ item\(s\) scanned/.test(r0.section) && r0.failed.some(f => /Latest Claims Scan/.test(f)), r0.section);
  const rn = await records.call(null);
  check("J. the section reads with the caller's user_id", /\.eq\("user_id", userId\)\n\s+\.eq\("task_type", "vertical_marketing\/claims-scan"\)/.test(SRC) && !!rn.section);

  /* ── K. reuse ────────────────────────────────────────────────────────── */
  console.log("\n══ K. the rulebooks are reused, not copied ══");
  const scanCode = ["claimsScanText", "measureClaimsScan", "loadClaimsScanItems"].map(definitionOf).join("\n");
  check("K. the claims-scan code holds no regular-expression literal of its own except whitespace collapsing",
    (uncommented(scanCode).match(/\/[^/\n*][^/\n]*\/[gimsuy]*(?=[.,);\s])/g) || []).every(x => x === "/\\s+/g"), (uncommented(scanCode).match(/\/[^/\n*][^/\n]*\/[gimsuy]*(?=[.,);\s])/g) || []).join(" "));
  check("K. it runs COMPLIANCE_PROFILES' banned patterns and scanAdPolicy", /\(profile\.banned \|\| \[\]\)\.forEach/.test(scanCode) && /scanAdPolicy\(scanned\)/.test(scanCode) &&
    /new RegExp\(entry\.pattern\.source,/.test(scanCode));

  console.log("\n" + (failures ? failures + " FAILED, " + passes + " passed" : "ALL " + passes + " CHECKS PASSED"));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack)); process.exit(1); });
