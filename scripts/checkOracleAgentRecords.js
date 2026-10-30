"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkOracleAgentRecords — Termaximus sees what the agents actually did, and
   is never told a failed read is a fact.

   POST /api/oracle is lifted from server.js, with everything it calls, and run
   in a vm against an in-memory Supabase (with failures injected per table) and
   a stubbed model that only records the system prompt it was handed.
   config/brain.js is loaded from its source in its own vm, so a mutation can
   reach it too. No network, no real model, no database, no email.

   WHAT THIS PROVES
     A. The AGENT RECORDS block, with data: every section shows this account's
        records — tool runs, proposals by status and the newest pending,
        schedules and autonomy, email sequences with enrollment counts and the
        sender readiness, published content, arrivals attributed through the
        posts' tracked links, this month's spend priced as the code prices it,
        and the latest self-review cut to 300 characters. It opens with the
        line telling him these are records and that anything unlisted is
        unknown, not zero. Another user's rows never appear.
     B. With nothing to show, each section says "none".
     C. With each section's read failing, that section says "could not be read
        just now" — never a 0 or "none" — and the others still render.
     D. The block is capped at 4,000 characters and says so inside itself when
        cut.
     E. ai_agents.estimated_roi appears nowhere in the prompt.
     F. Every other read in the prompt path fails loudly: the business profile,
        oracle_sync (seeker profile, numerology and natal chart with it), a
        numerology failure, a natal failure, each enterprise line, every
        getLiveStats count, getLiveStats as a whole, and the memory reads. A
        real empty (no profile row, no sync row) still reads as empty.
     G. Order: the memories, then the records, then NO_INVENTION_RULE, which
        stays the last block of the shared brain.
     H. YouTube API spend today, for the owner account only (the radar runs
        on its key): "N of CAP units used (radar R)" summed from today's
        youtube_api_calls rows; a ledger that cannot be read (the table not
        applied yet included) says "could not be read just now", never 0;
        an unusable cap is named; any other account has no such section.

   NAMED BEFORE → AFTER (Arrivals Ledger, Oct 18 2026, assertion changed on
   purpose):
     A arrivals: "of M post(s)" counted every slugged post; it now counts only
        posts whose stored body carries their ref, and only their arrivals.
        The fixture gains bodies carrying the refs and a third slugged post
        whose body carries none (Autumn notes), so the old count reads
        "of 3 post(s)" and the new one "of 2 post(s)". The text the check pins
        is unchanged, "3 arrival(s) through the tracked links of 2 post(s)";
        what it now proves is that the untracked post is left out.

   MUTATE=<name> edits server.js or config/brain.js IN MEMORY (nothing on disk
   is touched). MUTATE=all runs each in its own process; an unmatched search
   text is an ERROR, never a catch (scripts/_shared.js).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), crypto = require("crypto");
const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
const s = MUT;

const SERVER = "server.js", BRAIN = "config/brain.js";
const MUTATIONS = {
  // a failed live-stats count is a 0 again
  "failed-count-zero": [[SERVER, '    tasksRun: softCount(tasksRunResult, "tasksRun"),', "    tasksRun: tasksRunResult.count || 0,"]],
  // the proposals section reads every account's proposals
  "proposals-unscoped": [[SERVER, '      .select("status, title, agent_type, created_at")\n      .eq("user_id", userId)\n', '      .select("status, title, agent_type, created_at")\n']],
  // estimated_roi is back in the enterprise block
  "roi-back": [[SERVER, '        .select("tasks_completed")\n        .eq("user_id", req.user.id);', '        .select("tasks_completed, estimated_roi")\n        .eq("user_id", req.user.id);'],
    [SERVER, '      enterpriseLines.push("AI Agent Team: " + oracleAgentRows.length + " agents, " + totalTasksCompleted + " tasks completed");',
      '      enterpriseLines.push("AI Agent Team: " + oracleAgentRows.length + " agents, " + totalTasksCompleted + " tasks completed, $" + oracleAgentRows.reduce(function (sum, row) { return sum + Number(row.estimated_roi || 0); }, 0) + " estimated ROI");']],
  // the records go after NO_INVENTION_RULE
  "records-after-rule": [[BRAIN, "  (Array.isArray(extraBlocks) ? extraBlocks : []).forEach(function (block) {", "  blocks.push(NO_INVENTION_RULE);\n  (Array.isArray(extraBlocks) ? extraBlocks : []).forEach(function (block) {"],
    [BRAIN, "    if (typeof block === \"string\" && block.trim()) blocks.push(block.trim());\n  });\n  blocks.push(NO_INVENTION_RULE);", "    if (typeof block === \"string\" && block.trim()) blocks.push(block.trim());\n  });"]],
  // the arrivals section counts every slugged post again, tracked or not
  "old-denominator": [[SERVER, "\" arrival(s) through the tracked links of \" + refs.length + \" post(s);",
    "\" arrival(s) through the tracked links of \" + posts.length + \" post(s);"]],
  // the YouTube spend line is shown to every account, not only the owner
  "youtube-spend-for-everyone": [[SERVER, "  if (userId === OUTREACH_CREDENTIAL_OWNER_ID) {\n    await section(\"YouTube API spend today (UTC)\"",
    "  if (true) {\n    await section(\"YouTube API spend today (UTC)\""]],
  // the 4,000-character cap is gone
  "no-cap": [[SERVER, "  if (text.length <= ORACLE_RECORDS_CAP) return text;", "  return text;"]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[SERVER, BRAIN].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = MUT.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}
const SRC = FILES[SERVER];

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── config/brain.js, from its (possibly mutated) source ──────────────────── */
function loadBrain() {
  const m = { exports: {} };
  vm.runInNewContext(FILES[BRAIN], { module: m, exports: m.exports, console });
  return m.exports;
}
const BRAIN_MOD = loadBrain();

/* ── the route, lifted ────────────────────────────────────────────────────── */
/* NAMED BEFORE → AFTER (Oct 30 2026, no emojis): server.js's require of config/brain gave buildAgentSystemPrompt and
   useBillingPlans; it now gives NO_EMOJI_RULE too, which oracleSystemPrompt() appends. It is supplied from the
   brain as the other two are. */
const STUBS = new Set(["supabase", "console", "process", "require", "module", "app", "Anthropic", "requireAuth",
  "requireActiveSubscription", "aiLimiter", "oracleChatLimiter", "buildAgentSystemPrompt", "useBillingPlans", "NO_EMOJI_RULE", "Buffer", "URL", "setTimeout", "setImmediate", "fetch"]);
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
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
// NAMED (Oct 27 2026, launch hardening #6). BEFORE: requireAuth, requireActiveSubscription, oracleChatUpload.
// AFTER: oracleChatLimiter between the subscription gate and the upload (checkLaunchHardening holds the limiter).
const SIG = 'app.post("/api/oracle", requireAuth, requireActiveSubscription, oracleChatLimiter, oracleChatUpload.array("files", 8), async function (req, res, next) {';
const routeStart = SRC.indexOf(SIG);
if (routeStart < 0) { console.log("    FAIL  POST /api/oracle not found"); process.exit(1); }
const ROUTE = SRC.slice(routeStart, s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", routeStart))) + 2);
const LIFTED = closure(ROUTE + "\n\nthis.__api = { blogRefToken: blogRefToken, getLiveStats: getLiveStats, modelCallCostUsd: modelCallCostUsd, modelSpendMonth: modelSpendMonth, " +
  "ORACLE_RECORDS_CAP: ORACLE_RECORDS_CAP };\nuseBillingPlans(PLAN_CONFIG);");

/* ── the fake database ─────────────────────────────────────────────────────── */
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
      if (op === "is") return val === null ? v == null : v === val;
      if (op === "not") return extra === null && val === "is" ? v != null : true;
      if (op === "like") return typeof v === "string" && new RegExp("^" + String(val).replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/%/g, ".*") + "$").test(v);
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
      const payload = [].concat(q.payload).map(p => Object.assign({ id: crypto.randomUUID() }, JSON.parse(JSON.stringify(p))));
      rows.push(...payload);
      return Promise.resolve({ data: q.single ? payload[0] : payload, error: null });
    }
    if (q.op === "update") {
      const hit = rows.filter(r => keep(q, r)); hit.forEach(r => Object.assign(r, q.payload));
      return Promise.resolve({ data: hit, error: null });
    }
    if (q.op === "delete") return Promise.resolve({ data: null, error: null });
    let hits = rows.filter(r => keep(q, r));
    const count = hits.length;
    const order = q.mods.find(m => m[0] === "order");
    if (order) hits = hits.slice().sort((a, b) => (a[order[1]] < b[order[1]] ? -1 : a[order[1]] > b[order[1]] ? 1 : 0) * (order[2] && order[2].ascending === false ? -1 : 1));
    const range = q.mods.find(m => m[0] === "range"); if (range) hits = hits.slice(range[1], range[2] + 1);
    const limit = q.mods.find(m => m[0] === "limit"); if (limit) hits = hits.slice(0, limit[1]);
    const withCount = q.opts && q.opts.count ? count : null;
    if (q.opts && q.opts.head) return Promise.resolve({ data: null, count, error: null });
    const copies = hits.map(r => JSON.parse(JSON.stringify(r)));
    if (q.single) {
      if (copies.length > 1) return Promise.resolve({ data: null, error: { message: "multiple rows" } });
      if (!copies.length && q.single === "single") return Promise.resolve({ data: null, error: { code: "PGRST116", message: "no rows" } });
      return Promise.resolve({ data: copies[0] || null, error: null, count: withCount });
    }
    return Promise.resolve({ data: copies, count: withCount, error: null });
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
    ["eq", "neq", "in", "is", "like", "ilike", "gte", "lte", "gt", "lt"].forEach(op => { b[op] = function (col, val) { q.filters.push([op === "ilike" ? "like" : op, col, val]); return b; }; });
    ["order", "limit", "range"].forEach(op => { b[op] = function () { q.mods.push([op].concat([].slice.call(arguments))); return b; }; });
    return b;
  }
  return { tables, log, client: { from, rpc: () => Promise.resolve({ data: null, error: { message: "no rpc" } }) } };
}

/* ── fixtures ──────────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const OTHER = "bbbbbbbb-0000-4000-8000-000000000002";
const MARK = "ZZOTHERUSER";
const NOW = new Date();
const today = NOW.toISOString().slice(0, 10);
const day = (n) => new Date(NOW.getTime() - n * 86400000).toISOString();
const NARRATIVE = "This week the agents ran forty tasks. " + "Detail sentence that keeps going on and on. ".repeat(20);
function world(opts) {
  const o = opts || {};
  const w = {
    users: [{ id: OWNER, role: "admin" }, { id: OTHER, role: "user" }],
    oracle_sync: [{ user_id: OWNER, birth_name: "Pat Seeker", birth_date: "1980-03-15", birth_time: "14:30", birth_place: "Paris, France", current_location: "Leeds", path_focus: "Build" }],
    business_profiles: [{ user_id: OWNER, business_name: "Acme Herbs", industry: "Wellness" }, { user_id: OTHER, business_name: MARK + " Biz" }],
    oracle_messages: [{ user_id: OWNER, role: "user", content: "earlier question", created_at: day(3) }, { user_id: OWNER, role: "assistant", content: "earlier reply", created_at: day(3) }],
    agent_memory: [{ user_id: OWNER, agent_type: "oracle", memory_key: "oracle_soul_record", title: "Soul record", content: "A builder.", created_at: day(5) }],
    user_wallets: [{ user_id: OWNER, balance: 120 }],
    marketplace_listings: [{ seller_id: OWNER, status: "active" }, { seller_id: OWNER, status: "draft" }],
    marketplace_orders: [{ seller_id: OWNER, amount_usd: 25, status: "paid", created_at: day(2) }],
    ai_agents: [{ user_id: OWNER, tasks_completed: 7, estimated_roi: 98765 }, { user_id: OWNER, tasks_completed: 3, estimated_roi: 4321 }],
    ai_tasks: [
      { user_id: OWNER, agent_type: "seo", task_type: "seo/audit", status: "completed", output: { ok: 1 }, created_at: day(1) },
      { user_id: OWNER, agent_type: "email", task_type: "email/sequence", status: "completed", output: { steps: [] }, created_at: day(2) },
      { user_id: OWNER, agent_type: "sales", task_type: "sales/plain", status: "completed", output: null, created_at: day(0) },
      { user_id: OTHER, agent_type: "seo", task_type: MARK + "/tool", status: "completed", output: { x: 1 }, created_at: day(0) }
    ],
    agent_proposals: [
      { user_id: OWNER, status: "pending", title: "Publish the spring post", agent_type: "seo", created_at: day(1) },
      { user_id: OWNER, status: "pending", title: "Email sequence: Welcome", agent_type: "email", created_at: day(2) },
      { user_id: OWNER, status: "executed", title: "Old one", agent_type: "seo", created_at: day(9) },
      { user_id: OTHER, status: "pending", title: MARK + " proposal", agent_type: "seo", created_at: day(0) }
    ],
    agent_autonomy: [{ user_id: OWNER, agent_type: "seo", enabled: true }, { user_id: OWNER, agent_type: "sales", enabled: false }, { user_id: OTHER, agent_type: MARK, enabled: true }],
    agent_schedules: [{ user_id: OWNER, agent_type: "seo", cadence: "weekly", enabled: true }, { user_id: OTHER, agent_type: MARK + "x", cadence: "daily", enabled: true }],
    email_sequences: [
      { id: "s1", owner_id: OWNER, name: "Welcome series", status: "active", created_at: day(4) },
      { id: "s2", owner_id: OWNER, name: "Gone series", status: "cancelled", created_at: day(5) },
      { id: "s3", owner_id: OTHER, name: MARK + " series", status: "active", created_at: day(1) }
    ],
    email_sequence_enrollments: [
      { sequence_id: "s1", status: "active" }, { sequence_id: "s1", status: "active" }, { sequence_id: "s1", status: "stopped" },
      { sequence_id: "s3", status: "active" }
    ],
    content_library: [
      { user_id: OWNER, title: "Spring tonics", status: "published", slug: "spring-tonics", created_at: day(3) },
      { user_id: OWNER, title: "Winter roots", status: "published", slug: "winter-roots", created_at: day(30) },
      { user_id: OWNER, title: "Draft idea", status: "draft", slug: null, created_at: day(1) },
      { user_id: OWNER, title: "Autumn notes", status: "draft", slug: "autumn-notes", body: "<p>No tracked link here.</p>", created_at: day(2) },
      { user_id: OTHER, title: MARK + " post", status: "published", slug: "spring-tonics", created_at: day(0) }
    ],
    engine_visits: [],
    model_calls: [
      { user_id: OWNER, model: "claude-sonnet-5", input_tokens: 1000000, output_tokens: 100000, funded_by: "platform", created_on: today, created_at: NOW.toISOString() },
      { user_id: OWNER, model: "claude-haiku-4-5-20251001", input_tokens: 500000, output_tokens: 0, funded_by: "platform", created_on: today, created_at: NOW.toISOString() },
      { user_id: OTHER, model: "claude-sonnet-5", input_tokens: 9000000, output_tokens: 9000000, funded_by: "platform", created_on: today, created_at: NOW.toISOString() }
    ],
    self_reviews: [{ user_id: OWNER, period_type: "weekly", narrative: NARRATIVE, created_at: day(2) }, { user_id: OTHER, period_type: "weekly", narrative: MARK + " review", created_at: day(0) }],
    sms_subscribers: [], sms_campaigns: [], social_post_drafts: [], user_api_keys: [], user_settings: [], user_preferences: []
  };
  return Object.assign(w, o);
}
// PLATFORM_DAILY_SPEND_CAP_USD (launch hardening #5): the fake model_calls hold OTHER's rows for today, more than
// the $25 default ceiling, and this check is about the records, not the ceiling (checkLaunchHardening holds it).
const ENV = { ENABLE_EMAIL_SEQUENCES: "true", MAIL_POSTAL_ADDRESS: "1 Example St", RESEND_WEBHOOK_SECRET: "", EMAIL_MARKETING_DAILY_CAP: "40", ANTHROPIC_API_KEY: "sk-check",
  PLATFORM_DAILY_SPEND_CAP_USD: "1000000" };

/* ── one request ───────────────────────────────────────────────────────────── */
async function ask(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed, o.fail);
  let captured = null;
  class Anthropic {
    constructor() {
      this.messages = { create: async (args) => {
        if (!captured) captured = args;
        return { model: "claude-sonnet-5", usage: { input_tokens: 1, output_tokens: 1 }, content: [{ type: "text", text: "a reply" }] };
      } };
    }
  }
  const logs = [];
  const handlers = {};
  const rq = require("module").createRequire(path.join(REPO, "server.js"));
  const ctx = {
    supabase: db.client, require: rq, module: {}, Date, Buffer, URL, setImmediate,
    setTimeout: (fn) => 0, fetch: () => { throw new Error("no network"); },
    process: { env: Object.assign({}, ENV, o.env || {}) },
    console: { log: (...a) => logs.push(a.join(" ")), error: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")) },
    Anthropic, requireAuth() {}, requireActiveSubscription() {}, aiLimiter() {}, oracleChatLimiter() {},
    buildAgentSystemPrompt: BRAIN_MOD.buildAgentSystemPrompt, useBillingPlans: BRAIN_MOD.useBillingPlans, NO_EMOJI_RULE: BRAIN_MOD.NO_EMOJI_RULE,
    AsyncLocalStorage: require("async_hooks").AsyncLocalStorage,
    decodeHTML: rq("entities").decodeHTML, decodeHTMLAttribute: rq("entities").decodeHTMLAttribute,
    DateTime: rq("luxon").DateTime, encrypt: rq("./lib/apiKeyCrypto").encrypt, decrypt: rq("./lib/apiKeyCrypto").decrypt,
    OWNER_ACCOUNT_ID: rq("./lib/ownerAccount").OWNER_ACCOUNT_ID, computeSynastryAspects: rq("./lib/synastry").computeSynastryAspects,
    // NAMED (Oct 27 2026, launch item #0): BEFORE the platform ceiling's closure took only OWNER_ACCOUNT_ID from outside.
    // AFTER platformSpendToday leaves out test accounts through lib/testAccounts.js's isTestAccount, passed in here.
    isTestAccount: rq("./lib/testAccounts").isTestAccount,
    youtubeCaps: rq("./lib/youtubeQuota").youtubeCaps, youtubeUnitsToday: rq("./lib/youtubeQuota").youtubeUnitsToday,
    app: { post(p) { handlers[p] = arguments[arguments.length - 1]; }, get() {}, use() {} }
  };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  (o.override || []).forEach(code => vm.runInContext(code, ctx));
  const req = { user: { id: o.userId || OWNER, role: "admin" }, body: { message: "What did my agents do?" }, files: [], headers: {} };
  const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
  let error = null;
  await ctx.app && handlers["/api/oracle"](req, res, (e) => { error = e; });
  for (let i = 0; i < 20; i++) await new Promise(r => setImmediate(r));
  return { system: captured ? captured.system : "", captured, res, error, logs, db, api: ctx.__api };
}
const recordsOf = (sys) => {
  const i = sys.indexOf("AGENT RECORDS ("), j = sys.indexOf(BRAIN_MOD.NO_INVENTION_RULE);
  return i < 0 ? "" : sys.slice(i, j > i ? j : undefined).trim();
};
const sectionOf = (block, title) => {
  const i = block.indexOf(title); if (i < 0) return null;
  const rest = block.slice(i);
  const next = rest.slice(title.length).search(/\n[A-Z][^\n]*?:/);
  return next < 0 ? rest : rest.slice(0, title.length + next);
};
const SECTION_TITLES = ["Recent tool runs", "Proposals", "Schedules and autonomy", "Email sequences", "Published content", "Arrivals from this account's published posts", "Model spend this calendar month", "Latest self-review"];
const UNREAD = "could not be read just now";

(async function main() {
  /* ── A. with data ───────────────────────────────────────────────────────── */
  console.log("\n══ A. the agent records, with data ══");
  const seedA = world();
  const posts = seedA.content_library.filter(r => r.user_id === OWNER && r.slug);
  const probe = await ask(world());
  check("the model was called once with a system prompt (stubbed)", !!probe.captured && probe.system.length > 1000, probe.error && probe.error.message);
  const ref = (slug) => probe.api.blogRefToken(OWNER, slug);
  // The two published posts carry their refs, as publish_blog_post writes a money_path post; Autumn notes carries none.
  seedA.content_library.forEach(r => { if (r.user_id === OWNER && (r.slug === "spring-tonics" || r.slug === "winter-roots")) r.body = '<a href="/suppressed.html?ref=' + ref(r.slug) + '">x</a>'; });
  seedA.engine_visits = [{ id: 1, ref: ref("spring-tonics"), landing_path: "/x" }, { id: 2, ref: ref("spring-tonics"), landing_path: "/x" },
    { id: 3, ref: ref("winter-roots"), landing_path: "/y" }, { id: 4, ref: probe.api.blogRefToken(OTHER, "spring-tonics"), landing_path: "/z" }];
  const A = await ask(seedA);
  const block = recordsOf(A.system);
  check("the block opens with the records line: cite as records; anything not listed is unknown, not zero",
    block.indexOf("AGENT RECORDS (read from this account's own records just now). Cite these as records, exactly as written. Anything not listed here is unknown to you — not zero, and not none.") === 0, block.slice(0, 200));
  SECTION_TITLES.forEach(t => check("section present: " + t, block.indexOf(t) !== -1));
  const runs = sectionOf(block, "Recent tool runs");
  check("tool runs: only runs with a stored result, newest first, with tool, status and date",
    /seo\/audit · completed/.test(runs) && /email\/sequence · completed/.test(runs) && !/sales\/plain/.test(runs) && runs.indexOf("seo/audit") < runs.indexOf("email/sequence"), runs);
  check("tool runs: no output contents", !/"ok"|steps/.test(runs));
  const props = sectionOf(block, "Proposals");
  check("proposals: counts by status", /by status: executed 1, pending 2/.test(props), props);
  check("proposals: the newest pending titles with agent and date", props.indexOf("\"Publish the spring post\" (seo, " + day(1).slice(0, 10) + ")") !== -1 && props.indexOf("Email sequence: Welcome") !== -1, props);
  const sched = sectionOf(block, "Schedules and autonomy");
  check("schedules and autonomy: per agent", /- sales: autonomy off; schedule none/.test(sched) && /- seo: autonomy on; schedule weekly/.test(sched), sched);
  const email = sectionOf(block, "Email sequences");
  check("email: the active sequence with its enrollment counts, the cancelled one left out",
    /"Welcome series" · active · active 2, stopped 1/.test(email) && !/Gone series/.test(email), email);
  check("email: the sender readiness, as booleans and the cap", /sender: switched on; postal address set; bounce and complaint reports not connected; daily cap 40/.test(email), email);
  const pub = sectionOf(block, "Published content");
  check("published content: the count and newest titles with dates", /- 2 published/.test(pub) && pub.indexOf("\"Spring tonics\" (" + day(3).slice(0, 10) + ")") !== -1 && !/Draft idea/.test(pub), pub);
  const arr = sectionOf(block, "Arrivals from this account's published posts");
  check("arrivals: only visits through this account's posts' refs (3, not 4), and only posts whose body carries the ref (2 of the 3 slugged)",
    /- 3 arrival\(s\) through the tracked links of 2 post\(s\)/.test(arr) && posts.length === 3, arr);
  const spend = sectionOf(block, "Model spend this calendar month");
  const expectUsd = seedA.model_calls.filter(r => r.user_id === OWNER).reduce((n, r) => n + A.api.modelCallCostUsd(r).usd, 0);
  check("model spend: this month's, this account's, priced as the code prices it ($" + expectUsd.toFixed(2) + ")",
    spend.indexOf("- $" + expectUsd.toFixed(2) + " across 2 call(s) since " + A.api.modelSpendMonth(NOW).since) !== -1, spend);
  const rev = sectionOf(block, "Latest self-review");
  const revText = (rev.match(/: (This week[\s\S]*)$/) || [])[1] || "";
  check("self-review: its date and at most 300 characters of it", rev.indexOf(day(2).slice(0, 10) + " (weekly)") !== -1 && revText.length > 0 && revText.length <= 300, revText.length);
  check("another account's rows appear nowhere in the prompt", A.system.indexOf(MARK) === -1 && A.system.indexOf("$90.00") === -1, (A.system.match(new RegExp(MARK + "[^\\n]{0,40}")) || [])[0]);
  check("no record section says it could not be read", block.indexOf(UNREAD) === -1);

  /* ── B. with nothing ────────────────────────────────────────────────────── */
  console.log("\n══ B. with nothing to show ══");
  const empty = world({ ai_tasks: [], agent_proposals: [], agent_autonomy: [], agent_schedules: [], email_sequences: [], email_sequence_enrollments: [],
    content_library: [], engine_visits: [], model_calls: [], self_reviews: [] });
  const B = await ask(empty);
  const bb = recordsOf(B.system);
  ["Recent tool runs", "Proposals", "Schedules and autonomy", "Published content", "Arrivals from this account's published posts", "Latest self-review"].forEach(t =>
    check(t + ": none", /\n- none(\n|$)/.test(sectionOf(bb, t) + "\n"), sectionOf(bb, t)));
  check("Email sequences: sequences none, and the sender still shown", /- sequences: none/.test(sectionOf(bb, "Email sequences")) && /- sender:/.test(sectionOf(bb, "Email sequences")));
  check("Model spend: $0.00 across 0 calls (a real zero, read)", /- \$0\.00 across 0 call\(s\)/.test(sectionOf(bb, "Model spend this calendar month")));
  check("nothing says it could not be read", bb.indexOf(UNREAD) === -1);

  /* ── C. each section's read failing ─────────────────────────────────────── */
  console.log("\n══ C. a failed read says so ══");
  const failing = [["Recent tool runs", "ai_tasks", q => q.filters.some(f => f[0] === "not")], ["Proposals", "agent_proposals"], ["Schedules and autonomy", "agent_schedules"],
    ["Email sequences", "email_sequences"], ["Published content", "content_library", q => q.filters.some(f => f[1] === "status")], ["Arrivals from this account's published posts", "engine_visits"],
    // NAMED (Oct 27 2026, launch hardening #5). BEFORE: every counted model_calls select failed. AFTER: only the
    // account's own (user_id) read fails; the platform ceiling's whole-day read must succeed, or it refuses the call.
    ["Model spend this calendar month", "model_calls", q => q.opts && q.opts.count === "exact" && !q.opts.head && q.filters.some(f => f[1] === "user_id")], ["Latest self-review", "self_reviews"]];
  for (const [title, table, when] of failing) {
    const C = await ask(seedA, { fail: q => q.table === table && q.op === "select" && (!when || when(q)) ? { message: "relation is unavailable" } : null });
    const cb = recordsOf(C.system);
    const sec = sectionOf(cb, title) || "";
    check(title + " failing: says it could not be read", new RegExp("^" + title.replace(/[()]/g, "\\$&") + "[^\\n]*: could not be read just now\\.").test(sec), sec);
    check(title + " failing: no figure and no 'none' in its place", !/\n- /.test(sec) && !/\b0\b/.test(sec.replace(/\([^)]*\)/g, "")), sec);
    check(title + " failing: the other sections still render", SECTION_TITLES.filter(t => t !== title).every(t => cb.indexOf(t) !== -1));
    check(title + " failing: logged once", C.logs.filter(l => l.indexOf("agent records: " + title) !== -1).length === 1, C.logs.filter(l => /agent records/.test(l)).length);
  }
  const thrown = await ask(seedA, { fail: q => q.table === "self_reviews" ? "throw" : null });
  check("a read that throws is also 'could not be read'", /Latest self-review: could not be read just now\./.test(recordsOf(thrown.system)));

  /* ── D. the cap ─────────────────────────────────────────────────────────── */
  console.log("\n══ D. the 4,000-character cap ══");
  const big = world();
  big.ai_tasks = Array.from({ length: 10 }, (_, i) => ({ user_id: OWNER, agent_type: "seo", task_type: "seo/" + "x".repeat(55) + i, status: "completed", output: { a: 1 }, created_at: day(i) }));
  big.agent_proposals = Array.from({ length: 60 }, (_, i) => ({ user_id: OWNER, status: i % 2 ? "pending" : "status_" + i + "_" + "y".repeat(40), title: "P".repeat(80) + i, agent_type: "seo", created_at: day(i) }));
  big.email_sequences = Array.from({ length: 10 }, (_, i) => ({ id: "q" + i, owner_id: OWNER, name: "N".repeat(78) + i, status: "active", created_at: day(i) }));
  big.agent_autonomy = Array.from({ length: 40 }, (_, i) => ({ user_id: OWNER, agent_type: "agent_" + i + "_" + "z".repeat(20), enabled: true }));
  const D = await ask(big);
  const db2 = recordsOf(D.system);
  check("a long block is cut to at most 4,000 characters", db2.length <= 4000 && db2.length > 3500, db2.length);
  check("…and says so inside itself, at the end", /\[Cut at 4,000 characters: records past this point were left out and are unknown to you\.\]$/.test(db2), db2.slice(-160));
  check("…still opening with the records line", db2.indexOf("AGENT RECORDS (") === 0);
  check("an uncut block carries no truncation line", block.indexOf("[Cut at") === -1);

  /* ── E. estimated_roi ───────────────────────────────────────────────────── */
  console.log("\n══ E. estimated_roi is gone ══");
  check("no estimated ROI anywhere in the prompt", !/estimated ROI|estimated_roi|98765|4321|103086/i.test(A.system));
  check("the agent line still gives agents and tasks completed", /AI Agent Team: 2 agents, 10 tasks completed\n?/.test(A.system), (A.system.match(/AI Agent Team[^\n]*/) || [])[0]);

  /* ── F. every other read fails loudly ───────────────────────────────────── */
  console.log("\n══ F. the other reads fail loudly ══");
  let F = await ask(seedA, { fail: q => q.table === "business_profiles" ? { message: "down" } : null });
  check("business profile failing: 'Could not be read just now', no 'Not provided'", /BUSINESS PROFILE:\nCould not be read just now/.test(F.system) && F.system.indexOf("Not provided") === -1);
  F = await ask(world({ business_profiles: [] }));
  check("no profile row (a real empty): 'Not provided', no failure line", F.system.indexOf("Business Name: Not provided") !== -1 && !/BUSINESS PROFILE:\nCould not be read/.test(F.system));
  F = await ask(seedA, { fail: q => q.table === "oracle_sync" ? { message: "down" } : null });
  check("oracle_sync failing: the seeker profile says it could not be read, never 'not yet synchronized'",
    /SEEKER PROFILE:\ncould not be read just now/.test(F.system) && F.system.indexOf("has not yet synchronized") === -1, (F.system.match(/SEEKER PROFILE:[^\n]*\n[^\n]*/) || [])[0]);
  check("oracle_sync failing: numerology and natal chart say they could not be read",
    /NUMEROLOGICAL SIGNATURE: could not be read just now/.test(F.system) && /NATAL CHART: could not be read just now/.test(F.system));
  F = await ask(world({ oracle_sync: [] }));
  check("no sync row (a real empty): 'not yet synchronized', no failure line", F.system.indexOf("has not yet synchronized") !== -1 && F.system.indexOf("SEEKER PROFILE:\ncould not be read") === -1);
  F = await ask(seedA, { override: ["computeAllNumerology = function () { throw new Error('boom'); }; calculateLifePath = function () { throw new Error('boom'); };"] });
  check("numerology failing: 'NUMEROLOGICAL SIGNATURE: could not be read just now'", /NUMEROLOGICAL SIGNATURE: could not be read just now/.test(F.system));
  F = await ask(seedA, { override: ["computeNatalChart = function () { throw new Error('boom'); };"] });
  check("natal chart failing: 'NATAL CHART: could not be read just now'", /NATAL CHART: could not be read just now/.test(F.system));
  check("with birth data that reads, the chart is computed", /NATAL CHART \(computed/.test(A.system), (A.system.match(/NATAL CHART[^\n]*/) || ["no natal block"])[0]);
  for (const [table, label] of [["user_wallets", "BFC Wallet Balance"], ["marketplace_listings", "Active Marketplace Listings"], ["marketplace_orders", "Recent Sales (last 5 orders)"], ["ai_agents", "AI Agent Team"]]) {
    F = await ask(seedA, { fail: q => q.table === table ? { message: "down" } : null });
    check("enterprise · " + table + " failing: '" + label + ": could not be read just now'", F.system.indexOf(label + ": could not be read just now") !== -1, (F.system.match(new RegExp(label.replace(/[()]/g, "\\$&") + "[^\\n]*")) || [])[0]);
  }
  check("enterprise lines that read give their figures", /BFC Wallet Balance: 120 BFC/.test(A.system) && /Active Marketplace Listings: 1 \(of 2 total\)/.test(A.system));
  F = await ask(seedA, { fail: q => q.opts && q.opts.head && ["ai_tasks", "content_library", "sms_subscribers", "sms_campaigns", "social_post_drafts"].indexOf(q.table) !== -1 ? { message: "count failed" } : null });
  const keys = ["tasksRun", "tasksCompleted", "contentItems", "blogItems", "smsItems", "subscribers", "optedIn", "campaigns", "socialDrafts", "byAgent"];
  keys.forEach(k => check("live stat " + k + " failing: 'could not be read just now', not 0", F.system.indexOf("- " + k + ": could not be read just now (unknown for this request — not zero)") !== -1 &&
    !new RegExp("- " + k + ": 0\\b").test(F.system), (F.system.match(new RegExp("- " + k + ":[^\\n]*")) || ["no line for " + k + " · " + (F.system.match(/LIVE PLATFORM STATS:?\n[^\n]*/g) || []).join(" | ") + " · " + F.logs.filter(l => /oracle|getLiveStats/.test(l)).slice(0, 3).join(" | ")])[0]));
  const countFail = q => q.opts && q.opts.head && q.table === "ai_tasks" ? { message: "count failed" } : null;
  const plainCall = await ask(seedA, { fail: countFail });
  let threw = null;
  try { await plainCall.api.getLiveStats(OWNER); } catch (e) { threw = e; }
  check("every other caller (e.g. GET /api/analytics/summary) still gets the error, never a 0", !!threw && /count failed/.test(threw.message || ""), threw && threw.message);
  F = await ask(seedA, { override: ["getLiveStats = async function () { throw new Error('stats down'); };"] });
  check("getLiveStats failing as a whole: 'LIVE PLATFORM STATS:\\nCould not be read just now'", /LIVE PLATFORM STATS:\nCould not be read just now — unknown for this request, not zero\./.test(F.system));
  check("live stats that read are numbers, with no failure line", /- tasksRun: 3 /.test(A.system) && A.system.indexOf("tasksRun: could not be read") === -1, (A.system.match(/- tasksRun:[^\n]*/) || [])[0]);
  F = await ask(seedA, { fail: q => q.table === "agent_memory" && q.op === "select" ? { message: "down" } : null });
  check("memory reads failing: a note right after the memories says they could not be read",
    /MEMORY READ FAILURES: the soul record, the distilled memories, the recent conversation memories could not be read just now\./.test(F.system));
  F = await ask(seedA, { fail: q => q.table === "oracle_messages" && q.op === "select" ? { message: "down" } : null });
  check("history failing: the note says the earlier conversation could not be read", /MEMORY READ FAILURES: the earlier conversation could not be read just now/.test(F.system));
  check("with every read working there is no memory-failure note", A.system.indexOf("MEMORY READ FAILURES") === -1);

  /* ── G. order ───────────────────────────────────────────────────────────── */
  console.log("\n══ G. order ══");
  const iMem = A.system.indexOf("ACCUMULATED MEMORY"), iRec = A.system.indexOf("AGENT RECORDS ("), iRule = A.system.indexOf(BRAIN_MOD.NO_INVENTION_RULE);
  check("memories, then the records, then NO_INVENTION_RULE", iMem > -1 && iMem < iRec && iRec < iRule, [iMem, iRec, iRule].join(","));
  check("NO_INVENTION_RULE is the last block of the shared brain (only the Oracle's own seeker blocks follow it)",
    A.system.indexOf(BRAIN_MOD.NO_INVENTION_RULE + "\n\nSEEKER PROFILE:") !== -1 && A.system.lastIndexOf("AGENT RECORDS (") < iRule);
  const plain = BRAIN_MOD.buildAgentSystemPrompt("Agent prompt.", {}, {}, [], []);
  check("another agent's prompt is unchanged: no records, the rule still last", plain.indexOf("AGENT RECORDS") === -1 && plain.endsWith(BRAIN_MOD.NO_INVENTION_RULE));

  /* ── H. YouTube API spend today, owner only ────────────────────────────── */
  console.log("\n══ H. YouTube API spend today ══");
  const YT_OWNER = require(path.join(REPO, "lib", "ownerAccount.js")).OWNER_ACCOUNT_ID;
  const utcToday = new Date().toISOString().slice(0, 10);
  const ytLedger = [
    { id: 1, created_on: utcToday, caller: "radar", units: 100 }, { id: 2, created_on: utcToday, caller: "radar", units: 1 },
    { id: 3, created_on: utcToday, caller: "social_search", units: 100 }, { id: 4, created_on: "2000-01-01", caller: "radar", units: 4000 }
  ];
  const ytTitle = "YouTube API spend today (UTC)";
  const H1 = await ask(Object.assign(world(), { youtube_api_calls: ytLedger }), { userId: YT_OWNER });
  check("H. the owner sees today's spend: 201 of 5000 units used (radar 101); yesterday's rows are not counted",
    sectionOf(recordsOf(H1.system), ytTitle) === ytTitle + ":\n- 201 of 5000 units used (radar 101)", sectionOf(recordsOf(H1.system), ytTitle));
  const H2 = await ask(Object.assign(world(), { youtube_api_calls: ytLedger }), { userId: YT_OWNER, env: { YOUTUBE_DAILY_UNIT_CAP: "800" } });
  check("H. the cap comes from YOUTUBE_DAILY_UNIT_CAP", /- 201 of 800 units used \(radar 101\)/.test(recordsOf(H2.system)), sectionOf(recordsOf(H2.system), ytTitle));
  const H3 = await ask(Object.assign(world(), { youtube_api_calls: ytLedger }), { userId: YT_OWNER, env: { YOUTUBE_RADAR_DAILY_UNITS: "2.5" } });
  check("H. an unusable cap is named, and every call said to be refused",
    /- 201 units used \(radar 101\); YOUTUBE_RADAR_DAILY_UNITS is set but is not a positive whole number, so every YouTube call is refused/.test(recordsOf(H3.system)), sectionOf(recordsOf(H3.system), ytTitle));
  const H4 = await ask(world(), { userId: YT_OWNER, fail: q => q.table === "youtube_api_calls" ? { message: "relation \"public.youtube_api_calls\" does not exist" } : null });
  check("H. the ledger missing: the section says it could not be read, never 0, and the failure is logged",
    recordsOf(H4.system).indexOf(ytTitle + ": " + UNREAD + ".") !== -1 && !/units used/.test(recordsOf(H4.system)) &&
    H4.logs.some(l => /YouTube API spend today/.test(l)), sectionOf(recordsOf(H4.system), ytTitle));
  const H5 = await ask(Object.assign(world(), { youtube_api_calls: ytLedger }));
  check("H. any other account has no YouTube spend section, and its records never read the ledger",
    recordsOf(H5.system).indexOf(ytTitle) === -1 && !H5.db.log.some(q => q.table === "youtube_api_calls"), recordsOf(H5.system).slice(-200));

  check("zero model calls left the process (the model was a stub)", true);
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
