"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkLaunchHardening — the launch hardening of 2026-10-27, items 1, 2, 3,
   5, 6 and 9 of that day's diagnostic (11 is checkOwnerPass's frozen clock).

     node scripts/checkLaunchHardening.js
     MUTATE=<name> node scripts/checkLaunchHardening.js
     MUTATE=all    node scripts/checkLaunchHardening.js

   NOTHING LEAVES THIS PROCESS. server.js is read as text and the pieces under
   test are lifted into vm contexts against an in-memory database; the only
   sockets are express apps this script starts on 127.0.0.1 and calls itself.
   No live row is read or written, no model is called, no email is sent.

   1. PROFILE PRIVACY. GET /api/profile/:username is gone: no GET path in
      server.js matches /api/profile/<a username>, routed by real Express. The
      one profile route left that reads another account, GET
      /api/profile/by-id/:userId, is run against a profiles row with EVERY
      column of the table filled (the column list is read from migration 071),
      and answers the five display columns and no other value.
   2. DONATIONS UNDER THE TRANSFER LIMITS. The donate and transfer routes are
      run against an in-memory database whose bfc_donate and bfc_send have NO
      limits at all, so every refusal here is the route's own: over the
      per-transfer maximum, over the shared 24-hour cap, inside the new-account
      hold, and to one's own campaign, each with its reason and nothing moved.
      A donation counts toward a transfer's cap and a transfer toward a
      donation's. Through real Express: 402 without a subscription, 429 past
      the per-account rate limit, nothing moved by either. Migration 148 is
      read as text: the old signature dropped, every limit raised, the wallet
      lock taken before the shared total is read, every reason it raises
      mapped by the route, the records unchanged, service_role only.
   3. rd-agent.html loads scripts/bf-session.js first in its head, in place
      of the inline presence-only guard.
   5. THE PLATFORM CEILING, lifted with a fake model_calls ledger and a fake
      alert sink: under 80% allowed and silent; at 80% one alert, however many
      calls; at 100% a member refused with the platform message and the owner
      allowed; through enforceDailyModelCallLimit, before the per-account
      checks; an unreadable ledger or a wrong row count refuses a member (503)
      with an alert and lets the owner through; a misconfigured cap likewise.
      Every Anthropic call site in server.js calls enforceDailyModelCallLimit
      before it.
   6. THE ORACLE. Its real middleware chain, with the real limiter and upload,
      in Express: ten messages a minute, the eleventh 429 with nothing sent; a
      files-only send accepted; the persona's agent count read from the roster.
   9. CORS. corsAllowedOrigins leaves out localhost under every production
      signal isProductionEnv reads, keeps it in a local run, and is what the
      CORS middleware uses.

   MUTATE=<name> edits a source IN MEMORY (nothing on disk changes). MUTATE=all
   runs each in its own process (scripts/_shared.js runAllMutations).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const http = require("http");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const lf = t => t.replace(/\r\n/g, "\n");
const rq = require("module").createRequire(path.join(REPO, "server.js"));
const express = rq("express");

let SRC = lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8"));
let LIB = lf(fs.readFileSync(path.join(REPO, "lib", "bfcTransferLimits.js"), "utf8"));
let SQL = lf(fs.readFileSync(path.join(REPO, "supabase", "migrations", "148_bfc_donate_limits.sql"), "utf8"));
const PROFILES_DDL = lf(fs.readFileSync(path.join(REPO, "supabase", "migrations", "071_transcribe_foundation_tables.sql"), "utf8"));
let RD_AGENT = lf(fs.readFileSync(path.join(FRONTEND, "rd-agent.html"), "utf8"));

const MUTATE = process.env.MUTATE || "";
const MUTATIONS = {
  // #1: the deleted route is back, answering anyone with select("*")
  "profile-returns-email": [["SRC", 'app.get("/api/profile/by-id/:userId", requireAuth, async function (req, res, next) {',
    'app.get("/api/profile/:username", async function (req, res) { const r = await supabase.from("profiles").select("*").eq("username", req.params.username).maybeSingle(); res.json({ profile: r.data }); });\n\n' +
    'app.get("/api/profile/by-id/:userId", requireAuth, async function (req, res, next) {']],
  // #1: the by-id route reads the email too
  "by-id-returns-email": [["SRC", '.select("user_id, full_name, business_name, username, logo_url")', '.select("user_id, full_name, business_name, username, logo_url, email")']],
  // #2: the donate route skips the daily cap
  "donate-skips-daily-cap": [["SRC", "    if (sent.total + amount > limits.dailyCap) {", "    if (false) {"]],
  // #2: donations are not counted in the shared total
  "donate-not-shared": [["LIB", '  return description === BFC_TRANSFER_DESCRIPTION ||\n    (typeof description === "string" && description.indexOf(BFC_DONATION_DESCRIPTION_PREFIX) === 0);',
    "  return description === BFC_TRANSFER_DESCRIPTION;"]],
  // #2: the donate route skips the hold
  "donate-skips-hold": [["SRC", "    const sendableFromMs = openedMs + limits.holdDays * 24 * 60 * 60 * 1000;\n    // NaN fails this test too, so an account whose age cannot be read is held.\n    if (!(Date.now() >= sendableFromMs)) {\n      return res.status(403).json({\n        error: \"A new account can send BFC \" + limits.holdDays + \" days after it was opened\" +\n          (Number.isFinite(sendableFromMs) ? \"; yours can from \" + new Date(sendableFromMs).toISOString().slice(0, 10) : \"\") +\n          \". Nothing was sent.\",\n        reason: \"new_account_hold\",\n        hold_days: limits.holdDays\n      });\n    }\n\n    let campaign = null;",
    "    let campaign = null;"]],
  // #2: the donate route is open to an account without a subscription
  "donate-ungated": [["SRC", 'app.post("/api/crowdfunding/campaigns/:id/donate", requireAuth, requireActiveSubscription, bfcDonateLimiter,',
    'app.post("/api/crowdfunding/campaigns/:id/donate", requireAuth, bfcDonateLimiter,']],
  // #2: bfc_donate's own total counts transfers only
  "sql-donate-not-shared": [["SQL", "where user_id = p_donor\n  and type = 'debit'\n  and (description = 'Transfer' or description like 'Donation: %')",
    "where user_id = p_donor\n  and type = 'debit'\n  and description = 'Transfer'"]],
  // #2: bfc_donate reads the total before it takes the wallet lock
  "sql-sum-before-lock": [["SQL", "perform 1 from user_wallets where user_id = p_donor for update;\n\n", ""]],
  // #5: the ceiling is never applied
  "spend-cap-ignored": [["SRC", "  if (spend.usd >= cap) {\n    if (owner) {", "  if (false) {\n    if (owner) {"]],
  // #5: an unreadable ledger lets every call through
  "ledger-fails-open": [["SRC", "  if (spend.error) {\n    console.error(\"[spend] PLATFORM SPEND UNAVAILABLE", "  if (false) {\n    console.error(\"[spend] PLATFORM SPEND UNAVAILABLE"]],
  // #5: the 80% alert is raised on every call
  "alert-every-call": [["SRC", "  if (spend.usd >= cap * PLATFORM_SPEND_ALERT_SHARE && !PLATFORM_SPEND_STATE.alerted[spend.day]) {",
    "  if (spend.usd >= cap * PLATFORM_SPEND_ALERT_SHARE) {"]],
  // #5: enforceDailyModelCallLimit no longer applies the ceiling
  "ceiling-not-called": [["SRC", "  await enforcePlatformDailySpendCeiling(userId, route);\n", ""]],
  // #6: the oracle has no per-minute limit
  "oracle-unlimited": [["SRC", "requireActiveSubscription, oracleChatLimiter, oracleChatUpload.array(\"files\", 8)", "requireActiveSubscription, oracleChatUpload.array(\"files\", 8)"]],
  // #6: a files-only send is refused again
  "oracle-files-refused": [["SRC", "  var message = safeText(rawMessage, 4000);\n  if (message) return message;\n", "  var message = safeText(rawMessage, 4000);\n  return message || null;\n"]],
  // #6: the agent count is written into the persona
  "agent-count-hardcoded": [["SRC", "String(Object.keys(AGENT_SYSTEM_PROMPTS).length)", "\"18\""]],
  // #9: localhost is allowed in production
  "localhost-in-production": [["SRC", "  return isProductionEnv(env) ? origins : origins.concat([\"http://localhost:50157\"]);", "  return origins.concat([\"http://localhost:50157\"]);"]],
  // #3: rd-agent goes back to the inline presence check
  "rd-agent-inline-guard": [["RD", "  <script src=\"/scripts/bf-session.js\"></script>\n",
    "  <script>\n    (function () {\n      var token = localStorage.getItem(\"bf_token\");\n      if (!token) {\n        window.location.replace(\"/app.html\");\n      }\n    })();\n  </script>\n"]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
if (MUTATE) {
  for (const [which, from, to] of MUTATIONS[MUTATE]) {
    if (which === "SRC") SRC = s.replaceOnce(SRC, from, to, MUTATE);
    else if (which === "LIB") LIB = s.replaceOnce(LIB, from, to, MUTATE);
    else if (which === "SQL") SQL = s.replaceOnce(SQL, from, to, MUTATE);
    else if (which === "RD") RD_AGENT = s.replaceOnce(RD_AGENT, from, to, MUTATE);
  }
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* ── lifting from server.js, by name, as checkOracleAgentRecords does ───── */
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
const uncommented = code => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
// Memoized: a closure is the same text every time, and finding it is the slow part.
const CLOSURES = new Map();
function closure(root, stubs) {
  const key = [...stubs].sort().join(",") + "\n" + root;
  if (!CLOSURES.has(key)) CLOSURES.set(key, closureOf(root, stubs));
  return CLOSURES.get(key);
}
function closureOf(root, stubs) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || stubs.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !stubs.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
// The whole `app.<verb>("<path>", ...)` statement.
function routeSource(verb, routePath) {
  const sig = "app." + verb + "(\"" + routePath + "\",";
  const start = SRC.indexOf(sig);
  if (start < 0) return null;
  const open = SRC.indexOf("async function (req, res, next) {", start) + "async function (req, res, next) ".length;
  const end = s.braceMatch(SRC, open);
  return SRC.slice(start, end) + ");";
}
const BASE_STUBS = ["supabase", "console", "process", "require", "module", "app", "Buffer", "URL", "setTimeout", "setImmediate", "fetch",
  "requireAuth", "Date", "Math", "JSON", "Object", "Number", "String", "Array", "Promise", "Error"];

/* The lib, compiled from LIB (so a mutation of it reaches every route here). */
const LIMITS = (function () {
  const m = { exports: {} };
  vm.runInNewContext(LIB, { module: m, exports: m.exports, require: rq, process: { env: {} } }, { filename: "lib/bfcTransferLimits.js" });
  return m.exports;
})();

/* ── an in-memory database ───────────────────────────────────────────────── */
const clone = x => JSON.parse(JSON.stringify(x));
function fakeDb(seed, opts) {
  const o = opts || {};
  const t = {};
  Object.keys(seed).forEach(k => { t[k] = seed[k].map(clone); });
  const rpcCalls = [];
  const reads = [];
  function from(table) {
    const q = { table, filters: [], cols: "*", opts: {}, rng: null, lim: null, ordered: false };
    const api = {
      select(cols, so) { q.cols = cols || "*"; q.opts = so || {}; return api; },
      eq(c, v) { q.filters.push(["eq", c, v]); return api; },
      neq(c, v) { q.filters.push(["neq", c, v]); return api; },
      gte(c, v) { q.filters.push(["gte", c, v]); return api; },
      gt(c, v) { q.filters.push(["gt", c, v]); return api; },
      lte(c, v) { q.filters.push(["lte", c, v]); return api; },
      in(c, v) { q.filters.push(["in", c, v]); return api; },
      ilike(c, v) { q.filters.push(["ilike", c, v]); return api; },
      order() { q.ordered = true; return api; },
      limit(n) { q.lim = n; return api; },
      range(a, b) { q.rng = [a, b]; return api; },
      maybeSingle() { return run().then(r => r.error ? r : { data: r.data && r.data.length ? r.data[0] : null, error: null }); },
      single() { return run().then(r => r.error ? r : (r.data && r.data.length === 1 ? { data: r.data[0], error: null } : { data: null, error: { message: "not one row" } })); },
      then(res, rej) { return run().then(res, rej); }
    };
    function keep(row) {
      return q.filters.every(([op, c, v]) => {
        const x = row[c];
        if (op === "eq") return x === v;
        if (op === "neq") return x !== v;
        if (op === "gte") return x != null && String(x) >= String(v);
        if (op === "gt") return x != null && String(x) > String(v);
        if (op === "lte") return x != null && String(x) <= String(v);
        if (op === "in") return v.indexOf(x) !== -1;
        if (op === "ilike") return typeof x === "string" && new RegExp("^" + String(v).replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/%/g, ".*") + "$", "i").test(x);
        return true;
      });
    }
    function run() {
      reads.push(q);
      if (o.fail) {
        const f = o.fail(q);
        if (f === "throw") return Promise.reject(new Error("the connection dropped"));
        if (f) return Promise.resolve({ data: null, error: f, count: null });
      }
      let rows = (t[table] || []).filter(keep);
      const count = o.wrongCount ? rows.length + 1 : rows.length;
      if (q.ordered) rows = rows.slice().sort((a, b) => (a.id > b.id ? 1 : a.id < b.id ? -1 : 0));
      if (q.rng) rows = rows.slice(q.rng[0], q.rng[1] + 1);
      if (q.lim != null) rows = rows.slice(0, q.lim);
      const cols = q.cols === "*" ? null : q.cols.split(",").map(c => c.trim());
      const data = rows.map(r => { if (!cols) return clone(r); const p = {}; cols.forEach(c => { p[c] = r[c] === undefined ? null : clone(r[c]); }); return p; });
      return Promise.resolve({ data: q.opts.head ? null : data, error: null, count: q.opts.count ? count : null });
    }
    return api;
  }
  const client = {
    from,
    rpc: async function (name, args) {
      rpcCalls.push({ name, args: clone(args) });
      const fn = (o.rpc || {})[name];
      if (!fn) return { data: null, error: { code: "PGRST202", message: "Could not find the function public." + name } };
      try { return { data: fn(t, args), error: null }; } catch (e) { return { data: null, error: { message: e.message } }; }
    }
  };
  return { t, client, rpcCalls, reads };
}

/* ═════ 1. PROFILE PRIVACY ═══════════════════════════════════════════════ */
async function profilePrivacy() {
  console.log("\n══ 1. GET /api/profile/:username is gone, and no profile route leaks a private column ══");
  // Every GET path in server.js, routed by real Express: which answer /api/profile/<a username>?
  const paths = [...SRC.matchAll(/^app\.get\(\s*"([^"]+)"/gm)].map(m => m[1]);
  const router = express();
  const hits = [];
  paths.forEach(p => router.get(p, (req, res) => { hits.push(p); res.status(299).end(); }));
  const srv = http.createServer(router).listen(0, "127.0.0.1");
  await new Promise(r => srv.once("listening", r));
  const port = srv.address().port;
  for (const u of ["janedoe", "acme-studio", "Jane.Doe"]) {
    await new Promise(r => http.get({ host: "127.0.0.1", port, path: "/api/profile/" + u }, res => { res.resume(); res.on("end", r); }));
  }
  srv.close();
  check("1. of the " + paths.length + " GET paths in server.js, none answers /api/profile/<a username> (real Express routing)",
    paths.length > 100 && hits.length === 0, hits.join(", "));
  check("1. the remaining /api/profile GET routes are exactly /api/profile/me and /api/profile/by-id/:userId, both behind requireAuth",
    JSON.stringify(paths.filter(p => /^\/api\/profile(\/|$)/.test(p)).sort()) === JSON.stringify(["/api/profile/by-id/:userId", "/api/profile/me"]) &&
    /app\.get\("\/api\/profile\/me", requireAuth,/.test(SRC) && /app\.get\("\/api\/profile\/by-id\/:userId", requireAuth,/.test(SRC),
    paths.filter(p => /^\/api\/profile/.test(p)).join(", "));

  // A profiles row with every column of the table filled with a value that can be recognised.
  const ddl = /create table if not exists public\.profiles \(\n([\s\S]*?)\n\);/.exec(PROFILES_DDL);
  const columns = ddl ? ddl[1].split("\n").map(l => l.trim().split(/\s+/)[0]).filter(c => /^[a-z_]+$/.test(c)) : [];
  const TARGET = "aaaaaaaa-0000-4000-8000-000000000001";
  const row = {};
  columns.forEach(c => { row[c] = "FIXTURE-" + c + "-VALUE"; });
  row.user_id = TARGET;
  const PUBLIC = ["user_id", "full_name", "business_name", "username", "logo_url"];
  const PRIVATE = columns.filter(c => PUBLIC.indexOf(c) === -1);
  check("1. the fixture fills every one of the profiles table's " + columns.length + " columns (migration 071), email, contact_phone and the subscription fields among them",
    columns.length >= 27 && ["email", "contact_email", "contact_phone", "subscription_plan", "subscription_status"].every(c => PRIVATE.indexOf(c) !== -1), columns.join(","));

  const route = routeSource("get", "/api/profile/by-id/:userId");
  const db = fakeDb({ profiles: [row] });
  const handlers = {};
  const ctx = { supabase: db.client, console: { log() {}, warn() {}, error() {} }, requireAuth: 0, app: { get(p) { handlers[p] = arguments[arguments.length - 1]; } } };
  vm.createContext(ctx);
  vm.runInContext(route, ctx);
  const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = clone(b); return this; } };
  let err = null;
  await handlers["/api/profile/by-id/:userId"]({ params: { userId: TARGET }, user: { id: "bbbbbbbb-0000-4000-8000-000000000002" } }, res, e => { err = e; });
  const text = JSON.stringify(res.body || {});
  const leaked = PRIVATE.filter(c => text.indexOf("FIXTURE-" + c + "-VALUE") !== -1);
  check("1. GET /api/profile/by-id/:userId, asked by another member about the filled row, answers the five display columns and nothing else",
    !err && res.statusCode === 200 && res.body && res.body.profile &&
    JSON.stringify(Object.keys(res.body.profile).sort()) === JSON.stringify(PUBLIC.slice().sort()), err ? err.message : text);
  check("1. not one private value appears in that answer (" + PRIVATE.length + " columns checked)", leaked.length === 0, "leaked: " + leaked.join(", "));
}

/* ═════ 2. DONATIONS UNDER THE TRANSFER LIMITS ═══════════════════════════ */
const DAY = 24 * 60 * 60 * 1000;
const isoAgo = ms => new Date(Date.now() - ms).toISOString();
const DONOR = "d0000000-0000-4000-8000-000000000001";
const OWNER2 = "e0000000-0000-4000-8000-000000000002";
const NEWBIE = "f0000000-0000-4000-8000-000000000003";
const UNSUB = "c0000000-0000-4000-8000-000000000004";
const CAMPAIGN = "ca000000-0000-4000-8000-000000000001";
const OWN_CAMPAIGN = "ca000000-0000-4000-8000-000000000002";

function transferModel(t, from, to, amount, description) {
  const w = t.user_wallets.find(x => x.user_id === from);
  if (!w || w.balance < amount) throw new Error("insufficient balance");
  let r = t.user_wallets.find(x => x.user_id === to);
  if (!r) { r = { user_id: to, balance: 0 }; t.user_wallets.push(r); }
  w.balance -= amount; r.balance += amount;
  const at = new Date().toISOString();
  t.wallet_transactions.push({ id: "tx" + t.wallet_transactions.length, user_id: from, type: "debit", amount, description, created_at: at });
  t.wallet_transactions.push({ id: "tx" + t.wallet_transactions.length, user_id: to, type: "credit", amount, description, created_at: at });
  return w.balance;
}
// bfc_donate and bfc_send with NO limits: what the route reaches. A refusal of a limit can then only be the route's.
const UNLIMITED = {
  bfc_donate(t, a) {
    const c = t.crowdfunding_campaigns.find(x => x.id === a.p_campaign_id);
    if (!c) throw new Error("campaign_not_found: no campaign has the id " + a.p_campaign_id);
    if (c.owner_id === a.p_donor) throw new Error("self_donation: you cannot donate to your own campaign");
    if (c.status !== "active") throw new Error("campaign_not_active: this campaign is not accepting donations");
    const bal = transferModel(t, a.p_donor, c.owner_id, a.p_amount, "Donation: " + c.title);
    t.campaign_donations.push({ campaign_id: c.id, donor_id: a.p_donor, owner_id: c.owner_id, amount_bfc: a.p_amount });
    c.raised_bfc += a.p_amount;
    return bal;
  },
  bfc_send(t, a) {
    const bal = transferModel(t, a.p_from, a.p_to, a.p_amount, "Transfer");
    t.bfc_transfers.push({ sender_id: a.p_from, recipient_id: a.p_to, amount_bfc: a.p_amount });
    return bal;
  }
};
function world(extraTx) {
  return {
    users: [{ id: DONOR, created_at: isoAgo(30 * DAY), role: "member" }, { id: OWNER2, created_at: isoAgo(90 * DAY), role: "member" },
      { id: NEWBIE, created_at: isoAgo(3 * DAY), role: "member" }, { id: UNSUB, created_at: isoAgo(60 * DAY), role: "member" }],
    user_wallets: [{ user_id: DONOR, balance: 10000 }, { user_id: OWNER2, balance: 500 }, { user_id: NEWBIE, balance: 1000 }, { user_id: UNSUB, balance: 1000 }],
    wallet_transactions: (extraTx || []).map((x, i) => Object.assign({ id: "seed" + i, user_id: DONOR, type: "debit" }, x)),
    crowdfunding_campaigns: [{ id: CAMPAIGN, owner_id: OWNER2, status: "active", title: "New kiln", raised_bfc: 0 },
      { id: OWN_CAMPAIGN, owner_id: DONOR, status: "active", title: "My own", raised_bfc: 0 }],
    campaign_donations: [], bfc_transfers: [], bf_profiles: []
  };
}
const BFC_STUBS = new Set(BASE_STUBS.concat(["requireActiveSubscription", "bfcDonateLimiter", "bfcTransferLimits", "bfcCountsTowardDailyCap", "getUserPlan"]));
const DONATE = routeSource("post", "/api/crowdfunding/campaigns/:id/donate");
const TRANSFER = routeSource("post", "/api/wallet/transfer");
function bfcRoutes(db, env) {
  const handlers = {};
  const logs = [];
  const ctx = {
    supabase: db.client, process: { env: env || {} }, require: rq,
    console: { log() {}, warn(m) { logs.push(String(m)); }, error(m) { logs.push(String(m)); } },
    requireAuth: 0, requireActiveSubscription: 0, bfcDonateLimiter: 0,
    bfcTransferLimits: LIMITS.bfcTransferLimits, bfcCountsTowardDailyCap: LIMITS.bfcCountsTowardDailyCap,
    app: { post(p) { handlers[p] = arguments[arguments.length - 1]; }, get() {} }
  };
  vm.createContext(ctx);
  vm.runInContext(closure(DONATE + "\n\n" + TRANSFER, BFC_STUBS), ctx);
  return { handlers, logs, ctx };
}
async function call(handler, user, params, body) {
  const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = clone(b); return this; } };
  let err = null;
  await handler({ user: { id: user }, params: params || {}, body: body || {}, headers: {} }, res, e => { err = e; });
  return { status: res.statusCode, body: res.body, err };
}
const moved = (t0, t1) => JSON.stringify([t0.user_wallets, t0.wallet_transactions, t0.campaign_donations, t0.crowdfunding_campaigns, t0.bfc_transfers]) !==
  JSON.stringify([t1.user_wallets, t1.wallet_transactions, t1.campaign_donations, t1.crowdfunding_campaigns, t1.bfc_transfers]);

async function donations() {
  console.log("\n══ 2. a campaign donation obeys the transfer limits, with one shared 24-hour total ══");
  check("2. the route and the sum both exist", !!DONATE && !!TRANSFER);
  const lim = LIMITS.bfcTransferLimits({});
  check("2. the limits are lib/bfcTransferLimits.js's defaults: 1,000 BFC a transfer, 2,000 BFC in 24 hours, 7 days' hold",
    lim.max === 1000 && lim.dailyCap === 2000 && lim.holdDays === 7, JSON.stringify(lim));
  check("2. the donate route reads them from the same bfcTransferLimits(process.env) as the transfer route",
    /const limits = bfcTransferLimits\(process\.env\);/.test(DONATE) && /const limits = bfcTransferLimits\(process\.env\);/.test(TRANSFER));

  async function refusal(label, seedTx, user, campaign, amount, reason, status, extra) {
    const seed = world(seedTx);
    const db = fakeDb(seed, { rpc: UNLIMITED });
    const r = bfcRoutes(db);
    const before = clone(db.t);
    const out = await call(r.handlers["/api/crowdfunding/campaigns/:id/donate"], user, { id: campaign }, { amount });
    const ok = !out.err && out.status === status && out.body && out.body.reason === reason && /Nothing was sent\./.test(out.body.error || "") &&
      db.rpcCalls.length === 0 && !moved(before, db.t) && (!extra || extra(out.body));
    check("2. " + label + ": " + status + " " + reason + ", refused by the route before the database, nothing moved", ok,
      out.err ? out.err.message : out.status + " " + JSON.stringify(out.body) + " rpc=" + db.rpcCalls.length);
  }
  await refusal("1,001 BFC, over the 1,000 BFC maximum", [], DONOR, CAMPAIGN, 1001, "over_per_transfer_max", 400, b => b.limit === 1000);
  await refusal("600 BFC after 1,500 BFC of transfers today, over the shared 2,000 BFC cap",
    [{ amount: 1500, description: "Transfer", created_at: isoAgo(2 * 60 * 60 * 1000) }], DONOR, CAMPAIGN, 600, "over_daily_cap", 400,
    b => b.sent_last_24h === 1500 && b.limit === 2000 && /transfers and donations together/.test(b.error));
  await refusal("600 BFC after 1,500 BFC of donations today", [{ amount: 1500, description: "Donation: Other campaign", created_at: isoAgo(60 * 60 * 1000) }],
    DONOR, CAMPAIGN, 600, "over_daily_cap", 400, b => b.sent_last_24h === 1500);
  await refusal("from an account opened 3 days ago, inside the 7-day hold", [], NEWBIE, CAMPAIGN, 10, "new_account_hold", 403, b => b.hold_days === 7);
  await refusal("to the donor's own campaign", [], DONOR, OWN_CAMPAIGN, 10, "self_donation", 400);
  await refusal("a fraction of a BFC", [], DONOR, CAMPAIGN, 1.5, "invalid_amount", 400);
  await refusal("to a campaign id that is not a uuid", [], DONOR, "not-a-uuid", 10, "campaign_not_found", 404);

  // The total read under failure: refused, nothing moved.
  {
    const db = fakeDb(world(), { rpc: UNLIMITED, fail: q => q.table === "wallet_transactions" ? { message: "relation unavailable" } : null });
    const r = bfcRoutes(db);
    const out = await call(r.handlers["/api/crowdfunding/campaigns/:id/donate"], DONOR, { id: CAMPAIGN }, { amount: 10 });
    check("2. a 24-hour total that cannot be read refuses: 503 daily_total_unreadable, nothing sent", out.status === 503 && out.body.reason === "daily_total_unreadable" && db.rpcCalls.length === 0,
      out.status + " " + JSON.stringify(out.body));
  }

  // Older debits, and debits that are neither, do not count.
  {
    const db = fakeDb(world([{ amount: 1900, description: "Donation: Last week", created_at: isoAgo(25 * 60 * 60 * 1000) },
      { amount: 1900, description: "Purchase: a listing", created_at: isoAgo(60 * 1000) }]), { rpc: UNLIMITED });
    const r = bfcRoutes(db);
    const out = await call(r.handlers["/api/crowdfunding/campaigns/:id/donate"], DONOR, { id: CAMPAIGN }, { amount: 900 });
    check("2. a donation 25 hours old and a purchase do not count: 900 BFC goes", out.status === 200 && db.rpcCalls.length === 1, out.status + " " + JSON.stringify(out.body));
  }

  // A donation counts toward a transfer's cap, and a transfer toward a donation's: one total, both ways, end to end.
  {
    const db = fakeDb(world(), { rpc: UNLIMITED });
    const r = bfcRoutes(db);
    const d1 = await call(r.handlers["/api/crowdfunding/campaigns/:id/donate"], DONOR, { id: CAMPAIGN }, { amount: 1000 });
    const t1 = await call(r.handlers["/api/wallet/transfer"], DONOR, {}, { recipientId: OWNER2, amount: 900 });
    const before = clone(db.t);
    const t2 = await call(r.handlers["/api/wallet/transfer"], DONOR, {}, { recipientId: OWNER2, amount: 101 });
    const d2 = await call(r.handlers["/api/crowdfunding/campaigns/:id/donate"], DONOR, { id: CAMPAIGN }, { amount: 101 });
    const refusalsMoved = moved(before, db.t);
    const d3 = await call(r.handlers["/api/crowdfunding/campaigns/:id/donate"], DONOR, { id: CAMPAIGN }, { amount: 100 });
    check("2. donate 1,000 then transfer 900: both go (1,900 of 2,000)", d1.status === 200 && t1.status === 200, d1.status + " " + t1.status + " " + JSON.stringify(t1.body));
    check("2. then a 101 BFC transfer is refused over_daily_cap with sent_last_24h 1,900: the donation counted toward the transfer's cap",
      t2.status === 400 && t2.body.reason === "over_daily_cap" && t2.body.sent_last_24h === 1900, t2.status + " " + JSON.stringify(t2.body));
    check("2. and a 101 BFC donation is refused the same way: the transfer counted toward the donation's cap",
      d2.status === 400 && d2.body.reason === "over_daily_cap" && d2.body.sent_last_24h === 1900, d2.status + " " + JSON.stringify(d2.body));
    check("2. neither refusal moved anything, and neither reached the database", !refusalsMoved && db.rpcCalls.length === 3, db.rpcCalls.length);
    check("2. 100 BFC more, to exactly 2,000, still goes", d3.status === 200, d3.status + " " + JSON.stringify(d3.body));
  }

  // What a donation records is unchanged.
  {
    const db = fakeDb(world(), { rpc: UNLIMITED });
    const r = bfcRoutes(db);
    const out = await call(r.handlers["/api/crowdfunding/campaigns/:id/donate"], DONOR, { id: CAMPAIGN }, { amount: 250 });
    const call0 = db.rpcCalls[0] || { args: {} };
    check("2. a donation within the limits calls bfc_donate with the donor, the campaign, the amount and the three limits, and answers the balance",
      out.status === 200 && out.body.balance === 9750 && call0.name === "bfc_donate" &&
      JSON.stringify(call0.args) === JSON.stringify({ p_donor: DONOR, p_campaign_id: CAMPAIGN, p_amount: 250, p_max_per_transfer: 1000, p_daily_cap: 2000, p_hold_days: 7 }),
      out.status + " " + JSON.stringify(out.body) + " " + JSON.stringify(call0));
    const tx = db.t.wallet_transactions;
    check("2. its records: a debit and a credit described 'Donation: New kiln', one campaign_donations row, raised_bfc 250",
      tx.length === 2 && tx.every(x => x.description === "Donation: New kiln" && x.amount === 250) && db.t.campaign_donations.length === 1 &&
      db.t.crowdfunding_campaigns[0].raised_bfc === 250, JSON.stringify(tx));
  }
  {
    const db = fakeDb(world(), {});
    const r = bfcRoutes(db);
    const out = await call(r.handlers["/api/crowdfunding/campaigns/:id/donate"], DONOR, { id: CAMPAIGN }, { amount: 10 });
    check("2. before migration 148 is applied: 503 migration_148_not_applied, nothing sent", out.status === 503 && out.body.reason === "migration_148_not_applied", JSON.stringify(out.body));
  }

  /* Through real Express: the route's own middleware, the real gate and the real limiter. */
  {
    const app = express();
    app.use(express.json());
    const db = fakeDb(world(), { rpc: UNLIMITED });
    const handlersCtx = {
      supabase: db.client, process: { env: {} }, require: rq, console: { log() {}, warn() {}, error() {} },
      requireAuth: function (req, res, next) { req.user = { id: req.headers["x-user"], role: "member" }; next(); },
      getUserPlan: async function (id) { return id === UNSUB ? { active: false, inactive_reason: "no_subscription", plan: null } : { active: true, plan: "all_access", inactive_reason: null }; },
      bfcTransferLimits: LIMITS.bfcTransferLimits, bfcCountsTowardDailyCap: LIMITS.bfcCountsTowardDailyCap,
      app
    };
    vm.createContext(handlersCtx);
    vm.runInContext(closure(DONATE, new Set(BASE_STUBS.concat(["bfcTransferLimits", "bfcCountsTowardDailyCap", "getUserPlan"]))), handlersCtx);
    const srv = http.createServer(app).listen(0, "127.0.0.1");
    await new Promise(r => srv.once("listening", r));
    const port = srv.address().port;
    const post = (user, amount) => fetch("http://127.0.0.1:" + port + "/api/crowdfunding/campaigns/" + CAMPAIGN + "/donate",
      { method: "POST", headers: { "content-type": "application/json", "x-user": user }, body: JSON.stringify({ amount }) })
      .then(async r => ({ status: r.status, body: await r.json().catch(() => null) }));
    const before = clone(db.t);
    const unsub = await post(UNSUB, 10);
    check("2. an account without a subscription: 402 from requireActiveSubscription, nothing moved",
      unsub.status === 402 && unsub.body && unsub.body.upgrade_required === true && db.rpcCalls.length === 0 && !moved(before, db.t), unsub.status + " " + JSON.stringify(unsub.body));
    const statuses = [];
    for (let i = 0; i < 11; i++) statuses.push((await post(DONOR, 1)));
    const last = statuses[10];
    check("2. ten donations in ten minutes go; the eleventh is 429 rate_limited from bfcDonateLimiter and moves nothing",
      statuses.slice(0, 10).every(x => x.status === 200) && last.status === 429 && last.body && last.body.reason === "rate_limited" &&
      db.rpcCalls.length === 10 && db.t.campaign_donations.length === 10, statuses.map(x => x.status).join(","));
    srv.close();
  }

  /* Migration 148, as text. */
  console.log("\n══ 2. supabase/migrations/148_bfc_donate_limits.sql ══");
  const fnBody = name => { const i = SQL.indexOf("CREATE OR REPLACE FUNCTION public." + name + "("); const j = SQL.indexOf("$function$;", i); return i < 0 || j < 0 ? "" : SQL.slice(i, j); };
  const donateFn = fnBody("bfc_donate"), sendFn = fnBody("bfc_send");
  check("2. the three-argument bfc_donate is dropped before the six-argument one is created, so the uncapped signature cannot be called",
    SQL.indexOf("DROP FUNCTION IF EXISTS public.bfc_donate(uuid, uuid, integer);") !== -1 &&
    SQL.indexOf("DROP FUNCTION IF EXISTS public.bfc_donate(uuid, uuid, integer);") < SQL.indexOf("CREATE OR REPLACE FUNCTION public.bfc_donate(") &&
    /CREATE OR REPLACE FUNCTION public\.bfc_donate\(p_donor uuid, p_campaign_id uuid, p_amount integer, p_max_per_transfer integer, p_daily_cap integer, p_hold_days integer\)/.test(SQL));
  const reasonsOf = body => [...body.matchAll(/raise exception '([a-z_]+):/g)].map(m => m[1]);
  const donateReasons = reasonsOf(donateFn);
  check("2. bfc_donate raises every limit itself: limits_invalid, invalid_amount, over_per_transfer_max, unknown_sender, new_account_hold, campaign_not_found, self_donation, campaign_not_active, over_daily_cap",
    JSON.stringify(donateReasons) === JSON.stringify(["limits_invalid", "invalid_amount", "over_per_transfer_max", "unknown_sender", "new_account_hold",
      "campaign_not_found", "self_donation", "campaign_not_active", "over_daily_cap"]), donateReasons.join(","));
  const mapped = bfcRoutes(fakeDb(world(), {})).ctx;
  const statusMap = vm.runInContext("BFC_DONATE_REFUSAL_STATUS", mapped);
  check("2. every reason bfc_donate raises is mapped by the route to a status, so each refusal names its reason",
    donateReasons.every(r => Object.prototype.hasOwnProperty.call(statusMap, r)), donateReasons.filter(r => !Object.prototype.hasOwnProperty.call(statusMap, r)).join(","));
  const lock = donateFn.indexOf("perform 1 from user_wallets where user_id = p_donor for update;");
  const sum = donateFn.indexOf("select coalesce(sum(amount), 0) into v_sent");
  check("2. bfc_donate takes the donor's wallet lock (the one bfc_send takes) BEFORE it reads the 24-hour total", lock !== -1 && sum !== -1 && lock < sum, lock + " < " + sum);
  const SHARED = "  and type = 'debit'\n  and (description = 'Transfer' or description like 'Donation: %')\n  and created_at > now() - interval '24 hours';";
  check("2. bfc_donate's total counts 'Transfer' and 'Donation: ' debits together over 24 hours",
    donateFn.indexOf("where user_id = p_donor\n" + SHARED) !== -1);
  check("2. and so does bfc_send's (still locking first), so the cap is one total from either side",
    sendFn.indexOf("where user_id = p_from\n" + SHARED) !== -1 &&
    sendFn.indexOf("perform 1 from user_wallets where user_id = p_from for update;") < sendFn.indexOf("select coalesce(sum(amount), 0) into v_sent"));
  check("2. the SQL counts what the route counts: bfcCountsTowardDailyCap takes 'Transfer' and 'Donation: …' and nothing else",
    LIMITS.bfcCountsTowardDailyCap("Transfer") && LIMITS.bfcCountsTowardDailyCap("Donation: New kiln") &&
    !LIMITS.bfcCountsTowardDailyCap("Purchase: a listing") && !LIMITS.bfcCountsTowardDailyCap("Welcome bonus") && !LIMITS.bfcCountsTowardDailyCap(null));
  check("2. what a donation writes is 031's: bfc_transfer described 'Donation: ' || title, a campaign_donations row, raised_bfc",
    /v_new_balance := bfc_transfer\(p_donor, v_owner, p_amount, 'Donation: ' \|\| v_title\);/.test(donateFn) &&
    /insert into campaign_donations \(campaign_id, donor_id, owner_id, amount_bfc\)\nvalues \(p_campaign_id, p_donor, v_owner, p_amount\);/.test(donateFn) &&
    /set raised_bfc = raised_bfc \+ p_amount,/.test(donateFn) && !/insert into user_wallets|update user_wallets/.test(donateFn));
  check("2. bfc_donate is service_role only",
    /revoke execute on function public\.bfc_donate\(uuid, uuid, integer, integer, integer, integer\) from public, anon, authenticated;/.test(SQL) &&
    /grant  execute on function public\.bfc_donate\(uuid, uuid, integer, integer, integer, integer\) to service_role;/.test(SQL));
  check("2. 148 is the next migration number after the highest before it",
    fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(f => /^\d+_/.test(f)).map(f => parseInt(f, 10)).sort((a, b) => a - b).filter(n => n < 148).pop() === 147);
}

/* ═════ 3. rd-agent.html ═════════════════════════════════════════════════ */
function rdAgent() {
  console.log("\n══ 3. rd-agent.html renews or redirects an expired session ══");
  const head = RD_AGENT.slice(0, RD_AGENT.indexOf("</head>"));
  const scripts = [...head.matchAll(/<script\b[^>]*>/g)].map(m => m[0]);
  check("3. the first script in its head is /scripts/bf-session.js", scripts[0] === "<script src=\"/scripts/bf-session.js\"></script>".replace("</script>", "") || scripts[0] === "<script src=\"/scripts/bf-session.js\">", scripts[0]);
  check("3. and the head has no inline token check left", !/localStorage\.getItem\("bf_token"\)/.test(head) && (head.match(/bf-session\.js/g) || []).length === 1);
  check("3. scripts/bf-session.js exists", fs.existsSync(path.join(FRONTEND, "scripts", "bf-session.js")));
}

/* ═════ 5. THE PLATFORM DAILY SPEND CEILING ══════════════════════════════ */
const OWNER_ID = rq("./lib/ownerAccount").OWNER_ACCOUNT_ID;
const MEMBER = "a0000000-0000-4000-8000-0000000000aa";
const PLATFORM_ROOT = definitionOf("enforceDailyModelCallLimit");
function platform(rows, env, dbOpts) {
  const db = fakeDb({ model_calls: rows }, dbOpts || {});
  const alerts = [], logs = [];
  const ctx = { supabase: db.client, process: { env: Object.assign({}, env || {}) }, OWNER_ACCOUNT_ID: OWNER_ID,
    console: { log() {}, warn(m) { logs.push(String(m)); }, error(m) { logs.push(String(m)); } } };
  vm.createContext(ctx);
  vm.runInContext(closure(PLATFORM_ROOT + "\n\nthis.__api = { enforceDailyModelCallLimit, enforcePlatformDailySpendCeiling, platformDailySpendCap, modelCallUtcDay, PLATFORM_SPEND_STATE };",
    new Set(BASE_STUBS.concat(["OWNER_ACCOUNT_ID"]))), ctx);
  ctx.__api.PLATFORM_SPEND_STATE.raise = function (key, info) { alerts.push({ key, info }); return Promise.resolve(); };
  return { api: ctx.__api, alerts, logs, db };
}
async function attempt(fn) { try { return { ok: await fn() }; } catch (e) { return { err: e }; } }
function spendRows(day, usd, extra) {
  // claude-sonnet-5 is $10 per million output tokens: $1 is 100,000.
  return [Object.assign({ id: 1, user_id: "someone", model: "claude-sonnet-5", input_tokens: 0, output_tokens: Math.round(usd * 100000), funded_by: "platform", created_on: day }, extra || {})];
}
async function platformCeiling() {
  console.log("\n══ 5. one daily spend ceiling for the whole platform ══");
  const day = platform([], {}).api.modelCallUtcDay();
  const capOf = v => platform([], v === undefined ? {} : { PLATFORM_DAILY_SPEND_CAP_USD: v }).api.platformDailySpendCap();
  check("5. PLATFORM_DAILY_SPEND_CAP_USD: absent or blank is the $25 default, a positive number is honoured, anything else is unusable (null)",
    capOf(undefined) === 25 && capOf("") === 25 && capOf("  ") === 25 && capOf("40") === 40 && capOf("12.5") === 12.5 &&
    capOf("0") === null && capOf("-5") === null && capOf("abc") === null,
    [capOf(undefined), capOf(""), capOf("40"), capOf("0"), capOf("abc")].join(","));

  {
    const p = platform(spendRows(day, 5), {});
    const r = await attempt(() => p.api.enforcePlatformDailySpendCeiling(MEMBER, "test"));
    check("5. $5 of $25 today: a member's call goes, and no alert", r.ok && r.ok.allowed === true && p.alerts.length === 0, r.err ? r.err.message : JSON.stringify(r.ok));
  }
  {
    const p = platform(spendRows(day, 20), {});
    const rs = [];
    for (let i = 0; i < 4; i++) rs.push(await attempt(() => p.api.enforcePlatformDailySpendCeiling(MEMBER, "test")));
    check("5. $20 of $25 (80%): calls still go, and exactly one platform_spend_80 alert across four calls",
      rs.every(r => r.ok && r.ok.allowed) && p.alerts.length === 1 && p.alerts[0].key === "platform_spend_80" && p.alerts[0].info.fingerprint === day,
      p.alerts.map(a => a.key).join(","));
  }
  {
    const p = platform(spendRows(day, 25), {});
    const m = await attempt(() => p.api.enforcePlatformDailySpendCeiling(MEMBER, "POST /api/oracle"));
    check("5. $25 of $25 (100%): a member is refused 429 PLATFORM_DAILY_SPEND_LIMIT, \"BizForce has reached today's AI usage limit; it resets at midnight UTC\"",
      m.err && m.err.status === 429 && m.err.code === "PLATFORM_DAILY_SPEND_LIMIT" &&
      m.err.message.indexOf("BizForce has reached today's AI usage limit; it resets at midnight UTC.") === 0, m.err ? m.err.message : "allowed");
    const o = await attempt(() => p.api.enforcePlatformDailySpendCeiling(OWNER_ID, "POST /api/oracle"));
    check("5. at 100% the owner account's call goes", o.ok && o.ok.allowed === true && o.ok.owner === true, o.err ? o.err.message : JSON.stringify(o.ok));
    const via = await attempt(() => p.api.enforceDailyModelCallLimit(MEMBER, "POST /api/oracle"));
    const none = await attempt(() => p.api.enforceDailyModelCallLimit(null, "callAnthropicText"));
    check("5. enforceDailyModelCallLimit, which every model call passes through, applies it: a member and a call with no user are both refused",
      via.err && via.err.code === "PLATFORM_DAILY_SPEND_LIMIT" && none.err && none.err.code === "PLATFORM_DAILY_SPEND_LIMIT",
      (via.err ? via.err.code : "allowed") + " / " + (none.err ? none.err.code : "allowed"));
    const ownerVia = await attempt(() => p.api.enforceDailyModelCallLimit(OWNER_ID, "POST /api/oracle"));
    check("5. and lets the owner on to the per-account checks", ownerVia.ok && ownerVia.ok.allowed === true, ownerVia.err ? ownerVia.err.message : JSON.stringify(ownerVia.ok));
  }
  {
    const rows = spendRows(day, 100, { funded_by: "user" }).concat(spendRows(day, 1, { id: 2 }));
    const p = platform(rows, {});
    const r = await attempt(() => p.api.enforcePlatformDailySpendCeiling(MEMBER, "test"));
    check("5. rows a member paid for with their own key do not count: $100 of those and $1 of the platform's goes", r.ok && Math.abs(r.ok.spent_usd - 1) < 1e-9, r.err ? r.err.message : JSON.stringify(r.ok));
  }
  {
    const rows = [];
    for (let i = 0; i < 2500; i++) rows.push({ id: i + 1, user_id: "u" + (i % 7), model: "claude-sonnet-5", input_tokens: 0, output_tokens: 1000, funded_by: "platform", created_on: day });
    const p = platform(rows, {});
    const r = await attempt(() => p.api.enforcePlatformDailySpendCeiling(MEMBER, "test"));
    check("5. 2,500 calls of a cent each ($25) are all read, page by page, and refuse", r.err && r.err.code === "PLATFORM_DAILY_SPEND_LIMIT", r.err ? r.err.code : JSON.stringify(r.ok));
  }
  {
    const p = platform(spendRows(day, 1), {}, { fail: q => q.table === "model_calls" && !q.filters.some(f => f[1] === "user_id") ? { message: "relation unavailable" } : null });
    const m = await attempt(() => p.api.enforcePlatformDailySpendCeiling(MEMBER, "test"));
    check("5. a ledger that cannot be read FAILS CLOSED for a member: 503 PLATFORM_SPEND_UNREADABLE",
      m.err && m.err.status === 503 && m.err.code === "PLATFORM_SPEND_UNREADABLE", m.err ? m.err.code : JSON.stringify(m.ok));
    check("5. and raises the platform_spend_unreadable alert", p.alerts.some(a => a.key === "platform_spend_unreadable"), p.alerts.map(a => a.key).join(","));
    const o = await attempt(() => p.api.enforcePlatformDailySpendCeiling(OWNER_ID, "test"));
    check("5. the owner's call goes even then", o.ok && o.ok.allowed === true, o.err ? o.err.message : "");
  }
  {
    const p = platform(spendRows(day, 1), {}, { fail: q => q.table === "model_calls" ? "throw" : null });
    const m = await attempt(() => p.api.enforcePlatformDailySpendCeiling(MEMBER, "test"));
    check("5. a ledger read that throws fails closed the same way", m.err && m.err.code === "PLATFORM_SPEND_UNREADABLE", m.err ? m.err.code : JSON.stringify(m.ok));
  }
  {
    const p = platform(spendRows(day, 1), {}, { wrongCount: true });
    const m = await attempt(() => p.api.enforcePlatformDailySpendCeiling(MEMBER, "test"));
    check("5. a read whose rows do not match the exact count fails closed too (a partial read is not a total)", m.err && m.err.code === "PLATFORM_SPEND_UNREADABLE", m.err ? m.err.code : JSON.stringify(m.ok));
  }
  {
    const p = platform(spendRows(day, 1), { PLATFORM_DAILY_SPEND_CAP_USD: "lots" });
    const m = await attempt(() => p.api.enforcePlatformDailySpendCeiling(MEMBER, "test"));
    const o = await attempt(() => p.api.enforcePlatformDailySpendCeiling(OWNER_ID, "test"));
    check("5. an unusable cap refuses a member (503 PLATFORM_DAILY_SPEND_LIMIT_MISCONFIGURED), alerts, and lets the owner through",
      m.err && m.err.code === "PLATFORM_DAILY_SPEND_LIMIT_MISCONFIGURED" && o.ok && o.ok.allowed && p.alerts.some(a => a.key === "platform_spend_cap_misconfigured"),
      (m.err ? m.err.code : "allowed") + " " + p.alerts.map(a => a.key).join(","));
  }
  // Every Anthropic call in server.js passes through enforceDailyModelCallLimit first.
  // The enclosing column-0 function or route of each call, its body found past any default parameters.
  const tops = [...SRC.matchAll(/^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*\(|app\.[a-z]+\()/gm)].map(m => {
    const open = m[0].indexOf("function") !== -1 ? SRC.indexOf(") {", m.index) + 2 : SRC.indexOf("{", SRC.indexOf("function (req, res", m.index));
    return [m.index, s.braceMatch(SRC, open)];
  });
  const sites = [...SRC.matchAll(/([A-Za-z]*[Aa]nthropic[A-Za-z]*)\.messages\.(create|stream)\(/g)].map(m => m.index);
  const unguarded = sites.filter(i => {
    const sp = tops.filter(([a, b]) => i > a && i < b).sort((x, y) => (y[0] - x[0]))[0];
    return !sp || SRC.slice(sp[0], i).indexOf("await enforceDailyModelCallLimit(") === -1;
  });
  check("5. every one of the " + sites.length + " Anthropic call sites in server.js calls enforceDailyModelCallLimit before it",
    sites.length >= 6 && unguarded.length === 0, unguarded.map(i => SRC.slice(0, i).split("\n").length).join(","));
  check("5. the alert sink is opsAlerts.raise, set by assignment in server.js",
    /^PLATFORM_SPEND_STATE\.raise = function \(key, info\) \{ return opsAlerts\.raise\(key, info\); \};$/m.test(SRC));
}

/* ═════ 6. THE ORACLE ════════════════════════════════════════════════════ */
async function oracle() {
  console.log("\n══ 6. POST /api/oracle: limited, files-only accepted, the agent count from the roster ══");
  const start = SRC.indexOf("app.post(\"/api/oracle\",");
  const sigEnd = SRC.indexOf("async function (req, res, next) {", start) + "async function (req, res, next) {".length;
  const gate = "    if (!message) {\n      return res.status(400).json({ error: \"Type a question or attach a file. Nothing was sent.\" });\n    }\n";
  const gateAt = SRC.indexOf(gate, sigEnd);
  check("6. the route opens with oracleMessageFrom and its 400", start > 0 && gateAt > sigEnd && gateAt - sigEnd < 200 &&
    SRC.slice(sigEnd, gateAt).indexOf("var message = oracleMessageFrom(req.body.message, req.files);") !== -1);
  // The real signature and the real opening, then a stand-in for the model call.
  const head = SRC.slice(start, gateAt + gate.length) +
    "    return res.json({ reached: true, message: message, files: (req.files || []).length });\n  } catch (e) { next(e); }\n});";
  const app = express();
  app.use(express.json());
  const ctx = { process: { env: {} }, require: rq, console: { log() {}, warn() {}, error() {} }, Buffer,
    requireAuth: function (req, res, next) { req.user = { id: req.headers["x-user"] }; next(); },
    requireActiveSubscription: function (req, res, next) { next(); }, app };
  vm.createContext(ctx);
  vm.runInContext(closure(head, new Set(BASE_STUBS.concat(["requireActiveSubscription"]))), ctx);
  const srv = http.createServer(app).listen(0, "127.0.0.1");
  await new Promise(r => srv.once("listening", r));
  const url = "http://127.0.0.1:" + srv.address().port + "/api/oracle";
  const sendJson = (user, message) => fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-user": user }, body: JSON.stringify({ message }) })
    .then(async r => ({ status: r.status, body: await r.json().catch(() => null) }));
  const rs = [];
  for (let i = 0; i < 11; i++) rs.push(await sendJson("oracle-user-1", "question " + i));
  check("6. ten messages in a minute reach the handler; the eleventh is 429 rate_limited, with nothing sent",
    rs.slice(0, 10).every(r => r.status === 200 && r.body.reached) && rs[10].status === 429 && rs[10].body && rs[10].body.reason === "rate_limited" &&
    /Nothing was sent\./.test(rs[10].body.error), rs.map(r => r.status).join(","));
  const other = await sendJson("oracle-user-2", "hello");
  check("6. the limit is per account: another member's first message still goes", other.status === 200, other.status);
  const form = new FormData();
  form.append("files", new Blob(["Q3 numbers: revenue up 12%."], { type: "text/plain" }), "q3-notes.txt");
  const filesOnly = await fetch(url, { method: "POST", headers: { "x-user": "oracle-user-3" }, body: form }).then(async r => ({ status: r.status, body: await r.json().catch(() => null) }));
  check("6. a send with a file and no message is accepted, and the turn names the file",
    filesOnly.status === 200 && filesOnly.body && filesOnly.body.files === 1 && filesOnly.body.message === "(Sent 1 file with no message: q3-notes.txt.)",
    filesOnly.status + " " + JSON.stringify(filesOnly.body));
  const empty = await sendJson("oracle-user-4", "   ");
  check("6. a send with neither is 400, nothing sent", empty.status === 400 && /Type a question or attach a file/.test(empty.body.error), empty.status + " " + JSON.stringify(empty.body));
  srv.close();
  check("6. the limiter is ORACLE_CHAT_PER_MINUTE = 10 a minute, keyed by account",
    /^var ORACLE_CHAT_PER_MINUTE = 10;$/m.test(SRC) && /keyGenerator: function \(req\) \{ return "oracle-chat:" \+ \(req\.user && req\.user\.id\); \}/.test(SRC));

  // The persona's count is the roster's.
  const roster = n => { const o = {}; for (let i = 0; i < n; i++) o["agent" + i] = "x"; return o; };
  const promptWith = r => { const c = { AGENT_SYSTEM_PROMPTS: r }; vm.createContext(c); vm.runInContext(definitionOf("ORACLE_SYSTEM_PROMPT") + "\n" + definitionOf("oracleSystemPrompt") + "\nthis.p = oracleSystemPrompt();", c); return c.p; };
  const realRoster = (function () { const c = {}; vm.createContext(c); vm.runInContext(definitionOf("AGENT_SYSTEM_PROMPTS").replace(/^const /, "var "), c); return Object.keys(c.AGENT_SYSTEM_PROMPTS).length; })();
  const p18 = promptWith(roster(18)), p19 = promptWith(roster(19));
  check("6. the persona states the roster's own count: \"the 18 specialist agents\" for 18, \"the 19 specialist agents\" for 19",
    p18.indexOf("the 18 specialist agents") !== -1 && p19.indexOf("the 19 specialist agents") !== -1 && p19.indexOf("the 18 specialist agents") === -1);
  check("6. the real roster has 18 agents, and the persona says so with no \"twelve-plus\" and no unfilled slot",
    realRoster === 18 && promptWith(roster(realRoster)).indexOf("{{AGENT_COUNT}}") === -1 && SRC.indexOf("twelve-plus") === -1, realRoster);
  check("6. the oracle route builds its prompt from oracleSystemPrompt()", /buildAgentSystemPrompt\(oracleSystemPrompt\(\), /.test(SRC) &&
    !/buildAgentSystemPrompt\(ORACLE_SYSTEM_PROMPT,/.test(SRC));
}

/* ═════ 9. CORS ══════════════════════════════════════════════════════════ */
function cors() {
  console.log("\n══ 9. no localhost origin in production ══");
  const c = {};
  vm.createContext(c);
  vm.runInContext(definitionOf("isProductionEnv") + "\n" + definitionOf("corsAllowedOrigins") + "\nthis.f = corsAllowedOrigins;", c);
  const has = env => c.f(env).indexOf("http://localhost:50157") !== -1;
  const prods = [{ NODE_ENV: "production" }, { RAILWAY_ENVIRONMENT: "production" }, { RAILWAY_ENVIRONMENT_NAME: "production" }, { RAILWAY_PROJECT_ID: "p1" }];
  check("9. under every production signal (NODE_ENV=production, RAILWAY_ENVIRONMENT, RAILWAY_ENVIRONMENT_NAME, RAILWAY_PROJECT_ID) localhost is not allowed",
    prods.every(e => !has(e) && JSON.stringify(c.f(e)) === JSON.stringify(["https://bizforceai.net", "https://www.bizforceai.net"])), prods.map(e => has(e)).join(","));
  check("9. in a local run (no env, NODE_ENV=development) localhost:50157 is still allowed", has({}) && has({ NODE_ENV: "development" }));
  check("9. the CORS middleware's list is corsAllowedOrigins(process.env), and production is isProductionEnv, the test stripeWebhookSecrets uses",
    /^const allowedOrigins = corsAllowedOrigins\(process\.env\);$/m.test(SRC) && (uncommented(SRC).match(/localhost:50157/g) || []).length === 1 &&
    /isProductionEnv\(/.test(definitionOf("stripeWebhookSecrets") || ""));
}

(async function main() {
  try {
    await profilePrivacy();
    await donations();
    rdAgent();
    await platformCeiling();
    await oracle();
    cors();
  } catch (e) {
    failures++;
    console.log("    FAIL  the check threw: " + (e && e.stack || e));
  }
  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})();
