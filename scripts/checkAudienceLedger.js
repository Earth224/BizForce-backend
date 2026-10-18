"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkAudienceLedger — the Community agent's Audience Ledger counts each
   brand's audience from the caller's own sign-up rows, in code, never shows a
   person, never fills a failed read with 0, and never calls a model;
   Termaximus's Latest Audience Ledger section is counts only and fails loud.

   POST /api/agents/community/audience, requireActiveSubscription and
   buildOracleAgentRecords are lifted from server.js with everything they call,
   and run in a vm against an in-memory Supabase (failures injected per table)
   with every model entry point stubbed to record a call. TEST ROWS ARE
   ISOLATED BY CONSTRUCTION: no database, no network, no model and no email is
   reached, so nobody's live data is read and nothing is written anywhere. The
   owner account's id is used only inside the in-memory tables, as the account
   lib/ownerAccount.js names; the other two accounts are made up.

   THE NULL-OWNER RULE. Recon (Oct 17 2026) found every capture path writing a
   non-null owner and production holding no NULL-owner lead_captures or
   contacts row, so the ledger is owner-scoped for EVERY account, the owner
   included: NULL-owner rows are seeded here and must never be counted.

   WHAT THIS PROVES
     A. Ownership: every lead_captures and contacts read filters on the
        caller's owner_id and nothing else; consent_events are asked for only
        the caller's contact ids; sms_subscribers on the caller's user_id;
        enrollments only for the caller's sequences. Another account's rows
        appear nowhere.
     B. NULL-owner rows: no read asks for them, the owner's figures leave them
        out, and a non-owner never sees them.
     C. Exact counts on a known fixture, per brand: contacts (the account's own
        registration row counted apart), captures with email and SMS consent,
        contacts with an email but no recorded email consent, enrollments by
        status, SMS subscribers by consent status.
     D. New captures by month: every month of the window present, a month with
        none is 0, and a capture older than the window is not in any month.
     E. A failed read (error or throw) of any table is null with its reason in
        exactly the figures it feeds, never 0, and the rest still count.
     F. Counts only: no email, name, phone or row id anywhere in the response,
        nor in the Termaximus section; a free-text brand is "other".
     G. window_days 6, 731, "30" and true are each a 400 naming the field,
        with nothing read; absent is 365; 7 and 730 are accepted. An unknown
        brand is a 400 naming the valid ones; a known one narrows the list.
     H. No rows at all: a 200 with a note naming where sign-ups come from.
     I. No model call on any path, none reachable, model_call_made: false.
     J. Without an active subscription: a 402, and nothing is read.
     K. Termaximus: the latest run's per-brand counts, the caller's only;
        "could not be read just now" for a failed read, never a count.

   MUTATE=<name> edits server.js IN MEMORY (nothing on disk is touched).
   MUTATE=all runs each in its own process; an unmatched search text is an
   ERROR, never a catch (scripts/_shared.js).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), crypto = require("crypto"), net = require("net"), dns = require("dns");
const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
const s = MUT;
const { OWNER_ACCOUNT_ID } = require("../lib/ownerAccount");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkAudienceLedger: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkAudienceLedger: no network"); };

const SERVER = "server.js";
const MUTATIONS = {
  // the lead_captures read loses its owner filter
  "drop-owner-filter": [[SERVER, "    return supabase.from(\"lead_captures\").select(\"id, brand, email_consent, sms_consent, created_at\").eq(\"owner_id\", userId);",
    "    return supabase.from(\"lead_captures\").select(\"id, brand, email_consent, sms_consent, created_at\");"]],
  // the contacts read takes NULL-owner rows too, for whoever asks
  "null-owner-for-anyone": [[SERVER, "    return supabase.from(\"contacts\").select(\"id, brand, email, source\").eq(\"owner_id\", userId);",
    "    return supabase.from(\"contacts\").select(\"id, brand, email, source\").or(\"owner_id.eq.\" + userId + \",owner_id.is.null\");"]],
  // each brand carries its contacts' emails
  "email-in-output": [[SERVER, "      row.contacts = mine.length;\n", "      row.contacts = mine.length;\n      row.contact_emails = mine.map(function (c) { return c.email; }).filter(Boolean);\n"]],
  // a failed read is taken as an empty table, so its figures read 0
  "failed-read-as-zero": [[SERVER, "    return { rows: null, reason: table + \" could not be read just now\" };", "    return { rows: [], reason: null };"]],
  // the route loses its subscription gate
  "ungate": [[SERVER, "app.post(\"/api/agents/community/audience\", requireAuth, requireActiveSubscription, aiLimiter,",
    "app.post(\"/api/agents/community/audience\", requireAuth, aiLimiter,"]]
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
  "Buffer", "URL", "setTimeout", "setImmediate", "fetch", "crypto", "OWNER_ACCOUNT_ID"].concat(MODEL_ENTRY));
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
const PATH = "/api/agents/community/audience";
const SIG = 'app.post("' + PATH + '",';
const routeStart = SRC.indexOf(SIG);
if (routeStart < 0) { console.log("    FAIL  POST " + PATH + " not found"); process.exit(1); }
const ROUTE = SRC.slice(routeStart, s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", routeStart))) + 3);
const LIFT = closure(ROUTE + "\n\nthis.__api = { buildOracleAgentRecords: buildOracleAgentRecords, requireActiveSubscription: requireActiveSubscription, " +
  "audienceMonths: audienceMonths };");

/* ── the fake database ────────────────────────────────────────────────────── */
function fakeDb(seed, fail) {
  const tables = {};
  Object.keys(seed).forEach(t => { tables[t] = seed[t].map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  function test(op, v, val, extra) {
    if (op === "eq") return v === val;
    if (op === "neq") return v !== val;
    if (op === "in") return val.indexOf(v) !== -1;
    if (op === "is") return val === null ? v == null : v === val;
    if (op === "not") return extra === null && val === "is" ? v != null : true;
    if (op === "gte") return v != null && String(v) >= String(val);
    if (op === "lte") return v != null && String(v) <= String(val);
    return true;
  }
  function keep(q, row) {
    return q.filters.every(([op, col, val, extra]) => {
      if (op === "or") {
        return String(col).split(",").some(part => {
          const [c, o, ...rest] = part.split("."); const raw = rest.join(".");
          return o === "is" ? test("is", row[c], raw === "null" ? null : raw) : test(o, row[c], raw);
        });
      }
      return test(op, row[col], val, extra);
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
    const order = q.mods.find(m => m[0] === "order");
    if (order) hits = hits.slice().sort((a, b) => (a[order[1]] < b[order[1]] ? -1 : a[order[1]] > b[order[1]] ? 1 : 0) * (order[2] && order[2].ascending === false ? -1 : 1));
    const range = q.mods.find(m => m[0] === "range"); if (range) hits = hits.slice(range[1], range[2] + 1);
    const limit = q.mods.find(m => m[0] === "limit"); if (limit) hits = hits.slice(0, limit[1]);
    const copies = hits.map(r => JSON.parse(JSON.stringify(r)));
    if (q.single) {
      if (copies.length > 1) return Promise.resolve({ data: null, error: { message: "multiple rows" } });
      if (!copies.length && q.single === "single") return Promise.resolve({ data: null, error: { code: "PGRST116", message: "no rows" } });
      return Promise.resolve({ data: copies[0] || null, error: null });
    }
    return Promise.resolve({ data: copies, error: null });
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
      or(expr) { q.filters.push(["or", expr]); return b; },
      single() { q.single = "single"; return answer(q); },
      maybeSingle() { q.single = "maybe"; return answer(q); },
      then(res, rej) { return answer(q).then(res, rej); }
    };
    ["eq", "neq", "in", "is", "gte", "lte", "gt", "lt"].forEach(op => { b[op] = function (col, val) { q.filters.push([op, col, val]); return b; }; });
    ["order", "limit", "range"].forEach(op => { b[op] = function () { q.mods.push([op].concat([].slice.call(arguments))); return b; }; });
    return b;
  }
  return { tables, log, client: { from, rpc: () => Promise.resolve({ data: null, error: { message: "no rpc" } }) } };
}

/* ── fixtures ─────────────────────────────────────────────────────────────── */
const OWNER = OWNER_ACCOUNT_ID;
const OTHER = "bbbbbbbb-0000-4000-8000-0000000000b2";
const EMPTY = "cccccccc-0000-4000-8000-0000000000c3";
const NOW = Date.now();
const day = (n) => new Date(NOW - n * 86400000).toISOString();
let seq = 0;
const uid = (p) => p + "-0000-4000-8000-" + String(++seq).padStart(12, "0");
const PII = { emails: [], names: [], phones: [], ids: [] };
function person(i) {
  const e = "person" + i + "@audience.test", n = "Fixture Person " + i, p = "1555555" + String(1000 + i);
  PII.emails.push(e); PII.names.push(n); PII.phones.push(p);
  return { email: e, name: n, phone: p };
}
function capture(owner, brand, emailConsent, smsConsent, ago, i) {
  const id = uid("aaaa0001"); PII.ids.push(id);
  const who = person(i);
  return { id, owner_id: owner, brand, email: who.email, phone: who.phone, name: who.name, email_consent: emailConsent, sms_consent: smsConsent,
    source: "direct", status: "new", consent_ip: "203.0.113." + i, consent_timestamp: day(ago), created_at: day(ago) };
}
function contact(id, owner, brand, i, extra) {
  PII.ids.push(id);
  const who = person(i);
  return Object.assign({ id, owner_id: owner, brand, email: who.email, phone: who.phone, name: who.name, source: "direct", created_at: day(30) }, extra);
}
const C = { revoked: uid("cccc0001"), confirmed: uid("cccc0001"), phoneOnly: uid("cccc0001"), sword: uid("cccc0001"), freeText: uid("cccc0001"),
  own: uid("cccc0001"), null1: uid("cccc0001"), null2: uid("cccc0001"), other: uid("cccc0001") };
const SEQ = { owner: uid("dddd0001"), other: uid("dddd0001") };
const FREE_TEXT_BRAND = "visitor-typed@brand.test";
function event(contactId, action, ago) { const id = uid("eeee0001"); PII.ids.push(id); return { id, contact_id: contactId, channel: "email", action, occurred_at: day(ago), created_at: day(ago) }; }
function sub(user, status, i) { const id = uid("ffff0001"); PII.ids.push(id); const who = person(i); return { id, user_id: user, phone_number: who.phone, customer_name: who.name, consent_status: status, created_at: day(20) }; }
function enr(sequence, contactId, status) { const id = uid("abab0001"); PII.ids.push(id); return { id, sequence_id: sequence, contact_id: contactId, status, created_at: day(5) }; }
PII.ids.push(SEQ.owner, SEQ.other);

function world() {
  return {
    lead_captures: [
      capture(OWNER, "mrearthrose", true, false, 10, 1),
      capture(OWNER, "mrearthrose", true, true, 40, 2),
      capture(OWNER, "mrearthrose", false, true, 400, 3),   // older than the 365-day window
      capture(OWNER, "swordvitality", true, false, 70, 4),
      capture(OTHER, "mrearthrose", true, true, 3, 5),
      capture(OTHER, "mrearthrose", false, false, 4, 6),
      capture(null, "bizforce", true, true, 2, 7)            // a NULL-owner row
    ],
    contacts: [
      contact(C.revoked, OWNER, "mrearthrose", 11),
      contact(C.confirmed, OWNER, "mrearthrose", 12),
      contact(C.phoneOnly, OWNER, "mrearthrose", 13, { email: null }),
      contact(C.sword, OWNER, "swordvitality", 14),
      contact(C.freeText, OWNER, FREE_TEXT_BRAND, 15),
      contact(C.own, OWNER, "bizforce", 16, { source: "registration" }),
      contact(C.null1, null, "bizforce", 17),
      contact(C.null2, null, "mrearthrose", 18),
      contact(C.other, OTHER, "mrearthrose", 19)
    ],
    consent_events: [
      event(C.revoked, "granted", 20), event(C.revoked, "revoked", 2),
      event(C.confirmed, "granted", 20), event(C.confirmed, "confirmed", 19),
      event(C.null1, "granted", 5), event(C.other, "granted", 5)
    ],
    sms_subscribers: [sub(OWNER, "opted_in", 21), sub(OWNER, "opted_in", 22), sub(OWNER, "opted_out", 23), sub(OTHER, "opted_in", 24)],
    email_sequences: [{ id: SEQ.owner, owner_id: OWNER, name: "Welcome", status: "active" }, { id: SEQ.other, owner_id: OTHER, name: "Other", status: "active" }],
    email_sequence_enrollments: [enr(SEQ.owner, C.revoked, "active"), enr(SEQ.owner, C.confirmed, "completed"), enr(SEQ.owner, C.sword, "stopped"),
      enr(SEQ.other, C.other, "active")],
    ai_tasks: []
  };
}

/* ── the harness ──────────────────────────────────────────────────────────── */
function context(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed, o.fail);
  const modelCalls = [];
  const logs = [];
  const handlers = {};
  const record = (name) => function () { modelCalls.push(name); throw new Error("checkAudienceLedger: " + name + " must not be called"); };
  const rq = require("module").createRequire(path.join(REPO, "server.js"));
  const ctx = {
    supabase: db.client, require: rq, module: {}, Date, Buffer, URL, setImmediate, crypto, OWNER_ACCOUNT_ID,
    setTimeout: () => 0, fetch: record("fetch"),
    process: { env: Object.assign({ ENABLE_EMAIL_SEQUENCES: "false" }, o.env || {}) },
    console: { log: (...a) => logs.push(a.join(" ")), error: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")) },
    getUserPlan: async () => (o.plan || { active: true, plan: "pro", subscription: { status: "active" }, config: {}, exempt: false, access_reason: "subscribed" }),
    app: { post(p) { handlers[p] = [].slice.call(arguments, 1); }, get() {}, use() {} }
  };
  MODEL_ENTRY.forEach(n => { ctx[n] = record(n); });
  ctx.requireAuth = function requireAuth(req, res, next) { next(); };
  ctx.aiLimiter = function aiLimiter(req, res, next) { next(); };
  vm.createContext(ctx);
  vm.runInContext(LIFT.code, ctx);
  return { ctx, db, modelCalls, logs, handlers };
}

// One request down the route's real middleware chain, as registered.
async function post(body, opts) {
  const o = opts || {};
  const h = context(o.seed || world(), o);
  const chain = h.handlers[PATH] || [];
  const req = { user: { id: o.user || OWNER, role: "user" }, body, method: "POST", route: { path: PATH }, headers: {} };
  const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
  let error = null;
  for (let i = 0; i < chain.length; i++) {
    let advanced = false;
    await chain[i](req, res, (e) => { if (e) error = e; else advanced = true; });
    if (error || !advanced) break;
  }
  return { status: error ? 500 : res.statusCode, body: res.body, error, h, chain };
}
const brandsOf = (r) => { const by = {}; ((r.body && r.body.measured && r.body.measured.brands) || []).forEach(b => { by[b.brand] = b; }); return by; };
const reads = (r, table) => r.h.db.log.filter(q => q.table === table && q.op === "select");
const ownerOnly = (q, col, who) => q.filters.some(f => f[0] === "eq" && f[1] === col && f[2] === who) &&
  !q.filters.some(f => f[0] === "or" || (f[0] === "is" && f[1] === col));
function piiIn(text) {
  return [].concat(PII.emails, PII.names, PII.phones, PII.ids, [FREE_TEXT_BRAND, "203.0.113."]).filter(x => text.indexOf(x) !== -1);
}
function withoutRunId(body) { const c = JSON.parse(JSON.stringify(body || {})); delete c.task_id; return c; }

(async function main() {
  check("the route, requireActiveSubscription and buildOracleAgentRecords were lifted",
    ["requireActiveSubscription", "buildOracleAgentRecords", "loadAudience", "measureAudience", "audienceRead", "startToolRun", "toolProvenance", "CAPTURE_BRANDS"]
      .every(n => LIFT.names.indexOf(n) !== -1), LIFT.names.join(","));

  /* ── A, B, C. the owner, on the fixture ─────────────────────────────── */
  console.log("\n══ A, B, C. ownership, NULL-owner rows and exact counts ══");
  const r = await post({});
  const m = (r.body && r.body.measured) || {};
  const by = brandsOf(r);
  check("200 with a measured block", r.status === 200 && r.body && r.body.success === true, r.status + " " + (r.error && r.error.message));
  check("A. every lead_captures read filters on the caller's owner_id, and only that", reads(r, "lead_captures").length > 0 &&
    reads(r, "lead_captures").every(q => ownerOnly(q, "owner_id", OWNER)), JSON.stringify(reads(r, "lead_captures").map(q => q.filters)));
  check("A. every contacts read filters on the caller's owner_id, and only that", reads(r, "contacts").length > 0 &&
    reads(r, "contacts").every(q => ownerOnly(q, "owner_id", OWNER)), JSON.stringify(reads(r, "contacts").map(q => q.filters)));
  const askedContacts = [].concat(...reads(r, "consent_events").map(q => (q.filters.find(f => f[0] === "in" && f[1] === "contact_id") || [0, 0, ["(none)"]])[2]));
  const ownerContactIds = world().contacts.filter(c => c.owner_id === OWNER).map(c => c.id);
  check("A. consent_events are asked for the caller's own contact ids only", askedContacts.length === ownerContactIds.length &&
    askedContacts.every(id => ownerContactIds.indexOf(id) !== -1), JSON.stringify(askedContacts));
  check("A. sms_subscribers on the caller's user_id; email_sequences on the caller's owner_id",
    reads(r, "sms_subscribers").every(q => ownerOnly(q, "user_id", OWNER)) && reads(r, "email_sequences").every(q => ownerOnly(q, "owner_id", OWNER)) &&
    reads(r, "sms_subscribers").length > 0 && reads(r, "email_sequences").length > 0);
  const askedSeq = [].concat(...reads(r, "email_sequence_enrollments").map(q => (q.filters.find(f => f[0] === "in" && f[1] === "sequence_id") || [0, 0, ["(none)"]])[2]));
  check("A. enrollments are asked for the caller's own sequences only", JSON.stringify(askedSeq) === JSON.stringify([SEQ.owner]), JSON.stringify(askedSeq));
  check("A. nothing was written but the tool run's own ai_tasks row", r.h.db.log.filter(q => q.op !== "select").every(q => q.table === "ai_tasks") &&
    r.h.db.log.some(q => q.table === "ai_tasks" && q.op === "insert"));
  check("B. no read asks for NULL-owner rows (no owner_id IS NULL, no OR)", r.h.db.log.every(q => !q.filters.some(f => f[0] === "or" || (f[0] === "is" && /owner_id|user_id/.test(f[1])))));
  check("B. the owner's brands are mrearthrose, other and swordvitality: the NULL-owner bizforce rows are not counted, and the registration row makes no brand",
    JSON.stringify(Object.keys(by)) === JSON.stringify(["mrearthrose", "other", "swordvitality"]), JSON.stringify(Object.keys(by)));
  const mr = by.mrearthrose || {}, sw = by.swordvitality || {}, ot = by.other || {};
  check("C. mrearthrose: 3 contacts (the NULL-owner one left out), 3 captures, 2 with email consent, 2 with SMS consent",
    mr.contacts === 3 && mr.captures === 3 && mr.captures_with_email_consent === 2 && mr.captures_with_sms_consent === 2, JSON.stringify(mr).slice(0, 300));
  check("C. mrearthrose: 1 contact with an email but no recorded email consent (latest revoked); the confirmed one and the phone-only one are not counted",
    mr.contacts_with_email_without_recorded_email_consent === 1, mr.contacts_with_email_without_recorded_email_consent);
  check("C. mrearthrose enrollments: active 1, completed 1, stopped 0", JSON.stringify(mr.email_enrollments_by_status) === JSON.stringify({ active: 1, completed: 1, stopped: 0 }),
    JSON.stringify(mr.email_enrollments_by_status));
  check("C. swordvitality: 1 contact, 1 capture (1 email, 0 SMS consent), 1 without recorded consent, enrollments stopped 1",
    sw.contacts === 1 && sw.captures === 1 && sw.captures_with_email_consent === 1 && sw.captures_with_sms_consent === 0 &&
    sw.contacts_with_email_without_recorded_email_consent === 1 && JSON.stringify(sw.email_enrollments_by_status) === JSON.stringify({ active: 0, completed: 0, stopped: 1 }),
    JSON.stringify(sw).slice(0, 300));
  check("C. the free-text brand is counted under \"other\": 1 contact, 0 captures (a real 0), 1 without recorded consent",
    ot.contacts === 1 && ot.captures === 0 && ot.contacts_with_email_without_recorded_email_consent === 1, JSON.stringify(ot).slice(0, 300));
  check("C. SMS subscribers: 3 for the account, opted_in 2 and opted_out 1, and the scope says sms_subscribers records no brand",
    m.sms_subscribers === 3 && JSON.stringify(m.sms_subscribers_by_consent_status) === JSON.stringify({ opted_in: 2, opted_out: 1 }) &&
    /records no brand/.test(m.sms_subscribers_scope || ""), JSON.stringify([m.sms_subscribers, m.sms_subscribers_by_consent_status]));
  check("C. enrollments across brands: active 1, completed 1, stopped 1 (the other account's left out)",
    JSON.stringify(m.email_enrollments_by_status_all_brands) === JSON.stringify({ active: 1, completed: 1, stopped: 1 }), JSON.stringify(m.email_enrollments_by_status_all_brands));
  check("C. the account's own registration row is counted apart: 1", m.own_account_contact_rows_not_counted === 1, m.own_account_contact_rows_not_counted);
  check("C. window_days defaults to 365", m.window_days === 365, m.window_days);

  /* ── D. months ──────────────────────────────────────────────────────── */
  console.log("\n══ D. new captures by calendar month ══");
  const expectMonths = r.h.ctx.__api.audienceMonths(NOW - 365 * 86400000, NOW);
  const bucket = (ago) => day(ago).slice(0, 7);
  const months = mr.new_captures_by_month || [];
  check("D. every month of the window is listed, oldest first (" + expectMonths.length + ")", JSON.stringify(months.map(x => x.month)) === JSON.stringify(expectMonths) &&
    expectMonths.length >= 12, months.map(x => x.month).join(","));
  const expectCount = (k) => [10, 40].filter(a => bucket(a) === k).length;
  check("D. mrearthrose: each month holds exactly the captures made in it; the 400-day-old capture is in none",
    months.every(x => x.captures === expectCount(x.month)) && months.reduce((n, x) => n + x.captures, 0) === 2, JSON.stringify(months));
  check("D. a month with no captures shows 0, a number", months.some(x => x.captures === 0 && typeof x.captures === "number"));
  check("D. \"other\" has every month at 0, read and real", (ot.new_captures_by_month || []).length === expectMonths.length && ot.new_captures_by_month.every(x => x.captures === 0));
  const r7 = await post({ window_days: 7 });
  const m7 = (brandsOf(r7).mrearthrose || {}).new_captures_by_month || [];
  check("D. a 7-day window: the 10-day-old capture is outside it, so every month is 0", m7.length >= 1 && m7.every(x => x.captures === 0), JSON.stringify(m7));

  /* ── E. failed reads ────────────────────────────────────────────────── */
  console.log("\n══ E. a failed read is null with its reason, never 0 ══");
  for (const how of ["error", "throw"]) {
    const fail = (t) => (q) => q.table === t && q.op === "select" ? (how === "throw" ? "throw" : { message: "permission denied" }) : null;
    const fc = await post({}, { fail: fail("lead_captures") });
    const bc = brandsOf(fc);
    check("E. lead_captures failing (" + how + "): 200, every capture figure null with its reason, contacts still counted",
      fc.status === 200 && Object.values(bc).length > 0 && Object.values(bc).every(b => b.captures === null && /lead_captures could not be read/.test(b.captures_reason || "") &&
        b.new_captures_by_month === null && b.captures_with_email_consent === null && typeof b.new_captures_by_month_reason === "string") &&
        bc.mrearthrose && bc.mrearthrose.contacts === 3, fc.status + " " + JSON.stringify(bc.mrearthrose || {}).slice(0, 300));
    check("E. … and the note says so", /Not measured, shown as null rather than 0: lead_captures could not be read/.test((fc.body && fc.body.measured.note) || ""));
    const fs2 = await post({}, { fail: fail("sms_subscribers") });
    check("E. sms_subscribers failing (" + how + "): null with its reason, never 0", fs2.status === 200 && fs2.body.measured.sms_subscribers === null &&
      /sms_subscribers could not be read/.test(fs2.body.measured.sms_subscribers_reason || "") && fs2.body.measured.sms_subscribers_by_consent_status === null,
      JSON.stringify(fs2.body && fs2.body.measured).slice(0, 300));
    const fe = await post({}, { fail: fail("consent_events") });
    check("E. consent_events failing (" + how + "): the no-consent count null with its reason, contacts still 3",
      fe.status === 200 && brandsOf(fe).mrearthrose.contacts_with_email_without_recorded_email_consent === null &&
      /consent_events could not be read/.test(brandsOf(fe).mrearthrose.contacts_with_email_without_recorded_email_consent_reason || "") && brandsOf(fe).mrearthrose.contacts === 3);
    const fk = await post({}, { fail: fail("contacts") });
    const bk = brandsOf(fk);
    check("E. contacts failing (" + how + "): contacts and enrollments-by-brand null with reasons; captures still 3 for mrearthrose",
      fk.status === 200 && bk.mrearthrose && bk.mrearthrose.contacts === null && /contacts could not be read/.test(bk.mrearthrose.contacts_reason || "") &&
      bk.mrearthrose.email_enrollments_by_status === null && bk.mrearthrose.captures === 3 && fk.body.measured.own_account_contact_rows_not_counted === null,
      JSON.stringify(bk.mrearthrose || {}).slice(0, 300));
    const fq = await post({}, { fail: fail("email_sequence_enrollments") });
    check("E. enrollments failing (" + how + "): null with the reason, across brands and per brand", fq.status === 200 &&
      fq.body.measured.email_enrollments_by_status_all_brands === null && brandsOf(fq).mrearthrose.email_enrollments_by_status === null &&
      /could not be read/.test(brandsOf(fq).mrearthrose.email_enrollments_by_status_reason || ""));
  }
  const unreasoned = [];
  const walkSeeds = [r, await post({}, { fail: q => q.table === "contacts" ? { message: "x" } : null }), await post({}, { fail: q => q.table === "lead_captures" ? { message: "x" } : null })];
  walkSeeds.forEach((x, n) => (function walk(v, where) {
    if (Array.isArray(v)) return v.forEach((y, i) => walk(y, where + "[" + i + "]"));
    if (!v || typeof v !== "object") return;
    Object.keys(v).forEach(k => {
      if (v[k] === null && !(typeof v[k + "_reason"] === "string" && v[k + "_reason"].trim())) unreasoned.push(n + where + "." + k);
      walk(v[k], where + "." + k);
    });
  })(x.body && x.body.measured, "measured"));
  check("E. every null in the measured block has a <key>_reason beside it", unreasoned.length === 0, unreasoned.join(", "));

  /* ── F. counts only ─────────────────────────────────────────────────── */
  console.log("\n══ F. counts only ══");
  const leaked = piiIn(JSON.stringify(withoutRunId(r.body)));
  check("F. no fixture email, name, phone, IP or row id, and not the free-text brand, anywhere in the response (" +
    (PII.emails.length + PII.names.length + PII.phones.length + PII.ids.length) + " values)", leaked.length === 0, leaked.join(", "));
  check("F. the only id in the response is the run's own task_id", typeof r.body.task_id === "string" && piiIn(r.body.task_id).length === 0);
  check("F. no field name carries a person: no email, name, phone or id key", (function () {
    const keys = []; (function walk(v) { if (Array.isArray(v)) return v.forEach(walk); if (v && typeof v === "object") Object.keys(v).forEach(k => { keys.push(k); walk(v[k]); }); })(r.body.measured);
    return !keys.some(k => /^(email|emails|name|phone|id|contact_id|contact_emails)$/.test(k));
  })());

  /* ── B. a non-owner ─────────────────────────────────────────────────── */
  console.log("\n══ B. another account ══");
  const ro = await post({}, { user: OTHER });
  const bo = brandsOf(ro);
  check("B. a non-owner sees only its own rows: mrearthrose with 2 captures, 1 contact, enrollments active 1, 1 SMS subscriber",
    ro.status === 200 && JSON.stringify(Object.keys(bo)) === JSON.stringify(["mrearthrose"]) && bo.mrearthrose.captures === 2 && bo.mrearthrose.contacts === 1 &&
    JSON.stringify(bo.mrearthrose.email_enrollments_by_status) === JSON.stringify({ active: 1, completed: 0, stopped: 0 }) && ro.body.measured.sms_subscribers === 1,
    JSON.stringify(ro.body && ro.body.measured).slice(0, 300));
  check("B. a non-owner never sees NULL-owner rows: no bizforce brand, and every read is filtered on its own id",
    !bo.bizforce && reads(ro, "contacts").every(q => ownerOnly(q, "owner_id", OTHER)) && reads(ro, "lead_captures").every(q => ownerOnly(q, "owner_id", OTHER)));
  check("B. nothing of the owner's reaches a non-owner", piiIn(JSON.stringify(withoutRunId(ro.body))).length === 0);

  /* ── G. validation ──────────────────────────────────────────────────── */
  console.log("\n══ G. window_days and brand are refused, never coerced ══");
  for (const bad of [6, 731, "30", true, 0, 7.5]) {
    const rb = await post({ window_days: bad });
    check("G. window_days " + JSON.stringify(bad) + " is a 400 naming the field, and nothing is read or recorded",
      rb.status === 400 && rb.body && rb.body.field === "window_days" && /window_days/.test(rb.body.error || "") && rb.h.db.log.length === 0, rb.status + " " + JSON.stringify(rb.body));
  }
  for (const good of [7, 730]) {
    const rg = await post({ window_days: good });
    check("G. window_days " + good + " is accepted", rg.status === 200 && rg.body.measured.window_days === good, rg.status);
  }
  const ub = await post({ brand: "nope" });
  check("G. an unknown brand is a 400 naming the field and the valid brands, and no run is recorded",
    ub.status === 400 && ub.body.field === "brand" && JSON.stringify(ub.body.valid_brands) === JSON.stringify(["mrearthrose", "other", "swordvitality"]) &&
    /mrearthrose, other, swordvitality/.test(ub.body.error) && !ub.h.db.log.some(q => q.table === "ai_tasks"), JSON.stringify(ub.body));
  for (const bad of [FREE_TEXT_BRAND, "bizforce", 5, true]) {
    const rb = await post({ brand: bad });
    check("G. brand " + JSON.stringify(bad) + " is a 400 (not a brand this account has rows for)", rb.status === 400 && rb.body.field === "brand", rb.status);
  }
  const kb = await post({ brand: "swordvitality" });
  check("G. a known brand narrows the list to it", kb.status === 200 && kb.body.measured.brands.length === 1 && kb.body.measured.brands[0].brand === "swordvitality" &&
    kb.body.measured.brand_filter === "swordvitality");

  /* ── H. nothing recorded ────────────────────────────────────────────── */
  console.log("\n══ H. no rows at all ══");
  const re = await post({}, { user: EMPTY });
  check("H. an account with no rows: 200, no brands, and a note naming the SMS page", re.status === 200 && re.body.measured.brands.length === 0 &&
    /SMS page/.test(re.body.measured.note || "") && /platform's own account/.test(re.body.measured.note), JSON.stringify(re.body && re.body.measured));
  const ownerless = world();
  ["lead_captures", "sms_subscribers", "email_sequences", "email_sequence_enrollments"].forEach(t => { ownerless[t] = ownerless[t].filter(x => x.owner_id !== OWNER && x.user_id !== OWNER); });
  ownerless.contacts = ownerless.contacts.filter(x => x.owner_id !== OWNER || x.source === "registration");
  const rw = await post({}, { seed: ownerless });
  check("H. the owner with only its registration row: 200, no brands, a note naming /api/capture, /api/contacts/capture and the SMS page",
    rw.status === 200 && rw.body.measured.brands.length === 0 && /\/api\/capture/.test(rw.body.measured.note) && /\/api\/contacts\/capture/.test(rw.body.measured.note) &&
    /SMS page/.test(rw.body.measured.note), JSON.stringify(rw.body && rw.body.measured).slice(0, 300));
  check("H. no screen of zeros: only window_days, brands and the note", JSON.stringify(Object.keys(re.body.measured).sort()) === JSON.stringify(["brands", "note", "window_days"]));
  const re2 = await post({}, { user: EMPTY, fail: q => q.table === "sms_subscribers" ? { message: "x" } : null });
  check("H. with a failed read the account is not called empty: the figure is null with its reason", re2.status === 200 && re2.body.measured.sms_subscribers === null &&
    !/No sign-ups are recorded/.test(re2.body.measured.note || ""), JSON.stringify(re2.body && re2.body.measured).slice(0, 200));

  /* ── I. no model ────────────────────────────────────────────────────── */
  console.log("\n══ I. no model call ══");
  const every = [r, r7, ro, kb, re, rw];
  check("I. no model entry point or network call was made on any path", every.every(x => x.h.modelCalls.length === 0) && NETWORK.length === 0,
    every.map(x => x.h.modelCalls.join("+")).join(" | ") + " " + NETWORK.join(","));
  const lifted = closure(ROUTE);
  const reach = MODEL_ENTRY.filter(n => new RegExp("\\b" + n + "\\b").test(uncommented(lifted.code)));
  check("I. no model entry point is reachable from the route", reach.length === 0, reach.join(","));
  check("I. the provenance says model_call_made: false, from the caller's own records, no unassigned rows",
    r.body.provenance && r.body.provenance.model_call_made === false && r.body.provenance.inferred_by_model.length === 0 &&
    r.body.provenance.unassigned_rows_read === false && r.body.provenance.other_accounts_read === false &&
    /Source: your own sign-up records\. Model called: no\./.test(r.body.provenance.caveat), JSON.stringify(r.body.provenance).slice(0, 300));
  check("I. not_measured names opens, reads or clicks; anyone outside your captures; other platforms; purchases",
    ["Opens, reads or clicks", "Anyone outside your own captures", "Audiences on other platforms", "Purchases"].every(p =>
      r.body.limitations.not_measured.some(x => x.indexOf(p) === 0)), JSON.stringify(r.body.limitations));

  /* ── J. the gate ────────────────────────────────────────────────────── */
  console.log("\n══ J. no free tier ══");
  const rj = await post({}, { plan: { active: false, plan: null, subscription: null, config: null, exempt: false, access_reason: "no_subscription" } });
  check("J. without an active subscription: 402", rj.status === 402, rj.status + " " + JSON.stringify(rj.body).slice(0, 200));
  check("J. and none of the six tables, nor ai_tasks, was touched", rj.h.db.log.filter(q => q.table !== "users").length === 0 ||
    rj.h.db.log.every(q => !/lead_captures|contacts|consent_events|sms_subscribers|email_sequence|ai_tasks/.test(q.table)), rj.h.db.log.map(q => q.table).join(","));
  check("J. the gate in front of the handler is the real requireActiveSubscription", r.chain.some(f => f === r.h.ctx.__api.requireActiveSubscription));

  /* ── K. Termaximus ──────────────────────────────────────────────────── */
  console.log("\n══ K. Termaximus's Latest Audience Ledger section ══");
  const TITLE = "Latest Audience Ledger (counts only)";
  const stored = r.h.db.tables.ai_tasks.find(t => t.task_type === "community/audience" && t.output);
  check("K. the run was stored on ai_tasks with its output", !!stored && stored.user_id === OWNER);
  async function records(seed, who, fail) {
    const h = context(seed, { fail });
    const failed = [];
    const text = await h.ctx.__api.buildOracleAgentRecords(who || OWNER, (what) => failed.push(what));
    const i = text.indexOf(TITLE);
    const rest = i === -1 ? "" : text.slice(i);
    const next = rest.slice(TITLE.length).search(/\n[A-Z][^\n]*?:/);
    return { text, section: next < 0 ? rest : rest.slice(0, TITLE.length + next), failed, log: h.db.log };
  }
  const seeded = world();
  seeded.ai_tasks = [JSON.parse(JSON.stringify(stored)),
    { id: uid("acac0001"), user_id: OTHER, task_type: "community/audience", status: "completed", created_at: day(0),
      output: { measured: { window_days: 30, brands: [{ brand: "mrearthrose", contacts: 999, captures: 999 }] } } }];
  PII.ids.push(stored.id);
  const k1 = await records(seeded);
  check("K. per brand: contacts, captures with email and SMS consent, and the no-consent count",
    /- mrearthrose: 3 contact\(s\); 3 capture\(s\), 2 with email consent, 2 with SMS consent; 1 contact\(s\) with an email but no recorded email consent/.test(k1.section) &&
    /- swordvitality: 1 contact\(s\); 1 capture\(s\), 1 with email consent, 0 with SMS consent/.test(k1.section) && /- other: 1 contact\(s\); 0 capture\(s\)/.test(k1.section) &&
    /: 3 brand\(s\), window 365 days/.test(k1.section), k1.section);
  check("K. the caller's run only: the other account's 999 is not shown, and the read filters on the caller's user_id",
    k1.section.indexOf("999") === -1 && k1.log.filter(q => q.table === "ai_tasks" && q.filters.some(f => f[1] === "task_type" && f[2] === "community/audience"))
      .every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === OWNER)));
  const kLeak = piiIn(k1.section);
  check("K. counts only: no email, name, phone, id or free-text brand in the section", kLeak.length === 0, kLeak.join(", "));
  const k0 = await records(world());
  check("K. no run yet: \"- none\"", /^Latest Audience Ledger \(counts only\):\n- none/.test(k0.section), k0.section);
  for (const how of ["error", "throw"]) {
    const kf = await records(seeded, OWNER, q => q.table === "ai_tasks" && q.filters.some(f => f[1] === "task_type" && f[2] === "community/audience")
      ? (how === "throw" ? "throw" : { message: "permission denied" }) : null);
    check("K. a failed read (" + how + ") says it could not be read, never a count",
      /^Latest Audience Ledger \(counts only\): could not be read just now\./.test(kf.section) && !/contact\(s\)/.test(kf.section) &&
      kf.failed.some(f => /Latest Audience Ledger/.test(f)), kf.section);
  }

  console.log("\n" + (failures ? failures + " FAILED, " + passes + " passed" : "ALL " + passes + " CHECKS PASSED"));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack)); process.exit(1); });
