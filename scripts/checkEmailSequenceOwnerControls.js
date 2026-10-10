"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkEmailSequenceOwnerControls — the owner can see every email sequence and
   stop any of it, whatever their subscription.

   GET /api/email/sequences, GET /api/email/sequences/:id and
   POST /api/email/sequences/:id/status are lifted from server.js and run in a
   vm against an in-memory Supabase that keeps its rows. Each request runs the
   route's WHOLE middleware chain, with stand-ins that behave as the real ones
   would for these accounts: requireAuth sets the user, and
   requireActiveSubscription and requireAdmin refuse the lapsed, non-admin
   account. So a gate added to a route shows up as a refusal, not just as a
   name. Resend is a class that records and sends nothing. No network, no mail.

   WHAT THIS PROVES
     1. The list: the caller's sequences only, newest first, with step count,
        enrollment counts by status, the earliest next_send_at among ACTIVE
        enrollments, and stopped counts by stop_reason.
     2. The sender object holds booleans and the cap, and no value read from
        the environment, set or unset; an unreadable cap is null.
     3. The detail: steps and enrollments with contact name and email; another
        user's sequence, a missing id and a malformed id are the same 404 — on
        the status route too, where nothing changes.
     4. Every allowed transition, and every refused one as a 409 naming the
        current status; a bad status is a 400.
     5. Cancelling stops active enrollments only (cancelled_by_owner,
        next_send_at null); completed and stopped rows, and other sequences, are
        untouched. Pausing changes no enrollment.
     6. A non-admin account whose subscription has lapsed can read, pause and
        cancel. The three routes carry requireAuth and nothing else.
     7. Zero Resend calls, no email_sends row; the sender reads only active
        sequences, so a paused one is not sent.

   MUTATE=<name> edits the lifted source (server.js on disk is never touched).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly once
   is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { spawnSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const ANCHOR_ERROR_EXIT = 3;

const MUTATIONS = {
  // the sender object carries the postal address itself
  "leak-env-value": [["        postal_address_set: String(process.env.MAIL_POSTAL_ADDRESS || \"\").trim() !== \"\",\n",
    "        postal_address_set: String(process.env.MAIL_POSTAL_ADDRESS || \"\").trim(),\n"]],
  // a cancelled sequence can be made active again
  "cancelled-to-active": [["  paused: [\"active\", \"cancelled\"]\n};", "  paused: [\"active\", \"cancelled\"],\n  cancelled: [\"active\"]\n};"]],
  // stopping needs a subscription
  "gate-cancel-on-subscription": [["app.post(\"/api/email/sequences/:id/status\", requireAuth, async function",
    "app.post(\"/api/email/sequences/:id/status\", requireAuth, requireActiveSubscription, async function"]],
  // the detail route reads any sequence by id
  "detail-unscoped": [["    var sequence = await ownEmailSequence(req.user.id, req.params.id,\n      \"id, name, brand, status, steps, created_at, approved_at\");\n",
    "    var sequence = UUID_RE.test(req.params.id) ? (await supabase.from(\"email_sequences\").select(\"id, name, brand, status, steps, created_at, approved_at\").eq(\"id\", req.params.id).maybeSingle()).data : null;\n"]],
  // cancelling also stops completed enrollments
  "stop-completed-on-cancel": [["        .eq(\"sequence_id\", sequence.id)\n        .eq(\"status\", \"active\")\n        .select(\"id\");\n",
    "        .eq(\"sequence_id\", sequence.id)\n        .select(\"id\");\n"]]
};

if (MUTATE === "all") {
  const names = Object.keys(MUTATIONS);
  let survived = 0, errors = 0;
  for (const name of names) {
    const r = spawnSync(process.execPath, [__filename], { env: Object.assign({}, process.env, { MUTATE: name }), encoding: "utf8", timeout: 300000 });
    if (r.status === ANCHOR_ERROR_EXIT) {
      errors++;
      console.log("    ERROR     " + name.padEnd(28) + " " + (r.stdout.trim().split("\n").pop() || r.stderr.trim()));
      continue;
    }
    const fails = (r.stdout.match(/^ {4}FAIL {2}.*$/gm) || []);
    const caught = r.status !== 0 && fails.length > 0;
    if (!caught) survived++;
    console.log((caught ? "    caught    " : "    SURVIVED  ") + name.padEnd(28) + " " + fails.length + " failing check(s)" +
      (fails.length ? "  e.g. " + fails[0].trim().slice(6, 110) : (r.stderr ? "  stderr: " + r.stderr.trim().split("\n")[0] : "")));
  }
  const ok = survived === 0 && errors === 0;
  console.log(ok ? "\nALL CHECKS PASSED — every one of " + names.length + " mutations was caught"
    : "\nCHECKS FAILED: " + survived + " mutation(s) survived, " + errors + " mutation(s) could not be applied");
  process.exit(ok ? 0 : 1);
}

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the source ─────────────────────────────────────────────────────────── */
let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) {
    const hits = SRC.split(from).length - 1;
    if (hits !== 1) { console.log("MUTATION ANCHOR ERROR: expected exactly one match, found " + hits + ": " + JSON.stringify(from.slice(0, 80))); process.exit(ANCHOR_ERROR_EXIT); }
    SRC = SRC.replace(from, () => to);
  }
  console.log("\n!! MUTATION: " + MUTATE);
}

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
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "Resend", "app", "Buffer", "setTimeout",
  "requireAuth", "requireActiveSubscription", "requireAdmin", "aiLimiter", "crypto", "Date", "cron"]);
// Identifiers are followed through code only: a name in a comment is not a dependency.
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
function routeText(method, route) {
  const sig = "app." + method + "(\"" + route + "\",";
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const ROUTES = [["get", "/api/email/sequences"], ["get", "/api/email/sequences/:id"], ["post", "/api/email/sequences/:id/status"]];
const LIFTED = closure(ROUTES.map(([m, r]) => routeText(m, r)).join("\n\n"));

/* ── the fake database ──────────────────────────────────────────────────── */
const TABLES = ["email_sequences", "email_sequence_enrollments", "contacts", "email_sends", "users"];
function fakeDb(seed, fail) {
  const tables = {};
  TABLES.forEach(t => { tables[t] = ((seed || {})[t] || []).map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  function keep(q, row) {
    return q.filters.every(f => {
      if (f[0] === "eq") return row[f[1]] === f[2];
      if (f[0] === "in") return f[2].indexOf(row[f[1]]) !== -1;
      return true;
    });
  }
  function shape(q, row) {
    const copy = JSON.parse(JSON.stringify(row));
    if (q.table === "email_sequence_enrollments" && /contacts\(name, email\)/.test(q.cols || "")) {
      const c = tables.contacts.find(x => x.id === row.contact_id);
      copy.contacts = c ? { name: c.name, email: c.email } : null;
    }
    return copy;
  }
  function answer(q) {
    const injected = fail && fail(q);
    if (injected) return Promise.resolve({ data: null, error: injected });
    const rows = tables[q.table];
    if (!rows) return Promise.resolve({ data: null, error: { message: "unplanned table " + q.table } });
    if (q.op === "insert") {
      rows.push(JSON.parse(JSON.stringify(q.payload)));
      return Promise.resolve({ data: null, error: null });
    }
    if (q.op === "update") {
      const hit = rows.filter(r => keep(q, r));
      hit.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(q.payload))));
      const copies = hit.map(r => shape(q, r));
      return Promise.resolve({ data: q.single ? (copies[0] || null) : (q.cols ? copies : null), error: null });
    }
    let hits = rows.filter(r => keep(q, r));
    const order = q.filters.find(f => f[0] === "order");
    if (order) hits = hits.slice().sort((a, b) => (a[order[1]] < b[order[1]] ? -1 : a[order[1]] > b[order[1]] ? 1 : 0) * (order[2] && order[2].ascending === false ? -1 : 1));
    const range = q.filters.find(f => f[0] === "range");
    if (range) hits = hits.slice(range[1], range[2] + 1);
    const copies = hits.map(r => shape(q, r));
    if (q.single) return Promise.resolve({ data: copies[0] || null, error: null });
    return Promise.resolve({ data: copies, error: null });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, payload: null, filters: [], single: false };
    log.push(q);
    const b = {
      select(cols) { q.cols = cols || "*"; return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; }
    };
    ["eq", "in", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, tables, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const LAPSED = "aaaaaaaa-0000-4000-8000-000000000002";   // role user, subscription past due
const OTHER = "aaaaaaaa-0000-4000-8000-000000000003";
const USERS = {
  [OWNER]: { id: OWNER, role: "admin", subscribed: true },
  [LAPSED]: { id: LAPSED, role: "user", subscribed: false },
  [OTHER]: { id: OTHER, role: "admin", subscribed: true }
};
const sid = (k) => "5e000000-0000-4000-8000-" + String(k).padStart(12, "0");
const STEPS = [
  { step: 1, delay_days: 0, purpose: "welcome", subject: "Welcome", body: "b1", subject_measurement: {} },
  { step: 2, delay_days: 3, purpose: "tips", subject: "Tips", body: "b2", subject_measurement: {} }
];
function seq(k, owner, status, created) {
  return { id: sid(k), owner_id: owner, name: "Seq " + k, brand: k === 1 ? "bizforce" : null, status, steps: STEPS,
    created_at: created, approved_at: created, proposal_id: null, source_task_id: null };
}
let en = 0;
function enr(seqK, contactK, status, extra) {
  en++;
  return Object.assign({ id: "e0000000-0000-4000-8000-" + String(en).padStart(12, "0"), sequence_id: sid(seqK), contact_id: "c" + contactK,
    next_step: 0, next_send_at: null, status, stop_reason: null, last_sent_at: null }, extra || {});
}
function world() {
  en = 0;
  return {
    email_sequences: [
      seq(1, OWNER, "active", "2026-10-01T00:00:00.000Z"),
      seq(2, OWNER, "paused", "2026-10-03T00:00:00.000Z"),
      seq(3, OWNER, "completed", "2026-09-20T00:00:00.000Z"),
      seq(4, OWNER, "cancelled", "2026-09-25T00:00:00.000Z"),
      seq(5, OTHER, "active", "2026-10-05T00:00:00.000Z"),
      seq(6, LAPSED, "active", "2026-10-02T00:00:00.000Z"),
      seq(7, LAPSED, "paused", "2026-10-02T01:00:00.000Z")
    ],
    email_sequence_enrollments: [
      enr(1, 1, "active", { next_send_at: "2026-10-12T09:00:00.000Z" }),
      enr(1, 2, "active", { next_send_at: "2026-10-11T09:00:00.000Z", next_step: 1, last_sent_at: "2026-10-08T09:00:00.000Z" }),
      enr(1, 3, "completed", { next_step: 2, last_sent_at: "2026-10-05T09:00:00.000Z" }),
      enr(1, 4, "stopped", { stop_reason: "suppressed", next_send_at: "2026-10-01T00:00:00.000Z" }),
      enr(1, 5, "stopped", { stop_reason: "no_consent" }),
      enr(1, 6, "stopped", { stop_reason: "no_consent" }),
      enr(2, 1, "active", { next_send_at: "2026-10-20T00:00:00.000Z" }),
      enr(5, 7, "active", { next_send_at: "2026-10-11T00:00:00.000Z" }),
      enr(6, 8, "active", { next_send_at: "2026-10-11T00:00:00.000Z" }),
      enr(6, 9, "completed", { next_step: 2 }),
      enr(7, 8, "active", { next_send_at: "2026-10-15T00:00:00.000Z" })
    ],
    contacts: [1, 2, 3, 4, 5, 6, 7, 8, 9].map(k => ({ id: "c" + k, owner_id: k === 7 ? OTHER : k >= 8 ? LAPSED : OWNER, name: "Person " + k, email: "p" + k + "@example.com" })),
    email_sends: [], users: []
  };
}
const ENV_SET = { ENABLE_EMAIL_SEQUENCES: "true", MAIL_POSTAL_ADDRESS: "SECRET-POSTAL 9 Hidden Lane", RESEND_WEBHOOK_SECRET: "whsec_LEAKME_123",
  EMAIL_MARKETING_DAILY_CAP: "37", RESEND_API_KEY: "re_SHOULD_NOT_APPEAR", JWT_SECRET: "jwt-SHOULD-NOT-APPEAR" };

let RESEND_CALLS = 0;
function build(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed, o.fail);
  const logs = [];
  class Resend { constructor() { RESEND_CALLS++; this.emails = { send: async () => { RESEND_CALLS++; return { data: { id: "x" }, error: null }; } }; } }
  const refusedBy = [];
  const ctx = {
    supabase: db.client, Resend, JSON, Math, Promise, Date,
    nowIso: () => new Date().toISOString(),
    process: { env: Object.assign({}, o.env === undefined ? ENV_SET : o.env) },
    console: { log: m => logs.push(String(m)), error: (...a) => logs.push(a.map(String).join(" ")), warn: m => logs.push(String(m)) },
    requireAuth: function requireAuth(req, res, next) { req.user = { id: req.headers.user, role: USERS[req.headers.user].role }; next(); },
    requireActiveSubscription: function requireActiveSubscription(req, res, next) {
      if (!USERS[req.user.id].subscribed) { refusedBy.push("requireActiveSubscription"); return res.status(402).json({ error: "Subscription required", upgrade_required: true }); }
      next();
    },
    requireAdmin: function requireAdmin(req, res, next) {
      if (req.user.role !== "admin") { refusedBy.push("requireAdmin"); return res.status(403).json({ error: "Admin access required" }); }
      next();
    }
  };
  const routes = {};
  const register = (method) => function (p) { routes[method + " " + p] = [].slice.call(arguments, 1); };
  ctx.app = { get: register("get"), post: register("post") };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);

  async function call(key, user, params, body) {
    const chain = routes[key];
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    const req = { headers: { user }, params: params || {}, query: {}, body: body || {} };
    let i = 0;
    let error = null;
    async function step() {
      const fn = chain[i++];
      if (!fn) return;
      let advanced = false;
      await fn(req, res, (e) => { if (e) { error = e; res.code = 500; return; } advanced = true; });
      if (advanced) await step();
    }
    await step();
    res.error = error;
    return res;
  }
  return {
    db, logs, routes, refusedBy,
    list: (user) => call("get /api/email/sequences", user),
    detail: (user, id) => call("get /api/email/sequences/:id", user, { id }),
    setStatus: (user, id, status) => call("post /api/email/sequences/:id/status", user, { id }, { status }),
    seqRow: (k) => db.tables.email_sequences.find(x => x.id === sid(k)),
    enrOf: (k) => db.tables.email_sequence_enrollments.filter(e => e.sequence_id === sid(k))
  };
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

(async function main() {
  /* ── 1. the list ──────────────────────────────────────────────────────── */
  console.log("\n══ 1. GET /api/email/sequences ══");
  let b = build(world());
  let r = await b.list(OWNER);
  const list = (r.body && r.body.sequences) || [];
  check("200 with the caller's four sequences only, newest first",
    r.code === 200 && same(list.map(x => x.id), [sid(2), sid(1), sid(4), sid(3)]), JSON.stringify(list.map(x => x.id)));
  const s1 = list.find(x => x.id === sid(1)) || {};
  check("each row: id, name, brand, status, step_count, created_at, approved_at, enrollments, next_send_at, stopped_by_reason",
    same(Object.keys(s1), ["id", "name", "brand", "status", "step_count", "created_at", "approved_at", "enrollments", "next_send_at", "stopped_by_reason"]), JSON.stringify(Object.keys(s1)));
  check("step_count 2, status active, brand bizforce", s1.step_count === 2 && s1.status === "active" && s1.brand === "bizforce", JSON.stringify(s1));
  check("enrollment counts by status: active 2, completed 1, stopped 3", same(s1.enrollments, { active: 2, completed: 1, stopped: 3 }), JSON.stringify(s1.enrollments));
  check("next_send_at: the earliest among ACTIVE enrollments (a stopped row's earlier time ignored)", s1.next_send_at === "2026-10-11T09:00:00.000Z", s1.next_send_at);
  check("stopped by reason: no_consent 2, suppressed 1", same(s1.stopped_by_reason, { suppressed: 1, no_consent: 2 }), JSON.stringify(s1.stopped_by_reason));
  const s3 = list.find(x => x.id === sid(3)) || {};
  check("a sequence with no enrollments: zero counts, next_send_at null, no reasons",
    same(s3.enrollments, { active: 0, completed: 0, stopped: 0 }) && s3.next_send_at === null && same(s3.stopped_by_reason, {}), JSON.stringify(s3));
  check("the enrollment read is scoped to the caller's sequence ids",
    b.db.log.filter(q => q.table === "email_sequence_enrollments").every(q => q.filters.some(f => f[0] === "in" && f[1] === "sequence_id" && same(f[2].slice().sort(), [sid(1), sid(2), sid(3), sid(4)]))));

  /* ── 2. the sender object ─────────────────────────────────────────────── */
  console.log("\n══ 2. the sender object ══");
  const sender = r.body && r.body.sender;
  check("sender is exactly { enabled, postal_address_set, webhook_secret_set, daily_cap }",
    sender && same(Object.keys(sender), ["enabled", "postal_address_set", "webhook_secret_set", "daily_cap"]), JSON.stringify(sender));
  check("everything set: true, true, true, cap 37 — booleans and a number",
    sender && sender.enabled === true && sender.postal_address_set === true && sender.webhook_secret_set === true && sender.daily_cap === 37, JSON.stringify(sender));
  const whole = JSON.stringify(r.body);
  const leaked = Object.values(ENV_SET).filter(v => v !== "true" && v !== "37" && whole.indexOf(v) !== -1);
  const fragments = ["SECRET-POSTAL", "Hidden Lane", "whsec_", "LEAKME", "re_SHOULD", "jwt-SHOULD"].filter(f => whole.indexOf(f) !== -1);
  check("no environment value appears anywhere in the response", leaked.length === 0 && fragments.length === 0, JSON.stringify(leaked.concat(fragments)));
  b = build(world(), { env: {} });
  r = await b.list(OWNER);
  check("nothing set: enabled false, postal false, webhook false, cap the default 50",
    same(r.body.sender, { enabled: false, postal_address_set: false, webhook_secret_set: false, daily_cap: 50 }), JSON.stringify(r.body.sender));
  b = build(world(), { env: { ENABLE_EMAIL_SEQUENCES: "TRUE", MAIL_POSTAL_ADDRESS: "   ", RESEND_WEBHOOK_SECRET: "", EMAIL_MARKETING_DAILY_CAP: "lots" } });
  r = await b.list(OWNER);
  check("\"TRUE\", a blank address, an empty secret, an unreadable cap: false, false, false, null",
    same(r.body.sender, { enabled: false, postal_address_set: false, webhook_secret_set: false, daily_cap: null }), JSON.stringify(r.body.sender));
  check("…and the unreadable cap's text is not echoed", JSON.stringify(r.body).indexOf("lots") === -1);

  /* ── 3. the detail, and identical 404s ────────────────────────────────── */
  console.log("\n══ 3. GET /api/email/sequences/:id and the 404 rule ══");
  b = build(world());
  r = await b.detail(OWNER, sid(1));
  const d = r.body && r.body.sequence;
  check("200 with the sequence", r.code === 200 && d && d.id === sid(1) && d.name === "Seq 1" && d.status === "active", JSON.stringify(r.body).slice(0, 200));
  check("steps: step number, delay_days, subject, purpose — and not the body",
    d && same(d.steps, [{ step: 1, delay_days: 0, subject: "Welcome", purpose: "welcome" }, { step: 2, delay_days: 3, subject: "Tips", purpose: "tips" }]), d && JSON.stringify(d.steps));
  const e2 = d && d.enrollments.find(x => x.contact_email === "p2@example.com");
  check("enrollments: six, each with contact name and email, next_step, next_send_at, status, stop_reason, last_sent_at",
    d && d.enrollments.length === 6 && e2 && e2.contact_name === "Person 2" && e2.next_step === 1 && e2.next_send_at === "2026-10-11T09:00:00.000Z" &&
    e2.status === "active" && e2.stop_reason === null && e2.last_sent_at === "2026-10-08T09:00:00.000Z", d && JSON.stringify(d.enrollments.slice(0, 2)));
  check("…only this sequence's", d && d.enrollments.every(x => ["p1", "p2", "p3", "p4", "p5", "p6"].some(p => x.contact_email === p + "@example.com")));

  for (const [label, run] of [["GET detail", (bb, id) => bb.detail(OWNER, id)], ["POST status", (bb, id) => bb.setStatus(OWNER, id, "paused")]]) {
    b = build(world());
    const before = JSON.stringify(b.db.tables);
    const others = await run(b, sid(5));
    const missing = await run(b, sid(99));
    const malformed = await run(b, "not-a-uuid");
    check(label + ": another user's sequence is a 404", others.code === 404, others.code + " " + JSON.stringify(others.body));
    check(label + ": another user's, a missing and a malformed id answer identically",
      same([others.code, others.body], [missing.code, missing.body]) && same([others.code, others.body], [malformed.code, malformed.body]),
      JSON.stringify([others.body, missing.body, malformed.body]));
    check(label + ": nothing changed", JSON.stringify(b.db.tables) === before);
  }
  b = build(world());
  r = await b.list(OTHER);
  check("another owner's list holds only their sequence", r.body.sequences.length === 1 && r.body.sequences[0].id === sid(5));

  /* ── 4. transitions ───────────────────────────────────────────────────── */
  console.log("\n══ 4. every transition ══");
  const allowed = [["active", "paused", 1], ["paused", "active", 2], ["active", "cancelled", 1], ["paused", "cancelled", 2]];
  for (const [from, to, k] of allowed) {
    b = build(world());
    r = await b.setStatus(OWNER, sid(k), to);
    check(from + " → " + to + ": 200 and the status is " + to, r.code === 200 && r.body.sequence.status === to && b.seqRow(k).status === to, r.code + " " + JSON.stringify(r.body));
  }
  const refused = [["active", "active", 1], ["active", "completed", 1], ["paused", "paused", 2], ["paused", "completed", 2],
    ["completed", "active", 3], ["completed", "paused", 3], ["completed", "cancelled", 3], ["completed", "completed", 3],
    ["cancelled", "active", 4], ["cancelled", "paused", 4], ["cancelled", "cancelled", 4], ["cancelled", "completed", 4]];
  for (const [from, to, k] of refused) {
    b = build(world());
    const before = JSON.stringify(b.db.tables);
    r = await b.setStatus(OWNER, sid(k), to);
    check(from + " → " + to + ": 409 naming " + from + ", nothing changed",
      r.code === 409 && new RegExp("This sequence is " + from + "\\b").test(r.body.error) && r.body.status === from && JSON.stringify(b.db.tables) === before,
      r.code + " " + JSON.stringify(r.body));
  }
  for (const bad of [undefined, "", "Paused", "stopped", 1]) {
    b = build(world());
    r = await b.setStatus(OWNER, sid(1), bad);
    check("status " + JSON.stringify(bad) + ": 400, nothing changed", r.code === 400 && b.seqRow(1).status === "active", r.code);
  }

  /* ── 5. what cancelling and pausing do to enrollments ─────────────────── */
  console.log("\n══ 5. enrollments under cancel and pause ══");
  b = build(world());
  const beforeRows = JSON.parse(JSON.stringify(b.db.tables.email_sequence_enrollments));
  r = await b.setStatus(OWNER, sid(1), "cancelled");
  const after1 = b.enrOf(1);
  const wasActive = beforeRows.filter(e => e.sequence_id === sid(1) && e.status === "active").map(e => e.id);
  check("cancel: enrollments_stopped 2", r.body && r.body.enrollments_stopped === 2, JSON.stringify(r.body));
  check("cancel: each formerly active enrollment is stopped, cancelled_by_owner, next_send_at null, step and history kept",
    wasActive.length === 2 && wasActive.every(id => {
      const now = after1.find(e => e.id === id), was = beforeRows.find(e => e.id === id);
      return now.status === "stopped" && now.stop_reason === "cancelled_by_owner" && now.next_send_at === null &&
        now.next_step === was.next_step && now.last_sent_at === was.last_sent_at;
    }), JSON.stringify(after1));
  check("cancel: completed and stopped enrollments are untouched",
    beforeRows.filter(e => e.sequence_id === sid(1) && e.status !== "active").every(was => same(after1.find(e => e.id === was.id), was)));
  check("cancel: other sequences' enrollments are untouched",
    same(b.db.tables.email_sequence_enrollments.filter(e => e.sequence_id !== sid(1)), beforeRows.filter(e => e.sequence_id !== sid(1))));

  b = build(world());
  let before = JSON.stringify(b.db.tables.email_sequence_enrollments);
  r = await b.setStatus(OWNER, sid(1), "paused");
  check("pause: no enrollment changes at all", r.code === 200 && JSON.stringify(b.db.tables.email_sequence_enrollments) === before && r.body.enrollments_stopped === 0);
  check("pause: no enrollment write was even attempted", !b.db.log.some(q => q.table === "email_sequence_enrollments" && q.op !== "select"));
  before = JSON.stringify(b.db.tables.email_sequence_enrollments);
  r = await b.setStatus(OWNER, sid(1), "active");
  check("resume: no enrollment changes either", r.code === 200 && JSON.stringify(b.db.tables.email_sequence_enrollments) === before);

  /* ── 6. a lapsed, non-admin account can still read and stop ───────────── */
  console.log("\n══ 6. stopping never needs a subscription ══");
  b = build(world());
  r = await b.list(LAPSED);
  check("lapsed account: the list answers 200 with its two sequences", r.code === 200 && r.body.sequences.length === 2, r.code + " " + JSON.stringify(r.body));
  r = await b.detail(LAPSED, sid(6));
  check("lapsed account: the detail answers 200", r.code === 200 && r.body.sequence.id === sid(6), r.code);
  r = await b.setStatus(LAPSED, sid(6), "paused");
  check("lapsed account: can pause", r.code === 200 && b.seqRow(6).status === "paused", r.code + " " + JSON.stringify(r.body));
  r = await b.setStatus(LAPSED, sid(7), "cancelled");
  check("lapsed account: can cancel, and its active enrollment is stopped",
    r.code === 200 && b.seqRow(7).status === "cancelled" && b.enrOf(7)[0].status === "stopped" && b.enrOf(7)[0].stop_reason === "cancelled_by_owner", r.code + " " + JSON.stringify(r.body));
  r = await b.setStatus(LAPSED, sid(6), "cancelled");
  check("lapsed account: can cancel a paused one", r.code === 200 && b.seqRow(6).status === "cancelled", r.code);
  check("no subscription or admin gate refused anything", b.refusedBy.length === 0, JSON.stringify(b.refusedBy));
  for (const [m, route] of ROUTES) {
    check(m.toUpperCase() + " " + route + ": requireAuth and nothing else before the handler",
      same(b.routes[m + " " + route].slice(0, -1).map(f => f.name), ["requireAuth"]), JSON.stringify(b.routes[m + " " + route].slice(0, -1).map(f => f.name)));
  }

  /* ── 7. nothing is sent, and the sender skips what is not active ──────── */
  console.log("\n══ 7. nothing is sent ══");
  check("zero Resend constructions or calls across every request", RESEND_CALLS === 0, RESEND_CALLS);
  check("the lifted routes never name Resend, sendEmail or sendMarketingEmail",
    !/\bResend\b|\bsendEmail\(|\bsendMarketingEmail\(/.test(uncommented(LIFTED)));
  const pass = definitionOf("runEmailSequencePass") || "";
  check("the sender reads only active sequences, so a paused or cancelled one is never sent",
    /\.from\("email_sequences"\)\n\s*\.select\("id, owner_id, status, steps"\)\n\s*\.eq\("status", "active"\);/.test(pass));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
