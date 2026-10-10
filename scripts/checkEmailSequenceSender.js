"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkEmailSequenceSender — approved sequences are sent one due step at a
   time, through sendMarketingEmail and nowhere else.

   emailSequenceTick (with its claim, ceiling and pass), executeSendEmailSequence
   and POST /api/proposals are lifted from server.js and run in a vm against an
   in-memory Supabase that keeps its rows between calls. sendMarketingEmail and
   sendEmail are the REAL functions, lifted with them, so every refusal below is
   the one sendMarketingEmail actually gives. Resend is a class that records
   what it is asked to send and sends nothing; the clock is a fake that the
   Resend stub moves forward on every send, so "the time of the send" and "the
   time the tick started" are different instants. No network, no model, no mail.

   WHAT THIS PROVES
     1. The gates: the flag off runs nothing at all; a second claim of the same
        UTC hour runs nothing past job_runs; a malformed ceiling aborts before
        any read, and does not leave the tick stuck; blank is the default 25.
     2. Selection: paused, cancelled and non-admin sequences are not sent; the
        ceiling counts ATTEMPTS — failures included — oldest due first.
     3. The already-sent guard: a "sent" row for the step's template advances
        the enrollment without a Resend call; a "failed" row does not.
     4. Each outcome, exactly: sent; stopped for suppressed, no_consent and
        not_confirmed (and never retried); cap_reached left due with that
        owner's other enrollments skipped and another owner's still sent;
        no_postal_address and cap_unreadable abort the tick; another refusal, a
        send that returns not sent, and a throw each leave the enrollment due
        while the tick goes on.
     5. Timing: the next step is due its delay_days after the actual send; the
        last step completes the enrollment, and a sequence whose enrollments are
        all completed or stopped is completed.
     6. The message: the template is "seq-<sequence id>-s<step>", stored as
        "marketing:seq-…" and inside sendMarketingEmail's rule; the HTML is the
        escaped text in paragraphs; the tick logs its summary line.
     7. The filing path: an unreadable consent is skipped_unreadable (A1);
        POST /api/proposals refuses send_email_sequence (A2); the executor
        requires the source run's steps, exactly (A3).
     8. The wiring: registered hourly, UTC, behind the flag, never at boot.

   MUTATE=<name> edits the lifted source (server.js on disk is never touched).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly once
   is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const ANCHOR_ERROR_EXIT = 3;

const MUTATIONS = {
  // the tick runs whatever the flag says
  "ignore-flag": [["  if (!emailSequencesEnabled()) {\n    console.log(\"[EmailSequences] Tick skipped", "  if (false) {\n    console.log(\"[EmailSequences] Tick skipped"]],
  // a step already sent is sent again
  "drop-already-sent-guard": [["      if (prior.data && prior.data.length > 0) {\n", "      if (false) {\n"]],
  // a suppressed contact is left due and retried
  "retry-suppressed": [["var EMAIL_SEQUENCE_STOP_REASONS = [\"suppressed\", \"no_consent\", \"not_confirmed\"];",
    "var EMAIL_SEQUENCE_STOP_REASONS = [\"no_consent\", \"not_confirmed\"];"]],
  // the tick carries on past a missing postal address
  "continue-after-no-postal": [["          console.error(\"[EmailSequences] Tick aborted — \" + sendErr.message);\n          break;\n",
    "          console.error(\"[EmailSequences] Tick aborted — \" + sendErr.message);\n          continue;\n"]],
  // the ceiling counts sends, not attempts
  "count-successes": [["    if (summary.attempted >= maxPerTick) {\n", "    if (summary.sent >= maxPerTick) {\n"]],
  // the executor takes steps that differ from the source run
  "accept-differing-steps": [["  if (!emailSequenceSameJson(steps, source.output && source.output.steps)) {\n", "  if (false) {\n"]],
  // an unreadable consent is counted as not confirmed
  "unreadable-as-not-confirmed": [["    if (!latest.ok) {\n      unreadable++;\n", "    if (!latest.ok) {\n      notConfirmed++;\n"]],
  // a failed consent lookup is reported as no_consent
  "consent-failure-as-no-consent": [["  if (!consent.ok) {\n    throw emailMarketingRefusal(\"lookup_failed\", \"the contact's email consent could not be read.\");\n  }\n", ""]],
  // lookup_failed stops the enrollment instead of deferring it
  "stop-on-lookup-failed": [["var EMAIL_SEQUENCE_STOP_REASONS = [\"suppressed\", \"no_consent\", \"not_confirmed\"];",
    "var EMAIL_SEQUENCE_STOP_REASONS = [\"suppressed\", \"no_consent\", \"not_confirmed\", \"lookup_failed\"];"]],
  // the per-send status re-read is gone
  "drop-status-reread": [["      var statusRead = await supabase\n        .from(\"email_sequences\")\n        .select(\"status\")\n        .eq(\"id\", sequence.id)\n        .maybeSingle();\n      if (statusRead.error) {\n",
    "      var statusRead = { data: { status: \"active\" }, error: null };\n      if (statusRead.error) {\n"]],
  // the sweep completes sequences that still have active enrollments
  // no_webhook_secret stops the enrollment instead of ending the tick
  "stop-on-no-webhook-secret": [["var EMAIL_SEQUENCE_ABORT_REASONS = [\"no_postal_address\", \"no_webhook_secret\", \"cap_unreadable\"];",
    "var EMAIL_SEQUENCE_ABORT_REASONS = [\"no_postal_address\", \"cap_unreadable\"];\nEMAIL_SEQUENCE_STOP_REASONS.push(\"no_webhook_secret\");"]],
  "sweep-with-active-enrollments": [["    if (open.data && open.data.length > 0) continue;\n    var done = await supabase\n", "    var done = await supabase\n"]]
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
  "requireAuth", "requireActiveSubscription", "aiLimiter", "crypto", "Date", "cron"]);
// Identifiers are followed through code only: a name mentioned in a comment
// is not a dependency. (A "//" inside a string cuts that line short; anything
// that drops would fail loudly as a ReferenceError in the vm.)
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
function routeText(sig) {
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error(sig + " not found");
  const end = s.braceMatch(SRC, SRC.indexOf("{", start + sig.length - 1));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(sig + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const ROOT = routeText("app.post(\"/api/proposals\", requireAuth, async function (req, res, next) {") +
  "\n\nthis.api = { tick: emailSequenceTick, execute: executeSendEmailSequence, html: emailSequenceHtml, template: emailSequenceTemplate, " +
  "maxPerTick: emailSequenceMaxPerTick };";
const LIFTED = closure(ROOT);

/* ── the clock ──────────────────────────────────────────────────────────── */
const T0 = Date.parse("2026-10-10T13:00:00.000Z");
let CLOCK = T0;
class FakeDate extends Date {
  constructor(...a) { if (a.length === 0) super(CLOCK); else super(...a); }
  static now() { return CLOCK; }
}
const iso = (ms) => new Date(ms).toISOString();
const DAY = 86400000;
const SEND_BUMP = 7 * 60000;   // each Resend call takes "seven minutes"

/* ── the fake database ──────────────────────────────────────────────────── */
function likeMatch(pattern, value, caseBlind) {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "\\" && i + 1 < pattern.length) { re += pattern[++i].replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); continue; }
    re += c === "%" ? "[\\s\\S]*" : c === "_" ? "[\\s\\S]" : c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + re + "$", caseBlind ? "i" : "").test(String(value == null ? "" : value));
}
const TABLES = ["contacts", "consent_events", "email_sends", "email_sequences", "email_sequence_enrollments", "users", "job_runs", "ai_tasks", "agent_proposals"];
function fakeDb(seed, fail) {
  const tables = {};
  TABLES.forEach(t => { tables[t] = ((seed || {})[t] || []).map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  let seq = 0;
  function cell(row, col) {
    if (col.indexOf(".") !== -1) { const c = tables.contacts.find(x => x.id === row.contact_id); return c ? c[col.split(".")[1]] : undefined; }
    return row[col];
  }
  function orMatch(expr, row) {
    return expr.split(",").some(part => {
      const [col, op, ...rest] = part.split("."); const val = rest.join(".");
      if (op === "is" && val === "null") return row[col] == null;
      if (op === "neq") return row[col] != null && String(row[col]) !== val;
      if (op === "eq") return String(row[col]) === val;
      throw new Error("fake db: unplanned or() term " + part);
    });
  }
  function keep(q, row) {
    return q.filters.every(f => {
      if (f[0] === "eq") return cell(row, f[1]) === f[2];
      if (f[0] === "in") return f[2].indexOf(cell(row, f[1])) !== -1;
      if (f[0] === "ilike") return likeMatch(f[2], cell(row, f[1]), true);
      if (f[0] === "like") return likeMatch(f[2], cell(row, f[1]), false);
      if (f[0] === "gte") return String(cell(row, f[1])) >= String(f[2]);
      if (f[0] === "lte") return cell(row, f[1]) != null && String(cell(row, f[1])) <= String(f[2]);
      if (f[0] === "or") return orMatch(f[1], row);
      return true;
    });
  }
  function answer(q) {
    const injected = fail && fail(q);
    if (injected === "throw") return Promise.reject(new Error("the database connection dropped"));
    if (injected) return Promise.resolve({ data: null, count: null, error: injected });
    const rows = tables[q.table];
    if (!rows) return Promise.resolve({ data: null, error: { message: "unplanned table " + q.table } });
    if (q.op === "insert") {
      const payload = JSON.parse(JSON.stringify(q.payload));
      const dup = (q.table === "job_runs" && rows.some(r => r.job_name === payload.job_name)) ||
        (q.table === "email_sequence_enrollments" && rows.some(r => r.sequence_id === payload.sequence_id && r.contact_id === payload.contact_id));
      if (dup) return Promise.resolve({ data: null, error: { code: "23505", message: "duplicate key value violates unique constraint" } });
      const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++seq).padStart(12, "0"), created_at: new FakeDate().toISOString() }, payload);
      rows.push(row);
      const copy = JSON.parse(JSON.stringify(row));
      return Promise.resolve({ data: q.single ? copy : (q.cols ? [copy] : null), error: null });
    }
    if (q.op === "update") {
      const hit = rows.filter(r => keep(q, r));
      hit.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(q.payload))));
      const copies = hit.map(r => JSON.parse(JSON.stringify(r)));
      return Promise.resolve({ data: q.single ? (copies[0] || null) : (q.cols ? copies : null), error: null });
    }
    let hits = rows.filter(r => keep(q, r));
    const order = q.filters.find(f => f[0] === "order");
    if (order) hits = hits.slice().sort((a, b) => (a[order[1]] < b[order[1]] ? -1 : a[order[1]] > b[order[1]] ? 1 : 0) * (order[2] && order[2].ascending === false ? -1 : 1));
    const range = q.filters.find(f => f[0] === "range");
    if (range) hits = hits.slice(range[1], range[2] + 1);
    const limit = q.filters.find(f => f[0] === "limit");
    if (limit) hits = hits.slice(0, limit[1]);
    if (q.opts && q.opts.head) return Promise.resolve({ data: null, count: hits.length, error: null });
    const copies = hits.map(r => JSON.parse(JSON.stringify(r)));
    if (q.single) return Promise.resolve({ data: copies[0] || null, error: null });
    return Promise.resolve({ data: copies, error: null });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, opts: null, payload: null, filters: [], single: false };
    log.push(q);
    const b = {
      select(cols, opts) { q.cols = cols || "*"; if (opts) q.opts = opts; return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; }
    };
    ["eq", "in", "ilike", "like", "gte", "lte", "or", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, tables, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const OWNER2 = "aaaaaaaa-0000-4000-8000-000000000002";
const PLAIN = "cccccccc-0000-4000-8000-000000000003";
const SEQ = { main: "5e000000-0000-4000-8000-000000000001", paused: "5e000000-0000-4000-8000-000000000002", cancelled: "5e000000-0000-4000-8000-000000000003",
  plain: "5e000000-0000-4000-8000-000000000004", other: "5e000000-0000-4000-8000-000000000005" };
const STEPS = [
  { step: 1, delay_days: 0, cumulative_day: 0, purpose: "welcome", subject: "Welcome aboard", body: "Hi <b>&\"Pat\"'\n\nSecond para\nnext line", subject_measurement: {} },
  { step: 2, delay_days: 2, cumulative_day: 2, purpose: "tips", subject: "Getting started", body: "Here is how.", subject_measurement: {} },
  { step: 3, delay_days: 5, cumulative_day: 7, purpose: "ask", subject: "One question", body: "How is it going?", subject_measurement: {} }
];
let n = 0;
const cid = (k) => "c0000000-0000-4000-8000-" + String(k).padStart(12, "0");
// No marketing mail while bounces cannot be heard: the fixture sets the webhook secret too.
const ENV = { ENABLE_EMAIL_SEQUENCES: "true", RESEND_API_KEY: "re_test_key", JWT_SECRET: "check-jwt-secret", MAIL_POSTAL_ADDRESS: "BizForce AI\n1 Example St",
  RESEND_WEBHOOK_SECRET: "whsec_check" };

// Every fixture sequence is older than the sweep's grace period.
const OLD = iso(T0 - 30 * DAY);

// A world: sequences, contacts with a consent state, and an enrollment each.
// people: [{ k, seq, consent, next_step, due_ms, owner }]
function world(people, extra) {
  n = 0;
  const w = {
    users: [{ id: OWNER, role: "admin" }, { id: OWNER2, role: "admin" }, { id: PLAIN, role: "user" }],
    email_sequences: [
      { id: SEQ.main, owner_id: OWNER, status: "active", steps: STEPS, name: "Main", created_at: OLD },
      { id: SEQ.paused, owner_id: OWNER, status: "paused", steps: STEPS, name: "Paused", created_at: OLD },
      { id: SEQ.cancelled, owner_id: OWNER, status: "cancelled", steps: STEPS, name: "Cancelled", created_at: OLD },
      { id: SEQ.plain, owner_id: PLAIN, status: "active", steps: STEPS, name: "Not admin", created_at: OLD },
      { id: SEQ.other, owner_id: OWNER2, status: "active", steps: STEPS, name: "Owner two", created_at: OLD }
    ],
    contacts: [], consent_events: [], email_sequence_enrollments: [], email_sends: [], job_runs: []
  };
  const ownerOf = { [SEQ.main]: OWNER, [SEQ.paused]: OWNER, [SEQ.cancelled]: OWNER, [SEQ.plain]: PLAIN, [SEQ.other]: OWNER2 };
  people.forEach(p => {
    const id = cid(p.k);
    w.contacts.push({ id, owner_id: ownerOf[p.seq || SEQ.main], email: "p" + p.k + "@example.com", brand: "bizforce" });
    (p.consent === "confirmed" ? ["granted", "confirmed"] : p.consent === "granted" ? ["granted"] : p.consent === "revoked" ? ["granted", "confirmed", "revoked"] : [])
      .forEach(a => w.consent_events.push({ id: "e" + (++n), contact_id: id, channel: "email", action: a, occurred_at: String(n).padStart(8, "0") }));
    w.email_sequence_enrollments.push({ id: "en-" + p.k, sequence_id: p.seq || SEQ.main, contact_id: id, next_step: p.next_step || 0,
      next_send_at: iso(T0 - (p.due_ms === undefined ? DAY : p.due_ms)), status: p.status || "active", stop_reason: null, last_sent_at: null });
  });
  return Object.assign(w, extra || {});
}

function build(seed, opts) {
  const o = opts || {};
  CLOCK = T0;
  const db = fakeDb(seed, o.fail);
  const sent = [], logs = [];
  class Resend {
    constructor() {
      this.emails = { send: async (args) => {
        CLOCK += SEND_BUMP;
        sent.push(JSON.parse(JSON.stringify(args)));
        if (o.providerError) return { data: null, error: { message: "provider said no" } };
        return { data: { id: "re_" + sent.length }, error: null };
      } };
    }
  }
  const ctx = {
    supabase: db.client, Resend, crypto, Buffer, URL, JSON, Math, Promise, require, Date: FakeDate,
    nowIso: () => new FakeDate().toISOString(),
    process: { env: Object.assign({}, o.env === undefined ? ENV : o.env) },
    console: { log: m => logs.push(String(m)), error: (...a) => logs.push(a.map(String).join(" ")), warn: m => logs.push(String(m)) },
    requireAuth: function requireAuth() {}
  };
  let proposalsHandler = null;
  ctx.app = { post(p) { if (p === "/api/proposals") proposalsHandler = arguments[arguments.length - 1]; } };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  return {
    db, sent, logs, ctx, api: ctx.api,
    enr: (k) => db.tables.email_sequence_enrollments.find(e => e.id === "en-" + k),
    seq: (id) => db.tables.email_sequences.find(x => x.id === id),
    tick: () => ctx.api.tick(),
    summary: () => logs.filter(l => l.indexOf("[EmailSequences] Tick: claimed yes") === 0).pop() || "",
    proposals: async (body) => {
      const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = x; return this; } };
      await proposalsHandler({ user: { id: OWNER }, body }, res, e => { res.code = 500; res.body = { error: String(e) }; });
      return res;
    }
  };
}
const nonJobReads = (b) => b.db.log.filter(q => q.table !== "job_runs");
const untouched = (b, seed, k) => JSON.stringify(b.enr(k)) === JSON.stringify(seed.email_sequence_enrollments.find(e => e.id === "en-" + k));

(async function main() {
  /* ── 1. the gates ─────────────────────────────────────────────────────── */
  console.log("\n══ 1. the gates ══");
  for (const flag of [undefined, "", "TRUE", "1", "yes"]) {
    const env = Object.assign({}, ENV); if (flag === undefined) delete env.ENABLE_EMAIL_SEQUENCES; else env.ENABLE_EMAIL_SEQUENCES = flag;
    const b = build(world([{ k: 1, consent: "confirmed" }]), { env });
    await b.tick();
    check("flag " + JSON.stringify(flag) + ": nothing read, nothing claimed, nothing sent", b.db.log.length === 0 && b.sent.length === 0, b.db.log.length + "/" + b.sent.length);
  }

  let seed = world([{ k: 1, consent: "confirmed" }]);
  let b = build(seed);
  await b.tick();
  check("first tick of the hour: claims, sends one", b.sent.length === 1 && b.db.tables.job_runs.length === 1 && b.db.tables.job_runs[0].job_name === "hourly_email_sequences_h13",
    b.sent.length + " " + JSON.stringify(b.db.tables.job_runs));
  b.db.tables.contacts.push({ id: cid(2), owner_id: OWNER, email: "p2@example.com", brand: "bizforce" });
  b.db.tables.consent_events.push({ id: "late", contact_id: cid(2), channel: "email", action: "confirmed", occurred_at: "99999999" });
  b.db.tables.email_sequence_enrollments.push({ id: "en-2", sequence_id: SEQ.main, contact_id: cid(2), next_step: 0, next_send_at: iso(T0 - DAY), status: "active" });
  const logBefore = b.db.log.length;
  CLOCK = T0 + 20 * 60000;   // later in the same UTC hour
  await b.tick();
  check("a second claim in the same hour: nothing sent and nothing read past job_runs",
    b.sent.length === 1 && b.db.log.slice(logBefore).every(q => q.table === "job_runs") && b.logs.some(l => /claimed no/.test(l)), b.db.log.slice(logBefore).map(q => q.table).join(","));
  CLOCK = T0 + 60 * 60000;   // the next hour
  await b.tick();
  check("the next hour claims again and sends", b.sent.length === 2 && b.db.tables.job_runs.length === 2, b.sent.length);

  for (const bad of ["abc", "0", "-3", "2.5", "1e400"]) {
    b = build(world([{ k: 1, consent: "confirmed" }]), { env: Object.assign({}, ENV, { EMAIL_SEQUENCE_MAX_PER_TICK: bad }) });
    await b.tick();
    check("ceiling " + JSON.stringify(bad) + ": aborts before any read or claim", b.db.log.length === 0 && b.sent.length === 0 && b.logs.some(l => /Tick aborted — EMAIL_SEQUENCE_MAX_PER_TICK/.test(l)),
      b.db.log.length + " " + b.logs.join(" | "));
    b.ctx.process.env.EMAIL_SEQUENCE_MAX_PER_TICK = "  ";
    await b.tick();
    check("ceiling " + JSON.stringify(bad) + " then blank: the next tick runs (no stuck flag), ceiling 25", b.sent.length === 1 && /ceiling 25\)/.test(b.summary()), b.summary());
  }

  /* ── 2. selection and the ceiling ─────────────────────────────────────── */
  console.log("\n══ 2. what is due, and how many ══");
  seed = world([
    { k: 1, consent: "confirmed", seq: SEQ.paused }, { k: 2, consent: "confirmed", seq: SEQ.cancelled }, { k: 3, consent: "confirmed", seq: SEQ.plain },
    { k: 4, consent: "confirmed", due_ms: -3600000 }   // not due for an hour
  ]);
  b = build(seed);
  await b.tick();
  check("paused, cancelled and non-admin sequences, and a not-yet-due step: nothing sent, nothing changed",
    b.sent.length === 0 && [1, 2, 3, 4].every(k => untouched(b, seed, k)) && /due 0, attempted 0/.test(b.summary()), b.summary());

  const four = [{ k: 1, consent: "confirmed", due_ms: 4 * DAY }, { k: 2, consent: "confirmed", due_ms: 3 * DAY }, { k: 3, consent: "confirmed", due_ms: 2 * DAY }, { k: 4, consent: "confirmed", due_ms: DAY }];
  seed = world(four);
  b = build(seed, { env: Object.assign({}, ENV, { EMAIL_SEQUENCE_MAX_PER_TICK: "2" }) });
  await b.tick();
  check("ceiling 2 of 4 due: two sends, the two oldest", b.sent.length === 2 && b.enr(1).next_step === 1 && b.enr(2).next_step === 1 && untouched(b, seed, 3) && untouched(b, seed, 4),
    b.sent.map(m => m.to).join(","));
  b = build(seed, { env: Object.assign({}, ENV, { EMAIL_SEQUENCE_MAX_PER_TICK: "2" }), providerError: true });
  await b.tick();
  check("ceiling 2 of 4 due, every send failing: still exactly two attempts", b.sent.length === 2 && /attempted 2 \(ceiling 2, reached\)/.test(b.summary()), b.sent.length + " " + b.summary());

  /* ── 3. the already-sent guard ────────────────────────────────────────── */
  console.log("\n══ 3. a step already sent is not sent again ══");
  const sentAt = iso(T0 - 5 * 3600000);
  seed = world([{ k: 1, consent: "confirmed" }], {});
  seed.email_sends = [{ id: "s-old", contact_id: cid(1), to_email: "p1@example.com", template: "marketing:seq-" + SEQ.main + "-s0", status: "sent", created_at: sentAt }];
  b = build(seed);
  await b.tick();
  check("a sent row for this step: no Resend call", b.sent.length === 0, b.sent.length);
  check("…the enrollment advances from that send: step 1, last_sent_at the row's time, due 2 days after it",
    b.enr(1).next_step === 1 && b.enr(1).last_sent_at === sentAt && b.enr(1).next_send_at === iso(Date.parse(sentAt) + 2 * DAY) && b.enr(1).status === "active",
    JSON.stringify(b.enr(1)));
  seed.email_sends[0].status = "failed";
  b = build(seed);
  await b.tick();
  check("a failed row for this step does not count: it is sent", b.sent.length === 1 && b.enr(1).next_step === 1, b.sent.length);
  seed.email_sends[0] = Object.assign({}, seed.email_sends[0], { status: "sent", template: "marketing:seq-" + SEQ.main + "-s1" });
  b = build(seed);
  await b.tick();
  check("a sent row for a different step does not count", b.sent.length === 1, b.sent.length);

  /* ── 4. the outcomes ──────────────────────────────────────────────────── */
  console.log("\n══ 4. every outcome ══");
  seed = world([{ k: 1, consent: "confirmed" }]);
  b = build(seed);
  await b.tick();
  const firstSend = T0 + SEND_BUMP;
  let e = b.enr(1);
  check("sent: next_step 1, last_sent_at the send's own time, next_send_at that + 2 days, still active",
    e.next_step === 1 && e.last_sent_at === iso(firstSend) && e.next_send_at === iso(firstSend + 2 * DAY) && e.status === "active" && e.stop_reason === null, JSON.stringify(e));
  check("…not timed from the tick's start nor from the old due time",
    e.next_send_at !== iso(T0 + 2 * DAY) && e.next_send_at !== iso(T0 - DAY + 2 * DAY));
  const row = b.db.tables.email_sends[0] || {};
  check("…one email_sends row, template marketing:seq-<sequence id>-s0, status sent", b.db.tables.email_sends.length === 1 &&
    row.template === "marketing:seq-" + SEQ.main + "-s0" && row.status === "sent" && row.contact_id === cid(1), JSON.stringify(row));
  check("…to the contact, with the step's subject", b.sent[0].to === "p1@example.com" && b.sent[0].subject === "Welcome aboard", JSON.stringify(b.sent[0]));

  const stops = [["suppressed", { consent: "confirmed" }, (w) => { w.email_sends = [{ id: "cmp", contact_id: cid(1), to_email: "p1@example.com", template: "x", status: "complained", created_at: iso(T0 - 9 * DAY) }]; }],
    ["no_consent", { consent: "revoked" }, null], ["not_confirmed", { consent: "granted" }, null]];
  for (const [reason, person, tweak] of stops) {
    seed = world([Object.assign({ k: 1 }, person), { k: 2, consent: "confirmed" }]);
    if (tweak) tweak(seed);
    b = build(seed);
    await b.tick();
    e = b.enr(1);
    check(reason + ": stopped, stop_reason " + reason + ", next_send_at null, step unchanged, no send to them",
      e.status === "stopped" && e.stop_reason === reason && e.next_send_at === null && e.next_step === 0 && !b.sent.some(m => m.to === "p1@example.com"), JSON.stringify(e));
    check(reason + ": the next contact is still sent", b.enr(2).next_step === 1, JSON.stringify(b.enr(2)));
    check(reason + ": the summary counts it", new RegExp(reason + " 1").test(b.summary()), b.summary());
    CLOCK = T0 + 3 * 3600000;
    const readsBefore = b.db.log.length;
    await b.tick();
    check(reason + ": never retried — a later tick does not take it up",
      b.enr(1).status === "stopped" && !b.db.log.slice(readsBefore).some(q => q.filters.some(f => f[1] === "contact_id" && f[2] === cid(1))), "");
  }

  // cap_reached: OWNER is at the daily cap, OWNER2 is not.
  seed = world([{ k: 1, consent: "confirmed", due_ms: 3 * DAY }, { k: 2, consent: "confirmed", due_ms: 2 * DAY }, { k: 3, consent: "confirmed", seq: SEQ.other, due_ms: DAY }]);
  seed.email_sends = [{ id: "m-today", contact_id: cid(1), to_email: "p1@example.com", template: "marketing:news", status: "sent", created_at: iso(T0 - 3600000) }];
  b = build(seed, { env: Object.assign({}, ENV, { EMAIL_MARKETING_DAILY_CAP: "1" }) });
  await b.tick();
  check("cap_reached: that enrollment is left due, unchanged", untouched(b, seed, 1), JSON.stringify(b.enr(1)));
  check("cap_reached: the owner's other enrollment is skipped this tick, unread and unchanged",
    untouched(b, seed, 2) && !b.db.log.some(q => q.table === "consent_events" && q.filters.some(f => f[2] === cid(2))), JSON.stringify(b.enr(2)));
  check("cap_reached: another owner's enrollment is still sent", b.sent.length === 1 && b.sent[0].to === "p3@example.com" && b.enr(3).next_step === 1, b.sent.map(m => m.to).join(","));
  check("cap_reached: attempted 2, deferred 2", /attempted 2 .*deferred 2, aborted no/.test(b.summary()), b.summary());

  // no_webhook_secret: No marketing mail while bounces cannot be heard.
  for (const [reason, env] of [["no_postal_address", Object.assign({}, ENV, { MAIL_POSTAL_ADDRESS: "  " })], ["no_webhook_secret", Object.assign({}, ENV, { RESEND_WEBHOOK_SECRET: "" })],
    ["cap_unreadable", Object.assign({}, ENV, { EMAIL_MARKETING_DAILY_CAP: "lots" })]]) {
    seed = world([{ k: 1, consent: "confirmed", due_ms: 3 * DAY }, { k: 2, consent: "confirmed", due_ms: 2 * DAY }, { k: 3, consent: "confirmed", seq: SEQ.other, due_ms: DAY }]);
    b = build(seed, { env });
    await b.tick();
    check(reason + ": the tick aborts after one attempt — nothing sent, every enrollment unchanged",
      b.sent.length === 0 && [1, 2, 3].every(k => untouched(b, seed, k)) && new RegExp("attempted 1 .*aborted " + reason).test(b.summary()), b.summary());
    check(reason + ": no enrollment is stopped", !b.db.tables.email_sequence_enrollments.some(x => x.status === "stopped"),
      JSON.stringify(b.db.tables.email_sequence_enrollments.map(x => x.status)));
    check(reason + ": the hour's job_runs row records the abort", /aborted: /.test(b.db.tables.job_runs[0].last_error || "") && !!b.db.tables.job_runs[0].finished_at,
      JSON.stringify(b.db.tables.job_runs[0]));
  }

  const leftDue = [
    ["another refusal (the contact cannot be read: lookup_failed)", { fail: q => q.table === "contacts" && q.filters.some(f => f[1] === "id" && f[2] === cid(1)) ? { message: "down" } : null }],
    ["a send that returns not sent (provider error)", { providerErrorFor: "p1@example.com" }],
    ["a throw (the consent read rejects)", { fail: q => q.table === "consent_events" && q.filters.some(f => f[2] === cid(1)) ? "throw" : null }],
    ["a throw (the already-sent read rejects)", { fail: q => q.table === "email_sends" && q.filters.some(f => f[1] === "template" && /^marketing:seq-/.test(f[2])) && q.filters.some(f => f[2] === cid(1)) ? "throw" : null }]
  ];
  for (const [label, o] of leftDue) {
    seed = world([{ k: 1, consent: "confirmed", due_ms: 2 * DAY }, { k: 2, consent: "confirmed", due_ms: DAY }]);
    const opts = { fail: o.fail };
    b = build(seed, opts);
    if (o.providerErrorFor) {
      const send = b.ctx.Resend;
      b.ctx.Resend = class extends send { constructor() { super(); const inner = this.emails.send; this.emails.send = async (a) => { const r = await inner(a); return a.to === o.providerErrorFor ? { data: null, error: { message: "no" } } : r; }; } };
    }
    await b.tick();
    check(label + ": left due, unchanged", untouched(b, seed, 1), JSON.stringify(b.enr(1)));
    check(label + ": the tick goes on — the next enrollment is sent", b.enr(2).next_step === 1, JSON.stringify(b.enr(2)));
    check(label + ": deferred 1, aborted no", /deferred 1, aborted no/.test(b.summary()), b.summary());
  }

  /* ── 5. timing and completion ─────────────────────────────────────────── */
  console.log("\n══ 5. delays chain from each send, and the end completes ══");
  seed = world([{ k: 1, consent: "confirmed" }]);
  b = build(seed);
  await b.tick();
  const s1 = T0 + SEND_BUMP;
  CLOCK = s1 + 2 * DAY + 3 * 3600000;   // three hours after step 2 fell due
  await b.tick();
  const s2 = s1 + 2 * DAY + 3 * 3600000 + SEND_BUMP;
  check("step 2 is due 2 days after step 1's send; once sent, step 3 is due 5 days after step 2's actual send",
    b.enr(1).next_step === 2 && b.enr(1).last_sent_at === iso(s2) && b.enr(1).next_send_at === iso(s2 + 5 * DAY), JSON.stringify(b.enr(1)));
  check("(not 5 days after step 2's due time)", b.enr(1).next_send_at !== iso(s1 + 2 * DAY + 5 * DAY));
  CLOCK = s2 + 5 * DAY;
  await b.tick();
  e = b.enr(1);
  check("the last step: next_step 3, status completed, next_send_at null", e.next_step === 3 && e.status === "completed" && e.next_send_at === null, JSON.stringify(e));
  check("three sends in all, one per step, templates s0 s1 s2",
    JSON.stringify(b.db.tables.email_sends.map(r => r.template)) === JSON.stringify([0, 1, 2].map(i => "marketing:seq-" + SEQ.main + "-s" + i)), JSON.stringify(b.db.tables.email_sends.map(r => r.template)));
  check("its only enrollment done, the sequence is completed", b.seq(SEQ.main).status === "completed", b.seq(SEQ.main).status);
  CLOCK += 30 * DAY;
  const sentBefore = b.sent.length;
  await b.tick();
  check("a completed enrollment is never sent again", b.sent.length === sentBefore);

  seed = world([{ k: 1, consent: "confirmed", next_step: 2 }, { k: 2, consent: "revoked" }]);
  b = build(seed);
  await b.tick();
  check("one completed and one stopped: the sequence is completed", b.enr(1).status === "completed" && b.enr(2).status === "stopped" && b.seq(SEQ.main).status === "completed",
    b.seq(SEQ.main).status);
  seed = world([{ k: 1, consent: "confirmed", next_step: 2 }, { k: 2, consent: "confirmed", due_ms: -DAY }]);
  b = build(seed);
  await b.tick();
  check("one completed and one still active: the sequence stays active", b.enr(1).status === "completed" && b.seq(SEQ.main).status === "active", b.seq(SEQ.main).status);

  /* ── 5b. never stop a sequence on a read that failed ──────────────────── */
  console.log("\n══ 5b. failed reads defer, a pause mid-tick holds, and the sweep ══");
  // A consent lookup that fails is lookup_failed: left due, never stopped, and sent once it reads.
  let consentDown = true;
  seed = world([{ k: 1, consent: "confirmed", due_ms: 2 * DAY }, { k: 2, consent: "confirmed", due_ms: DAY }]);
  b = build(seed, { fail: q => consentDown && q.table === "consent_events" && q.filters.some(f => f[2] === cid(1)) ? { message: "down" } : null });
  await b.tick();
  e = b.enr(1);
  check("a failed consent lookup: left due — still active, still due, no stop_reason, step unchanged",
    untouched(b, seed, 1) && e.status === "active" && e.stop_reason === null && e.next_step === 0 && Date.parse(e.next_send_at) <= CLOCK, JSON.stringify(e));
  check("a failed consent lookup: no send to them, the next contact is sent, deferred 1, stopped none",
    !b.sent.some(m => m.to === "p1@example.com") && b.enr(2).next_step === 1 &&
    /stopped suppressed 0 \/ no_consent 0 \/ not_confirmed 0, skipped not active 0, deferred 1,/.test(b.summary()), b.summary());
  consentDown = false;
  CLOCK = T0 + 3600000;
  await b.tick();
  check("a failed consent lookup: the next tick, once it reads, sends it",
    b.sent.some(m => m.to === "p1@example.com") && b.enr(1).next_step === 1 && b.enr(1).status === "active", JSON.stringify(b.enr(1)));

  // A pause or cancel between two sends of one tick stops the second.
  for (const to of ["paused", "cancelled"]) {
    seed = world([{ k: 1, consent: "confirmed", due_ms: 2 * DAY }, { k: 2, consent: "confirmed", due_ms: DAY }]);
    b = build(seed);
    const inner = b.ctx.Resend, db = b.db;
    b.ctx.Resend = class extends inner { constructor() { super(); const send = this.emails.send; this.emails.send = async (a) => {
      const r = await send(a); db.tables.email_sequences.find(x => x.id === SEQ.main).status = to; return r; }; } };
    await b.tick();
    check(to + " between two sends of one tick: the second is not sent", b.sent.length === 1 && b.sent[0].to === "p1@example.com", b.sent.map(m => m.to).join(","));
    check(to + " between two sends: the second enrollment is unchanged, the sequence stays " + to,
      untouched(b, seed, 2) && b.seq(SEQ.main).status === to && /skipped not active 1,/.test(b.summary()), b.summary());
  }

  // A status re-read that fails defers.
  seed = world([{ k: 1, consent: "confirmed", due_ms: 2 * DAY }, { k: 2, consent: "confirmed", due_ms: DAY }]);
  b = build(seed, { fail: q => q.table === "email_sequences" && q.op === "select" && q.cols === "status" ? { message: "down" } : null });
  await b.tick();
  check("a failed status re-read: nothing sent, both left due and unchanged, deferred 2",
    b.sent.length === 0 && untouched(b, seed, 1) && untouched(b, seed, 2) && /deferred 2, aborted no/.test(b.summary()), b.summary());
  check("a failed status re-read: the hour's job_runs row records it", /status could not be read again/.test(b.db.tables.job_runs[0].last_error || ""),
    JSON.stringify(b.db.tables.job_runs[0]));

  // The sweep.
  seed = world([]);
  seed.email_sequences.push({ id: "5e000000-0000-4000-8000-000000000006", owner_id: OWNER, status: "active", steps: STEPS, name: "Closed", created_at: OLD },
    { id: "5e000000-0000-4000-8000-000000000007", owner_id: OWNER, status: "active", steps: STEPS, name: "Open", created_at: OLD },
    { id: "5e000000-0000-4000-8000-000000000008", owner_id: OWNER, status: "active", steps: STEPS, name: "Just approved", created_at: iso(T0 - 10 * 60000) });
  const enr = (id, sequence_id, status, due) => ({ id, sequence_id, contact_id: cid(9), next_step: 0, next_send_at: due === undefined ? null : iso(due), status, stop_reason: status === "stopped" ? "suppressed" : null, last_sent_at: null });
  seed.email_sequence_enrollments.push(enr("x-1", "5e000000-0000-4000-8000-000000000006", "completed"), enr("x-2", "5e000000-0000-4000-8000-000000000006", "stopped"),
    enr("x-3", "5e000000-0000-4000-8000-000000000007", "completed"), enr("x-4", "5e000000-0000-4000-8000-000000000007", "active", T0 + 3 * DAY),
    enr("x-5", SEQ.paused, "completed"));
  b = build(seed);
  await b.tick();
  check("the sweep: a sequence with no enrollments is completed", b.seq(SEQ.main).status === "completed", b.seq(SEQ.main).status);
  check("the sweep: one whose enrollments were all closed elsewhere (completed, stopped) is completed",
    b.seq("5e000000-0000-4000-8000-000000000006").status === "completed", b.seq("5e000000-0000-4000-8000-000000000006").status);
  check("the sweep: one with an active enrollment (not yet due) stays active", b.seq("5e000000-0000-4000-8000-000000000007").status === "active");
  check("the sweep: a paused sequence is never swept, nor a cancelled one", b.seq(SEQ.paused).status === "paused" && b.seq(SEQ.cancelled).status === "cancelled");
  check("the sweep: a sequence younger than the grace period is left active (its enrollments may still be landing)",
    b.seq("5e000000-0000-4000-8000-000000000008").status === "active");
  check("the sweep: counted in the tick log — sequences completed 4 (main, closed, non-admin, second owner)", /sequences completed 4\.$/.test(b.summary()), b.summary());
  check("the sweep: conditional on status active", b.db.log.filter(q => q.table === "email_sequences" && q.op === "update")
    .every(q => q.filters.some(f => f[0] === "eq" && f[1] === "status" && f[2] === "active")));

  seed = world([]);
  seed.users.forEach(u => { u.role = "user"; });
  b = build(seed);
  await b.tick();
  check("the sweep runs on a tick with nothing sendable (no admin owner)", b.seq(SEQ.main).status === "completed" && /due 0, .*sequences completed 3\.$/.test(b.summary()), b.summary());

  /* ── 6. the message and the log ───────────────────────────────────────── */
  console.log("\n══ 6. what is sent, and what is logged ══");
  seed = world([{ k: 1, consent: "confirmed" }]);
  b = build(seed);
  await b.tick();
  const mail = b.sent[0] || {};
  check("HTML: escaped, blank lines become paragraphs, a single break is <br>",
    String(mail.html).indexOf("<p>Hi &lt;b&gt;&amp;&quot;Pat&quot;&#39;</p>\n<p>Second para<br>next line</p>") === 0, String(mail.html).slice(0, 160));
  check("HTML: no raw markup from the body survives", !/<b>/.test(mail.html));
  check("text: the body as written, then the footer", String(mail.text).indexOf(STEPS[0].body + "\n\n--\n") === 0, String(mail.text).slice(0, 80));
  const tpl = b.api.template(SEQ.main, 0);
  check("template seq-<sequence id>-s<step>, inside sendMarketingEmail's rule", tpl === "seq-" + SEQ.main + "-s0" && /^[a-z0-9][a-z0-9_-]{0,58}$/.test(tpl), tpl);
  check("an upper-case id is lowered, step 11 still fits", b.api.template(SEQ.main.toUpperCase(), 11) === "seq-" + SEQ.main + "-s11" && /^[a-z0-9][a-z0-9_-]{0,58}$/.test(b.api.template(SEQ.main, 11)));
  // Never stop a sequence on a read that failed: skipped not active, and the sweep's sequences completed
  // (2: the non-admin and the second owner's sequences have no enrollment here, so the sweep completes them).
  check("the tick logs claimed, due, attempted, sent, stopped by reason, skipped not active, deferred, aborted, sequences completed",
    /^\[EmailSequences\] Tick: claimed yes, due 1, attempted 1 \(ceiling 25\), sent 1, .*stopped suppressed 0 \/ no_consent 0 \/ not_confirmed 0, skipped not active 0, deferred 0, aborted no, sequences completed 2\.$/.test(b.summary()), b.summary());
  check("the hour closes clean in job_runs", b.db.tables.job_runs[0].finished_at && !b.db.tables.job_runs[0].last_error, JSON.stringify(b.db.tables.job_runs[0]));

  /* ── 7. the filing path ───────────────────────────────────────────────── */
  console.log("\n══ 7. the filing path (A1-A3) ══");
  const TASK = "11111111-0000-4000-8000-000000000001";
  const proposal = { id: "99999999-0000-4000-8000-000000000001", user_id: OWNER, agent_type: "email", action_type: "send_email_sequence", status: "executing",
    payload: { name: "Welcome", brand: null, steps: STEPS, source_task_id: TASK } };
  function fileWorld(taskPatch) {
    const w = world([{ k: 1, consent: "confirmed" }, { k: 2, consent: "granted" }, { k: 3, consent: "none" }, { k: 4, consent: "confirmed" }]);
    w.email_sequences = []; w.email_sequence_enrollments = [];
    w.ai_tasks = [Object.assign({ id: TASK, user_id: OWNER, task_type: "email/sequence", status: "completed", output: { steps: STEPS } }, taskPatch || {})];
    return w;
  }
  b = build(fileWorld(), { fail: q => q.table === "consent_events" && q.filters.some(f => f[2] === cid(4)) ? { message: "down" } : null });
  let x = await b.api.execute(proposal).then(r => ({ r }), err => ({ err }));
  check("A1: an unreadable consent is skipped_unreadable, not skipped_not_confirmed",
    x.r && x.r.enrolled === 1 && x.r.skipped_not_confirmed === 2 && x.r.skipped_unreadable === 1, x.err ? x.err.message : JSON.stringify(x.r));
  check("A1: and is not enrolled", !b.db.tables.email_sequence_enrollments.some(r => r.contact_id === cid(4)));

  b = build(fileWorld());
  let r = await b.proposals({ agent_type: "email", action_type: "send_email_sequence", title: "x", payload: { name: "x", steps: STEPS, source_task_id: TASK } });
  check("A2: POST /api/proposals refuses send_email_sequence with 400 naming the route to use",
    r.code === 400 && /POST \/api\/agents\/email\/propose-sequence/.test(r.body && r.body.error), r.code + " " + JSON.stringify(r.body));
  check("A2: and files nothing", b.db.tables.agent_proposals.length === 0 && !b.db.log.some(q => q.op === "insert"));
  r = await b.proposals({ agent_type: "executive", action_type: "some_other_action", title: "x" });
  check("A2: another action type is still filed", r.code === 201 && b.db.tables.agent_proposals.length === 1, r.code);

  const reorder = STEPS.map(st => Object.fromEntries(Object.entries(st).reverse()));
  const a3 = [
    ["steps that differ from the source run (one subject changed)", fileWorld({ output: { steps: STEPS.map((st, i) => i === 1 ? Object.assign({}, st, { subject: "Changed" }) : st) } }), null, /differ from the steps the source run drafted/],
    ["a source run with one step fewer", fileWorld({ output: { steps: STEPS.slice(0, 2) } }), null, /differ/],
    ["a missing source run", Object.assign(fileWorld(), { ai_tasks: [] }), null, /source run is missing/],
    ["another user's source run", fileWorld({ user_id: OWNER2 }), null, /source run is missing/],
    ["a source run not completed", fileWorld({ status: "processing" }), null, /source run is missing/],
    ["a source run that is not email/sequence", fileWorld({ task_type: "seo/audit" }), null, /source run is missing/],
    ["an unreadable source run", fileWorld(), q => q.table === "ai_tasks" ? { message: "down" } : null, /could not be read/],
    ["no source_task_id", fileWorld(), null, /names no source run/]
  ];
  for (const [label, w, fail, re] of a3) {
    b = build(w, { fail });
    const prop = label === "no source_task_id" ? Object.assign({}, proposal, { payload: Object.assign({}, proposal.payload, { source_task_id: null }) }) : proposal;
    x = await b.api.execute(prop).then(r2 => ({ r: r2 }), err => ({ err }));
    check("A3: " + label + ": refused " + re.source, x.err && re.test(x.err.message), x.err ? x.err.message : JSON.stringify(x.r));
    check("A3: " + label + ": nothing created", b.db.tables.email_sequences.length === 0 && b.db.tables.email_sequence_enrollments.length === 0);
  }
  b = build(fileWorld({ output: { steps: reorder } }));
  x = await b.api.execute(proposal).then(r2 => ({ r: r2 }), err => ({ err }));
  check("A3: the same steps with keys in another order (as jsonb returns them) are accepted", x.r && b.db.tables.email_sequences.length === 1, x.err && x.err.message);

  /* ── 8. the wiring ────────────────────────────────────────────────────── */
  console.log("\n══ 8. the wiring ══");
  check("registered only behind ENABLE_EMAIL_SEQUENCES, hourly on the hour, in UTC",
    /\n  if \(emailSequencesEnabled\(\)\) \{\n    cron\.schedule\("0 \* \* \* \*", function \(\) \{\n      emailSequenceTick\(\)\.catch\([\s\S]{0,200}?\}, \{\n      timezone: "UTC"\n    \}\);/.test(SRC));
  check("emailSequenceTick is called from the cron and nowhere else (no boot run)", (SRC.match(/\bemailSequenceTick\(/g) || []).length === 2);
  check("sendMarketingEmail is called only by the sequence pass", (SRC.match(/\bsendMarketingEmail\(/g) || []).length === 2 &&
    (definitionOf("runEmailSequencePass") || "").includes("await sendMarketingEmail({"));
  check("server.js still calls Resend in exactly one place", (SRC.match(/\.emails\.send\(/g) || []).length === 1);
  check("its own job name, not the agent schedule's", /var EMAIL_SEQUENCE_JOB_PREFIX = "hourly_email_sequences_h";/.test(SRC));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
