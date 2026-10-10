"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkEmailSequenceProposal — an Email agent sequence is filed for approval,
   and approving it creates the sequence and enrolls confirmed contacts. Nothing
   is sent.

   POST /api/agents/email/propose-sequence and executeSendEmailSequence (the
   send_email_sequence entry in PROPOSAL_EXECUTORS) are lifted from server.js
   and run in a vm against an in-memory Supabase that keeps its rows between
   calls, so a proposal filed by the route is the row the executor is handed.
   Resend, sendEmail and sendMarketingEmail are spies that record and send
   nothing. No network, no model, no rows, no mail.

   WHAT THIS PROVES
     1. The route refuses: a non-admin with 403 before reading anything;
        another user's task, a missing task and a malformed id with the same
        404; a task that is not email/sequence, or not completed, with 400; a
        null delay, a negative delay and a non-zero first delay with 400 naming
        the step; an empty subject or body with 400; an unknown brand with 400.
        No refusal files anything.
     2. The route files: one pending agent_proposals row, agent_type email,
        action_type send_email_sequence, payload { name, brand, steps,
        source_task_id } with the steps taken from the stored run — steps in
        the body are ignored — and a measured count of confirmed contacts that
        is not called a send.
     3. The executor refuses a tampered payload (null delay, non-zero first
        delay, no subject, no steps, a long name) and an owner who is no longer
        admin, creating nothing.
     4. The executor creates one sequence and enrolls only "confirmed" contacts
        of the owner (granted, revoked and none excluded), brand respected,
        next_step 0, next_send_at now. Run twice: one sequence, no duplicate
        enrollment; a unique-key conflict is counted, not thrown. Zero confirmed
        contacts still creates the sequence.
     5. Nothing anywhere called Resend, sendEmail or sendMarketingEmail, or
        touched email_sends.
     6. The wiring: the executor is registered, the action is subscription
        gated, the route has the email tools' auth and subscription middleware,
        a TOOL_INPUT_SPECS entry, and is in CHAIN_NON_DISPATCHABLE_TOOLS.

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
  // the route reads steps from the request body
  "steps-from-body": [["      var steps = task.output && task.output.steps;\n",
    "      var steps = req.body.steps || (task.output && task.output.steps);\n"]],
  // a null delay passes validation
  "accept-null-delay": [["    if (typeof delay !== \"number\" || !Number.isInteger(delay) || delay < 0) {\n",
    "    if (delay !== null && (typeof delay !== \"number\" || !Number.isInteger(delay) || delay < 0)) {\n"]],
  // the executor no longer checks the owner is admin
  "executor-skips-admin": [["  if (!ownerRead.data || ownerRead.data.role !== \"admin\") {\n", "  if (false) {\n"]],
  // a grant still waiting on its confirmation link is enrolled
  "enroll-granted": [["    if (latest.ok && latest.action === \"confirmed\") {\n",
    "    if (latest.ok && (latest.action === \"confirmed\" || latest.action === \"granted\")) {\n"]],
  // a rerun creates a second sequence
  "second-sequence-on-rerun": [["  if (existing.data && existing.data.length > 0) {\n", "  if (false) {\n"]],
  // a chain may dispatch the route
  "chain-dispatchable": [["  \"sales/lead-status\",\n  \"email/propose-sequence\"\n];", "  \"sales/lead-status\"\n];"]]
};

if (MUTATE === "all") {
  const names = Object.keys(MUTATIONS);
  let survived = 0, errors = 0;
  for (const name of names) {
    const r = spawnSync(process.execPath, [__filename], { env: Object.assign({}, process.env, { MUTATE: name }), encoding: "utf8", timeout: 300000 });
    if (r.status === ANCHOR_ERROR_EXIT) {
      errors++;
      console.log("    ERROR     " + name.padEnd(26) + " " + (r.stdout.trim().split("\n").pop() || r.stderr.trim()));
      continue;
    }
    const fails = (r.stdout.match(/^ {4}FAIL {2}.*$/gm) || []);
    const caught = r.status !== 0 && fails.length > 0;
    if (!caught) survived++;
    console.log((caught ? "    caught    " : "    SURVIVED  ") + name.padEnd(26) + " " + fails.length + " failing check(s)" +
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

/* _shared.definitionOf caches by "working tree or not", and a mutated SRC is
   neither; this one reads only SRC. */
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
  "requireAuth", "requireActiveSubscription", "aiLimiter", "sendEmail", "sendMarketingEmail"]);
function closure(root) {
  const have = new Map();
  const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
const ROUTE = "/api/agents/email/propose-sequence";
function routeText() {
  const start = SRC.indexOf("app.post(\"" + ROUTE + "\"");
  if (start < 0) throw new Error("POST " + ROUTE + " not found");
  const end = s.braceMatch(SRC, SRC.indexOf("{", start));
  if (SRC.slice(end, end + 2) !== ");") throw new Error("POST " + ROUTE + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const ROOT = routeText() + "\n\nthis.executeSendEmailSequence = executeSendEmailSequence;";
const LIFTED = closure(ROOT);

/* ── the fake database ──────────────────────────────────────────────────── */
const TABLES = ["ai_tasks", "contacts", "consent_events", "agent_proposals", "users", "email_sequences", "email_sequence_enrollments", "email_sends"];
function fakeDb(seed, override) {
  const tables = {};
  TABLES.forEach(t => { tables[t] = ((seed || {})[t] || []).map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  let seq = 0;
  function keep(q, row) {
    return q.filters.every(f => {
      if (f[0] === "eq") return row[f[1]] === f[2];
      return true;
    });
  }
  function answer(q) {
    const forced = override && override(q);
    if (forced) return Promise.resolve(forced);
    const rows = tables[q.table];
    if (!rows) return Promise.resolve({ data: null, error: { message: "unplanned table " + q.table } });
    if (q.op === "insert") {
      const payload = JSON.parse(JSON.stringify(q.payload));
      if (q.table === "email_sequence_enrollments" &&
          rows.some(r => r.sequence_id === payload.sequence_id && r.contact_id === payload.contact_id)) {
        return Promise.resolve({ data: null, error: { code: "23505", message: "duplicate key value violates unique constraint \"email_sequence_enrollments_sequence_contact_key\"" } });
      }
      const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++seq).padStart(12, "0"), created_at: new Date().toISOString() }, payload);
      rows.push(row);
      return Promise.resolve({ data: q.single ? JSON.parse(JSON.stringify(row)) : null, error: null });
    }
    let hits = rows.filter(r => keep(q, r));
    const order = q.filters.find(f => f[0] === "order");
    if (order) hits = hits.slice().sort((a, b) => (a[order[1]] < b[order[1]] ? -1 : a[order[1]] > b[order[1]] ? 1 : 0) * (order[2] && order[2].ascending === false ? -1 : 1));
    const range = q.filters.find(f => f[0] === "range");
    if (range) hits = hits.slice(range[1], range[2] + 1);
    const limit = q.filters.find(f => f[0] === "limit");
    if (limit) hits = hits.slice(0, limit[1]);
    const copies = hits.map(r => JSON.parse(JSON.stringify(r)));
    if (q.single) return Promise.resolve({ data: copies[0] || null, error: null });
    return Promise.resolve({ data: copies, error: null });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, payload: null, filters: [], single: false };
    log.push(q);
    const b = {
      select(cols) { if (q.op === "select") q.cols = cols; return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      upsert(p) { q.op = "upsert"; q.payload = p; return b; },
      delete() { q.op = "delete"; return b; }
    };
    ["eq", "neq", "in", "is", "not", "gte", "lte", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, tables, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const OTHER = "bbbbbbbb-0000-4000-8000-000000000002";
const PLAIN = "cccccccc-0000-4000-8000-000000000003";   // a subscriber who is not admin
const tid = (n) => "11111111-0000-4000-8000-" + String(n).padStart(12, "0");
const STEPS = [
  { step: 1, delay_days: 0, cumulative_day: 0, purpose: "welcome", subject: "Welcome", body: "Thanks for joining.", subject_measurement: { subject: "Welcome" } },
  { step: 2, delay_days: 3, cumulative_day: 3, purpose: "tips", subject: "Getting started", body: "Here is how.", subject_measurement: { subject: "Getting started" } }
];
const withStep = (i, patch) => STEPS.map((st, j) => j === i ? Object.assign({}, st, patch) : st);
const task = (n, user, steps, extra) => Object.assign({ id: tid(n), user_id: user, agent_type: "email", task_type: "email/sequence", status: "completed", output: { steps } }, extra || {});
const T = {
  ok: tid(1), other: tid(2), seo: tid(3), nullDelay: tid(4), negDelay: tid(5), firstDelay: tid(6), processing: tid(7),
  noSubject: tid(8), noBody: tid(9), missing: tid(99)
};
const c = (n, owner, brand) => ({ id: "cccc0000-0000-4000-8000-" + String(n).padStart(12, "0"), owner_id: owner, email: "p" + n + "@example.com", brand });
const C = {
  confirmed: c(1, OWNER, "bizforce"), granted: c(2, OWNER, "bizforce"), revoked: c(3, OWNER, "bizforce"), none: c(4, OWNER, "bizforce"),
  confirmedSword: c(5, OWNER, "sword"), confirmedThenRevoked: c(6, OWNER, "bizforce"), grantedThenConfirmed: c(7, OWNER, "bizforce"),
  othersConfirmed: c(8, OTHER, "bizforce")
};
let ev = 0;
const consent = (contact, action) => ({ id: "e" + (++ev), contact_id: contact.id, channel: "email", action, occurred_at: String(ev).padStart(8, "0") });
function seed() {
  ev = 0;
  return {
    users: [{ id: OWNER, role: "admin" }, { id: OTHER, role: "admin" }, { id: PLAIN, role: "user" }],
    ai_tasks: [
      task(1, OWNER, STEPS), task(2, OTHER, STEPS), task(3, OWNER, STEPS, { task_type: "seo/audit" }),
      task(4, OWNER, withStep(1, { delay_days: null })), task(5, OWNER, withStep(1, { delay_days: -1 })),
      task(6, OWNER, withStep(0, { delay_days: 3 })), task(7, OWNER, STEPS, { status: "processing" }),
      task(8, OWNER, withStep(1, { subject: "  " })), task(9, OWNER, withStep(0, { body: "" }))
    ],
    contacts: Object.values(C),
    consent_events: [
      consent(C.confirmed, "granted"), consent(C.confirmed, "confirmed"),
      consent(C.granted, "granted"),
      consent(C.revoked, "granted"), consent(C.revoked, "revoked"),
      consent(C.confirmedSword, "confirmed"),
      consent(C.confirmedThenRevoked, "confirmed"), consent(C.confirmedThenRevoked, "revoked"),
      consent(C.grantedThenConfirmed, "granted"), consent(C.grantedThenConfirmed, "confirmed"),
      consent(C.othersConfirmed, "confirmed")
    ]
  };
}

/* ── the build ──────────────────────────────────────────────────────────── */
const SPIES = { resend: 0, sendEmail: 0, sendMarketingEmail: 0 };
function build(seedTables, override) {
  const db = fakeDb(seedTables, override);
  const logs = [];
  class Resend { constructor() { SPIES.resend++; this.emails = { send: async () => { SPIES.resend++; return { data: { id: "re" }, error: null }; } }; } }
  const ctx = {
    supabase: db.client, Resend, Date, JSON, Math, Promise, Number, Object, Array, String,
    nowIso: () => new Date().toISOString(),
    process: { env: {} },
    console: { log: m => logs.push(String(m)), error: m => logs.push(String(m)), warn: m => logs.push(String(m)) },
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {}, aiLimiter: function aiLimiter() {},
    sendEmail: async () => { SPIES.sendEmail++; return { sent: true }; },
    sendMarketingEmail: async () => { SPIES.sendMarketingEmail++; return { sent: true }; }
  };
  let handler = null, middleware = null;
  ctx.app = { post(p) { if (p === ROUTE) { handler = arguments[arguments.length - 1]; middleware = [].slice.call(arguments, 1, -1).map(f => f.name); } } };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function propose(user, body) {
    const res = { code: 200, body: null, error: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    await handler({ user: { id: user, role: user === PLAIN ? "user" : "admin" }, body: body || {} }, res, e => { res.error = e; res.code = 500; });
    return res;
  }
  async function execute(proposal) {
    try { return { result: await ctx.executeSendEmailSequence(JSON.parse(JSON.stringify(proposal))) }; }
    catch (e) { return { error: e }; }
  }
  return { db, logs, propose, execute, middleware };
}
const writes = (db) => db.log.filter(q => q.op !== "select");
const sameSteps = (a, b) => JSON.stringify(a) === JSON.stringify(b);

(async function main() {
  /* ── 1. the route refuses ─────────────────────────────────────────────── */
  console.log("\n══ 1. the route refuses ══");
  let b = build(seed());
  let r = await b.propose(PLAIN, { task_id: T.ok, name: "Welcome" });
  check("a non-admin: 403", r.code === 403, r.code);
  check("…saying sending is limited to the owner until subscribers can verify their own sending domain",
    /owner account/.test(r.body && r.body.error) && /verify their own sending domain/.test(r.body && r.body.error), r.body && r.body.error);
  check("…before reading anything", b.db.log.length === 0, b.db.log.length);

  const rOther = await b.propose(OWNER, { task_id: T.other, name: "Welcome" });
  const rMissing = await b.propose(OWNER, { task_id: T.missing, name: "Welcome" });
  const rMalformed = await b.propose(OWNER, { task_id: "not-a-uuid", name: "Welcome" });
  check("another user's task: 404", rOther.code === 404, rOther.code + " " + JSON.stringify(rOther.body));
  check("another user's task and a missing task: identical status and body",
    rOther.code === rMissing.code && JSON.stringify(rOther.body) === JSON.stringify(rMissing.body), JSON.stringify([rOther.body, rMissing.body]));
  check("a malformed task id: the same 404", rMalformed.code === 404 && JSON.stringify(rMalformed.body) === JSON.stringify(rMissing.body), JSON.stringify(rMalformed.body));
  const taskRead = b.db.log.find(q => q.table === "ai_tasks");
  check("the task is read scoped to the caller", taskRead && taskRead.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === OWNER),
    taskRead && JSON.stringify(taskRead.filters));

  const refusals = [
    ["a task that is not email/sequence", { task_id: T.seo, name: "W" }, /not an email sequence/],
    ["a task that is not completed", { task_id: T.processing, name: "W" }, /not completed/],
    ["a null delay", { task_id: T.nullDelay, name: "W" }, /^Step 2 has no readable delay/],
    ["a negative delay", { task_id: T.negDelay, name: "W" }, /^Step 2 has no readable delay/],
    ["a non-zero first delay", { task_id: T.firstDelay, name: "W" }, /^Step 1 must have delay_days 0/],
    ["an empty subject", { task_id: T.noSubject, name: "W" }, /^Step 2 has no subject/],
    ["an empty body", { task_id: T.noBody, name: "W" }, /^Step 1 has no body/],
    ["no name", { task_id: T.ok }, /name is required/],
    ["a name over 100 characters", { task_id: T.ok, name: "x".repeat(101) }, /name is required/],
    ["no task_id", { name: "W" }, /task_id is required/],
    ["an unknown brand", { task_id: T.ok, name: "W", brand: "nobody-has-this" }, /None of your contacts has the brand/],
    ["another owner's brand only", { task_id: T.ok, name: "W", brand: "elsewhere" }, /None of your contacts has the brand/]
  ];
  for (const [label, body, re] of refusals) {
    b = build(seed());
    r = await b.propose(OWNER, body);
    check(label + ": 400 " + re.source, r.code === 400 && re.test(r.body && r.body.error), r.code + " " + JSON.stringify(r.body));
    check(label + ": nothing filed", writes(b.db).length === 0 && b.db.tables.agent_proposals.length === 0, JSON.stringify(writes(b.db)));
  }

  b = build(seed());
  r = await b.propose(OWNER, { task_id: T.nullDelay, name: "W", steps: STEPS });
  check("a null delay with valid steps in the body: still 400 naming step 2 (body steps are not read)",
    r.code === 400 && /^Step 2 has no readable delay/.test(r.body && r.body.error), r.code + " " + JSON.stringify(r.body));

  /* ── 2. the route files ───────────────────────────────────────────────── */
  console.log("\n══ 2. the route files a proposal ══");
  b = build(seed());
  const bodySteps = [{ step: 1, delay_days: 0, subject: "FROM THE BODY", body: "injected" }];
  r = await b.propose(OWNER, { task_id: T.ok, name: "  Welcome series  ", steps: bodySteps });
  const proposal = b.db.tables.agent_proposals[0];
  check("201 with the proposal", r.code === 201 && r.body && r.body.proposal && proposal && r.body.proposal.id === proposal.id, r.code + " " + JSON.stringify(r.body));
  check("exactly one agent_proposals row, and nothing else written",
    b.db.tables.agent_proposals.length === 1 && writes(b.db).length === 1, JSON.stringify(writes(b.db).map(q => q.table)));
  check("agent_type email, action_type send_email_sequence, status pending, owned by the caller",
    proposal && proposal.agent_type === "email" && proposal.action_type === "send_email_sequence" && proposal.status === "pending" && proposal.user_id === OWNER,
    JSON.stringify(proposal));
  check("payload is exactly { name, brand, steps, source_task_id }",
    proposal && JSON.stringify(Object.keys(proposal.payload)) === JSON.stringify(["name", "brand", "steps", "source_task_id"]) &&
    proposal.payload.name === "Welcome series" && proposal.payload.brand === null && proposal.payload.source_task_id === T.ok,
    proposal && JSON.stringify(proposal.payload));
  check("the steps are the stored run's; the body's steps are ignored",
    proposal && sameSteps(proposal.payload.steps, STEPS) && !JSON.stringify(proposal).includes("FROM THE BODY"), proposal && JSON.stringify(proposal.payload.steps));
  const audience = r.body && r.body.audience_now;
  check("the measured count: 3 confirmed contacts right now (granted, revoked, none, another owner's excluded)",
    audience && audience.confirmed_contacts === 3, JSON.stringify(audience));
  check("the count is not called a send or a promise",
    audience && !Object.keys(audience).some(k => /send|sent|deliver|will/i.test(k)) && /Nothing has been sent/.test(audience.note) && !/will (be )?(sent|receive|deliver)/i.test(audience.note),
    JSON.stringify(audience));

  b = build(seed());
  r = await b.propose(OWNER, { task_id: T.ok, name: "W", brand: "bizforce" });
  check("a known brand: filed, the brand in the payload, the count 2", r.code === 201 && r.body.proposal.payload.brand === "bizforce" && r.body.audience_now.confirmed_contacts === 2,
    r.code + " " + JSON.stringify(r.body && r.body.audience_now));
  b = build(seed());
  r = await b.propose(OWNER, { task_id: T.ok, name: "W", brand: "sword" });
  check("the other brand: the count 1", r.code === 201 && r.body.audience_now.confirmed_contacts === 1, JSON.stringify(r.body && r.body.audience_now));

  /* ── 3. the executor refuses ──────────────────────────────────────────── */
  console.log("\n══ 3. the executor trusts nothing it is handed ══");
  const good = { id: "99999999-0000-4000-8000-000000000001", user_id: OWNER, agent_type: "email", action_type: "send_email_sequence", status: "executing",
    payload: { name: "Welcome", brand: null, steps: STEPS, source_task_id: T.ok } };
  const tampered = (patch) => Object.assign({}, good, { payload: Object.assign({}, good.payload, patch) });
  const executorRefusals = [
    ["a null delay", tampered({ steps: withStep(1, { delay_days: null }) }), /Step 2 has no readable delay/],
    ["a negative delay", tampered({ steps: withStep(1, { delay_days: -2 }) }), /Step 2 has no readable delay/],
    ["a string delay", tampered({ steps: withStep(1, { delay_days: "3" }) }), /Step 2 has no readable delay/],
    ["a non-zero first delay", tampered({ steps: withStep(0, { delay_days: 1 }) }), /Step 1 must have delay_days 0/],
    ["no subject", tampered({ steps: withStep(0, { subject: "" }) }), /Step 1 has no subject/],
    ["no steps", tampered({ steps: [] }), /no steps/],
    ["steps not an array", tampered({ steps: "x" }), /no steps/],
    ["a name over 100 characters", tampered({ name: "n".repeat(101) }), /name/],
    ["an owner who is no longer admin", Object.assign({}, good, { user_id: PLAIN }), /limited to the owner account/],
    ["an owner who no longer exists", Object.assign({}, good, { user_id: "dddddddd-0000-4000-8000-000000000009" }), /limited to the owner account/]
  ];
  for (const [label, prop, re] of executorRefusals) {
    b = build(seed());
    const x = await b.execute(prop);
    check("executor, " + label + ": throws " + re.source, x.error && re.test(x.error.message), x.error ? x.error.message : JSON.stringify(x.result));
    check("executor, " + label + ": creates nothing", writes(b.db).length === 0, JSON.stringify(writes(b.db).map(q => q.table)));
  }

  /* ── 4. the executor creates and enrolls ──────────────────────────────── */
  console.log("\n══ 4. the executor creates one sequence and enrolls confirmed contacts ══");
  b = build(seed());
  const t0 = Date.now();
  let x = await b.execute(good);
  check("returns { sequence_id, enrolled 3, already_enrolled 0, skipped_not_confirmed 4 }",
    x.result && JSON.stringify(Object.keys(x.result)) === JSON.stringify(["sequence_id", "enrolled", "already_enrolled", "skipped_not_confirmed"]) &&
    x.result.enrolled === 3 && x.result.already_enrolled === 0 && x.result.skipped_not_confirmed === 4,
    x.error ? x.error.message : JSON.stringify(x.result));
  const seqRow = b.db.tables.email_sequences[0];
  check("one email_sequences row: owner, proposal, source task, name, brand, steps, active, approved now",
    b.db.tables.email_sequences.length === 1 && seqRow.id === (x.result && x.result.sequence_id) && seqRow.owner_id === OWNER && seqRow.proposal_id === good.id &&
    seqRow.source_task_id === T.ok && seqRow.name === "Welcome" && seqRow.brand === null && sameSteps(seqRow.steps, STEPS) && seqRow.status === "active" &&
    Math.abs(Date.parse(seqRow.approved_at) - t0) < 60000, JSON.stringify(seqRow));
  const enrolledIds = () => b.db.tables.email_sequence_enrollments.map(e => e.contact_id).sort();
  check("enrolled exactly the confirmed contacts (granted, revoked, none and confirmed-then-revoked excluded)",
    JSON.stringify(enrolledIds()) === JSON.stringify([C.confirmed.id, C.confirmedSword.id, C.grantedThenConfirmed.id].sort()), JSON.stringify(enrolledIds()));
  check("another owner's confirmed contact is not enrolled", !enrolledIds().includes(C.othersConfirmed.id));
  check("each enrollment: next_step 0, status active, next_send_at now + steps[0].delay_days (0) days",
    b.db.tables.email_sequence_enrollments.every(e => e.sequence_id === seqRow.id && e.next_step === 0 && e.status === "active" && Math.abs(Date.parse(e.next_send_at) - t0) < 60000),
    JSON.stringify(b.db.tables.email_sequence_enrollments));

  x = await b.execute(good);
  check("run twice: one sequence", b.db.tables.email_sequences.length === 1, b.db.tables.email_sequences.length);
  check("run twice: no duplicate enrollment, the rerun reports enrolled 0, already_enrolled 3",
    b.db.tables.email_sequence_enrollments.length === 3 && x.result && x.result.sequence_id === seqRow.id && x.result.enrolled === 0 && x.result.already_enrolled === 3,
    x.error ? x.error.message : JSON.stringify(x.result) + " rows " + b.db.tables.email_sequence_enrollments.length);

  b.db.tables.contacts.push(c(10, OWNER, "bizforce"));
  b.db.tables.consent_events.push({ id: "e-late", contact_id: c(10).id, channel: "email", action: "confirmed", occurred_at: "2026-10-10" });
  x = await b.execute(good);
  check("a rerun after someone confirms enrolls only them", x.result && x.result.enrolled === 1 && x.result.already_enrolled === 3 && b.db.tables.email_sequence_enrollments.length === 4,
    JSON.stringify(x.result));

  // The enrollment pre-read misses everyone, so every insert meets the unique key.
  const blind = (q) => q.table === "email_sequence_enrollments" && q.op === "select" ? { data: [], error: null } : null;
  const bb = build(b.db.tables, blind);
  x = await bb.execute(good);
  check("a unique-key conflict is counted as already_enrolled, not thrown, and adds no row",
    !x.error && x.result.enrolled === 0 && x.result.already_enrolled === 4 && bb.db.tables.email_sequence_enrollments.length === 4,
    x.error ? x.error.message : JSON.stringify(x.result));

  b = build(seed());
  x = await b.execute(tampered({ brand: "bizforce" }));
  check("brand bizforce: only that brand's confirmed contacts", x.result && x.result.enrolled === 2 &&
    JSON.stringify(enrolledIds()) === JSON.stringify([C.confirmed.id, C.grantedThenConfirmed.id].sort()) && b.db.tables.email_sequences[0].brand === "bizforce",
    x.error ? x.error.message : JSON.stringify(enrolledIds()));
  const contactReads = b.db.log.filter(q => q.table === "contacts");
  check("the contacts read is scoped to the owner and the brand", contactReads.length > 0 && contactReads.every(q =>
    q.filters.some(f => f[0] === "eq" && f[1] === "owner_id" && f[2] === OWNER) && q.filters.some(f => f[0] === "eq" && f[1] === "brand" && f[2] === "bizforce")));

  const empty = seed(); empty.contacts = []; empty.consent_events = [];
  b = build(empty);
  x = await b.execute(good);
  check("zero confirmed contacts: the sequence is still created, enrolled 0",
    x.result && x.result.enrolled === 0 && x.result.skipped_not_confirmed === 0 && b.db.tables.email_sequences.length === 1 && b.db.tables.email_sequence_enrollments.length === 0,
    x.error ? x.error.message : JSON.stringify(x.result));

  b = build(seed(), q => q.table === "consent_events" ? { data: null, error: { message: "down" } } : null);
  x = await b.execute(good);
  check("consent unreadable: nobody is enrolled (fails closed)", x.result && x.result.enrolled === 0 && b.db.tables.email_sequence_enrollments.length === 0,
    x.error ? x.error.message : JSON.stringify(x.result));

  // The route's proposal, handed to the executor as the approve route would.
  b = build(seed());
  r = await b.propose(OWNER, { task_id: T.ok, name: "Welcome" });
  x = await b.execute(Object.assign({}, b.db.tables.agent_proposals[0], { status: "executing" }));
  check("the route's own proposal executes: enrolled matches the count it reported",
    x.result && x.result.enrolled === r.body.audience_now.confirmed_contacts && b.db.tables.email_sequences[0].proposal_id === b.db.tables.agent_proposals[0].id,
    x.error ? x.error.message : JSON.stringify(x.result));

  /* ── 5. nothing is sent ───────────────────────────────────────────────── */
  console.log("\n══ 5. nothing is sent ══");
  check("zero Resend constructions or calls across every run", SPIES.resend === 0, SPIES.resend);
  check("zero sendEmail and sendMarketingEmail calls", SPIES.sendEmail === 0 && SPIES.sendMarketingEmail === 0, JSON.stringify(SPIES));
  check("the lifted code never names Resend, sendEmail, sendMarketingEmail or email_sends",
    !/\bResend\b|\bsendEmail\(|\bsendMarketingEmail\(|"email_sends"/.test(LIFTED.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "")));
  check("server.js still calls Resend in exactly one place and sendMarketingEmail nowhere",
    (SRC.match(/\.emails\.send\(/g) || []).length === 1 && (SRC.match(/\bsendMarketingEmail\(/g) || []).length === 1);

  /* ── 6. the wiring ────────────────────────────────────────────────────── */
  console.log("\n══ 6. the wiring ══");
  check("the route has requireAuth and requireActiveSubscription, as the email tools do",
    JSON.stringify(build(seed()).middleware) === JSON.stringify(["requireAuth", "requireActiveSubscription"]) &&
    /app\.post\("\/api\/agents\/email\/sequence", requireAuth, requireActiveSubscription,/.test(SRC));
  const execStart = SRC.indexOf("const PROPOSAL_EXECUTORS = {");
  const executors = execStart < 0 ? "" : SRC.slice(execStart, s.braceMatch(SRC, SRC.indexOf("{", execStart)) + 1);
  check("PROPOSAL_EXECUTORS registers send_email_sequence: executeSendEmailSequence",
    /\n  send_email_sequence: executeSendEmailSequence\n\};$/.test(executors), executors.slice(-80));
  const gated = /const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = \[([^\]]*)\]/.exec(SRC);
  check("send_email_sequence is subscription gated at approval", gated && /"send_email_sequence"/.test(gated[1]), gated && gated[1]);
  const nonDispatch = /var CHAIN_NON_DISPATCHABLE_TOOLS = \[([^\]]*)\]/.exec(SRC);
  check("email/propose-sequence is in CHAIN_NON_DISPATCHABLE_TOOLS", nonDispatch && /"email\/propose-sequence"/.test(nonDispatch[1]), nonDispatch && nonDispatch[1]);
  const specs = definitionOf("TOOL_INPUT_SPECS") || "";
  check("TOOL_INPUT_SPECS has email/propose-sequence: task_id and name required, brand optional",
    /"email\/propose-sequence": \[\n    toolField\("task_id", "string", true,[^\n]*\n    toolField\("name", "string", true,[^\n]*\n    toolField\("brand", "string", false,[^\n]*\n  \]/.test(specs));
  check("the misleading cumulative-day comment is gone", !/stops advancing at the first unreadable delay/.test(SRC));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
