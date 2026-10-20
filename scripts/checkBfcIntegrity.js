/* ══════════════════════════════════════════════════════════════════════════
   checkBfcIntegrity.js — BizCash (BFC) is earned only by server-graded passes
   and moves only within limits.

   THE DEFECTS (launch audit, 2026-10-19)
     #3   POST /api/certifications/award believed the browser: passed and score
          came from the body, and any cert_id was accepted, so a subscriber
          could post cert_id "a1", "a2", … with passed: true and be paid 100 BFC
          for each, without limit.
     #13  POST /api/wallet/transfer had no per-transfer maximum, no daily cap
          and no new-account hold, and bfc_transfer upserted a wallet for any
          uuid, so BFC sent to an id no account had was gone.
     #18  migration 005's user_wallets_insert_own and user_wallets_update_own
          policies would let a Supabase Auth session set its own balance.

   WHAT THIS PROVES
     A. The catalogue (lib/certificationCatalog.js): 12 certifications moved
        from certifications.html unchanged, and GET /api/certifications/catalog
        serves every question WITHOUT its answer.
     B. The award route grades: passed: true with wrong answers earns nothing;
        an unknown cert_id is a 400 naming it, records nothing, credits
        nothing; a malformed answer list is a 400; body category is ignored; a
        first pass credits 100 and a second pass credits nothing.
     C. The earning bound: every catalogue certification passed, then passed
        again, then fifty invented ids, pays exactly catalogue size × the
        route's credit — 12 × 100 = 1,200 — and the comments that state the
        bound state that number.
     D. The limits parse like the other caps: absent or blank gives the
        default (1,000 / 2,000 / 7 days), an unusable value is an error naming
        the variable, a hold of 0 is allowed.
     E. Transfers, run twice:
          E1 against a model of migration 139's bfc_send (end to end, and the
             reasons the database raises mapped back to the response);
          E2 against a model of TODAY's bfc_transfer (migration 089: no
             limits, upserts any recipient), proving the ROUTE ALONE refuses
             an unknown recipient, an amount over the maximum, a send over the
             24-hour cap, a new account and a self-transfer — never reaching
             the database for any of them.
        Every refusal says its reason and moves nothing, and no wallet is ever
        created for an unknown id.
     F. Migration 139's SQL, by its text: bfc_transfer refuses an unknown
        recipient before any wallet write; bfc_send checks every limit, reads
        the 24-hour total under the sender's wallet lock, counts the same
        description the route counts, and is service_role only; the foreign
        key is guarded by an orphan count; both latent policies are dropped
        and the select policy is not.
     G. certifications.html holds no answer key, sends only cert_id and
        answers, and shows the server's result: the page's own script is run
        in a vm against stub responses, and the score and verdict on the
        result screen are the server's even when they contradict the answers.
     L. THE LEDGER INVARIANT — every wallet's balance equals its credits and
        rewards minus its debits, and no wallet lacks an account — is checked
        after every operation in B, C and E.

   ALL IN MEMORY. The routes are lifted out of server.js and run in a vm
   against in-memory tables; the libraries are loaded from their source text;
   the SQL is read as text. No database, no network, nothing written.

   MUTATIONS (MUTATE=<name>, or MUTATE=all), each applied to the lifted text:
     trust-body-passed       the route takes passed from the body again
     skip-catalogue-check    an unknown cert_id is not refused
     answers-leaked-in-get   the public catalogue carries each answer
     upsert-recipient-wallet bfc_transfer's recipient check removed from the SQL
     route-trusts-recipient  the route treats any uuid as an account
     remove-daily-cap        the route's 24-hour cap check removed
     sql-remove-daily-cap    bfc_send's 24-hour cap check removed
     route-skips-max         the route's per-transfer maximum removed
     route-skips-hold        the route's new-account hold removed
     keep-latent-policies    the migration no longer drops user_wallets_update_own
   ══════════════════════════════════════════════════════════════════════════ */

"use strict";

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const MUT = require("./_shared");
const { braceMatch } = MUT;
const REPO = path.join(__dirname, "..");
const FRONTEND = path.join(REPO, "..", "BizForce-fronyend");

const MUTATIONS = ["trust-body-passed", "skip-catalogue-check", "answers-leaked-in-get", "upsert-recipient-wallet",
  "route-trusts-recipient", "remove-daily-cap", "sql-remove-daily-cap", "route-skips-max", "route-skips-hold",
  "keep-latent-policies"];
const MUTATE = process.env.MUTATE || "";
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const lf = s => s.replace(/\r\n/g, "\n");
const SERVER = lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8"));
let CATALOG_SRC = lf(fs.readFileSync(path.join(REPO, "lib", "certificationCatalog.js"), "utf8"));
const LIMITS_SRC = lf(fs.readFileSync(path.join(REPO, "lib", "bfcTransferLimits.js"), "utf8"));
let SQL = lf(fs.readFileSync(path.join(REPO, "supabase", "migrations", "139_bfc_transfer_limits.sql"), "utf8"));
const PAGE = lf(fs.readFileSync(path.join(FRONTEND, "certifications.html"), "utf8"));
const PAGE_AT_A8B45FC = (function () {
  const { execFileSync } = require("child_process");
  return lf(execFileSync("git", ["show", "a8b45fc:certifications.html"], { cwd: FRONTEND, maxBuffer: 16 << 20 }).toString("utf8"));
})();

/* ── the code under test, lifted out of the source ──────────────────────── */
function routeSource(src, sig) {
  const start = src.indexOf(sig);
  if (start < 0 || src.indexOf(sig, start + 1) !== -1) throw new Error("expected one route " + sig);
  const end = braceMatch(src, src.indexOf("{", start + sig.length));
  if (src.slice(end, end + 2) !== ");") throw new Error("route did not end where expected: " + sig);
  return src.slice(start, end + 2);
}
function functionSource(src, name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (!m) throw new Error("function " + name + " was not found");
  return src.slice(m.index, braceMatch(src, src.indexOf(") {", m.index) + 2));
}
function blockSource(src, startText, endText) {
  const a = src.indexOf(startText);
  if (a < 0 || src.indexOf(startText, a + 1) !== -1) throw new Error("expected one " + startText);
  const b = src.indexOf(endText, a);
  if (b < 0) throw new Error("no end for " + startText);
  return src.slice(a, b + endText.length);
}

let AWARD = routeSource(SERVER, 'app.post("/api/certifications/award"');
const CATALOG_ROUTE = routeSource(SERVER, 'app.get("/api/certifications/catalog"');
let TRANSFER = routeSource(SERVER, 'app.post("/api/wallet/transfer"');
const TRANSFER_CONSTS = blockSource(SERVER, "const BFC_RECIPIENT_UUID = ", "  unknown_sender:        400\n};\n");
const HELPERS = ["nowIso", "safeText", "creditWallet"].map(n => functionSource(SERVER, n)).join("\n\n");

if (MUTATE === "trust-body-passed") {
  AWARD = MUT.replaceOnce(AWARD, "const passed   = graded.passed;", "const passed   = Boolean(req.body.passed);", MUTATE);
}
if (MUTATE === "skip-catalogue-check") {
  AWARD = MUT.replaceOnce(AWARD, "const certDef = findCertification(certId);",
    "const certDef = findCertification(certId) || Object.assign({}, findCertification(\"sales-1\"), { id: certId });", MUTATE);
}
if (MUTATE === "answers-leaked-in-get") {
  CATALOG_SRC = MUT.replaceOnce(CATALOG_SRC, "return { q: q.q, opts: q.opts.slice() };", "return { q: q.q, opts: q.opts.slice(), ans: q.ans };", MUTATE);
}
if (MUTATE === "upsert-recipient-wallet") {
  SQL = MUT.replaceOnce(SQL,
    "if not exists (select 1 from users where id = p_to) then\nraise exception 'unknown_recipient: no account has the id %', p_to;\nend if;\n\nselect balance into cur",
    "select balance into cur", MUTATE);
}
if (MUTATE === "route-trusts-recipient") {
  TRANSFER = MUT.replaceOnce(TRANSFER, "recipient = found.data;", "recipient = found.data || { id: recipientId };", MUTATE);
}
if (MUTATE === "remove-daily-cap") {
  TRANSFER = MUT.replaceOnce(TRANSFER, "if (sentLast24h + amount > limits.dailyCap) {", "if (false) {", MUTATE);
}
if (MUTATE === "sql-remove-daily-cap") {
  SQL = MUT.replaceOnce(SQL,
    "if v_sent + p_amount > p_daily_cap then\nraise exception 'over_daily_cap: % BFC sent in the last 24 hours, and % more would pass the % BFC cap', v_sent, p_amount, p_daily_cap;\nend if;\n",
    "", MUTATE);
}
if (MUTATE === "route-skips-max") {
  TRANSFER = MUT.replaceOnce(TRANSFER, "if (amount > limits.max) {", "if (false) {", MUTATE);
}
if (MUTATE === "route-skips-hold") {
  TRANSFER = MUT.replaceOnce(TRANSFER, "if (!(Date.now() >= sendableFromMs)) {", "if (false) {", MUTATE);
}
if (MUTATE === "keep-latent-policies") {
  SQL = MUT.replaceOnce(SQL, "drop policy if exists user_wallets_update_own on public.user_wallets;\n", "", MUTATE);
}

function loadModule(src) {
  const mod = { exports: {} };
  new Function("module", "exports", "require", src)(mod, mod.exports, function () { throw new Error("no require here"); });
  return mod.exports;
}
const CATALOG = loadModule(CATALOG_SRC);
const LIMITS = loadModule(LIMITS_SRC);

/* ── in-memory tables, and a client that speaks enough supabase-js ──────── */
let idSeq = 1;
const nextId = () => "row-" + (idSeq++);

function makeDb() {
  return { users: [], user_wallets: [], wallet_transactions: [], user_certifications: [] };
}

class Query {
  constructor(client, table) { this.client = client; this.table = table; this.op = "select"; this.filters = []; }
  select() { return this; }
  insert(row) { this.op = "insert"; this.row = row; return this; }
  update(patch) { this.op = "update"; this.patch = patch; return this; }
  eq(col, val) { this.filters.push(r => r[col] === val); return this; }
  gte(col, val) { this.filters.push(r => r[col] >= val); return this; }
  order() { return this; }
  limit() { return this; }
  run() {
    const db = this.client.db;
    const rows = db[this.table];
    if (!rows) return { data: null, error: { message: "relation " + this.table + " does not exist" } };
    this.client.reads.push(this.table + ":" + this.op);
    if (this.op === "insert") {
      if (this.table === "user_certifications" &&
          rows.some(r => r.user_id === this.row.user_id && r.cert_id === this.row.cert_id)) {
        return { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint" } };
      }
      const row = Object.assign({ id: nextId() }, this.row);
      rows.push(row);
      return { data: [Object.assign({}, row)], error: null };
    }
    const matched = rows.filter(r => this.filters.every(f => f(r)));
    if (this.op === "update") {
      matched.forEach(r => Object.assign(r, this.patch));
      return { data: matched.map(r => Object.assign({}, r)), error: null };
    }
    if (this.table === "wallet_transactions" && this.client.staleTransactionReads > 0) {
      this.client.staleTransactionReads--;
      return { data: [], error: null };
    }
    return { data: matched.map(r => Object.assign({}, r)), error: null };
  }
  single() {
    const r = this.run();
    if (r.error) return Promise.resolve(r);
    if (r.data.length !== 1) return Promise.resolve({ data: null, error: { code: "PGRST116", message: r.data.length + " rows" } });
    return Promise.resolve({ data: r.data[0], error: null });
  }
  maybeSingle() {
    const r = this.run();
    if (r.error) return Promise.resolve(r);
    if (r.data.length > 1) return Promise.resolve({ data: null, error: { code: "PGRST116", message: r.data.length + " rows" } });
    return Promise.resolve({ data: r.data[0] || null, error: null });
  }
  then(resolve, reject) { return Promise.resolve(this.run()).then(resolve, reject); }
}

function makeClient(db, rpcModels) {
  const client = {
    db: db, reads: [], rpcCalls: [], staleTransactionReads: 0,
    from: table => new Query(client, table),
    rpc: async function (name, args) {
      client.rpcCalls.push(name);
      const model = rpcModels[name];
      if (!model) return { data: null, error: { code: "PGRST202", message: "Could not find the function public." + name + " in the schema cache" } };
      try { return { data: model(db, args), error: null }; }
      catch (e) { return { data: null, error: { message: e.message } }; }
    }
  };
  return client;
}

/* ── the database functions, modelled ────────────────────────────────────── */
function walletOf(db, userId) { return db.user_wallets.find(w => w.user_id === userId) || null; }
function ledger(db, userId, type, amount, description) {
  db.wallet_transactions.push({ id: nextId(), user_id: userId, type: type, amount: amount, description: description, created_at: new Date().toISOString() });
}
function bfcCreditModel(db, a) {           // migration 121
  if (!(a.p_amount > 0)) throw new Error("amount must be positive");
  let w = walletOf(db, a.p_user_id);
  if (!w) { w = { id: nextId(), user_id: a.p_user_id, balance: 0 }; db.user_wallets.push(w); }
  w.balance += a.p_amount;
  ledger(db, a.p_user_id, a.p_type, a.p_amount, a.p_description || "");
  return w.balance;
}
// bfc_transfer. checkRecipient: migration 139 (true) or 089, as in production today (false).
function bfcTransferModel(db, from, to, amount, description, checkRecipient) {
  if (from === to) throw new Error("cannot transfer to self");
  if (!(amount > 0)) throw new Error("amount must be positive");
  if (checkRecipient && !db.users.some(u => u.id === to)) throw new Error("unknown_recipient: no account has the id " + to);
  const fw = walletOf(db, from);
  if (!fw) throw new Error("sender wallet not found");
  if (fw.balance < amount) throw new Error("insufficient balance");
  fw.balance -= amount;
  let tw = walletOf(db, to);
  if (!tw) { tw = { id: nextId(), user_id: to, balance: 0 }; db.user_wallets.push(tw); }
  tw.balance += amount;
  ledger(db, from, "debit", amount, description);
  ledger(db, to, "credit", amount, description);
  return fw.balance;
}
const DAY_MS = 24 * 60 * 60 * 1000;
function bfcSendModel139(db, a) {          // migration 139's bfc_send
  if (!(a.p_max_per_transfer >= 1 && a.p_daily_cap >= 1 && a.p_hold_days >= 0)) throw new Error("limits_invalid: every transfer limit must be given");
  if (a.p_from === a.p_to) throw new Error("cannot transfer to self");
  if (!(a.p_amount > 0)) throw new Error("amount must be positive");
  if (a.p_amount > a.p_max_per_transfer) throw new Error("over_per_transfer_max: too much for one transfer");
  if (!db.users.some(u => u.id === a.p_to)) throw new Error("unknown_recipient: no account has the id " + a.p_to);
  const sender = db.users.find(u => u.id === a.p_from);
  if (!sender) throw new Error("unknown_sender: no account has the id " + a.p_from);
  if (Date.parse(sender.created_at) > Date.now() - a.p_hold_days * DAY_MS) throw new Error("new_account_hold: too new");
  const since = new Date(Date.now() - DAY_MS).toISOString();
  const sent = db.wallet_transactions.filter(t => t.user_id === a.p_from && t.type === "debit" && t.description === "Transfer" && t.created_at > since)
    .reduce((n, t) => n + t.amount, 0);
  if (sent + a.p_amount > a.p_daily_cap) throw new Error("over_daily_cap: " + sent + " BFC sent in the last 24 hours");
  return bfcTransferModel(db, a.p_from, a.p_to, a.p_amount, "Transfer", true);
}
// What the route would reach if migration 139 were never applied and bfc_send were today's bfc_transfer.
function bfcSendModel089(db, a) {
  return bfcTransferModel(db, a.p_from, a.p_to, a.p_amount, "Transfer", false);
}

/* ── THE LEDGER INVARIANT ────────────────────────────────────────────────── */
function invariant(db, label) {
  const problems = [];
  db.user_wallets.forEach(function (w) {
    const sum = db.wallet_transactions.filter(t => t.user_id === w.user_id)
      .reduce((n, t) => n + (t.type === "debit" ? -t.amount : t.amount), 0);
    if (sum !== w.balance) problems.push(w.user_id + " balance " + w.balance + " vs ledger " + sum);
    if (w.balance < 0) problems.push(w.user_id + " negative");
    if (!db.users.some(u => u.id === w.user_id)) problems.push("wallet for " + w.user_id + " which is no account");
  });
  check("L. ledger invariant after " + label, problems.length === 0, problems.join("; "));
}

/* ── the routes, built in a vm against a client ──────────────────────────── */
function buildRoutes(client, env) {
  const routes = {};
  const capture = verb => function (p) { routes[verb + " " + p] = arguments[arguments.length - 1]; };
  const ctx = {
    supabase: client,
    console: { log() {}, warn() {}, error() {} },
    process: { env: env || {} },
    requireAuth: 0, requireActiveSubscription: 0,
    getUserPlan: async function () { return { active: true, plan: "all_access", inactive_reason: null }; },
    BILLING_URL: "/billing.html",
    CERTIFICATION_PASS_MARK: CATALOG.CERTIFICATION_PASS_MARK,
    findCertification: CATALOG.findCertification,
    gradeCertification: CATALOG.gradeCertification,
    publicCertificationCatalog: CATALOG.publicCertificationCatalog,
    bfcTransferLimits: LIMITS.bfcTransferLimits,
    BFC_TRANSFER_DESCRIPTION: LIMITS.BFC_TRANSFER_DESCRIPTION,
    app: { get: capture("get"), post: capture("post") }
  };
  vm.createContext(ctx);
  vm.runInContext([HELPERS, TRANSFER_CONSTS, CATALOG_ROUTE, AWARD, TRANSFER].join("\n\n"), ctx);
  return routes;
}

async function call(handler, user, body) {
  const res = {
    statusCode: 200, body: undefined,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; }
  };
  let nextErr = null;
  await handler({ user: user, body: body || {} }, res, e => { nextErr = e || new Error("next() called"); });
  if (nextErr) { res.statusCode = 500; res.body = { error: String(nextErr.message || nextErr) }; }
  return res;
}

const daysAgo = d => new Date(Date.now() - d * DAY_MS).toISOString();
const uuid = n => "00000000-0000-4000-8000-" + String(n).padStart(12, "0");
const balanceOf = (db, id) => { const w = walletOf(db, id); return w ? w.balance : 0; };
const correctAnswers = cert => cert.questions.map(q => q.ans);
const wrongAnswers = cert => cert.questions.map(q => (q.ans + 1) % q.opts.length);

(async function main() {
  console.log("\n══ handler under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "server.js as it stands") + " ══");

  /* ── A. the catalogue, and the GET without answers ─────────────────────── */
  console.log("\n══ A. the catalogue and GET /api/certifications/catalog ══");
  const certs = CATALOG.CERTIFICATIONS;
  const pageData = (function () {
    const a = PAGE_AT_A8B45FC.indexOf("var CERTS = ["), b = PAGE_AT_A8B45FC.indexOf("/* ── Category styles ── */");
    const ctx = {};
    vm.createContext(ctx);
    vm.runInContext(PAGE_AT_A8B45FC.slice(a, b).replace(/var (CERTS|QUESTIONS) =/g, "this.$1 ="), ctx);
    return ctx.CERTS.map(c => ({ id: c.id, category: c.category, name: c.name, desc: c.desc, difficulty: c.difficulty,
      questions: ctx.QUESTIONS[c.id].map(q => ({ q: q.q, opts: q.opts, ans: q.ans })) }));
  })();
  check("A1. the catalogue is the 12 certifications and 120 questions certifications.html held at a8b45fc, unchanged",
    certs.length === 12 && JSON.stringify(certs) === JSON.stringify(pageData),
    certs.length + " certifications; equal to the page's: " + (JSON.stringify(certs) === JSON.stringify(pageData)));
  check("A2. the pass mark is the page's 80", CATALOG.CERTIFICATION_PASS_MARK === 80, CATALOG.CERTIFICATION_PASS_MARK);

  {
    const db = makeDb();
    const routes = buildRoutes(makeClient(db, {}), {});
    const res = await call(routes["get /api/certifications/catalog"], { id: uuid(1) });
    const served = JSON.stringify(res.body);
    const keys = new Set();
    (function walk(v) {
      if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === "object") Object.keys(v).forEach(k => { keys.add(k); walk(v[k]); });
    })(res.body);
    console.log("    served keys: " + [...keys].sort().join(", ") + " (" + served.length + " chars)");
    check("A3. the GET serves every certification and every question", res.statusCode === 200 && res.body.certifications.length === 12 &&
      res.body.certifications.every((c, i) => c.id === certs[i].id && c.questions.length === certs[i].questions.length && c.question_count === certs[i].questions.length),
      res.statusCode);
    check("A4. and no answer: no key named ans, answer or correct anywhere in the response",
      !keys.has("ans") && !keys.has("answer") && !keys.has("correct"), [...keys].join(","));
    check("A5. each question is exactly its text and its options",
      res.body.certifications.every(c => c.questions.every(q => JSON.stringify(Object.keys(q)) === '["q","opts"]')));
    check("A6. and says the pass mark", res.body.pass_mark === 80, res.body.pass_mark);
  }

  /* ── B. the award route grades ───────────────────────────────────────────── */
  console.log("\n══ B. POST /api/certifications/award grades the answers itself ══");
  {
    const db = makeDb();
    const user = { id: uuid(10) };
    db.users.push({ id: user.id, created_at: daysAgo(100) });
    const routes = buildRoutes(makeClient(db, { bfc_credit: bfcCreditModel }), {});
    const award = routes["post /api/certifications/award"];
    const sales1 = CATALOG.findCertification("sales-1");

    const lie = await call(award, user, { cert_id: "sales-1", answers: wrongAnswers(sales1), passed: true, score: 100, category: "Sales" });
    console.log("    passed:true, score:100, wrong answers → HTTP " + lie.statusCode + " " + JSON.stringify(lie.body.result));
    check("B1. passed: true with wrong answers earns nothing", balanceOf(db, user.id) === 0 && lie.body.credited === false &&
      lie.body.result && lie.body.result.passed === false && lie.body.result.score === 0, JSON.stringify(lie.body));
    check("B1. and the record is a fail, not an earned certification",
      db.user_certifications.length === 1 && db.user_certifications[0].passed === false && db.user_certifications[0].score === 0,
      JSON.stringify(db.user_certifications));
    invariant(db, "a lying pass");

    const unknown = await call(award, user, { cert_id: "a1", answers: [0, 0, 0], passed: true, score: 100, category: "Sales" });
    console.log("    cert_id \"a1\" → HTTP " + unknown.statusCode + " " + JSON.stringify(unknown.body));
    check("B2. an unknown cert_id is a 400 that names it", unknown.statusCode === 400 && /"a1"/.test(unknown.body.error || ""), JSON.stringify(unknown.body));
    check("B2. and records nothing and credits nothing",
      db.user_certifications.length === 1 && balanceOf(db, user.id) === 0 && db.wallet_transactions.length === 0);
    invariant(db, "an unknown cert_id");

    const malformed = [
      ["a string", "abc"], ["too few answers", [1, 1]], ["an option out of range", correctAnswers(sales1).map((a, i) => i === 3 ? 9 : a)],
      ["a non-integer option", correctAnswers(sales1).map((a, i) => i === 0 ? "1" : a)], ["no answers at all", undefined]
    ];
    for (const [what, answers] of malformed) {
      const r = await call(award, user, { cert_id: "sales-2", answers: answers, passed: true, score: 100 });
      check("B3. a malformed answer list (" + what + ") is a 400 and records nothing",
        r.statusCode === 400 && !db.user_certifications.some(c => c.cert_id === "sales-2"), r.statusCode + " " + JSON.stringify(r.body));
    }

    const first = await call(award, user, { cert_id: "sales-1", answers: correctAnswers(sales1), category: "Hacked", score: 1, passed: false });
    console.log("    correct answers, body says passed:false score:1 → HTTP " + first.statusCode + " " + JSON.stringify(first.body.result));
    check("B4. a first server-graded pass credits 100, whatever the body claims", first.statusCode === 201 && first.body.credited === true &&
      balanceOf(db, user.id) === 100 && first.body.result.passed === true && first.body.result.score === 100, JSON.stringify(first.body));
    check("B5. the category stored is the catalogue's, not the body's",
      db.user_certifications.find(c => c.cert_id === "sales-1").category === "Sales", db.user_certifications.find(c => c.cert_id === "sales-1").category);
    invariant(db, "a first pass");

    const again = await call(award, user, { cert_id: "sales-1", answers: correctAnswers(sales1) });
    check("B6. a second pass of the same certification credits nothing", again.body.already_earned === true && again.body.credited === false &&
      balanceOf(db, user.id) === 100 && db.wallet_transactions.length === 1, JSON.stringify(again.body));
    invariant(db, "a second pass");

    check("B7. the response carries no per-question marks", first.body.result &&
      JSON.stringify(Object.keys(first.body.result).sort()) === JSON.stringify(["correct", "pass_mark", "passed", "score", "total"]),
      JSON.stringify(first.body.result));
  }

  /* ── C. the earning bound ────────────────────────────────────────────────── */
  console.log("\n══ C. the most certifications can ever pay one account ══");
  {
    const db = makeDb();
    const user = { id: uuid(20) };
    db.users.push({ id: user.id, created_at: daysAgo(100) });
    const routes = buildRoutes(makeClient(db, { bfc_credit: bfcCreditModel }), {});
    const award = routes["post /api/certifications/award"];
    const credit = Number((/await creditWallet\(req\.user\.id, (\d+), "Certification earned: " \+ certId\);/.exec(AWARD) || [])[1]);
    const bound = certs.length * credit;

    for (const c of certs) await call(award, user, { cert_id: c.id, answers: correctAnswers(c) });
    const afterAll = balanceOf(db, user.id);
    invariant(db, "every certification passed");
    for (const c of certs) await call(award, user, { cert_id: c.id, answers: correctAnswers(c) });
    invariant(db, "every certification passed again");
    let refused = 0;
    for (let i = 0; i < 50; i++) {
      const r = await call(award, user, { cert_id: "invented-" + i, answers: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1], passed: true, score: 100 });
      if (r.statusCode === 400) refused++;
    }
    invariant(db, "fifty invented ids");
    const total = balanceOf(db, user.id);
    console.log("    credit per certification " + credit + " × " + certs.length + " certifications = " + bound +
      "; paid after all twelve " + afterAll + ", after repeats and 50 invented ids " + total + " (" + refused + " of 50 refused)");
    check("C1. all twelve passed pays exactly the bound, 12 × 100 = 1,200", credit === 100 && afterAll === bound && bound === 1200, afterAll);
    check("C2. passing them all again, and fifty invented ids, pays nothing more", total === bound && refused === 50, total + ", " + refused);
    check("C3. the route's comment states the same bound", /12 × 100 = 1,200 today/.test(AWARD) && certs.length === 12);
    check("C4. and so does the catalogue's", /12 × 100\n\/\/ = 1,200 BFC today/.test(CATALOG_SRC));
  }

  /* ── D. the limits parse like the other caps ─────────────────────────────── */
  console.log("\n══ D. BFC_TRANSFER_MAX, BFC_TRANSFER_DAILY_CAP, BFC_TRANSFER_HOLD_DAYS ══");
  {
    const L = LIMITS.bfcTransferLimits;
    const d = L({});
    check("D1. absent gives the defaults: 1,000 per transfer, 2,000 per 24 hours, a 7-day hold",
      d.max === 1000 && d.dailyCap === 2000 && d.holdDays === 7 && d.error === null, JSON.stringify(d));
    const blank = L({ BFC_TRANSFER_MAX: " ", BFC_TRANSFER_DAILY_CAP: "", BFC_TRANSFER_HOLD_DAYS: "" });
    check("D2. blank gives the defaults", blank.max === 1000 && blank.dailyCap === 2000 && blank.holdDays === 7 && !blank.error, JSON.stringify(blank));
    const set = L({ BFC_TRANSFER_MAX: "250", BFC_TRANSFER_DAILY_CAP: " 500 ", BFC_TRANSFER_HOLD_DAYS: "0" });
    check("D3. whole numbers are honoured, and a hold of 0 turns the hold off", set.max === 250 && set.dailyCap === 500 && set.holdDays === 0 && !set.error, JSON.stringify(set));
    for (const [name, value] of [["BFC_TRANSFER_MAX", "abc"], ["BFC_TRANSFER_MAX", "0"], ["BFC_TRANSFER_DAILY_CAP", "2.5"], ["BFC_TRANSFER_DAILY_CAP", "-1"], ["BFC_TRANSFER_HOLD_DAYS", "-1"], ["BFC_TRANSFER_HOLD_DAYS", "1e9x"]]) {
      const r = L({ [name]: value });
      check("D4. " + name + "=\"" + value + "\" is an error that names the variable", r.error && r.error.indexOf(name) === 0, JSON.stringify(r));
    }
  }

  /* ── E. transfers ────────────────────────────────────────────────────────── */
  for (const model of ["139", "089"]) {
    const routeAlone = model === "089";
    console.log("\n══ E" + (routeAlone ? "2" : "1") + ". POST /api/wallet/transfer against " +
      (routeAlone ? "TODAY's bfc_transfer (migration 089: no limits, upserts any recipient) — the route alone must refuse" : "migration 139's bfc_send") + " ══");
    const tag = "E" + (routeAlone ? "2" : "1") + ". ";
    const db = makeDb();
    const client = makeClient(db, { bfc_credit: bfcCreditModel, bfc_send: routeAlone ? bfcSendModel089 : bfcSendModel139 });
    const alice = { id: uuid(31) }, bob = { id: uuid(32) }, newbie = { id: uuid(33) }, ghost = uuid(99);
    db.users.push({ id: alice.id, created_at: daysAgo(30) }, { id: bob.id, created_at: daysAgo(30) }, { id: newbie.id, created_at: daysAgo(2) });
    bfcCreditModel(db, { p_user_id: alice.id, p_amount: 5000, p_type: "reward", p_description: "fixture" });
    bfcCreditModel(db, { p_user_id: newbie.id, p_amount: 1000, p_type: "reward", p_description: "Welcome bonus" });
    invariant(db, tag + "the fixture");
    const routes = buildRoutes(client, {});
    const send = (user, to, amount) => call(routes["post /api/wallet/transfer"], user, { recipientId: to, amount: amount });

    const refused = async function (label, user, to, amount, status, reason) {
      const before = JSON.stringify([db.user_wallets, db.wallet_transactions]);
      const rpcBefore = client.rpcCalls.length;
      const r = await send(user, to, amount);
      console.log("    " + label + " → HTTP " + r.statusCode + " " + JSON.stringify(r.body));
      check(tag + label + ": refused " + status + " with reason " + reason, r.statusCode === status && r.body.reason === reason, r.statusCode + " " + JSON.stringify(r.body));
      check(tag + label + ": the refusal says nothing was sent", /Nothing was sent|Invalid recipient/.test(r.body.error || ""), r.body.error);
      check(tag + label + ": no balance, wallet or ledger row changed", JSON.stringify([db.user_wallets, db.wallet_transactions]) === before);
      check(tag + label + ": decided by the route, without reaching the database function", client.rpcCalls.length === rpcBefore,
        client.rpcCalls.slice(rpcBefore).join(","));
      invariant(db, tag + label);
    };

    const ok1 = await send(alice, bob.id, 500);
    check(tag + "a transfer within every limit goes through", ok1.statusCode === 200 && ok1.body.balance === 4500 && balanceOf(db, bob.id) === 500,
      ok1.statusCode + " " + JSON.stringify(ok1.body));
    check(tag + "and writes the debit and the credit under \"Transfer\"",
      db.wallet_transactions.filter(t => t.description === "Transfer").map(t => t.type + ":" + t.amount).join(",") === "debit:500,credit:500");
    invariant(db, tag + "a transfer");

    await refused("to an unknown account id", alice, ghost, 10, 404, "unknown_recipient");
    check(tag + "and no wallet was created for that id", !walletOf(db, ghost));
    await refused("to an id that is not a uuid", alice, "not-a-user", 10, 404, "unknown_recipient");
    await refused("over the per-transfer maximum (1,001)", alice, bob.id, 1001, 400, "over_per_transfer_max");
    await refused("from an account opened 2 days ago", newbie, bob.id, 10, 403, "new_account_hold");
    await refused("to oneself", alice, alice.id, 10, 400, "self_transfer");

    const ok2 = await send(alice, bob.id, 1000);
    check(tag + "1,000 more in the same 24 hours fits (1,500 of 2,000)", ok2.statusCode === 200, ok2.statusCode + " " + JSON.stringify(ok2.body));
    invariant(db, tag + "a second transfer");
    await refused("600 more, past the 2,000 cap", alice, bob.id, 600, 400, "over_daily_cap");
    const ok3 = await send(alice, bob.id, 500);
    check(tag + "exactly up to the cap (2,000) is allowed", ok3.statusCode === 200, ok3.statusCode + " " + JSON.stringify(ok3.body));
    invariant(db, tag + "a transfer up to the cap");
    await refused("1 BFC past the cap", alice, bob.id, 1, 400, "over_daily_cap");
    const over = db.wallet_transactions.filter(t => t.user_id === alice.id && t.type === "debit" && t.description === "Transfer").reduce((n, t) => n + t.amount, 0);
    check(tag + "the sender's 24-hour total ends at the cap, not past it", over === 2000, over);

    // A misconfigured limit stops transfers rather than lifting the limit.
    const badRoutes = buildRoutes(client, { BFC_TRANSFER_MAX: "abc" });
    const rpcBefore = client.rpcCalls.length;
    const before = JSON.stringify(db.user_wallets);
    const bad = await call(badRoutes["post /api/wallet/transfer"], bob, { recipientId: alice.id, amount: 1 });
    check(tag + "an unusable BFC_TRANSFER_MAX refuses every transfer with a message naming it",
      bad.statusCode === 503 && bad.body.reason === "limits_misconfigured" && /BFC_TRANSFER_MAX/.test(bad.body.error) &&
      JSON.stringify(db.user_wallets) === before && client.rpcCalls.length === rpcBefore, bad.statusCode + " " + JSON.stringify(bad.body));
    invariant(db, tag + "a misconfigured limit");

    if (!routeAlone) {
      // Two transfers at once: the route read a total that was already out of date,
      // and bfc_send, counting under the lock, refuses. Its reason reaches the response.
      client.staleTransactionReads = 1;
      const raced = await send(alice, bob.id, 100);
      console.log("    the route's 24-hour read was stale → HTTP " + raced.statusCode + " " + JSON.stringify(raced.body));
      check(tag + "when the route's read is stale, bfc_send's cap refuses, and the reason is over_daily_cap",
        raced.statusCode === 400 && raced.body.reason === "over_daily_cap" && client.rpcCalls[client.rpcCalls.length - 1] === "bfc_send", JSON.stringify(raced.body));
      check(tag + "and the person reads a sentence, not the database's reason code",
        /^\d+ BFC sent in the last 24 hours\. Nothing was sent\.$/.test(raced.body.error || ""), raced.body.error);
      invariant(db, tag + "a raced transfer");

      const carol = { id: uuid(34) };
      db.users.push({ id: carol.id, created_at: daysAgo(30) });
      bfcCreditModel(db, { p_user_id: carol.id, p_amount: 50, p_type: "reward", p_description: "fixture" });
      const walletsBefore = JSON.stringify(db.user_wallets);
      const poor = await send(carol, alice.id, 100);
      console.log("    100 BFC from a wallet holding 50 → HTTP " + poor.statusCode + " " + JSON.stringify(poor.body));
      check(tag + "more than the balance is refused as insufficient_balance, and nothing moves",
        poor.statusCode === 400 && poor.body.reason === "insufficient_balance" && JSON.stringify(db.user_wallets) === walletsBefore,
        poor.statusCode + " " + JSON.stringify(poor.body));
      invariant(db, tag + "a balance check");

      const noFn = buildRoutes(makeClient(db, { bfc_credit: bfcCreditModel }), {});
      const missing = await call(noFn["post /api/wallet/transfer"], bob, { recipientId: alice.id, amount: 1 });
      check(tag + "before migration 139 is applied, a transfer is a 503 naming it, and nothing moves",
        missing.statusCode === 503 && missing.body.reason === "migration_139_not_applied", JSON.stringify(missing.body));
      invariant(db, tag + "a missing bfc_send");
    }
  }

  /* ── F. migration 139, by its text ───────────────────────────────────────── */
  console.log("\n══ F. supabase/migrations/139_bfc_transfer_limits.sql ══");
  {
    const fnBody = name => {
      const a = SQL.indexOf("CREATE OR REPLACE FUNCTION public." + name + "(");
      if (a < 0) return "";
      const open = SQL.indexOf("AS $function$", a);
      return SQL.slice(open, SQL.indexOf("$function$;", open + 14));
    };
    const transfer = fnBody("bfc_transfer"), sendFn = fnBody("bfc_send");
    const guard = "if not exists (select 1 from users where id = p_to) then\nraise exception 'unknown_recipient:";
    const gi = transfer.indexOf(guard), firstWalletWrite = transfer.search(/update user_wallets|insert into user_wallets/);
    check("F1. bfc_transfer refuses a recipient with no users row, before any wallet write",
      gi !== -1 && firstWalletWrite !== -1 && gi < firstWalletWrite && transfer.indexOf("raise exception 'cannot transfer to self'") !== -1,
      "guard at " + gi + ", first wallet write at " + firstWalletWrite);
    check("F2. bfc_send refuses an unknown recipient too", sendFn.indexOf(guard) !== -1);
    check("F3. bfc_send refuses more than p_max_per_transfer",
      /if p_amount > p_max_per_transfer then\nraise exception 'over_per_transfer_max:/.test(sendFn));
    check("F4. bfc_send holds an account opened within p_hold_days",
      /select created_at into v_created from users where id = p_from;/.test(sendFn) &&
      /if v_created > now\(\) - make_interval\(days => p_hold_days\) then\nraise exception 'new_account_hold:/.test(sendFn));
    const lock = sendFn.indexOf("perform 1 from user_wallets where user_id = p_from for update;");
    const sum = sendFn.indexOf("select coalesce(sum(amount), 0) into v_sent");
    check("F5. bfc_send takes the sender's wallet lock before it reads the 24-hour total", lock !== -1 && sum !== -1 && lock < sum, lock + " < " + sum);
    check("F6. the total counts the sender's 'Transfer' debits in the last 24 hours, the same description the route counts",
      /where user_id = p_from\n  and type = 'debit'\n  and description = 'Transfer'\n  and created_at > now\(\) - interval '24 hours';/.test(sendFn) &&
      LIMITS.BFC_TRANSFER_DESCRIPTION === "Transfer" && /\.eq\("description", BFC_TRANSFER_DESCRIPTION\)/.test(TRANSFER));
    check("F7. bfc_send refuses a send that would pass p_daily_cap",
      /if v_sent \+ p_amount > p_daily_cap then\nraise exception 'over_daily_cap:/.test(sendFn));
    check("F8. bfc_send refuses itself when a limit is missing, and then moves BFC only through bfc_transfer under 'Transfer'",
      /raise exception 'limits_invalid:/.test(sendFn) && /return bfc_transfer\(p_from, p_to, p_amount, 'Transfer'\);/.test(sendFn) &&
      !/insert into user_wallets|update user_wallets/.test(sendFn));
    check("F9. bfc_send is service_role only",
      /revoke execute on function public\.bfc_send\(uuid, uuid, integer, integer, integer, integer\) from public, anon, authenticated;/.test(SQL) &&
      /grant  execute on function public\.bfc_send\(uuid, uuid, integer, integer, integer, integer\) to service_role;/.test(SQL));
    const raised = (SQL.match(/raise exception '([a-z_]+):/g) || []).map(s => s.slice(17, -1));
    const mapped = Object.keys(new Function(TRANSFER_CONSTS + "\nreturn BFC_SEND_REFUSAL_STATUS;")());
    check("F10. every reason the SQL raises is one the route maps to a status",
      raised.length > 0 && raised.every(r => mapped.indexOf(r) !== -1), "raised " + [...new Set(raised)].join(",") + " / mapped " + mapped.join(","));
    check("F11. the foreign key is added only when no wallet lacks an account",
      /select count\(\*\) into v_orphans\s+from user_wallets w\s+where not exists \(select 1 from users u where u\.id = w\.user_id\);\s+if v_orphans > 0 then\s+raise notice[^;]*;\s+else\s+alter table public\.user_wallets\s+add constraint user_wallets_user_id_fkey\s+foreign key \(user_id\) references public\.users\(id\);/.test(SQL));
    check("F12. both latent auth.uid() write policies are dropped",
      /\ndrop policy if exists user_wallets_insert_own on public\.user_wallets;\n/.test(SQL) &&
      /\ndrop policy if exists user_wallets_update_own on public\.user_wallets;\n/.test(SQL));
    check("F13. and the select policy is not", !/drop policy[^;]*user_wallets_select_own/i.test(SQL));
    check("F14. the route calls bfc_send with every limit", /rpc\("bfc_send", \{\s*p_from: req\.user\.id,\s*p_to: recipient\.id,\s*p_amount: amount,\s*p_max_per_transfer: limits\.max,\s*p_daily_cap: limits\.dailyCap,\s*p_hold_days: limits\.holdDays\s*\}\)/.test(TRANSFER));
  }

  /* ── G. the page shows the server's result ───────────────────────────────── */
  console.log("\n══ G. certifications.html ══");
  {
    check("G1. the page holds no answer key and no question bank",
      !/\bans\s*:/.test(PAGE) && PAGE.indexOf("QUESTIONS") === -1 && certs.every(c => PAGE.indexOf(c.questions[0].q.slice(0, 30)) === -1));
    check("G2. it loads the catalogue from the server", /authFetch\("\/api\/certifications\/catalog"\)/.test(PAGE));
    check("G3. and sends only cert_id and answers",
      /body: JSON\.stringify\(\{cert_id: cert\.id, answers: answers\}\)/.test(PAGE) && !/passed: passed|score: pct/.test(PAGE));

    const script = /<script>\n(var API_URL[\s\S]*?)<\/script>/.exec(PAGE)[1];
    const els = {};
    const el = id => els[id] || (els[id] = {
      id: id, textContent: "", innerHTML: "", className: "", style: {}, children: [],
      classList: { add() {}, remove() {} }, addEventListener() {}, appendChild(c) { this.children.push(c); },
      querySelectorAll() { return []; }, getAttribute() { return null; }
    });
    const pending = [];
    const fetchCalls = [];
    const doc = {
      getElementById: el, querySelectorAll() { return []; }, addEventListener() {},
      body: { style: {} }, createElement() { return el("created-" + Math.random()); }
    };
    const pubCatalog = CATALOG.publicCertificationCatalog();
    const ctx = {
      document: doc, window: {}, console: { log() {}, error() {} },
      localStorage: { getItem() { return "t"; } },
      Set: Set, Promise: Promise, JSON: JSON, Math: Math, Array: Array, Object: Object,
      fetch: function (url, opts) {
        fetchCalls.push({ url: url, opts: opts });
        if (/\/catalog$/.test(url)) return Promise.resolve({ ok: true, status: 200, json: async () => ({ pass_mark: 80, certifications: pubCatalog }) });
        if (/\/earned$/.test(url)) return Promise.resolve({ ok: true, status: 200, json: async () => ({ certifications: [] }) });
        return new Promise(resolve => pending.push(resolve));
      }
    };
    vm.createContext(ctx);
    vm.runInContext(script, ctx);
    const settle = () => new Promise(r => setImmediate(r));
    for (let i = 0; i < 5; i++) await settle();
    check("G4. the page drew its cards from the server's catalogue", els.statTotal && els.statTotal.textContent === 12 && els.statPass.textContent === "80%",
      els.statTotal && els.statTotal.textContent);

    const answerAndSubmit = async function (serverReply) {
      vm.runInContext("openQuiz('sales-1'); answers = [0,0,0,0,0,0,0,0,0,0]; submitQuiz();", ctx);
      const sent = fetchCalls[fetchCalls.length - 1];
      const waiting = els.resultHeadline.textContent;
      pending.shift()(serverReply);
      for (let i = 0; i < 5; i++) await settle();
      return { sent: sent, waiting: waiting, headline: els.resultHeadline.textContent, score: els.resultScore.textContent, sub: els.resultSub.textContent };
    };
    const reply = (ok, status, body) => ({ ok: ok, status: status, json: async () => body });

    const pass = await answerAndSubmit(reply(true, 201, { success: true, already_earned: false, credited: true, result: { score: 70, passed: true, correct: 7, total: 10, pass_mark: 80 } }));
    console.log("    sent " + pass.sent.opts.body + " | while waiting: \"" + pass.waiting + "\" | shown: \"" + pass.headline + "\", " + pass.score);
    check("G5. the request carries exactly cert_id and answers", JSON.stringify(Object.keys(JSON.parse(pass.sent.opts.body))) === '["cert_id","answers"]', pass.sent.opts.body);
    check("G6. until the server answers, the page claims no result", pass.waiting === "Grading your answers…", pass.waiting);
    check("G7. a server pass is shown as a pass with the server's score, though the page's answers were all option A",
      pass.headline === "Certification Earned!" && pass.score === "70%", pass.headline + " " + pass.score);

    const fail = await answerAndSubmit(reply(true, 201, { success: true, already_earned: false, credited: false, result: { score: 90, passed: false, correct: 9, total: 10, pass_mark: 80 } }));
    check("G8. a server fail is shown as a fail with the server's score, whatever the score says", fail.headline === "Not Quite" && fail.score === "90%",
      fail.headline + " " + fail.score);

    const error = await answerAndSubmit(reply(false, 400, { error: "Unknown certification \"sales-1\"" }));
    check("G9. a refusal shows no score and no verdict", error.headline === "Not Graded" && error.score === "—" && /Unknown certification/.test(error.sub),
      error.headline + " " + error.score + " " + error.sub);
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
