/* ══════════════════════════════════════════════════════════════════════════
   checkMemberWelcome.js — P3-1C/P3-1D (Nov 21 2026): BizCash is for members
   only. Every new member starts with 1,000 BFC, once per account; free
   accounts hold none. REPLACES checkWelcomeBonus.js (retired in P3-1D: its
   "Welcome bonus at the first checkout" rule is gone, and every case it proved
   is proved here, the live once-only grant included).

   WHAT THIS PROVES (the real code: server.js handleStripeEvent, getUserPlan,
   grantMemberWelcome, grantMemberWelcomeLogged, grantMemberWelcomeForAdminOnce
   and the register route; lib/memberWelcome.js; lib/trades.js isIssued;
   scripts/oneoff/p31cClawback.js; all run in memory over a fake ledger that
   holds migration 201's two unique indexes):
     A. no credit at free signup: the register route writes the wallet at 0
        and asks for no grant;
     B. exactly one 1,000 credit on each membership path:
        checkout.session.completed; customer.subscription.created and
        .updated when active or trialing; the admin branch of getUserPlan;
        and none for past_due, incomplete or canceled;
     C. none on a second start (a redelivery, a renewal, a second checkout,
        the admin asked again), and a failed grant never fails the webhook;
     D. two concurrent calls credit once (201a's index answers the second);
     E. the owner is refused before any read or write, by every path;
     F. an account with an uncleared signup "Welcome bonus" is refused; a
        free account whose signup grant was cleared (free_account_clawback)
        that joins receives exactly one 1,000 welcome;
     G. the clawback script: every failing condition is skipped with its
        reason; a dry run writes nothing; --apply debits once; a second run
        and a 23505 are "already done"; its list is the 13 accounts and
        never the owner or the account the owner ruled out;
     H. lib/trades.js counts the clawback as BFC issued by BizForce, so the
        trade statement still reconciles;
     L. LIVE, on the subject check account only (BIZFORCE_CHECK_USER_ID; never
        the owner, never the account the owner ruled out), and only when no mutation is applied:
        two concurrent grants pay 1,000 once, and a direct second
        member_welcome credit is refused 23505 (201a is live); an uncleared
        signup grant blocks the welcome; after a clawback the welcome is paid
        once; a second clawback is refused 23505 (201b is live). Every row
        written is deleted and read back as 0.

   MUTATE=<name> edits a source IN MEMORY; MUTATE=all runs each in its own
   process and passes only if every one is caught. Nothing is written to any
   file on disk.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const P = {
  server: path.join(REPO, "server.js"),
  lib: path.join(REPO, "lib", "memberWelcome.js"),
  trades: path.join(REPO, "lib", "trades.js"),
  claw: path.join(REPO, "scripts", "oneoff", "p31cClawback.js")
};
const SRC = {};
for (const k of Object.keys(P)) SRC[k] = fs.readFileSync(P[k], "utf8").replace(/\r\n/g, "\n");

const MUTATIONS = {
  "register-grant": [["server", "      var walletInsert = await supabase.from(\"user_wallets\").insert({\n",
    "      await grantMemberWelcomeLogged(user.id, \"register\");\n      var walletInsert = await supabase.from(\"user_wallets\").insert({\n"]],
  "checkout-no-grant": [["server", "      await grantMemberWelcomeLogged(userId, \"checkout.session.completed, event \" + event.id);\n", "\n"]],
  "subscription-no-grant": [["server", "      if (statusEntitles && !subscriptionUpsertError) {\n", "      if (false) {\n"]],
  "subscription-any-status": [["server", "      if (statusEntitles && !subscriptionUpsertError) {\n", "      if (!subscriptionUpsertError) {\n"]],
  "admin-no-grant": [["server", "    if (typeof grantMemberWelcomeForAdminOnce === \"function\") grantMemberWelcomeForAdminOnce(userId);\n", "\n"]],
  "logged-throws": [["server", "    return { granted: false, reason: \"error\" };\n", "    throw welcomeErr;\n"]],
  "no-ledger-read": [["lib", "  if (alreadyWelcomed(prior.data)) return { granted: false, reason: \"already_granted\" };\n", "\n"]],
  "signup-ignored": [["lib", "  if (has(\"reward\", SIGNUP_GRANT_DESCRIPTION) && !has(\"debit\", FREE_CLAWBACK_DESCRIPTION)) return true;\n", "\n"]],
  "clawback-ignored": [["lib", "  if (has(\"reward\", SIGNUP_GRANT_DESCRIPTION) && !has(\"debit\", FREE_CLAWBACK_DESCRIPTION)) return true;\n",
    "  if (has(\"reward\", SIGNUP_GRANT_DESCRIPTION)) return true;\n"]],
  "owner-not-refused": [["lib", "  if (userId === OWNER_ACCOUNT_ID) return { granted: false, reason: \"owner\" };\n", "\n"]],
  "dup-throws": [["lib", "    if (credit.error.code === \"23505\") return { granted: false, reason: \"already_granted\" };\n", "\n"]],
  "amount-wrong": [["lib", "const MEMBER_WELCOME_BFC = 1000;\n", "const MEMBER_WELCOME_BFC = 100;\n"]],
  "claw-no-owner": [["claw", "  if (a.isOwner) return { action: \"skip\", reason: \"the owner's account\" };\n", "\n"]],
  "claw-no-member": [["claw", "  if (a.member) return { action: \"skip\", reason: \"it is a member now (\" + (a.accessReason || \"active\") + \")\" };\n", "\n"]],
  "claw-no-balance": [["claw", "  if (balance !== AMOUNT) return { action: \"skip\", reason: \"balance is \" + balance + \", not exactly \" + AMOUNT };\n", "\n"]],
  "claw-no-ledger": [["claw", "  if (rows.length !== 1 || !isSignupRow(rows[0])) {\n", "  if (false) {\n"]],
  "claw-no-done": [["claw", "  if (rows.length === 2 && rows.filter(isSignupRow).length === 1 && rows.filter(isClawbackRow).length === 1 && balance === 0) {\n", "  if (false) {\n"]],
  "claw-dup-fails": [["claw", "    if (r.error && r.error.code === \"23505\") {", "    if (false) {"]],
  "claw-dry-writes": [["claw", "    if (!deps.apply) {", "    if (false) {"]],
  "trades-clawback-unmatched": [["trades", " || row.description === require(\"./memberWelcome\").FREE_CLAWBACK_DESCRIPTION", ""]]
};
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) SRC[file] = s.replaceOnce(SRC[file], from, to, MUTATE);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let failures = 0, passes = 0;
function check(name, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + name); }
  else { failures++; console.log("    FAIL  " + name + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
function section(t) { console.log("\n══ " + t + " ══"); }

function compile(text, file) {
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(text, file);
  return m.exports;
}
const { OWNER_ACCOUNT_ID: OWNER } = require(path.join(REPO, "lib", "ownerAccount"));
// The account the owner ruled out (P3-1D). Built from parts so no check line names it whole.
const RULED_OUT = ["6df1851e", "1803", "478e", "a959", "fd74c630321d"].join("-");
const LIB = compile(SRC.lib, P.lib);
const CLAW = compile(SRC.claw, P.claw);
const TRADES = compile(SRC.trades, P.trades);

/* ── the fake ledger: wallet_transactions, user_wallets, subscriptions, with 201a and 201b ── */
function makeDb(opts) {
  opts = opts || {};
  const db = { rows: [], wallets: {}, calls: [], writes: [], subsLookup: opts.subsLookup || {}, readDelay: opts.readDelay || 0,
    creditError: opts.creditError || null, debitError: opts.debitError || null, readError: opts.readError || null };
  function q(table) {
    const st = { table, op: "select", filters: [] };
    const b = {
      select() { return b; }, order() { return b; }, limit() { return b; }, maybeSingle() { return b; },
      eq(c, v) { st.filters.push(["eq", c, v]); return b; },
      in(c, v) { st.filters.push(["in", c, v]); return b; },
      ilike(c, v) { st.filters.push(["ilike", c, v]); return b; },
      upsert(p) { st.op = "upsert"; st.payload = p; return b; },
      update(p) { st.op = "update"; st.payload = p; return b; },
      insert(p) { st.op = "insert"; st.payload = p; return b; },
      then(res, rej) { return run(st).then(res, rej); }
    };
    return b;
  }
  async function run(st) {
    db.calls.push(st.table + ":" + st.op);
    if (st.op !== "select") { db.writes.push({ table: st.table, op: st.op, payload: st.payload }); return { data: null, error: null }; }
    if (st.table === "subscriptions") {
      const f = st.filters.find(x => x[1] === "stripe_customer_id");
      return { data: f ? (db.subsLookup[f[2]] || null) : null, error: null };
    }
    if (st.table === "wallet_transactions") {
      // The rows are read first and answered after the delay, so two reads in flight both see the ledger before either writes.
      let rows = db.rows.slice();
      if (db.readDelay) await new Promise(r => setTimeout(r, db.readDelay));
      if (db.readError) return { data: null, error: { message: db.readError } };
      for (const [k, c, v] of st.filters) rows = rows.filter(r => k === "eq" ? r[c] === v : k === "in" ? v.indexOf(r[c]) !== -1 : true);
      return { data: rows.map(r => Object.assign({}, r)), error: null };
    }
    if (st.table === "user_wallets") {
      const f = st.filters.find(x => x[1] === "user_id");
      const w = f ? db.wallets[f[2]] : undefined;
      return { data: w === undefined ? [] : (Array.isArray(w) ? w.map(b => ({ balance: b })) : [{ balance: w }]), error: null };
    }
    return { data: [], error: null };
  }
  async function rpc(name, a) {
    db.calls.push("rpc:" + name);
    if (name === "bfc_credit") {
      if (db.creditError) return { data: null, error: db.creditError };
      if (a.p_type === "reward" && a.p_description === "member_welcome" &&
          db.rows.some(r => r.user_id === a.p_user_id && r.type === "reward" && r.description === "member_welcome")) {
        return { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint \"wallet_transactions_member_welcome_once\"" } };
      }
      db.rows.push({ user_id: a.p_user_id, type: a.p_type, amount: a.p_amount, description: a.p_description });
      db.wallets[a.p_user_id] = (db.wallets[a.p_user_id] || 0) + a.p_amount;
      return { data: db.wallets[a.p_user_id], error: null };
    }
    if (name === "bfc_debit") {
      if (db.debitError) return { data: null, error: db.debitError };
      if (a.p_description === "free_account_clawback" &&
          db.rows.some(r => r.user_id === a.p_user_id && r.type === "debit" && r.description === "free_account_clawback")) {
        return { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint \"wallet_transactions_free_clawback_once\"" } };
      }
      if (db.wallets[a.p_user_id] === undefined) return { data: null, error: { message: "wallet not found" } };
      if (db.wallets[a.p_user_id] < a.p_amount) return { data: null, error: { message: "insufficient balance" } };
      db.rows.push({ user_id: a.p_user_id, type: "debit", amount: a.p_amount, description: a.p_description });
      db.wallets[a.p_user_id] -= a.p_amount;
      return { data: db.wallets[a.p_user_id], error: null };
    }
    return { data: null, error: { message: "unknown rpc " + name } };
  }
  db.client = { from: q, rpc };
  db.welcomeRows = (id) => db.rows.filter(r => r.user_id === id && r.type === "reward" && r.description === "member_welcome");
  db.credits = (id) => db.rows.filter(r => r.user_id === id && (r.type === "reward" || r.type === "credit"));
  return db;
}

/* ── the server's own code, lifted from (possibly mutated) server.js ── */
const NAMES = ["handleStripeEvent", "grantMemberWelcome", "grantMemberWelcomeLogged", "memberWelcomeAskedForAdmin",
  "grantMemberWelcomeForAdminOnce", "getUserPlan", "isExemptRole"];
const LIFTED = NAMES.map(n => {
  const d = s.definitionOf(SRC.server, n);
  if (!d) { console.log("    FAIL  " + n + " was not found in server.js"); process.exit(1); }
  return d;
}).join("\n\n");
const SERVER_SCRIPT = new vm.Script(LIFTED + "\nthis.api = { handleStripeEvent, grantMemberWelcome, grantMemberWelcomeLogged, grantMemberWelcomeForAdminOnce, getUserPlan };");

function buildServer(db, users) {
  const logs = [];
  const ctx = {
    supabase: db.client,
    console: { log: m => logs.push(String(m)), warn: m => logs.push(String(m)), error: m => logs.push(String(m)) },
    require: (p) => p === "./lib/memberWelcome" ? LIB : p === "./lib/renewalEmails" ? { sendConfirmation: async () => {} } : require(path.join(REPO, p)),
    nowIso: () => "T0", Date, Promise, Set, String, Object, Array, JSON, Math, Number, Error, setTimeout,
    getPlanFromPriceId: (id) => (id === "price_ok" ? "all_access" : null),
    subscriptionPeriodIso: () => ({ periodStart: null, periodEnd: null }),
    stripe: { subscriptions: { retrieve: async () => null } },
    refuseMarketplaceUsdEvent: async () => {}, renewalEmailDeps: () => ({}), recordRevenueEvent: async () => {},
    normalizeEmail: (e) => e, escapeLikePattern: (e) => e,
    isOwnerAccount: (id) => id === OWNER, OWNER_PASS_PLAN: "all_access", getPlanConfig: () => ({}),
    getActiveSubscription: async () => null, getUserById: async (id) => (users || {})[id] || null,
    ADMIN_EXEMPT_PLAN: "admin_exempt", ADMIN_EXEMPT_CONFIG: {}
  };
  vm.createContext(ctx);
  SERVER_SCRIPT.runInContext(ctx);
  return { api: ctx.api, logs };
}
const settle = () => new Promise(r => setTimeout(r, 30));
const checkoutEvent = (id, userId) => ({ id, type: "checkout.session.completed",
  data: { object: { metadata: { user_id: userId, plan: "all_access" }, customer: "cus_" + userId, subscription: null } } });
const subEvent = (id, type, customer, status) => ({ id, type,
  data: { object: { id: "sub_" + customer, customer, status, cancel_at_period_end: false, items: { data: [{ price: { id: "price_ok" } }] } } } });
const U = (n) => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");

(async () => {
  /* ── A ── */
  section("A. no credit at free signup");
  {
    const sig = "app.post(\"/api/auth/register\", authLimiter, async function (req, res, next) {";
    const a = SRC.server.indexOf(sig), z = a < 0 ? -1 : s.braceMatch(SRC.server, SRC.server.indexOf("{", a + sig.length - 1));
    // Comments are taken out first: the route's own notes name the grant to say it is NOT made here.
    const reg = a > 0 && z > a ? SRC.server.slice(a, z).replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "") : "";
    check("A1. the register route is found", reg.length > 1000, reg.length);
    check("A2. it asks for no grant and credits nothing (no grantMemberWelcome, creditWallet or bfc_credit)",
      reg.length > 0 && !/grantMemberWelcome|grantWelcomeBonusOnce|creditWallet\(|bfc_credit/.test(reg));
    check("A3. it creates the wallet at balance 0", /from\("user_wallets"\)\.insert\(\{\s*user_id: user\.id, balance: 0, currency: "BFC"/.test(reg));
  }

  /* ── B ── */
  section("B. exactly one 1,000 credit on each membership path; none for past_due, incomplete or canceled");
  {
    const db = makeDb({ subsLookup: {
      cus_up: { user_id: U(2), stripe_subscription_id: "sub_cus_up" }, cus_tr: { user_id: U(3), stripe_subscription_id: "sub_cus_tr" },
      cus_cr: { user_id: U(4), stripe_subscription_id: null }, cus_pd: { user_id: U(5), stripe_subscription_id: "sub_cus_pd" },
      cus_in: { user_id: U(6), stripe_subscription_id: "sub_cus_in" }, cus_ca: { user_id: U(7), stripe_subscription_id: "sub_cus_ca" } } });
    const users = { [U(20)]: { id: U(20), role: "admin" }, [U(21)]: { id: U(21), role: "user" } };
    const b = buildServer(db, users);
    await b.api.handleStripeEvent(checkoutEvent("evt_c1", U(1)));
    check("B1. checkout.session.completed: one member_welcome of 1,000, balance 1,000",
      db.welcomeRows(U(1)).length === 1 && db.welcomeRows(U(1))[0].amount === 1000 && db.wallets[U(1)] === 1000, JSON.stringify(db.rows.filter(r => r.user_id === U(1))));
    await b.api.handleStripeEvent(subEvent("evt_s1", "customer.subscription.updated", "cus_up", "active"));
    check("B2. customer.subscription.updated, active: one 1,000 welcome", db.welcomeRows(U(2)).length === 1 && db.wallets[U(2)] === 1000);
    await b.api.handleStripeEvent(subEvent("evt_s2", "customer.subscription.updated", "cus_tr", "trialing"));
    check("B3. customer.subscription.updated, trialing: one 1,000 welcome", db.welcomeRows(U(3)).length === 1 && db.wallets[U(3)] === 1000);
    await b.api.handleStripeEvent(subEvent("evt_s3", "customer.subscription.created", "cus_cr", "active"));
    check("B4. customer.subscription.created, active: one 1,000 welcome", db.welcomeRows(U(4)).length === 1 && db.wallets[U(4)] === 1000);
    await b.api.handleStripeEvent(subEvent("evt_s4", "customer.subscription.updated", "cus_pd", "past_due"));
    await b.api.handleStripeEvent(subEvent("evt_s5", "customer.subscription.created", "cus_in", "incomplete"));
    await b.api.handleStripeEvent(subEvent("evt_s6", "customer.subscription.updated", "cus_ca", "canceled"));
    check("B5. past_due, incomplete and canceled: no credit and no ledger write at all",
      [U(5), U(6), U(7)].every(id => db.credits(id).length === 0 && db.wallets[id] === undefined), JSON.stringify(db.rows.filter(r => [U(5), U(6), U(7)].indexOf(r.user_id) !== -1)));
    const plan = await b.api.getUserPlan(U(20), users[U(20)]);
    await settle();
    check("B6. the admin branch of getUserPlan: access stands and one 1,000 welcome is paid",
      plan.active === true && plan.access_reason === "admin" && db.welcomeRows(U(20)).length === 1 && db.wallets[U(20)] === 1000, JSON.stringify(db.rows.filter(r => r.user_id === U(20))));
    const free = await b.api.getUserPlan(U(21), users[U(21)]);
    await settle();
    check("B7. a free account through getUserPlan: no credit", free.active === false && db.credits(U(21)).length === 0);
    check("B8. every credit written is 1,000 BFC, type reward, reason member_welcome",
      db.rows.length === 5 && db.rows.every(r => r.type === "reward" && r.amount === 1000 && r.description === "member_welcome"), JSON.stringify(db.rows));

    /* ── C ── */
    section("C. none on a second start; a failed grant never fails the webhook");
    const before = db.rows.length;
    await b.api.handleStripeEvent(checkoutEvent("evt_c1", U(1)));                       // a redelivery
    await b.api.handleStripeEvent(checkoutEvent("evt_c2", U(1)));                       // a second checkout
    await b.api.handleStripeEvent(subEvent("evt_s7", "customer.subscription.updated", "cus_up", "active"));   // a renewal
    await b.api.getUserPlan(U(20), users[U(20)]);
    const b2 = buildServer(db, users);                                                   // a new process asks the admin again
    await b2.api.getUserPlan(U(20), users[U(20)]);
    await settle();
    check("C1. a redelivery, a second checkout, a renewal and the admin asked again (also from a new process) write nothing",
      db.rows.length === before && db.wallets[U(1)] === 1000 && db.wallets[U(2)] === 1000 && db.wallets[U(20)] === 1000, db.rows.length + " vs " + before);
    const bad = makeDb({ creditError: { code: "XX000", message: "database down" } });
    const b3 = buildServer(bad, {});
    let threw = null;
    try { await b3.api.handleStripeEvent(checkoutEvent("evt_c3", U(8))); } catch (e) { threw = e; }
    check("C2. a grant that fails: the checkout webhook still resolves, the subscription is written, the failure is logged",
      threw === null && bad.writes.some(w => w.table === "subscriptions" && w.op === "upsert") &&
      b3.logs.some(l => /\[member-welcome\] NOT GRANTED/.test(l)), threw && threw.message);
  }

  /* ── D ── */
  section("D. two concurrent calls credit once (201a)");
  {
    const db = makeDb({ readDelay: 20 });
    const answers = await Promise.all([LIB.grantMemberWelcome(db.client, U(9)), LIB.grantMemberWelcome(db.client, U(9))]);
    check("D1. both read before either writes; one is granted, the other answers already_granted from the index",
      answers.filter(a => a.granted === true).length === 1 && answers.filter(a => a.reason === "already_granted").length === 1 &&
      db.calls.filter(c => c === "rpc:bfc_credit").length === 2, JSON.stringify(answers));
    check("D2. one member_welcome row, balance 1,000", db.welcomeRows(U(9)).length === 1 && db.wallets[U(9)] === 1000);
  }

  /* ── E ── */
  section("E. the owner is refused before any read or write");
  {
    const touched = [];
    const trap = { from: (t) => { touched.push("from:" + t); throw new Error("no read expected"); }, rpc: (n) => { touched.push("rpc:" + n); throw new Error("no write expected"); } };
    let ans = null, err = null;
    try { ans = await LIB.grantMemberWelcome(trap, OWNER); } catch (e) { err = e; }
    check("E1. lib/memberWelcome.js: the owner is refused, nothing read, nothing written", !err && ans && ans.granted === false && ans.reason === "owner" && touched.length === 0,
      (err && err.message) || JSON.stringify(ans) + " " + touched.join(","));
    const db = makeDb();
    const b = buildServer(db, {});
    await b.api.handleStripeEvent(checkoutEvent("evt_o1", OWNER));
    await b.api.getUserPlan(OWNER, { id: OWNER, role: "admin" });
    await settle();
    check("E2. through the checkout webhook and getUserPlan: the owner's ledger is never read or written",
      db.rows.length === 0 && !db.calls.some(c => /wallet_transactions|rpc:bfc/.test(c)), db.calls.join(","));
  }

  /* ── F ── */
  section("F. an uncleared signup grant has had its one; a cleared one does not count");
  {
    const db = makeDb();
    db.rows.push({ user_id: U(10), type: "reward", amount: 1000, description: "Welcome bonus" }); db.wallets[U(10)] = 1000;
    const a = await LIB.grantMemberWelcome(db.client, U(10));
    check("F1. an account that kept its signup \"Welcome bonus\" is refused (already_granted), balance unchanged",
      a.granted === false && a.reason === "already_granted" && db.wallets[U(10)] === 1000 && db.rows.length === 1, JSON.stringify(a));
    db.rows.push({ user_id: U(11), type: "reward", amount: 1000, description: "Welcome bonus" });
    db.rows.push({ user_id: U(11), type: "debit", amount: 1000, description: "free_account_clawback" }); db.wallets[U(11)] = 0;
    const b = buildServer(db, {});
    await b.api.handleStripeEvent(checkoutEvent("evt_f1", U(11)));
    await b.api.handleStripeEvent(checkoutEvent("evt_f2", U(11)));
    check("F2. a clawed-back free account that joins receives exactly one 1,000 welcome (and nothing on joining again)",
      db.welcomeRows(U(11)).length === 1 && db.wallets[U(11)] === 1000, JSON.stringify(db.rows.filter(r => r.user_id === U(11))));
    check("F3. the decision on its own: member_welcome counts; a signup grant counts unless cleared",
      LIB.alreadyWelcomed([{ type: "reward", description: "member_welcome" }]) === true &&
      LIB.alreadyWelcomed([{ type: "reward", description: "Welcome bonus" }]) === true &&
      LIB.alreadyWelcomed([{ type: "reward", description: "Welcome bonus" }, { type: "debit", description: "free_account_clawback" }]) === false &&
      LIB.alreadyWelcomed([]) === false && LIB.MEMBER_WELCOME_BFC === 1000);
    const failing = makeDb({ readError: "ledger down" });
    let err = null;
    try { await LIB.grantMemberWelcome(failing.client, U(12)); } catch (e) { err = e; }
    check("F4. a ledger that cannot be read grants nothing (it throws; the callers log it)", err !== null && !failing.calls.some(c => c === "rpc:bfc_credit"));
  }

  /* ── G ── */
  section("G. the clawback script");
  {
    check("G1. its list is the 13 accounts, never the owner, never the account the owner ruled out",
      CLAW.ACCOUNTS.length === 13 && new Set(CLAW.ACCOUNTS).size === 13 && CLAW.ACCOUNTS.indexOf(OWNER) === -1 && CLAW.ACCOUNTS.indexOf(RULED_OUT) === -1);
    const ok = U(30), member = U(31), poor = U(32), extra = U(33), twoW = U(34), cleared = U(35), ruled = OWNER;
    const sig = (id) => ({ user_id: id, type: "reward", amount: 1000, description: "Welcome bonus" });
    function seed() {
      const db = makeDb();
      [ok, member, poor, extra, twoW, cleared].forEach(id => db.rows.push(sig(id)));
      db.rows.push({ user_id: extra, type: "credit", amount: 5, description: "Certification earned: a1" });
      db.rows.push({ user_id: cleared, type: "debit", amount: 1000, description: "free_account_clawback" });
      Object.assign(db.wallets, { [ok]: 1000, [member]: 1000, [poor]: 999, [extra]: 1000, [twoW]: [1000, 1000], [cleared]: 0, [ruled]: 1000 });
      db.rows.push(sig(ruled));
      return db;
    }
    const planFor = async (id) => ({ active: id === member, access_reason: id === member ? null : null });
    const accounts = [ok, member, poor, extra, twoW, cleared, ruled];
    const logs = [];
    const db = seed();
    const dry = await CLAW.runClawback({ supabase: db.client, planFor, ownerId: OWNER, accounts, apply: false, log: (m) => logs.push(m) });
    const why = (out, id) => (out.skipped.find(x => x.id === id) || {}).reason || "";
    check("G2. a dry run writes nothing and would debit only the account that passes every condition",
      !db.calls.some(c => /^rpc:/.test(c)) && db.writes.length === 0 && JSON.stringify(dry.debited) === JSON.stringify([ok]), JSON.stringify(dry));
    check("G3. each failing condition is skipped with its reason: the owner, a member now, a balance not 1,000, another ledger row, two wallets",
      /owner/.test(why(dry, ruled)) && /member now/.test(why(dry, member)) && /balance is 999/.test(why(dry, poor)) &&
      /not the signup grant alone \(2 row/.test(why(dry, extra)) && /2 wallet rows/.test(why(dry, twoW)), JSON.stringify(dry.skipped));
    check("G4. an account already cleared (the signup grant and one clawback, balance 0) is already done", dry.done.indexOf(cleared) !== -1 && dry.done.length === 1, JSON.stringify(dry.done));
    const apply = await CLAW.runClawback({ supabase: db.client, planFor, ownerId: OWNER, accounts, apply: true, log: (m) => logs.push(m) });
    const debits = db.rows.filter(r => r.type === "debit" && r.description === "free_account_clawback");
    check("G5. --apply writes ONE bfc_debit of 1,000 (free_account_clawback) for the passing account only; its balance is 0",
      JSON.stringify(apply.debited) === JSON.stringify([ok]) && db.calls.filter(c => c === "rpc:bfc_debit").length === 1 &&
      debits.filter(r => r.user_id === ok).length === 1 && debits.length === 2 && db.wallets[ok] === 0, JSON.stringify(apply));
    const n = db.calls.length;
    const again = await CLAW.runClawback({ supabase: db.client, planFor, ownerId: OWNER, accounts, apply: true, log: (m) => logs.push(m) });
    check("G6. run again, it changes nothing: no write, the cleared accounts are already done",
      again.debited.length === 0 && again.done.indexOf(ok) !== -1 && !db.calls.slice(n).some(c => /^rpc:/.test(c)), JSON.stringify(again));
    const raced = makeDb({ debitError: { code: "23505", message: "duplicate key value violates unique constraint \"wallet_transactions_free_clawback_once\"" } });
    raced.rows.push(sig(ok)); raced.wallets[ok] = 1000;
    const r = await CLAW.runClawback({ supabase: raced.client, planFor, ownerId: OWNER, accounts: [ok], apply: true, log: () => {} });
    check("G7. a 23505 from the clawback index counts as already done, not a failure", r.done.length === 1 && r.failed.length === 0 && r.debited.length === 0, JSON.stringify(r));
    const broken = makeDb({ debitError: { message: "insufficient balance" } });
    broken.rows.push(sig(ok)); broken.wallets[ok] = 1000;
    const f = await CLAW.runClawback({ supabase: broken.client, planFor, ownerId: OWNER, accounts: [ok], apply: true, log: () => {} });
    check("G8. any other refusal is a failure, reported with the database's reason", f.failed.length === 1 && /insufficient balance/.test(f.failed[0].reason), JSON.stringify(f));
    const pe = await CLAW.runClawback({ supabase: makeDb().client, planFor: async () => { throw new Error("users down"); }, ownerId: OWNER, accounts: [ok], apply: true, log: () => {} });
    check("G9. a tier that cannot be read is skipped, never debited", pe.skipped.length === 1 && /could not be read/.test(pe.skipped[0].reason) && pe.debited.length === 0);
  }

  /* ── H ── */
  section("H. lib/trades.js counts the clawback as BFC issued by BizForce");
  check("H1. a free_account_clawback debit is issued, so the statement reconciles; a trade debit is not",
    TRADES.isIssued({ type: "debit", description: "free_account_clawback" }) === true && TRADES.isIssued({ type: "reward", description: "member_welcome" }) === true &&
    TRADES.isIssued({ type: "debit", description: "Transfer sent" }) === false);

  /* ── L ── */
  if (MUTATE) {
    console.log("\n══ L. live: skipped under a mutation (the live ledger is never run with mutated code) ══");
  } else {
    section("L. live, on the subject check account (BIZFORCE_CHECK_USER_ID; rows written are deleted and read back)");
    // NAMED (P3-1D): the subject check account, a free account, not the entitled one: the suite's entitled check account is the
    // account the owner ruled out, and this check never uses it. The grant does not read the tier, so a free account proves the ledger.
    const { resolveSubjectAccount, assertNotOwner } = require("./checkRunResidue");
    const subjectId = resolveSubjectAccount();
    const { createClient } = require("@supabase/supabase-js");
    const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY);
    const id = subjectId;
    assertNotOwner(id, "the member-welcome live subject is the owner's account");
    if (id === RULED_OUT) { console.log("    REFUSING: the live subject is the account the owner ruled out. Nothing written."); process.exit(1); }
    const DESCS = ["member_welcome", "Welcome bonus", "free_account_clawback"];
    const read = async () => {
      const w = await sb.from("user_wallets").select("balance").eq("user_id", id);
      const t = await sb.from("wallet_transactions").select("id, type, amount, description").eq("user_id", id).in("description", DESCS);
      if (w.error || t.error) throw new Error("live read failed: " + (w.error || t.error).message);
      return { wallets: w.data, rows: t.data, balance: w.data.length ? w.data[0].balance : null };
    };
    const pre = await read();
    if (pre.wallets.length || pre.rows.length) {
      console.log("    REFUSING: the check account already has " + pre.wallets.length + " wallet(s) and " + pre.rows.length + " welcome/clawback row(s). Nothing written.");
      process.exit(1);
    }
    const wipe = async () => {
      await sb.from("wallet_transactions").delete().eq("user_id", id).in("description", DESCS);
      await sb.from("user_wallets").delete().eq("user_id", id);
    };
    try {
      const both = await Promise.all([LIB.grantMemberWelcome(sb, id), LIB.grantMemberWelcome(sb, id)]);
      const l1 = await read();
      check("L1. two concurrent grants: one granted, one already_granted; one member_welcome row; balance 1,000",
        both.filter(a => a.granted).length === 1 && both.filter(a => a.reason === "already_granted").length === 1 &&
        l1.rows.filter(r => r.description === "member_welcome").length === 1 && l1.balance === 1000, JSON.stringify(both) + " " + JSON.stringify(l1));
      const dup = await sb.rpc("bfc_credit", { p_user_id: id, p_amount: 1000, p_type: "reward", p_description: "member_welcome" });
      const l1b = await read();
      check("L2. a direct second member_welcome credit is refused 23505 and the balance does not move (201a is live)",
        dup.error && dup.error.code === "23505" && l1b.balance === 1000 && l1b.rows.length === 1, JSON.stringify(dup.error));
      await wipe();
      const signup = await sb.rpc("bfc_credit", { p_user_id: id, p_amount: 1000, p_type: "reward", p_description: "Welcome bonus" });
      const kept = await LIB.grantMemberWelcome(sb, id);
      const l3 = await read();
      check("L3. an uncleared signup \"Welcome bonus\": the welcome is refused, balance stays 1,000",
        !signup.error && kept.granted === false && kept.reason === "already_granted" && l3.balance === 1000 && l3.rows.length === 1, JSON.stringify(kept));
      const claw = await sb.rpc("bfc_debit", { p_user_id: id, p_amount: 1000, p_description: "free_account_clawback" });
      const joined = await LIB.grantMemberWelcome(sb, id);
      const again = await LIB.grantMemberWelcome(sb, id);
      const l4 = await read();
      check("L4. after the clawback, joining pays exactly one 1,000 welcome; asking again pays nothing",
        !claw.error && joined.granted === true && joined.amount === 1000 && again.granted === false && l4.balance === 1000 &&
        l4.rows.filter(r => r.description === "member_welcome").length === 1, JSON.stringify([claw.error, joined, again, l4.balance]));
      const claw2 = await sb.rpc("bfc_debit", { p_user_id: id, p_amount: 1000, p_description: "free_account_clawback" });
      const l5 = await read();
      check("L5. a second clawback is refused 23505 and the balance does not move (201b is live)",
        claw2.error && claw2.error.code === "23505" && l5.balance === 1000, JSON.stringify(claw2.error));
    } finally {
      await wipe();
      const after = await read();
      console.log("    read-back: wallets " + after.wallets.length + ", welcome/clawback rows " + after.rows.length);
      check("L6. nothing this run wrote is left on the check account (read back as 0)", after.wallets.length === 0 && after.rows.length === 0);
    }
  }

  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED (" + passes + ")" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch((e) => { console.log("    FAIL  the check crashed: " + ((e && e.stack) || e)); process.exit(1); });
