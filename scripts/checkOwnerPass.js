"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkOwnerPass.js — the owner account always has full access, and is never
   billed or counted.

   THE DEFECT. The owner account (lib/ownerAccount.js OWNER_ACCOUNT_ID) holds a
   Stripe subscription row that is past_due with current_period_end null:
   Stripe has been retrying the owner's own card for $199. That row decided
   his access, his checkout and whether he counted as a subscriber.

   WHAT THIS PROVES
     A. ENTITLED, WHATEVER THE ROW SAYS. The real getUserPlan and
        subscriptionEntitlement, lifted from server.js: the owner is all_access,
        active, access_reason "owner", exempt, with a past_due/null row (the
        live shape), a canceled row, no row, a row that cannot be read, and
        with role "admin" or not. The real row is returned, never a made-up one.
        requireActiveSubscription, refuseUnlessSubscribed and ownerPagePublic
        (lifted) let him through, and every caller of getUserPlan is listed.
     B. NOBODY ELSE. Another account with the same past_due row is refused,
        and for every row tried, every other account's answer (and log) is
        byte for byte what PRE (the commit before the pass) gives. No user
        field (the owner's email, role, an `owner` flag, the owner's id on the
        user object) and no environment variable makes another account the
        owner. The pass is keyed by the code constant alone.
     C. CHECKOUT. The real POST /api/stripe/checkout, lifted: the owner gets
        409 "owner_account" with the exact message, and nothing is read,
        written or sent to Stripe. Another account still reaches Stripe, even
        carrying the owner's id and email in its body.
     D. NOT COUNTED. lib/testAccounts.js isUncountedAccount: the owner by id
        (not by email), the test accounts as before, an ordinary member not.
        Self-review gives the owner 0 revenue without reading revenue_events.
        Every require of lib/testAccounts.js counts through isUncountedAccount.
     E. NO WELCOME BONUS. The owner pass credits nothing and writes nothing;
        grantWelcomeBonusOnce has one caller, inside checkout.session.completed.
     F. BILLING (frontend billing.html, in jsdom): the owner sees "Owner
        account: full access, no subscription needed", his past_due row as
        information with "Cancel this in Stripe so it stops retrying your
        card." and the Manage button, and no Subscribe button. Others see what
        they saw before.

   NO NETWORK. NO DATABASE. Supabase, Stripe and fetch are in-memory stubs.

   MUTATE=<name> edits a source IN MEMORY. MUTATE=all runs each in its own
   process (scripts/_shared.js): a search text that does not match exactly
   once is an ERROR, never a catch.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
// The last commit before the owner pass. Every other account must answer as it did here.
const PRE = "07adb05";

const lf = t => t.replace(/\r\n/g, "\n");
const SRC = {
  "server.js": lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8")),
  "lib/testAccounts.js": lf(fs.readFileSync(path.join(REPO, "lib/testAccounts.js"), "utf8")),
  "lib/selfReview.js": lf(fs.readFileSync(path.join(REPO, "lib/selfReview.js"), "utf8")),
  "lib/ownerAccount.js": lf(fs.readFileSync(path.join(REPO, "lib/ownerAccount.js"), "utf8")),
  "billing.html": lf(fs.readFileSync(path.join(FRONTEND, "billing.html"), "utf8"))
};
const OLD_SERVER = lf(execFileSync("git", ["show", PRE + ":server.js"], { cwd: REPO, encoding: "utf8", maxBuffer: 64 << 20 }));

const MUTATIONS = {
  // the owner is refused when his row is past_due: the pass is gone
  "owner-refused-when-past-due": [["server.js", "async function getUserPlan(userId, user) {\n  if (isOwnerAccount(userId)) {\n",
    "async function getUserPlan(userId, user) {\n  if (false) {\n"]],
  // the pass is keyed by the owner's email as well
  "owner-pass-by-email": [["server.js", "async function getUserPlan(userId, user) {\n  if (isOwnerAccount(userId)) {\n",
    "async function getUserPlan(userId, user) {\n  if (isOwnerAccount(userId) || String((user && user.email) || \"\").toLowerCase() === \"angelic2201@gmail.com\") {\n"]],
  // the pass is keyed by an environment variable as well
  "owner-pass-by-env": [["server.js", "  return typeof userId === \"string\" && userId === OWNER_ACCOUNT_ID;\n",
    "  return typeof userId === \"string\" && (userId === OWNER_ACCOUNT_ID || userId === process.env.OWNER_ACCOUNT_ID);\n"]],
  // another account's row entitles as the owner's does
  "another-account-entitled": [["server.js", "  if (subscription && isOwnerAccount(subscription.user_id)) {\n", "  if (subscription) {\n"]],
  // checkout goes ahead for the owner
  "checkout-allowed-for-owner": [["server.js", "    if (isOwnerAccount(req.user.id)) {\n      return res.status(409).json({\n        error: \"owner_account\",",
    "    if (false) {\n      return res.status(409).json({\n        error: \"owner_account\","]],
  // the owner is counted as a subscriber (revenue counted)
  "owner-counted": [["lib/testAccounts.js", "  return String(user.id || \"\").toLowerCase() === OWNER_ACCOUNT_ID || isTestAccount(user);\n",
    "  return isTestAccount(user);\n"]],
  // self-review goes back to the test-only question
  "selfreview-test-only": [["lib/selfReview.js", "      testAccount = isUncountedAccount((accountRead && accountRead.data) || { id: userId });\n",
    "      testAccount = require(\"./testAccounts\").isTestAccount((accountRead && accountRead.data) || { id: userId });\n"]],
  // a welcome bonus on the pass
  "bonus-on-pass": [["server.js", "    var ownerRow = null;\n", "    await grantWelcomeBonusOnce(userId);\n    var ownerRow = null;\n"]],
  // Billing shows no owner notice
  "billing-no-owner-notice": [["billing.html", "      document.getElementById(\"ownerNotice\").style.display = owner ? \"block\" : \"none\";\n", ""]],
  // Billing hides the owner's Stripe row, so he cannot cancel it
  "billing-hides-owner-row": [["billing.html", "      if (sub && owner) {\n        showOwnerRow(sub);\n        return;\n      }\n",
    "      if (sub && owner) {\n        showNeither();\n        return;\n      }\n"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) SRC[file] = s.replaceOnce(SRC[file], from, to, MUTATE);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const section = t => console.log("\n══ " + t + " ══");
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };
const DAY = 86400000;
const iso = ms => new Date(ms).toISOString();
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const { OWNER_ACCOUNT_ID } = require("../lib/ownerAccount");
const OWNER = OWNER_ACCOUNT_ID;
const OWNER_EMAIL = "angelic2201@gmail.com";
const OTHER = "11111111-1111-4111-8111-111111111111";
const OTHER_ADMIN = "22222222-2222-4222-8222-222222222222";
const OWNER_MESSAGE = "The owner account has full access and never needs a subscription. Nothing was charged.";

/* ── server.js code, lifted ──────────────────────────────────────────────── */
function liftFrom(src, name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (m) return src.slice(m.index, s.braceMatch(src, src.indexOf(") {", m.index) + 2));
  const v = new RegExp("^(?:var|const|let) " + name + "[ \t]*=", "m").exec(src);
  if (!v) return null;
  const brk = /;\n/g; brk.lastIndex = v.index;
  let b;
  while ((b = brk.exec(src))) {
    const piece = src.slice(v.index, b.index + 1);
    try { new vm.Script(piece); return piece; } catch (e) { /* not the end yet */ }
  }
  throw new Error("no end found for " + name);
}
const NAMES = ["PAST_DUE_GRACE_DEFAULT_DAYS", "PAST_DUE_GRACE_MAX_DAYS", "parsePastDueGraceDays", "pastDueTimeOf", "pastDueGraceState",
  "SUBSCRIPTION_GRACE_DAYS", "SUBSCRIPTION_PAST_DUE_GRACE_DAYS", "subscriptionExpiryState", "subscriptionEntitlement",
  "ADMIN_EXEMPT_PLAN", "ADMIN_EXEMPT_CONFIG", "isExemptRole", "OWNER_PASS_PLAN", "isOwnerAccount", "getPlanConfig", "getUserPlan",
  "BILLING_URL", "SUBSCRIPTION_REFUSAL_MESSAGES", "SUBSCRIPTION_REFUSAL_DEFAULT", "SUBSCRIPTION_PAST_DUE_MESSAGE", "subscriptionRequiredBody",
  "refuseUnlessSubscribed", "ownerPagePublic", "requireActiveSubscription",
  "CHECKOUT_PRODUCTS", "PLAN_CONFIG", "AUTO_RENEW_CONSENT_VERSION", "autoRenewConsent"];
const ROUTE_SIG = 'app.post("/api/stripe/checkout", requireAuth, async function (req, res) {';
function routeFrom(src) {
  const start = src.indexOf(ROUTE_SIG);
  if (start < 0) throw new Error("checkout route not found");
  return src.slice(start, s.braceMatch(src, src.indexOf("{", start + ROUTE_SIG.length - 2)) + 2);
}

const USERS = {
  [OWNER]: { id: OWNER, email: OWNER_EMAIL, role: "admin" },
  [OTHER]: { id: OTHER, email: "member@example.com", role: "user" },
  [OTHER_ADMIN]: { id: OTHER_ADMIN, email: "staff@example.com", role: "admin" }
};

/* A server built from `src`, with in-memory stand-ins. opts.rows: userId → row (or an Error to throw). */
function buildServer(src, opts) {
  opts = opts || {};
  const logs = [], stripeCalls = [], dbCalls = [], subReads = [], bonus = [];
  let handler = null;
  const chain = (table) => {
    dbCalls.push(table);
    const q = {};
    ["select", "eq", "not", "order", "limit", "in", "is", "gte", "lt"].forEach(k => { q[k] = () => q; });
    ["insert", "update", "upsert", "delete"].forEach(k => { q[k] = () => { dbCalls.push(table + ":" + k); return q; }; });
    q.maybeSingle = async () => ({ data: null, error: null });
    q.then = (res, rej) => Promise.resolve({ data: null, error: null }).then(res, rej);
    return q;
  };
  const rowFor = async (userId) => {
    subReads.push(userId);
    const r = (opts.rows || {})[userId];
    if (r instanceof Error) throw r;
    return r || null;
  };
  const ctx = {
    process: { env: Object.assign({ STRIPE_STARTER_PRICE_ID: "price_check" }, opts.env || {}) },
    console: { log: m => logs.push(String(m)), warn: m => logs.push(String(m)), error: m => logs.push(String(m)) },
    Date, Math, Number, String, Object, Array, JSON, Promise,
    AGENT_SYSTEM_PROMPTS: { seo: "", sales: "" },
    OWNER_ACCOUNT_ID: OWNER,
    getUserById: async (id) => USERS[id] || null,
    getActiveSubscription: rowFor,
    getActiveSubscriptions: async (id) => { const r = await rowFor(id); return r ? [r] : []; },
    grantWelcomeBonusOnce: async (id) => { bonus.push("grantWelcomeBonusOnce:" + id); return { granted: true, amount: 1000 }; },
    creditWallet: async (id, amt) => { bonus.push("creditWallet:" + id + ":" + amt); },
    supabase: { from: (t) => chain(t) },
    stripe: { checkout: { sessions: { create: async (p) => { stripeCalls.push(p); return { url: "https://checkout.stripe.test/s1" }; } } } },
    FRONTEND_URL: "https://bizforce.test",
    nowIso: () => new Date().toISOString(),
    requireAuth: function requireAuth() {},
    app: { post(p, mw, h) { if (p === "/api/stripe/checkout") handler = h; } }
  };
  vm.createContext(ctx);
  const code = NAMES.map(n => liftFrom(src, n)).filter(Boolean).join("\n\n") + "\n\n" + routeFrom(src) + "\n\n" +
    "this.api = { getUserPlan, subscriptionEntitlement, requireActiveSubscription, refuseUnlessSubscribed, ownerPagePublic, autoRenewConsent };";
  vm.runInContext(code, ctx);
  const api = ctx.api;
  api.checkout = async function (user, body) {
    const res = { code: 200, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    await handler({ user: user, body: body || {} }, res);
    return { status: res.code, body: res.body };
  };
  return { api, logs, stripeCalls, dbCalls, subReads, bonus, ctx };
}

const NOW = Date.now();
const row = (userId, status, extra) => Object.assign({ id: "row-" + status, user_id: userId, plan: "all_access", status: status,
  stripe_subscription_id: "sub_check", stripe_customer_id: "cus_check", current_period_start: null, current_period_end: null,
  created_at: "2026-08-09T01:33:10.239Z" }, extra || {});
// The owner's live row, as read on Oct 27, 2026: past_due, start Sep 9, end null.
const LIVE = userId => row(userId, "past_due", { current_period_start: "2026-09-09T01:33:05.000Z", current_period_end: null });

(async function main() {
  console.log("\n══ code under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "as it stands") + "; other accounts compared with " + PRE + " ══");
  const SERVER = SRC["server.js"];

  /* ── A ─────────────────────────────────────────────────────────────────── */
  section("A. the owner is always entitled, as all_access, reason \"owner\"");
  {
    const shapes = [
      ["past_due, period end null (the live row)", LIVE(OWNER)],
      ["past_due, period long over", row(OWNER, "past_due", { current_period_start: iso(NOW - 90 * DAY), current_period_end: iso(NOW - 60 * DAY) })],
      ["canceled", row(OWNER, "canceled", { current_period_end: iso(NOW - 30 * DAY) })],
      ["no row at all", null],
      ["a row that cannot be read", new Error("subscriptions unreachable")]
    ];
    for (const [what, r] of shapes) {
      for (const role of ["admin", "user"]) {
        const b = buildServer(SERVER, { rows: { [OWNER]: r } });
        let p, err = null;
        try { p = await b.api.getUserPlan(OWNER, { id: OWNER, email: OWNER_EMAIL, role: role }); } catch (e) { err = e.message; }
        const ok = !err && p && p.active === true && p.plan === "all_access" && p.access_reason === "owner" && p.exempt === true &&
          p.inactive_reason === null && p.config && p.config.price === 199;
        check("A. " + what + ", role " + role + ": entitled, all_access, reason owner, exempt", ok, err || JSON.stringify(p && { active: p.active, plan: p.plan, why: p.access_reason }));
        if (r && !(r instanceof Error)) check("A. " + what + ", role " + role + ": the real row is returned as it is", p && same(p.subscription, r));
        if (r instanceof Error) check("A. " + what + ", role " + role + ": the failed read is logged, and the pass stands",
          p && p.subscription === null && b.logs.some(l => /OWNER PASS — the owner's subscription row could not be read: subscriptions unreachable/.test(l)), b.logs.join(" | "));
      }
    }
    {
      // Called the way the pass cache and ownerPagePublic call it: no user object.
      const b = buildServer(SERVER, { rows: { [OWNER]: LIVE(OWNER) } });
      const p = await b.api.getUserPlan(OWNER);
      check("A. with no user object (background passes, public pages): entitled as owner", p && p.active === true && p.access_reason === "owner");
      const e = b.api.subscriptionEntitlement(LIVE(OWNER));
      check("A. subscriptionEntitlement: the owner's live row entitles", e && e.active === true && e.inactive_reason === null, JSON.stringify(e));
      check("A. subscriptionEntitlement: so does his canceled row", b.api.subscriptionEntitlement(row(OWNER, "canceled")).active === true);
      check("A. ownerPagePublic: the owner's public pages are served", (await b.api.ownerPagePublic(OWNER)) === true);
      let nexted = false;
      const res = { code: 200, status(c) { this.code = c; return this; }, json() { return this; } };
      const req = { user: { id: OWNER, email: OWNER_EMAIL, role: "admin" }, method: "POST", route: { path: "/api/oracle/chat" } };
      await b.api.requireActiveSubscription(req, res, () => { nexted = true; });
      check("A. requireActiveSubscription lets the owner through, marked exempt, reason owner",
        nexted && res.code === 200 && req.planExempt === true && req.planAccessReason === "owner" && req.plan === "all_access");
      const res2 = { code: 200, status(c) { this.code = c; return this; }, json() { return this; } };
      check("A. refuseUnlessSubscribed does not refuse the owner",
        (await b.api.refuseUnlessSubscribed({ user: { id: OWNER, role: "user" } }, res2, "post /x")) === false && res2.code === 200);
    }
    // Every reader of entitlement goes through getUserPlan (or the pass cache, which calls it).
    const callers = [];
    // Comments blanked to spaces, so a comment that names getUserPlan is not a caller.
    const CODE = SERVER.replace(/\/\*[\s\S]*?\*\//g, c => c.replace(/[^\n]/g, " "));
    const re = /(?:await )?getUserPlan\(|planLookup\(|subscriptionEntitlement\(/g;
    let m;
    while ((m = re.exec(CODE))) {
      const before = CODE.slice(0, m.index);
      if (/(?:async )?function $/.test(before)) continue;
      const head = /(?:^(?:async )?function ([A-Za-z_$][\w$]*)|^app\.(?:get|post|put|delete|patch)\("([^"]+)"|^  (__\w+): function)[^\n]*$/gm;
      let h, last = null;
      while ((h = head.exec(before))) last = h[1] || h[2] || h[3];
      callers.push(m[0].replace(/^await /, "").replace("(", "") + " in " + last);
    }
    console.log("    entitlement readers:\n      " + callers.join("\n      "));
    const KNOWN = ["subscriptionEntitlement in getUserPlan", "getUserPlan in refuseUnlessSubscribed", "getUserPlan in ownerPagePublic",
      "getUserPlan in requireActiveSubscription", "planLookup in createPassEntitlementCache",
      "getUserPlan in enforceAgentLimit", "getUserPlan in enforceTaskLimit", "getUserPlan in /api/auth/me", "getUserPlan in /api/agents",
      "getUserPlan in dispatchToolCall", "getUserPlan in /api/agent-schedules", "subscriptionEntitlement in /api/stripe/checkout",
      "getUserPlan in /api/certifications/award", "getUserPlan in runAgentSchedulePass", "getUserPlan in __selfReviewPlanFor"];
    const extra = callers.filter(c => KNOWN.indexOf(c) === -1), missing = KNOWN.filter(c => callers.indexOf(c) === -1);
    check("A. the entitlement readers are exactly the " + KNOWN.length + " listed (a new one must be added here and reviewed)",
      extra.length === 0 && missing.length === 0, "new: " + extra.join(", ") + "; gone: " + missing.join(", "));
  }

  /* ── B ─────────────────────────────────────────────────────────────────── */
  section("B. no other account is the owner, and every other account answers as at " + PRE);
  {
    const rows = [
      ["the owner's live past_due row", u => LIVE(u)],
      ["past_due inside its grace", u => row(u, "past_due", { current_period_start: iso(NOW - 40 * DAY), current_period_end: iso(NOW - 2 * DAY) })],
      ["active, in period", u => row(u, "active", { current_period_end: iso(NOW + 20 * DAY) })],
      ["active, proven expired", u => row(u, "active", { current_period_end: iso(NOW - 30 * DAY) })],
      ["trialing", u => row(u, "trialing")],
      ["canceled", u => row(u, "canceled")],
      ["no row", () => null]
    ];
    for (const [what, mk] of rows) {
      for (const id of [OTHER, OTHER_ADMIN]) {
        const nb = buildServer(SERVER, { rows: { [id]: mk(id) } }), ob = buildServer(OLD_SERVER, { rows: { [id]: mk(id) } });
        const np = await nb.api.getUserPlan(id, USERS[id]), op = await ob.api.getUserPlan(id, USERS[id]);
        check("B. " + (id === OTHER ? "a member" : "an admin who is not the owner") + ", " + what + ": getUserPlan and its log are what " + PRE + " gives",
          same(np, op) && same(nb.logs, ob.logs), JSON.stringify(np).slice(0, 120) + " vs " + JSON.stringify(op).slice(0, 120));
        const r = mk(id);
        if (r) check("B. " + (id === OTHER ? "a member" : "an admin who is not the owner") + ", " + what + ": subscriptionEntitlement is what " + PRE + " gives",
          same(nb.api.subscriptionEntitlement(r), ob.api.subscriptionEntitlement(r)));
      }
    }
    const b = buildServer(SERVER, { rows: { [OTHER]: LIVE(OTHER) } });
    const p = await b.api.getUserPlan(OTHER, USERS[OTHER]);
    check("B. another account with the owner's exact past_due row is refused, reason past_due", p.active === false && p.inactive_reason === "past_due" && p.access_reason === null,
      JSON.stringify(p).slice(0, 200));
    const tricks = [
      ["the owner's email on the user object", { id: OTHER, email: OWNER_EMAIL, role: "user" }],
      ["the owner's id on the user object", { id: OWNER, email: "member@example.com", role: "user" }],
      ["an owner flag and access_reason on the user object", { id: OTHER, role: "user", owner: true, is_owner: true, access_reason: "owner", owner_account_id: OWNER }]
    ];
    for (const [what, user] of tricks) {
      const t = buildServer(SERVER, { rows: { [OTHER]: LIVE(OTHER) } });
      const tp = await t.api.getUserPlan(OTHER, user);
      check("B. " + what + ": still refused, not the owner", tp.active === false && tp.access_reason !== "owner", JSON.stringify(tp).slice(0, 160));
    }
    const env = { OWNER_ACCOUNT_ID: OTHER, BIZFORCE_OWNER_ID: OTHER, OWNER_ID: OTHER, OWNER_EMAIL: "member@example.com", BIZFORCE_OWNER_EMAIL: "member@example.com" };
    const e = buildServer(SERVER, { rows: { [OTHER]: LIVE(OTHER) }, env: env });
    const ep = await e.api.getUserPlan(OTHER, USERS[OTHER]);
    check("B. environment variables naming another account as owner change nothing", ep.active === false && ep.access_reason !== "owner", JSON.stringify(ep).slice(0, 160));
    check("B. ... and the real owner keeps the pass under them", (await e.api.getUserPlan(OWNER, USERS[OWNER])).access_reason === "owner");
    const isOwnerSrc = liftFrom(SERVER, "isOwnerAccount") || "";
    check("B. isOwnerAccount compares the id with OWNER_ACCOUNT_ID and reads nothing else (no env, email, role or request)",
      /userId === OWNER_ACCOUNT_ID/.test(isOwnerSrc) && !/process\.env|email|role|req\b|user\./.test(isOwnerSrc), isOwnerSrc);
    const ownerDecl = SERVER.match(/^(?:const|let|var)\s*\{?\s*OWNER_ACCOUNT_ID\b.*$/gm) || [];
    check("B. server.js takes OWNER_ACCOUNT_ID from lib/ownerAccount.js, once, and never assigns it",
      same(ownerDecl, ['const { OWNER_ACCOUNT_ID } = require("./lib/ownerAccount");']) && !/[^=!<>]\bOWNER_ACCOUNT_ID\s*=[^=]/.test(SERVER.replace(ownerDecl[0] || "", "")), ownerDecl.join(" | "));
    const ownerCode = SRC["lib/ownerAccount.js"].replace(/\/\*[\s\S]*?\*\//g, "");
    check("B. lib/ownerAccount.js holds the id as a string literal and reads no environment",
      /const OWNER_ACCOUNT_ID = "[0-9a-f-]{36}";/.test(ownerCode) && !/process\.env/.test(ownerCode));
  }

  /* ── C ─────────────────────────────────────────────────────────────────── */
  section("C. checkout refuses the owner before any Stripe call");
  {
    const b = buildServer(SERVER, { rows: { [OWNER]: LIVE(OWNER) } });
    const consent = b.api.autoRenewConsent("all_access");
    const body = { product: "all_access", auto_renew_consent: true, auto_renew_consent_text: consent.text, auto_renew_consent_version: consent.version };
    const r = await b.api.checkout({ id: OWNER, email: OWNER_EMAIL, role: "admin" }, body);
    check("C. the owner gets 409 owner_account with the exact message", r.status === 409 && r.body && r.body.error === "owner_account" && r.body.message === OWNER_MESSAGE,
      r.status + " " + JSON.stringify(r.body));
    check("C. no Stripe session, no database read or write, no subscription lookup",
      b.stripeCalls.length === 0 && b.dbCalls.length === 0 && b.subReads.length === 0, b.stripeCalls.length + " / " + b.dbCalls.join(",") + " / " + b.subReads.join(","));
    const b0 = buildServer(SERVER, { rows: { [OWNER]: LIVE(OWNER) } });
    const r0 = await b0.api.checkout({ id: OWNER, email: OWNER_EMAIL }, {});
    check("C. refused as owner even with no consent in the body", r0.status === 409 && r0.body.error === "owner_account" && b0.stripeCalls.length === 0);
    const c = buildServer(SERVER, { rows: {} });
    const rc = await c.api.checkout({ id: OTHER, email: "member@example.com" }, Object.assign({ user_id: OWNER, owner: true, email: OWNER_EMAIL }, body));
    check("C. another account, carrying the owner's id and email in its body, still reaches Stripe (one session)",
      rc.status === 200 && rc.body && rc.body.url && c.stripeCalls.length === 1, rc.status + " " + JSON.stringify(rc.body));
  }

  /* ── D ─────────────────────────────────────────────────────────────────── */
  section("D. the owner is left out of every count");
  {
    // lib/testAccounts.js from (possibly mutated) source, cached so lib/selfReview.js requires this copy.
    const taFile = path.join(REPO, "lib/testAccounts.js");
    const ta = new Module(taFile, module);
    ta.filename = taFile; ta.paths = Module._nodeModulePaths(path.dirname(taFile));
    ta._compile(SRC["lib/testAccounts.js"], taFile); ta.loaded = true;
    require.cache[taFile] = ta;
    const TA = ta.exports;
    const cases = [
      [{ id: OWNER }, true, "the owner, by id"],
      [{ id: OWNER.toUpperCase() }, true, "the owner's id in capitals"],
      [{ id: OTHER, email: OWNER_EMAIL }, false, "another account with the owner's email"],
      [{ id: OTHER, email: "owner+bftest3@gmail.com" }, true, "a +bftest account, as before"],
      [{ id: OTHER, email: "clean-run-1@bizforceai.invalid" }, true, "a harness account, as before"],
      [{ id: OTHER, email: "member@example.com" }, false, "an ordinary member"],
      [null, false, "no account"]
    ];
    cases.forEach(([u, want, what]) => check("D. isUncountedAccount: " + what + " is " + (want ? "not counted" : "counted"),
      typeof TA.isUncountedAccount === "function" && TA.isUncountedAccount(u) === want));
    check("D. the owner is not a test account (isTestAccount is unchanged)", TA.isTestAccount({ id: OWNER, email: OWNER_EMAIL }) === false);

    const srFile = path.join(REPO, "lib/selfReview.js");
    const sr = new Module(srFile, module);
    sr.filename = srFile; sr.paths = Module._nodeModulePaths(path.dirname(srFile));
    sr._compile(SRC["lib/selfReview.js"], srFile);
    const at = "2026-10-03T12:00:00.000Z";
    const tables = {
      users: [{ id: OWNER, email: OWNER_EMAIL }, { id: OTHER, email: "member@example.com" }],
      revenue_events: [OWNER, OTHER].flatMap(u => [{ user_id: u, amount: "199", currency: "usd", created_at: at }])
    };
    function fakeClient() {
      const reads = [];
      return {
        reads,
        from(table) {
          const q = { filters: [], head: false, counting: false, range: null, single: false };
          const api = {
            select(cols, o) { q.counting = !!(o && o.count); q.head = !!(o && o.head); return api; },
            eq(c, v) { q.filters.push(r => r[c] === v); return api; },
            gte(c, v) { q.filters.push(r => r[c] >= v); return api; },
            lt(c, v) { q.filters.push(r => r[c] < v); return api; },
            order() { return api; },
            range(a, b) { q.range = [a, b]; return api; },
            maybeSingle() { q.single = true; return api; },
            then(resolve, reject) {
              reads.push(table);
              let rows = (tables[table] || []).filter(r => q.filters.every(f => f(r)));
              const count = rows.length;
              if (q.range) rows = rows.slice(q.range[0], q.range[1] + 1);
              const out = q.single ? { data: rows[0] || null, error: null } : { data: q.head ? null : rows, count: q.counting ? count : null, error: null };
              return Promise.resolve(out).then(resolve, reject);
            }
          };
          return api;
        }
      };
    }
    const realErr = console.error; console.error = () => {};
    const run = async (id) => { const c = fakeClient(); const r = await sr.exports.gatherReviewMetrics({ supabase: c, userId: id,
      start: new Date("2026-10-01T00:00:00Z"), end: new Date("2026-10-08T00:00:00Z") }); return { m: r.metrics, reads: c.reads }; };
    let o, mem;
    try { o = await run(OWNER); mem = await run(OTHER); } finally { console.error = realErr; }
    check("D. self-review: a member's $199 is counted", mem.m.revenueEvents === 1 && mem.m.revenueTotal === 199, JSON.stringify(mem.m));
    check("D. self-review: the owner's own $199 is not revenue: 0 events, 0 total, revenue_events not read",
      o.m.revenueEvents === 0 && o.m.revenueTotal === 0 && o.reads.indexOf("revenue_events") === -1, JSON.stringify(o.m) + " " + o.reads.join(","));
    const files = { "server.js": SERVER };
    fs.readdirSync(path.join(REPO, "lib")).filter(f => /\.js$/.test(f)).forEach(f => {
      files["lib/" + f] = f === "selfReview.js" ? SRC["lib/selfReview.js"] : lf(fs.readFileSync(path.join(REPO, "lib", f), "utf8"));
    });
    const requirers = Object.keys(files).filter(f => /require\("\.\/(lib\/)?testAccounts"\)/.test(files[f]));
    const testOnly = Object.keys(files).filter(f => f !== "lib/testAccounts.js" && /isTestAccount\s*\(/.test(files[f]));
    check("D. every file that requires lib/testAccounts.js counts through isUncountedAccount (" + requirers.join(", ") + ")",
      requirers.length > 0 && requirers.every(f => /\{ isUncountedAccount \} = require\("\.\/(lib\/)?testAccounts"\)/.test(files[f])), requirers.join(", "));
    check("D. no file outside lib/testAccounts.js asks the test-only question", testOnly.length === 0, testOnly.join(", "));
  }

  /* ── E ─────────────────────────────────────────────────────────────────── */
  section("E. the owner pass grants no welcome bonus");
  {
    const b = buildServer(SERVER, { rows: { [OWNER]: LIVE(OWNER) } });
    await b.api.getUserPlan(OWNER, USERS[OWNER]);
    await b.api.getUserPlan(OWNER);
    check("E. the pass credits nothing and writes nothing (no bonus, no wallet, no database write)",
      b.bonus.length === 0 && b.dbCalls.length === 0, b.bonus.join(",") + " / " + b.dbCalls.join(","));
    const calls = [];
    const re = /grantWelcomeBonusOnce\(/g;
    let m;
    while ((m = re.exec(SERVER))) if (!/async function $/.test(SERVER.slice(0, m.index))) calls.push(m.index);
    const blockSig = '  if (event.type === "checkout.session.completed") {';
    const a = SERVER.indexOf(blockSig), z = a < 0 ? -1 : s.braceMatch(SERVER, a + blockSig.length - 1);
    check("E. grantWelcomeBonusOnce has one caller, inside checkout.session.completed", calls.length === 1 && a > 0 && calls[0] > a && calls[0] < z, calls.length);
  }

  /* ── F ─────────────────────────────────────────────────────────────────── */
  section("F. billing.html");
  {
    const { JSDOM, VirtualConsole } = require("jsdom");
    async function runBilling(me) {
      const d = new JSDOM(SRC["billing.html"], { url: "https://bizforceai.net/billing.html", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: new VirtualConsole() });
      const w = d.window, calls = [], errs = [];
      w.localStorage.setItem("bf_token", "tok-1");
      w.fetch = (url) => {
        calls.push(String(url));
        const body = /\/api\/auth\/me$/.test(url) ? me : { error: "stub" };
        const p = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(JSON.parse(JSON.stringify(body))) });
        p.catch(() => {});
        return p;
      };
      [...w.document.querySelectorAll("script:not([src])")].forEach(sc => { try { w.eval(sc.textContent); } catch (e) { errs.push(e.message); } });
      await flush();
      const doc = w.document;
      const shown = id => { let el = doc.getElementById(id); if (!el) return false;
        for (; el && el !== doc.body; el = el.parentElement) if (el.style.display === "none" || (el.style.display === "" && el.classList.contains("warn-banner"))) return false;
        return true; };
      const text = id => ((doc.getElementById(id) || {}).textContent || "").trim();
      return { doc, shown, text, errs, calls };
    }
    const ownerAccess = { active: true, exempt: true, access_reason: "owner", inactive_reason: null };
    const ownerRow = LIVE(OWNER);
    let p = await runBilling({ user: { id: OWNER }, subscription: ownerRow, access: ownerAccess });
    check("F. the owner sees \"Owner account: full access, no subscription needed\"", p.shown("ownerNotice") && p.text("ownerNotice") === "Owner account: full access, no subscription needed",
      p.text("ownerNotice") + " " + p.errs.join("; "));
    check("F. not the admin notice beside it", !p.shown("adminNotice"));
    check("F. his past_due Stripe row is shown as information (status past due)", p.shown("subContent") && p.text("statusText") === "past due");
    check("F. with \"Cancel this in Stripe so it stops retrying your card.\"", p.shown("ownerCancelWarn") && p.text("ownerCancelWarn") === "Cancel this in Stripe so it stops retrying your card.");
    check("F. and the Manage button, so he can", p.shown("portalBtn") && /Manage/.test(p.text("portalBtn")));
    check("F. not the failed-card line, not the renewal line, and no Subscribe button", !p.shown("pastDueWarn") && !p.shown("renewalNote") && !p.shown("checkoutBtn"));
    p = await runBilling({ user: { id: OWNER }, subscription: null, access: ownerAccess });
    check("F. the owner with no row: the owner notice and no Subscribe button", p.shown("ownerNotice") && !p.shown("checkoutBtn") && !p.shown("adminNotice"));
    p = await runBilling({ user: { id: OTHER }, subscription: LIVE(OTHER), access: { active: false, exempt: false, access_reason: null, inactive_reason: "past_due" } });
    check("F. a member with a past_due row: the failed-card line, no owner notice, no owner line",
      p.shown("pastDueWarn") && !p.shown("ownerNotice") && !p.shown("ownerCancelWarn") && p.shown("portalBtn"));
    p = await runBilling({ user: { id: OTHER_ADMIN }, subscription: null, access: { active: true, exempt: true, access_reason: "admin", inactive_reason: null } });
    check("F. an admin who is not the owner: the admin notice, not the owner's", p.shown("adminNotice") && !p.shown("ownerNotice"));
    p = await runBilling({ user: { id: OTHER }, subscription: null, access: { active: false, exempt: false, access_reason: null, inactive_reason: "no_subscription" } });
    check("F. a member with nothing: the Subscribe button, no owner notice", p.shown("checkoutBtn") && !p.shown("ownerNotice"));
  }

  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  // A crash is a failure, never the mutation-anchor exit (3).
  console.log("    FAIL  the check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
