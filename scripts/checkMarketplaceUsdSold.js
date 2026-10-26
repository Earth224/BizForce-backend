"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMarketplaceUsdSold.js — a marketplace_usd payment sells nothing.

   BizForce Market trades in BizCash only (owner decision of 2026-10-26, option
   (i) of the USD marketplace recon in ae8e5db). This check used to prove the
   opposite: that a paid USD listing ended up sold and its file delivered. It
   now proves the switch-off, named entry by entry:

     webhook, a NEW marketplace_usd event
       BEFORE (ae8e5db)  wrote a marketplace_orders row, marked the listing
                         sold, and signed a download for a digital good
       AFTER             writes nothing: no order, nothing marked sold, no
                         file delivered; logs "[marketplace-usd] REFUSED" and
                         raises the marketplace_usd_refused ops alert
     webhook, the ONE PAST USD order's session delivered again
       BEFORE            "already recorded", nothing written
       AFTER             the same: read, logged, left as it is, no alert
     webhook signing secrets
       BEFORE            STRIPE_WEBHOOK_SECRET and STRIPE_TEST_WEBHOOK_SECRET,
                         everywhere: a test-card payment signed in test mode
                         was accepted by the live server
       AFTER             production (NODE_ENV=production or any Railway
                         variable) accepts the live secret only; a local run
                         still accepts both
     the test-mode client
       BEFORE            stripeTest, used by the USD checkout and the webhook's
                         payment-intent metadata fallback
       AFTER             removed; no code in server.js names it, its key, or
                         paymentIntents.retrieve

   HOW. The real handleStripeEvent, refuseMarketplaceUsdEvent,
   stripeWebhookSecrets and constructStripeEventFromSecrets are lifted from
   server.js into a vm, against a fake database that records every call and an
   ops alert stub that records every alert. Events are signed with the real
   stripe library's offline test-header helper. The network is blocked: a
   Stripe API call would fail the run. No database, no Stripe, no
   BIZFORCE_CHECK_USER_ID; nothing is written anywhere.

   MUTATE=webhook-marks-sold   the refusal marks the listing sold before it
                               logs. "nothing is written" must go red.
   MUTATE=no-alert             the refusal raises no ops alert.
   MUTATE=test-secret-in-production  production accepts the test secret again.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const net = require("net");
const dns = require("dns");
const MUT = require("./_shared");

const MUTATIONS = ["webhook-marks-sold", "no-alert", "test-secret-in-production"];
const MUTATE = process.env.MUTATE || "";
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + MUTATIONS.join(", "));
  process.exit(2);
}

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkMarketplaceUsdSold: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkMarketplaceUsdSold: no network"); };

const REPO = path.join(__dirname, "..");
let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");

if (MUTATE === "webhook-marks-sold") {
  SRC = MUT.replaceOnce(SRC,
    "  const detail = \"event \" + (event && event.id) + \", session \" + session.id + \", amount \" +\n",
    "  await supabase.from(\"marketplace_listings\").update({ status: \"sold\" }).eq(\"id\", m.listing_id);\n" +
    "  const detail = \"event \" + (event && event.id) + \", session \" + session.id + \", amount \" +\n", MUTATE);
}
if (MUTATE === "no-alert") {
  SRC = MUT.replaceOnce(SRC, "  opsAlerts.marketplaceUsdRefused({", "  ({", MUTATE);
}
if (MUTATE === "test-secret-in-production") {
  SRC = MUT.replaceOnce(SRC, "    ? [e.STRIPE_WEBHOOK_SECRET]\n", "    ? [e.STRIPE_WEBHOOK_SECRET, e.STRIPE_TEST_WEBHOOK_SECRET]\n", MUTATE);
}
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE + " (server.js, in memory)");

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the fake database: every call recorded ───────────────────────────── */
const WRITE_OPS = ["insert", "update", "upsert", "delete"];
function fakeDb(plan) {
  const calls = [];
  function from(table) {
    const q = { table: table, op: "select", filters: [] };
    const chain = {};
    ["select", "eq", "neq", "in", "is", "order", "limit", "gt", "lte", "or"].forEach(function (op) {
      chain[op] = function () { if (op !== "select") q.filters.push([op].concat([].slice.call(arguments))); return chain; };
    });
    WRITE_OPS.forEach(function (op) {
      chain[op] = function (payload) { q.op = op; q.payload = payload; return chain; };
    });
    const answer = function () {
      calls.push(JSON.parse(JSON.stringify(q)));
      if (q.op === "select" && table === "marketplace_orders") {
        if (plan.lookupError) return { data: null, error: { message: plan.lookupError } };
        const session = (q.filters.find(function (f) { return f[0] === "eq" && f[1] === "stripe_session_id"; }) || [])[2];
        return { data: plan.orders && plan.orders[session] ? { id: plan.orders[session] } : null, error: null };
      }
      return { data: q.op === "select" ? null : [{ id: "row" }], error: null };
    };
    chain.maybeSingle = async function () { return answer(); };
    chain.single = async function () { return answer(); };
    chain.then = function (res, rej) { return Promise.resolve(answer()).then(res, rej); };
    return chain;
  }
  const storage = {
    from: function (bucket) {
      return {
        createSignedUrl: async function (p) { calls.push({ table: "storage:" + bucket, op: "sign", payload: p }); return { data: { signedUrl: "https://signed" }, error: null }; },
        upload: async function (p) { calls.push({ table: "storage:" + bucket, op: "upload", payload: p }); return { data: {}, error: null }; },
        remove: async function (p) { calls.push({ table: "storage:" + bucket, op: "remove", payload: p }); return { data: {}, error: null }; }
      };
    }
  };
  return { client: { from: from, storage: storage }, calls: calls };
}
const writesIn = function (calls) { return calls.filter(function (c) { return c.op !== "select"; }); };

/* ── the real functions, lifted ────────────────────────────────────────── */
const NAMES = ["isProductionEnv", "stripeWebhookSecrets", "constructStripeEventFromSecrets", "refuseMarketplaceUsdEvent", "handleStripeEvent"];
const lifted = NAMES.map(function (n) {
  const d = MUT.definitionOf(SRC, n);
  if (!d) { console.log("    FAIL  " + n + " was not found in server.js"); process.exit(1); }
  return d;
}).join("\n\n");

const Stripe = require(require.resolve("stripe", { paths: [REPO] }));
const stripeLib = Stripe("sk_test_check_offline_not_a_key");

function build(plan) {
  const db = fakeDb(plan || {});
  const logs = [];
  const alerts = [];
  const ctx = {
    supabase: db.client,
    stripe: stripeLib,
    nowIso: function () { return "2026-10-26T12:00:00.000Z"; },
    console: {
      log: function () { logs.push(["log", [].join.call(arguments, " ")]); },
      warn: function () { logs.push(["warn", [].join.call(arguments, " ")]); },
      error: function () { logs.push(["error", [].join.call(arguments, " ")]); }
    },
    opsAlerts: {
      marketplaceUsdRefused: function (info) { alerts.push(JSON.parse(JSON.stringify(info))); return Promise.resolve({ sent: true }); },
      stripeWebhookFailed: function () { return Promise.resolve({}); },
      noteSignatureFailure: function () {}
    },
    recordRevenueEvent: async function () { throw new Error("no revenue_events row may be written for a marketplace_usd event"); },
    getPlanFromPriceId: function () { return null; },
    JSON: JSON, Object: Object, Array: Array, Number: Number, String: String, Promise: Promise, Error: Error, Date: Date, Buffer: Buffer
  };
  vm.createContext(ctx);
  vm.runInContext(lifted + "\nthis.__f = { " + NAMES.join(", ") + " };", ctx);
  return { f: ctx.__f, db: db, logs: logs, alerts: alerts };
}

function usdEvent(sessionId, extra) {
  return {
    id: "evt_" + sessionId, type: "checkout.session.completed",
    data: { object: Object.assign({
      id: sessionId, amount_total: 4900, payment_intent: "pi_" + sessionId,
      metadata: { kind: "marketplace_usd", listing_id: "listing-1", buyer_id: "buyer-1", seller_id: "seller-1" }
    }, extra || {}) }
  };
}

(async function main() {
  /* ── 1. a new marketplace_usd event ─────────────────────────────────── */
  console.log("\n══ 1. a NEW marketplace_usd event (BEFORE: order, sold, delivered · AFTER: nothing) ══");
  const fresh = build({ orders: {} });
  let threw = null;
  try { await fresh.f.handleStripeEvent(usdEvent("cs_new_after_switch_off")); } catch (e) { threw = e; }
  check("the handler returns normally, so Stripe gets a 200 and does not redeliver", threw === null, threw && threw.message);
  const freshWrites = writesIn(fresh.db.calls);
  check("nothing is written: no insert, update, upsert, delete or storage call", freshWrites.length === 0, JSON.stringify(freshWrites));
  check("no marketplace_orders row is created", !fresh.db.calls.some(function (c) { return c.table === "marketplace_orders" && c.op !== "select"; }));
  check("no listing is marked sold", !fresh.db.calls.some(function (c) { return c.table === "marketplace_listings" && c.op !== "select"; }));
  check("no file is delivered: no signed URL is made", !fresh.db.calls.some(function (c) { return c.op === "sign"; }));
  check("the only database call is the read for a past order with that session",
    fresh.db.calls.length === 1 && fresh.db.calls[0].table === "marketplace_orders" && fresh.db.calls[0].op === "select",
    JSON.stringify(fresh.db.calls));
  const refusedLog = fresh.logs.filter(function (l) { return l[0] === "error" && l[1].indexOf("[marketplace-usd] REFUSED") === 0; });
  check("it is logged as REFUSED, naming the session, the amount and the listing",
    refusedLog.length === 1 && /cs_new_after_switch_off/.test(refusedLog[0][1]) && /4900/.test(refusedLog[0][1]) && /listing-1/.test(refusedLog[0][1]),
    JSON.stringify(fresh.logs));
  check("one ops alert is raised, for that session",
    fresh.alerts.length === 1 && fresh.alerts[0].session_id === "cs_new_after_switch_off" && fresh.alerts[0].event_id === "evt_cs_new_after_switch_off",
    JSON.stringify(fresh.alerts));

  /* a digital listing and no listing id change nothing */
  const bare = build({ orders: {} });
  await bare.f.handleStripeEvent(usdEvent("cs_new_no_listing", { metadata: { kind: "marketplace_usd" } }));
  check("an event with no listing id is refused the same way: nothing written, one alert",
    writesIn(bare.db.calls).length === 0 && bare.alerts.length === 1, JSON.stringify(bare.db.calls) + " " + bare.alerts.length);

  /* a failed past-order read still writes nothing and still alerts */
  const failing = build({ lookupError: "connection reset" });
  threw = null;
  try { await failing.f.handleStripeEvent(usdEvent("cs_new_lookup_fails")); } catch (e) { threw = e; }
  check("a failed past-order read: no throw, nothing written, one alert that says the read failed",
    threw === null && writesIn(failing.db.calls).length === 0 && failing.alerts.length === 1 && /lookup failed: connection reset/.test(failing.alerts[0].detail),
    (threw && threw.message) + " " + JSON.stringify(failing.alerts));

  /* ── 2. the one past USD order ──────────────────────────────────────── */
  console.log("\n══ 2. the past USD order's session, delivered again (read-only) ══");
  const past = build({ orders: { cs_past_order: "order-past-1" } });
  await past.f.handleStripeEvent(usdEvent("cs_past_order"));
  check("nothing is written for the past order", writesIn(past.db.calls).length === 0, JSON.stringify(past.db.calls));
  check("no alert: it is the order recorded before the switch-off", past.alerts.length === 0, JSON.stringify(past.alerts));
  check("it is logged as left as it is, naming the order",
    past.logs.some(function (l) { return l[0] === "log" && /cs_past_order is order order-past-1, recorded before USD sales were switched off\. Left as it is\./.test(l[1]); }),
    JSON.stringify(past.logs));

  /* ── 3. the signing secrets ─────────────────────────────────────────── */
  console.log("\n══ 3. the webhook's signing secrets (BEFORE: test secret everywhere · AFTER: refused in production) ══");
  const sec = build({}).f;
  const LIVE = "whsec_live_check", TEST = "whsec_test_check";
  const PROD_ENVS = [
    ["NODE_ENV=production", { NODE_ENV: "production" }],
    ["Railway (RAILWAY_ENVIRONMENT), NODE_ENV unset", { RAILWAY_ENVIRONMENT: "production" }],
    ["Railway (RAILWAY_ENVIRONMENT_NAME), NODE_ENV=development", { NODE_ENV: "development", RAILWAY_ENVIRONMENT_NAME: "production" }],
    ["Railway (RAILWAY_PROJECT_ID)", { RAILWAY_PROJECT_ID: "p1" }]
  ];
  const payload = JSON.stringify({ id: "evt_sig", object: "event", type: "checkout.session.completed", data: { object: { id: "cs_sig", metadata: { kind: "marketplace_usd" } } } });
  const signedTest = stripeLib.webhooks.generateTestHeaderString({ payload: payload, secret: TEST });
  const signedLive = stripeLib.webhooks.generateTestHeaderString({ payload: payload, secret: LIVE });
  PROD_ENVS.forEach(function (pe) {
    const env = Object.assign({ STRIPE_WEBHOOK_SECRET: LIVE, STRIPE_TEST_WEBHOOK_SECRET: TEST }, pe[1]);
    const list = sec.stripeWebhookSecrets(env);
    check(pe[0] + ": the live secret only", JSON.stringify(list) === JSON.stringify([LIVE]), JSON.stringify(list));
    let refused = null;
    try { sec.constructStripeEventFromSecrets(Buffer.from(payload), signedTest, list); } catch (e) { refused = e; }
    check(pe[0] + ": an event signed with the test secret is refused", refused !== null);
    let ok = null;
    try { ok = sec.constructStripeEventFromSecrets(Buffer.from(payload), signedLive, list); } catch (e) { ok = null; }
    check(pe[0] + ": an event signed with the live secret is accepted", !!ok && ok.id === "evt_sig");
  });
  const local = sec.stripeWebhookSecrets({ STRIPE_WEBHOOK_SECRET: LIVE, STRIPE_TEST_WEBHOOK_SECRET: TEST, NODE_ENV: "development" });
  check("a local run (no production marker) still accepts both, for replaying test events",
    JSON.stringify(local) === JSON.stringify([LIVE, TEST]), JSON.stringify(local));
  check("the webhook route reads its secrets from stripeWebhookSecrets(process.env)",
    SRC.indexOf("event = constructStripeEventFromSecrets(req.body, signature, stripeWebhookSecrets(process.env));") !== -1);
  check("the comment says why the test secret is refused in production",
    /STRIPE_TEST_WEBHOOK_SECRET signs Stripe TEST-mode events, which anyone\n\s+can produce with a test card and no money/.test(SRC));

  /* ── 4. the test-mode client is gone ────────────────────────────────── */
  console.log("\n══ 4. the test-mode Stripe client (BEFORE: stripeTest · AFTER: removed) ══");
  const code = SRC.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
  check("no code names stripeTest", !/\bstripeTest\b/.test(code), (code.match(/[^\n]*\bstripeTest\b[^\n]*/) || [""])[0].trim());
  check("no code reads STRIPE_TEST_SECRET_KEY", code.indexOf("STRIPE_TEST_SECRET_KEY") === -1);
  check("no code retrieves a payment intent", code.indexOf("paymentIntents.retrieve") === -1);
  check("the only Stripe checkout session server.js creates is the subscription's",
    (code.match(/checkout\.sessions\.create\(/g) || []).length === 1 && code.indexOf("await stripe.checkout.sessions.create(sessionParams);") !== -1);

  check("zero network: no Stripe or database call left this process", NETWORK.length === 0, JSON.stringify(NETWORK));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check threw: " + ((e && e.stack) || e)); process.exit(1); });
