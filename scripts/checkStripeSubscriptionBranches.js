"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkStripeSubscriptionBranches.js — what a Stripe subscription event does
   to the one subscriptions row a user has.

   WHY THIS IS A CHECK. The Stripe webhook is live in production
   (STRIPE_WEBHOOK_SECRET and STRIPE_SECRET_KEY are set on Railway, read
   2026-10-04), and these branches decide who is entitled and who is canceled.
   The marketplace checks call handleStripeEvent for the payment branch only;
   nothing covered customer.subscription.*. This was
   scripts/stripe-branches.test.js, which already proved the right things, but
   nothing ran it.

   WHAT THIS PROVES. The REAL handleStripeEvent, extracted from server.js by
   brace-matching and run in a vm context:
     created/updated  a-c, e: written when the row is empty, the same
                      subscription, a creation, or an entitling status
                      d: an update about an OLDER subscription carrying a
                      non-entitling status ("canceled") writes NOTHING — the
                      guard that stops a stale cancel overwriting the row of a
                      customer who has since bought again and is paying
                      f: a failed lookup throws, zero writes
     deleted          g-h: failed lookups throw, zero writes
                      i-a..i-f: cancel by subscription id, fall back to the
                      customer row, refuse a row holding a different id, and
                      the subscriptions → profiles write order

   ⚠️ THE DATABASE IS FAKE. Supabase is a stub that answers the select / upsert
   / update shapes the function uses today, and the expected writes are typed
   out here. A renamed column, a changed table, a different onConflict target
   or a constraint the real subscriptions table would reject would NOT be
   caught; this proves the branch decisions, not that the real database
   accepts them. No network, no database, no BIZFORCE_CHECK_USER_ID needed.

   MUTATE=stale-cancel  removes the older-subscription guard
                        (`!sameOrEmpty && !isCreated && !statusEntitles`) from
                        the extracted handler, in memory. d must go red: the
                        stale "canceled" is written over the current row.
                        Nothing is written to server.js.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const assert = require("assert");

const MUTATIONS = ["stale-cancel"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

const REPO = path.join(__dirname, "..");
const src = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const start = src.indexOf("async function handleStripeEvent(event) {");
assert(start > 0, "handleStripeEvent not found");
let depth = 0, i = src.indexOf("{", start), end = -1;
for (; i < src.length; i++) {
  const c = src[i];
  if (c === "{") depth++;
  else if (c === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
}
let fnSrc = src.slice(start, end);

if (MUTATE === "stale-cancel") {
  const GUARD = "      if (!sameOrEmpty && !isCreated && !statusEntitles) {\n";
  const hits = fnSrc.split(GUARD).length - 1;
  if (hits !== 1) { console.error("MUTATION REFUSED: expected exactly one older-subscription guard, found " + hits); process.exit(1); }
  fnSrc = fnSrc.replace(GUARD, "      if (false) {\n");
  console.log("\n!! MUTATION: the older-subscription guard is gone — a stale \"canceled\" update must now overwrite the current row.");
}

/* plan:
   lookups: { "<col>": { data, error } }   keyed by the first .eq column of a select
   subUpdateError / profUpdateError / upsertError */
function makeFake(plan) {
  const writes = [];
  const selects = [];
  function table(name) {
    return {
      select(cols) {
        const q = { table: name, cols, filters: [] };
        const api = {
          eq(col, val) { q.filters.push([col, val]); return api; },
          async maybeSingle() {
            selects.push(q);
            const r = (plan.lookups || {})[q.filters[0][0]];
            return r ? { data: r.data == null ? null : r.data, error: r.error || null } : { data: null, error: null };
          }
        };
        return api;
      },
      async upsert(payload, opts) {
        writes.push({ table: name, op: "upsert", payload, opts });
        return { error: plan.upsertError || null };
      },
      update(payload) {
        return {
          async eq(col, val) {
            writes.push({ table: name, op: "update", payload, where: [col, val] });
            if (name === "subscriptions" && plan.subUpdateError) return { error: plan.subUpdateError };
            if (name === "profiles" && plan.profUpdateError) return { error: plan.profUpdateError };
            return { error: null };
          }
        };
      }
    };
  }
  return { client: { from: table }, writes, selects };
}

function build(fake, logs) {
  const ctx = {
    supabase: fake.client,
    nowIso: () => "T0",
    console: {
      log: (m) => logs.push(["log", String(m)]),
      warn: (m) => logs.push(["warn", String(m)]),
      error: (m) => logs.push(["error", String(m)])
    },
    getPlanFromPriceId: (id) => (id === "price_ok" ? "all_access" : null),
    subscriptionPeriodIso: () => ({ periodStart: "PS", periodEnd: "PE" }),
    stripe: {}, stripeTest: {}, recordRevenueEvent: async () => {},
    normalizeEmail: (e) => e, escapeLikePattern: (e) => e
  };
  vm.createContext(ctx);
  vm.runInContext(fnSrc + "\nthis.handleStripeEvent = handleStripeEvent;", ctx);
  return ctx.handleStripeEvent;
}

function subEvent(type, status, cancelAtPeriodEnd) {
  return {
    id: "evt_1", type,
    data: { object: {
      id: "sub_EVT", customer: "cus_1", status,
      cancel_at_period_end: !!cancelAtPeriodEnd,
      items: { data: [{ price: { id: "price_ok" } }] }
    } }
  };
}
const DELETED = { id: "evt_1", type: "customer.subscription.deleted", data: { object: { id: "sub_EVT", customer: "cus_1" } } };

let failures = 0;
async function run(name, event, plan, check) {
  const logs = [];
  const fake = makeFake(plan);
  const fn = build(fake, logs);
  let threw = null;
  try { await fn(event); } catch (e) { threw = e; }
  try {
    check({ writes: JSON.parse(JSON.stringify(fake.writes)), selects: JSON.parse(JSON.stringify(fake.selects)), logs, threw });
    console.log("    pass  " + name);
  } catch (e) { failures++; console.log("    FAIL  " + name + "  [" + e.message + "]"); }
}

function expectedUpsert(status, userId) {
  return {
    table: "subscriptions", op: "upsert",
    payload: {
      user_id: userId, plan: "all_access", status, stripe_customer_id: "cus_1",
      stripe_subscription_id: "sub_EVT", stripe_price_id: "price_ok",
      current_period_start: "PS", current_period_end: "PE",
      cancel_at_period_end: false, updated_at: "T0"
    },
    opts: { onConflict: "user_id" }
  };
}
function expectedProfile(status, userId) {
  return { table: "profiles", op: "update", payload: { subscription_plan: "all_access", subscription_status: status, updated_at: "T0" }, where: ["user_id", userId] };
}

(async () => {
  const UPD = "customer.subscription.updated", CRE = "customer.subscription.created";

  console.log("\n══ created/updated branch (fake database) ══");

  await run("a) updated, stored id equals event id: written as today",
    subEvent(UPD, "past_due"),
    { lookups: { stripe_customer_id: { data: { user_id: "u1", stripe_subscription_id: "sub_EVT" } } } },
    ({ writes, threw, logs }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, [expectedUpsert("past_due", "u1"), expectedProfile("past_due", "u1")]);
      assert.deepStrictEqual(logs, []);
    });

  await run("b) updated, stored id null: written, stored id filled in",
    subEvent(UPD, "past_due"),
    { lookups: { stripe_customer_id: { data: { user_id: "u1", stripe_subscription_id: null } } } },
    ({ writes, threw, logs }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, [expectedUpsert("past_due", "u1"), expectedProfile("past_due", "u1")]);
      assert.strictEqual(writes[0].payload.stripe_subscription_id, "sub_EVT");
      assert.deepStrictEqual(logs, []);
    });

  await run("c) created, stored id is a different non-null id: written, one log naming both ids",
    subEvent(CRE, "incomplete"),
    { lookups: { stripe_customer_id: { data: { user_id: "u1", stripe_subscription_id: "sub_OLD" } } } },
    ({ writes, threw, logs }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, [expectedUpsert("incomplete", "u1"), expectedProfile("incomplete", "u1")]);
      assert.strictEqual(logs.length, 1, JSON.stringify(logs));
      assert(/sub_OLD/.test(logs[0][1]) && /sub_EVT/.test(logs[0][1]) && /evt_1/.test(logs[0][1]), logs[0][1]);
    });

  await run("d) updated, stored id different, status canceled: zero writes, one log naming both ids and the status",
    subEvent(UPD, "canceled"),
    { lookups: { stripe_customer_id: { data: { user_id: "u1", stripe_subscription_id: "sub_OLD" } } } },
    ({ writes, threw, logs }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, []);
      assert.strictEqual(logs.length, 1, JSON.stringify(logs));
      assert(/sub_OLD/.test(logs[0][1]) && /sub_EVT/.test(logs[0][1]) && /"canceled"/.test(logs[0][1]) && /evt_1/.test(logs[0][1]), logs[0][1]);
    });

  await run("e) updated, stored id different, status active: written",
    subEvent(UPD, "active"),
    { lookups: { stripe_customer_id: { data: { user_id: "u1", stripe_subscription_id: "sub_OLD" } } } },
    ({ writes, threw, logs }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, [expectedUpsert("active", "u1"), expectedProfile("active", "u1")]);
      assert.deepStrictEqual(logs, []);
    });

  await run("e2) updated, stored id different, status trialing: written",
    subEvent(UPD, "trialing"),
    { lookups: { stripe_customer_id: { data: { user_id: "u1", stripe_subscription_id: "sub_OLD" } } } },
    ({ writes, threw }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes.map(w => w.table), ["subscriptions", "profiles"]);
    });

  await run("f) created/updated lookup returns an error: throws, zero writes",
    subEvent(UPD, "active"),
    { lookups: { stripe_customer_id: { data: null, error: { message: "db-down" } } } },
    ({ writes, threw }) => {
      assert(threw, "expected throw");
      assert(/customer\.subscription\.updated/.test(threw.message), threw.message);
      assert(/lookup failed/.test(threw.message), threw.message);
      assert(/sub_EVT/.test(threw.message) && /db-down/.test(threw.message), threw.message);
      assert.deepStrictEqual(writes, []);
    });

  console.log("\n══ deleted branch: lookup errors ══");

  await run("g) deleted, lookup by stripe_subscription_id errors: throws, zero writes",
    DELETED,
    { lookups: { stripe_subscription_id: { data: null, error: { message: "db-down" } } } },
    ({ writes, threw, selects }) => {
      assert(threw, "expected throw");
      assert(/lookup by stripe_subscription_id failed/.test(threw.message), threw.message);
      assert(/sub_EVT/.test(threw.message), threw.message);
      assert.deepStrictEqual(writes, []);
      assert.strictEqual(selects.length, 1);
    });

  await run("h) deleted, no row by sub id, lookup by stripe_customer_id errors: throws, zero writes",
    DELETED,
    { lookups: { stripe_subscription_id: { data: null }, stripe_customer_id: { data: null, error: { message: "db-down" } } } },
    ({ writes, threw, selects }) => {
      assert(threw, "expected throw");
      assert(/lookup by stripe_customer_id failed/.test(threw.message), threw.message);
      assert(/sub_EVT/.test(threw.message), threw.message);
      assert.deepStrictEqual(writes, []);
      assert.strictEqual(selects.length, 2);
    });

  console.log("\n══ i) deleted branch: the six cases from 74e9f77 ══");
  const CANCEL_SUB = { status: "canceled", cancel_at_period_end: true, updated_at: "T0" };
  const CANCEL_PROF = { subscription_status: "canceled", updated_at: "T0" };

  await run("i-a) found by subscription id: both tables canceled, no throw",
    DELETED, { lookups: { stripe_subscription_id: { data: { user_id: "u1", stripe_subscription_id: "sub_EVT" } } } },
    ({ writes, threw }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, [
        { table: "subscriptions", op: "update", payload: CANCEL_SUB, where: ["user_id", "u1"] },
        { table: "profiles", op: "update", payload: CANCEL_PROF, where: ["user_id", "u1"] }
      ]);
    });

  await run("i-b) subscriptions update errors: throws naming subscriptions, profiles never attempted",
    DELETED, { lookups: { stripe_subscription_id: { data: { user_id: "u1", stripe_subscription_id: "sub_EVT" } } }, subUpdateError: { message: "boom-sub" } },
    ({ writes, threw }) => {
      assert(threw && /subscriptions update failed/.test(threw.message) && /sub_EVT/.test(threw.message), threw && threw.message);
      assert.deepStrictEqual(writes.map(w => w.table), ["subscriptions"]);
    });

  await run("i-c) profiles update errors: throws naming profiles",
    DELETED, { lookups: { stripe_subscription_id: { data: { user_id: "u1", stripe_subscription_id: "sub_EVT" } } }, profUpdateError: { message: "boom-prof" } },
    ({ writes, threw }) => {
      assert(threw && /profiles update failed/.test(threw.message), threw && threw.message);
      assert.deepStrictEqual(writes.map(w => w.table), ["subscriptions", "profiles"]);
    });

  await run("i-d) no sub-id match, customer row with null id: canceled and id filled in",
    DELETED, { lookups: { stripe_subscription_id: { data: null }, stripe_customer_id: { data: { user_id: "u2", stripe_subscription_id: null } } } },
    ({ writes, threw }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, [
        { table: "subscriptions", op: "update", payload: Object.assign({}, CANCEL_SUB, { stripe_subscription_id: "sub_EVT" }), where: ["user_id", "u2"] },
        { table: "profiles", op: "update", payload: CANCEL_PROF, where: ["user_id", "u2"] }
      ]);
    });

  await run("i-e) no sub-id match, customer row holds a DIFFERENT id: zero writes, one log naming both ids",
    DELETED, { lookups: { stripe_subscription_id: { data: null }, stripe_customer_id: { data: { user_id: "u2", stripe_subscription_id: "sub_OLD_CURRENT" } } } },
    ({ writes, threw, logs }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, []);
      assert.strictEqual(logs.length, 1, JSON.stringify(logs));
      assert(/sub_EVT/.test(logs[0][1]) && /sub_OLD_CURRENT/.test(logs[0][1]), logs[0][1]);
    });

  await run("i-f) no row either way: zero writes, no throw, one log line",
    DELETED, { lookups: {} },
    ({ writes, threw, logs }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, []);
      assert.strictEqual(logs.length, 1, JSON.stringify(logs));
      assert(/sub_EVT/.test(logs[0][1]) && /cus_1/.test(logs[0][1]), logs[0][1]);
    });

  console.log("\n    extracted handleStripeEvent: " + fnSrc.length + " chars");
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
