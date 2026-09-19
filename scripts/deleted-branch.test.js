"use strict";
/* Loads the REAL handleStripeEvent out of server.js (by locating the function
   and brace-matching to its end) and runs it in a vm context with a fake
   Supabase client. No network, no database, no app.listen. */
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");

const src = fs.readFileSync("C:/Users/ALGORITHM/BizForce-backend/server.js", "utf8");
const start = src.indexOf("async function handleStripeEvent(event) {");
assert(start > 0, "handleStripeEvent not found");
let depth = 0, i = src.indexOf("{", start), end = -1;
for (; i < src.length; i++) {
  const c = src[i];
  if (c === "{") depth++;
  else if (c === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
}
const fnSrc = src.slice(start, end);

function makeFake(plan) {
  // plan: { bySub, byCust, subUpdateError, profUpdateError }
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
            const f = q.filters[0];
            if (f[0] === "stripe_subscription_id") return { data: plan.bySub || null, error: null };
            if (f[0] === "stripe_customer_id") return { data: plan.byCust || null, error: null };
            return { data: null, error: null };
          }
        };
        return api;
      },
      update(payload) {
        return {
          async eq(col, val) {
            writes.push({ table: name, payload, where: [col, val] });
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
    nowIso: () => "2026-09-11T00:00:00.000Z",
    console: {
      log: (m) => logs.push(["log", String(m)]),
      error: (m) => logs.push(["error", String(m)])
    },
    // Referenced by other branches of the function body; never reached here.
    stripe: {}, stripeTest: {}, getPlanFromPriceId: () => null,
    subscriptionPeriodIso: () => ({}), recordRevenueEvent: async () => {},
    normalizeEmail: (e) => e, escapeLikePattern: (e) => e
  };
  vm.createContext(ctx);
  vm.runInContext(fnSrc + "\nthis.handleStripeEvent = handleStripeEvent;", ctx);
  return ctx.handleStripeEvent;
}

const EVENT = {
  id: "evt_1", type: "customer.subscription.deleted",
  data: { object: { id: "sub_NEW", customer: "cus_1" } }
};

async function run(name, plan, check) {
  const logs = [];
  const fake = makeFake(plan);
  const fn = build(fake, logs);
  let threw = null;
  try { await fn(EVENT); } catch (e) { threw = e; }
  try { check({ writes: JSON.parse(JSON.stringify(fake.writes)), selects: JSON.parse(JSON.stringify(fake.selects)), logs, threw }); console.log("PASS " + name); }
  catch (e) { console.log("FAIL " + name + ": " + e.message); process.exitCode = 1; }
}

(async () => {
  const CANCEL_SUB = { status: "canceled", cancel_at_period_end: true, updated_at: "2026-09-11T00:00:00.000Z" };
  const CANCEL_PROF = { subscription_status: "canceled", updated_at: "2026-09-11T00:00:00.000Z" };

  await run("a) found by subscription id: both tables canceled, no throw",
    { bySub: { user_id: "u1", stripe_subscription_id: "sub_NEW" } },
    ({ writes, threw }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, [
        { table: "subscriptions", payload: CANCEL_SUB, where: ["user_id", "u1"] },
        { table: "profiles", payload: CANCEL_PROF, where: ["user_id", "u1"] }
      ]);
    });

  await run("b) subscriptions update errors: throws naming subscriptions, profiles never attempted",
    { bySub: { user_id: "u1", stripe_subscription_id: "sub_NEW" }, subUpdateError: { message: "boom-sub" } },
    ({ writes, threw, logs }) => {
      assert(threw, "expected throw");
      assert(/customer\.subscription\.deleted/.test(threw.message), threw.message);
      assert(/subscriptions update failed/.test(threw.message), threw.message);
      assert(/sub_NEW/.test(threw.message), threw.message);
      assert(/boom-sub/.test(threw.message), threw.message);
      assert.deepStrictEqual(writes.map(w => w.table), ["subscriptions"]);
      assert(logs.some(l => l[0] === "error" && /subscriptions update failed/.test(l[1])));
    });

  await run("c) profiles update errors: throws naming profiles",
    { bySub: { user_id: "u1", stripe_subscription_id: "sub_NEW" }, profUpdateError: { message: "boom-prof" } },
    ({ writes, threw }) => {
      assert(threw, "expected throw");
      assert(/profiles update failed/.test(threw.message), threw.message);
      assert(/sub_NEW/.test(threw.message), threw.message);
      assert.deepStrictEqual(writes.map(w => w.table), ["subscriptions", "profiles"]);
    });

  await run("d) no sub-id match, customer row with null stripe_subscription_id: canceled and id filled in",
    { bySub: null, byCust: { user_id: "u2", stripe_subscription_id: null } },
    ({ writes, selects, threw }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(selects.map(s => s.filters[0]), [["stripe_subscription_id", "sub_NEW"], ["stripe_customer_id", "cus_1"]]);
      assert.deepStrictEqual(writes, [
        { table: "subscriptions", payload: Object.assign({}, CANCEL_SUB, { stripe_subscription_id: "sub_NEW" }), where: ["user_id", "u2"] },
        { table: "profiles", payload: CANCEL_PROF, where: ["user_id", "u2"] }
      ]);
    });

  await run("e) no sub-id match, customer row holds a DIFFERENT id: zero writes, one log naming both ids",
    { bySub: null, byCust: { user_id: "u2", stripe_subscription_id: "sub_OLD_CURRENT" } },
    ({ writes, threw, logs }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, []);
      assert.strictEqual(logs.length, 1, JSON.stringify(logs));
      assert(/sub_NEW/.test(logs[0][1]) && /sub_OLD_CURRENT/.test(logs[0][1]), logs[0][1]);
    });

  await run("f) no row either way: zero writes, no throw, one log line",
    { bySub: null, byCust: null },
    ({ writes, threw, logs }) => {
      assert.strictEqual(threw, null);
      assert.deepStrictEqual(writes, []);
      assert.strictEqual(logs.length, 1, JSON.stringify(logs));
      assert(/sub_NEW/.test(logs[0][1]) && /cus_1/.test(logs[0][1]), logs[0][1]);
    });

  console.log("extracted handleStripeEvent length: " + fnSrc.length + " chars");
})();
