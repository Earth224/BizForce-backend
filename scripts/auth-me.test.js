"use strict";
/* Extracts the inline GET /api/auth/me route (app.get(...) call, brace-matched)
   from both the committed HEAD server.js and the working copy, registers each
   against a fake `app` that captures the handler, and invokes it with fake
   req/res. Real publicUser is extracted too. No network, no database. */
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");
const { execSync } = require("child_process");

const REPO = "C:/Users/ALGORITHM/BizForce-backend";
const before = execSync("git show HEAD:server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");
const after = fs.readFileSync(REPO + "/server.js", "utf8");

function extractBlock(src, signature) {
  const start = src.indexOf(signature);
  assert(start > 0, signature + " not found");
  let depth = 0, i = src.indexOf("{", start), end = -1;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  return src.slice(start, end);
}
function extractRoute(src) {
  // app.get("/api/auth/me", requireAuth, async function (req, res, next) { ... });
  const start = src.indexOf('app.get("/api/auth/me"');
  assert(start > 0, "route not found");
  let depth = 0, i = src.indexOf("{", start), end = -1;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  const tail = src.slice(end, end + 3);
  assert.strictEqual(tail, ");\n", "unexpected route terminator: " + JSON.stringify(tail));
  return src.slice(start, end + 2);
}

function buildHandler(src, stubs, logs) {
  const ctx = {
    requireAuth: function () {},
    console: { log: (m) => logs.push(["log", String(m)]), error: (m) => logs.push(["error", String(m)]), warn: (m) => logs.push(["warn", String(m)]) },
    getProfileByUserId: stubs.getProfileByUserId,
    getActiveSubscription: stubs.getActiveSubscription,
    getUserPlan: stubs.getUserPlan || (async () => { throw new Error("getUserPlan should not be reached in the pre-change route"); })
  };
  let captured = null;
  ctx.app = { get: function (path) { captured = arguments[arguments.length - 1]; } };
  vm.createContext(ctx);
  vm.runInContext(extractBlock(src, "function publicUser(user) {") + "\n" + extractRoute(src), ctx);
  assert(typeof captured === "function", "handler not captured");
  return captured;
}

async function invoke(handler, user) {
  const res = { statusCode: 200, body: undefined,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler({ user }, res, (e) => { nextErr = e || new Error("next() called"); });
  return { status: res.statusCode, body: res.body, nextErr };
}

const ADMIN = { id: "u-admin", email: "owner@example.com", role: "admin", banned_at: null, created_at: "2026-01-01T00:00:00.000Z" };
const USER  = { id: "u-paid",  email: "paid@example.com",  role: "user",  banned_at: null, created_at: "2026-02-01T00:00:00.000Z" };
const NONE  = { id: "u-none",  email: "none@example.com",  role: "user",  banned_at: null, created_at: "2026-03-01T00:00:00.000Z" };
const PROFILE = { id: "p1", user_id: "x", business_name: "Biz", subscription_status: "canceled", subscription_plan: "all_access" };
const ACTIVE_ROW = { id: "s1", user_id: "u-paid", plan: "all_access", status: "active", stripe_subscription_id: "sub_1", current_period_end: "2099-01-01T00:00:00.000Z" };

/* getActiveSubscription filters to active/trialing/past_due, so a canceled row
   comes back null — that is what the real helper does and what the stub does. */
function stubsFor(kind, planImpl) {
  return {
    getProfileByUserId: async () => PROFILE,
    getActiveSubscription: async () => (kind === "active" ? ACTIVE_ROW : null),
    getUserPlan: planImpl
  };
}

let failures = 0;
async function t(name, fn) {
  try { await fn(); console.log("PASS " + name); }
  catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); }
}
function withoutAccess(body) { const c = Object.assign({}, body); delete c.access; return c; }

(async () => {
  // a) admin, canceled row
  const adminPlan = async () => ({ plan: "admin_exempt", config: {}, subscription: null, active: true, expired: false, inactive_reason: null, exempt: true, access_reason: "admin" });
  let logsA = [], logsA0 = [];
  const afterA  = await invoke(buildHandler(after,  stubsFor("canceled", adminPlan), logsA),  ADMIN);
  const beforeA = await invoke(buildHandler(before, stubsFor("canceled", adminPlan), logsA0), ADMIN);
  await t("a) admin with canceled row: access.active true, exempt true, access_reason admin; subscription_status still free", async () => {
    assert.strictEqual(afterA.status, 200);
    assert.deepStrictEqual(afterA.body.access, { active: true, exempt: true, access_reason: "admin", inactive_reason: null });
    assert.strictEqual(afterA.body.user.subscription_status, "free");
    assert.strictEqual(afterA.body.user.subscription_active, false);
    assert.strictEqual(afterA.body.user.subscription_plan, "free");
    assert.strictEqual(afterA.body.subscription, null);
    assert.deepStrictEqual(logsA, []);
  });

  // b) ordinary user, active row
  const paidPlan = async () => ({ plan: "all_access", config: {}, subscription: ACTIVE_ROW, active: true, expired: false, inactive_reason: null, exempt: false, access_reason: "subscription" });
  let logsB = [], logsB0 = [];
  const afterB  = await invoke(buildHandler(after,  stubsFor("active", paidPlan), logsB),  USER);
  const beforeB = await invoke(buildHandler(before, stubsFor("active", paidPlan), logsB0), USER);
  await t("b) ordinary user with active row: access.active true, exempt false", async () => {
    assert.deepStrictEqual(afterB.body.access, { active: true, exempt: false, access_reason: "subscription", inactive_reason: null });
    assert.strictEqual(afterB.body.user.subscription_status, "active");
    assert.strictEqual(afterB.body.user.subscription_active, true);
    assert.strictEqual(afterB.body.user.subscription_plan, "all_access");
  });

  // c) no subscription
  const nonePlan = async () => ({ plan: null, config: null, subscription: null, active: false, expired: false, inactive_reason: "no_subscription", exempt: false, access_reason: null });
  let logsC = [], logsC0 = [];
  const afterC  = await invoke(buildHandler(after,  stubsFor("none", nonePlan), logsC),  NONE);
  const beforeC = await invoke(buildHandler(before, stubsFor("none", nonePlan), logsC0), NONE);
  await t("c) no subscription: access.active false, inactive_reason present", async () => {
    assert.deepStrictEqual(afterC.body.access, { active: false, exempt: false, access_reason: null, inactive_reason: "no_subscription" });
    assert.strictEqual(afterC.body.user.subscription_status, "free");
  });

  // d) getUserPlan throws
  let logsD = [];
  const afterD = await invoke(buildHandler(after, stubsFor("active", async () => { throw new Error("plan-db-down"); }), logsD), USER);
  await t("d) getUserPlan throws: 200, access null, every existing field present, exactly one log naming the user id", async () => {
    assert.strictEqual(afterD.status, 200);
    assert.strictEqual(afterD.nextErr, null);
    assert.strictEqual(afterD.body.access, null);
    assert.deepStrictEqual(Object.keys(afterD.body).sort(), ["access", "profile", "subscription", "user"]);
    assert.deepStrictEqual(Object.keys(afterD.body.user).sort(),
      ["banned_at", "created_at", "email", "id", "role", "subscription_active", "subscription_plan", "subscription_status"]);
    assert.deepStrictEqual(withoutAccess(afterD.body), beforeB.body);
    assert.strictEqual(logsD.length, 1, JSON.stringify(logsD));
    assert(/u-paid/.test(logsD[0][1]) && /plan-db-down/.test(logsD[0][1]), logsD[0][1]);
  });

  // d2) getUserPlan returns nothing
  let logsD2 = [];
  const afterD2 = await invoke(buildHandler(after, stubsFor("active", async () => null), logsD2), USER);
  await t("d2) getUserPlan returns null: 200, access null, one log naming the user id", async () => {
    assert.strictEqual(afterD2.status, 200);
    assert.strictEqual(afterD2.body.access, null);
    assert.strictEqual(logsD2.length, 1);
    assert(/u-paid/.test(logsD2[0][1]));
  });

  // e) key-for-key identity minus access
  await t("e-a) admin: response minus access identical to pre-change", async () => {
    assert.deepStrictEqual(withoutAccess(afterA.body), beforeA.body);
    assert.deepStrictEqual(Object.keys(beforeA.body), ["user", "profile", "subscription"]);
    assert.deepStrictEqual(Object.keys(afterA.body), ["user", "profile", "subscription", "access"]);
  });
  await t("e-b) paid user: response minus access identical to pre-change", async () => {
    assert.deepStrictEqual(withoutAccess(afterB.body), beforeB.body);
  });
  await t("e-c) no subscription: response minus access identical to pre-change", async () => {
    assert.deepStrictEqual(withoutAccess(afterC.body), beforeC.body);
  });

  console.log("failures: " + failures);
  process.exitCode = failures ? 1 : 0;
})();
