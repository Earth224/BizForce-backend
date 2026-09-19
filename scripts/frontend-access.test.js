"use strict";
/* Extracts the decision functions from dashboard.html and billing.html
   (brace-matched out of the real files) and runs them against a stub DOM.
   Also parse-checks every inline <script> block in both files with vm.Script
   (the same V8 parse node --check performs). No browser, no network. */
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");

const FE = "C:/Users/ALGORITHM/BizForce-fronyend/";
const dash = fs.readFileSync(FE + "dashboard.html", "utf8");
const bill = fs.readFileSync(FE + "billing.html", "utf8");

function extract(src, signature) {
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

/* ── parse check of every inline script block ───────────────────────────── */
function parseCheck(name, html) {
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m, n = 0;
  while ((m = re.exec(html))) {
    n++;
    new vm.Script(m[1], { filename: name + "#script" + n });   // throws SyntaxError on failure
  }
  return n;
}

/* ── stub DOM ───────────────────────────────────────────────────────────── */
function stubDocument(ids) {
  const els = {};
  ids.forEach(id => { els[id] = { id, style: {}, textContent: "", className: "", innerHTML: "" }; });
  return { els, getElementById: (id) => { assert(els[id], "unexpected element #" + id); return els[id]; } };
}

/* ── dashboard ──────────────────────────────────────────────────────────── */
const dashCode = extract(dash, "function planStatusText(access, subscription) {");
const dashCtx = {}; vm.createContext(dashCtx);
vm.runInContext(dashCode + "\nthis.planStatusText = planStatusText;", dashCtx);
const planStatusText = dashCtx.planStatusText;
// Mirror the .then() body's derivation so the harness feeds the function what the page does.
function dashboardLine(data) {
  const access = (data && data.access != null) ? data.access : null;
  const subscription = (data && data.subscription) || null;
  return planStatusText(access, subscription);
}

/* ── billing ────────────────────────────────────────────────────────────── */
const billCode = [
  "function fmt(v) {", "function planLabel(plan) {", "function planPrice(plan) {",
  "function showActive(sub) {", "function showNone(unknown) {", "function showNeither() {",
  "function renderBilling(data) {"
].map(s => extract(bill, s)).join("\n");
const BILL_IDS = ["adminNotice", "subSkeleton", "subContent", "noSubContent", "noSubText", "checkoutBtn",
  "planName", "planPrice", "periodEnd", "memberSince", "statusBadge", "statusText", "cancelWarn", "pastDueWarn"];
function renderBillingWith(data) {
  const doc = stubDocument(BILL_IDS);
  const ctx = { document: doc }; vm.createContext(ctx);
  vm.runInContext(billCode + "\nthis.renderBilling = renderBilling;", ctx);
  ctx.renderBilling(data);
  const e = doc.els;
  return {
    adminNotice: e.adminNotice.style.display,
    subContent: e.subContent.style.display,
    noSubContent: e.noSubContent.style.display,
    noSubText: e.noSubText.textContent,
    checkoutBtn: e.checkoutBtn.style.display,             // "none" hidden, "" visible, undefined untouched
    periodEnd: e.periodEnd.textContent,
    badgeText: e.statusBadge.textContent,
    badgeClass: e.statusBadge.className,
    cancelWarn: e.cancelWarn.style.display,
    pastDueWarn: e.pastDueWarn.style.display
  };
}
// Subscribe button is visible iff noSubContent is shown AND the button is not hidden.
function subscribeVisible(v) { return v.noSubContent === "block" && v.checkoutBtn !== "none"; }
function portalVisible(v) { return v.subContent === "block"; }   // portalBtn lives inside #subContent

/* ── fixtures (the /api/auth/me shape) ──────────────────────────────────── */
const USER = { id: "u1", email: "a@b.c", role: "user", subscription_status: "free", subscription_plan: "free", subscription_active: false };
const PERIOD_END = "2026-10-11T00:00:00.000Z";
const row = (status, extra) => Object.assign({ id: "s1", plan: "all_access", status, current_period_end: PERIOD_END, created_at: "2026-01-11T00:00:00.000Z", cancel_at_period_end: false }, extra || {});
const ACCESS_ADMIN = { active: true, exempt: true, access_reason: "admin", inactive_reason: null };
const ACCESS_SUB   = { active: true, exempt: false, access_reason: "subscription", inactive_reason: null };
const ACCESS_NONE  = { active: false, exempt: false, access_reason: null, inactive_reason: "no_subscription" };
const ACCESS_STAT  = { active: false, exempt: false, access_reason: null, inactive_reason: "status" };

const T1 = "Admin access — full access, not billed.";
const T2 = "Subscription ACTIVE — Full Access";
const T3 = "Your last payment failed — update your card on the Billing page.";
const T4 = "Subscription not active yet.";
const T5 = "Subscription status could not be determined right now.";
const EXPECTED_DATE = new Date(PERIOD_END).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });

let failures = 0;
function t(name, fn) { try { fn(); console.log("PASS " + name); } catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); } }

t("parse: every inline <script> in dashboard.html and billing.html parses", () => {
  const nd = parseCheck("dashboard.html", dash), nb = parseCheck("billing.html", bill);
  assert(nd > 0 && nb > 0);
  console.log("   dashboard.html scripts: " + nd + ", billing.html scripts: " + nb);
});

t("a) admin, subscription null: dashboard case 1; billing admin notice, no Subscribe button", () => {
  const data = { user: Object.assign({}, USER, { role: "admin" }), profile: {}, subscription: null, access: ACCESS_ADMIN };
  assert.strictEqual(dashboardLine(data), T1);
  const v = renderBillingWith(data);
  assert.strictEqual(v.adminNotice, "block");
  assert.strictEqual(subscribeVisible(v), false);
  assert.strictEqual(v.subContent, "none");
  assert.strictEqual(v.noSubContent, "none");
});

t("a2) admin WITH a row: notice plus details", () => {
  const data = { user: USER, profile: {}, subscription: row("active"), access: ACCESS_ADMIN };
  const v = renderBillingWith(data);
  assert.strictEqual(v.adminNotice, "block");
  assert.strictEqual(portalVisible(v), true);
  assert.strictEqual(v.periodEnd, EXPECTED_DATE);
  assert.strictEqual(dashboardLine(data), T1);
});

t("b) active: dashboard case 2; billing renewal date from subscription, badge active, portal, no cancelWarn", () => {
  const data = { user: Object.assign({}, USER, { subscription_status: "active", subscription_active: true }), profile: {}, subscription: row("active"), access: ACCESS_SUB };
  assert.strictEqual(dashboardLine(data), T2);
  const v = renderBillingWith(data);
  assert.strictEqual(v.periodEnd, EXPECTED_DATE);
  assert.strictEqual(v.badgeText, "active");
  assert.strictEqual(v.badgeClass, "status-badge active");
  assert.strictEqual(portalVisible(v), true);
  assert.strictEqual(subscribeVisible(v), false);
  assert.strictEqual(v.cancelWarn, "none");
  assert.strictEqual(v.pastDueWarn, "none");
  assert.strictEqual(v.adminNotice, "none");
});

t("c) active with cancel_at_period_end: billing cancelWarn visible", () => {
  const data = { user: USER, profile: {}, subscription: row("active", { cancel_at_period_end: true }), access: ACCESS_SUB };
  const v = renderBillingWith(data);
  assert.strictEqual(v.cancelWarn, "block");
  assert.strictEqual(portalVisible(v), true);
});

t("d) trialing: dashboard case 2", () => {
  const data = { user: USER, profile: {}, subscription: row("trialing"), access: ACCESS_SUB };
  assert.strictEqual(dashboardLine(data), T2);
  const v = renderBillingWith(data);
  assert.strictEqual(v.badgeClass, "status-badge trialing");
});

t("e) past_due: dashboard case 3; billing past_due warning and portal button", () => {
  const data = { user: Object.assign({}, USER, { subscription_status: "past_due" }), profile: {}, subscription: row("past_due"), access: ACCESS_STAT };
  assert.strictEqual(dashboardLine(data), T3);
  const v = renderBillingWith(data);
  assert.strictEqual(v.pastDueWarn, "block");
  assert.strictEqual(portalVisible(v), true);
  assert.strictEqual(subscribeVisible(v), false);
  assert.strictEqual(v.badgeText, "past due");
});

t("f) no subscription, not entitled: dashboard case 4; billing Subscribe button", () => {
  const data = { user: USER, profile: {}, subscription: null, access: ACCESS_NONE };
  assert.strictEqual(dashboardLine(data), T4);
  const v = renderBillingWith(data);
  assert.strictEqual(subscribeVisible(v), true);
  assert.strictEqual(v.noSubText, "You don't have an active BizForce AI subscription.");
  assert.strictEqual(v.adminNotice, "none");
});

const gData = { user: USER, profile: {}, subscription: null, access: null };
t("g) access null, no subscription: dashboard case 5; billing case 5, no Subscribe button", () => {
  assert.strictEqual(dashboardLine(gData), T5);
  const v = renderBillingWith(gData);
  assert.strictEqual(v.noSubContent, "block");
  assert.strictEqual(v.noSubText, T5);
  assert.strictEqual(subscribeVisible(v), false);
  assert.strictEqual(v.adminNotice, "none");
});

t("h) access key absent entirely: identical to g", () => {
  const hData = { user: USER, profile: {}, subscription: null };
  assert.strictEqual(dashboardLine(hData), dashboardLine(gData));
  assert.deepStrictEqual(renderBillingWith(hData), renderBillingWith(gData));
});

console.log("failures: " + failures);
process.exitCode = failures ? 1 : 0;
