"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkLaunchAccessFixes.js — the launch audit's subscriber-access fixes.

   Backend "Subscribers keep access through a failed card's grace, and cannot
   be charged twice" and frontend "Clear subscribe prompts, day-8 sessions
   handled everywhere, stale pages removed". Audit items #4, #7, #8, #10 and
   #11 are proved here; #12 (no sid-less tokens, a failed session lookup
   fails closed) is proved by checkRequireAuthSidGrace.js.

   WHAT THIS PROVES
     A. #4 past_due grace, through the REAL getUserPlan,
        subscriptionEntitlement and pastDueGraceState lifted from
        server.js: past_due inside the grace is entitled, outside is
        refused with reason "past_due", grace 0 refuses at once, a row with no
        usable period is refused, the grace is counted from the period
        boundary the payment fell due on, and SUBSCRIPTION_PAST_DUE_GRACE_DAYS
        parses like SUBSCRIPTION_GRACE_DAYS (default 14, clamped 0..30).
        active, trialing and canceled answer exactly as before.
     B. #4 the 402 for a past_due row past its grace says the payment failed
        and how to update the card, and carries billing_url.
     C. #11 the real POST /api/stripe/checkout, lifted: an account holding an
        entitling subscription (active, trialing, past_due inside its grace)
        is refused with 409, a message and billing_url, and NO Stripe session
        is created; a lapsed row does not block; a failed lookup refuses.
     D. #7 an agent page renders the 402's message and Billing link: the real
        scripts/agent-profile.js and scripts/bf-paywall.js run in a vm, a tool
        run and a plan dispatch each answered by the real 402 body. Every page
        that loads agent-profile.js loads bf-paywall.js before it, and the
        pages' own gated calls (seo, sales, content) take the same branch.
     E. #7 the dashboard's real plan-status code, lifted: an unentitled account
        sees "Subscribe to start" in place of the three gated sections; an
        entitled one, an unknown answer, or the seconds after a payment do
        not; past_due gets "Update your card". "Welcome back" only once the
        account is past its first day (users.created_at, from /api/auth/me).
     F. #8 ai-agents, index, my-purchases, profile and seller load
        bf-session.js in the head: the two protected pages as a plain tag, the
        three public pages only when a token is present (run in a vm).
     G. #10 oracle.backup.html and oracle.backup2.html are gone from the
        frontend tree and from git, and no tracked file names them.

   NO NETWORK. NO DATABASE. Supabase, Stripe and fetch are in-memory stubs.

   MUTATE=<name> edits server.js or a frontend file IN MEMORY.
   MUTATE=all runs each in its own process (scripts/_shared.js): a search text
   that does not match exactly once is an ERROR, never a catch.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const AGENT_PAGES = ["ads-agent.html", "broker-agent.html", "community-agent.html", "email-agent.html", "etsy-agent.html",
  "executive-agent.html", "influencer-agent.html", "operations-agent.html", "publicist-agent.html", "rd-agent.html",
  "reputation-agent.html", "run.html", "store-agent.html", "vertical-marketing-agent.html", "agents/analytics.html",
  "agents/content.html", "agents/sales.html", "agents/seo.html", "agents/social.html"];
const SESSION_PAGES = ["ai-agents.html", "my-purchases.html"];
const SESSION_IF_SIGNED_IN_PAGES = ["index.html", "profile.html", "seller.html"];
const AP = "scripts/agent-profile.js", PAYWALL = "scripts/bf-paywall.js", DASH = "dashboard.html";

const MUTATIONS = {
  // #4: past_due never entitles again — the grace is ignored
  "grace-ignored": [["server.js",
    "  const active = (statusEntitles && !expiry.proven) || (pastDue !== null && pastDue.within === true);\n",
    "  const active = statusEntitles && !expiry.proven;\n"]],
  // #4: a grace of 0 still lets the first instant through
  "grace-zero-allows": [["server.js", "    within: graceDays > 0 && nowMs < endsMs,\n", "    within: nowMs <= endsMs,\n"]],
  // #4: the grace is counted from the end of a period that has not ended yet
  "grace-from-future-end": [["server.js", "  if (endMs !== null && endMs <= nowMs) {\n", "  if (endMs !== null) {\n"]],
  // #11: a second checkout is allowed
  "double-checkout-allowed": [["server.js", "    if (alreadyHeld) {\n      return res.status(409).json({\n",
    "    if (false) {\n      return res.status(409).json({\n"]],
  // #11: a failed lookup lets the checkout go ahead
  "checkout-lookup-fails-open": [["server.js", "      heldSubscriptions = await getActiveSubscriptions(req.user.id);\n    } catch (heldError) {\n",
    "      heldSubscriptions = await getActiveSubscriptions(req.user.id);\n    } catch (heldError) {\n      heldSubscriptions = [];\n    }\n    if (false) {\n"]],
  // #7: a tool run shows "HTTP 402" again
  "agent-402-as-http": [[AP, "        if (showPaywall(document.getElementById(toolDomId(tool.id, \"msg\")), res)) return;\n\n", ""]],
  // #7: a page that loads agent-profile.js without bf-paywall.js
  "agent-page-missing-paywall": [["agents/seo.html", "<script src=\"/scripts/bf-paywall.js\"></script>\n", ""]],
  // #7: the dashboard never shows the subscribe panel
  "panel-not-shown": [[DASH, "        showStartPanel(access);\n", ""]],
  // #7: the panel shows on any answer that is not a definite "entitled"
  "panel-on-unknown": [[DASH, "  if (!access || access.active !== false) return false;\n", "  if (!access || access.active === true) return false;\n"]],
  // #7: "Welcome back" for everyone, first visit or not
  "welcome-back-always": [[DASH, "  if (!isFinite(created) || (nowMs - created) < FIRST_VISIT_MS) return line;\n", ""]],
  // #8: a page missing bf-session
  "page-missing-bf-session": [["my-purchases.html", "<head>\n<script src=\"/scripts/bf-session.js\"></script>\n", "<head>\n"]],
  // #8: a public page loads bf-session.js for signed-out visitors too
  "public-page-session-always": [["seller.html", "    if (localStorage.getItem(\"bf_token\")) {\n      document.write(", "    if (true) {\n      document.write("]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

/* ── sources, LF, mutated in memory ─────────────────────────────────────── */
const lf = t => t.replace(/\r\n/g, "\n");
const SRC = { "server.js": s.after };
const FE_FILES = [AP, PAYWALL, DASH].concat(AGENT_PAGES, SESSION_PAGES, SESSION_IF_SIGNED_IN_PAGES);
FE_FILES.forEach(f => { SRC[f] = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8")); });
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) SRC[file] = s.replaceOnce(SRC[file], from, to, MUTATE);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };
const DAY = 86400000;
const iso = ms => new Date(ms).toISOString();

/* ── the backend, lifted from server.js ─────────────────────────────────── */
/* A top-level definition, read from the (possibly mutated) source. A function
   ends at its matching brace; a var/const ends at the first ";" + line break
   after which the text so far compiles, so a blank line inside an IIFE or an
   object literal cannot cut it short. */
function lift(name) {
  const src = SRC["server.js"];
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (m) return src.slice(m.index, s.braceMatch(src, src.indexOf(") {", m.index) + 2));
  const v = new RegExp("^(?:var|const|let) " + name + "[ \t]*=", "m").exec(src);
  if (!v) throw new Error("not found in server.js: " + name);
  const brk = /;\n/g; brk.lastIndex = v.index;
  let b;
  while ((b = brk.exec(src))) {
    const piece = src.slice(v.index, b.index + 1);
    try { new vm.Script(piece); return piece; } catch (e) { /* not the end yet */ }
  }
  throw new Error("no end found for " + name);
}

const ENTITLEMENT_NAMES = ["PAST_DUE_GRACE_DEFAULT_DAYS", "PAST_DUE_GRACE_MAX_DAYS", "parsePastDueGraceDays", "pastDueTimeOf", "pastDueGraceState",
  "SUBSCRIPTION_GRACE_DAYS", "SUBSCRIPTION_PAST_DUE_GRACE_DAYS", "subscriptionExpiryState", "subscriptionEntitlement",
  "ADMIN_EXEMPT_PLAN", "ADMIN_EXEMPT_CONFIG", "isExemptRole", "getUserPlan",
  "BILLING_URL", "SUBSCRIPTION_REFUSAL_MESSAGES", "SUBSCRIPTION_REFUSAL_DEFAULT", "SUBSCRIPTION_PAST_DUE_MESSAGE", "subscriptionRequiredBody",
  "CHECKOUT_PRODUCTS"];
const ROUTE_SIG = 'app.post("/api/stripe/checkout", requireAuth, async function (req, res) {';
function checkoutRoute() {
  const src = SRC["server.js"];
  const start = src.indexOf(ROUTE_SIG);
  if (start < 0) throw new Error("checkout route not found");
  const end = s.braceMatch(src, src.indexOf("{", start + ROUTE_SIG.length - 2));
  return src.slice(start, end + 2);
}

function buildServer(opts) {
  opts = opts || {};
  const logs = [], stripeCalls = [], dbWrites = [];
  let handler = null;
  const chain = () => {
    const q = {};
    ["select", "eq", "not", "order", "limit", "in", "is"].forEach(k => { q[k] = () => q; });
    ["insert", "update", "upsert", "delete"].forEach(k => { q[k] = (p) => { dbWrites.push(k); return q; }; });
    q.maybeSingle = async () => ({ data: { stripe_customer_id: "cus_check" }, error: null });
    return q;
  };
  const ctx = {
    process: { env: Object.assign({ STRIPE_STARTER_PRICE_ID: "price_check" }, opts.env || {}) },
    console: { log: m => logs.push(String(m)), warn: m => logs.push(String(m)), error: m => logs.push(String(m)) },
    Date: opts.Date || Date, Math, Number, String, Object, Array, JSON, Promise,
    AGENT_SYSTEM_PROMPTS: { seo: "" },
    getPlanConfig: plan => (plan === "all_access" ? { name: "All Access" } : null),
    getUserById: async () => opts.user || { id: "u1", role: "user" },
    getActiveSubscription: async () => (opts.subs && opts.subs[0]) || null,
    getActiveSubscriptions: async () => { if (opts.subsThrow) throw new Error("database unreachable"); return opts.subs || []; },
    supabase: { from: () => chain() },
    stripe: { checkout: { sessions: { create: async (p) => { stripeCalls.push(p); return { url: "https://checkout.stripe.test/s1" }; } } } },
    FRONTEND_URL: "https://bizforce.test",
    requireAuth: function requireAuth() {},
    app: { post(p, mw, h) { if (p === "/api/stripe/checkout") handler = h; } }
  };
  vm.createContext(ctx);
  const code = ENTITLEMENT_NAMES.map(lift).join("\n\n") + "\n\n" + checkoutRoute() + "\n\n" +
    "this.api = { getUserPlan: getUserPlan, subscriptionEntitlement: subscriptionEntitlement, subscriptionRequiredBody: subscriptionRequiredBody," +
    " pastDueDays: SUBSCRIPTION_PAST_DUE_GRACE_DAYS, BILLING_URL: BILLING_URL, pastDueGraceState: pastDueGraceState };";
  vm.runInContext(code, ctx);
  ctx.api.checkout = async function (body) {
    const res = { code: 200, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    await handler({ user: { id: "u1", email: "u1@example.test" }, body: body || {} }, res);
    return { status: res.code, body: res.body };
  };
  return { api: ctx.api, logs, stripeCalls, dbWrites };
}

const NOW = Date.now();
const sub = (status, extra) => Object.assign({ user_id: "u1", plan: "all_access", status: status,
  stripe_subscription_id: "sub_check", current_period_start: null, current_period_end: null }, extra || {});
const pastDue = (endAgoDays, startAgoDays) => sub("past_due", {
  current_period_end: endAgoDays == null ? null : iso(NOW - endAgoDays * DAY),
  current_period_start: startAgoDays == null ? null : iso(NOW - startAgoDays * DAY) });

/* ── the frontend fakes ─────────────────────────────────────────────────── */
function fakeEl(id) {
  const el = { id: id, tagName: "", className: "", value: "", disabled: false, style: {}, children: [], attrs: {}, _text: "", innerHTMLSet: null,
    classSet: new Set(),
    appendChild(c) { this.children.push(c); c.parentNode = this; return c; },
    removeChild(c) { this.children = this.children.filter(x => x !== c); return c; },
    insertBefore(c) { this.children.push(c); c.parentNode = this; return c; },
    setAttribute(k, v) { this.attrs[k] = String(v); }, getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; },
    addEventListener() {}, querySelector() { return null; }, querySelectorAll() { return []; }
  };
  Object.defineProperty(el, "firstChild", { get() { return this.children[0] || null; } });
  Object.defineProperty(el, "nextSibling", { get() { return null; } });
  // As in a DOM: setting textContent leaves one text node as the only child.
  Object.defineProperty(el, "textContent", {
    get() { return this._text + this.children.map(c => c.textContent).join(""); },
    set(v) {
      if (this.isText) { this._text = String(v); return; }
      this._text = ""; this.innerHTMLSet = null;
      this.children = String(v) === "" ? [] : [textNode(String(v))];
    }
  });
  Object.defineProperty(el, "innerHTML", {
    get() { return this.innerHTMLSet == null ? "" : this.innerHTMLSet; },
    set(v) { this.children = []; this._text = ""; this.innerHTMLSet = String(v); }
  });
  el.classList = { add: c => el.classSet.add(c), remove: c => el.classSet.delete(c), contains: c => el.classSet.has(c) };
  return el;
}
function textNode(t) { const n = fakeEl(null); n.isText = true; n._text = String(t); return n; }
function fakeDocument() {
  const els = new Map();
  const document = {
    head: fakeEl("head"), body: fakeEl("body"),
    createElement(tag) { const e = fakeEl(null); e.tagName = String(tag).toUpperCase(); return e; },
    createTextNode(t) { return textNode(t); },
    getElementById(id) { if (!els.has(id)) els.set(id, fakeEl(id)); return els.get(id); },
    querySelector() { return null; }, querySelectorAll() { return []; }, addEventListener() {}
  };
  return { document, els };
}
const linkIn = el => el.children.find(c => c.tagName === "A") || null;
function fetchFrom(handlers, posted) {
  return function (url, init) {
    const p = String(url).replace(/^https?:\/\/[^/]+/, "");
    posted.push({ method: (init && init.method) || "GET", path: p });
    const r = handlers(p) || { status: 404, body: { error: "unplanned " + p } };
    return Promise.resolve({ ok: r.status >= 200 && r.status < 300, status: r.status, json: () => Promise.resolve(JSON.parse(JSON.stringify(r.body))) });
  };
}

function pageConfig(file) {
  const m = SRC[file].match(/<script>\s*(window\.AGENT_PROFILE_CONFIG\s*=[\s\S]*?)<\/script>/);
  const w = {}; vm.runInNewContext(m[1], { window: w });
  return w.AGENT_PROFILE_CONFIG;
}
function loadAgentPage(file, handlers) {
  const { document, els } = fakeDocument();
  const posted = [];
  const window = { AGENT_PROFILE_CONFIG: pageConfig(file) };
  const ctx = { window, document, console: { log() {}, warn() {}, error() {} }, localStorage: { getItem() { return "check-token"; }, setItem() {} },
    fetch: fetchFrom(handlers, posted), setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {} };
  vm.createContext(ctx);
  // bf-paywall.js only when this page loads it, as the browser would.
  if (SRC[file].indexOf('<script src="/scripts/bf-paywall.js"></script>') !== -1) vm.runInContext(SRC[PAYWALL], ctx);
  const tail = '  document.addEventListener("DOMContentLoaded", inject);\n})();';
  const src = SRC[AP];
  if (src.indexOf(tail) < 0) throw new Error("agent-profile.js does not end where expected");
  vm.runInContext(src.slice(0, src.lastIndexOf(tail)) +
    "  window.__ap = { runTool: runTool, TOOLS: TOOLS, toolDomId: toolDomId, dispatchPlanAssignment: dispatchPlanAssignment };\n" + tail, ctx);
  return { ap: window.__ap, els, document, posted };
}

(async function main() {
  console.log("checkLaunchAccessFixes — server.js and the frontend at " + FRONTEND + "; no network, no database");

  /* ── A. #4 past_due grace ─────────────────────────────────────────────── */
  console.log("\n══ A. #4 a past_due subscription keeps access through its grace ══");
  const plan = async (subscription, env) => {
    const b = buildServer({ subs: subscription ? [subscription] : [], env: env });
    return { p: await b.api.getUserPlan("u1", { id: "u1", role: "user" }), logs: b.logs, days: b.api.pastDueDays };
  };
  let r = await plan(pastDue(3, 33));
  check("A1. default grace is 14 days", r.days === 14, r.days);
  check("A2. past_due, payment fell due 3 days ago: ENTITLED", r.p.active === true && r.p.inactive_reason === null && r.p.access_reason === "subscription",
    JSON.stringify([r.p.active, r.p.inactive_reason, r.p.access_reason]));
  check("A3. ...and nothing is logged as a refusal", !r.logs.some(l => /PAST_DUE REFUSED/.test(l)));
  r = await plan(pastDue(15, 45));
  check("A4. past_due, payment fell due 15 days ago: REFUSED, reason past_due", r.p.active === false && r.p.inactive_reason === "past_due",
    JSON.stringify([r.p.active, r.p.inactive_reason]));
  check("A5. ...and the refusal log names the start, its source and when the grace ended",
    r.logs.some(l => /PAST_DUE REFUSED/.test(l) && /counted from .* \(current_period_end\), ended /.test(l)), r.logs.join(" | "));
  r = await plan(pastDue(0.0007, 30), { SUBSCRIPTION_PAST_DUE_GRACE_DAYS: "0" });
  check("A6. grace 0: refused at once (payment fell due a minute ago)", r.days === 0 && r.p.active === false && r.p.inactive_reason === "past_due",
    JSON.stringify([r.days, r.p.active, r.p.inactive_reason]));
  r = await plan(pastDue(-25, 5));
  check("A7. the period already moved on (ends in 25 days): counted from its START, 5 days ago — ENTITLED", r.p.active === true, JSON.stringify(r.p.inactive_reason));
  r = await plan(pastDue(-5, 25));
  check("A8. the period moved on 25 days ago: REFUSED, although its end is still 5 days away", r.p.active === false && r.p.inactive_reason === "past_due",
    JSON.stringify([r.p.active, r.p.inactive_reason]));
  r = await plan(pastDue(null, null));
  check("A9. no usable period at all: REFUSED, as every past_due row was before", r.p.active === false && r.p.inactive_reason === "past_due");
  check("A10. ...and the log says no grace could be counted", r.logs.some(l => /PAST_DUE REFUSED/.test(l) && /no usable current_period_end or current_period_start/.test(l)));
  r = await plan(pastDue(10, 40), { SUBSCRIPTION_PAST_DUE_GRACE_DAYS: "7" });
  check("A11. grace 7, payment fell due 10 days ago: refused", r.days === 7 && r.p.active === false);
  r = await plan(pastDue(25, 55), { SUBSCRIPTION_PAST_DUE_GRACE_DAYS: "45" });
  check("A12. grace 45 is clamped to 30: 25 days in, still entitled", r.days === 30 && r.p.active === true, r.days);
  const parsed = ["", "   ", "abc", "-3", "7", "2.5", "31", "30"].map(v => { const b = buildServer({ env: { SUBSCRIPTION_PAST_DUE_GRACE_DAYS: v } }); return b.api.pastDueDays; });
  check("A13. parsing like SUBSCRIPTION_GRACE_DAYS: blank 14, spaces 14, junk 14, -3 to 0, 7, 2.5, 31 to 30, 30",
    JSON.stringify(parsed) === JSON.stringify([14, 14, 14, 0, 7, 2.5, 30, 30]), JSON.stringify(parsed));
  const libState = buildServer({}).api.pastDueGraceState(pastDue(3, 33), 14, NOW);
  check("A14. the grace ends exactly 14 days after the payment fell due",
    libState.since_source === "current_period_end" && Date.parse(libState.grace_ends_at) - Date.parse(libState.since) === 14 * DAY, JSON.stringify(libState));
  /* The boundaries, to the millisecond: grace 0 refuses even at the very
     moment the payment fell due, and a grace ends AT its last instant. */
  const atDue = sub("past_due", { current_period_end: iso(NOW), current_period_start: iso(NOW - 30 * DAY) });
  const gs = (row, days, at) => buildServer({}).api.pastDueGraceState(row, days, at).within;
  check("A14b. grace 0, at the very moment the payment fell due: not within", gs(atDue, 0, NOW) === false);
  check("A14c. grace 14: within 1 ms before its end, not within at its end",
    gs(atDue, 14, NOW + 14 * DAY - 1) === true && gs(atDue, 14, NOW + 14 * DAY) === false,
    JSON.stringify([gs(atDue, 14, NOW + 14 * DAY - 1), gs(atDue, 14, NOW + 14 * DAY)]));
  r = await plan(sub("active", { current_period_end: iso(NOW + 10 * DAY) }));
  check("A15. active is entitled, as before", r.p.active === true && r.p.inactive_reason === null);
  r = await plan(sub("active", { current_period_end: iso(NOW - 10 * DAY) }));
  check("A16. active with a period 10 days gone is still refused as expired, as before", r.p.active === false && r.p.inactive_reason === "expired", r.p.inactive_reason);
  r = await plan(sub("trialing"));
  check("A17. trialing is entitled, as before", r.p.active === true);
  r = await plan(sub("canceled", { current_period_end: iso(NOW - 1 * DAY) }));
  check("A18. canceled is refused with reason status, and gets no grace", r.p.active === false && r.p.inactive_reason === "status", r.p.inactive_reason);
  r = await plan(null);
  check("A19. no subscription: refused, no_subscription", r.p.active === false && r.p.inactive_reason === "no_subscription");

  /* ── B. #4 the 402 for a lapsed past_due ─────────────────────────────── */
  console.log("\n══ B. #4 the refusal says the payment failed and how to update the card ══");
  const srv = buildServer({});
  const pd = srv.api.subscriptionRequiredBody({ inactive_reason: "past_due" }, "post /api/agents/ads/copy");
  check("B1. 402 body: upgrade_required, reason past_due, billing_url /billing.html",
    pd.upgrade_required === true && pd.reason === "past_due" && pd.billing_url === "/billing.html", JSON.stringify(pd));
  check("B2. the message says the card payment failed", /payment failed/i.test(pd.message), pd.message);
  check("B3. ...and how to update the card: Billing, Manage / Cancel Subscription", /update your card/i.test(pd.message) && /Billing/.test(pd.message) && /Manage \/ Cancel Subscription/.test(pd.message), pd.message);
  check("B4. ...and does not tell them to subscribe again", !/\bSubscribe on Billing\b/.test(pd.message), pd.message);
  const ns = srv.api.subscriptionRequiredBody({ inactive_reason: "no_subscription" }, "post /api/agents/ads/copy");
  check("B5. an account that never subscribed keeps the old message", /needs an active subscription/.test(ns.message) && !/payment failed/.test(ns.message), ns.message);

  /* ── C. #11 no second checkout ───────────────────────────────────────── */
  console.log("\n══ C. #11 checkout refuses an account that already has an entitling subscription ══");
  async function checkout(opts) { const b = buildServer(opts); const out = await b.api.checkout({}); return Object.assign(out, { stripe: b.stripeCalls.length, writes: b.dbWrites.length }); }
  let c = await checkout({ subs: [sub("active", { current_period_end: iso(NOW + 20 * DAY) })] });
  check("C1. active subscription: 409 already_subscribed", c.status === 409 && c.body.error === "already_subscribed", JSON.stringify([c.status, c.body]));
  check("C2. ...with a message and billing_url", /already has an active subscription/.test(c.body.message) && c.body.billing_url === "/billing.html", JSON.stringify(c.body));
  check("C3. ...and NOTHING was created: no Stripe session, no database write", c.stripe === 0 && c.writes === 0, c.stripe + " stripe, " + c.writes + " writes");
  c = await checkout({ subs: [sub("trialing")] });
  check("C4. trialing: refused, nothing created", c.status === 409 && c.stripe === 0, JSON.stringify([c.status, c.stripe]));
  c = await checkout({ subs: [pastDue(3, 33)] });
  check("C5. past_due inside its grace: refused, the message says the payment failed and to update the card",
    c.status === 409 && c.body.status === "past_due" && /last payment failed/.test(c.body.message) && /Update your card/.test(c.body.message) && c.stripe === 0, JSON.stringify(c.body));
  c = await checkout({ subs: [pastDue(20, 50)] });
  check("C6. past_due past its grace: NOT blocked — one Stripe session, as before", c.status === 200 && c.stripe === 1 && /checkout\.stripe\.test/.test(c.body.url), JSON.stringify([c.status, c.stripe]));
  c = await checkout({ subs: [sub("active", { current_period_end: iso(NOW - 30 * DAY) })] });
  check("C7. an active row proven expired does not entitle, so it does not block", c.status === 200 && c.stripe === 1, JSON.stringify([c.status, c.stripe]));
  c = await checkout({ subs: [] });
  check("C8. no subscription: one Stripe session", c.status === 200 && c.stripe === 1);
  c = await checkout({ subsThrow: true });
  check("C9. the subscription lookup fails: 503, refused, nothing created", c.status === 503 && c.body.error === "subscription_check_failed" && c.stripe === 0 && c.body.billing_url === "/billing.html", JSON.stringify([c.status, c.body, c.stripe]));
  const bill = lf(fs.readFileSync(path.join(FRONTEND, "billing.html"), "utf8"));
  check("C10. billing.html shows the refusal's own message", bill.indexOf('throw new Error(d.message || d.error || "Checkout failed.");') !== -1);

  /* ── D. #7 agent pages render the 402 ────────────────────────────────── */
  console.log("\n══ D. #7 an agent page shows the 402's message and the Billing link ══");
  const body402 = srv.api.subscriptionRequiredBody({ inactive_reason: "no_subscription" }, "post /api/agents/ads/copy");
  const pg = loadAgentPage("ads-agent.html", p => (p === "/api/agents/ads/copy" ? { status: 402, body: body402 } : null));
  const tool = pg.ap.TOOLS.find(t => t.id === "copy");
  (tool.fields || []).forEach(f => { pg.document.getElementById(pg.ap.toolDomId(tool.id, "f_" + f.name)).value = f.options ? f.options[0].value : "Hand-poured candles"; });
  pg.ap.runTool(tool);
  await flush();
  const msgEl = pg.els.get(pg.ap.toolDomId(tool.id, "msg"));
  check("D1. the tool run reached the gated route", pg.posted.some(x => x.method === "POST" && x.path === "/api/agents/ads/copy"), JSON.stringify(pg.posted));
  check("D2. the message line shows the server's message", msgEl && msgEl.textContent.indexOf(body402.message) === 0, msgEl && msgEl.textContent);
  const a = msgEl && linkIn(msgEl);
  check("D3. ...and a link to Billing at billing_url", !!a && a.attrs.href === "/billing.html" && a.textContent === "Open Billing", a && JSON.stringify(a.attrs));
  check("D4. ...never 'HTTP 402' or the bare error", msgEl && msgEl.textContent.indexOf("HTTP 402") === -1 && msgEl.textContent.indexOf("Active subscription required") === -1, msgEl && msgEl.textContent);
  const dp = loadAgentPage("ads-agent.html", p => (p === "/api/assignments/dispatch" ? { status: 402, body: body402 } : null));
  const dMsg = fakeEl("dmsg"), dRes = fakeEl("dres");
  const wrap = fakeEl("wrap"); wrap.querySelector = sel => (sel === "[data-plan-dispatch-msg]" ? dMsg : sel === "[data-plan-dispatch-result]" ? dRes : null);
  const btn = fakeEl("btn"); btn.parentNode = wrap; btn.attrs = { "data-plan-task": "t1", "data-assignment-id": "4", "data-plan-tool": "copy", "data-plan-inputs": "[]" };
  dp.ap.dispatchPlanAssignment(btn);
  await flush();
  check("D5. a plan dispatch answered 402 shows the message and the Billing link, and re-enables its button",
    dMsg.textContent.indexOf(body402.message) === 0 && !!linkIn(dMsg) && linkIn(dMsg).attrs.href === "/billing.html" && btn.disabled === false, dMsg.textContent);
  const missing = AGENT_PAGES.filter(f => {
    const t = SRC[f]; const pi = t.indexOf('<script src="/scripts/bf-paywall.js"></script>'), ai = t.indexOf('<script src="/scripts/agent-profile.js"></script>');
    return pi === -1 || ai === -1 || pi > ai;
  });
  check("D6. all " + AGENT_PAGES.length + " pages that load agent-profile.js load bf-paywall.js before it", missing.length === 0, missing.join(", "));
  const ownCalls = [["agents/seo.html", 2], ["agents/sales.html", 2], ["agents/content.html", 2]].filter(([f, n]) =>
    (SRC[f].match(/var paywall = window\.bfPaywall \? window\.bfPaywall\.from\(res\.status, res\.data\) : null;/g) || []).length !== n);
  check("D7. the pages' own gated calls take the 402 branch (seo optimize and generate-post, sales convert x2, content launch x2)", ownCalls.length === 0, JSON.stringify(ownCalls));

  /* ── E. #7 the dashboard ─────────────────────────────────────────────── */
  console.log("\n══ E. #7 the dashboard: subscribe to start, and the welcome line ══");
  const dashSrc = SRC[DASH];
  const dStart = dashSrc.indexOf("function planStatusText(");
  const DASH_CODE = dashSrc.slice(dStart, dashSrc.indexOf("</script>", dStart));
  async function dashboard(me, opts) {
    opts = opts || {};
    const { document, els } = fakeDocument();
    if (opts.paid) document.getElementById("paidBanner").classList.add("show");
    document.getElementById("welcomeMsg").textContent = opts.welcome || "Welcome, Acme";
    document.getElementById("subscribeStartPanel").style.display = "none";
    const ctx = { document, API_URL: "https://api.test", dashboardToken: "check-token", planStatus: document.getElementById("planStatus"),
      fetch: fetchFrom(p => (p === "/api/auth/me" ? { status: 200, body: me } : null), []), Date, console };
    vm.createContext(ctx);
    vm.runInContext(DASH_CODE, ctx);
    await flush();
    const shown = id => document.getElementById(id).style.display;
    return { panel: shown("subscribeStartPanel"), sections: ["aiTaskSection", "commandCenterSection", "agentAssignmentsSection"].map(shown),
      profile: shown("businessProfileSection"), title: els.get("subscribeStartTitle") ? els.get("subscribeStartTitle").textContent : "",
      welcome: document.getElementById("welcomeMsg").textContent };
  }
  const old = iso(NOW - 40 * DAY), fresh = iso(NOW - 2 * 3600000);
  let d = await dashboard({ user: { created_at: fresh }, subscription: null, access: { active: false, exempt: false, access_reason: null, inactive_reason: "no_subscription" } });
  check("E1. unentitled: the subscribe panel is shown", d.panel === "block", d.panel);
  check("E2. ...and the three gated sections are hidden in its place", d.sections.every(x => x === "none"), JSON.stringify(d.sections));
  check("E3. ...and the business profile, which works without a subscription, is not", d.profile !== "none");
  const markup = dashSrc.slice(dashSrc.indexOf('<div class="bf-start-panel" id="subscribeStartPanel"'), dashSrc.indexOf("</div>", dashSrc.indexOf('id="subscribeStartLink"')));
  check("E4. the panel reads 'Subscribe to start' and links to /billing.html, hidden until shown",
    /<h2 id="subscribeStartTitle">Subscribe to start<\/h2>/.test(markup) && /href="\/billing\.html"/.test(markup) && /style="display:none"/.test(markup), markup.slice(0, 200));
  d = await dashboard({ user: { created_at: old }, subscription: { status: "active" }, access: { active: true, exempt: false, access_reason: "subscription", inactive_reason: null } });
  check("E5. entitled: no panel, every section stays", d.panel === "none" && d.sections.every(x => x !== "none"), JSON.stringify([d.panel, d.sections]));
  d = await dashboard({ user: { created_at: old }, subscription: null, access: null });
  check("E6. access unknown (null): no panel, nothing hidden", d.panel === "none" && d.sections.every(x => x !== "none"), JSON.stringify([d.panel, d.sections]));
  d = await dashboard({ user: { created_at: old }, subscription: null, access: { active: null, exempt: false, access_reason: null, inactive_reason: null } });
  check("E6b. access present but active not a definite false: no panel, nothing hidden", d.panel === "none" && d.sections.every(x => x !== "none"), JSON.stringify([d.panel, d.sections]));
  d = await dashboard({ user: { created_at: fresh }, subscription: null, access: { active: false, inactive_reason: "no_subscription" } }, { paid: true });
  check("E7. just paid (the Payment received banner is up): no panel", d.panel === "none", d.panel);
  d = await dashboard({ user: { created_at: old }, subscription: { status: "past_due" }, access: { active: false, inactive_reason: "past_due" } });
  check("E8. past_due past its grace: the panel says 'Update your card'", d.panel === "block" && d.title === "Update your card", d.title);
  d = await dashboard({ user: { created_at: fresh }, subscription: null, access: { active: false, inactive_reason: "no_subscription" } });
  check("E9. first visit (account 2 hours old): 'Welcome, Acme'", d.welcome === "Welcome, Acme", d.welcome);
  d = await dashboard({ user: { created_at: old }, subscription: null, access: { active: true, inactive_reason: null } });
  check("E10. an account 40 days old: 'Welcome back, Acme'", d.welcome === "Welcome back, Acme", d.welcome);
  d = await dashboard({ user: {}, subscription: null, access: null });
  check("E11. no created_at: stays 'Welcome, Acme' (never a wrong 'back')", d.welcome === "Welcome, Acme", d.welcome);
  d = await dashboard({ user: { created_at: old }, subscription: null, access: null }, { welcome: "Welcome" });
  check("E12. no name: 'Welcome' becomes 'Welcome back'", d.welcome === "Welcome back", d.welcome);
  check("E13. the static greeting is 'Welcome', and the named one is set as 'Welcome, ' + name",
    dashSrc.indexOf('<p class="hq-hero-welcome" id="welcomeMsg">Welcome</p>') !== -1 && dashSrc.indexOf("textContent = 'Welcome, ' + name;") !== -1 &&
    dashSrc.indexOf("'Welcome back, ' + name") === -1);

  /* ── F. #8 bf-session.js on the five pages ───────────────────────────── */
  console.log("\n══ F. #8 bf-session.js on ai-agents, index, my-purchases, profile and seller ══");
  const TAG = '<script src="/scripts/bf-session.js"></script>';
  const headOf = t => t.slice(t.indexOf("<head>"), t.indexOf("</head>"));
  SESSION_PAGES.forEach(f => {
    const h = headOf(SRC[f]);
    const firstScript = h.indexOf("<script");
    check("F. " + f + ": bf-session.js in the head, its first script", h.indexOf(TAG) !== -1 && h.indexOf(TAG) === firstScript, firstScript + " vs " + h.indexOf(TAG));
  });
  SESSION_IF_SIGNED_IN_PAGES.forEach(f => {
    const h = headOf(SRC[f]);
    const m = h.match(/<script>([\s\S]*?bf-session\.js[\s\S]*?)<\/script>/);
    check("F. " + f + ": a bf-session.js loader in the head, its first script", !!m && h.indexOf(m[0]) === h.indexOf("<script"));
    if (!m) return;
    const run = token => { const written = []; vm.runInNewContext(m[1], { localStorage: { getItem: k => (k === "bf_token" ? token : null) }, document: { write: x => written.push(x) } }); return written; };
    const signedIn = run("a-token"), signedOut = run(null);
    check("F. " + f + ": signed in, it writes exactly " + TAG, signedIn.length === 1 && signedIn[0] === TAG, JSON.stringify(signedIn));
    check("F. " + f + ": signed out, it loads nothing, so the page stays readable", signedOut.length === 0, JSON.stringify(signedOut));
  });

  /* ── G. #10 the stale backups ────────────────────────────────────────── */
  console.log("\n══ G. #10 oracle.backup.html and oracle.backup2.html are gone ══");
  const BACKUPS = ["oracle.backup.html", "oracle.backup2.html"];
  check("G1. neither file is in the frontend tree", BACKUPS.every(f => !fs.existsSync(path.join(FRONTEND, f))), BACKUPS.filter(f => fs.existsSync(path.join(FRONTEND, f))).join(", "));
  const tracked = execFileSync("git", ["ls-files"], { cwd: FRONTEND, maxBuffer: 64 << 20 }).toString().split(/\r?\n/);
  check("G2. neither is tracked by git", BACKUPS.every(f => tracked.indexOf(f) === -1));
  let refs = "";
  try { refs = execFileSync("git", ["grep", "-n", "oracle\\.backup", "--", "."], { cwd: FRONTEND, maxBuffer: 64 << 20 }).toString(); } catch (e) { refs = e.status === 1 ? "" : "git grep failed: " + e.message; }
  check("G3. no tracked frontend file names either of them", refs.trim() === "", refs.slice(0, 200));

  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("HARNESS ERROR: " + ((e && e.stack) || e)); process.exit(3); });
