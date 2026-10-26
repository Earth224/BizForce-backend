"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkAutoRenewConsent — express, affirmative consent to automatic renewal
   before any subscription checkout (California's Automatic Renewal Law).

   Before POST /api/stripe/checkout creates a Stripe session, the member ticks
   a box, unchecked by default and placed directly beside the price:
     "I agree that All Access renews automatically every month at $199 until
      I cancel, and that I can cancel online at any time in Billing."
   The name, price and interval come from server.js PLAN_CONFIG (through
   autoRenewConsent), never from a typed figure. This reads the frontend
   checkout beside this repo.

   WHAT THIS PROVES
     A. The words: exactly the sentence above for today's PLAN_CONFIG, and,
        with another name, price or interval in PLAN_CONFIG, that one's
        figures (a typed price fails). PLAN_CONFIG's interval is the one the
        Terms state. GET /api/billing/consent gives them, signed in or not.
     B. The real checkout route, lifted: without the box ticked on today's
        words and version (missing, false, the string "true", an older price's
        words, another version) it answers 400 with a message, before anything
        is read, written or sent to Stripe. Ticked, it records
        users.auto_renew_consent_at and auto_renew_consent_version first, then
        creates the session with both in its metadata and the subscription's.
        A record that cannot be written stops the checkout (503), naming
        migration 147 when the columns are missing.
     C. Migration 147 adds the two columns, with no default and no backfill.
     D. Every frontend file that starts a checkout (a "/api/stripe/checkout"
        string: billing.html and app.html today) carries the box directly
        beside the price, ahead of its Subscribe button, unchecked, with no
        words typed in, and loads scripts/bf-renew-consent.js; that script
        types no price.
     E. Each page's own code, run in jsdom with the real bf-renew-consent.js:
        the box shows the server's words, unticked; Subscribe without the tick
        sends nothing and says why; ticked, the checkout request carries the
        consent; if the words cannot be loaded, the box stays hidden and no
        checkout is sent.

   NO NETWORK. NO DATABASE. Supabase, Stripe and fetch are in-memory stubs.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process (scripts/_shared.js) and passes only if every one fails at least
   one check; a search text that does not match exactly once is an ERROR.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns");
const cp = require("child_process");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkAutoRenewConsent: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkAutoRenewConsent: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const lf = t => t.replace(/\r\n/g, "\n");

const EXPECTED_TEXT = "I agree that All Access renews automatically every month at $199 until I cancel, and that I can cancel online at any time in Billing.";
const BOX = "<label class=\"renew-consent\" data-bf-renew-consent hidden><input type=\"checkbox\" data-bf-renew-consent-box> <span data-bf-renew-consent-text></span></label>";
const SCRIPT_TAG = "<script src=\"/scripts/bf-renew-consent.js\"></script>";
const MIGRATION = "supabase/migrations/147_users_auto_renew_consent.sql";

const MUTATIONS = {
  // the route starts a checkout without the box
  "consent-bypassed": [["server.js", "    if (!consentGiven) {\n", "    if (false) {\n"]],
  // the box comes pre-ticked on Billing
  "box-prechecked": [["billing.html", "<input type=\"checkbox\" data-bf-renew-consent-box>", "<input type=\"checkbox\" data-bf-renew-consent-box checked>"]],
  // the box comes pre-ticked on the sign-in page
  "app-box-prechecked": [["app.html", "<input type=\"checkbox\" data-bf-renew-consent-box>", "<input type=\"checkbox\" data-bf-renew-consent-box checked>"]],
  // the words state a typed price instead of PLAN_CONFIG's
  "price-hard-coded": [["server.js", "\" renews automatically every \" + plan.interval + \" at \" + price +", "\" renews automatically every \" + plan.interval + \" at $199\" +"]],
  // the words typed into the page beside the box
  "price-typed-on-page": [["billing.html", "<span data-bf-renew-consent-text></span>", "<span data-bf-renew-consent-text>" + EXPECTED_TEXT + "</span>"]],
  // words from an older page (an older price) accepted as consent
  "stale-text-accepted": [["server.js", "req.body.auto_renew_consent_text === consent.text && ", ""]],
  // the consent is not recorded
  "consent-not-recorded": [["server.js", ".update({ auto_renew_consent_at: consentAt, auto_renew_consent_version: consent.version })", ".update({})"]],
  // a failed record is ignored and checkout goes ahead
  "record-failure-ignored": [["server.js", "    if (consentError) {\n", "    if (false) {\n"]],
  // the subscription's metadata loses the consent
  "metadata-missing": [["server.js", "          plan: entry.plan,\n          auto_renew_consent_at: consentAt,\n          auto_renew_consent_version: consent.version\n", "          plan: entry.plan\n"]],
  // the script treats an unticked box as consent
  "script-skips-box": [["scripts/bf-renew-consent.js", "if (!box || box.checked !== true) {", "if (!box) {"]],
  // Billing's Subscribe ignores the script's answer
  "billing-ignores-consent": [["billing.html", "      if (consent.error) {\n        setMsg(\"checkoutMsg\", consent.error, \"err\");", "      if (false) {\n        setMsg(\"checkoutMsg\", consent.error, \"err\");"]],
  // the sign-in page's Subscribe ignores the script's answer
  "app-ignores-consent": [["app.html", "      if (consent.error) {\n        setError(consent.error);", "      if (false) {\n        setError(consent.error);"]],
  // the box moved away from the price, below the Subscribe button
  "box-away-from-price": [["billing.html", "        " + BOX + "\n        <button class=\"btn\" id=\"checkoutBtn\" type=\"button\">Subscribe — $199/month</button>\n",
    "        <button class=\"btn\" id=\"checkoutBtn\" type=\"button\">Subscribe — $199/month</button>\n        " + BOX + "\n"]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the files, read once (and mutated in memory) ───────────────────────── */
const SRC = { "server.js": lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8")) };
const FE_FILES = cp.execFileSync("git", ["ls-files", "*.html", "*.js"], { cwd: FRONTEND }).toString().trim().split(/\r?\n/);
["scripts/bf-renew-consent.js"].forEach(f => { if (FE_FILES.indexOf(f) === -1) FE_FILES.push(f); });
const FE = {};
FE_FILES.forEach(f => { const p = path.join(FRONTEND, f); FE[f] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null; });
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  if (!m) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  m.forEach(([file, from, to]) => {
    const store = Object.prototype.hasOwnProperty.call(SRC, file) ? SRC : FE;
    store[file] = s.replaceOnce(store[file], from, to, MUTATE + " in " + file);
  });
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
function section(t) { console.log("\n══ " + t + " ══"); }
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const settle = () => new Promise(r => setTimeout(r, 20));

/* ── server.js, lifted ──────────────────────────────────────────────────── */
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
function routeSrc(sig) {
  const src = SRC["server.js"];
  const a = src.indexOf(sig);
  if (a === -1) throw new Error("route not found: " + sig);
  const e = s.braceMatch(src, src.indexOf("{", src.indexOf("function", a)));
  return src.slice(a, e + 2);
}
const CHECKOUT_SIG = "app.post(\"/api/stripe/checkout\", requireAuth, async function (req, res) {";
const CONSENT_SIG = "app.get(\"/api/billing/consent\"";

function buildServer(opts) {
  opts = opts || {};
  const events = [], stripeCalls = [], writes = [];
  let reads = 0;
  const routes = {}, middleware = {};
  const chain = table => {
    const q = { _op: "select" };
    ["select", "eq", "not", "order", "limit", "in", "is"].forEach(k => { q[k] = () => q; });
    q.update = p => { q._op = "update"; writes.push({ table, payload: p }); events.push("write " + table); return q; };
    ["insert", "upsert", "delete"].forEach(k => { q[k] = p => { writes.push({ table, op: k, payload: p }); events.push(k + " " + table); return q; }; });
    q.maybeSingle = async () => { reads++; events.push("read " + table); return { data: { stripe_customer_id: "cus_check" }, error: null }; };
    q.then = (res, rej) => Promise.resolve(q._op === "update" && opts.updateError ? { data: null, error: opts.updateError } : { data: null, error: null }).then(res, rej);
    return q;
  };
  const ctx = {
    process: { env: { STRIPE_STARTER_PRICE_ID: "price_check" } },
    console: { log() {}, warn() {}, error() {} },
    Date, Math, Number, String, Object, Array, JSON, Promise,
    AGENT_SYSTEM_PROMPTS: { seo: "" },
    nowIso: () => new Date().toISOString(),
    getActiveSubscriptions: async () => { reads++; events.push("read subscriptions"); return opts.subs || []; },
    subscriptionEntitlement: held => ({ active: held.status === "active" }),
    supabase: { from: t => chain(t) },
    stripe: { checkout: { sessions: { create: async p => { stripeCalls.push(p); events.push("stripe"); return { url: "https://checkout.stripe.test/s1" }; } } } },
    FRONTEND_URL: "https://bizforce.test",
    requireAuth: function requireAuth() {},
    app: {
      get(p) { routes["get " + p] = arguments[arguments.length - 1]; middleware["get " + p] = [].slice.call(arguments, 1, -1); },
      post(p) { routes["post " + p] = arguments[arguments.length - 1]; middleware["post " + p] = [].slice.call(arguments, 1, -1); }
    }
  };
  vm.createContext(ctx);
  vm.runInContext(["BILLING_URL", "PLAN_CONFIG", "CHECKOUT_PRODUCTS", "AUTO_RENEW_CONSENT_VERSION", "autoRenewConsent"].map(lift).join("\n\n") + "\n\n" +
    routeSrc(CONSENT_SIG) + "\n\n" + routeSrc(CHECKOUT_SIG) + "\n\n" +
    "this.api = { PLAN_CONFIG: PLAN_CONFIG, autoRenewConsent: autoRenewConsent, VERSION: AUTO_RENEW_CONSENT_VERSION };", ctx);
  async function run(key, req) {
    const res = { code: 200, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    await routes[key](Object.assign({ user: { id: "u1", email: "u1@example.test" }, body: {}, query: {} }, req), res);
    return { status: res.code, body: res.body };
  }
  return { api: ctx.api, run, events, stripeCalls, writes, middleware, reads: () => reads };
}

(async function main() {
  /* ── A ─────────────────────────────────────────────────────────────────── */
  section("A. the words, from PLAN_CONFIG");
  const srv = buildServer();
  const today = srv.api.autoRenewConsent("all_access");
  const plan = srv.api.PLAN_CONFIG.all_access;
  check("A1. today the box says exactly: \"" + EXPECTED_TEXT + "\"", today && today.text === EXPECTED_TEXT, today && today.text);
  check("A2. its name, price and interval are PLAN_CONFIG.all_access's (" + plan.name + ", $" + plan.price + ", " + plan.interval + ")",
    today && today.plan_name === plan.name && today.price === plan.price && today.interval === plan.interval && typeof today.version === "string" && /^\d{4}-\d{2}-\d{2}$/.test(today.version),
    JSON.stringify(today));
  {
    const b = buildServer();
    Object.assign(b.api.PLAN_CONFIG.all_access, { name: "Elite", price: 249, interval: "year" });
    const other = b.api.autoRenewConsent("all_access");
    Object.assign(b.api.PLAN_CONFIG.all_access, { price: 19.5 });
    const cents = b.api.autoRenewConsent("all_access");
    check("A3. with another plan in PLAN_CONFIG, the words state that plan's figures and none of today's (nothing is typed in)",
      other.text === "I agree that Elite renews automatically every year at $249 until I cancel, and that I can cancel online at any time in Billing." &&
      cents.text.indexOf(" at $19.50 until I cancel") !== -1 && other.text.indexOf("$199") === -1, other.text + " / " + cents.text);
  }
  const facts = require("../lib/legalPages").codeFacts({ server: SRC["server.js"] });
  check("A4. PLAN_CONFIG's interval and price are the ones the Terms state (" + facts.interval + ", $" + facts.price + ")",
    plan.interval === facts.interval && plan.price === facts.price, plan.interval + " / " + facts.interval);
  {
    const g = await srv.run("get /api/billing/consent", { user: undefined });
    const u = await srv.run("get /api/billing/consent", { query: { product: "nope" } });
    check("A5. GET /api/billing/consent gives the words and version to anyone (no sign-in), and refuses an unknown product",
      g.status === 200 && same(g.body, today) && srv.middleware["get /api/billing/consent"].length === 0 && u.status === 400, JSON.stringify([g.status, srv.middleware["get /api/billing/consent"].length, u.status]));
  }

  /* ── B ─────────────────────────────────────────────────────────────────── */
  section("B. the checkout route refuses without it, and records it");
  const OK = { product: "all_access", auto_renew_consent: true, auto_renew_consent_text: today.text, auto_renew_consent_version: today.version };
  const older = buildServer();
  Object.assign(older.api.PLAN_CONFIG.all_access, { price: 149 });
  const STALE = older.api.autoRenewConsent("all_access").text;
  const REFUSE = [
    ["no body at all", undefined],
    ["no consent field", { product: "all_access" }],
    ["auto_renew_consent false", Object.assign({}, OK, { auto_renew_consent: false })],
    ["auto_renew_consent \"true\" (a string)", Object.assign({}, OK, { auto_renew_consent: "true" })],
    ["ticked on an older price's words", Object.assign({}, OK, { auto_renew_consent_text: STALE })],
    ["ticked without the words", Object.assign({}, OK, { auto_renew_consent_text: undefined })],
    ["another version", Object.assign({}, OK, { auto_renew_consent_version: "2020-01-01" })]
  ];
  for (const [label, body] of REFUSE) {
    const b = buildServer();
    const out = await b.run("post /api/stripe/checkout", { body });
    check("B1. " + label + ": 400 with a clear message, before anything is read, written or sent to Stripe",
      out.status === 400 && out.body.error === "auto_renew_consent_required" && /Tick the box beside the price/.test(out.body.message) &&
      /No checkout was started and nothing was charged/.test(out.body.message) && out.body.consent_text === today.text &&
      b.events.length === 0 && b.stripeCalls.length === 0, JSON.stringify([out.status, out.body, b.events]));
  }
  {
    const b = buildServer();
    const out = await b.run("post /api/stripe/checkout", { body: Object.assign({}, OK, { product: "nope" }) });
    check("B2. an unknown product is still refused as one", out.status === 400 && out.body.error === "unknown_product" && b.events.length === 0, JSON.stringify(out));
  }
  {
    const b = buildServer();
    const before = Date.now();
    const out = await b.run("post /api/stripe/checkout", { body: OK });
    const rec = (b.writes.find(w => w.table === "users") || {}).payload || {};
    check("B3. ticked: the consent is written to the member's users row (auto_renew_consent_at now, auto_renew_consent_version " + today.version + ")",
      out.status === 200 && same(Object.keys(rec).sort(), ["auto_renew_consent_at", "auto_renew_consent_version"]) && rec.auto_renew_consent_version === today.version &&
      Math.abs(Date.parse(rec.auto_renew_consent_at) - before) < 10000, JSON.stringify([out.status, rec]));
    check("B4. ...before the Stripe session is created, and one session is created",
      b.events.indexOf("write users") !== -1 && b.events.indexOf("write users") < b.events.indexOf("stripe") && b.stripeCalls.length === 1, b.events.join(", "));
    const p = b.stripeCalls[0] || {};
    const m1 = p.metadata || {}, m2 = (p.subscription_data || {}).metadata || {};
    check("B5. the session's metadata and the subscription's carry the same consent time and version",
      m1.auto_renew_consent_at === rec.auto_renew_consent_at && m2.auto_renew_consent_at === rec.auto_renew_consent_at &&
      m1.auto_renew_consent_version === today.version && m2.auto_renew_consent_version === today.version && p.mode === "subscription", JSON.stringify([m1, m2]));
  }
  for (const [label, err, reason, words] of [
    ["the columns are missing (before migration 147)", { code: "PGRST204", message: "Could not find the 'auto_renew_consent_at' column of 'users'" }, "consent_columns_missing", /could not be recorded/],
    ["the write fails", { code: "08006", message: "connection lost" }, "consent_not_recorded", /could not be recorded/]]) {
    const b = buildServer({ updateError: err });
    const out = await b.run("post /api/stripe/checkout", { body: OK });
    check("B6. ticked, but " + label + ": 503 " + reason + ", and no Stripe session", out.status === 503 && out.body.error === reason && words.test(out.body.message) &&
      b.stripeCalls.length === 0, JSON.stringify([out.status, out.body, b.stripeCalls.length]));
  }
  {
    const b = buildServer({ subs: [{ plan: "all_access", status: "active" }] });
    const out = await b.run("post /api/stripe/checkout", { body: OK });
    check("B7. ticked, but already subscribed: still 409, nothing recorded or created", out.status === 409 && b.writes.length === 0 && b.stripeCalls.length === 0, JSON.stringify([out.status, b.writes]));
  }

  /* ── C ─────────────────────────────────────────────────────────────────── */
  section("C. migration 147");
  {
    const p = path.join(REPO, MIGRATION);
    const mig = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : "";
    const stmts = mig.split("\n").filter(l => !/^\s*--/.test(l)).join("\n");
    check("C1. it adds users.auto_renew_consent_at (timestamptz) and auto_renew_consent_version (text), if not there, with no default and no backfill",
      /ALTER TABLE public\.users ADD COLUMN IF NOT EXISTS auto_renew_consent_at timestamptz;/.test(stmts) &&
      /ALTER TABLE public\.users ADD COLUMN IF NOT EXISTS auto_renew_consent_version text;/.test(stmts) && !/\bDEFAULT\b/i.test(stmts) && !/\bUPDATE\b/i.test(stmts));
    const n147 = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^147_/.test(f));
    check("C2. 147 is its own migration number", same(n147, [path.basename(MIGRATION)]), n147.join());
  }

  /* ── D ─────────────────────────────────────────────────────────────────── */
  section("D. every page that starts a checkout carries the box beside the price");
  const callers = FE_FILES.filter(f => FE[f] && /["'`]\/api\/stripe\/checkout["'`]/.test(FE[f])).sort();
  check("D1. the pages that start a checkout are found (" + callers.join(", ") + ")", callers.length >= 2 && callers.indexOf("billing.html") !== -1 && callers.indexOf("app.html") !== -1, callers.join(", "));
  callers.forEach(f => {
    const t = FE[f];
    const boxes = t.split(BOX).length - 1;
    check("D2. " + f + ": the box once, a checkbox, unchecked, with no words typed in, and bf-renew-consent.js loaded after it",
      boxes === 1 && t.indexOf(SCRIPT_TAG) > t.indexOf(BOX) && t.split(SCRIPT_TAG).length === 2, "boxes " + boxes);
    const inputs = (t.match(/<input[^>]*data-bf-renew-consent-box[^>]*>/g) || []);
    check("D3. " + f + ": the box is not pre-ticked", inputs.length === 1 && !/\bchecked\b/.test(inputs[0]), inputs.join(" "));
  });
  {
    const b = FE["billing.html"] || "";
    check("D4. billing.html: directly beside the price, between the renewal note and \"Subscribe — $" + plan.price + "/month\"",
      /<p class="renewal-note" id="checkoutRenewalNote">[^\n]*\$\d+[^\n]*<\/p>\n\s*<label class="renew-consent" data-bf-renew-consent hidden>[^\n]*<\/label>\n\s*<button class="btn" id="checkoutBtn" type="button">Subscribe — \$\d+\/month<\/button>/.test(b));
    const a = FE["app.html"] || "";
    check("D5. app.html: directly beside the price, between the plan's price and Start Subscription",
      /<strong>BizForce AI All Access — \$\d+\/month<\/strong>\n[^\n]*\n\s*<\/div>\n\s*<label class="renew-consent" data-bf-renew-consent hidden>[^\n]*<\/label>\n<button id="subscribeBtn"/.test(a));
    const code = (FE["scripts/bf-renew-consent.js"] || "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
    check("D6. bf-renew-consent.js types no price or interval: the words come from GET /api/billing/consent",
      code.length > 0 && !/\$\s*\d/.test(code) && !/\bmonth\b|\b199\b/.test(code) && /\/api\/billing\/consent/.test(code));
  }

  /* ── E ─────────────────────────────────────────────────────────────────── */
  section("E. each page's own code, in jsdom");
  const { JSDOM, VirtualConsole } = require("jsdom");
  async function runPage(file, opts) {
    const vc = new VirtualConsole();
    const d = new JSDOM(FE[file], { url: "https://bizforceai.net/" + file, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
    const w = d.window, calls = [];
    w.localStorage.setItem("bf_token", "tok-1");
    w.fetch = (url, init) => {
      calls.push({ url: String(url), method: (init && init.method) || "GET", body: init && init.body });
      let status = 404, body = { error: "stub" };
      if (/\/api\/billing\/consent/.test(url)) { if (!opts.consentDown) { status = 200; body = today; } else { status = 503; } }
      else if (/\/api\/auth\/me$/.test(url)) { status = 200; body = { user: { id: "u1" }, subscription: null, access: { active: false } }; }
      else if (/\/api\/stripe\/checkout$/.test(url)) { status = 400; body = { error: "stub", message: "stub refusal" }; }
      const p = Promise.resolve({ ok: status === 200, status, json: () => Promise.resolve(JSON.parse(JSON.stringify(body))), text: () => Promise.resolve(JSON.stringify(body)),
        headers: { get: () => "application/json" } });
      p.catch(() => {});
      return p;
    };
    w.PublicKeyCredential = undefined;
    const errs = [];
    // jsdom fires DOMContentLoaded itself, once, after these run; it is
    // dispatched here only if it has already gone by, so no page wires twice.
    let loadedEvent = false;
    w.document.addEventListener("DOMContentLoaded", () => { loadedEvent = true; });
    [...w.document.querySelectorAll("script:not([src])")].forEach(sc => { try { w.eval(sc.textContent); } catch (e) { errs.push(e.message); } });
    await settle();
    if (!loadedEvent) w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
    try { w.eval(FE["scripts/bf-renew-consent.js"]); } catch (e) { errs.push("bf-renew-consent.js: " + e.message); }
    await settle(); await settle();
    return { w, doc: w.document, calls, errs };
  }
  const PAGES = [
    ["billing.html", "checkoutBtn", doc => (doc.getElementById("checkoutMsg") || {}).textContent || ""],
    ["app.html", "subscribeBtn", doc => (doc.getElementById("err") || {}).textContent || ""]
  ];
  for (const [file, btnId, msgOf] of PAGES) {
    let p = await runPage(file, {});
    const label = p.doc.querySelector("[data-bf-renew-consent]"), box = p.doc.querySelector("[data-bf-renew-consent-box]");
    check("E1. " + file + ": the box shows the server's words, visible and unticked",
      label && !label.hidden && label.textContent.trim() === today.text && box && box.checked === false && p.calls.some(c => /\/api\/billing\/consent\?product=all_access$/.test(c.url)),
      (label && label.textContent) + " " + p.errs.join("; "));
    const checkoutCalls = () => p.calls.filter(c => /\/api\/stripe\/checkout$/.test(c.url));
    p.doc.getElementById(btnId).click();
    await settle();
    check("E2. " + file + ": Subscribe without the tick sends no checkout and says why", checkoutCalls().length === 0 && /Tick the box beside the price/.test(msgOf(p.doc)),
      checkoutCalls().length + " " + msgOf(p.doc));
    box.checked = true;
    p.doc.getElementById(btnId).click();
    await settle();
    const sent = checkoutCalls()[0];
    let body = {};
    try { body = JSON.parse(sent && sent.body || "{}"); } catch (e) { /* none */ }
    check("E3. " + file + ": ticked, the checkout request carries the consent on the words shown",
      checkoutCalls().length === 1 && sent.method === "POST" && same(body, OK), checkoutCalls().length + " " + (sent && sent.method) + " " + JSON.stringify(body));
    check("E4. " + file + ": a refusal's own message is shown", /stub refusal/.test(msgOf(p.doc)), msgOf(p.doc));
    p = await runPage(file, { consentDown: true });
    const l2 = p.doc.querySelector("[data-bf-renew-consent]"), b2 = p.doc.querySelector("[data-bf-renew-consent-box]");
    b2.checked = true;   // even ticked by hand while hidden
    p.doc.getElementById(btnId).click();
    await settle();
    check("E5. " + file + ": the words cannot be loaded: the box stays hidden and no checkout is sent",
      l2.hidden === true && p.calls.filter(c => /\/api\/stripe\/checkout$/.test(c.url)).length === 0 && /could not be loaded/.test(msgOf(p.doc)), msgOf(p.doc));
  }

  check("no network was touched", NETWORK.length === 0, NETWORK.join(", "));
  console.log("\n" + passes + " passed, " + failures + " failed");
  console.log(failures === 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.log("FAIL  checkAutoRenewConsent crashed: " + (e && e.stack || e)); process.exit(1); });
