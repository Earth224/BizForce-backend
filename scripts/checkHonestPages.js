"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkHonestPages — nothing on the agent pages pretends.

   Frontend "Nothing on the agent pages pretends" made the sales funnel count
   what is recorded, removed every static capability-pill row, relabelled the
   dashboard link, renamed two task labels, replaced "marketplace
   intelligence", and stopped agents/content.html showing leftover simulated
   stats. This reads the frontend checkout beside this repo.

   WHAT THIS PROVES
     1. The funnel, run in vm with a stubbed DOM: Drafted counts today's
        dry_run and drafted tasks; Sent counts only "sent" (never "completed");
        Replied and Converted count today's sales_lead_pipeline rows, from a
        response made by the real GET /api/agents/sales/pipeline route lifted
        against a fake database. A failed pipeline read, and a failed task read,
        each show "could not be read", never 0.
     2. No capability-pill row or rule on any page (dashboard.html excepted).
     3. No "Run on Dashboard"; every agent page links "Open Dashboard".
     4. "Shop Audit Checklist" and "Competitor Comparison (from your profile)".
     5. No "marketplace intelligence".
     6. agents/content.html never reads contentAgent.stats and draws no
        "Sample" note.
     7. BizForce Market is priced in BizCash only: no page or script offers a
        USD purchase, a USD price or a cash portion; a seller sees "Priced in
        BizCash (BFC)"; a listing with no BFC price says it is not for sale;
        integrations.html and my-purchases.html stay true.

   MUTATE=<name> edits the frontend files IN MEMORY. MUTATE=all runs each in
   its own process and passes only if every one fails. A mutation whose search
   text does not match exactly once is an ERROR, never counted as caught.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkHonestPages: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkHonestPages: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const SALES = "agents/sales.html", ETSY = "etsy-agent.html", INDEX = "index.html";
const MUTATIONS = {
  // Sent counts finished tasks again
  "restore-old-funnel-status": [[SALES, "else if (t.status === \"sent\") sentCount++;", "else if (t.status === \"completed\") sentCount++;"]],
  // a pill row comes back
  // NAMED (Oct 28 2026, one honest description per agent): the Storefront subtitle these two anchors sit on changes
  // from "Listing copy, tag-length keyword candidates, and pricing arithmetic on figures you supply." to config/brain.js's "Listing copy, keyword candidates measured against the tag limits you enter, and pricing arithmetic on figures you supply."
  "restore-pill-row": [[ETSY, "<p class=\"agent-subtitle\">Listing copy, keyword candidates measured against the tag limits you enter, and pricing arithmetic on figures you supply.</p>",
    "<p class=\"agent-subtitle\">Listing copy, keyword candidates measured against the tag limits you enter, and pricing arithmetic on figures you supply.</p>\n        <div class=\"capability-pills\"><span class=\"capability-pill\">Competitors</span></div>"]],
  // the marketplace claim comes back
  "restore-marketplace-intelligence": [[INDEX, "Listing copy, keyword candidates measured against the tag limits you enter, and pricing arithmetic on figures you supply.",
    "Shop listings, keywords, pricing, and marketplace intelligence."]],
  // a failed pipeline read shows 0
  "zero-on-failed-pipeline": [[SALES, "          setFn(\"mcFnReplied\", \"could not be read\");\n          setFn(\"mcFnConverted\", \"could not be read\");\n",
    "          setFn(\"mcFnReplied\", 0);\n          setFn(\"mcFnConverted\", 0);\n"]],
  // a "Buy with USD" button left on one page
  "buy-usd-left": [["marketplace.html", "'<span class=\"not-for-sale\">Not for sale until the seller sets a BizCash price</span>') +\n",
    "'<span class=\"not-for-sale\">Not for sale until the seller sets a BizCash price</span>') +\n        '<button type=\"button\" class=\"btn-sm btn-buy btn-buy-usd\"' + idAttr + '>Buy with USD</button>' +\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the frontend, every page but dashboard.html ───────────────────────── */
const PAGES = {};
(function walk(dir) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
    const p = path.join(dir, d.name);
    if (d.isDirectory()) { if (!/^\.|node_modules/.test(d.name)) walk(p); }
    else if (d.name.endsWith(".html") && d.name !== "dashboard.html") PAGES[path.relative(FRONTEND, p).replace(/\\/g, "/")] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
  });
})(FRONTEND);
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) PAGES[file] = s.replaceOnce(PAGES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (frontend, in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const flush = async () => { for (let i = 0; i < 40; i++) await new Promise(r => setImmediate(r)); };

/* ── the real pipeline route, lifted ───────────────────────────────────── */
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch",
  "requireAuth", "OUTREACH_CREDENTIAL_OWNER_ID", "LEAD_RADAR_UNAVAILABLE"]);
function liftRoute(route) {
  const start = SRC.indexOf("app.get(\"" + route + "\",");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", start)));
  const root = SRC.slice(start, end + 2);
  const have = new Map(); const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = s.definitionOf(SRC, name);
    if (!def) continue;
    if (/^(?:var|const|let) [^=]*=[^;]*\brequire\(/.test(def)) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((a, b) => SRC.indexOf(a) - SRC.indexOf(b)).join("\n\n") + "\n\n" + root;
}
const OWNER = "owner-1";
const now = new Date();
const TODAY = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 12).toISOString();
const YESTERDAY = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1, 12).toISOString();
async function realPipeline() {
  const rows = {
    sales_lead_pipeline: [
      { user_id: OWNER, lead_post_uri: "u1", status: "replied", last_draft: null, updated_at: TODAY },
      { user_id: OWNER, lead_post_uri: "u2", status: "replied", last_draft: null, updated_at: TODAY },
      { user_id: OWNER, lead_post_uri: "u3", status: "replied", last_draft: null, updated_at: YESTERDAY },
      { user_id: OWNER, lead_post_uri: "u4", status: "converted", last_draft: null, updated_at: TODAY },
      { user_id: OWNER, lead_post_uri: "u5", status: "contacted", last_draft: null, updated_at: TODAY }
    ],
    bsky_leads: []
  };
  const from = (table) => {
    const q = { filters: [] };
    const b = { select() { return b; } };
    ["eq", "in", "order", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.then = (res, rej) => Promise.resolve({ data: (rows[table] || []).filter(r => q.filters.every(f => f[0] !== "eq" || r[f[1]] === f[2])), error: null }).then(res, rej);
    return b;
  };
  let handler = null;
  const ctx = { supabase: { from }, JSON, Object, Array, Number, String, Promise, Date, console: { log() {}, error() {}, warn() {} },
    OUTREACH_CREDENTIAL_OWNER_ID: OWNER, LEAD_RADAR_UNAVAILABLE: { error: "no" }, requireAuth: 0,
    app: { get() { handler = arguments[arguments.length - 1]; } } };
  vm.createContext(ctx);
  vm.runInContext(liftRoute("/api/agents/sales/pipeline"), ctx);
  const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
  await handler({ user: { id: OWNER } }, res, (e) => { res.code = 500; res.body = { error: String(e && e.message) }; });
  return res;
}

/* ── the funnel, in a stubbed page ─────────────────────────────────────── */
function fakeEl(id) {
  const el = { id, innerHTML: "", textContent: "", value: "10", className: "", disabled: false, style: {}, dataset: {}, children: [], parentNode: null,
    classList: { add() {}, remove() {}, toggle() { return false; }, contains() { return false; } },
    appendChild(c) { this.children.push(c); return c; }, insertBefore(c) { return c; }, removeChild() {}, remove() {}, addEventListener() {},
    setAttribute() {}, getAttribute() { return null; }, querySelector() { return null; }, querySelectorAll() { return []; }, closest() { return null; },
    getContext() { return {}; } };
  el.parentNode = { removeChild() {}, insertBefore() {}, appendChild() {} };
  return el;
}
async function runFunnel(handlers) {
  const els = new Map();
  let ready = null;
  const document = {
    readyState: "loading", body: fakeEl("body"), head: fakeEl("head"),
    getElementById(id) { if (!els.has(id)) els.set(id, fakeEl(id)); return els.get(id); },
    querySelector() { return fakeEl(null); }, querySelectorAll() { return []; }, createElement() { return fakeEl(null); },
    addEventListener(type, fn) { if (type === "DOMContentLoaded") ready = fn; }
  };
  const fetchStub = (url) => {
    const p = url.replace(/^https?:\/\/[^/]+/, "");
    const h = handlers(p.split("?")[0], p);
    if (h === "reject") return Promise.reject(new TypeError("Failed to fetch"));
    return Promise.resolve({ ok: h.status >= 200 && h.status < 300, status: h.status, json: () => Promise.resolve(JSON.parse(JSON.stringify(h.body))) });
  };
  function Chart() { return { destroy() {}, update() {}, data: { labels: [], datasets: [{ data: [] }] } }; }
  function MutationObserver() { return { observe() {}, disconnect() {} }; }
  const ctx = { window: {}, document, console: { log() {}, error() {}, warn() {} }, fetch: fetchStub, Chart, MutationObserver, Date, JSON, Math, Promise,
    localStorage: { getItem(k) { return k === "bf_token" ? "check-token" : null; }, setItem() {}, removeItem() {} },
    setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {}, requestAnimationFrame() { return 0; },
    location: { href: "", search: "" }, navigator: {} };
  ctx.window = ctx;
  vm.createContext(ctx);
  const blocks = PAGES[SALES].match(/<script>([\s\S]*?)<\/script>/g).map(b => b.slice(8, -9));
  blocks.forEach((b, i) => { try { vm.runInContext(b, ctx, { filename: SALES + "#" + i }); } catch (e) { /* a block reaching for something this stub lacks */ } });
  if (ready) { try { ready(); } catch (e) { /* the handler's other loads */ } }
  await flush();
  const read = (id) => els.has(id) ? els.get(id).textContent : "(never written)";
  return { drafted: read("mcFnDrafted"), sent: read("mcFnSent"), replied: read("mcFnReplied"), converted: read("mcFnConverted"), ready: !!ready };
}
const TASKS = [
  { id: 1, status: "dry_run", created_at: TODAY, prompt: "x" }, { id: 2, status: "dry_run", created_at: TODAY, prompt: "x" },
  { id: 3, status: "dry_run", created_at: TODAY, prompt: "x" }, { id: 4, status: "drafted", created_at: TODAY, prompt: "x" },
  { id: 5, status: "sent", created_at: TODAY, prompt: "x @someone" }, { id: 6, status: "sent", created_at: TODAY, prompt: "x" },
  { id: 7, status: "completed", created_at: TODAY, prompt: "x" }, { id: 8, status: "completed", created_at: TODAY, prompt: "x" },
  { id: 9, status: "send_failed", created_at: TODAY, prompt: "x" }, { id: 11, status: "completed", created_at: TODAY, prompt: "x" }, { id: 10, status: "sent", created_at: YESTERDAY, prompt: "x" }
];

(async function main() {
  /* ── 1. the funnel ────────────────────────────────────────────────────── */
  console.log("\n══ 1. the sales funnel ══");
  const pipe = await realPipeline();
  check("fixture: the real pipeline route answers 200 with replied and converted groups",
    pipe.code === 200 && pipe.body.pipeline && pipe.body.pipeline.replied.length === 3 && pipe.body.pipeline.converted.length === 1, JSON.stringify(pipe.body).slice(0, 200));
  const ok = await runFunnel((p) => p === "/api/ai/tasks" ? { status: 200, body: { tasks: TASKS } }
    : p === "/api/agents/sales/pipeline" ? { status: 200, body: pipe.body } : { status: 200, body: {} });
  check("the page's ready handler ran", ok.ready);
  check("Drafted: today's 3 dry runs and 1 draft = 4", ok.drafted === "4", ok.drafted);
  check("Sent: only today's 2 \"sent\" tasks — not the 3 completed, the failed send or yesterday's", ok.sent === "2", ok.sent);
  check("Replied: today's 2 pipeline rows at replied (yesterday's is not today)", ok.replied === "2", ok.replied);
  check("Converted: today's 1 pipeline row at converted", ok.converted === "1", ok.converted);
  const pfail = await runFunnel((p) => p === "/api/ai/tasks" ? { status: 200, body: { tasks: TASKS } }
    : p === "/api/agents/sales/pipeline" ? { status: 500, body: { error: "down" } } : { status: 200, body: {} });
  check("a failed pipeline read: Replied and Converted say could not be read, never 0",
    pfail.replied === "could not be read" && pfail.converted === "could not be read", JSON.stringify(pfail));
  check("…while Drafted and Sent still count", pfail.drafted === "4" && pfail.sent === "2");
  const poff = await runFunnel((p) => p === "/api/agents/sales/pipeline" ? "reject" : p === "/api/ai/tasks" ? { status: 200, body: { tasks: TASKS } } : { status: 200, body: {} });
  check("an unreachable pipeline says could not be read too", poff.replied === "could not be read" && poff.converted === "could not be read", JSON.stringify(poff));
  const tfail = await runFunnel((p) => p === "/api/ai/tasks" ? { status: 500, body: {} }
    : p === "/api/agents/sales/pipeline" ? { status: 200, body: pipe.body } : { status: 200, body: {} });
  check("a failed task read: Drafted and Sent say could not be read, never 0",
    tfail.drafted === "could not be read" && tfail.sent === "could not be read" && tfail.replied === "2", JSON.stringify(tfail));
  const sales = PAGES[SALES];
  check("the status list calls only \"sent\" Sent, and a completed task Completed",
    /sent:\s*\{ label: "Sent"/.test(sales) && /completed:\s*\{ label: "Completed"/.test(sales) && !/completed:\s*\{ label: "Sent"/.test(sales));
  check("drafts are labelled as not sent", sales.indexOf("<span class=\"fn-label\">Drafted (not sent)</span>") !== -1 && /dry_run:\s*\{ label: "Drafted \(dry run, not sent\)"/.test(sales));
  check("no funnel count reads a replied or converted ai_tasks status", !/t\.status === "replied"|t\.status === "converted"/.test(sales));

  /* ── 2-6. the pages ───────────────────────────────────────────────────── */
  console.log("\n══ 2-6. every page ══");
  const files = Object.keys(PAGES);
  const pilled = files.filter(f => /capability-pill/.test(PAGES[f]));
  check("2. no capability-pill row or rule on any of " + files.length + " pages", pilled.length === 0, pilled.join(", "));
  const runOn = files.filter(f => PAGES[f].indexOf("Run on Dashboard") !== -1);
  check("3. no \"Run on Dashboard\" anywhere", runOn.length === 0, runOn.join(", "));
  const openD = files.filter(f => /<a class="action-btn" href="(?:\.\.\/)?dashboard\.html">Open Dashboard<\/a>/.test(PAGES[f]));
  check("3. 18 agent pages link \"Open Dashboard\", still to the dashboard", openD.length === 18, openD.length + ": " + openD.join(", "));
  check("4. the Etsy page offers \"Shop Audit Checklist\"", /\{ value: "shop_audit",\s*label:\s*"Shop Audit Checklist" \}/.test(PAGES[ETSY]));
  const comp = files.filter(f => /value: "competitor_analysis"/.test(PAGES[f]));
  check("4. every page offering competitor_analysis calls it \"Competitor Comparison (from your profile)\"",
    comp.length === 2 && comp.every(f => /value: "competitor_analysis",\s*label:\s*"Competitor Comparison \(from your profile\)"/.test(PAGES[f])), comp.join(", "));
  check("4. the old labels are gone", files.every(f => !/label:\s*"Shop Audit" \}|label:\s*"Competitor Analysis" \}/.test(PAGES[f])));
  const mi = files.filter(f => /marketplace intelligence/i.test(PAGES[f]));
  check("5. no \"marketplace intelligence\"", mi.length === 0, mi.join(", "));
  // NAMED (Oct 28 2026): BEFORE "Listing copy, tag-length keyword candidates, and pricing arithmetic on figures you supply." AFTER the one honest description (config/brain.js; checkAgentDescriptions).
  check("5. the Storefront page and the home page describe listing copy, keyword candidates against the tag limits you enter, and pricing arithmetic",
    [ETSY, INDEX].every(f => PAGES[f].indexOf("Listing copy, keyword candidates measured against the tag limits you enter, and pricing arithmetic on figures you supply.") !== -1));
  const content = PAGES["agents/content.html"];
  const code = content.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
  check("6. content.html never reads .stats from the contentAgent store", !/\.stats\b/.test(code), (code.match(/[^\n]*\.stats\b[^\n]*/) || [""])[0].trim());
  check("6. and draws no \"Sample\" note", content.indexOf("statsSimNote") === -1 && content.indexOf("sim-note") === -1);

  /* ── 7. BizForce Market is priced in BizCash only ─────────────────────── */
  /* BEFORE (frontend 9197caa): marketplace.html and garage-sale.html had a "Buy with USD" button, a Price (USD)
     or "Cash portion (USD)" field sent as price_usd, and copy offering a BFC/USD split; seller.html's Buy and
     listing.html's price ran through the USD checkout. AFTER: BizCash only, everywhere. */
  console.log("\n══ 7. no page offers a USD purchase ══");
  const scriptFiles = fs.existsSync(path.join(FRONTEND, "scripts")) ? fs.readdirSync(path.join(FRONTEND, "scripts")).filter(f => f.endsWith(".js")) : [];
  const ALL = Object.assign({}, PAGES);
  scriptFiles.forEach(f => { ALL["scripts/" + f] = fs.readFileSync(path.join(FRONTEND, "scripts", f), "utf8"); });
  const dash = path.join(FRONTEND, "dashboard.html");
  if (fs.existsSync(dash)) ALL["dashboard.html"] = fs.readFileSync(dash, "utf8");
  const offenders = (re) => Object.keys(ALL).filter(f => re.test(ALL[f]));
  const usdBuy = offenders(/Buy with USD|btn-buy-usd|buyWithUsd|checkout-usd/);
  check("7. no page or script has a \"Buy with USD\" button or calls the USD checkout (" + Object.keys(ALL).length + " files)", usdBuy.length === 0, usdBuy.join(", "));
  const usdField = offenders(/id="fPriceUsd"|Price \(USD\)|Cash portion|price_usd\s*:/);
  check("7. no USD price or cash-portion field, and no request sends price_usd", usdField.length === 0, usdField.join(", "));
  const usdCopy = offenders(/cash portion in USD|BFC\/USD split|USD-only|a cash \(USD\) amount/i);
  check("7. no copy implies USD sales between members", usdCopy.length === 0, usdCopy.join(", "));
  const SELLER_FORMS = ["marketplace.html", "garage-sale.html"];
  check("7. a seller sees \"Priced in BizCash (BFC)\" beside the price on " + SELLER_FORMS.join(" and "),
    SELLER_FORMS.every(f => /<label class="form-label">Price \(BFC\) \*<\/label>\s*<input class="form-input" id="fPrice"[^>]*>\s*<p class="field-hint">Priced in BizCash \(BFC\)\. BizForce Market trades in BizCash only\.<\/p>/.test(PAGES[f])));
  const NFS = "Not for sale until the seller sets a BizCash price";
  const nfsPages = ["marketplace.html", "garage-sale.html", "listing.html", "seller.html"];
  check("7. a listing with no BFC price says \"" + NFS + "\" on " + nfsPages.join(", "), nfsPages.every(f => PAGES[f].indexOf(NFS) !== -1),
    nfsPages.filter(f => PAGES[f].indexOf(NFS) === -1).join(", "));
  check("7. the storefront's Buy spends BizCash through the buy route",
    /fetch\(API_URL \+ "\/api\/marketplace\/listings\/" \+ encodeURIComponent\(id\) \+ "\/buy"/.test(PAGES["seller.html"]) && PAGES["seller.html"].indexOf(">Buy with BizCash</button>") !== -1);
  check("7. the listing page shows a BFC price only and sends Buy to the marketplace",
    !/price_usd|formatUsd/.test(PAGES["listing.html"]) && PAGES["listing.html"].indexOf("'<a class=\"buy-btn\" href=\"' + escapeHtml(buyHref) + '\">Buy with BizCash</a>'") !== -1);
  check("7. integrations.html still says Stripe bills the subscription only",
    PAGES["integrations.html"].indexOf("BizForce uses Stripe to bill your BizForce subscription: checkout and the billing portal. Taking payments into your own Stripe account is not built.") !== -1);
  check("7. my-purchases.html still formats a past USD order in dollars",
    PAGES["my-purchases.html"].indexOf("return isUsd ? (\"$\" + ((p.amount_usd || 0) / 100).toFixed(2)) : (p.amount_bfc || 0).toLocaleString() + \" BFC\";") !== -1);

  check("zero network", NETWORK.length === 0, JSON.stringify(NETWORK));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
