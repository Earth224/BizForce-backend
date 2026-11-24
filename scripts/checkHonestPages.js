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
        dry_run and drafted tasks; Sent counts only "sent" (never "completed").
        A failed task read shows "could not be read", never 0.
        NAMED (Nov 23 2026, LR-2): BEFORE also Replied and Converted, today's
        sales_lead_pipeline rows from the real GET /api/agents/sales/pipeline
        route. AFTER that route is gone (Lead Radar's replies are every
        member's, on agents/lead-radar.html; the old pipeline is the owner's
        read-only archive), so the funnel is Drafted and Sent, and the page
        makes no call to the removed route.
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
  // NAMED (Nov 23 2026, LR-2): BEFORE "zero-on-failed-pipeline" (the removed pipeline read). AFTER a failed task read shows 0.
  "zero-on-failed-tasks": [[SALES, "            if (el) el.textContent = \"could not be read\";\n", "            if (el) el.textContent = \"0\";\n"]],
  // the page reads the removed pipeline route again
  "removed-route-read": [[SALES, "          var r = await fetch(API_URL + \"/api/ai/tasks?agent_type=sales&limit=50\", {", "          fetch(API_URL + \"/api/agents/sales/pipeline\");\n          var r = await fetch(API_URL + \"/api/ai/tasks?agent_type=sales&limit=50\", {"]],
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

/* NAMED (Nov 23 2026, LR-2): the real GET /api/agents/sales/pipeline route was lifted here for Replied and Converted. The
   route is gone (lib/routeAccess.js lists GET /api/leads/archive, the owner's read-only archive, in its place), so nothing
   is lifted; the funnel below is Drafted and Sent, from the page's own tasks read. */
const now = new Date();
const TODAY = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 12).toISOString();
const YESTERDAY = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1, 12).toISOString();

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
  const calls = [];
  const fetchStub = (url) => {
    const p = url.replace(/^https?:\/\/[^/]+/, "");
    calls.push(p);
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
  return { drafted: read("mcFnDrafted"), sent: read("mcFnSent"), replied: read("mcFnReplied"), converted: read("mcFnConverted"), ready: !!ready, calls };
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
  const ok = await runFunnel((p) => p === "/api/ai/tasks" ? { status: 200, body: { tasks: TASKS } } : { status: 200, body: {} });
  check("the page's ready handler ran", ok.ready);
  check("Drafted: today's 3 dry runs and 1 draft = 4", ok.drafted === "4", ok.drafted);
  check("Sent: only today's 2 \"sent\" tasks — not the 3 completed, the failed send or yesterday's", ok.sent === "2", ok.sent);
  // NAMED (Nov 23 2026, LR-2): BEFORE Replied 2 and Converted 1 from the pipeline route. AFTER no Replied or Converted row,
  // and no call to the removed route.
  check("no Replied or Converted figure is drawn (the old pipeline is an archive, not today's work)",
    ok.replied === "(never written)" && ok.converted === "(never written)" && PAGES[SALES].indexOf("mcFnReplied") === -1 && PAGES[SALES].indexOf("mcFnConverted") === -1,
    JSON.stringify(ok));
  check("the page never calls the removed GET /api/agents/sales/pipeline", ok.calls.every(p => p.indexOf("/api/agents/sales/pipeline") === -1) &&
    PAGES[SALES].indexOf("/api/agents/sales/pipeline") === -1, JSON.stringify(ok.calls));
  const tfail = await runFunnel((p) => p === "/api/ai/tasks" ? { status: 500, body: {} } : { status: 200, body: {} });
  check("a failed task read: Drafted and Sent say could not be read, never 0",
    tfail.drafted === "could not be read" && tfail.sent === "could not be read", JSON.stringify(tfail));
  const toff = await runFunnel((p) => p === "/api/ai/tasks" ? "reject" : { status: 200, body: {} });
  check("an unreachable task read says could not be read too", toff.drafted === "could not be read" && toff.sent === "could not be read", JSON.stringify(toff));
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
