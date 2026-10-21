"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkBfcNotice — every place BizCash is shown says plainly what it is.

   Launch audit #9. One sentence, word for word, from one source per repo:

     BizCash (BFC) is an in-app credit for use on BizForceAI only. It has no
     cash value, cannot be bought, sold, exchanged or withdrawn for money, and
     its rules or availability may change.

   The frontend keeps it in scripts/bf-bfc-notice.js, which fills every
   <p class="bfc-notice" data-bfc-notice></p> on the page it is loaded by. The
   server keeps it in BFC_NOTICE and sends it as bfcDisclaimer on GET
   /api/wallet and on a successful POST /api/wallet/transfer.

   WHAT THIS PROVES
     1. The server's BFC_NOTICE, the frontend's sentence and the sentence above
        are the same string.
     2. bf-bfc-notice.js, run in a vm against a stub document, writes exactly
        that sentence into every notice element and adds its style once.
     3. A BFC page is any page whose markup or code says BFC, BizCash or
        BizForce Credits, or that calls a route where BFC is earned, sent, spent
        or shown (wallet, marketplace, purchases, crowdfunding, certification
        award; the USD checkout is not one). Every BFC page has one empty notice
        element and loads bf-bfc-notice.js after it. A new BFC page without it
        fails here.
     4. The exemptions are few, named, and still true: an exempt page calls
        none of those routes. An exemption for a page that no longer mentions
        BFC is stale and fails too.
     5. No page or script writes its own copy of the sentence ("no cash value"
        appears in the frontend only in bf-bfc-notice.js, and in server.js only
        in BFC_NOTICE).
     6. GET /api/wallet, run in a vm with a stub database, answers
        bfcDisclaimer equal to the sentence; every success answer of POST
        /api/wallet/transfer carries bfcDisclaimer: BFC_NOTICE.

   MUTATE=<name> edits server.js or a frontend file IN MEMORY. MUTATE=all runs
   each in its own process and passes only if every one fails at least one
   check. A mutation whose search text does not match exactly once is an
   ERROR, never counted as caught.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const NOTICE_JS = "scripts/bf-bfc-notice.js";
const SENTENCE = "BizCash (BFC) is an in-app credit for use on BizForceAI only. It has no cash value, cannot be bought, sold, " +
  "exchanged or withdrawn for money, and its rules or availability may change.";
const ELEMENT = "<p class=\"bfc-notice\" data-bfc-notice></p>";
const SCRIPT_TAG = "<script src=\"/scripts/bf-bfc-notice.js\"></script>";

/* Pages that mention BFC but show no balance and offer no BFC action. Each
   reason must stay true: section 4 fails an exempt page that calls a BFC route. */
const EXEMPT = {
  "dashboard.html": "link tiles to the wallet and to crowdfunding; it reads no balance and moves no BFC"
};
/* Routes where BFC is earned, sent, spent or shown. */
const BFC_ROUTE = /\/api\/(wallet|marketplace|purchases|crowdfunding|certifications\/award)\b/;

const SV_FILE = "server.js";
const MUTATIONS = {
  // the wallet page loses its notice
  "notice-missing-wallet": [["wallet.html", "    " + ELEMENT + "\n", ""]],
  // the frontend sentence drifts
  "notice-text-drift": [[NOTICE_JS, "It has no cash value, cannot be bought", "It has no fixed cash value, cannot be bought"]],
  // the server sentence drifts
  "server-text-drift": [[SV_FILE, "exchanged or withdrawn for money, and its rules or availability may change.\";", "exchanged or withdrawn for money.\";"]],
  // a page starts showing a balance without the notice
  "new-page-without-notice": [["billing.html", "</body>", "<script>fetch(API_URL + \"/api/wallet\");</script>\n</body>"]],
  // the marketplace keeps the element but stops loading the script
  "script-not-loaded": [["marketplace.html", "    " + SCRIPT_TAG + "\n", ""]],
  // the script is loaded before the element, so the element stays empty
  "script-before-element": [["campaigns.html", "    " + ELEMENT + "\n    " + SCRIPT_TAG + "\n", "    " + SCRIPT_TAG + "\n    " + ELEMENT + "\n"]],
  // a page writes its own copy of the sentence
  "hardcoded-copy": [["receipts.html", "    " + ELEMENT + "\n", "    <p class=\"bfc-notice\" data-bfc-notice>BizCash has no cash value.</p>\n"]],
  // the exempt dashboard starts reading the balance
  "exempt-page-shows-balance": [["dashboard.html", "(function syncAgentsNavCountFromApi() {\n",
    "fetch(API_URL + \"/api/wallet\");\n(function syncAgentsNavCountFromApi() {\n"]],
  // the transfer answer drops the disclaimer
  "transfer-drops-disclaimer": [[SV_FILE, "return res.json({ balance: data, bfcDisclaimer: BFC_NOTICE });", "return res.json({ balance: data });"]],
  // the wallet answer drops the disclaimer
  "wallet-drops-disclaimer": [[SV_FILE, "transactions: txns || [], bfcDisclaimer: BFC_NOTICE });", "transactions: txns || [] });"]],
  // the script fills the first element only
  "fills-first-only": [[NOTICE_JS, "for (var i = 0; i < els.length; i++) { els[i].textContent = BFC_NOTICE; }", "if (els.length) { els[0].textContent = BFC_NOTICE; }"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the two repos ──────────────────────────────────────────────────────── */
const FILES = {};
(function walk(dir) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
    const p = path.join(dir, d.name);
    if (d.isDirectory()) { if (!/^\.|node_modules/.test(d.name)) walk(p); }
    else if (/\.(html|js)$/.test(d.name)) FILES[path.relative(FRONTEND, p).replace(/\\/g, "/")] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
  });
})(FRONTEND);
let SV = fs.readFileSync(path.join(REPO, SV_FILE), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) {
    if (file === SV_FILE) SV = s.replaceOnce(SV, from, to, MUTATE + " in " + file);
    else FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  }
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* The sentence a string-literal expression evaluates to, or null. */
function literalValue(expr) {
  if (!/^\s*("([^"\\\n]|\\.)*"\s*\+?\s*)+$/.test(expr)) return null;
  try { return vm.runInNewContext("(" + expr + ")", {}); } catch (e) { return null; }
}
/* Runs bf-bfc-notice.js against a stub document holding `count` notice elements. */
function runNoticeScript(src, count) {
  const els = Array.from({ length: count }, () => ({ textContent: "" }));
  const head = { children: [], appendChild(n) { this.children.push(n); } };
  const byId = {};
  const document = {
    head, documentElement: head,
    querySelectorAll: sel => (sel === "[data-bfc-notice]" ? els : []),
    getElementById: id => byId[id] || null,
    createElement: () => { const n = { id: "", textContent: "" }; return n; }
  };
  head.appendChild = function (n) { this.children.push(n); if (n.id) byId[n.id] = n; };
  const win = { document };
  vm.runInNewContext(src, { window: win, document });
  const again = typeof win.bfFillBfcNotices === "function" ? win.bfFillBfcNotices(document) : -1;
  return { els, styles: head.children.length, win, again };
}
const visibleAndCode = html => html.replace(/<!--[\s\S]*?-->/g, "");

(async function main() {
  /* ── 1. one sentence ──────────────────────────────────────────────────── */
  console.log("\n══ 1. the server, the frontend and the brief say the same sentence ══");
  const svDecl = /\nconst BFC_NOTICE = ((?:"(?:[^"\\\n]|\\.)*"\s*\+?\s*)+);/.exec(SV);
  const svText = svDecl ? literalValue(svDecl[1]) : null;
  check("server.js declares BFC_NOTICE once, as plain string literals", svDecl && (SV.match(/\nconst BFC_NOTICE = /g) || []).length === 1 && svText !== null);
  check("server.js BFC_NOTICE is the sentence, word for word", svText === SENTENCE, svText);
  const feDecl = /var BFC_NOTICE = ((?:"(?:[^"\\\n]|\\.)*"\s*\+?\s*)+);/.exec(FILES[NOTICE_JS] || "");
  const feText = feDecl ? literalValue(feDecl[1]) : null;
  check("bf-bfc-notice.js holds the sentence, word for word", feText === SENTENCE, feText);

  /* ── 2. the script ────────────────────────────────────────────────────── */
  console.log("\n══ 2. bf-bfc-notice.js fills every notice ══");
  let run = null;
  try { run = runNoticeScript(FILES[NOTICE_JS], 3); } catch (e) { check("bf-bfc-notice.js runs", false, e.message); }
  if (run) {
    check("every notice element on the page gets the sentence (3 of 3)", run.els.every(e => e.textContent === SENTENCE), JSON.stringify(run.els.map(e => e.textContent.slice(0, 40))));
    check("it adds its style once, even when run again", run.styles === 1 && run.again === 3, run.styles + " style(s), refill " + run.again);
    check("it exposes the same sentence as window.BF_BFC_NOTICE", run.win.BF_BFC_NOTICE === SENTENCE);
    let none = null; try { none = runNoticeScript(FILES[NOTICE_JS], 0); } catch (e) { /* reported below */ }
    check("a page with no notice element gets no style", none && none.styles === 0);
  }

  /* ── 3. every BFC page carries it ─────────────────────────────────────── */
  console.log("\n══ 3. every page that shows BFC carries the notice ══");
  const pages = Object.keys(FILES).filter(f => f.endsWith(".html")).sort();
  /* The first argument of each fetch(…), whole: up to the comma or paren that
     closes it at depth 0, so `"/api/marketplace/listings/" + id + "/checkout-usd"`
     is read as one URL (the USD checkout), not cut at encodeURIComponent(. */
  const fetchUrls = html => {
    const code = visibleAndCode(html), out = [];
    for (const m of code.matchAll(/\bfetch\(/g)) {
      let d = 0, j = m.index + m[0].length, q = null;
      for (; j < code.length; j++) {
        const c = code[j];
        if (q) { if (c === "\\") j++; else if (c === q) q = null; continue; }
        if (c === "\"" || c === "'" || c === "`") q = c;
        else if (c === "(" || c === "[" || c === "{") d++;
        else if (c === ")" || c === "]" || c === "}") { if (!d) break; d--; }
        else if (c === "," && !d) break;
      }
      out.push(code.slice(m.index + m[0].length, j));
    }
    return out;
  };
  const callsBfcRoute = html => fetchUrls(html).some(u => BFC_ROUTE.test(u) && u.indexOf("checkout-usd") === -1);
  const bfcPages = pages.filter(f => /\bBFC\b|BizCash|BizForce Credits/.test(visibleAndCode(FILES[f])) || callsBfcRoute(FILES[f]));
  check("the BFC pages are found (" + bfcPages.length + ")", bfcPages.length >= 8 && bfcPages.indexOf("wallet.html") !== -1 && bfcPages.indexOf("marketplace.html") !== -1,
    bfcPages.join(", "));
  const needing = bfcPages.filter(f => !Object.prototype.hasOwnProperty.call(EXEMPT, f));
  const problems = [];
  needing.forEach(f => {
    const html = visibleAndCode(FILES[f]);
    const elAt = html.indexOf(ELEMENT), scAt = html.indexOf(SCRIPT_TAG);
    if (elAt === -1) problems.push(f + ": no empty notice element");
    else if (html.indexOf(ELEMENT, elAt + 1) !== -1) problems.push(f + ": two notice elements");
    if ((html.match(/data-bfc-notice/g) || []).length !== 1) problems.push(f + ": data-bfc-notice " + (html.match(/data-bfc-notice/g) || []).length + " times");
    if (scAt === -1) problems.push(f + ": bf-bfc-notice.js not loaded");
    else if (elAt !== -1 && scAt < elAt) problems.push(f + ": bf-bfc-notice.js loaded before the element");
  });
  check("each of the " + needing.length + " BFC pages has one empty notice element and loads bf-bfc-notice.js after it", problems.length === 0, problems.join("; "));
  console.log("      pages: " + needing.join(", "));

  /* ── 4. the exemptions ────────────────────────────────────────────────── */
  console.log("\n══ 4. each exemption is still true ══");
  Object.keys(EXEMPT).forEach(f => {
    check(f + " is exempt (" + EXEMPT[f] + ") and still mentions BFC", FILES[f] !== undefined && bfcPages.indexOf(f) !== -1);
    check(f + " calls no route where BFC is earned, sent, spent or shown", FILES[f] !== undefined && !callsBfcRoute(FILES[f]));
  });

  /* ── 5. no copies ─────────────────────────────────────────────────────── */
  console.log("\n══ 5. no page writes its own copy ══");
  const copies = Object.keys(FILES).filter(f => f !== NOTICE_JS && /no cash value|in-app credit for use on BizForceAI|withdrawn for money/i.test(FILES[f]));
  check("\"no cash value\" appears in the frontend only in " + NOTICE_JS, copies.length === 0, copies.join(", "));
  const filled = pages.filter(f => /data-bfc-notice\s*>[^<\s]/.test(FILES[f]) || /<p class="bfc-notice"[^>]*>[^<\s]/.test(FILES[f]));
  check("no notice element carries text of its own", filled.length === 0, filled.join(", "));
  check("server.js says \"no cash value\" only in BFC_NOTICE", (SV.match(/no cash value/gi) || []).length === 1 && svDecl && /no cash value/.test(svDecl[1]));

  /* ── 6. the wallet routes ─────────────────────────────────────────────── */
  console.log("\n══ 6. the wallet answers carry bfcDisclaimer ══");
  function routeText(sig) {
    const start = SV.indexOf(sig);
    if (start === -1) return "";
    return SV.slice(start, s.braceMatch(SV, SV.indexOf("{", SV.indexOf("async function", start))) + 2);
  }
  const getRoute = routeText("app.get(\"/api/wallet\", requireAuth,");
  const transferRoute = routeText("app.post(\"/api/wallet/transfer\", requireAuth,");
  check("both wallet routes are found", getRoute.length > 200 && transferRoute.length > 200);
  /* Every answer a caller can succeed with: res.json(…) or res.status(2xx).json(…). */
  function successAnswers(code) {
    const out = [];
    for (const m of code.matchAll(/res(?:\.status\((\d{3})\))?\.json\(/g)) {
      if (m[1] && !/^2/.test(m[1])) continue;
      const open = m.index + m[0].length - 1;
      let d = 0, j = open;
      for (; j < code.length; j++) { if (code[j] === "(") d++; else if (code[j] === ")") { d--; if (!d) break; } }
      out.push(code.slice(open + 1, j));
    }
    return out;
  }
  const getOk = successAnswers(getRoute), transferOk = successAnswers(transferRoute);
  check("GET /api/wallet: every success answer carries bfcDisclaimer: BFC_NOTICE (" + getOk.length + ")",
    getOk.length >= 1 && getOk.every(a => /\bbfcDisclaimer: BFC_NOTICE\b/.test(a)), getOk.join(" | "));
  check("POST /api/wallet/transfer: every success answer carries bfcDisclaimer: BFC_NOTICE (" + transferOk.length + ")",
    transferOk.length >= 1 && transferOk.every(a => /\bbfcDisclaimer: BFC_NOTICE\b/.test(a)), transferOk.join(" | "));

  // GET /api/wallet, run: a wallet with a balance and one transaction
  let answer = null;
  try {
    let handler = null;
    const chain = (result) => {
      const q = {}; ["select", "eq", "order", "limit", "gte", "in", "neq"].forEach(k => { q[k] = () => q; });
      q.maybeSingle = async () => result.one; q.single = async () => result.one;
      q.then = (ok, bad) => Promise.resolve(result.many).then(ok, bad);
      return q;
    };
    const supabase = {
      from(table) {
        if (table === "user_wallets") return Object.assign(chain({ one: { data: { balance: 40 }, error: null } }), { insert: async () => ({ error: null }) });
        if (table === "wallet_transactions") return chain({ many: { data: [{ id: 1, type: "credit", amount: 40, description: "Welcome bonus" }], error: null } });
        return chain({ one: { data: null, error: null }, many: { data: [], error: null } });
      }
    };
    const ctx = { supabase, nowIso: () => "2026-10-21T12:00:00.000Z", console: { log() {}, error() {}, warn() {} }, requireAuth: 0,
      app: { get() { handler = arguments[arguments.length - 1]; }, post() {}, put() {}, delete() {} } };
    vm.createContext(ctx);
    vm.runInContext(s.closureFor(SV, getRoute), ctx);
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    let nextErr = null;
    await handler({ user: { id: "u1" } }, res, e => { nextErr = e || new Error("next"); });
    answer = { status: res.statusCode, body: res.body, nextErr };
  } catch (e) { answer = { error: e.message }; }
  check("GET /api/wallet, run: 200 with the balance, the transactions and bfcDisclaimer equal to the sentence",
    answer && answer.status === 200 && answer.body && answer.body.balance === 40 && Array.isArray(answer.body.transactions) &&
    answer.body.transactions.length === 1 && answer.body.bfcDisclaimer === SENTENCE, JSON.stringify(answer));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
