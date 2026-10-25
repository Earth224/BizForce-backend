"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkLegalPages — Terms, Privacy, Refunds and Contact: true to the code,
   linked from every page, accepted at sign-up, and in every email footer.

   The fixed facts (operator, postal address, contact address, law, age,
   refund policy, Terms version) live in lib/legal.js and nowhere else. The
   four frontend pages are built by lib/legalPages.js from those facts and
   from the code each figure comes from (scripts/buildLegalPages.js writes
   them). This reads the frontend checkout beside this repo.

   WHAT THIS PROVES
     A. The four pages in the frontend are exactly what the backend builds
        from the code as it stands, each with "Last updated" and the version;
        and the builder follows its sources: built from other figures, the
        pages state those figures (a hard-coded price or amount fails).
     B. Netlify serves /terms, /privacy, /refund and /contact from the pages,
        ahead of the catch-all: /terms no longer falls through to sign-in.
     C. One copy: the postal address and the contact address appear in
        lib/legal.js and, in the frontend, only in the four built pages.
        server.js no longer reads MAIL_POSTAL_ADDRESS.
     D. No personal name: no git author's name in the pages, lib/legal.js or
        the email footers.
     E. Every figure the Terms, Refunds and Billing state equals the code's:
        the price and interval, the past-due grace, the welcome bonus, the
        certification credit and count, the three transfer limits, the
        forfeit, and Privacy's YouTube retention.
     F. Privacy's service lists, protections and collected data equal Your
        data's (lib/yourData.js), and every host a frontend page has the
        browser load from is named there.
     G. The YouTube section: the YouTube Terms and Google Privacy Policy links,
        what is accessed and kept, and the code that backs "not combined".
     H. The footer (Terms · Privacy · Refunds · Contact · Your data) is on
        every page, run in jsdom; the updated-Terms notice shows only when the
        server says so, records the current version, and blocks nothing.
     I. Sign-up: the box is there, unchecked, with the exact words; the page
        will not send without it; the server refuses without it (before
        anything is read or written) and stores the version and time with the
        account; GET and POST /api/me/terms; migration 146.
     J. Email: every transactional email ends with the contact line, every
        marketing email with the unsubscribe link and the postal address, run
        through sendEmail and sendMarketingEmail lifted from server.js.
     K. No claim the code cannot back: checkHonestPages' rules and a list of
        security and compliance claims nothing here proves.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR, never counted
   as caught. BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns"), Module = require("module");
const cp = require("child_process");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkLegalPages: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkLegalPages: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const lf = t => t.replace(/\r\n/g, "\n");
const LEGAL = require("../lib/legal");
const YD = require("../lib/yourData");

const FOOTER_TAGS = "<footer class=\"bf-legal-footer\" data-bf-legal-footer></footer>\n<script src=\"/scripts/bf-legal-footer.js\"></script>\n";
const MUTATIONS = {
  // the Terms state a typed price instead of the code's
  "hard-coded-price": [["lib/legalPages.js", "const priceLine = money(f.price) + \" per \" + per;", "const priceLine = \"$199 per \" + per;"]],
  // a second copy of the postal address, on the sign-up page
  "address-duplicated": [["app.html", "        <button id=\"registerBtn\" class=\"btn\" type=\"submit\">Create Account</button>",
    "        <p>" + LEGAL.POSTAL_ADDRESS + "</p>\n        <button id=\"registerBtn\" class=\"btn\" type=\"submit\">Create Account</button>"]],
  // the YouTube Terms of Service link removed from Privacy
  "youtube-link-removed": [["privacy.html", "<a href=\"https://www.youtube.com/t/terms\">YouTube Terms of Service</a>", "YouTube Terms of Service"]],
  // the server accepts a sign-up without the box
  "signup-without-consent": [["server.js", "    if (req.body.accept_terms !== true) {", "    if (false) {"]],
  // one page loses the footer
  "footer-missing-one-page": [["wallet.html", FOOTER_TAGS, ""]],
  // a BFC limit stated wrong in the Terms
  "bfc-limit-wrong": [["terms.html", "one transfer can move at most 1,000 BFC", "one transfer can move at most 5,000 BFC"]],
  // the acceptance is not stored with the account
  "acceptance-not-recorded": [["server.js", "        terms_version: require(\"./lib/legal\").TERMS_VERSION,\n", ""]],
  // the box comes pre-ticked
  "box-prechecked": [["app.html", "<input id=\"rterms\" name=\"accept_terms\" type=\"checkbox\" required>", "<input id=\"rterms\" name=\"accept_terms\" type=\"checkbox\" required checked>"]],
  // the page sends the sign-up without the box
  "page-skips-box": [["app.html", "      if (!acceptedTerms) {\n", "      if (false) {\n"]],
  // /terms goes back behind the catch-all
  "terms-after-catchall": [["_redirects", "/terms /terms.html 200\n", ""], ["_redirects", "/* /app.html 200", "/* /app.html 200\n/terms /terms.html 200"]],
  // marketing mail loses its footer
  "marketing-no-footer": [["server.js", "    var footerHtml = footer.html;\n", "    var footerHtml = \"\";\n"]],
  // transactional mail loses the contact line
  "transactional-no-contact": [["server.js", "  if (String(template || \"\").indexOf(\"marketing:\") !== 0) {\n    var contactFooter", "  if (false) {\n    var contactFooter"]],
  // Privacy drops a service Your data names
  "privacy-list-drifts": [["privacy.html", "<li>Twilio: text messages.</li>", ""]],
  // the Terms route made subscription-only
  "terms-route-gated": [["server.js", "app.get(\"/api/me/terms\", requireAuth, async function (req, res) {", "app.get(\"/api/me/terms\", requireAuth, requireActiveSubscription, async function (req, res) {"]],
  // the notice shown to members who already accepted
  "notice-always": [["scripts/bf-legal-footer.js", "if (terms && terms.needs_acceptance === true && terms.current_version) {", "if (terms && terms.current_version) {"]],
  // an unbackable security claim on Privacy
  "claim-bank-level": [["privacy.html", "<p>Exactly as the Your data page states it:</p>", "<p>Exactly as the Your data page states it, with bank-level encryption:</p>"]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the files, read once (and mutated in memory) ───────────────────────── */
const BACKEND_FILES = ["server.js", "lib/legalPages.js", "config/brain.js", "leadRadar.js"];
const SRC = {};
BACKEND_FILES.forEach(f => { SRC[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
const FE_HTML = cp.execFileSync("git", ["ls-files", "*.html"], { cwd: FRONTEND }).toString().trim().split(/\r?\n/);
const LEGAL_PAGES = ["terms.html", "privacy.html", "refund.html", "contact.html"];
LEGAL_PAGES.forEach(f => { if (FE_HTML.indexOf(f) === -1) FE_HTML.push(f); });
const FE = {};
FE_HTML.concat(["_redirects", "scripts/bf-legal-footer.js", "scripts/bf-bfc-notice.js"]).forEach(f => {
  const p = path.join(FRONTEND, f);
  FE[f] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null;
});
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

// lib/legalPages.js as it stands (or mutated), requiring the real lib modules.
function loadModule(rel, src) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(src, file);
  return m.exports;
}
const LP = loadModule("lib/legalPages.js", SRC["lib/legalPages.js"]);
const serverRequire = Module.createRequire(path.join(REPO, "server.js"));

// Visible text of a page: tags out, entities decoded, whitespace collapsed.
const { decodeHTML } = require("entities");
function textOf(html) {
  return decodeHTML(String(html || "").replace(/<style[\s\S]*?<\/style>/g, " ").replace(/<script[\s\S]*?<\/script>/g, " ").replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
}
function listAfter(html, marker) {
  const i = html.indexOf(marker);
  if (i === -1) return null;
  const a = html.indexOf("<ul>", i), b = html.indexOf("</ul>", a);
  if (a === -1 || b === -1) return null;
  return (html.slice(a + 4, b).match(/<li>([\s\S]*?)<\/li>/g) || []).map(li => decodeHTML(li.replace(/<\/?li>/g, "")));
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const fmt = n => Number(n).toLocaleString("en-US");

(async function main() {
  const facts = LP.codeFacts({ server: SRC["server.js"], brain: SRC["config/brain.js"] });
  const built = LP.buildLegalPages(facts);

  /* ── A ─────────────────────────────────────────────────────────────────── */
  section("A. the four pages are what the backend builds from the code");
  LEGAL_PAGES.forEach(f => {
    const have = FE[f], want = built[f];
    let detail = "missing";
    if (have != null) {
      const hl = have.split("\n"), wl = want.split("\n");
      const i = hl.findIndex((l, k) => l !== wl[k]);
      detail = i === -1 ? "lengths " + hl.length + "/" + wl.length : "line " + (i + 1) + ": " + JSON.stringify(hl[i]) + " vs built " + JSON.stringify(wl[i]);
    }
    check("A1. " + f + " is exactly what scripts/buildLegalPages.js builds (run it after any change)", have === want, detail);
    check("A2. " + f + " says \"" + LEGAL.TERMS_UPDATED + "\" and Version " + LEGAL.TERMS_VERSION,
      have != null && textOf(have).indexOf(LEGAL.TERMS_UPDATED + " · Version " + LEGAL.TERMS_VERSION) !== -1);
  });
  {
    const other = Object.assign({}, facts, { price: 249, interval: "year", pastDueGraceDays: 11, welcomeBonus: 1234, certificationCredit: 77, certifications: 9,
      transferMax: 4321, transferDailyCap: 8765, transferHoldDays: 9, youtubeRetentionDays: 21 });
    const b2 = LP.buildLegalPages(other), t2 = textOf(b2["terms.html"]), r2 = textOf(b2["refund.html"]), p2 = textOf(b2["privacy.html"]);
    const expect = [["$249 per year", t2], ["charged $249 at the start of each new year", t2], ["up to 11 days", t2], ["welcome bonus of 1,234 BFC", t2],
      ["77 BFC for each certification", t2], ["there are 9", t2], ["at most 4,321 BFC", t2], ["at most 8,765 BFC in any rolling 24 hours", t2],
      ["until 9 days after", t2], ["$249 per year", r2], ["at most 21 days", p2]];
    const missing = expect.filter(([needle, hay]) => hay.indexOf(needle) === -1).map(([n]) => n);
    const stale = [["$199", t2], ["$199", r2], ["1,000 BFC", t2], ["2,000 BFC", t2], ["100 BFC", t2], ["14 days", t2], ["30 days", p2]]
      .filter(([needle, hay]) => hay.indexOf(needle) !== -1).map(([n]) => n);
    check("A3. built from other figures, the pages state those figures and none of today's (nothing is typed in)", missing.length === 0 && stale.length === 0,
      "missing " + missing.join(" | ") + "; stale " + stale.join(" | "));
  }

  /* ── B ─────────────────────────────────────────────────────────────────── */
  section("B. Netlify routes the pages ahead of the catch-all");
  {
    const rules = (FE["_redirects"] || "").split("\n").map(l => l.trim()).filter(l => l && l[0] !== "#").map(l => l.split(/\s+/));
    const fileExists = p => FE_HTML.indexOf(p.replace(/^\//, "")) !== -1;
    function resolve(p) {
      if (fileExists(p)) return p;   // a file at the path shadows the rules
      for (const [from, to, status] of rules) {
        const re = new RegExp("^" + from.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "(.*)").replace(/:[a-z]+/g, "[^/]+") + "$");
        const m = re.exec(p);
        if (m) return status === "200" ? to.replace(":splat", m[1] || "") : status + " " + to;
      }
      return "404";
    }
    const got = ["/terms", "/privacy", "/refund", "/contact"].map(p => [p, resolve(p)]);
    check("B1. /terms, /privacy, /refund and /contact serve the four pages", same(got.map(g => g[1]), ["/terms.html", "/privacy.html", "/refund.html", "/contact.html"]), JSON.stringify(got));
    check("B2. /terms no longer falls through to the sign-in page", resolve("/terms") !== "/app.html", resolve("/terms"));
    check("B3. the catch-all still catches everything else", resolve("/no-such-page") === "/app.html", resolve("/no-such-page"));
  }

  /* ── C ─────────────────────────────────────────────────────────────────── */
  section("C. one copy of the address and the contact address");
  {
    const NEEDLES = [LEGAL.CONTACT_EMAIL, LEGAL.ADDRESS_LINES[1], LEGAL.ADDRESS_LINES[2]];
    function walk(root, rel, out) {
      fs.readdirSync(path.join(root, rel), { withFileTypes: true }).forEach(d => {
        if (d.name === ".git" || d.name === "node_modules") return;
        const r = rel ? rel + "/" + d.name : d.name;
        if (d.isDirectory()) walk(root, r, out); else if (/\.(js|html|sql|md|json|toml|txt|xml)$|^_redirects$/.test(d.name)) out.push(r);
      });
      return out;
    }
    const backendHits = walk(REPO, "", []).filter(f => {
      const t = Object.prototype.hasOwnProperty.call(SRC, f) ? SRC[f] : fs.readFileSync(path.join(REPO, f), "utf8");
      return NEEDLES.some(n => t.indexOf(n) !== -1);
    });
    check("C1. in the backend, only lib/legal.js holds the postal address or the contact address", same(backendHits, ["lib/legal.js"]), backendHits.join(", "));
    const feHits = walk(FRONTEND, "", []).filter(f => {
      const t = Object.prototype.hasOwnProperty.call(FE, f) && FE[f] != null ? FE[f] : fs.readFileSync(path.join(FRONTEND, f), "utf8");
      return NEEDLES.some(n => t.indexOf(n) !== -1);
    }).sort();
    check("C2. in the frontend, only the four built pages hold them", same(feHits, LEGAL_PAGES.slice().sort()), feHits.join(", "));
    const sv = SRC["server.js"];
    check("C3. server.js no longer reads MAIL_POSTAL_ADDRESS", !/process\.env\.MAIL_POSTAL_ADDRESS/.test(sv));
    const reads = [".contactFooter()", ".marketingFooter(unsubscribeUrl)", ".POSTAL_ADDRESS", ".TERMS_VERSION", ".MINIMUM_AGE"]
      .filter(x => sv.indexOf("require(\"./lib/legal\")" + x) === -1);
    check("C4. sendEmail, sendMarketingEmail, the sender readiness and registration read lib/legal.js", reads.length === 0, "not read: " + reads.join(", "));
  }

  /* ── D ─────────────────────────────────────────────────────────────────── */
  section("D. no personal name");
  {
    const norm = t => String(t).toLowerCase().replace(/[^a-z]/g, "");
    const names = new Set();
    [REPO, FRONTEND].forEach(dir => {
      cp.execFileSync("git", ["log", "--format=%an"], { cwd: dir, maxBuffer: 16 * 1024 * 1024 }).toString().split(/\r?\n/).forEach(n => { if (norm(n).length >= 4) names.add(n.trim()); });
      try { const n = cp.execFileSync("git", ["config", "user.name"], { cwd: dir }).toString().trim(); if (norm(n).length >= 4) names.add(n); } catch (e) { /* none set */ }
    });
    const STAFF = new Set(["claude", "github", "dependabot", "netlify"]);
    const people = [...names].filter(n => !STAFF.has(norm(n)) && !/\[bot\]/.test(n));
    const ff = LEGAL.contactFooter(), mf = LEGAL.marketingFooter("https://bizforceai.net/unsubscribe?token=x");
    const texts = LEGAL_PAGES.map(f => [f, FE[f]]).concat([["lib/legal.js", fs.readFileSync(path.join(REPO, "lib/legal.js"), "utf8")],
      ["email footers", ff.html + ff.text + mf.html + mf.text], ["scripts/bf-legal-footer.js", FE["scripts/bf-legal-footer.js"]]]);
    const found = [];
    texts.forEach(([f, t]) => people.forEach(n => { if (norm(t).indexOf(norm(n)) !== -1) found.push(f); }));
    check("D1. no git author's name appears (" + people.length + " author name(s) tried)", people.length > 0 && found.length === 0, found.join(", "));
    check("D2. the operator is \"" + LEGAL.OPERATOR + "\", a fictitious business name, with no honorific anywhere",
      LEGAL.OPERATOR === "BizForceAI" && texts.every(([, t]) => !/\b(Mr|Mrs|Ms|Dr)\.\s/.test(textOf(t))) && textOf(FE["terms.html"]).indexOf(LEGAL.OPERATOR + " (a fictitious business name") !== -1);
  }

  /* ── E ─────────────────────────────────────────────────────────────────── */
  section("E. every figure equals the code's");
  {
    const sv = SRC["server.js"];
    const plan = /const PLAN_CONFIG = \{\s*all_access: \{\s*name: "([^"]+)",\s*price: (\d+),/.exec(sv) || [];
    const price = Number(plan[2]), planName = plan[1];
    const interval = (/\n\s*"\/(month|year), single \\"" \+ plan\.name/.exec(SRC["config/brain.js"]) || [])[1];
    const grace = Number((/\nconst PAST_DUE_GRACE_DEFAULT_DAYS = (\d+);/.exec(sv) || [])[1]);
    const welcome = Number((/\nconst WELCOME_BONUS_BFC = (\d+);/.exec(sv) || [])[1]);
    const cert = Number((/await creditWallet\(req\.user\.id, (\d+), "Certification earned: " \+ certId\);/.exec(sv) || [])[1]);
    const certCount = require("../lib/certificationCatalog").CERTIFICATIONS.length;
    const L = require("../lib/bfcTransferLimits");
    const ytDays = require("../lib/youtubeRetention").YOUTUBE_RETENTION_DAYS;
    check("E0. the code's figures are found", price > 0 && planName && interval && grace > 0 && welcome > 0 && cert > 0 && certCount > 0 && ytDays > 0,
      JSON.stringify({ price, planName, interval, grace, welcome, cert, certCount, ytDays }));
    const T = textOf(FE["terms.html"]), R = textOf(FE["refund.html"]), P = textOf(FE["privacy.html"]);
    const has = (hay, needle) => hay.indexOf(needle) !== -1;
    check("E1. Terms: \"" + planName + " costs $" + price + " per " + interval + "\", renewing every " + interval + " until cancelled",
      has(T, planName + " costs $" + price + " per " + interval + ". Your subscription renews automatically every " + interval + ", and your card is charged $" + price + " at the start of each new " + interval + ", until you cancel."));
    const dollarsT = (T.match(/\$\d[\d,.]*/g) || []), dollarsR = (R.match(/\$\d[\d,.]*/g) || []);
    check("E2. every dollar amount on the Terms and Refunds is the price", dollarsT.length >= 2 && dollarsR.length >= 1 && dollarsT.concat(dollarsR).every(d => d === "$" + price),
      dollarsT.concat(dollarsR).join(" "));
    const B = textOf(FE["billing.html"]);
    const dollarsB = B.match(/\$\d[\d,.]*/g) || [];
    check("E3. Billing states the price next to Subscribe with automatic renewal, and links Terms and Refunds",
      dollarsB.length >= 2 && dollarsB.every(d => d === "$" + price) && has(B, "All Access is $" + price + " per " + interval + " and renews automatically every " + interval + " until you cancel") &&
      /id="checkoutRenewalNote">[\s\S]*?href="\/terms"[\s\S]*?href="\/refund"[\s\S]*?<\/p>\s*<button class="btn" id="checkoutBtn"/.test(FE["billing.html"]) &&
      /id="renewalNote">[\s\S]*?href="\/terms"[\s\S]*?href="\/refund"/.test(FE["billing.html"]), dollarsB.join(" "));
    check("E4. the past-due grace is the code's " + grace + " days", has(T, "You keep access for up to " + grace + " days from the day the payment was due") && has(T, "after " + grace + " days, access pauses"));
    check("E5. the welcome bonus is the code's " + fmt(welcome) + " BFC, once per account", has(T, "a one-time welcome bonus of " + fmt(welcome) + " BFC when an account's subscription first becomes active (once per account)"));
    check("E6. the certification credit is the code's " + cert + " BFC, and there are " + certCount, has(T, fmt(cert) + " BFC for each certification earned while the account has an active subscription (once per certification; there are " + certCount + ")"));
    check("E7. the transfer limits are lib/bfcTransferLimits.js's: " + fmt(L.BFC_TRANSFER_MAX_DEFAULT) + " per transfer, " + fmt(L.BFC_TRANSFER_DAILY_CAP_DEFAULT) + " a rolling 24 hours, a " + L.BFC_TRANSFER_HOLD_DAYS_DEFAULT + "-day hold",
      has(T, "one transfer can move at most " + fmt(L.BFC_TRANSFER_MAX_DEFAULT) + " BFC") && has(T, "an account can send at most " + fmt(L.BFC_TRANSFER_DAILY_CAP_DEFAULT) + " BFC in any rolling 24 hours") &&
      has(T, "a new account cannot send BFC until " + L.BFC_TRANSFER_HOLD_DAYS_DEFAULT + " days after it was created"));
    const amounts = [...new Set((T.match(/\b[\d,]+ BFC\b/g) || []).map(a => a.replace(/ BFC$/, "")))].sort();
    const allowed = [welcome, cert, L.BFC_TRANSFER_MAX_DEFAULT, L.BFC_TRANSFER_DAILY_CAP_DEFAULT].map(fmt);
    check("E8. no other BFC amount appears in the Terms", amounts.every(a => allowed.indexOf(a) !== -1), amounts.join(", "));
    check("E9. the forfeit on deletion is recorded as lib/yourData.js records it", has(T, "your BFC balance is forfeited and recorded in the ledger as \"" + YD.FORFEIT_DESCRIPTION + "\"") &&
      YD.DATA.some(d => d.table === "user_wallets" && d.onDelete === "forfeit"));
    check("E10. the BizCash agreement says closed-loop, no cash value, not a party, tax, and changes", ["closed-loop, in-app trade credit for member trades on BizForceAI",
      "It cannot be bought, sold, exchanged or withdrawn for money", "is not a party to the goods or services traded", "can count as income for tax purposes",
      "BizForce may change the BFC rules"].every(x => has(T, x)));
    check("E11. Privacy's YouTube retention is lib/youtubeRetention.js's " + ytDays + " days", has(P, "How long: at most " + ytDays + " days."));
    check("E12. the refund policy is lib/legal.js's, on Terms and Refunds", LEGAL.REFUND_POLICY.every(x => has(T, x) && has(R, x)));
  }

  /* ── F ─────────────────────────────────────────────────────────────────── */
  section("F. Privacy says what Your data says");
  {
    const ph = FE["privacy.html"] || "";
    const tp = listAfter(ph, "The services BizForce sends your data to:");
    check("F1. the services BizForce sends data to are lib/yourData.js THIRD_PARTIES, in order", tp && same(tp, YD.THIRD_PARTIES.map(x => x.name + ": " + x.for + ".")), JSON.stringify(tp));
    const ps = listAfter(ph, "The services some pages have your browser fetch files from:");
    check("F2. the services pages load from are lib/yourData.js PAGE_SERVICES, in order", ps && same(ps, YD.PAGE_SERVICES.map(x => x.name + ": " + x.for + ".")), JSON.stringify(ps));
    const noSale = YD.PROTECTIONS.find(x => x.key === "no_sale").text;
    check("F3. Your data's no-sale statement appears word for word, and \"We do not sell your personal information\"",
      ph.indexOf("<p>" + LEGAL.escapeHtml(noSale) + "</p>") !== -1 && textOf(ph).indexOf("We do not sell your personal information") !== -1);
    const prot = listAfter(ph, "Exactly as the Your data page states it");
    check("F4. the protections are Your data's, word for word (encrypted in transit, at rest per the host, encrypted backups, not end-to-end)",
      prot && same(prot, YD.PROTECTIONS.filter(x => x.key !== "no_sale").map(x => x.text)) && ["transit", "at_rest", "backups", "not_e2e"].every(k => YD.PROTECTIONS.some(x => x.key === k)),
      JSON.stringify(prot));
    const groups = YD.describe().groups.filter(g => g.items.length);
    const shown = groups.map(g => {
      const i = ph.indexOf("<p><strong>" + LEGAL.escapeHtml(g.title) + "</strong></p>");
      return i === -1 ? null : listAfter(ph.slice(i), "<strong>");
    });
    check("F5. what is collected is Your data's description, group by group (" + groups.length + " groups)",
      groups.every((g, k) => shown[k] && same(shown[k], g.items.map(it => it.what))));
    check("F6. the opt-in device copy is described in Your data's words", YD.DEVICE_COPY.lines.every(l => textOf(ph).indexOf(l) !== -1));
    // every host a page has the browser load from is named
    const hosts = new Set();
    Object.keys(FE).filter(f => FE[f] && /\.(html|js)$/.test(f)).forEach(f => {
      const t = FE[f];
      [/<script[^>]*\ssrc="https?:\/\/([^/"]+)/g, /<link[^>]*\shref="https?:\/\/([^/"]+)/g, /<img[^>]*\ssrc="https?:\/\/([^/"]+)/g,
        /<iframe[^>]*\ssrc=["']https?:\/\/([^/"']+)/g, /@import\s+url\(["']?https?:\/\/([^/"')]+)/g].forEach(re => {
        let m; while ((m = re.exec(t))) hosts.add(m[1]);
      });
    });
    const named = new Set([].concat.apply([], YD.PAGE_SERVICES.map(x => x.hosts)));
    const unnamed = [...hosts].filter(h => !named.has(h));
    check("F7. every host a frontend page loads from is named in PAGE_SERVICES (" + hosts.size + " hosts)", hosts.size > 0 && unnamed.length === 0, unnamed.join(", "));
    check("F8. the users entry in Your data lists and exports the Terms acceptance", /terms_accepted_at, terms_version/.test(YD.DATA.find(d => d.table === "users").select) &&
      /which version of the Terms you accepted and when/.test(YD.DATA.find(d => d.table === "users").what));
  }

  /* ── G ─────────────────────────────────────────────────────────────────── */
  section("G. YouTube");
  {
    const ph = FE["privacy.html"] || "", P = textOf(ph);
    check("G1. links the YouTube Terms of Service and the Google Privacy Policy",
      ph.indexOf("<a href=\"https://www.youtube.com/t/terms\">YouTube Terms of Service</a>") !== -1 && ph.indexOf("<a href=\"https://policies.google.com/privacy\">Google Privacy Policy</a>") !== -1);
    check("G2. says BizForce uses YouTube API Services, what is accessed and stored, and not combined", ["BizForce uses YouTube API Services",
      "What is accessed: public YouTube videos", "What is stored: those public comments", "not combined with data from any other source"].every(x => P.indexOf(x) !== -1));
    const lr = SRC["leadRadar.js"], sv = SRC["server.js"];
    const scorable = (/const SCORABLE_SOURCES = (\[[^\]]*\]);/.exec(lr) || [])[1] || "";
    check("G3. the code backs \"not combined\": never scored, excluded from demand, its own route",
      scorable && !/youtube/.test(scorable) && /\nvar DEMAND_EXCLUDED_SOURCE = "youtube";/.test(sv) && /app\.get\("\/api\/leads\/youtube-signals"/.test(sv), scorable);
    const yr = fs.readFileSync(path.join(REPO, "youtubeRadar.js"), "utf8");
    check("G4. the code backs \"no member's data is sent\": the searches are a fixed list", /\nconst KEYWORDS = \[/.test(yr) && /var keywords = KEYWORDS;/.test(yr));
  }

  /* ── H ─────────────────────────────────────────────────────────────────── */
  section("H. the footer is on every page, and the updated-Terms notice");
  const { JSDOM } = require("jsdom");
  {
    const pages = FE_HTML.filter(f => !/^google[0-9a-f]+\.html$/.test(f));
    const without = pages.filter(f => !FE[f] || FE[f].split(FOOTER_TAGS.trim()).length !== 2);
    check("H1. every page (" + pages.length + ") has the footer element followed by its script, once", pages.length >= 70 && without.length === 0, without.join(", "));
    const dom = new JSDOM("<!DOCTYPE html><html><head></head><body>" + FOOTER_TAGS.split("\n")[0] + "</body></html>", { url: "https://bizforceai.net/wallet.html", runScripts: "outside-only" });
    dom.window.fetch = () => { throw new Error("no fetch expected"); };
    dom.window.eval(FE["scripts/bf-legal-footer.js"]);
    const links = [...dom.window.document.querySelectorAll("[data-bf-legal-footer] a")].map(a => a.textContent + " " + a.getAttribute("href"));
    check("H2. it draws Terms · Privacy · Refunds · Contact · Your data, to lib/legal.js's paths",
      same(links, ["Terms " + LEGAL.PAGES.terms, "Privacy " + LEGAL.PAGES.privacy, "Refunds " + LEGAL.PAGES.refund, "Contact " + LEGAL.PAGES.contact, "Your data " + LEGAL.PAGES.yourData]), JSON.stringify(links));

    async function notice(answer) {
      const d = new JSDOM("<!DOCTYPE html><html><head></head><body><main id=\"m\">page</main>" + FOOTER_TAGS.split("\n")[0] + "</body></html>", { url: "https://bizforceai.net/dashboard.html", runScripts: "outside-only" });
      const w = d.window, calls = [];
      if (answer.token !== false) w.localStorage.setItem("bf_token", "tok-1");
      w.fetch = (url, init) => {
        calls.push({ url, method: (init && init.method) || "GET", body: init && init.body, auth: init && init.headers && init.headers.Authorization });
        const r = /\/api\/me\/terms\/accept$/.test(url) ? answer.accept : answer.get;
        const p = Promise.resolve({ ok: r.status === 200, status: r.status, json: () => Promise.resolve(r.body) });
        p.catch(() => {});
        return p;
      };
      w.eval(FE["scripts/bf-legal-footer.js"]);
      await new Promise(r => setTimeout(r, 20));
      return { w, doc: w.document, calls };
    }
    const CUR = { current_version: LEGAL.TERMS_VERSION, updated: LEGAL.TERMS_UPDATED };
    let n = await notice({ get: { status: 200, body: Object.assign({ needs_acceptance: true, accepted_version: null }, CUR) }, accept: { status: 200, body: { needs_acceptance: false } } });
    const box = n.doc.getElementById("bfTermsNotice");
    check("H3. a member with older Terms sees \"We've updated our Terms\" with a link to /terms", box && /We've updated our Terms/.test(box.textContent) && box.querySelector("a[href='/terms']") &&
      n.calls.length === 1 && /\/api\/me\/terms$/.test(n.calls[0].url) && n.calls[0].auth === "Bearer tok-1");
    check("H4. the notice blocks nothing: not a dialog, the page stays usable", box && box.getAttribute("role") !== "dialog" && !box.querySelector("form") &&
      n.doc.getElementById("m").textContent === "page" && !n.doc.body.style.overflow && !n.doc.querySelector("[inert]"));
    box && [...box.querySelectorAll("button")].find(b => b.textContent === "Accept").click();
    await new Promise(r => setTimeout(r, 20));
    const post = n.calls[1] || {};
    check("H5. Accept records the current version (POST /api/me/terms/accept), then the notice goes",
      post.method === "POST" && /\/api\/me\/terms\/accept$/.test(post.url) && same(JSON.parse(post.body || "{}"), { version: LEGAL.TERMS_VERSION }) && !n.doc.getElementById("bfTermsNotice"));
    n = await notice({ get: { status: 200, body: Object.assign({ needs_acceptance: false, accepted_version: LEGAL.TERMS_VERSION }, CUR) } });
    check("H6. a member who accepted the current Terms sees no notice", !n.doc.getElementById("bfTermsNotice") && n.calls.length === 1);
    n = await notice({ get: { status: 503, body: { error: "x" } } });
    check("H7. an unreadable record shows no notice", !n.doc.getElementById("bfTermsNotice"));
    n = await notice({ token: false, get: { status: 200, body: Object.assign({ needs_acceptance: true }, CUR) } });
    check("H8. signed out: no request and no notice", n.calls.length === 0 && !n.doc.getElementById("bfTermsNotice"));
    n = await notice({ get: { status: 200, body: Object.assign({ needs_acceptance: true }, CUR) }, accept: { status: 503, body: {} } });
    const b2 = n.doc.getElementById("bfTermsNotice");
    b2 && [...b2.querySelectorAll("button")].find(b => b.textContent === "Accept").click();
    await new Promise(r => setTimeout(r, 20));
    check("H9. a failed accept says so and keeps the notice", n.doc.getElementById("bfTermsNotice") && /could not be recorded/.test(n.doc.getElementById("bfTermsNotice").textContent));
  }

  /* ── I ─────────────────────────────────────────────────────────────────── */
  section("I. sign-up: the box, the refusal, and the record");
  {
    const app = FE["app.html"] || "";
    const field = (/<div class="field terms-field">([\s\S]*?)<\/div>/.exec(app) || [])[1] || "";
    const input = (/<input id="rterms"[^>]*>/.exec(field) || [])[0] || "";
    check("I1. the box is in the sign-up form, a checkbox, unchecked by default", /<form id="registerForm"[\s\S]*<div class="field terms-field">[\s\S]*<button id="registerBtn"/.test(app) &&
      /type="checkbox"/.test(input) && !/\bchecked\b/.test(input), input);
    check("I2. its words are lib/legal.js ACCEPT_LABEL, with Terms and Privacy Policy linked", textOf(field) === LEGAL.ACCEPT_LABEL &&
      /<a href="\/terms"[^>]*>Terms<\/a>/.test(field) && /<a href="\/privacy"[^>]*>Privacy Policy<\/a>/.test(field), textOf(field));

    // the page's own sign-up code, in jsdom
    async function signup(tick) {
      const d = new JSDOM(app, { url: "https://bizforceai.net/app.html", runScripts: "outside-only", pretendToBeVisual: true });
      const w = d.window, calls = [];
      w.fetch = (url, init) => { calls.push({ url, body: init && init.body }); const p = Promise.resolve({ ok: false, status: 400, json: () => Promise.resolve({ error: "stub" }), text: () => Promise.resolve("{}"), headers: { get: () => "application/json" } }); p.catch(() => {}); return p; };
      w.PublicKeyCredential = undefined;
      const errs = [];
      [...d.window.document.querySelectorAll("script:not([src])")].forEach(sc => { try { w.eval(sc.textContent); } catch (e) { errs.push(e.message); } });
      const doc = w.document;
      doc.dispatchEvent(new w.Event("DOMContentLoaded"));   // the page wires its forms on DOMContentLoaded
      doc.getElementById("rb").value = "Check Business";
      doc.getElementById("re").value = "check+bftest@example.invalid";
      doc.getElementById("rp").value = "long-enough-password";
      doc.getElementById("rterms").checked = tick;
      doc.getElementById("registerForm").dispatchEvent(new w.Event("submit", { cancelable: true, bubbles: true }));
      await new Promise(r => setTimeout(r, 30));
      return { calls: calls.filter(c => /\/api\/auth\/register$/.test(c.url)), err: (doc.getElementById("err") || {}).textContent || "", errs };
    }
    const no = await signup(false), yes = await signup(true);
    check("I3. unticked, the page sends nothing and says why", no.calls.length === 0 && /18 or older and agree to the Terms and Privacy Policy/.test(no.err), no.err + " " + no.errs.join("; "));
    check("I4. ticked, the page sends accept_terms: true", yes.calls.length === 1 && JSON.parse(yes.calls[0].body).accept_terms === true, JSON.stringify(yes.calls) + " " + yes.errs.join("; "));

    // the server's register route, lifted
    const sv = SRC["server.js"];
    function fnSrc(name) { const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(sv); return sv.slice(m.index, s.braceMatch(sv, sv.indexOf(") {", m.index) + 2)); }
    function routeSrc(method, route) {
      const sig = "app." + method + "(\"" + route + "\"";
      const a = sv.indexOf(sig);
      if (a === -1) throw new Error("route not found " + route);
      const e = s.braceMatch(sv, sv.indexOf("{", sv.indexOf("function", a)));
      return sv.slice(a, e + 2);
    }
    const HELPERS = ["nowIso", "safeText", "normalizeEmail", "normalizeUrl", "normalizeUsername", "publicUser"].map(fnSrc).join("\n\n");
    function register(opts) {
      const inserts = [], reads = [];
      const db = { from(table) {
        const st = { op: "select", payload: null };
        const q = {
          select() { return q; }, eq() { return q; }, limit() { return q; },
          insert(p) { st.op = "insert"; st.payload = p; inserts.push({ table, payload: p }); return q; },
          maybeSingle: async () => { reads.push(table); return { data: null, error: null }; },
          single: async () => {
            if (table === "users" && st.op === "insert" && opts.missingColumns) return { data: null, error: { code: "PGRST204", message: "Could not find the 'terms_version' column of 'users'" } };
            if (table === "users") return { data: { id: "user-new", email: st.payload.email, role: "user", banned_at: null, created_at: "2026-10-25T00:00:00.000Z", email_verified_at: null }, error: null };
            return { data: Object.assign({}, st.payload), error: null };
          },
          then(r) { return Promise.resolve({ data: null, error: null }).then(r); }
        };
        return q;
      } };
      let handler = null;
      const ctx = { console: { log() {}, warn() {}, error() {} }, authLimiter: 0, require: serverRequire, supabase: db, crypto: require("crypto"),
        bcrypt: { hash: async () => "hashed" }, FRONTEND_URL: "https://bizforceai.net", findOrCreateUserContact: async () => "contact-1",
        sendVerificationEmail: async () => ({ sent: true }), createSession: async () => ({ sessionId: "sid", refreshToken: "rt" }), createToken: () => "jwt",
        app: { post() { handler = arguments[arguments.length - 1]; } } };
      vm.createContext(ctx);
      vm.runInContext(HELPERS + "\n\n" + routeSrc("post", "/api/auth/register"), ctx);
      return { handler, inserts, reads };
    }
    async function call(h, body) {
      const res = { code: 200, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
      let err = null;
      await h({ body, ip: "127.0.0.1", headers: {} }, res, e => { err = e; res.code = 500; });
      return { code: res.code, body: res.body, err };
    }
    const BODY = { email: "check+bftest@example.invalid", password: "long-enough-password", business_name: "Check Business" };
    for (const [label, extra] of [["no box", {}], ["accept_terms \"true\" (a string)", { accept_terms: "true" }], ["accept_terms false", { accept_terms: false }]]) {
      const r = register({});
      const out = await call(r.handler, Object.assign({}, BODY, extra));
      check("I5. the server refuses " + label + " with 400, before anything is read or written", out.code === 400 && out.body && out.body.reason === "terms_not_accepted" &&
        r.inserts.length === 0 && r.reads.length === 0, out.code + " " + JSON.stringify(out.body) + " inserts " + r.inserts.length + " reads " + r.reads.length);
    }
    const ok = register({});
    const before = Date.now();
    const okOut = await call(ok.handler, Object.assign({}, BODY, { accept_terms: true }));
    const userRow = (ok.inserts.find(i => i.table === "users") || {}).payload || {};
    check("I6. ticked, the account is created with terms_version " + LEGAL.TERMS_VERSION + " and the time of acceptance", okOut.code === 201 && userRow.terms_version === LEGAL.TERMS_VERSION &&
      Math.abs(Date.parse(userRow.terms_accepted_at) - before) < 10000, okOut.code + " " + JSON.stringify({ v: userRow.terms_version, at: userRow.terms_accepted_at }) + (okOut.err ? " " + okOut.err.message : ""));
    const miss = register({ missingColumns: true });
    const missOut = await call(miss.handler, Object.assign({}, BODY, { accept_terms: true }));
    check("I7. before migration 146, sign-up answers 503 and creates nothing, never a 500", missOut.code === 503 && missOut.body.reason === "terms_columns_missing" &&
      miss.inserts.filter(i => i.table !== "users").length === 0, missOut.code + " " + JSON.stringify(missOut.body));

    // GET and POST /api/me/terms
    function termsRoutes(row, fail) {
      const handlers = {}, middleware = {}, writes = [];
      const db = { from() {
        const q = { _op: "select", select() { return q; }, eq() { return fail === "write" && q._op === "update" ? Promise.resolve({ error: { message: "down" } }) : (q._op === "update" ? Promise.resolve({ error: null }) : q); },
          update(p) { q._op = "update"; writes.push(p); return q; },
          maybeSingle: async () => fail === "read" ? { data: null, error: { message: "down" } } : { data: row, error: null } };
        return q;
      } };
      const requireAuth = function requireAuth() {}, requireActiveSubscription = function requireActiveSubscription() {};
      const ctx = { console: { log() {}, warn() {}, error() {} }, supabase: db, require: serverRequire, nowIso: () => "2026-10-25T12:00:00.000Z", requireAuth, requireActiveSubscription,
        app: { get(p) { handlers["get " + p] = arguments[arguments.length - 1]; middleware["get " + p] = [].slice.call(arguments, 1, -1); },
               post(p) { handlers["post " + p] = arguments[arguments.length - 1]; middleware["post " + p] = [].slice.call(arguments, 1, -1); } } };
      vm.createContext(ctx);
      vm.runInContext(routeSrc("get", "/api/me/terms") + "\n\n" + routeSrc("post", "/api/me/terms/accept"), ctx);
      const run = async (key, body) => {
        const res = { code: 200, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } };
        await handlers[key]({ user: { id: "u-1" }, body: body || {} }, res);
        return res;
      };
      return { middleware, writes, run, requireAuth };
    }
    let tr = termsRoutes({ terms_version: null, terms_accepted_at: null });
    check("I8. GET and POST /api/me/terms need sign-in and nothing more (never a subscription)",
      ["get /api/me/terms", "post /api/me/terms/accept"].every(k => tr.middleware[k] && tr.middleware[k].length === 1 && tr.middleware[k][0] === tr.requireAuth),
      JSON.stringify(Object.keys(tr.middleware).map(k => [k, (tr.middleware[k] || []).map(f => f.name)])));
    let g = await tr.run("get /api/me/terms");
    check("I9. a member who never accepted needs to accept", g.code === 200 && g.body.needs_acceptance === true && g.body.current_version === LEGAL.TERMS_VERSION);
    tr = termsRoutes({ terms_version: "2026-01-01", terms_accepted_at: "2026-01-01T00:00:00Z" });
    g = await tr.run("get /api/me/terms");
    check("I10. an older version needs to accept; the current one does not", g.body.needs_acceptance === true &&
      (await termsRoutes({ terms_version: LEGAL.TERMS_VERSION }).run("get /api/me/terms")).body.needs_acceptance === false);
    tr = termsRoutes({}, "read");
    g = await tr.run("get /api/me/terms");
    check("I11. an unreadable record answers 503, not a needs-acceptance guess", g.code === 503 && g.body.needs_acceptance === undefined);
    tr = termsRoutes({});
    let a = await tr.run("post /api/me/terms/accept", { version: "2020-01-01" });
    check("I12. accepting anything but the current version is refused and writes nothing", a.code === 400 && tr.writes.length === 0);
    a = await tr.run("post /api/me/terms/accept", { version: LEGAL.TERMS_VERSION });
    check("I13. accepting the current version records it with the time", a.code === 200 && tr.writes.length === 1 && tr.writes[0].terms_version === LEGAL.TERMS_VERSION &&
      tr.writes[0].terms_accepted_at === "2026-10-25T12:00:00.000Z");
    tr = termsRoutes({}, "write");
    a = await tr.run("post /api/me/terms/accept", { version: LEGAL.TERMS_VERSION });
    check("I14. a failed write answers 503", a.code === 503);
    const mig = fs.readFileSync(path.join(REPO, "supabase/migrations/146_users_terms_acceptance.sql"), "utf8");
    const stmts = mig.split("\n").filter(l => !/^\s*--/.test(l)).join("\n");
    check("I15. migration 146 adds users.terms_accepted_at (timestamptz) and terms_version (text), if not there, with no default",
      /ALTER TABLE public\.users ADD COLUMN IF NOT EXISTS terms_accepted_at timestamptz;/.test(stmts) && /ALTER TABLE public\.users ADD COLUMN IF NOT EXISTS terms_version text;/.test(stmts) &&
      !/\bDEFAULT\b/i.test(stmts) && !/\bUPDATE\b/i.test(stmts));
    const latest = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^146_/.test(f));
    check("I16. 146 is its own migration number", same(latest, ["146_users_terms_acceptance.sql"]), latest.join());
  }

  /* ── J ─────────────────────────────────────────────────────────────────── */
  section("J. email footers");
  {
    const sv = SRC["server.js"];
    const templates = [...sv.matchAll(/sendEmail\(\{[\s\S]{0,400}?template:\s*([A-Za-z_."-]+)/g)].map(m => m[1]);
    const constOf = name => (new RegExp("\\nvar " + name + " = \"([^\"]+)\";").exec(sv) || [])[1];
    const named = templates.map(t => /^"/.test(t) ? t.replace(/"/g, "") : (constOf(t) || t)).sort();
    check("J1. the email templates are the three transactional ones and marketing (\"marketing:\" + name)", same(named, ["consent_confirmation", "email_verification", "marketing:", "password_reset"]), named.join(", "));

    function lift(api) {
      const sent = [], tables = { consent_events: [{ contact_id: "c-1", channel: "email", action: "confirmed" }], contacts: [{ id: "c-1", email: "pat+bftest@example.invalid", owner_id: "o-1" }], email_sends: [] };
      const db = { from(table) {
        const q = { filters: [], op: "select", head: false,
          select(c, o) { if (o && o.head) q.head = true; return q; }, eq(k, v) { q.filters.push([k, v]); return q; }, in() { return q; }, ilike() { return q; }, like() { return q; }, gte() { return q; }, lt() { return q; }, lte() { return q; }, neq() { return q; }, not() { return q; }, is() { return q; }, range() { return q; },
          order() { return q; }, limit() { return q; }, insert(p) { q.op = "insert"; q.payload = p; return q; }, update(p) { q.op = "update"; return q; },
          single: () => q.then(r => r), maybeSingle: () => q.then(r => ({ data: r.data && r.data[0] || null, error: null })),
          then(res, rej) {
            let out;
            if (q.op === "insert") out = { data: { id: "send-1" }, error: null };
            else if (q.op === "update") out = { data: null, error: null };
            else {
              const rows = (tables[table] || []).filter(r => q.filters.every(([k, v]) => r[k] === undefined || r[k] === v));
              out = q.head ? { data: null, error: null, count: 0 } : { data: rows, error: null };
            }
            return Promise.resolve(out).then(res, rej);
          } };
        return q;
      } };
      class Resend { constructor() { this.emails = { send: async a => { sent.push(a); return { data: { id: "re_1" }, error: null }; } }; } }
      const ctx = { supabase: db, Resend, require: serverRequire, crypto: require("crypto"), Buffer, URL, Date, JSON, Math, Promise, nowIso: () => "2026-10-25T12:00:00.000Z",
        process: { env: { RESEND_API_KEY: "re_test", JWT_SECRET: "check-secret", RESEND_WEBHOOK_SECRET: "whsec_check", UNSUBSCRIBE_SECRET: "check-unsub" } },
        console: { log() {}, warn() {}, error() {} }, OWNER_ACCOUNT_ID: "o-1", setTimeout };
      vm.createContext(ctx);
      vm.runInContext(s.closureFor(sv, "this.api = { " + api.map(n => n + ": " + n).join(", ") + " };"), ctx);
      return { api: ctx.api, sent, ctx };
    }
    const cf = LEGAL.contactFooter();
    const tx = lift(["sendEmail"]);
    const html = "<!DOCTYPE html><html><body><p>Reset your password</p></body></html>";
    const r1 = await tx.api.sendEmail({ contactId: "c-1", to: "pat+bftest@example.invalid", subject: "Reset", html, text: "Reset your password", template: "password_reset", skipConsentCheck: true });
    const m1 = tx.sent[0] || {};
    check("J2. a transactional email ends with the contact line and postal address, inside the body, in HTML and text",
      r1 && r1.sent === true && m1.html === "<!DOCTYPE html><html><body><p>Reset your password</p>" + cf.html + "</body></html>" && m1.text === "Reset your password" + cf.text &&
      m1.text.indexOf(LEGAL.CONTACT_EMAIL) !== -1 && m1.text.indexOf(LEGAL.POSTAL_ADDRESS) !== -1, JSON.stringify({ r1, html: m1.html && m1.html.slice(-200) }));
    const mk = lift(["sendMarketingEmail", "emailUnsubscribeUrl"]);
    let mr;
    try { mr = await mk.api.sendMarketingEmail({ contactId: "c-1", subject: "News", html: "<p>News</p>", text: "News", template: "news" }); } catch (e) { mr = { error: e.message }; }
    const m2 = mk.sent[0] || {};
    const unsub = mk.api.emailUnsubscribeUrl("c-1");
    const count = (t, n) => String(t || "").split(n).length - 1;
    check("J3. a marketing email carries a working unsubscribe link and the postal address, in HTML and text",
      mr && mr.sent === true && String(m2.html).indexOf("href=\"" + LEGAL.escapeHtml(unsub) + "\"") !== -1 && String(m2.text).indexOf("Unsubscribe: " + unsub) !== -1 &&
      LEGAL.ADDRESS_LINES.every(l => String(m2.html).indexOf(LEGAL.escapeHtml(l)) !== -1 && String(m2.text).indexOf(l) !== -1) &&
      m2.headers && m2.headers["List-Unsubscribe"] === "<" + unsub + ">", JSON.stringify(mr) + " " + String(m2.html).slice(-300));
    check("J4. a marketing email gets one footer, not a second contact line", count(m2.html, LEGAL.CONTACT_EMAIL) === 1 && count(m2.text, LEGAL.CONTACT_EMAIL) === 1,
      count(m2.html, LEGAL.CONTACT_EMAIL) + "/" + count(m2.text, LEGAL.CONTACT_EMAIL));
    check("J5. the unsubscribe link opens the unsubscribe page", /^https:\/\/bizforceai\.net\/unsubscribe\?token=/.test(unsub) &&
      /^\/unsubscribe https:\/\/[^\s]+\/api\/unsubscribe 200$/m.test(FE["_redirects"] || ""), unsub);
  }

  /* ── K ─────────────────────────────────────────────────────────────────── */
  section("K. no claim the code cannot back");
  {
    const UNBACKED = /end-to-end encrypted(?<!Not end-to-end encrypted)|bank-level|military-grade|\bGDPR[- ]compliant|\bHIPAA\b|\bSOC ?2\b|PCI[- ]compliant|we never share|\b100%|\bguaranteed?\b(?! them)|free trial|money-back|\bfully secure\b|unhackable/i;
    LEGAL_PAGES.forEach(f => {
      const t = textOf(FE[f]).replace(/Not end-to-end encrypted/g, "");
      const m = UNBACKED.exec(t);
      check("K1. " + f + " makes no security, compliance or guarantee claim nothing proves", !m, m && t.slice(Math.max(0, m.index - 60), m.index + 60));
      check("K2. " + f + " keeps checkHonestPages' rules (no capability pills, no \"marketplace intelligence\", no \"Run on Dashboard\")",
        !/capability-pill/.test(FE[f]) && !/marketplace intelligence/i.test(FE[f]) && !/Run on Dashboard/.test(FE[f]));
    });
    check("K3. Terms mentions BizCash, so it carries the BizCash notice and its script", FE["terms.html"].indexOf("<p class=\"bfc-notice\" data-bfc-notice></p>\n<script src=\"/scripts/bf-bfc-notice.js\"></script>") !== -1);
  }

  check("no network was touched", NETWORK.length === 0, NETWORK.join(", "));
  console.log("\n" + passes + " passed, " + failures + " failed");
  console.log(failures === 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.log("FAIL  checkLegalPages crashed: " + (e && e.stack || e)); process.exit(1); });
