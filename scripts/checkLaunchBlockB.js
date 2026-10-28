"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkLaunchBlockB — the second launch block of 2026-10-27: items 0, 4, 7, 8,
   10, 12 and 13 of that day's brief.

     node scripts/checkLaunchBlockB.js
     MUTATE=<name> node scripts/checkLaunchBlockB.js
     MUTATE=all    node scripts/checkLaunchBlockB.js
     BIZFORCE_CDN_DIR=<dir> node scripts/checkLaunchBlockB.js

   NOTHING LEAVES THIS PROCESS. server.js and the frontend are read as text;
   the pieces under test run in vm contexts or against fakes. The one socket
   is an express app this script starts on 127.0.0.1 and calls itself. No
   live row is read or written, no email is sent, no CDN is fetched.

   0. TEST SPEND. platformSpendToday, lifted, over a fake model_calls ledger
      dated the 1st holding thousands of dollars of check-account rows (by id)
      and +bftest / @bizforceai.invalid rows (by email): the ceiling's total is
      exactly the real members' and the owner's platform-funded spend, the test
      rows are counted as test_rows, the check account's id is dropped without
      a users read, and a failed users read COUNTS the rows it could not clear.
   4. HONEST SOCIAL CONNECT. agents/content.html has the exact sentence of the
      brief in #connectIntro and no connect control of any kind.
   7. GRACEFUL RESTARTS. lib/gracefulShutdown.js driven with a fake server, fake
      cron tasks, a fake process, fake timers and the real lib/opsAlert.js with
      a fake mailer: SIGTERM and SIGINT stop every job and interval and close
      the server, which exits 0 once in flight requests finish (proved again on
      a real express server with a request in flight) or 1 at the timeout; a
      second signal changes nothing; new requests get 503 RESTARTING; an
      unhandled rejection is alerted once per distinct error and the server
      keeps serving; an uncaught exception is alerted and then shuts down with
      exit 1, even when the alert never answers. server.js routes every cron
      job and interval through it and installs it only as the program.
   8. FRONTEND SECURITY. _headers carries HSTS, nosniff, Referrer-Policy, XFO
      DENY with frame-ancestors 'none', a minimal Permissions-Policy and a
      report-only CSP; every external origin the pages load from is in that
      CSP's directive for it; every CDN script and stylesheet has a pinned
      version, valid SRI and crossorigin (and, with BIZFORCE_CDN_DIR naming a
      folder of the downloaded files, the hash of the real file); server error
      text never reaches innerHTML unescaped.
  10. THE BUSINESS CARD. scripts/bf-card.js, run: the public URL, tel: and
      mailto: links, a vCard with N, FN, ORG, TITLE, TEL, EMAIL, URL and PHOTO
      (embedded or linked), RFC 2426 escaping and folding. Both pages' QR codes
      encode the URL, never a vCard. server.js's slug validation, privacy
      allowlist and GET /api/cards/slug/:slug, lifted and run. Migration 149
      and the /c/:slug rewrite.
  12. SEO. Every public page: a unique title, a description, a canonical and
      OG tags, no noindex, and the static ones in the sitemap. Every other page
      noindex and out of the sitemap. robots.txt allows crawling and names the
      sitemap.
  13. DOCS. README.md names every environment variable the running backend
      reads (scripts/_envReads.js, from the code), every cron schedule, and the
      sections the brief asks for; RUNBOOK.md has every alert key the code can
      raise and the four procedures; the www to apex redirect comes first.

   MUTATE=<name> edits a source IN MEMORY (nothing on disk changes). MUTATE=all
   runs each in its own process (scripts/_shared.js runAllMutations).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const http = require("http");
const crypto = require("crypto");
const { EventEmitter } = require("events");
const { execSync } = require("child_process");
const s = require("./_shared");
const { envReads } = require("./_envReads");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const lf = t => t.replace(/\r\n/g, "\n");
const rq = require("module").createRequire(path.join(REPO, "server.js"));
const express = rq("express");
const readRepo = rel => lf(fs.readFileSync(path.join(REPO, rel), "utf8"));

let SRC = readRepo("server.js");
let SHUT = readRepo("lib/gracefulShutdown.js");
let MIG = readRepo("supabase/migrations/149_card_short_links_and_privacy.sql");
let README = readRepo("README.md");
let RUNBOOK = readRepo("RUNBOOK.md");
let LEADRADAR = readRepo("leadRadar.js");

/* Every frontend page and script, tracked or new, by its path in the repo. */
const FE = {};
execSync("git ls-files -co --exclude-standard", { cwd: FRONTEND, encoding: "utf8", maxBuffer: 64 << 20 })
  .split("\n").map(x => x.trim()).filter(x => /\.(html|js|xml|txt)$/.test(x) || x === "_headers" || x === "_redirects")
  .forEach(rel => { if (fs.existsSync(path.join(FRONTEND, rel))) FE[rel] = lf(fs.readFileSync(path.join(FRONTEND, rel), "utf8")); });

const CARD_VIEW = "card-view.html", CARDS = "digital-cards.html", BF_CARD = "scripts/bf-card.js", CONTENT = "agents/content.html";
const DASH = "dashboard.html", SMS = "agents/sms.html";

const MUTATE = process.env.MUTATE || "";
const EXACT_CONNECT_LINE = "Connecting your social accounts is coming: Bluesky first, then Facebook and Instagram, through each platform's own sign-in. BizForce will never ask for your passwords.";
const MUTATIONS = {
  // #0: test-account rows are counted in the platform's spend
  "test-fixture-counted": [["SRC", "    if (accounts.tests[String(row.user_id || \"\").toLowerCase()]) { testRows++; return; }\n", ""]],
  // #0: a test account known only by its email is counted
  "test-email-ignored": [["SRC", "  read.data.forEach(function (u) { if (isTestAccount(u)) tests[String(u.id)] = true; });", "  read.data.forEach(function (u) { });"]],
  // #0: a failed users read drops every row it could not clear, instead of counting them
  "unread-users-dropped": [["SRC", "    return { tests: tests, unread: unknown.length };", "    unknown.forEach(function (id) { tests[id] = true; });\n    return { tests: tests, unread: unknown.length };"]],
  // #4: a Connect button is back
  "connect-button-restored": [["FE:" + CONTENT, EXACT_CONNECT_LINE + "</p>",
    EXACT_CONNECT_LINE + "</p>\n      <button class=\"connect-btn\" onclick=\"connectPlatform('facebook')\">Connect Facebook</button>"]],
  // #4: the sentence is softened
  "connect-line-changed": [["FE:" + CONTENT, "BizForce will never ask for your passwords.</p>", "BizForce will not ask for your passwords.</p>"]],
  // #7: SIGTERM does not close the server
  "sigterm-not-closing-server": [["SHUT", "  proc.on(\"SIGTERM\", function () { shutdownApi.shutdown(\"SIGTERM\", 0); });", "  proc.on(\"SIGTERM\", function () { });"]],
  // #7: the shutdown never calls server.close
  "shutdown-skips-close": [["SHUT", "      server.close(function (err) {", "      (function (cb) { })(function (err) {"]],
  // #7: cron jobs keep running while draining
  "crons-not-stopped": [["SHUT", "      try { j.task.stop(); }", "      try { }"]],
  // #7: no timeout: a hung request holds the process forever
  "no-shutdown-timeout": [["SHUT", "      finish(1, \"Requests were still in flight after \"", "      if (false) finish(1, \"Requests were still in flight after \""]],
  // #7: new requests are served while draining
  "gate-open-while-draining": [["SHUT", "    if (!state.draining) return next();", "    return next();"]],
  // #7: an unhandled rejection is not alerted
  "rejection-not-alerted": [["SHUT", "    raise(\"process_unhandled_rejection\", ", "    if (false) raise(\"process_unhandled_rejection\", "]],
  // #7: the fingerprint is the time, so every rejection emails again
  "alert-not-deduped": [["SHUT", "        what: what, error: first, fingerprint: first,", "        what: what, error: first, fingerprint: first + \" \" + Math.random(),"]],
  // #7: an uncaught exception leaves the process running
  "uncaught-keeps-running": [["SHUT", "function go() { if (started) return; started = true; shutdownApi.shutdown(\"uncaughtException\", 1); }",
    "function go() { if (started) return; started = true; }"]],
  // #7: server.js does not hand the server to the shutdown
  "server-not-registered": [["SRC", "shutdownControl.setServer(app.listen(PORT, function () {", "(app.listen(PORT, function () {"]],
  // #7: server.js's cron wrapper bypasses the shutdown
  "cron-wrapper-bypassed": [["SRC", "    return shutdownControl.trackJob(expression, nodeCron.schedule(expression, fn, options));", "    return nodeCron.schedule(expression, fn, options);"]],
  // #7: an interval is started without being registered
  "interval-untracked": [["SRC", "  shutdownControl.trackInterval(\"reminderTick\", setInterval(reminderTick, 60000));", "  setInterval(reminderTick, 60000);"]],
  // #7: the radar's interval is not registered
  "radar-interval-untracked": [["LEADRADAR", "  if (typeof track === \"function\") track(\"leadRadarTick\", handle);\n", ""]],
  // #7: the handlers are installed when a check loads server.js
  "handlers-installed-when-loaded": [["SRC", "if (require.main === module) {\n  installProcessHandlers(", "if (true) {\n  installProcessHandlers("]],
  // #8: a CDN tag without SRI
  "cdn-tag-without-sri": [["FE:" + CARD_VIEW, " integrity=\"sha384-0RsG1yo/crf/1Qc14sho26SXXOTngNCjgJw7fuvXBt9W/OChF/Ijx+aUuBDqQwEk\"", ""]],
  // #8: a CDN tag without crossorigin
  "cdn-tag-without-crossorigin": [["FE:" + CARDS, "integrity=\"sha384-JcnsjUPPylna1s1fvi1u12X5qjY5OL56iySh75FdtrwhO/SWXgMjoVqcKyIIWOLk\" crossorigin=\"anonymous\"",
    "integrity=\"sha384-JcnsjUPPylna1s1fvi1u12X5qjY5OL56iySh75FdtrwhO/SWXgMjoVqcKyIIWOLk\""]],
  // #8: an SRI hash with one character changed
  "cdn-sri-wrong-hash": [["FE:analytics-dashboard.html", "sha384-9nhczxUqK87bcKHh20fSQcTGD4qq5GhayNYSYWqwBkINBhOfQLg/P5HG5lF1urn4", "sha384-9nhczxUqK87bcKHh20fSQcTGD4qq5GhayNYSYWqwBkINBhOfQLg/P5HG5lF1urn5"]],
  // #8: a CDN version that floats
  "cdn-version-floating": [["FE:agents/sales.html", "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js", "https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"]],
  // #8: an origin the pages load from is missing from the CSP
  "csp-origin-missing": [["FE:_headers", " https://cdnjs.cloudflare.com;", ";"]],
  // #8: HSTS dropped
  "hsts-dropped": [["FE:_headers", "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n", ""]],
  // #8: framing allowed again
  "xfo-dropped": [["FE:_headers", "  X-Frame-Options: DENY\n", ""]],
  // #8: the camera allowed for any origin
  "permissions-camera-open": [["FE:_headers", "camera=(), ", "camera=*, "]],
  // #8: a server error written as HTML
  "server-error-as-html": [["FE:" + DASH, "statusEl.textContent = err.message || \"Task failed.\";", "statusEl.innerHTML = err.message || \"Task failed.\";"]],
  // #8: an SMS body put into HTML unescaped
  "sms-body-unescaped": [["FE:" + SMS, "smsEsc(m.message_body)", "m.message_body"]],
  // #8: the content error helper parses HTML
  "content-error-as-html": [["FE:" + CONTENT, "      span.textContent = text;", "      span.innerHTML = text;"]],
  // #10: the QR holds a vCard
  "qr-holds-vcard": [["FE:" + CARD_VIEW, "QRCode.toCanvas(document.getElementById(\"qrCanvas\"), cardUrl, {",
    "QRCode.toCanvas(document.getElementById(\"qrCanvas\"), window.bfCard.buildVCard(c, null), {"]],
  // #10: the editor's QR holds a vCard
  "editor-qr-holds-vcard": [["FE:" + CARDS, "      QRCode.toCanvas(qr, url, {", "      QRCode.toCanvas(qr, buildVCard(collectFormData()), {"]],
  // #10: the vCard without PHOTO
  "vcard-missing-photo": [["FE:" + BF_CARD, "    if (photo && photo.base64 && photo.type) lines.push(\"PHOTO;ENCODING=b;TYPE=\" + photo.type + \":\" + photo.base64);\n    else if (photo && photo.url) lines.push(\"PHOTO;VALUE=uri:\" + photo.url);\n", ""]],
  // #10: the vCard without TITLE
  "vcard-missing-title": [["FE:" + BF_CARD, "    if (c.job_title) lines.push(\"TITLE:\" + esc(c.job_title));\n", ""]],
  // #10: vCard text not escaped
  "vcard-unescaped": [["FE:" + BF_CARD, ".replace(/,/g, \"\\\\,\").replace(/;/g, \"\\\\;\");", ";"]],
  // #10: long lines not folded
  "vcard-unfolded": [["FE:" + BF_CARD, "    return lines.map(fold).join(\"\\r\\n\") + \"\\r\\n\";", "    return lines.join(\"\\r\\n\") + \"\\r\\n\";"]],
  // #10: no tel: link
  "no-tel-link": [["FE:" + CARD_VIEW, "  setContactLink(\"pPhone\", c.phone, window.bfCard.telHref(c.phone));", "  setContactLink(\"pPhone\", c.phone, null);"]],
  // #10: the save-contact vCard leaves the photo out
  "save-contact-no-photo": [["FE:" + CARD_VIEW, "  var blob = new Blob([window.bfCard.buildVCard(cardData, photo)], { type: \"text/vcard\" });",
    "  var blob = new Blob([window.bfCard.buildVCard(cardData, null)], { type: \"text/vcard\" });"]],
  // #10: a hidden email is served to strangers
  "hidden-email-served": [["SRC", "    email: row.show_email === false ? \"\" : (row.email || \"\"),", "    email: row.email || \"\","]],
  // #10: a hidden photo is served
  "hidden-photo-served": [["SRC", "  if (!row || row.show_photo === false) return null;", "  if (!row) return null;"]],
  // #10: the public card carries the owner's id
  "card-leaks-user-id": [["SRC", "    public_url: cardPublicUrl(row),", "    public_url: cardPublicUrl(row), user_id: row.user_id,"]],
  // #10: any slug accepted
  "slug-unvalidated": [["SRC", "  if (!CARD_SLUG_RE.test(s) || s.indexOf(\"--\") !== -1) {", "  if (false) {"]],
  // #10: reserved slugs accepted
  "slug-reserved-accepted": [["SRC", "  if (CARD_SLUG_RESERVED.indexOf(s) !== -1) return { error: \"That short link is reserved. Choose another.\" };\n", ""]],
  // #10: slugs not unique in the database
  "slug-not-unique": [["MIG", "CREATE UNIQUE INDEX IF NOT EXISTS digital_cards_slug_unique", "CREATE INDEX IF NOT EXISTS digital_cards_slug_unique"]],
  // #10: the short link route served to a lapsed owner
  "slug-route-ungated": [["SRC", "    if (!data) return res.status(404).json({ error: \"Card not found\" });\n    if (!(await ownerPagePublic(data.user_id))) return res.status(404).json({ error: \"Card not found\" });\n\n    return res.json({ card: publicCardFrom(data, await cardOwnerPhoto(data)) });\n  } catch (error) { next(error); }\n});\n\n// ════════",
    "    if (!data) return res.status(404).json({ error: \"Card not found\" });\n\n    return res.json({ card: publicCardFrom(data, await cardOwnerPhoto(data)) });\n  } catch (error) { next(error); }\n});\n\n// ════════"]],
  // #10: Netlify does not serve /c/<slug>
  "short-link-unrouted": [["FE:_redirects", "/c/:slug /card-view.html 200\n", ""]],
  // #12: a public page without a canonical
  "public-page-without-canonical": [["FE:terms.html", "<link rel=\"canonical\" href=\"https://bizforceai.net/terms\">", ""]],
  // #12: a public page without a description
  "public-page-without-description": [["FE:vitality.html", "<meta name=\"description\"", "<meta name=\"x-description\""]],
  // #12: a public page without og:title
  "public-page-without-og": [["FE:index.html", "<meta property=\"og:title\"", "<meta property=\"x-og-title\""]],
  // #12: two public pages with one title
  "duplicate-title": [["FE:refund.html", "<title>Refund Policy — cancel BizForce AI online, keep paid access</title>", "<title>Terms of Service — BizForce AI subscription and BizCash</title>"]],
  // #12: an app page without noindex
  "app-page-without-noindex": [["FE:" + DASH, "<meta name=\"robots\" content=\"noindex\"/>\n", ""]],
  // #12: a public page marked noindex
  "public-page-noindex": [["FE:contact.html", "<meta name=\"description\"", "<meta name=\"robots\" content=\"noindex\">\n<meta name=\"description\""]],
  // #12: a public page left out of the sitemap
  "page-missing-from-sitemap": [["FE:sitemap-pages.xml", "<loc>https://bizforceai.net/privacy</loc>", "<loc>https://bizforceai.net/privacy-old</loc>"]],
  // #12: robots.txt blocks everything
  "robots-disallow-all": [["FE:robots.txt", "Allow: /", "Disallow: /"]],
  // #13: an env var missing from the README
  "env-var-missing-from-readme": [["README", /SHUTDOWN_TIMEOUT_MS/g, "SHUTDOWN_TIMEOUT"]],
  // #13: a cron schedule missing from the README
  "cron-missing-from-readme": [["README", "cron `15 4 * * *`, UTC", "cron nightly, UTC"]],
  // #13: an alert key missing from the runbook
  "alert-missing-from-runbook": [["RUNBOOK", /process_uncaught_exception/g, "process_crash"]],
  // #13: the runbook loses its payment section
  "runbook-no-payment-section": [["RUNBOOK", "## When a payment fails", "## Payments"]],
  // #13: the www redirect is gone
  "www-redirect-missing": [["FE:_redirects", "https://www.bizforceai.net/* https://bizforceai.net/:splat 301!\n", ""]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
if (MUTATE) {
  const apply = (text, from, to) => from instanceof RegExp ? s.requireChanged(text, text.replace(from, to), MUTATE) : s.replaceOnce(text, from, to, MUTATE);
  for (const [which, from, to] of MUTATIONS[MUTATE]) {
    if (which === "SRC") SRC = apply(SRC, from, to);
    else if (which === "SHUT") SHUT = apply(SHUT, from, to);
    else if (which === "MIG") MIG = apply(MIG, from, to);
    else if (which === "README") README = apply(README, from, to);
    else if (which === "RUNBOOK") RUNBOOK = apply(RUNBOOK, from, to);
    else if (which === "LEADRADAR") LEADRADAR = apply(LEADRADAR, from, to);
    else if (which.indexOf("FE:") === 0) FE[which.slice(3)] = apply(FE[which.slice(3)], from, to);
    else throw new Error("unknown source " + which);
  }
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}
const flush = async (n) => { for (let i = 0; i < (n || 10); i++) await new Promise(r => setImmediate(r)); };

/* ── lifting from server.js, by name ──────────────────────────────────────── */
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
function definitionOf(name) {
  let m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (m) return SRC.slice(m.index, s.braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
  const re = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
  while ((m = re.exec(SRC)) && SPANS.some(([x, y]) => m.index > x && m.index < y)) { /* a local */ }
  if (!m) return null;
  const brk = /;\n/g; brk.lastIndex = m.index + m[0].length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(m.index, b.index + 1);
  }
  return null;
}
const uncommented = code => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root, stubs) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || stubs.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !stubs.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
const BASE_STUBS = ["supabase", "console", "process", "require", "module", "app", "Buffer", "URL", "setTimeout", "setImmediate", "fetch",
  "requireAuth", "Date", "Math", "JSON", "Object", "Number", "String", "Array", "Promise", "Error", "isTestAccount", "OWNER_ACCOUNT_ID",
  "ownerPagePublic"];
const quiet = { log() {}, warn() {}, error() {} };

/* A fake Supabase over in-memory tables: select/eq/in/order/range, awaited or
   maybeSingle, with the exact count. fail[table] makes that table's reads fail. */
function fakeDb(tables, fail) {
  const reads = [];
  return {
    reads,
    client: {
      from(table) {
        const q = { table, eqs: [], ins: null, range: null };
        function run() {
          reads.push(q);
          if (fail && fail[table]) return { data: null, count: null, error: { message: table + " is down" } };
          let rows = (tables[table] || []).filter(r => q.eqs.every(([c, v]) => r[c] === v));
          if (q.ins) rows = rows.filter(r => q.ins[1].indexOf(String(r[q.ins[0]])) !== -1);
          const count = rows.length;
          rows = rows.slice().sort((a, b) => (a.id > b.id ? 1 : a.id < b.id ? -1 : 0));
          if (q.range) rows = rows.slice(q.range[0], q.range[1] + 1);
          return { data: rows.map(r => Object.assign({}, r)), count, error: null };
        }
        const chain = {
          select() { return chain; }, order() { return chain; },
          eq(c, v) { q.eqs.push([c, v]); return chain; },
          in(c, ids) { q.ins = [c, ids]; return chain; },
          range(a, b) { q.range = [a, b]; return chain; },
          maybeSingle: async () => { const r = run(); return r.error ? r : { data: r.data[0] || null, error: null }; },
          then(res, rej) { return Promise.resolve(run()).then(res, rej); }
        };
        return chain;
      }
    }
  };
}

(async function main() {
  const OWNER_ID = rq("./lib/ownerAccount").OWNER_ACCOUNT_ID;
  const { isTestAccount } = rq("./lib/testAccounts");

  /* ── 0. test spend ──────────────────────────────────────────────────────── */
  console.log("\n══ 0. test accounts' model calls never count toward the platform's daily ceiling ══");
  {
    const CHECK_ID = "53e6b330-d31c-4958-a10b-516397e7b9c9";
    const BFTEST = "aaaaaaaa-0000-4000-8000-000000000001", INVALID = "aaaaaaaa-0000-4000-8000-000000000002";
    const MEMBER = "bbbbbbbb-0000-4000-8000-000000000003";
    function lift(db) {
      const ctx = { supabase: db.client, process: { env: {} }, console: quiet, isTestAccount, OWNER_ACCOUNT_ID: OWNER_ID };
      vm.createContext(ctx);
      vm.runInContext(closure("this.__api = { platformSpendToday, modelCallCostUsd, modelCallUtcDay, MODEL_PRICES_USD_PER_MILLION };", new Set(BASE_STUBS)), ctx);
      ctx.__api.at = iso => vm.runInContext("new Date(" + JSON.stringify(iso) + ")", ctx);
      return ctx.__api;
    }
    const probe = lift(fakeDb({}));
    const model = Object.keys(probe.MODEL_PRICES_USD_PER_MILLION)[0];
    const DAY = "2026-11-01";
    const rows = [];
    let n = 0;
    const add = (user_id, count, funded_by, tokens, day) => {
      for (let i = 0; i < count; i++) {
        rows.push({ id: String(++n).padStart(6, "0"), user_id, model, input_tokens: tokens, output_tokens: tokens, funded_by, created_on: day || DAY });
      }
    };
    add(CHECK_ID, 1200, "platform", 1000000);       // the check account, by id: thousands of dollars on the 1st
    add(CHECK_ID, 7, "user", 1000000);              // and some it paid for itself
    add(BFTEST, 50, "platform", 1000000);           // a +bftest address, by email
    add(INVALID, 30, "platform", 1000000);          // an @bizforceai.invalid address, by email
    add(MEMBER, 20, "platform", 10000);             // a real member: counted
    add(MEMBER, 5, "user", 1000000);                // their own key: not the platform's spend
    add(OWNER_ID, 10, "platform", 10000);           // the owner: real spend, counted
    add(MEMBER, 40, "platform", 1000000, "2026-10-31");   // another day
    const users = [
      { id: CHECK_ID, email: "subject@example.com" },   // a plain address: only the id says it is the check account
      { id: BFTEST, email: "someone+bftest7@example.com" },
      { id: INVALID, email: "fixture@bizforceai.invalid" },
      { id: MEMBER, email: "member@example.com" },
      { id: OWNER_ID, email: "owner@example.com" }
    ];
    const costOf = r => probe.modelCallCostUsd(r).usd;
    const today = rows.filter(r => r.created_on === DAY);
    const expectUsd = today.filter(r => (r.user_id === MEMBER || r.user_id === OWNER_ID) && r.funded_by !== "user").reduce((a, r) => a + costOf(r), 0);
    const everything = today.filter(r => r.funded_by !== "user").reduce((a, r) => a + costOf(r), 0);
    const near = (a, b) => Math.abs(a - b) < 1e-9;

    const db = fakeDb({ model_calls: rows, users });
    const api = lift(db);
    const noon = api.at(DAY + "T12:00:00Z");
    check("0. the fixture day is the 1st of a month", api.modelCallUtcDay(noon) === DAY, api.modelCallUtcDay(noon));
    const got = await api.platformSpendToday(noon);
    console.log("    the 1st: every row would be $" + everything.toFixed(2) + "; members and owner $" + expectUsd.toFixed(6) + "; read $" + (got.usd || 0).toFixed(6) +
      " over " + got.rows + " rows, " + got.test_rows + " of them test rows");
    check("0. the test fixtures alone would trip a $25 ceiling many times over (so leaving them out is what matters)", everything > 1000, everything);
    check("0. the platform's spend for the 1st is exactly the real member's and the owner's platform-funded calls", !got.error && near(got.usd, expectUsd), JSON.stringify(got));
    check("0. every row of the day is read, across pages of 1000 (" + today.length + ")", got.rows === today.length, got.rows);
    check("0. the check account (by id, even its own-key rows) and the +bftest and @bizforceai.invalid accounts (by email) are the test rows",
      got.test_rows === 1200 + 7 + 50 + 30, got.test_rows);
    const userReads = db.reads.filter(q => q.table === "users");
    check("0. one users read, and the check account's id is not in it (a test id is known without a read)",
      userReads.length === 1 && userReads[0].ins && userReads[0].ins[1].indexOf(CHECK_ID) === -1 && userReads[0].ins[1].indexOf(BFTEST) !== -1,
      JSON.stringify(userReads.map(q => q.ins)));
    check("0. the owner's calls count (the owner is not a test account)", !isTestAccount({ id: OWNER_ID, email: "owner@example.com" }));

    const db2 = fakeDb({ model_calls: rows, users }, { users: true });
    const api2 = lift(db2);
    const got2 = await api2.platformSpendToday(api2.at(DAY + "T12:00:00Z"));
    const expect2 = expectUsd + today.filter(r => (r.user_id === BFTEST || r.user_id === INVALID)).reduce((a, r) => a + costOf(r), 0);
    check("0. when the users read fails, the accounts it could not clear are COUNTED (the ceiling errs toward stopping); the check account still is not",
      !got2.error && near(got2.usd, expect2) && got2.test_rows === 1207, JSON.stringify(got2));
    check("0. platformSpendToday counts test rows before the funded_by skip, so test_rows is every test row",
      /if \(accounts\.tests\[String\(row\.user_id \|\| ""\)\.toLowerCase\(\)\]\) \{ testRows\+\+; return; \}\n    if \(row\.funded_by === "user"\) return;/.test(SRC));
  }

  /* ── 4. honest social connect ───────────────────────────────────────────── */
  console.log("\n══ 4. the Content Agent offers no social connect control, and says exactly what is coming ══");
  {
    const page = FE[CONTENT];
    const code = page.replace(/<!--[\s\S]*?-->/g, " ");
    const intro = /<p id="connectIntro"[^>]*>([\s\S]*?)<\/p>/.exec(page);
    check("4. #connectIntro is exactly the brief's sentence", !!intro && intro[1] === EXACT_CONNECT_LINE, intro && intro[1]);
    const section = /<section[^>]*>\s*<h2 class="section-label">Social Accounts<\/h2>[\s\S]*?<\/section>/.exec(page);
    check("4. the Social Accounts section holds the heading and that sentence and nothing else",
      !!section && section[0].replace(/<section[^>]*>|<\/section>|<h2[^>]*>Social Accounts<\/h2>|<p id="connectIntro"[^>]*>[\s\S]*?<\/p>/g, "").trim() === "",
      section && section[0].slice(0, 200));
    const bad = [
      [/<button[^>]*>[^<]*\bConnect\b/i, "a Connect button"], [/connect-btn|connect-card|connect-grid/, "the connect controls' classes"],
      [/connectPlatform|connectAccount|disconnect/i, "a connect handler"],
      // /api/social-drafts (saving approved drafts) is not a connection
      [/\/api\/social\/|\/api\/social-(connect|accounts|auth)|oauth/i, "an OAuth or social connect endpoint"],
      [/type="password"/i, "a password field"], [/Create Account/i, "the Create Account modal"]
    ];
    bad.forEach(([re, what]) => check("4. content.html has no " + what, !re.test(code), (code.match(re) || [""])[0]));
    const brands = ["Facebook", "Instagram", "Bluesky", "LinkedIn", "TikTok", "Twitter", "YouTube", "Pinterest", "Threads"];
    const connectWords = brands.filter(b => new RegExp("Connect\\s+(your\\s+)?" + b, "i").test(code));
    check("4. no \"Connect <platform>\" anywhere on the page", connectWords.length === 0, connectWords.join(","));
  }

  /* ── 7. graceful restarts and crash alerts ──────────────────────────────── */
  console.log("\n══ 7. SIGTERM and SIGINT drain and exit; crashes are alerted, once per error ══");
  {
    const mod = { exports: {} };
    new Function("module", "exports", "require", SHUT)(mod, mod.exports, require);
    const G = mod.exports;

    check("7. SHUTDOWN_TIMEOUT_MS: default 10000, whole numbers 1000 to 120000, anything else the default",
      G.shutdownTimeoutMs({}) === 10000 && G.shutdownTimeoutMs({ SHUTDOWN_TIMEOUT_MS: "25000" }) === 25000 &&
      G.shutdownTimeoutMs({ SHUTDOWN_TIMEOUT_MS: "999" }) === 10000 && G.shutdownTimeoutMs({ SHUTDOWN_TIMEOUT_MS: "120001" }) === 10000 &&
      G.shutdownTimeoutMs({ SHUTDOWN_TIMEOUT_MS: "1.5e3" }) === 1500 && G.shutdownTimeoutMs({ SHUTDOWN_TIMEOUT_MS: "abc" }) === 10000 &&
      G.shutdownTimeoutMs({ SHUTDOWN_TIMEOUT_MS: "1500.5" }) === 10000);

    function rig(opts) {
      const o = opts || {};
      const exits = [], timers = [], cleared = [];
      const server = { closed: 0, idle: 0, all: 0, connectionCount: 2, cb: null,
        close(cb) { this.closed++; this.cb = cb; }, closeIdleConnections() { this.idle++; }, closeAllConnections() { this.all++; } };
      const api = G.createShutdown({ timeoutMs: 5000, log: quiet, exit: c => exits.push(c),
        setTimer: (fn, ms) => { const t = { fn, ms }; timers.push(t); return t; }, clearTimer: t => cleared.push(t) });
      const jobs = [1, 2, 3].map(i => ({ name: "job" + i, stopped: 0, stop() { this.stopped++; } }));
      jobs.forEach(j => api.trackJob(j.name, j));
      const ivs = [setInterval(() => {}, 1e9), setInterval(() => {}, 1e9)];
      ivs.forEach((h, i) => api.trackInterval("iv" + i, h));
      if (!o.noServer) api.setServer(server);
      const proc = new EventEmitter();
      const alerts = [];
      let alertImpl = o.alert || ((k, i) => { alerts.push([k, i]); return Promise.resolve({ sent: true }); });
      const handlerTimers = [];
      G.installProcessHandlers(proc, api, (k, i) => alertImpl(k, i), { log: quiet, setTimer: (fn, ms) => { const t = { fn, ms }; handlerTimers.push(t); return t; } });
      return { api, server, jobs, ivs, proc, exits, timers, cleared, alerts, handlerTimers };
    }

    for (const sig of ["SIGTERM", "SIGINT"]) {
      const r = rig();
      check("7. " + sig + ": not draining before the signal", r.api.draining() === false);
      r.proc.emit(sig);
      check("7. " + sig + ": draining at once", r.api.draining() === true);
      check("7. " + sig + ": every cron job stopped", r.jobs.every(j => j.stopped === 1), JSON.stringify(r.jobs.map(j => j.stopped)));
      check("7. " + sig + ": every interval cleared", r.ivs.every(h => h._destroyed === true));
      check("7. " + sig + ": server.close called and idle keep-alive sockets closed", r.server.closed === 1 && r.server.idle === 1, JSON.stringify([r.server.closed, r.server.idle]));
      check("7. " + sig + ": no exit while requests are in flight", r.exits.length === 0, JSON.stringify(r.exits));
      check("7. " + sig + ": a timeout is armed for the configured time", r.timers.length === 1 && r.timers[0].ms === 5000);
      r.proc.emit(sig === "SIGTERM" ? "SIGINT" : "SIGTERM");
      check("7. " + sig + ": a second signal changes nothing (one close, one timer)", r.server.closed === 1 && r.timers.length === 1 && r.exits.length === 0);
      if (r.server.cb) r.server.cb();
      check("7. " + sig + ": once the last request finishes, exit 0 and the timeout is cancelled", JSON.stringify(r.exits) === "[0]" && r.cleared.indexOf(r.timers[0]) !== -1,
        JSON.stringify(r.exits));
      r.ivs.forEach(h => clearInterval(h));
    }
    {
      const r = rig();
      r.proc.emit("SIGTERM");
      if (r.timers[0]) r.timers[0].fn();
      check("7. a request still in flight at the timeout: its connections are closed and the process exits 1",
        r.server.all === 1 && JSON.stringify(r.exits) === "[1]", JSON.stringify([r.server.all, r.exits]));
      if (r.server.cb) r.server.cb();
      check("7. a close that lands after the timeout does not exit twice", r.exits.length === 1, JSON.stringify(r.exits));
      r.ivs.forEach(h => clearInterval(h));
    }
    {
      const r = rig();
      const res = () => ({ code: 200, headers: {}, body: null, setHeader(k, v) { this.headers[k] = v; }, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } });
      let nexted = 0;
      const before = res(); r.api.gate({}, before, () => nexted++);
      r.proc.emit("SIGTERM");
      const during = res(); r.api.gate({}, during, () => nexted++);
      check("7. before the signal a request goes through; while draining it is a 503 RESTARTING with Connection: close and Retry-After",
        nexted === 1 && during.code === 503 && during.body && during.body.code === "RESTARTING" && during.headers.Connection === "close" && during.headers["Retry-After"] === "5",
        JSON.stringify([nexted, during.code, during.body, during.headers]));
      r.ivs.forEach(h => clearInterval(h));
    }

    // A real express server, a request in flight, SIGTERM in the middle of it.
    {
      const exits = [];
      const api = G.createShutdown({ timeoutMs: 5000, log: quiet, exit: c => exits.push(c) });
      const app = express();
      app.use(api.gate);
      let release;
      const held = new Promise(r => { release = r; });
      app.get("/slow", async (req, res) => { await held; res.json({ done: true }); });
      app.get("/fast", (req, res) => res.json({ fast: true }));
      const server = await new Promise(r => { const sv = app.listen(0, "127.0.0.1", () => r(sv)); });
      api.setServer(server);
      const port = server.address().port;
      const inFlight = new Promise((resolve, reject) => {
        http.get({ host: "127.0.0.1", port, path: "/slow", agent: false }, res => {
          let b = ""; res.on("data", d => { b += d; }); res.on("end", () => resolve({ status: res.statusCode, body: b }));
        }).on("error", reject);
      });
      await new Promise(r => setTimeout(r, 100));
      const proc = new EventEmitter();
      G.installProcessHandlers(proc, api, () => Promise.resolve(), { log: quiet });
      proc.emit("SIGTERM");
      await new Promise(r => setTimeout(r, 100));
      const exitedEarly = exits.length;
      const refused = await new Promise(resolve => {
        const rqst = http.get({ host: "127.0.0.1", port, path: "/fast", agent: false }, res => { res.resume(); resolve("answered " + res.statusCode); });
        rqst.on("error", e => resolve(e.code));
        rqst.setTimeout(3000, () => { rqst.destroy(); resolve("no answer in 3 s"); });
      });
      release();
      const done = await inFlight;
      await new Promise(r => setTimeout(r, 100));
      check("7. a real server: the request in flight at SIGTERM finishes with its answer", done.status === 200 && /"done":true/.test(done.body), JSON.stringify(done));
      check("7. a real server: no exit until it had", exitedEarly === 0, exitedEarly);
      check("7. a real server: a new connection after SIGTERM is not served", refused !== "answered 200", refused);
      check("7. a real server: then exit 0", JSON.stringify(exits) === "[0]", JSON.stringify(exits));
      try { server.close(); } catch (e) { /* already closed */ }
    }

    // Crashes, through the real lib/opsAlert.js with a fake mailer and table.
    {
      const sent = [];
      const ops = rq("./lib/opsAlert").createOpsAlerts({
        supabase: fakeDb({ ops_alerts: [] }).client,
        env: { OPS_ALERT_EMAIL: "ops@example.invalid" }, log: quiet, now: () => Date.parse("2026-11-01T12:00:00Z"),
        send: async (msg) => { sent.push(msg); return { ok: true }; }
      });
      const persisting = fakeDb({ ops_alerts: [] }).client;
      persisting.from = (function (orig) { return function (t) { const c = orig.call(this, t); c.upsert = async () => ({ error: null }); c.delete = () => c; return c; }; })(persisting.from);
      const r = rig({ alert: (k, i) => ops.raise(k, i) });
      const mk = msg => new Error(msg);
      r.proc.emit("unhandledRejection", mk("ledger write failed"));
      await flush(30);
      r.proc.emit("unhandledRejection", mk("ledger write failed"));
      await flush(30);
      const afterSame = sent.length;
      r.proc.emit("unhandledRejection", mk("a different failure"));
      await flush(30);
      check("7. an unhandled rejection sends one alert email (process_unhandled_rejection)", afterSame >= 1 && /UNHANDLED|unhandled|rejected/i.test(JSON.stringify(sent[0])), afterSame);
      check("7. the same rejection again is deduped: still one email", afterSame === 1, afterSame);
      check("7. a different rejection is a new email", sent.length === 2, sent.length);
      check("7. after rejections the server keeps serving: not draining, no exit", r.api.draining() === false && r.exits.length === 0 && r.server.closed === 0);
      r.ivs.forEach(h => clearInterval(h));

      const sentBefore = sent.length;
      const r2 = rig({ alert: (k, i) => ops.raise(k, i) });
      r2.proc.emit("uncaughtException", mk("state corrupted"));
      await flush(30);
      check("7. an uncaught exception sends an alert email (process_uncaught_exception)", sent.length === sentBefore + 1 && /process_uncaught_exception/.test(JSON.stringify(sent[sent.length - 1])),
        sent.length - sentBefore);
      check("7. then it shuts down: draining, server closing", r2.api.draining() === true && r2.server.closed === 1, JSON.stringify([r2.api.draining(), r2.server.closed]));
      if (r2.server.cb) r2.server.cb();
      check("7. and exits 1 (Railway starts a fresh process)", JSON.stringify(r2.exits) === "[1]", JSON.stringify(r2.exits));
      r2.ivs.forEach(h => clearInterval(h));

      const r3 = rig({ alert: () => new Promise(() => {}) });
      r3.proc.emit("uncaughtException", mk("mail is hanging"));
      await flush(10);
      const waited = r3.server.closed === 0;
      const t = r3.handlerTimers.find(x => x.ms === G.ALERT_WAIT_MS);
      if (t) t.fn();
      check("7. an alert that never answers delays the shutdown by ALERT_WAIT_MS at most, then it happens anyway",
        waited && !!t && r3.server.closed === 1 && r3.api.draining() === true, JSON.stringify([waited, !!t, r3.server.closed]));
      r3.ivs.forEach(h => clearInterval(h));
    }

    // server.js wiring
    const cronDef = definitionOf("cron");
    const tracked = [];
    let wrapped = null;
    if (cronDef) {
      const ctx = { nodeCron: { schedule: (e, f, o) => ({ expression: e, stop() {} }) }, shutdownControl: { trackJob: (n, t) => { tracked.push(n); return t; } } };
      vm.createContext(ctx);
      vm.runInContext(cronDef + "\nthis.__task = cron.schedule('15 4 * * *', function () {}, { timezone: 'UTC' });", ctx);
      wrapped = ctx.__task;
    }
    check("7. server.js's cron.schedule hands every task it creates to the shutdown", tracked.length === 1 && tracked[0] === "15 4 * * *" && wrapped && wrapped.expression === "15 4 * * *",
      JSON.stringify(tracked));
    const code = uncommented(SRC);
    check("7. node-cron is required once, as nodeCron, and nodeCron.schedule is called only in that wrapper",
      (code.match(/require\("node-cron"\)/g) || []).length === 1 && /const nodeCron = require\("node-cron"\);/.test(code) && (code.match(/nodeCron\.schedule\(/g) || []).length === 1);
    const intervals = code.match(/setInterval\(/g) || [];
    const trackedIv = code.match(/shutdownControl\.trackInterval\("[A-Za-z]+", setInterval\(/g) || [];
    check("7. every setInterval in server.js is registered with the shutdown (" + trackedIv.length + " of " + intervals.length + ")",
      intervals.length > 0 && intervals.length === trackedIv.length, intervals.length + " vs " + trackedIv.length);
    const lr = uncommented(LEADRADAR);
    check("7. the Lead Radar's interval is registered too: startLeadRadar(track) passes its handle, and server.js passes trackInterval",
      (lr.match(/setInterval\(/g) || []).length === 1 && /var handle = setInterval\(radarTick, 300000\);\n  if \(typeof track === "function"\) track\("leadRadarTick", handle\);/.test(lr) &&
      /startLeadRadar\(shutdownControl\.trackInterval\)/.test(code));
    const gateAt = code.indexOf("app.use(shutdownControl.gate);");
    const firstRoute = code.search(/^app\.(get|post|put|patch|delete)\(/m);
    check("7. the drain gate is middleware ahead of every route", gateAt > 0 && gateAt < firstRoute, gateAt + " / " + firstRoute);
    check("7. the listening server is handed to the shutdown", /shutdownControl\.setServer\(app\.listen\(PORT, function \(\) \{/.test(code));
    check("7. the handlers are installed only when server.js is the program",
      /if \(require\.main === module\) \{\n  installProcessHandlers\(process, shutdownControl, function \(key, info\) \{ return opsAlerts\.raise\(key, info\); \}\);/.test(code) &&
      (code.match(/installProcessHandlers\(/g) || []).length === 1);
    check("7. the timeout comes from SHUTDOWN_TIMEOUT_MS", /createShutdown\(\{ timeoutMs: shutdownTimeoutMs\(process\.env\) \}\)/.test(code));
  }

  /* ── 8. frontend security ───────────────────────────────────────────────── */
  console.log("\n══ 8. security headers, a CSP that lists every origin, SRI on every CDN tag, server text never as HTML ══");
  {
    const H = FE["_headers"] || "";
    const block = /^\/\*\n((?:[ \t]+[^\n]*\n?)+)/m.exec(H);
    const headers = {};
    if (block) block[1].split("\n").forEach(l => { const m = /^\s+([A-Za-z-]+):\s*(.*)$/.exec(l); if (m) headers[m[1].toLowerCase()] = m[2].trim(); });
    const hsts = headers["strict-transport-security"] || "";
    const maxAge = +((/max-age=(\d+)/.exec(hsts) || [])[1] || 0);
    check("8. HSTS for at least a year, with includeSubDomains, on every path", maxAge >= 31536000 && /includeSubDomains/.test(hsts), hsts);
    check("8. X-Content-Type-Options: nosniff", headers["x-content-type-options"] === "nosniff");
    check("8. Referrer-Policy: strict-origin-when-cross-origin", headers["referrer-policy"] === "strict-origin-when-cross-origin", headers["referrer-policy"]);
    check("8. X-Frame-Options: DENY", headers["x-frame-options"] === "DENY");
    check("8. an ENFORCED Content-Security-Policy of exactly frame-ancestors 'none'", headers["content-security-policy"] === "frame-ancestors 'none'", headers["content-security-policy"]);
    const pp = {};
    String(headers["permissions-policy"] || "").split(/,\s*/).forEach(x => { const m = /^([a-z-]+)=(.*)$/.exec(x.trim()); if (m) pp[m[1]] = m[2]; });
    check("8. Permissions-Policy: camera, microphone, payment, usb, serial and hid off; geolocation for this site only",
      ["camera", "microphone", "payment", "usb", "serial", "hid"].every(f => pp[f] === "()") && pp.geolocation === "(self)" &&
      Object.keys(pp).every(f => pp[f] === "()" || pp[f] === "(self)"), JSON.stringify(pp));

    const csp = {};
    String(headers["content-security-policy-report-only"] || "").split(";").forEach(d => {
      const parts = d.trim().split(/\s+/).filter(Boolean);
      if (parts.length) csp[parts[0]] = parts.slice(1);
    });
    check("8. a report-only CSP with default-src 'self', object-src 'none', base-uri 'self' and frame-ancestors 'none'",
      String(csp["default-src"]) === "'self'" && String(csp["object-src"]) === "'none'" && String(csp["base-uri"]) === "'self'" && String(csp["frame-ancestors"]) === "'none'",
      JSON.stringify(csp).slice(0, 200));
    const allows = (dir, origin) => {
      const list = csp[dir] || csp["default-src"] || [];
      return list.some(src => {
        if (src === origin) return true;
        const w = /^https:\/\/\*\.(.+)$/.exec(src);
        return !!w && origin.startsWith("https://") && origin.endsWith("." + w[1]);
      });
    };
    const needs = {};   // directive -> origin -> [file]
    const need = (dir, url, file) => {
      const m = /^(https?:\/\/[^/"'?#]+)/.exec(url);
      if (!m || /^https?:\/\/(www\.)?bizforceai\.net$/.test(m[1])) return;
      ((needs[dir] = needs[dir] || {})[m[1]] = needs[dir][m[1]] || []).push(file);
    };
    const tags = (text, name) => text.match(new RegExp("<" + name + "\\b[^>]*>", "gi")) || [];
    const attr = (tag, a) => { const m = new RegExp("\\s" + a + "\\s*=\\s*\"([^\"]*)\"", "i").exec(tag); return m ? m[1] : null; };
    const cdnTags = [];
    Object.keys(FE).filter(f => /\.(html|js)$/.test(f)).forEach(f => {
      const t = FE[f].replace(/<!--[\s\S]*?-->/g, " ");
      tags(t, "script").forEach(tag => { const src = attr(tag, "src"); if (src && /^https?:/.test(src)) { need("script-src", src, f); cdnTags.push({ f, tag, url: src, kind: "script" }); } });
      tags(t, "link").forEach(tag => {
        const rel = String(attr(tag, "rel") || "").toLowerCase(), href = attr(tag, "href");
        if (!href || !/^https?:/.test(href)) return;
        if (rel === "stylesheet") { need("style-src", href, f); if (!/^https:\/\/fonts\.googleapis\.com\//.test(href)) cdnTags.push({ f, tag, url: href, kind: "stylesheet" }); }
        if (/^https:\/\/fonts\.googleapis\.com\//.test(href) && rel === "stylesheet") need("font-src", "https://fonts.gstatic.com", f);
      });
      tags(t, "iframe").forEach(tag => { const src = attr(tag, "src"); if (src) need("frame-src", src, f); });
      ["img", "video", "audio", "source"].forEach(n => tags(t, n).forEach(tag => {
        const src = attr(tag, "src"); if (src) need(n === "img" ? "img-src" : "media-src", src, f);
      }));
      for (const m of t.matchAll(/["'`](https:\/\/[a-z0-9.-]+\.up\.railway\.app)[^"'`]*["'`]/g)) need("connect-src", m[1], f);
      for (const m of t.matchAll(/fetch\(\s*["'`](https:\/\/[^"'`]+)/g)) need("connect-src", m[1], f);
      for (const m of t.matchAll(/["'`](https:\/\/(?:www\.youtube\.com\/embed|player\.vimeo\.com\/video)[^"'`]*)/g)) need("frame-src", m[1], f);
      for (const m of t.matchAll(/["'`](https:\/\/[a-z0-9.-]+\/[^"'`\s]*\.(?:png|jpe?g|gif|webp|svg))["'`]/gi)) need("img-src", m[1], f);
      for (const m of t.matchAll(/["'`](https:\/\/img\.youtube\.com\/)/g)) need("img-src", m[1], f);
    });
    const missing = [];
    Object.keys(needs).forEach(dir => Object.keys(needs[dir]).forEach(o => { if (!allows(dir, o)) missing.push(dir + " " + o + " (" + needs[dir][o][0] + ")"); }));
    const counted = Object.keys(needs).reduce((a, d) => a + Object.keys(needs[d]).length, 0);
    console.log("    " + counted + " directive/origin pairs the pages need: " + Object.keys(needs).map(d => d + " " + Object.keys(needs[d]).join(" ")).join("; "));
    check("8. every external origin the pages load from is in the CSP directive that governs it", missing.length === 0 && counted >= 6, missing.join("; "));

    /* The hashes of the files as downloaded on 2026-10-27 (sha384, base64). A tag
       whose hash differs from its URL's here fails without a download; with
       BIZFORCE_CDN_DIR the files themselves are hashed too. */
    const KNOWN_SRI = {
      "https://cdn.jsdelivr.net/npm/qrcode@1.4.4/build/qrcode.min.js": "sha384-0RsG1yo/crf/1Qc14sho26SXXOTngNCjgJw7fuvXBt9W/OChF/Ijx+aUuBDqQwEk",
      "https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js": "sha384-ZZ1pncU3bQe8y31yfZdMFdSpttDoPmOZg2wguVK9almUodir1PghgT0eY7Mrty8H",
      "https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js": "sha384-JcnsjUPPylna1s1fvi1u12X5qjY5OL56iySh75FdtrwhO/SWXgMjoVqcKyIIWOLk",
      "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js": "sha384-9nhczxUqK87bcKHh20fSQcTGD4qq5GhayNYSYWqwBkINBhOfQLg/P5HG5lF1urn4"
    };
    const CDN_DIR = process.env.BIZFORCE_CDN_DIR || "";
    const B64LEN = { sha256: 44, sha384: 64, sha512: 88 };
    console.log("    " + cdnTags.length + " CDN tags" + (CDN_DIR ? ", hashed against the files in " + CDN_DIR : " (BIZFORCE_CDN_DIR not set: format checked, real files not hashed)"));
    check("8. the CDN tags are the seven known ones (qrcode x2, html2canvas, jspdf, chart.js x3)", cdnTags.length === 7, cdnTags.length);
    cdnTags.forEach(c => {
      const integ = attr(c.tag, "integrity") || "";
      const m = /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/.exec(integ);
      check("8. " + c.f + ": " + c.url.replace(/^https:\/\//, "") + " has a valid SRI hash and crossorigin=\"anonymous\"",
        !!m && m[2].length === B64LEN[m[1]] && attr(c.tag, "crossorigin") === "anonymous", integ + " / " + attr(c.tag, "crossorigin"));
      check("8. " + c.f + ": " + c.url.replace(/^https:\/\//, "") + " names an exact version", /[@/]\d+\.\d+\.\d+\//.test(c.url) && !/@latest/.test(c.url));
      check("8. " + c.f + ": " + c.url.replace(/^https:\/\//, "") + " carries the hash of that exact file", KNOWN_SRI[c.url] === integ, KNOWN_SRI[c.url] ? "differs" : "no known hash for this URL");
      if (CDN_DIR && m) {
        const file = path.join(CDN_DIR, c.url.replace(/^https:\/\//, "").replace(/[\/@]/g, "_"));
        const ok = fs.existsSync(file) && crypto.createHash(m[1]).update(fs.readFileSync(file)).digest("base64") === m[2];
        check("8. " + c.f + ": the SRI hash is the hash of the real file", ok, fs.existsSync(file) ? "hash differs" : "no file " + file);
      }
    });

    // Server text never becomes HTML unescaped. A markup builder may take it
    // when the builder itself is shown to escape it.
    const SAFE_BUILDERS = { loadFailMarkup: ["scripts/email-sequences.js", /function loadFailMarkup\(what, detail\) \{\n    return '[^\n]*' \+ esc\(what\) \+\n[^\n]*\n      \(detail \? ' \(' \+ esc\(detail\) \+ '\)' : ''\)/] };
    Object.keys(SAFE_BUILDERS).forEach(n => check("8. " + SAFE_BUILDERS[n][0] + ": " + n + " escapes what it is given", SAFE_BUILDERS[n][1].test(FE[SAFE_BUILDERS[n][0]] || "")));
    const unsafe = [];
    Object.keys(FE).filter(f => /\.(html|js)$/.test(f)).forEach(f => {
      const t = uncommented(FE[f].replace(/<!--[\s\S]*?-->/g, " "));
      for (const m of t.matchAll(/\.innerHTML\s*\+?=\s*([^;]*);/g)) {
        const builder = (/^([A-Za-z_$][\w$]*)\(/.exec(m[1].trim()) || [])[1];
        if (builder && SAFE_BUILDERS[builder] && SAFE_BUILDERS[builder][0] === f) continue;
        if (/\b(err|error|e|ex)\.message\b|\b(data|json|body|result|res)\.error\b/.test(m[1]) && !/esc|Esc|escape|sanitize/.test(m[1])) unsafe.push(f + ": " + m[0].slice(0, 90));
      }
    });
    check("8. no page writes a server error into innerHTML unescaped", unsafe.length === 0, unsafe.join(" | "));
    const content = FE[CONTENT];
    const helper = /function showContentError\(el, text\) \{([\s\S]*?)\n    \}/.exec(content);
    check("8. content.html: showContentError writes the text with textContent, into a fresh span",
      !!helper && /span\.textContent = text;/.test(helper[1]) && !/innerHTML/.test(helper[1]));
    check("8. content.html: the four error sites (two poll errors, two request errors) go through it",
      (content.match(/showContentError\(outputEl, "(Poll error|Error): " \+ \(err\.message \|\| "Request failed"\)\);/g) || []).length === 4);
    const dash = FE[DASH];
    check("8. dashboard.html: the profile save error and the task error are textContent",
      /bpErr\.textContent = err\.message \|\| "Save failed\.";/.test(dash) && /statusEl\.textContent = err\.message \|\| "Task failed\.";/.test(dash));
    const sms = FE[SMS];
    const escDef = /function smsEsc\(value\) \{[\s\S]*?\n    \}/.exec(sms);
    let escOk = false;
    if (escDef) { const fn = new Function(escDef[0] + "\nreturn smsEsc;")(); escOk = fn("<img src=x onerror=\"a('b')\">&") === "&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;" && fn(null) === ""; }
    check("8. sms.html: smsEsc escapes & < > \" and '", escOk);
    const smsFields = ["m.step_order", "m.message_body", "to", "msg", "status", "sentAt", "subId", "step"];
    const rawSms = smsFields.filter(v => new RegExp("[\"']\\s*\\+\\s*" + v.replace(".", "\\.") + "\\s*\\+\\s*[\"']").test(sms));
    check("8. sms.html: message bodies, steps, send-log cells and enrollment fields go into HTML only through smsEsc",
      rawSms.length === 0 && smsFields.every(v => sms.indexOf("smsEsc(" + v + ")") !== -1), rawSms.join(","));
  }

  /* ── 10. the business card ──────────────────────────────────────────────── */
  console.log("\n══ 10. the card: a QR that opens it, tap links, a full vCard, a validated short link, nothing hidden served ══");
  {
    const win = { btoa: x => Buffer.from(x, "binary").toString("base64") };
    vm.runInNewContext(FE[BF_CARD], { window: win, unescape, encodeURIComponent, Uint8Array, String, Promise });
    const C = win.bfCard;
    check("10. bf-card.js loads and exposes publicUrl, telHref, mailtoHref, buildVCard and photoFor",
      !!C && ["publicUrl", "telHref", "mailtoHref", "buildVCard", "photoFor"].every(k => typeof C[k] === "function"));
    check("10. the public URL: the short link when there is a slug, else card-view.html?token=",
      C.publicUrl({ slug: "jane-doe", share_token: "t" }) === "https://bizforceai.net/c/jane-doe" &&
      C.publicUrl({ share_token: "a b" }) === "https://bizforceai.net/card-view.html?token=a%20b" && C.publicUrl({}) === null);
    check("10. tel: keeps the + and the digits; too short is no link",
      C.telHref("+1 (555) 010-2030") === "tel:+15550102030" && C.telHref("555.010.2030") === "tel:5550102030" && C.telHref("12") === null && C.telHref("") === null);
    check("10. mailto: for a real address only", C.mailtoHref(" jane@example.com ") === "mailto:jane@example.com" && C.mailtoHref("jane") === null && C.mailtoHref("") === null);

    const card = { full_name: "Jane Q. Doe", job_title: "Owner, Roastery; Head", company: "Doe & Co", phone: "+1 (555) 010-2030",
      email: "jane@example.com", website: "https://doe.example", public_url: "https://bizforceai.net/c/jane-doe" };
    const b64 = Buffer.alloc(3000, 7).toString("base64");
    const v = C.buildVCard(card, { type: "JPEG", base64: b64 });
    const unfolded = v.replace(/\r\n /g, "");
    const lines = unfolded.split("\r\n").filter(Boolean);
    const has = p => lines.some(l => l.indexOf(p) === 0);
    check("10. the vCard is 3.0 and has N, FN, ORG, TITLE, TEL, EMAIL, both URLs and PHOTO",
      lines[0] === "BEGIN:VCARD" && lines[1] === "VERSION:3.0" && lines[lines.length - 1] === "END:VCARD" &&
      has("N:Doe;Jane Q.;;;") && has("FN:Jane Q. Doe") && has("ORG:Doe & Co") && has("TITLE:") && has("TEL;TYPE=WORK,VOICE:+15550102030") &&
      has("EMAIL;TYPE=INTERNET:jane@example.com") && has("URL:https://doe.example") && has("URL:https://bizforceai.net/c/jane-doe") &&
      has("PHOTO;ENCODING=b;TYPE=JPEG:" + b64), lines.map(l => l.slice(0, 30)).join(" | "));
    check("10. text values are escaped (commas and semicolons)", has("TITLE:Owner\\, Roastery\\; Head"), lines.find(l => l.indexOf("TITLE") === 0));
    const physical = v.split("\r\n");
    check("10. every line ends in CRLF and none is longer than 75 octets (long PHOTO lines are folded)",
      /\r\n$/.test(v) && !/[^\r]\n/.test(v) && physical.every(l => Buffer.byteLength(l, "utf8") <= 75) && physical.length > 40,
      Math.max(...physical.map(l => Buffer.byteLength(l, "utf8"))));
    const linked = C.buildVCard(card, { url: "https://x.supabase.co/a.webp" });
    check("10. a photo that cannot be embedded is linked: PHOTO;VALUE=uri:", linked.replace(/\r\n /g, "").indexOf("PHOTO;VALUE=uri:https://x.supabase.co/a.webp") !== -1);
    const hidden = C.buildVCard(Object.assign({}, card, { email: "", phone: "" }), null);
    check("10. a field the server sent as \"\" (hidden) is not in the vCard", !/EMAIL|TEL/.test(hidden) && !/PHOTO/.test(hidden));

    const blobOf = (type, size) => ({ ok: true, blob: async () => ({ type, size, arrayBuffer: async () => new Uint8Array(size).fill(1).buffer }) });
    const small = await C.photoFor("https://x.supabase.co/me.jpg", async () => blobOf("image/jpeg", 1000));
    const big = await C.photoFor("https://x.supabase.co/me.jpg", async () => blobOf("image/jpeg", C.PHOTO_EMBED_MAX_BYTES + 1));
    const webp = await C.photoFor("https://x.supabase.co/me.webp", async () => blobOf("image/webp", 1000));
    const down = await C.photoFor("https://x.supabase.co/me.jpg", async () => { throw new Error("offline"); });
    const plain = await C.photoFor("http://x.example/me.jpg", async () => blobOf("image/jpeg", 10));
    check("10. photoFor: a small JPEG is embedded; too big, not JPEG/PNG/GIF or unreachable is linked; non-https is none",
      small && small.type === "JPEG" && small.base64 === Buffer.alloc(1000, 1).toString("base64") &&
      big && big.url && !big.base64 && webp && webp.url && down && down.url && plain === null, JSON.stringify([small && small.type, big, webp, down, plain]));

    const view = FE[CARD_VIEW], editor = FE[CARDS];
    const qrArgs = text => [...text.matchAll(/QRCode\.toCanvas\(([^,]+),\s*([^,]+),/g)].map(m => m[2].trim());
    check("10. card-view.html: both QR codes encode cardUrl, the card's public URL", JSON.stringify(qrArgs(view)) === '["cardUrl","cardUrl"]' &&
      /var cardUrl = window\.bfCard\.publicUrl\(c\) \|\| window\.location\.href;/.test(view), JSON.stringify(qrArgs(view)));
    check("10. digital-cards.html: both QR codes encode url, the card's public URL (blank before the first save)",
      JSON.stringify(qrArgs(editor)) === '["url","url"]' && /var url = cardQrUrl\(\);/.test(editor) &&
      /function cardQrUrl\(\) \{\n  return window\.bfCard\.publicUrl\(\{ slug: activeSlug, share_token: activeShareToken \}\);/.test(editor), JSON.stringify(qrArgs(editor)));
    check("10. neither page builds a vCard of its own (bf-card.js is the one builder)",
      !/BEGIN:VCARD/.test(view) && !/BEGIN:VCARD/.test(editor) && /<script src="\/scripts\/bf-card\.js"><\/script>/.test(view) && /<script src="\/scripts\/bf-card\.js"><\/script>/.test(editor));
    check("10. card-view.html: email and phone are tap-to-email and tap-to-call links",
      /<a class="[^"]*" id="pEmail"><\/a>/.test(view) && /<a class="[^"]*" id="pPhone"><\/a>/.test(view) &&
      view.indexOf('setContactLink("pEmail", c.email, window.bfCard.mailtoHref(c.email));') !== -1 &&
      view.indexOf('setContactLink("pPhone", c.phone, window.bfCard.telHref(c.phone));') !== -1);
    check("10. card-view.html: Save Contact builds the vCard with the photo", /var photo = await window\.bfCard\.photoFor\(cardData\.photo_url\);\n  var blob = new Blob\(\[window\.bfCard\.buildVCard\(cardData, photo\)\]/.test(view));
    check("10. card-view.html opens from /c/<slug> or ?token=", view.indexOf('var m = /^\\/c\\/([a-z0-9-]{3,40})\\/?$/.exec(window.location.pathname);') !== -1 &&
      view.indexOf('if (m) return API_URL + "/api/cards/slug/" + encodeURIComponent(m[1]);') !== -1);
    check("10. digital-cards.html: a short link field and show email / phone / photo choices, sent with the save",
      /id="fSlug"/.test(editor) && /id="fShowEmail"/.test(editor) && /id="fShowPhone"/.test(editor) && /id="fShowPhoto"/.test(editor) &&
      /if \(cardPrivacyReady\) Object\.assign\(body, privacyFields\(\)\);/.test(editor));
    const R = FE["_redirects"];
    const cAt = R.indexOf("/c/:slug /card-view.html 200\n"), splatAt = R.search(/^\/\*\s/m);
    check("10. Netlify serves card-view.html at /c/<slug>", cAt !== -1 && (splatAt === -1 || cAt < splatAt), cAt + " / " + splatAt);

    // server.js, lifted
    const rows = {
      digital_cards: [{ id: "c1", user_id: "u1", slug: "jane-doe", share_token: "tok1", full_name: "Jane", job_title: "Owner", company: "Doe",
        email: "jane@example.com", phone: "555", website: "https://doe.example", theme: "dark", show_email: false, show_phone: true, show_photo: false },
      { id: "c2", user_id: "u2", slug: "lapsed", share_token: "tok2", full_name: "L", email: "l@example.com", phone: "1", theme: "dark" },
      { id: "c3", user_id: "u3", slug: "open-card", share_token: "tok3", full_name: "O", email: "o@example.com", phone: "777", theme: "dark" }],
      bf_profiles: [{ user_id: "u1", avatar_url: "https://x.supabase.co/u1.jpg" }, { user_id: "u3", avatar_url: "https://x.supabase.co/u3.jpg" }]
    };
    const db = fakeDb(rows);
    let handler = null;
    const ctx = { supabase: db.client, process: { env: {} }, console: quiet, ownerPagePublic: async uid => uid !== "u2",
      app: { get() { handler = arguments[arguments.length - 1]; } } };
    vm.createContext(ctx);
    const route = (() => { const at = SRC.indexOf('app.get("/api/cards/slug/:slug",'); if (at < 0) return ""; const open = SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", at)); return SRC.slice(at, s.braceMatch(SRC, open)) + ");"; })();
    vm.runInContext(closure(route + "\nthis.__api = { cardSlugFrom, cardPublicUrl, cardPrivacyUpdates, publicCardFrom, cardWriteRefusal, CARD_SLUG_RE };", new Set(BASE_STUBS)), ctx);
    const A = ctx.__api;
    const ok = x => A.cardSlugFrom(x).slug, err = x => !!A.cardSlugFrom(x).error;
    check("10. slugs: 3 to 40 lowercase letters, digits and single hyphens, ends alphanumeric; upper case folded; empty clears",
      ok("jane-doe") === "jane-doe" && ok("a1b") === "a1b" && ok("JaneDoe") === "janedoe" && ok(" x" + "y".repeat(38) + "z ") === "x" + "y".repeat(38) + "z" &&
      err("ab") && err("-ab") && err("ab-") && err("a--b") && err("jane doe") && err("jané") && err("x".repeat(41)) && err("a_b") && err("../x") &&
      A.cardSlugFrom("").slug === null && A.cardSlugFrom(null).slug === null);
    check("10. reserved slugs are refused", ["admin", "api", "www", "support", "official", "bizforce"].every(err));
    check("10. a privacy update keeps only the fields sent; \"false\" and false hide; a bad slug refuses the save",
      JSON.stringify(A.cardPrivacyUpdates({}).updates) === "{}" &&
      JSON.stringify(A.cardPrivacyUpdates({ show_email: "false", show_phone: false, show_photo: true, slug: "Jane-Doe" }).updates) === '{"show_email":false,"show_phone":false,"show_photo":true,"slug":"jane-doe"}' &&
      !!A.cardPrivacyUpdates({ slug: "-bad-" }).error);
    check("10. a taken slug is a 409; a database without migration 149 is a 503 that names it",
      (A.cardWriteRefusal({ code: "23505", message: "duplicate key value violates unique constraint \"digital_cards_slug_unique\"" }) || {}).status === 409 &&
      /149/.test((A.cardWriteRefusal({ code: "PGRST204", message: "Could not find the 'slug' column" }) || {}).error || "") &&
      A.cardWriteRefusal(null) === null && A.cardWriteRefusal({ code: "XX000", message: "other" }) === null);
    const pub = A.publicCardFrom(Object.assign({}, rows.digital_cards[0], { secret_note: "x" }), "https://x.supabase.co/u1.jpg");
    const ALLOWED = ["full_name", "job_title", "company", "website", "email", "phone", "photo_url", "public_url", "theme", "video_url", "bg_image_url",
      "still_image_url", "audio_url", "holographic_style", "media_layout"];
    check("10. the public card is an allowlist: no user_id, id, share_token, slug or any other column",
      Object.keys(pub).every(k => ALLOWED.indexOf(k) !== -1) && !("user_id" in pub) && !("share_token" in pub) && !("id" in pub), Object.keys(pub).join(","));
    check("10. a hidden email, phone or photo is served empty; a shown one as is",
      pub.email === "" && pub.phone === "555" && pub.photo_url === null &&
      A.publicCardFrom({ show_phone: false, phone: "1", email: "e@x.y" }, "https://p").phone === "" && A.publicCardFrom({ email: "e@x.y" }, "https://p").photo_url === "https://p");
    check("10. public_url is the short link, else the token link", pub.public_url === "https://bizforceai.net/c/jane-doe" &&
      A.publicCardFrom({ share_token: "tok" }, null).public_url === "https://bizforceai.net/card-view.html?token=tok");
    async function get(slug) {
      const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
      let nextErr = null;
      await handler({ params: { slug } }, res, e => { nextErr = e; });
      return { status: res.statusCode, body: res.body, nextErr };
    }
    const photoReadsBefore = db.reads.filter(q => q.table === "bf_profiles").length;
    const g1 = await get("Jane-Doe");
    check("10. a card whose photo is hidden never reads the owner's profile photo at all",
      db.reads.filter(q => q.table === "bf_profiles").length === photoReadsBefore, db.reads.filter(q => q.table === "bf_profiles").length - photoReadsBefore);
    check("10. GET /api/cards/slug/Jane-Doe: 200, the card with its email and photo hidden as the member chose",
      g1.status === 200 && g1.body && g1.body.card && g1.body.card.full_name === "Jane" && g1.body.card.email === "" && g1.body.card.photo_url === null &&
      !("user_id" in g1.body.card), JSON.stringify(g1));
    const g3 = await get("open-card");
    check("10. a card that hides nothing serves its email, phone and the owner's profile photo",
      g3.status === 200 && g3.body.card.email === "o@example.com" && g3.body.card.phone === "777" && g3.body.card.photo_url === "https://x.supabase.co/u3.jpg", JSON.stringify(g3.body));
    const readsBefore = db.reads.filter(q => q.table === "digital_cards").length;
    const g2 = await get("ab");
    check("10. an impossible slug is a 404 without a read", g2.status === 404 && db.reads.filter(q => q.table === "digital_cards").length === readsBefore);
    const g4 = await get("lapsed"), g5 = await get("nobody-here");
    check("10. a lapsed owner's card and an unknown slug are both 404", g4.status === 404 && g5.status === 404, g4.status + " " + g5.status);
    const code = uncommented(SRC);
    check("10. GET /api/cards/share/:token serves the same allowlist", /app\.get\("\/api\/cards\/share\/:token"[\s\S]*?return res\.json\(\{ card: publicCardFrom\(data, await cardOwnerPhoto\(data\)\) \}\);/.test(code));
    check("10. POST and PUT /api/digital-cards validate the privacy fields and map the slug refusals",
      (code.match(/const privacy = cardPrivacyUpdates\(req\.body\);/g) || []).length === 2 && /const postRefusal = cardWriteRefusal\(error\);/.test(code) && /const putRefusal = cardWriteRefusal\(error\);/.test(code));
    const reFromSql = (/slug ~ '([^']+)'/.exec(MIG) || [])[1];
    check("10. migration 149: slug, and show_email / show_phone / show_photo default true and not null",
      /ADD COLUMN IF NOT EXISTS slug text;/.test(MIG) && ["show_email", "show_phone", "show_photo"].every(c => new RegExp("ADD COLUMN IF NOT EXISTS " + c + " boolean NOT NULL DEFAULT true;").test(MIG)));
    check("10. migration 149: the slug format in the database is server.js's CARD_SLUG_RE, with no double hyphen",
      reFromSql === A.CARD_SLUG_RE.source && /position\('--' in slug\) = 0/.test(MIG), reFromSql + " vs " + A.CARD_SLUG_RE.source);
    check("10. migration 149: a slug is unique (a partial unique index)", /CREATE UNIQUE INDEX IF NOT EXISTS digital_cards_slug_unique ON public\.digital_cards \(slug\) WHERE slug IS NOT NULL;/.test(MIG));
  }

  /* ── 12. SEO ────────────────────────────────────────────────────────────── */
  console.log("\n══ 12. public pages are described and canonical; private pages are noindex ══");
  {
    // file -> the path its canonical names; null: a member's page whose canonical a script sets from the URL
    const PUBLIC = { "index.html": "/", "app.html": "/app", "vitality.html": "/vitality", "xxl-xtreme.html": "/xxl-xtreme",
      "suppressed.html": "/suppressed.html", "terms.html": "/terms", "privacy.html": "/privacy", "refund.html": "/refund", "contact.html": "/contact",
      "card-view.html": null, "profile.html": null, "seller.html": null, "listing.html": null, "blogindex.html": null, "blogpost.html": null };
    const VERIFY = /^google[0-9a-f]+\.html$/;
    const SITEMAP = FE["sitemap-pages.xml"] || "";
    const locs = [...SITEMAP.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
    const head = t => (/<head[\s\S]*?<\/head>/i.exec(t) || [t.slice(0, 6000)])[0];
    const metas = t => (head(t).match(/<meta\b[^>]*>/gi) || []);
    const metaContent = (t, key, val) => {
      const tag = metas(t).find(m => new RegExp("\\s" + key + "\\s*=\\s*\"" + val + "\"", "i").test(m));
      const c = tag && /\scontent\s*=\s*"([^"]*)"/i.exec(tag);
      return c ? c[1] : null;
    };
    const noindex = t => /noindex/i.test(String(metaContent(t, "name", "robots") || ""));
    const pages = Object.keys(FE).filter(f => /\.html$/.test(f) && !VERIFY.test(path.basename(f)));
    const titles = {};
    Object.keys(PUBLIC).forEach(f => {
      const t = FE[f];
      if (!t) { check("12. " + f + " exists", false); return; }
      const title = ((/<title>([^<]*)<\/title>/.exec(head(t)) || [])[1] || "").trim();
      const desc = metaContent(t, "name", "description");
      const can = /<link\s+rel="canonical"\s+href="([^"]*)"/.exec(head(t));
      const og = ["og:title", "og:description", "og:type", "og:url"].map(p => metaContent(t, "property", p));
      // The blog pages leave og:url, like the canonical, empty until the API names the page; their setCanonical fills both.
      if (/^blog/.test(f) && og[3] === "" && /og\.setAttribute\("content", CANONICAL_ORIGIN \+ path\);/.test(t)) og[3] = "set by setCanonical";
      (titles[title] = titles[title] || []).push(f);
      const want = PUBLIC[f];
      let canOk;
      if (want) canOk = !!can && can[1] === "https://bizforceai.net" + want;
      else if (/^blog/.test(f)) canOk = !!can && /tag\.setAttribute\("rel", "canonical"\)/.test(t);
      else if (f === "card-view.html") canOk = !!can && can[1] === "https://bizforceai.net/card-view.html" && /setCanonical\(cardUrl\);/.test(t);
      else canOk = !!can && can[1] === "https://bizforceai.net/" + f && /<script src="\/scripts\/bf-canonical\.js" data-keep="[a-z,]+"><\/script>/.test(t);
      check("12. " + f + ": a title, a description, a canonical, og:title/description/type/url, and not noindex",
        title.length >= 10 && !!desc && desc.length >= 50 && canOk && og.every(Boolean) && !noindex(t),
        JSON.stringify({ title, desc: desc && desc.length, can: can && can[1], og: og.map(Boolean), noindex: noindex(t) }));
      if (want) {
        const url = "https://bizforceai.net" + want;
        check("12. " + f + ": its og:url is its canonical, and it is in the sitemap", og[3] === url && locs.indexOf(url) !== -1, og[3] + " / " + (locs.indexOf(url) !== -1));
      }
    });
    const dup = Object.keys(titles).filter(k => titles[k].length > 1);
    check("12. every public page's title is its own", dup.length === 0, dup.map(k => k + " = " + titles[k].join(",")).join("; "));
    const privates = pages.filter(f => !(f in PUBLIC));
    const indexable = privates.filter(f => !noindex(FE[f]));
    console.log("    " + Object.keys(PUBLIC).length + " public pages, " + privates.length + " private pages");
    check("12. every other page (" + privates.length + ") is noindex", indexable.length === 0 && privates.length >= 50, indexable.join(", "));
    const privateInSitemap = locs.filter(u => privates.some(f => u === "https://bizforceai.net/" + f || u === "https://bizforceai.net/" + f.replace(/\.html$/, "")));
    check("12. no noindex page is in the sitemap", privateInSitemap.length === 0, privateInSitemap.join(", "));
    const robots = FE["robots.txt"] || "";
    check("12. robots.txt lets every crawler in and names the sitemap index",
      /^User-agent: \*$/m.test(robots) && !/^Disallow:\s*\/\s*$/m.test(robots) && /^Sitemap: https:\/\/bizforceai\.net\/sitemap\.xml$/m.test(robots), robots);
    const idx = FE["sitemap.xml"] || "";
    check("12. the sitemap index lists the pages and the blog sitemaps, and Netlify serves the blog one from the API",
      /<loc>https:\/\/bizforceai\.net\/sitemap-pages\.xml<\/loc>/.test(idx) && /<loc>https:\/\/bizforceai\.net\/sitemap-blog\.xml<\/loc>/.test(idx) &&
      /^\/sitemap-blog\.xml https:\/\/[a-z0-9.-]+\.up\.railway\.app\/api\/sitemap\/blog\.xml 200$/m.test(FE["_redirects"]));
  }

  /* ── 13. docs ───────────────────────────────────────────────────────────── */
  console.log("\n══ 13. the README names every env var and job; the runbook every alert ══");
  {
    const reads = envReads();
    const names = Object.keys(reads).sort();
    const missing = names.filter(n => !new RegExp("`" + n + "`").test(README));
    console.log("    " + names.length + " environment variables read by the running backend");
    check("13. README.md names every environment variable the backend reads (" + names.length + ")", names.length >= 60 && missing.length === 0, missing.join(", "));
    const rowsFor = names.map(n => README.split("\n").find(l => l.indexOf("| `" + n + "` |") === 0)).filter(Boolean);
    check("13. each has a table row with a default and an effect", rowsFor.length === names.length && rowsFor.every(l => l.split("|").length >= 5 && l.split("|")[3].trim().length > 10),
      names.filter(n => !README.split("\n").some(l => l.indexOf("| `" + n + "` |") === 0)).join(","));
    const exprs = [...new Set([...uncommented(SRC).matchAll(/cron\.schedule\("([^"]+)"/g)].map(m => m[1]))];
    const exprMissing = exprs.filter(e => README.indexOf("cron `" + e + "`") === -1);
    check("13. every cron schedule in server.js is in the README's job table (" + exprs.length + ")", exprs.length >= 5 && exprMissing.length === 0, exprMissing.join(", "));
    check("13. every interval is in the job table too", ["dripTick", "reminderTick", "salesAutoConvertTick", "Lead Radar"].every(j => README.indexOf(j) !== -1));
    const sections = ["## Environment variables", "## Background jobs", "## The check suite", "## Migrations", "## Deploy order", "## Email", "## Backups and the restore drill"];
    check("13. README sections: what BizForce is, env vars, jobs, the suite, migrations, deploy order, email, backups and the restore drill",
      sections.every(h => README.indexOf("\n" + h + "\n") !== -1) && /^# BizForce-backend\n\n\S/.test(README), sections.filter(h => README.indexOf("\n" + h + "\n") === -1).join(","));
    const email = (README.split("\n## Email\n")[1] || "").split("\n## ")[0];
    check("13. the email section: Resend sends from send.mail.bizforceai.net, ImprovMX receives at @bizforceai.net",
      /Resend/.test(email) && /send\.mail\.bizforceai\.net/.test(email) && /ImprovMX/.test(email) && /@bizforceai\.net/.test(email));
    const backups = (README.split("\n## Backups and the restore drill\n")[1] || "").split("\n## ")[0];
    check("13. the backups section has a restore drill", /restore/i.test(backups) && /drill/i.test(backups) && backups.length > 400);
    check("13. the README says migration 149 must be applied", /149/.test(README));

    const keys = new Set();
    const libs = ["server.js", "lib/opsAlert.js", "lib/gracefulShutdown.js"];
    libs.forEach(f => {
      const t = uncommented(f === "server.js" ? SRC : f === "lib/gracefulShutdown.js" ? SHUT : readRepo(f));
      for (const m of t.matchAll(/(?:raise|platformSpendAlert)\(\s*"([a-z0-9_]+)"/g)) keys.add(m[1]);
      if (/raise\("job:" \+/.test(t)) keys.add("job:<job_name>");
      if (/return "schedule_paused:" \+/.test(t)) keys.add("schedule_paused:<user>:<agent>");
    });
    const keyMissing = [...keys].filter(k => RUNBOOK.indexOf("| `" + k + "` |") === -1);
    check("13. RUNBOOK.md has a row for every alert key the code can raise (" + keys.size + ")", keys.size >= 14 && keyMissing.length === 0, keyMissing.join(", "));
    const procs = ["## When Railway is down", "## When the spend ceiling trips", "## When a backup fails", "## When a payment fails"];
    check("13. RUNBOOK.md: Railway down, the spend ceiling, a backup failing, a payment failing",
      procs.every(h => RUNBOOK.indexOf("\n" + h) !== -1), procs.filter(h => RUNBOOK.indexOf("\n" + h) === -1).join(","));
    check("13. RUNBOOK.md: an uptime monitor on /health", /\/health/.test(RUNBOOK) && /uptime/i.test(RUNBOOK));
    const R = (FE["_redirects"] || "").split("\n").filter(l => l.trim() && !/^#/.test(l));
    check("13. _redirects begins with the forced www to apex 301s, for https and http",
      R[0] === "https://www.bizforceai.net/* https://bizforceai.net/:splat 301!" && R[1] === "http://www.bizforceai.net/* https://bizforceai.net/:splat 301!", R.slice(0, 2).join(" | "));
  }

  console.log("\n══ summary ══");
  console.log("    " + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(e => { console.log("FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
