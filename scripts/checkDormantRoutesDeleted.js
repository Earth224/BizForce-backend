/* ══════════════════════════════════════════════════════════════════════════
   checkDormantRoutesDeleted.js — twenty-one routes no page ever called are
   gone, everything else still registers, and nothing refers to what was
   removed with them.

   WHAT WAS REMOVED (routes only, in af4d434 — the six tables behind them,
   follows, favorites, posts, deals, websites and analytics_events, were then
   dropped by migration 123):
     social graph / directory  GET /api/search/businesses, POST and DELETE
                               /api/follow/:userId, GET /api/followers,
                               GET /api/following, POST and DELETE
                               /api/favorites/:businessId, GET /api/feed,
                               POST /api/posts, DELETE /api/posts/:id
     deals                     GET, POST /api/deals; PUT, DELETE /api/deals/:id
     websites                  GET, POST /api/websites; DELETE /api/websites/:id
     analytics                 GET /api/analytics, POST /api/analytics/event
     legacy profile images     POST /api/profile/upload-logo, upload-banner
   and the helpers only they used: enforceWebsiteLimit, validateDealInput,
   parseDealCloseDate, DEAL_STAGES, DEAL_AMOUNT_MAX.
   GET /api/analytics/summary is a DIFFERENT route, is called by
   analytics-dashboard.html, and stays.

   WHAT THIS PROVES, against the real server booted in this process:
     1. Each of the 21 is absent from the Express router and answers 404 over
        HTTP. (Unauthenticated: a route that still existed would answer 401
        from requireAuth, so 404 means the path is not mounted.)
     2. Every other route that server.js registered at f045991 still
        registers — computed from that commit's source minus the 21, not typed
        in — and the total is exactly that.
     3. No code in server.js names any of the removed helpers. Comments that
        mention them as history are ignored.

   MUTATE=revive  re-mounts GET /api/deals after boot, ahead of the 404
                  catch-all. Its 404 check and the route total must go red.

   Starting server.js starts its intervals and crons as it always does; the
   run is over in seconds and nothing here writes to the database.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const fs = require("fs");
const http = require("http");
const path = require("path");
const { execSync } = require("child_process");
const REPO = path.join(__dirname, "..");
const SERVER_PATH = path.join(REPO, "server.js");
const PORT = Number(process.env.CHECK_PORT || 4791);
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATE !== "revive") { console.error("Unknown MUTATE=" + MUTATE + ". Known: revive"); process.exit(2); }

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const DELETED = [
  ["get", "/api/search/businesses"], ["post", "/api/follow/:userId"], ["delete", "/api/follow/:userId"],
  ["get", "/api/followers"], ["get", "/api/following"], ["post", "/api/favorites/:businessId"],
  ["delete", "/api/favorites/:businessId"], ["get", "/api/feed"], ["post", "/api/posts"], ["delete", "/api/posts/:id"],
  ["get", "/api/deals"], ["post", "/api/deals"], ["put", "/api/deals/:id"], ["delete", "/api/deals/:id"],
  ["get", "/api/websites"], ["post", "/api/websites"], ["delete", "/api/websites/:id"],
  ["get", "/api/analytics"], ["post", "/api/analytics/event"],
  ["post", "/api/profile/upload-logo"], ["post", "/api/profile/upload-banner"]
];
const ORPHANS = ["enforceWebsiteLimit", "validateDealInput", "parseDealCloseDate", "DEAL_STAGES", "DEAL_AMOUNT_MAX"];
const BEFORE = "f045991";

/* ── what should still be there, from the source before the deletion ────── */
const ROUTE_RE = /^app\.(get|post|put|patch|delete)\(\s*["']([^"']+)["']/gm;
function routeList(src) { const out = []; let m; while ((m = ROUTE_RE.exec(src))) out.push(m[1] + " " + m[2]); ROUTE_RE.lastIndex = 0; return out; }
const OLD_SRC = execSync("git show " + BEFORE + ":server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");
const deletedKeys = new Set(DELETED.map(function (d) { return d[0] + " " + d[1]; }));
/* Routes added since, each on purpose. The total stays exact: a route that is
   in neither list is still an extra. */
const ADDED = [
  ["post", "/api/engine-visits"],  // records an arrival from a Lead Radar reply (migration 128)
  ["post", "/api/agents/seo/audit"] // A real SEO audit, measured before it is explained
];
/* Routes removed since, each on purpose, by a later change. */
const REMOVED = new Set([
  "post /api/seo/audit"            // never fetched the site, so every audit was invented (5d014de)
]);
const EXPECTED = routeList(OLD_SRC).filter(function (k) { return !deletedKeys.has(k) && !REMOVED.has(k); })
  .concat(ADDED.map(function (a) { return a[0] + " " + a[1]; }));

/* ── boot the real server, capturing the app ────────────────────────────── */
const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () { const made = realExpress.apply(this, arguments); if (!app) app = made; return made; };
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;
process.env.PORT = String(PORT);
const quiet = console.log;
console.log = function () {};          // the server's own boot logging
require(SERVER_PATH);
console.log = quiet;

function mounted(method, routePath) {
  return app._router.stack.some(function (l) { return l.route && l.route.path === routePath && l.route.methods[method]; });
}
function request(method, routePath) {
  return new Promise(function (resolve) {
    const req = http.request({ host: "127.0.0.1", port: PORT, method: method.toUpperCase(), path: routePath.replace(/:[a-zA-Z]+/g, "00000000-0000-0000-0000-000000000000"), timeout: 10000 },
      function (res) { res.resume(); res.on("end", function () { resolve(res.statusCode); }); });
    req.on("error", function (e) { resolve("error " + e.message); });
    req.on("timeout", function () { req.destroy(); resolve("timeout"); });
    req.end();
  });
}
function waitForListen() {
  return new Promise(function (resolve) {
    let tries = 0;
    (function poll() {
      const r = http.get({ host: "127.0.0.1", port: PORT, path: "/health", timeout: 2000 }, function (res) { res.resume(); resolve(true); });
      r.on("error", function () { if (++tries > 40) resolve(false); else setTimeout(poll, 250); });
    })();
  });
}

(async function main() {
  const listening = await waitForListen();
  console.log("\n══ server booted on " + PORT + ": " + listening + (MUTATE ? " | MUTATED (" + MUTATE + ")" : "") + " ══");
  if (!listening) { console.log("    FAIL  the server did not come up"); process.exit(1); }

  if (MUTATE === "revive") {
    app.get("/api/deals", function (req, res) { res.json({ deals: [], revived: true }); });
    // app.get appends after the 404 catch-all, which would answer first; move it up.
    const revived = app._router.stack.pop();
    let lastRouteIdx = -1;
    app._router.stack.forEach(function (l, i) { if (l.route) lastRouteIdx = i; });
    app._router.stack.splice(lastRouteIdx + 1, 0, revived);
    console.log("!! MUTATION: GET /api/deals is mounted again — its checks and the total must fail.");
  }

  /* ── 1. the 21 are gone ─────────────────────────────────────────────── */
  console.log("\n══ 1. the twenty-one deleted routes ══");
  for (const [method, routePath] of DELETED) {
    const status = await request(method, routePath);
    check(method.toUpperCase().padEnd(6) + " " + routePath + " — not in the router, answers 404", !mounted(method, routePath) && status === 404,
      "mounted=" + mounted(method, routePath) + " status=" + status);
  }

  /* ── 2. everything else still registers ─────────────────────────────── */
  console.log("\n══ 2. the routes that remain ══");
  const live = app._router.stack.filter(function (l) { return l.route; })
    .reduce(function (acc, l) { Object.keys(l.route.methods).forEach(function (m) { acc.push(m + " " + l.route.path); }); return acc; }, []);
  const missing = EXPECTED.filter(function (k) { return live.indexOf(k) === -1; });
  const extra = live.filter(function (k) { return EXPECTED.indexOf(k) === -1; });
  console.log("    routes at " + BEFORE + ": " + routeList(OLD_SRC).length + " | expected now: " + EXPECTED.length + " | registered now: " + live.length);
  check("every route that should remain is registered", missing.length === 0, missing.join(", "));
  check("and nothing else is: the total is exactly " + EXPECTED.length, live.length === EXPECTED.length && extra.length === 0, live.length + (extra.length ? " extra: " + extra.join(", ") : ""));

  /* ── 3. no code names a removed helper ──────────────────────────────── */
  console.log("\n══ 3. the removed helpers ══");
  const code = fs.readFileSync(SERVER_PATH, "utf8").replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
  for (const name of ORPHANS) {
    const hits = (code.match(new RegExp("\\b" + name + "\\b", "g")) || []).length;
    check(name + " is not referenced by any code in server.js", hits === 0, hits + " reference(s)");
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) { console.error("\nThe check threw: " + ((err && err.stack) || err)); process.exit(1); });
