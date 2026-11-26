/* scripts/checkApiLimiter.js — the global API rate limit: a member's own bucket, everyone else by IP; busy pages wait and ask again.

   ══ What it proves ══════════════════════════════════════════════════════════
     K  THE KEY: server.js's apiLimiter (lifted into a vm and run on a real
        express app with the real express-rate-limit and jsonwebtoken) keys a
        request by the verified token's user id ("member:<id>", 1200 per 15
        minutes) and every other request by IP ("ip:<address>", 300 per 15
        minutes): the 301st signed-out request from one address is 429 with a
        Retry-After; a member gets 1200; two members on one address have a
        bucket each, and neither uses the address's own; a forged token (the
        wrong secret), an expired one, an unsigned one ("alg": "none") and one
        without a user id all count by IP. The Shopify webhook stays exempt.
     R  ROUTE LIMITERS UNCHANGED: authLimiter, lifted the same way, still keys
        by IP (two members' tokens on one address share its 25), and no other
        limiter in server.js uses the new key or limits.
     X  CORS: the API exposes Retry-After to the pages (Access-Control-Expose-Headers).
     P  THE PAGES: mychart.html and oracle.html hold the same bfBusyFetch, which
        on a 429 says "Busy for a moment. Trying again in N seconds." (N from
        Retry-After, at most 60, 60 when absent), waits N seconds, asks exactly
        once more and hands back that answer (a second 429 goes to the page's
        own failure message and Try again); any other status passes straight
        through. The Oracle loads go through it (mychart: numerology, natal and
        today's events; oracle: the profile, numerology and today's events),
        and when numerology fails mychart still asks for the natal chart.

   MUTATE=<name> edits the files IN MEMORY; MUTATE=all runs each in its own
   process. BIZFORCE_FRONTEND_DIR overrides the frontend location. No network
   beyond 127.0.0.1, no database. */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const http = require("http");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const lf = t => t.replace(/\r\n/g, "\n");
if (!fs.existsSync(path.join(FRONTEND, "mychart.html"))) { console.log("    FAIL  frontend not found at " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
const FILES = {
  server: lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8")),
  mychart: lf(fs.readFileSync(path.join(FRONTEND, "mychart.html"), "utf8")),
  oracle: lf(fs.readFileSync(path.join(FRONTEND, "oracle.html"), "utf8"))
};

/* Each mutation: [file, from, to]. Every one must make a check fail. */
const MUTATIONS = {
  // a member's token no longer gives a bucket of their own
  "key-by-ip-only": [["server", '      if (decoded && typeof decoded.id === "string" && decoded.id) key = "member:" + decoded.id;\n', ""]],
  // the token read without its signature checked: a forged token buys 1200
  "decode-not-verify": [["server", "jwt.verify(header.slice(7).trim(), process.env.JWT_SECRET)", "jwt.decode(header.slice(7).trim())"]],
  // an expired token still counted as its member
  "expired-accepted": [["server", "jwt.verify(header.slice(7).trim(), process.env.JWT_SECRET)", "jwt.verify(header.slice(7).trim(), process.env.JWT_SECRET, { ignoreExpiration: true })"]],
  // members held to the signed-out limit
  "member-limit-300": [["server", "var API_LIMIT_MEMBER = 1200,", "var API_LIMIT_MEMBER = 300,"]],
  // signed-out visitors given the members' limit
  "signed-out-1200": [["server", "API_LIMIT_SIGNED_OUT = 300;", "API_LIMIT_SIGNED_OUT = 1200;"]],
  // one bucket for the whole site
  "one-shared-key": [["server", "  keyGenerator: function (req) { return apiLimitKey(req); },\n", '  keyGenerator: function (req) { return "all"; },\n']],
  // the Shopify webhook limited again
  "webhook-not-skipped": [["server", '  skip: function (req) { return req.method === "POST" && req.path === "/api/webhooks/shopify"; }\n});\nvar API_LIMIT_MEMBER', "});\nvar API_LIMIT_MEMBER"]],
  // a route limiter moved onto the member key
  "auth-by-member": [["server", "const authLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 25,\n", "const authLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 25,\n  keyGenerator: function (req) { return apiLimitKey(req); },\n"]],
  // a route limiter's own limit changed
  "auth-max-changed": [["server", "const authLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 25,\n", "const authLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 50,\n"]],
  // the pages cannot read Retry-After
  "no-expose": [["server", '  res.setHeader("Access-Control-Expose-Headers", "Retry-After");\n', ""]],
  // no 60-second cap
  "no-cap": [["mychart", "        n = Math.min(60, n > 0 ? n : 60);\n", "        n = n > 0 ? n : 60;\n"]],
  // no second try: the 429 goes straight to the failure
  "no-retry": [["mychart", ".then(function () { return fetch(url, opts); });", ".then(function () { return r; });"]],
  // asks again at once, without waiting
  "retry-no-wait": [["mychart", "setTimeout(ok, n * 1000)", "setTimeout(ok, 0)"]],
  // the busy line not shown
  "no-busy-line": [["mychart", '        try { if (show) show("Busy for a moment. Trying again in " + n + " seconds."); } catch (e) {}\n', ""]],
  // the two pages' copies drift apart
  "oracle-helper-drifts": [["oracle", '"Busy for a moment. Trying again in "', '"Busy. Retrying in "']],
  // mychart's natal load no longer waits out a 429
  "natal-not-busy": [["mychart", 'natalFetchPromise = window.bfBusyFetch(API_URL + "/api/oracle/natal", {', 'natalFetchPromise = fetch(API_URL + "/api/oracle/natal", {']],
  // oracle's today strip no longer waits out a 429
  "oracle-today-not-busy": [["oracle", 'return window.bfBusyFetch(API_URL + "/api/calendar/events?startJdn=', 'return fetch(API_URL + "/api/calendar/events?startJdn=']],
  // a failed numerology request leaves the natal chart unasked again
  "numerology-fail-no-natal": [["mychart", "          // orbit nor the sigil drew. AFTER natal is asked anyway: the orbit and the sigil draw from it on their own.\n          loadAndRenderOrbit();\n", "          // orbit nor the sigil drew. AFTER natal is asked anyway: the orbit and the sigil draw from it on their own.\n"]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const J = JSON.stringify;
function sliceOf(text, from, to) {
  const a = text.indexOf(from); if (a === -1) return "";
  const b = text.indexOf(to, a + from.length); return b === -1 ? "" : text.slice(a, b);
}

/* ── the limiters, lifted from server.js into one vm, on real express ── */
const SECRET = "check-api-limiter-secret";
const LIMITER_DEF = sliceOf(FILES.server, "const apiLimiter = rateLimit({", "\nconst authLimiter");
const AUTH_DEF = sliceOf(FILES.server, "const authLimiter = rateLimit({", "\n});\n") + "\n});";
async function startApp() {
  const express = require("express"), rateLimit = require("express-rate-limit"), jwt = require("jsonwebtoken");
  const ctx = { rateLimit, jwt, process: { env: { JWT_SECRET: SECRET } } };
  vm.createContext(ctx);
  vm.runInContext(LIMITER_DEF.replace("const apiLimiter", "this.apiLimiter") + "\n" + AUTH_DEF.replace("const authLimiter", "this.authLimiter") +
    "\nthis.apiLimitKey = apiLimitKey;", ctx, { filename: "server.js (limiters)" });
  const app = express();
  app.set("trust proxy", 1);
  app.use("/api/auth", ctx.authLimiter);
  app.use(ctx.apiLimiter);
  app.get("/api/x", (req, res) => res.status(200).json({ ok: true }));
  app.post("/api/webhooks/shopify", (req, res) => res.status(200).json({ ok: true }));
  app.post("/api/auth/login", (req, res) => res.status(200).json({ ok: true }));
  const server = await new Promise(r => { const sv = app.listen(0, "127.0.0.1", () => r(sv)); });
  return { server, port: server.address().port, ctx };
}
const agent = new http.Agent({ keepAlive: true, maxSockets: 8 });
function req(port, method, p, ip, token) {
  return new Promise((resolve, reject) => {
    const headers = { "X-Forwarded-For": ip };
    if (token) headers.Authorization = "Bearer " + token;
    const r = http.request({ host: "127.0.0.1", port, method, path: p, headers, agent }, res => {
      res.resume(); res.on("end", () => resolve({ status: res.statusCode, retryAfter: res.headers["retry-after"], limit: res.headers["ratelimit-limit"] }));
    });
    r.on("error", reject); r.end();
  });
}
async function many(port, n, method, p, ip, token) {
  const out = []; for (let i = 0; i < n; i++) out.push(await req(port, method, p, ip, token)); return out;
}
const okCount = rs => rs.filter(r => r.status === 200).length;

/* ── the pages' helper, lifted and run with a fake fetch and clock ── */
const HELPER_FROM = "window.bfBusyFetch = window.bfBusyFetch || function (url, opts, show) {";
function helperOf(page) { const t = sliceOf(FILES[page], HELPER_FROM, "\n    };\n"); return t ? t + "\n    };" : ""; }
async function runHelper(answers, opts) {
  opts = opts || {};
  const calls = [], waits = [], shown = [];
  const ctx = {
    window: {},
    fetch: (url, o) => { calls.push(url); const a = answers[Math.min(calls.length - 1, answers.length - 1)];
      return Promise.resolve({ status: a.status, ok: a.status >= 200 && a.status < 300, headers: { get: k => (k === "Retry-After" ? (a.retryAfter === undefined ? null : String(a.retryAfter)) : null) } }); },
    setTimeout: (fn, ms) => { waits.push(ms); fn(); return 1; }
  };
  vm.createContext(ctx);
  vm.runInContext(helperOf(opts.page || "mychart"), ctx);
  const show = opts.throwingShow ? () => { shown.push("x"); throw new Error("show broke"); } : m => shown.push(m);
  const r = await ctx.window.bfBusyFetch("https://api.example/api/oracle/natal", { headers: {} }, show);
  return { calls: calls.length, waits, shown, status: r.status };
}

async function main() {
  const jwt = require("jsonwebtoken");
  const now = Math.floor(Date.now() / 1000);
  const tok = id => jwt.sign({ id }, SECRET, { expiresIn: "1h" });
  const M1 = "11111111-1111-4111-8111-111111111111", M2 = "22222222-2222-4222-8222-222222222222", M3 = "33333333-3333-4333-8333-333333333333";

  console.log("\n══ K. the key ══");
  check("K0. apiLimiter and authLimiter were found in server.js", LIMITER_DEF.length > 200 && /^const authLimiter = rateLimit\(\{/.test(AUTH_DEF), LIMITER_DEF.length);
  const { server, port, ctx } = await startApp();
  try {
    const fake = { ip: "203.0.113.9", headers: { authorization: "Bearer " + tok(M1) } };
    const fake2 = { ip: "203.0.113.9", headers: {} };
    check("K1. the key: a verified member is member:<their id>, a signed-out request ip:<address>, worked out once per request",
      ctx.apiLimitKey(fake) === "member:" + M1 && ctx.apiLimitKey(fake2) === "ip:203.0.113.9" && fake.bfApiLimitKey === "member:" + M1, ctx.apiLimitKey(fake) + " " + ctx.apiLimitKey(fake2));

    const A = await many(port, 301, "GET", "/api/x", "198.51.100.1");
    const last = A[300];
    check("K2. signed out: 300 from one address, the 301st is 429 with a Retry-After (in seconds, at most the 15-minute window)",
      okCount(A.slice(0, 300)) === 300 && last.status === 429 && +last.retryAfter > 0 && +last.retryAfter <= 900 && A[0].limit === "300", J([okCount(A.slice(0, 300)), last, A[0].limit]));

    const B = await many(port, 1201, "GET", "/api/x", "198.51.100.2", tok(M1));
    check("K3. a member: 1200 of their own, the 1201st is 429 with a Retry-After",
      okCount(B.slice(0, 1200)) === 1200 && B[1200].status === 429 && +B[1200].retryAfter > 0 && B[0].limit === "1200", J([okCount(B.slice(0, 1200)), B[1200], B[0].limit]));
    const B2 = await req(port, "GET", "/api/x", "198.51.100.2", tok(M2));
    const B3 = await req(port, "GET", "/api/x", "198.51.100.2");
    const B4 = await req(port, "GET", "/api/x", "198.51.100.77", tok(M1));
    check("K4. two members on one address: the second has a bucket of their own (200 while the first is spent), the address's own 300 is untouched, and the first is still spent from another address",
      B2.status === 200 && B2.limit === "1200" && B3.status === 200 && B3.limit === "300" && B4.status === 429, J([B2, B3, B4]));

    const C = await many(port, 300, "GET", "/api/x", "198.51.100.3");
    const forged = jwt.sign({ id: M3 }, "not-the-secret", { expiresIn: "1h" });
    const expired = jwt.sign({ id: M3, iat: now - 7200, exp: now - 3600 }, SECRET);
    const unsigned = Buffer.from(J({ alg: "none", typ: "JWT" })).toString("base64url") + "." + Buffer.from(J({ id: M3 })).toString("base64url") + ".";
    const noId = jwt.sign({ email: "x@example.com" }, SECRET, { expiresIn: "1h" });
    const CF = await req(port, "GET", "/api/x", "198.51.100.3", forged);
    const CE = await req(port, "GET", "/api/x", "198.51.100.3", expired);
    const CU = await req(port, "GET", "/api/x", "198.51.100.3", unsigned);
    const CN = await req(port, "GET", "/api/x", "198.51.100.3", noId);
    const CG = await req(port, "GET", "/api/x", "198.51.100.3", "garbage");
    check("K5. a forged token (the wrong secret) counts by IP: the address's 300 spent, it is 429", okCount(C) === 300 && CF.status === 429 && CF.limit === "300", J(CF));
    check("K6. ... and so do an expired token, an unsigned one (alg none), one without a user id, and a malformed one",
      [CE, CU, CN, CG].every(r => r.status === 429 && r.limit === "300"), J([CE, CU, CN, CG]));

    const W = await many(port, 4, "POST", "/api/webhooks/shopify", "198.51.100.1");
    check("K7. the Shopify webhook stays exempt (its address already spent: four deliveries, four 200s)", W.every(r => r.status === 200), J(W.map(r => r.status)));

    console.log("\n══ R. route limiters unchanged ══");
    // two members not yet spent on apiLimiter, which every /api request also passes
    const M4 = "44444444-4444-4444-8444-444444444444", M5 = "55555555-5555-4555-8555-555555555555";
    const R1 = await many(port, 25, "POST", "/api/auth/login", "198.51.100.4", tok(M4));
    const R2 = await req(port, "POST", "/api/auth/login", "198.51.100.4", tok(M5));
    const R3 = await req(port, "POST", "/api/auth/login", "198.51.100.5", tok(M4));
    check("R1. authLimiter still keys by address and still allows 25: two members' tokens on one address share it (the 26th, the other member's, is 429; another address is not)",
      okCount(R1) === 25 && R2.status === 429 && R2.limit === "25" && R3.status === 200, J([okCount(R1), R2, R3]));
  } finally { server.close(); agent.destroy(); }
  const blocks = FILES.server.split(/(?=\nconst \w+ = rateLimit\(\{)/).slice(1).map(b => sliceOf(b, "\nconst ", "\n});").slice(1));
  const others = blocks.filter(b => b.indexOf("const apiLimiter =") !== 0);
  const touched = others.filter(b => /apiLimitKey|API_LIMIT_|bfApiLimitKey/.test(b)).map(b => b.slice(6, 40));
  check("R2. no other limiter in server.js uses the member key or its limits (" + others.length + " route limiters)", others.length >= 30 && touched.length === 0, touched.join(", "));
  check("R3. apiLimitKey is the key of apiLimiter alone", (FILES.server.match(/keyGenerator: function \(req\) \{ return apiLimitKey\(req\); \}/g) || []).length === 1);

  console.log("\n══ X. CORS ══");
  const cors = sliceOf(FILES.server, 'res.setHeader("Access-Control-Allow-Headers"', 'if (req.method === "OPTIONS")');
  check("X1. the API exposes Retry-After to the pages (in the CORS middleware, before the preflight answer)", /res\.setHeader\("Access-Control-Expose-Headers", "Retry-After"\);/.test(cors), cors.slice(0, 120));

  console.log("\n══ P. the pages ══");
  const hm = helperOf("mychart"), ho = helperOf("oracle");
  check("P1. mychart.html and oracle.html hold the same bfBusyFetch", hm.length > 300 && hm === ho, hm.length + " vs " + ho.length);
  const p2 = await runHelper([{ status: 429, retryAfter: 7 }, { status: 200 }]);
  check("P2. a 429 with Retry-After 7: says \"Busy for a moment. Trying again in 7 seconds.\", waits 7 s, asks once more and hands back that answer",
    J(p2.shown) === J(["Busy for a moment. Trying again in 7 seconds."]) && J(p2.waits) === J([7000]) && p2.calls === 2 && p2.status === 200, J(p2));
  const p3a = await runHelper([{ status: 429, retryAfter: 500 }, { status: 200 }]);
  const p3b = await runHelper([{ status: 429 }, { status: 200 }]);
  const p3c = await runHelper([{ status: 429, retryAfter: "soon" }, { status: 200 }]);
  check("P3. N is at most 60 (Retry-After 500 waits 60 s), and 60 when Retry-After is absent or unreadable",
    [p3a, p3b, p3c].every(r => J(r.waits) === J([60000]) && r.shown[0] === "Busy for a moment. Trying again in 60 seconds."), J([p3a, p3b, p3c]));
  const p4 = await runHelper([{ status: 429, retryAfter: 3 }, { status: 429, retryAfter: 3 }, { status: 200 }]);
  check("P4. a second 429 goes back to the page (its own failure message and Try again): exactly two requests, one wait", p4.calls === 2 && p4.status === 429 && p4.waits.length === 1, J(p4));
  const p5 = await runHelper([{ status: 500 }]);
  const p5b = await runHelper([{ status: 200 }]);
  check("P5. any other status passes straight through: one request, no wait, nothing shown", p5.calls === 1 && p5.status === 500 && p5.waits.length === 0 && p5.shown.length === 0 && p5b.calls === 1 && p5b.status === 200, J([p5, p5b]));
  const p6 = await runHelper([{ status: 429, retryAfter: 2 }, { status: 200 }], { throwingShow: true });
  check("P6. a page whose busy line throws still asks again", p6.calls === 2 && p6.status === 200, J(p6));
  const p7 = await runHelper([{ status: 429, retryAfter: 4 }, { status: 200 }], { page: "oracle" });
  check("P7. oracle.html's copy behaves the same", p7.calls === 2 && J(p7.waits) === J([4000]) && p7.shown[0] === "Busy for a moment. Trying again in 4 seconds.", J(p7));
  const via = (page, url) => FILES[page].split("window.bfBusyFetch(API_URL + \"" + url).length - 1;
  check("P8. mychart.html's numerology, natal and today's-events loads go through bfBusyFetch",
    via("mychart", "/api/oracle/numerology\"") === 1 && via("mychart", "/api/oracle/natal\"") === 1 && via("mychart", "/api/calendar/events?startJdn=") === 1);
  check("P9. oracle.html's profile, numerology and today's-events loads go through bfBusyFetch",
    via("oracle", "/api/oracle/sync\"") === 1 && via("oracle", "/api/oracle/numerology\"") === 1 && via("oracle", "/api/calendar/events?startJdn=") === 1);
  const failBranch = sliceOf(FILES.mychart, "        } else if (numerologyFailed) {", "        } else {");
  check("P10. when numerology fails, mychart.html still asks for the natal chart (the orbit and sigil draw)", /appendChartRetry\(freshStage\.firstChild\);[\s\S]*\n          loadAndRenderOrbit\(\);\n$/.test(failBranch), failBranch.slice(-160));

  console.log("\n" + passes + " passed, " + failures + " failed");
  console.log(failures ? "CHECKS FAILED" : "ALL CHECKS PASSED");
  process.exit(failures ? 1 : 0);
}
main().catch(e => { console.log("    FAIL  the check crashed: " + (e && e.stack || e)); process.exit(1); });
