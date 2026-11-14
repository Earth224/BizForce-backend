"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   browserCheckSignIn — the sign-in page (app.html) IN A REAL BROWSER
   (NAMED Nov 13 2026, Q5b). jsdom applies no layout, so checkCardSizing can
   prove the rules but not what the browser draws. This runs the installed
   Chrome, headless, over the Chrome DevTools Protocol (Node's own WebSocket
   and child_process; no package), the same way as scripts/browserCheckSocial.js.

   The frontend is served from disk on 127.0.0.1; GET /api/billing/consent is
   answered with a long renewal sentence (so the line wraps, as the live one
   does); every other API call answers {}; every other outside request is
   refused. No account, no sign-in, nothing is sent.

   At 1440x900, 1366x768, 1280x720, 768x1024, 390x844 and 360x740:
     - no sideways scroll;
     - 1024 px and up: two columns, the brand left and the panel right, inside
       a container of at most 1080 px centred on the screen; below 1024 px one
       column, the panel centred;
     - the plan box, the renewal line and Start Subscription are three blocks,
       one under the other, none overlapping;
     - "Back to BizForce AI" is centred under the panel;
     - the footer is below everything, centred on the screen.
   app.html#create and app.html?tab=create open Create Account; app.html opens
   Sign In.
   Screenshots to <out>: signin-1440.png, signin-create-1440.png, signin-390.png.

   NOT PART OF THE SERVER SUITE (its name does not start with "check"): run it
   by hand. With no Chrome it prints SKIPPED and exits 0.
     CHROME_PATH            the browser (default: the usual Windows paths)
     BIZFORCE_FRONTEND_DIR  the frontend checkout
     SIGNIN_OUT             the screenshot folder (default Downloads\q5)
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn, execFileSync } = require("child_process");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const OUT = process.env.SIGNIN_OUT || path.join(os.homedir(), "Downloads", "q5");
const API_HOST = "dynamic-prosperity-production-5382.up.railway.app";
const CONSENT = "I agree that BizForce AI All Access renews automatically every month at $199 until I cancel, and that I can cancel at any time from Billing before the next renewal date.";

const CANDIDATES = [process.env.CHROME_PATH,
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  path.join(process.env.LOCALAPPDATA || "", "Google\\Chrome\\Application\\chrome.exe"),
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"].filter(Boolean);
const CHROME = CANDIDATES.find(p => { try { return fs.statSync(p).isFile(); } catch (e) { return false; } });
if (!CHROME) { console.log("SKIPPED  no Chrome found (set CHROME_PATH); nothing was checked."); process.exit(0); }
if (typeof WebSocket !== "function") { console.log("SKIPPED  this Node has no built-in WebSocket (Node 22 or later needed)."); process.exit(0); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 900) + "]" : "")); }
}
const J = JSON.stringify;

function answer(method, p) {
  if (/^\/api\/billing\/consent/.test(p)) return { text: CONSENT, version: "2026-10-01" };
  return {};
}

/* ── a small static server over the frontend ── */
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json",
  ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".webp": "image/webp", ".jpg": "image/jpeg", ".woff2": "font/woff2", ".mp3": "audio/mpeg" };
function serve() {
  const root = path.resolve(FRONTEND);
  const server = http.createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    if (p.endsWith("/")) p += "index.html";
    const file = path.resolve(root, "." + p);
    if (!file.startsWith(root) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end("not found"); return; }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(file).toLowerCase()] || "application/octet-stream" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise(r => server.listen(0, "127.0.0.1", () => r(server)));
}

/* ── Chrome and one page over the DevTools Protocol ── */
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function launch() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bf-signin-"));
  const proc = spawn(CHROME, ["--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + profile, "--no-first-run", "--no-default-browser-check",
    "--disable-gpu", "--disable-extensions", "--mute-audio", "about:blank"], { stdio: "ignore" });
  const portFile = path.join(profile, "DevToolsActivePort");
  for (let i = 0; i < 150 && !fs.existsSync(portFile); i++) await sleep(100);
  if (!fs.existsSync(portFile)) throw new Error("Chrome did not open its debugging port");
  let port = "";
  for (let i = 0; i < 50 && !/^\d+$/.test(port); i++) { try { port = fs.readFileSync(portFile, "utf8").split("\n")[0].trim(); } catch (e) { /* still being written */ } if (!/^\d+$/.test(port)) await sleep(100); }
  if (!/^\d+$/.test(port)) throw new Error("Chrome's debugging port could not be read");
  let list = [];
  for (let i = 0; i < 50 && !list.some(t => t.type === "page"); i++) { try { list = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json(); } catch (e) { /* not yet */ } await sleep(100); }
  const target = list.find(t => t.type === "page");
  if (!target) throw new Error("Chrome opened no page");
  return { proc, profile, ws: target.webSocketDebuggerUrl };
}
function connect(url) {
  const ws = new WebSocket(url);
  let id = 0; const waiting = new Map(), handlers = [];
  ws.onmessage = ev => {
    const msg = JSON.parse(typeof ev.data === "string" ? ev.data : Buffer.from(ev.data).toString("utf8"));
    if (msg.id && waiting.has(msg.id)) { const w = waiting.get(msg.id); waiting.delete(msg.id); if (msg.error) w.reject(new Error(msg.error.message)); else w.resolve(msg.result); }
    else if (msg.method) handlers.forEach(h => h(msg));
  };
  const send = (method, params) => new Promise((resolve, reject) => { const n = ++id; waiting.set(n, { resolve, reject }); ws.send(JSON.stringify({ id: n, method, params: params || {} })); });
  return new Promise((resolve, reject) => { ws.onopen = () => resolve({ send, on: h => handlers.push(h), close: () => ws.close() }); ws.onerror = reject; });
}
async function evaluate(cdp, expr) {
  const r = await cdp.send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error("page threw: " + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text));
  return r.result.value;
}
async function open(cdp, origin, page, w, h) {
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile: w < 600 });
  await cdp.send("Page.navigate", { url: "about:blank" });
  await sleep(150);
  await cdp.send("Page.navigate", { url: origin + "/" + page });
  for (let i = 0; i < 100; i++) {
    if (await evaluate(cdp, "document.readyState === 'complete' && !document.querySelector('[data-bf-renew-consent]').hidden && !!document.querySelector('footer.bf-legal-footer a')")) break;
    await sleep(100);
  }
  await sleep(300);
}

// Everything measured in one go, in page coordinates (scroll included).
const MEASURE = `(function(){
  var R = function (el) { var r = el.getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top + scrollY, b: r.bottom + scrollY, w: r.width, h: r.height }; };
  var q = function (s) { return document.querySelector(s); };
  var de = document.documentElement;
  // vw is the layout width (the screen less a vertical scrollbar, when the page is taller than the screen).
  return { vw: de.clientWidth, vh: innerHeight, docW: de.scrollWidth, docH: de.scrollHeight,
    wrap: R(q("main.wrap")), brand: R(q("section.brand")), panel: R(q("section.card")),
    plan: R(q(".subscribe .plan")), consent: R(q("[data-bf-renew-consent]")), sub: R(q("#subscribeBtn")),
    back: R(q(".panel-col > .forgot")), backLink: R(q(".panel-col > .forgot a")), foot: R(q("body > footer.bf-legal-footer")),
    footText: (function () { var f = q("body > footer.bf-legal-footer"), r = document.createRange(); r.selectNodeContents(f); var b = r.getBoundingClientRect(); return { l: b.left, r: b.right }; })(),
    consentShown: !q("[data-bf-renew-consent]").hidden, consentText: q("[data-bf-renew-consent-text]").textContent,
    registerShown: getComputedStyle(q("#registerForm")).display !== "none", loginShown: getComputedStyle(q("#loginForm")).display !== "none",
    registerTabActive: q("#registerTab").classList.contains("active") };
})()`;

(async () => {
  const version = execFileSync(process.platform === "win32" ? "powershell.exe" : CHROME,
    process.platform === "win32" ? ["-NoProfile", "-Command", "(Get-Item '" + CHROME + "').VersionInfo.ProductVersion"] : ["--version"]).toString().trim();
  console.log("Chrome: " + CHROME + "  (" + version + ")");
  fs.mkdirSync(OUT, { recursive: true });
  const server = await serve();
  const origin = "http://127.0.0.1:" + server.address().port;
  const chrome = await launch();
  let cdp;
  try {
    cdp = await connect(chrome.ws);
    cdp.on(async msg => {
      if (msg.method !== "Fetch.requestPaused") return;
      const { requestId, request } = msg.params;
      const u = new URL(request.url);
      try {
        if (u.origin === origin) await cdp.send("Fetch.continueRequest", { requestId });
        else if (u.hostname === API_HOST) {
          const body = request.method === "OPTIONS" ? "" : J(answer(request.method, u.pathname));
          await cdp.send("Fetch.fulfillRequest", { requestId, responseCode: 200, body: Buffer.from(body).toString("base64"),
            responseHeaders: [{ name: "Content-Type", value: "application/json" }, { name: "Access-Control-Allow-Origin", value: "*" },
              { name: "Access-Control-Allow-Headers", value: "*" }, { name: "Access-Control-Allow-Methods", value: "GET,POST,PUT,DELETE,OPTIONS" }] });
        } else await cdp.send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
      } catch (e) { /* the page moved on */ }
    });
    const exceptions = [];
    cdp.on(msg => { if (msg.method === "Runtime.exceptionThrown") { const d = msg.params.exceptionDetails; exceptions.push(((d.exception || {}).description || d.text) + " @ " + (d.url || "")); } });
    await cdp.send("Fetch.enable", { patterns: [{ urlPattern: "*" }] });
    await cdp.send("Runtime.enable");
    await cdp.send("Page.enable");

    const SIZES = [[1440, 900], [1366, 768], [1280, 720], [768, 1024], [390, 844], [360, 740]];
    const near = (a, b, tol) => Math.abs(a - b) <= (tol === undefined ? 2 : tol);
    for (const [W, H] of SIZES) {
      console.log("\n══ " + W + " x " + H + " ══");
      await open(cdp, origin, "app.html", W, H);
      const m = await evaluate(cdp, MEASURE);
      const two = W >= 1024;
      console.log("    note  container " + Math.round(m.wrap.l) + "-" + Math.round(m.wrap.r) + " (" + Math.round(m.wrap.w) + " px); brand " + Math.round(m.brand.l) + "-" + Math.round(m.brand.r) +
        "; panel " + Math.round(m.panel.l) + "-" + Math.round(m.panel.r) + " top " + Math.round(m.panel.t) + "; footer top " + Math.round(m.foot.t) + "; page " + m.docW + " x " + m.docH);
      check("no sideways scroll (page " + m.docW + " px wide on a " + m.vw + " px screen)", m.docW <= m.vw, J([m.docW, m.vw]));
      check("the container is at most 1080 px and centred on the screen", m.wrap.w <= 1080.5 && near(m.wrap.l, m.vw - m.wrap.r), J(m.wrap));
      if (two) {
        check("two columns: the brand on the left, the panel on the right, side by side, both inside the container",
          m.brand.r <= m.panel.l && m.brand.l >= m.wrap.l - 0.5 && m.panel.r <= m.wrap.r + 0.5 && m.brand.t < m.panel.b && m.panel.t < m.brand.b, J([m.brand, m.panel]));
      } else {
        check("one column: the brand above the panel, the panel centred on the screen",
          m.brand.b <= m.panel.t && near(m.panel.l, m.vw - m.panel.r), J([m.brand, m.panel]));
      }
      check("the renewal line is shown with the server's words", m.consentShown && m.consentText === CONSENT, J(m.consentText.slice(0, 60)));
      check("the plan box, the renewal line and Start Subscription are three blocks, one under the other, no overlap (gaps " +
        Math.round(m.consent.t - m.plan.b) + " and " + Math.round(m.sub.t - m.consent.b) + " px)",
        m.consent.t >= m.plan.b && m.sub.t >= m.consent.b && m.consent.h > 0 && m.sub.h > 0 &&
        m.consent.l >= m.panel.l && m.consent.r <= m.panel.r && m.sub.l >= m.panel.l && m.sub.r <= m.panel.r, J([m.plan, m.consent, m.sub]));
      check("\"Back to BizForce AI\" is under the panel and centred under it",
        m.back.t >= m.panel.b && near((m.backLink.l + m.backLink.r) / 2, (m.panel.l + m.panel.r) / 2), J([m.backLink, m.panel]));
      check("the footer is below everything and its text is centred on the screen",
        m.foot.t >= m.back.b && m.foot.t >= m.brand.b && near((m.footText.l + m.footText.r) / 2, m.vw / 2, 3), J([m.foot, m.footText]));
      check("app.html opens Sign In", m.loginShown && !m.registerShown && !m.registerTabActive, J([m.loginShown, m.registerShown]));
      if (W === 1440 || W === 390) {
        const s = await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
        fs.writeFileSync(path.join(OUT, "signin-" + W + ".png"), Buffer.from(s.data, "base64"));
      }
    }

    console.log("\n══ Create Account from the link ══");
    for (const page of ["app.html#create", "app.html?tab=create"]) {
      await open(cdp, origin, page, 1440, 900);
      const m = await evaluate(cdp, MEASURE);
      check(page + " opens Create Account (its form shown, its tab active)", m.registerShown && !m.loginShown && m.registerTabActive, J([m.registerShown, m.loginShown, m.registerTabActive]));
      check(page + ": still two balanced columns, no sideways scroll, the renewal line clear of Start Subscription",
        m.docW <= m.vw && m.brand.r <= m.panel.l && m.sub.t >= m.consent.b, J([m.docW, m.brand, m.panel]));
      if (page === "app.html#create") {
        const s = await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
        fs.writeFileSync(path.join(OUT, "signin-create-1440.png"), Buffer.from(s.data, "base64"));
      }
    }
    await open(cdp, origin, "app.html", 1440, 900);
    await evaluate(cdp, "location.hash = 'create', true");
    await sleep(200);
    const hc = await evaluate(cdp, MEASURE);
    check("a hash change to #create on the open page shows Create Account too", hc.registerShown && hc.registerTabActive, J([hc.registerShown, hc.registerTabActive]));
    check("no script error on the page", exceptions.length === 0, exceptions.join(" | "));
  } catch (e) {
    check("the harness ran to the end", false, e && e.stack || e);
  } finally {
    try { cdp && cdp.close(); } catch (e) { /* closed */ }
    try { chrome.proc.kill(); } catch (e) { /* gone */ }
    server.close();
    await sleep(500);
    try { fs.rmSync(chrome.profile, { recursive: true, force: true }); } catch (e) { /* Chrome may still hold a file */ }
  }
  console.log("\nScreenshots: " + OUT);
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})();
