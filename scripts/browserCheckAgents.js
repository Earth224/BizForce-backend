"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   browserCheckAgents — the agent pages' tab folders IN A REAL BROWSER
   (Nov 11 2026, agent tabs). jsdom applies no stylesheet, so a page rule can
   make a hidden panel show there unseen (the Command Center's lesson, Nov 10).
   This runs the installed Chrome, headless, over the Chrome DevTools Protocol
   (Node's own WebSocket and child_process; no package), the same way as
   scripts/browserCheckDashboard.js.

   The frontend is served from disk by a small static server on 127.0.0.1;
   every request to the API host is answered with an empty 200 (no data), and
   every other outside request is refused.

   For each of the 17 tabbed agent pages, at 1440 px:
     the tabs render (Run, Schedule, Activity, Learning, Business, and the
     page's own tab where it has one); clicking each tab shows only its panel
     (getComputedStyle up the tree); the Live Activity strip stays displayed
     above the tabs; no Live Status panel; nothing passes the screen's edge.
   At 390 px: the tab row scrolls sideways inside itself, and nothing on the
   page passes the screen's edge.
   The Executive page: its own deck, none of these tabs.
   Screenshots to <out>: <agent>-<tab>.png for ads-agent, sales and seo (every
   tab), <agent>-run.png for every other agent, and ads-agent-390.png.

   NOT PART OF THE SERVER SUITE (its name does not start with "check"): run it
   by hand, last. With no Chrome it prints SKIPPED and exits 0.
     CHROME_PATH            the browser (default: the usual Windows paths)
     BIZFORCE_FRONTEND_DIR  the frontend checkout
     AGENT_TABS_OUT         the screenshot folder (default Downloads\agent-tabs)
   NAMED (Nov 11 2026, polish): the 390 px NOTE on the live status line
   (#apLiveStatus) is a check now: below 560 px it wraps (white-space normal,
   overflow-wrap anywhere) and with a long status nothing passes 390 px on the
   17 tabbed pages and Executive; at 1440 px it keeps to one line.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn, execFileSync } = require("child_process");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const OUT = process.env.AGENT_TABS_OUT || path.join(os.homedir(), "Downloads", "agent-tabs");
const API_HOST = "dynamic-prosperity-production-5382.up.railway.app";

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
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 600) + "]" : "")); }
}

const PAGES = ["ads-agent.html", "broker-agent.html", "community-agent.html", "email-agent.html", "etsy-agent.html",
  "influencer-agent.html", "operations-agent.html", "publicist-agent.html", "rd-agent.html", "reputation-agent.html", "store-agent.html",
  "vertical-marketing-agent.html", "agents/analytics.html", "agents/content.html", "agents/sales.html", "agents/seo.html", "agents/social.html"];
const SPECIFIC = { "email-agent.html": "sequences", "store-agent.html": "store", "agents/content.html": "publishing", "agents/sales.html": "leads", "agents/seo.html": "audits", "agents/social.html": "accounts" };
const SHARED = ["run", "schedule", "activity", "learning", "business"];
const EVERY_TAB_SHOTS = ["ads-agent", "sales", "seo"];
const agentName = page => path.basename(page, ".html");
// KNOWN, NOT OURS (Nov 11 2026, agent tabs): at 390 px the Live Activity strip's status line (#apLiveStatus, nowrap)
// runs past the edge when it reads "Retrying in 120s — the request did not complete". The pre-tabs frontend (ecfd367,
// git archive) measures the same 163-431 px on all 17 pages; the strip stays unchanged by this work, so it is
// printed as a NOTE and left as an open item. Any other overflow still fails.
// NAMED (Nov 11 2026, polish): BEFORE the status line was exempted here and printed as a NOTE. AFTER it wraps below 560 px
// (scripts/agent-profile.js), so nothing is exempted: the status line is checked like everything else, and its own
// right edge and wrapping are checked too.
function splitWide(list) { return list; }

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
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bf-agent-tabs-"));
  const proc = spawn(CHROME, ["--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + profile, "--no-first-run", "--no-default-browser-check",
    "--disable-gpu", "--disable-extensions", "--mute-audio", "--hide-scrollbars", "about:blank"], { stdio: "ignore" });
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
async function openPage(cdp, origin, page, ready) {
  await cdp.send("Page.navigate", { url: "about:blank" });
  await sleep(150);
  await cdp.send("Storage.clearDataForOrigin", { origin, storageTypes: "session_storage" }).catch(() => {});
  await cdp.send("Page.navigate", { url: origin + "/" + page });
  for (let i = 0; i < 100; i++) {
    if (await evaluate(cdp, "document.readyState === 'complete' && !!document.querySelector(" + JSON.stringify(ready) + ")")) break;
    await sleep(100);
  }
  await sleep(500);
  await evaluate(cdp, HELPERS);
}
async function shot(cdp, file) {
  await evaluate(cdp, "(function(){var n=document.getElementById('apLive')||document.querySelector('.agent-header'); if(n) n.scrollIntoView({block:'start'}); window.scrollBy(0,-12); return true;})()");
  await sleep(150);
  const r = await cdp.send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(file, Buffer.from(r.data, "base64"));
}

/* Page-side helpers, installed once per page. */
const HELPERS = `
window.__bf = {
  shown: function (n) { if (!n) return false; for (var e = n; e && e.nodeType === 1; e = e.parentElement) { if (getComputedStyle(e).display === "none") return false; } return true; },
  // a closed overlay (fixed, transparent: the Business Profile modal) is not on screen
  seen: function (n) { for (var e = n; e && e.nodeType === 1; e = e.parentElement) { var cs = getComputedStyle(e); if (cs.position === "fixed" || cs.opacity === "0" || cs.visibility === "hidden") return false; } return true; },
  wide: function (W) { return [].filter.call(document.querySelectorAll("body *"), function (n) { var x = n.getBoundingClientRect(); if (!(x.width > 0 && x.right > W + 1) || !window.__bf.seen(n)) return false;
      for (var e = n.parentElement; e && e !== document.body; e = e.parentElement) { var cs = getComputedStyle(e); if (/auto|scroll|hidden|clip/.test(cs.overflowX)) { var b = e.getBoundingClientRect(); if (b.right <= W + 1) return false; } }
      return window.__bf.shown(n); })
    .slice(0, 6).map(function (n) { var x = n.getBoundingClientRect(); return n.tagName + "#" + n.id + "." + String(n.className && n.className.baseVal !== undefined ? n.className.baseVal : n.className).slice(0, 30) + " " + Math.round(x.left) + "-" + Math.round(x.right); }); }
};
true`;

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
          await cdp.send("Fetch.fulfillRequest", { requestId, responseCode: 200, body: Buffer.from(request.method === "OPTIONS" ? "" : "{}").toString("base64"),
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
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{localStorage.setItem('bf_token','browser-check-token');localStorage.setItem('bf_user',JSON.stringify({id:'00000000-0000-4000-8000-000000000001',role:'member'}));}catch(e){}" });

    const statusSeen = [];
    // NAMED (Nov 11 2026, polish): at 1440 px the status line keeps to one line (the desktop look unchanged).
    let deskStatus = null;
    for (const page of PAGES) {
      const name = agentName(page);
      const tabs = SHARED.concat(SPECIFIC[page] ? [SPECIFIC[page]] : []);
      console.log("\n══ " + page + " ══");
      await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
      exceptions.length = 0;
      await openPage(cdp, origin, page, "#agTabs");
      const base = await evaluate(cdp, "(function(){var b=window.__bf;return {tabs:[].map.call(document.querySelectorAll('#agTabs [role=tab]'),function(t){return t.getAttribute('data-ag-tab')}),row:b.shown(document.querySelector('#agTabs [role=tablist]'))," +
        "liveStatus:[].some.call(document.querySelectorAll('h1,h2,h3,h4'),function(h){return h.textContent.trim()==='Live Status'})||!!document.getElementById('apDot')," +
        "stripAbove:!!document.getElementById('apLive')&&(document.getElementById('agTabs').compareDocumentPosition(document.getElementById('apLive'))&2)===2};})()");
      check(page + ": the tabs render: " + tabs.join(", "), JSON.stringify(base.tabs) === JSON.stringify(tabs) && base.row, JSON.stringify(base.tabs));
      check(page + ": no Live Status panel; the Live Activity strip sits above the tabs", !base.liveStatus && base.stripAbove, JSON.stringify(base));
      check(page + ": no script error from bf-tabs.js or agent-profile.js", !exceptions.some(e => /bf-tabs|agent-profile/.test(e)), exceptions.filter(e => /bf-tabs|agent-profile/.test(e)).join(" | "));
      for (const tab of tabs) {
        await evaluate(cdp, "document.getElementById('agTab-" + tab + "').click(), true");
        await sleep(200);
        const st = await evaluate(cdp, "(function(){var b=window.__bf;return {sel:[].filter.call(document.querySelectorAll('#agTabs [role=tab]'),function(t){return t.getAttribute('aria-selected')==='true'}).map(function(t){return t.getAttribute('data-ag-tab')})," +
          "shown:" + JSON.stringify(tabs) + ".filter(function(n){return b.shown(document.getElementById('agPanel-'+n))}),height:document.getElementById('agPanel-" + tab + "').getBoundingClientRect().height," +
          "strip:b.shown(document.getElementById('apLive')),hash:location.hash,wide:b.wide(1440)};})()");
        check(page + " " + tab + ": selected, only its panel displayed (getComputedStyle), not empty, the strip still displayed, address #ag-" + tab,
          st.sel.join() === tab && st.shown.join() === tab && st.height > 20 && st.strip && st.hash === "#ag-" + tab, JSON.stringify(st));
        check(page + " " + tab + ": nothing passes the screen's edge at 1440 px", st.wide.length === 0, st.wide.join(" | "));
        if (EVERY_TAB_SHOTS.indexOf(name) !== -1 || tab === "run") {
          if (tab !== "run") await evaluate(cdp, "document.getElementById('agTab-" + tab + "').click(), true");
          await shot(cdp, path.join(OUT, name + "-" + tab + ".png"));
        }
      }
      if (deskStatus === null) deskStatus = await evaluate(cdp, "getComputedStyle(document.getElementById('apLiveStatus')).whiteSpace");
      await evaluate(cdp, "document.getElementById('agTab-run').click(), true");
      // 390 px: the tab row scrolls inside itself; nothing on the page passes the edge.
      await cdp.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
      await openPage(cdp, origin, page, "#agTabs");
      const m = await evaluate(cdp, "(function(){var b=window.__bf,l=document.querySelector('#agTabs [role=tablist]'),cs=getComputedStyle(l);return {scroll:cs.overflowX,wrap:cs.flexWrap,inner:l.scrollWidth,outer:l.clientWidth,right:Math.round(l.getBoundingClientRect().right),wide:b.wide(390),strip:b.shown(document.getElementById('apLive'))};})()");
      m.wide = splitWide(m.wide);
      check(page + ": at 390 px the tab row scrolls sideways inside itself, and nothing else on the page passes the screen's edge",
        m.scroll === "auto" && m.wrap === "nowrap" && m.right <= 391 && m.strip && m.wide.length === 0, JSON.stringify(m));
      // NAMED (Nov 11 2026, polish): the status line at 390 px, with the longest thing it says.
      const st = await evaluate(cdp, "(function(){var s=document.getElementById('apLiveStatus');s.textContent='Retrying in 120s \\u2014 the request did not complete';var r=s.getBoundingClientRect(),c=getComputedStyle(s);" +
        "return {ws:c.whiteSpace,wrap:c.overflowWrap,right:Math.round(r.right),lines:Math.round(r.height/parseFloat(c.lineHeight==='normal'?parseFloat(c.fontSize)*1.2:c.lineHeight)),docW:document.documentElement.scrollWidth};})()");
      statusSeen.push(name + " " + st.right + "px/" + st.lines);
      check(page + ": at 390 px the status line wraps (white-space normal, overflow-wrap anywhere) and \"Retrying in 120s — the request did not complete\" stays inside the screen",
        st.ws === "normal" && st.wrap === "anywhere" && st.right <= 390 && st.docW <= 390, JSON.stringify(st));
      if (name === "ads-agent") await shot(cdp, path.join(OUT, "ads-agent-390.png"));
    }

    console.log("\n══ executive-agent.html ══");
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
    await openPage(cdp, origin, "executive-agent.html", "#execDeck");
    const ex = await evaluate(cdp, "(function(){return {ours:!!document.getElementById('agTabs'),deck:document.querySelectorAll('[data-deck-tab]').length,liveStatus:!!document.getElementById('apDot')};})()");
    check("executive: its own deck tabs, none of the agent tabs, no Live Status", !ex.ours && ex.deck >= 6 && !ex.liveStatus, JSON.stringify(ex));
    // NAMED (Nov 11 2026, polish): the Executive page at 390 px, nothing past the edge either.
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await openPage(cdp, origin, "executive-agent.html", "#execDeck");
    const ex390 = await evaluate(cdp, "(function(){return {wide:window.__bf.wide(390),docW:document.documentElement.scrollWidth};})()");
    check("executive: at 390 px nothing on the page passes the screen's edge", ex390.wide.length === 0 && ex390.docW <= 390, JSON.stringify(ex390));
    console.log("    status line at 390 px (right edge / lines): " + statusSeen.join(", "));
    check("the status line at 1440 px stays on one line (white-space nowrap)", deskStatus === "nowrap", deskStatus);
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
