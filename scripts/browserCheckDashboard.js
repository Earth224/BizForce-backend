"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   browserCheckDashboard — the dashboard's Command Center tabs and the
   Executive deck's tabs IN A REAL BROWSER (Nov 10 2026, real-browser fix and
   essentials). jsdom applies no stylesheet, so it could not see that
   `.bf-panel { display: flex }` (css/bizforce-ui.css) and `.cc-panel ul
   { display: flex }` (scripts/bf-command-center.js) beat the hidden attribute:
   every tab panel and every list fold showed at once on the owner's screen.
   This runs the installed Chrome, headless, over the Chrome DevTools Protocol
   (Node's own WebSocket and child_process; no package).

   The frontend is served from disk by a small static server on 127.0.0.1;
   every request to the API host is answered from a fixture shaped like the
   owner's account (1 social draft, 3 articles, 20 runs, 63 jobs with the two
   hourly families, 1 automatic agent, 0 plans, 0 proposals, email sending
   held), as an admin and as a member; every other outside request is refused.

   For each of the 7 dashboard tabs: click it, assert with getComputedStyle
   that only its panel is displayed and every fold is closed, and save
   <out>/<tab>.png. Then open "Show more", "Show latest" and "Show all jobs"
   and assert they open. The Executive page's six tabs: click each, assert
   only its panel shows, save <out>/exec-<tab>.png.

   NOT PART OF THE SERVER SUITE (its name does not start with "check"): run it
   by hand, last. With no Chrome it prints SKIPPED and exits 0.
     CHROME_PATH            the browser (default: the usual Windows paths)
     BIZFORCE_FRONTEND_DIR  the frontend checkout
     CC_TABS_OUT            the screenshot folder (default Downloads\cc-tabs)
     DIAGNOSE=1             also print, per hidden element still displayed,
                            the stylesheet rules that set its display
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn, execFileSync } = require("child_process");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const OUT = process.env.CC_TABS_OUT || path.join(os.homedir(), "Downloads", "cc-tabs");
const API_HOST = "dynamic-prosperity-production-5382.up.railway.app";
const DIAGNOSE = process.env.DIAGNOSE === "1";

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
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 700) + "]" : "")); }
}

/* ── the fixture: the owner's account, as GET /api/command-center answers ── */
const NOW = Date.now();
const ago = h => new Date(NOW - h * 3600000).toISOString();
const uid = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");
function centerBody(admin) {
  const runs = [];
  for (let i = 0; i < 20; i++) runs.push({ id: uid(1000 + i), agent_type: ["seo", "social", "content"][i % 3], task_type: "general", status: i === 4 ? "failed" : "completed", created_at: ago(i * 5 + 1) });
  const counts = {};
  runs.filter(r => Date.parse(r.created_at) > NOW - 7 * 86400000).forEach(r => { counts[r.agent_type] = counts[r.agent_type] || {}; counts[r.agent_type][r.status] = (counts[r.agent_type][r.status] || 0) + 1; });
  const body = {
    generated_at: new Date(NOW).toISOString(), chaining_on: true,
    needs_you: { ok: true, data: { pending_proposals: { count: 0, rows: [] }, failed_runs_7d: { count: 0, rows: [] }, email_sender: { blocked_by: ["postal_address_set"] } } },
    plans: { ok: true, data: [] },
    plan_lists: { ok: true, data: { active: [], past_count: 0, past_after_days: 14, past_latest: [] } },
    activity: { ok: true, data: { since: ago(24 * 30), since_7d: ago(24 * 7), total: 20, by_agent: {}, counts_7d: counts, newest_runs: runs.slice(0, 10), newest_runs_20: runs, sales_dry_runs: 2 } },
    autopilot: { ok: true, data: {
      autonomy: [{ agent_type: "social", enabled: true, updated_at: ago(30) }, { agent_type: "seo", enabled: false, updated_at: ago(40) }, { agent_type: "content", enabled: false, updated_at: ago(50) }],
      schedules: [{ agent_type: "social", task_type: "calendar", cadence: "weekly", hour_utc: 9, enabled: true, last_run_on: "2026-11-09" }] } },
    outbound: { ok: true, data: { email_sequences: [], social_drafts_by_status: { published: 1 }, content_published_30d: { count: 3 },
      social_latest: [{ id: uid(7000), status: "published", platform: "bluesky", preview: "Spring workshop seats are open", created_at: ago(20) }],
      articles_latest: [0, 1, 2].map(i => ({ id: uid(8000 + i), title: "Article " + (i + 1), status: "published", published_at: ago(24 * (i + 1)), created_at: ago(24 * (i + 2)) })) } },
    spend: { ok: true, data: { usd: 4.25, monthly_cap_usd: 60, resets_at: new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth() + 1, 1)).toISOString(),
      note: "Figures are estimates from token counts at list prices; the provider's bill can differ." } },
    usage: { ok: true, data: { model_calls_today: 12, model_calls_daily_cap: 250, model_calls_unavailable: null, subscription_active: true } }
  };
  if (admin) {
    const verdicts = [], jobRuns = [];
    const add = (name, cadence, ok, reason, err) => {
      verdicts.push({ job_name: name, cadence, on_time: ok, reason: ok ? null : reason });
      jobRuns.push({ job_name: name, last_run_on: "2026-11-10", finished_at: ago(1), last_error: err || null });
    };
    for (let h = 0; h < 24; h++) add("hourly_triggers_h" + String(h).padStart(2, "0"), "hourly", true);
    for (let h = 0; h < 24; h++) add("hourly_agent_schedules_h" + String(h).padStart(2, "0"), "hourly", h !== 3, "late: it has not finished within its hourly schedule");
    ["daily_store_proposals", "daily_self_reviews", "daily_youtube_retention", "ops_alert_scan", "pending_storage_deletions", "gate_decisions_sweep", "card_leads_purge",
      "oauth_states_purge", "shopify_webhook_events_purge", "member_videos_retention", "instagram_token_refresh", "facebook_choosing_purge", "schema_check", "store_sync", "nightly_backup"]
      .forEach((n, i) => add(n, i === 3 ? "every 30 minutes" : "daily", i !== 13, "the last run failed", i === 13 ? "the store answered 500" : null));
    body.platform = { ok: true, data: { job_runs: jobRuns, jobs_on_time: verdicts, job_cadence: {},
      radar_status: [{ source: "news", last_tick_finished_at: ago(1), last_outcome: "ok", last_error: null }], ceiling: { spent_usd: 3.1, cap_usd: 50 } } };
  }
  return body;
}
function apiAnswer(pathname, admin) {
  if (pathname === "/api/command-center") return centerBody(admin);
  if (pathname === "/api/auth/me") return { user: { id: uid(1), email: "owner@example.test", role: admin ? "admin" : "member" }, access: { active: true } };
  if (pathname === "/api/ai/tasks") return { tasks: [] };
  if (pathname === "/api/proposals") return { proposals: [] };
  if (pathname === "/api/agents") return { agents: [] };
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
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bf-cc-tabs-"));
  const proc = spawn(CHROME, ["--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + profile, "--no-first-run", "--no-default-browser-check",
    "--disable-gpu", "--disable-extensions", "--mute-audio", "--hide-scrollbars", "about:blank"], { stdio: "ignore" });
  const portFile = path.join(profile, "DevToolsActivePort");
  for (let i = 0; i < 150 && !fs.existsSync(portFile); i++) await sleep(100);
  if (!fs.existsSync(portFile)) throw new Error("Chrome did not open its debugging port");
  const port = fs.readFileSync(portFile, "utf8").split("\n")[0].trim();
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

async function openPage(cdp, origin, page, o) {
  const errors = [];
  await cdp.send("Page.navigate", { url: "about:blank" });
  await sleep(200);
  await cdp.send("Storage.clearDataForOrigin", { origin, storageTypes: "local_storage,session_storage" }).catch(() => {});
  const nav = cdp.send("Page.navigate", { url: origin + "/" + page + (o.hash || "") });
  await nav;
  for (let i = 0; i < 100; i++) {
    const ready = await evaluate(cdp, "document.readyState === 'complete' && !!document.getElementById('commandCenterSection') && !/Loading/.test((document.getElementById('ccStatus')||{}).textContent||'')");
    if (ready) break;
    await sleep(100);
  }
  await sleep(400);
  return errors;
}
async function evaluate(cdp, expr) {
  const r = await cdp.send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error("page threw: " + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text));
  return r.result.value;
}
async function shot(cdp, file, selector) {
  await evaluate(cdp, "(function(){var n=document.querySelector(" + JSON.stringify(selector) + "); if(n) n.scrollIntoView({block:'start'}); window.scrollBy(0,-12); return true;})()");
  await sleep(150);
  const r = await cdp.send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(file, Buffer.from(r.data, "base64"));
}

/* Page-side helpers, installed once per page. */
const HELPERS = `
window.__bf = {
  shown: function (n) { if (!n) return false; for (var e = n; e && e.nodeType === 1; e = e.parentElement) { if (getComputedStyle(e).display === "none") return false; } return true; },
  rulesSettingDisplay: function (n) {
    var out = [];
    for (var s = 0; s < document.styleSheets.length; s++) {
      var sheet = document.styleSheets[s], rules; try { rules = sheet.cssRules; } catch (e) { continue; }
      for (var i = 0; i < rules.length; i++) { var r = rules[i];
        if (r.selectorText && r.style && r.style.display) { try { if (n.matches(r.selectorText)) out.push((sheet.href ? sheet.href.replace(location.origin, "") : (sheet.ownerNode && sheet.ownerNode.id ? "style#" + sheet.ownerNode.id : "inline <style>")) + "  " + r.selectorText + " { display: " + r.style.display + (r.style.getPropertyPriority("display") ? " !important" : "") + " }"); } catch (e) {} } }
    }
    return out;
  },
  hiddenButShown: function (root) {
    var out = []; (root || document).querySelectorAll("[hidden]").forEach(function (n) { if (getComputedStyle(n).display !== "none") out.push({ id: n.id || n.className || n.tagName, rules: window.__bf.rulesSettingDisplay(n) }); }); return out;
  }
};
true`;

const CC_TABS = ["command", "plans", "activity", "autopilot", "outbound", "system", "memory"];
const EXEC_TABS = ["command", "plans", "agents", "approvals", "history", "settings"];
const FOLDS = ["ccMoreRuns", "ccAllJobs", "ccPastPlans", "ccOutboundLatest"];

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
    let admin = true, apiCalls = [];
    cdp.on(async msg => {
      if (msg.method !== "Fetch.requestPaused") return;
      const { requestId, request } = msg.params;
      const u = new URL(request.url);
      try {
        if (u.origin === origin) await cdp.send("Fetch.continueRequest", { requestId });
        else if (u.hostname === API_HOST) {
          apiCalls.push(request.method + " " + u.pathname);
          const body = request.method === "OPTIONS" ? "" : JSON.stringify(apiAnswer(u.pathname, admin));
          await cdp.send("Fetch.fulfillRequest", { requestId, responseCode: 200, body: Buffer.from(body).toString("base64"),
            responseHeaders: [{ name: "Content-Type", value: "application/json" }, { name: "Access-Control-Allow-Origin", value: "*" },
              { name: "Access-Control-Allow-Headers", value: "*" }, { name: "Access-Control-Allow-Methods", value: "GET,POST,PUT,DELETE,OPTIONS" }] });
        } else await cdp.send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
      } catch (e) { /* the page moved on */ }
    });
    const exceptions = [];
    cdp.on(msg => { if (msg.method === "Runtime.exceptionThrown") exceptions.push((msg.params.exceptionDetails.exception || {}).description || msg.params.exceptionDetails.text); });
    await cdp.send("Fetch.enable", { patterns: [{ urlPattern: "*" }] });
    await cdp.send("Runtime.enable");
    await cdp.send("Page.enable");
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false });
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{localStorage.setItem('bf_token','browser-check-token');localStorage.setItem('bf_user',JSON.stringify({id:'" + uid(1) + "',role:'admin'}));}catch(e){}" });

    /* ── the dashboard, as an admin ── */
    console.log("\n══ the dashboard, admin ══");
    apiCalls = []; exceptions.length = 0;
    await openPage(cdp, origin, "dashboard.html", {});
    await evaluate(cdp, HELPERS);
    check("the dashboard loads its Command Center from one fixture read", apiCalls.filter(c => c === "GET /api/command-center").length === 1, apiCalls.filter(c => /command-center/.test(c)).join(", "));
    check("no script error from the Command Center's scripts", !exceptions.some(e => /bf-tabs|bf-command-center/.test(e)), exceptions.filter(e => /bf-tabs|bf-command-center/.test(e)).join(" | "));
    if (DIAGNOSE) {
      const bad = await evaluate(cdp, "window.__bf.hiddenButShown(document.getElementById('commandCenterSection'))");
      console.log("\n  DIAGNOSE: hidden elements in the Command Center that are still displayed, and the rules that set their display:");
      bad.forEach(b => { console.log("    " + b.id); b.rules.forEach(r => console.log("        " + r)); });
      if (!bad.length) console.log("    (none)");
    }
    const texts = {};
    for (const tab of CC_TABS) {
      await evaluate(cdp, "document.getElementById('ccTab-" + tab + "').click(), true");
      await sleep(250);
      const st = await evaluate(cdp, "(function(){var b=window.__bf;return {sel:[].map.call(document.querySelectorAll('[data-cc-tab]'),function(t){return t.getAttribute('aria-selected')==='true'?t.getAttribute('data-cc-tab'):null}).filter(Boolean)," +
        "shown:" + JSON.stringify(CC_TABS) + ".filter(function(n){return b.shown(document.getElementById('ccPanel-'+n))}),hash:location.hash," +
        "folds:" + JSON.stringify(FOLDS) + ".filter(function(f){return b.shown(document.getElementById(f))}).concat([].filter.call(document.querySelectorAll('.cc-steps'),function(n){return b.shown(n)}).map(function(n){return n.id})),"
        + "text:(document.getElementById('ccPanel-" + tab + "')||{}).innerText||''};})()");
      texts[tab] = st.text;
      check("admin " + tab + ": the tab is selected and ONLY its panel is displayed (getComputedStyle)", st.sel.join() === tab && st.shown.join() === tab, "selected " + st.sel.join() + "; displayed " + st.shown.join());
      check("admin " + tab + ": the address is #cc-" + tab, st.hash === "#cc-" + tab, st.hash);
      check("admin " + tab + ": every fold is closed", st.folds.length === 0, st.folds.join(", "));
      await shot(cdp, path.join(OUT, tab + ".png"), "#commandCenterSection");
    }
    if (DIAGNOSE) {
      const bad = await evaluate(cdp, "window.__bf.hiddenButShown(document.getElementById('commandCenterSection')).filter(function(b){return !/^ccPanel-/.test(b.id)})");
      console.log("\n  DIAGNOSE (every tab drawn): hidden folds still displayed, and the rules that set their display:");
      bad.forEach(b => { console.log("    " + b.id); b.rules.forEach(r => console.log("        " + r)); });
      if (!bad.length) console.log("    (none)");
    }
    // The folds open on request.
    const opened = async (tab, label, id) => {
      await evaluate(cdp, "document.getElementById('ccTab-" + tab + "').click(), true"); await sleep(150);
      const r = await evaluate(cdp, "(function(){var b=[].find.call(document.querySelectorAll('#ccPanel-" + tab + " button'),function(x){return x.textContent.indexOf(" + JSON.stringify(label) + ")===0});" +
        "if(!b) return {missing:true}; var before=b.getAttribute('aria-expanded'); b.click(); return {before:before, after:b.getAttribute('aria-expanded'), shown:window.__bf.shown(document.getElementById(" + JSON.stringify(id) + "))};})()");
      check("\"" + label + "\" starts closed (aria-expanded false) and opens on a click", !r.missing && r.before === "false" && r.after === "true" && r.shown === true, JSON.stringify(r));
      return r;
    };
    await opened("activity", "Show more", "ccMoreRuns");
    await shot(cdp, path.join(OUT, "activity-show-more.png"), "#commandCenterSection");
    await opened("outbound", "Show latest", "ccOutboundLatest");
    await shot(cdp, path.join(OUT, "outbound-show-latest.png"), "#commandCenterSection");
    await opened("system", "Show all jobs", "ccAllJobs");
    await shot(cdp, path.join(OUT, "system-show-all-jobs.png"), "#commandCenterSection");
    const allRows = await evaluate(cdp, "document.querySelectorAll('#ccAllJobs > li').length");
    check("\"Show all jobs\" lists all 63", allRows === 63, allRows);
    fs.writeFileSync(path.join(OUT, "tab-text-admin.json"), JSON.stringify(texts, null, 2));

    /* ── the dashboard, as a member ── */
    console.log("\n══ the dashboard, member ══");
    admin = false;
    await openPage(cdp, origin, "dashboard.html", { hash: "#cc-system" });
    await evaluate(cdp, HELPERS);
    const mem = await evaluate(cdp, "(function(){return {shown:" + JSON.stringify(CC_TABS) + ".filter(function(n){return window.__bf.shown(document.getElementById('ccPanel-'+n))}), text:document.getElementById('ccPanel-system').innerText};})()");
    check("member: #cc-system shows only System", mem.shown.join() === "system", mem.shown.join());
    check("member: System is spend only", /^Spend: /.test(mem.text.trim()) && !/jobs|Hourly|Radar|Email sending/i.test(mem.text), mem.text);
    await shot(cdp, path.join(OUT, "system-member.png"), "#commandCenterSection");
    const memCmd = await evaluate(cdp, "document.getElementById('ccTab-command').click(), new Promise(function(r){setTimeout(function(){r(document.getElementById('ccPanel-command').innerText)},200)})");
    check("member: no platform ceiling chip", !/Platform ceiling/.test(memCmd), memCmd);
    fs.writeFileSync(path.join(OUT, "tab-text-member.json"), JSON.stringify({ command: memCmd, system: mem.text }, null, 2));

    /* ── the Executive page ── */
    console.log("\n══ the Executive page ══");
    admin = true;
    await openPage(cdp, origin, "executive-agent.html", {});
    await evaluate(cdp, HELPERS);
    for (const tab of EXEC_TABS) {
      await evaluate(cdp, "document.getElementById('deckTab-" + tab + "').click(), true");
      await sleep(250);
      const st = await evaluate(cdp, "(function(){return {sel:[].map.call(document.querySelectorAll('[data-deck-tab]'),function(t){return t.getAttribute('aria-selected')==='true'?t.getAttribute('data-deck-tab'):null}).filter(Boolean)," +
        "shown:" + JSON.stringify(EXEC_TABS) + ".filter(function(n){return window.__bf.shown(document.getElementById('deckPanel-'+n))}), hash:location.hash};})()");
      check("executive " + tab + ": selected, only its panel displayed, address #" + tab, st.sel.join() === tab && st.shown.join() === tab && st.hash === "#" + tab, JSON.stringify(st));
      await shot(cdp, path.join(OUT, "exec-" + tab + ".png"), "#execDeck");
    }
    const kept = await evaluate(cdp, "localStorage.getItem('bf_exec_tab')");
    check("executive: the last tab is kept in localStorage bf_exec_tab", kept === "settings", kept);
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
