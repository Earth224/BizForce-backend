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

   THE TOP HALF (Nov 10 2026, orbit top half): GET /api/dashboard/top is
   answered from a fixture (2 proposals waiting, 3 items at or below their
   reorder point, 14 orders this week, 12 card visits today, tracked visits),
   and once more for a member with no store. Chrome checks that the orbit
   renders; each portal opens only its own grid and turns to the front; the
   badges and their beams; the core opens All tools; "/" and the search, and
   Enter opens the tool; Swap survives a reload; at 390 px the portals are a
   row, the main boxes stack and the grid is one column; under reduced motion
   (Emulation.setEmulatedMedia) nothing moves. It counts the API requests the
   dashboard makes on load at frontend 889cb13 (served from git) and now.
   Screenshots to <top>: orbit-sell.png, orbit-grow.png, orbit-connect.png,
   orbit-agents.png, orbit-oracle.png, all-tools.png, search.png, swap.png,
   mobile.png and member-no-store.png.
   THE STILL STARS (Nov 11 2026, still stars): at 1440 and 390 px, 14 to 18
   Oracle stars; none has a running animation (getAnimations() empty on every
   star and its parts, no animation or transition computed), and none
   overlaps a portal's disc, the core, a portal's label or the search bar,
   measured twice, three seconds apart, while the portals drift. Screenshots
   stars-1440.png and stars-390.png to <top>.
   THE FULLER, EVEN SKY (Nov 11 2026, more and even stars): at 1440, 1024 and
   390 px, every star measured: the count is the density rule's (40 on the
   1152 x 565 panel, the same per square pixel, 18 to 48); each quadrant holds
   20% to 30% of them and each half 40% to 60%; none closer than 60% of a grid
   cell's smaller side; then the no-animation and no-overlap checks above.
   Screenshots stars-1440.png, stars-1024.png and stars-390.png.
   ONE LIVING SKY (Nov 11 2026, one living sky): "no running animation"
   became "no POSITION animation" (the stars twinkle in place now). At 1440,
   1024 and 390 px every star's centre is recorded, then each portal is
   hovered for 1 s, each clicked (its turn waited for), Escape pressed, 6 s
   waited, Refresh pressed and the figures read again: after each step every
   centre is where it was (within 0.5 px) and the panel's height is
   unchanged. The stars' getAnimations() run on opacity and transform
   scale() only, the star's own group on nothing, each part on one at most;
   they pause with the panel off the screen; none under reduced motion. At
   least three distinct halo hues are sampled from the stars as drawn.
   Screenshots one-sky-sell.png, one-sky-oracle.png, sparkle-a.png and
   sparkle-b.png (1.5 s apart).
     TOP_HALF_OUT           that folder (default Downloads\top-half)

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
const TOP_OUT = process.env.TOP_HALF_OUT || path.join(os.homedir(), "Downloads", "top-half");
// The frontend commit before the orbit, served from git once to count the dashboard's requests before.
const BEFORE_ORBIT = "889cb13";
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
/* ── the fixture for GET /api/dashboard/top ── */
let topMode = "store";   // "store": the owner's figures; "nostore": a member with no store connected
function topBody() {
  const store = topMode === "store"
    ? { connected: true, low_stock: { count: 3, names: ["Blue mug", "Tea tin", "Spoon"] }, orders_this_week: 14, orders_per_day: [1, 0, 2, 0, 1, 0, 1, 2, 3, 1, 2, 2, 3, 1] }
    : { connected: false, low_stock: { count: 0, names: [] }, orders_this_week: 0, orders_per_day: Array(14).fill(0) };
  return {
    generated_at: new Date(NOW).toISOString(),
    visits: { per_day: [3, 1, 0, 4, 2, 5, 1, 2, 6, 3, 4, 2, 5, 7], this_week: 29, last_week: 16, tracked: true },
    store, proposals_pending: 2, cards: { count: 2, views_today: 12, views_7d: 31 }, certifications: { earned: 2, total: 8 },
    wallet: { balance: 1100, exists: true }, marketplace: { orders_this_week: 0 }, self_reviews: { latest_at: ago(30) }, mailbox: { connected: true },
    counts: { crm_customers: 18, prospects: 4, leads: topMode === "store" ? 6 : null, sms_subscribers: 0, campaigns: 1, routines: 2, saved_prompts: 3, purchases: 1, bizdoc_documents: 5 },
    media: { used_bytes: 52428800, cap_bytes: 1073741824 }, agents: { running_now: [] },
    _unreadable: topMode === "store" ? [] : ["counts.leads (Lead Radar reads the owner account's leads only)"], cached: false
  };
}
function apiAnswer(pathname, admin) {
  if (pathname === "/api/dashboard/top") return topBody();
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
const OVERRIDE = {};   // path -> text, served in place of the file on disk (the before-orbit count)
function serve() {
  const root = path.resolve(FRONTEND);
  const server = http.createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    if (p.endsWith("/")) p += "index.html";
    if (Object.prototype.hasOwnProperty.call(OVERRIDE, p)) {
      res.writeHead(200, { "Content-Type": TYPES[path.extname(p).toLowerCase()] || "application/octet-stream" });
      res.end(OVERRIDE[p]); return;
    }
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
  // Chrome may still hold the file open as it writes it (EBUSY on Windows): read again for a few seconds.
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

// The still stars: how many, any animation on them, and any star box meeting a portal's disc, the core, a label or the search.
const STARS_EVAL = "(function(){var r=function(n){var x=n.getBoundingClientRect();return {l:x.left,t:x.top,r:x.right,b:x.bottom,w:x.width,h:x.height}};" +
  "var stars=[].slice.call(document.querySelectorAll('#orbitStars g.orbit-star'));" +
  // NAMED (Nov 11 2026, one living sky): the open halo is a circle (border-radius 50%), so it is measured as one.
  // NAMED (Nov 11 2026, one living sky): "moving" counts a POSITION animation: any on the star's own group, any transition,
  // any keyframe on a part that sets something other than opacity or a transform of scale() alone, or two on one part.
  "var bad=function(a){return (a.effect&&a.effect.getKeyframes?a.effect.getKeyframes():[]).some(function(f){return Object.keys(f).some(function(k){return ['offset','computedOffset','easing','composite'].indexOf(k)===-1&&k!=='opacity'&&!(k==='transform'&&/^scale\\([\\d.]+\\)$/.test(String(f[k]).trim()))})})};" +
  "var moving=stars.filter(function(g){var parts=[].slice.call(g.querySelectorAll('*'));if(g.getAnimations().length||parseFloat(getComputedStyle(g).transitionDuration)>0)return true;return parts.some(function(p){var an=p.getAnimations();return an.length>1||an.some(bad)||parseFloat(getComputedStyle(p).transitionDuration)>0})}).length;" +
  "var vis=function(n){var x=n.getBoundingClientRect();return x.width>0&&x.height>0&&getComputedStyle(n).display!=='none'&&getComputedStyle(n).visibility!=='hidden'};" +
  "var things=[].slice.call(document.querySelectorAll('.orbit-portal .orbit-disc, .orbit-portal .orbit-halo, #orbitCore, .orbit-portal-name, .orbit-search, #orbitSay')).filter(vis).map(function(n){return {n:n.className||n.id,b:r(n)}});" +
  "var hits=[];stars.forEach(function(g){var c=g.querySelector('.orbit-star-core'),k=r(c),cx=(k.l+k.r)/2,cy=(k.t+k.b)/2,rr=Number(g.getAttribute('data-r'))*(g.getAttribute('data-spiked')==='1'?6*1.15:2.2);" +
  "things.forEach(function(t){var dx=Math.max(t.b.l-cx,0,cx-t.b.r),dy=Math.max(t.b.t-cy,0,cy-t.b.b);if(/orbit-halo/.test(t.n)?Math.hypot(cx-(t.b.l+t.b.r)/2,cy-(t.b.t+t.b.b)/2)<t.b.w/2+rr:dx*dx+dy*dy<rr*rr)hits.push(g.getAttribute('data-star')+' on '+t.n)})});" +
  "var p=document.getElementById('orbitPanel').getBoundingClientRect(),sky=(document.getElementById('orbitStars').getAttribute('data-sky')||'').split(',').map(Number);" +
  "var pts=stars.map(function(g){var k=r(g.querySelector('.orbit-star-core'));return [(k.l+k.r)/2-p.left,(k.t+k.b)/2-p.top]});" +
  "return {count:stars.length,moving:moving,hits:hits,things:things.length,spiked:stars.filter(function(g){return g.getAttribute('data-spiked')==='1'}).length," +
  "large:stars.filter(function(g){return g.getAttribute('data-size')==='large'}).length,w:p.width,h:p.height,cols:sky[1],rows:sky[2],pts:pts}})()";
// The owner's density rule (Nov 11 2026): 40 stars on the 1152 x 565 panel of a 1440 px screen, the same per square pixel, 18 to 48.
const skyCount = (w, h) => Math.max(18, Math.min(48, Math.round(40 * w * h / (1152 * 565))));
async function starsAt(W, file) {
  const a = await evaluate(cdp0, STARS_EVAL);
  await sleep(3000);
  const b = await evaluate(cdp0, STARS_EVAL);
  // NAMED (Nov 11 2026, more and even stars): 14 to 18 became the density rule's count, measured, with its balance and spacing.
  const n = a.count, q = [0, 0, 0, 0];
  a.pts.forEach(pt => q[(pt[1] < a.h / 2 ? 0 : 2) + (pt[0] < a.w / 2 ? 0 : 1)]++);
  let md = Infinity; a.pts.forEach((p1, i) => a.pts.forEach((p2, j) => { if (j > i) md = Math.min(md, Math.hypot(p1[0] - p2[0], p1[1] - p2[1])); }));
  const cell = Math.min(a.w / a.cols, a.h / a.rows);
  console.log("    " + W + " px sky: panel " + Math.round(a.w) + " x " + Math.round(a.h) + ", " + n + " stars, grid " + a.cols + " x " + a.rows + ", quadrants " + q.join("/") + ", closest " + md.toFixed(1) + " px");
  check(W + " px: the density rule's " + skyCount(a.w, a.h) + " still Oracle stars for a " + Math.round(a.w) + " x " + Math.round(a.h) + " panel" + (W === 390 ? "" : ", rays on the large bright ones"),
    n === skyCount(a.w, a.h) && (W === 390 || a.spiked >= 2), JSON.stringify(Object.assign({}, a, { pts: undefined })));
  check(W + " px: each quadrant holds 20% to 30% of the stars and each half 40% to 60% (" + q.join(", ") + ")",
    n > 0 && q.every(v => v >= 0.2 * n && v <= 0.3 * n) && q[0] + q[1] >= 0.4 * n && q[0] + q[1] <= 0.6 * n && q[2] + q[3] >= 0.4 * n && q[2] + q[3] <= 0.6 * n, q.join(","));
  check(W + " px: no two stars closer than 60% of a cell's smaller side (" + (0.6 * cell).toFixed(1) + " px; closest " + md.toFixed(1) + ")", a.cols >= 2 && md >= 0.6 * cell - 0.5, md);
  // NAMED (Nov 11 2026, one living sky): "no running animation" became "no POSITION animation".
  check(W + " px: no star has a POSITION animation (getAnimations(): none on a star's group, opacity and scale() only on its parts, one at most each; no transition)", a.moving === 0 && b.moving === 0, a.moving + "/" + b.moving);
  check(W + " px: no star overlaps a portal, the open halo, the core, a label, the search or the preview and status row (twice, 3 s apart, as the portals drift)", a.things >= 13 && a.hits.length === 0 && b.hits.length === 0, a.hits.concat(b.hits).join(", "));
  await shot(cdp0, file, "#orbitTop");
}
let cdp0 = null;
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
    cdp0 = cdp;
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

    /* ── the top half: the orbit ── */
    console.log("\n══ the top half: the orbit ══");
    fs.mkdirSync(TOP_OUT, { recursive: true });
    admin = true; topMode = "store";
    const orbitReady = async () => {
      for (let i = 0; i < 80; i++) { if (await evaluate(cdp, "!!(window.BFOrbit && window.BFOrbit.state && window.BFOrbit.state.top)")) break; await sleep(100); }
      await evaluate(cdp, HELPERS); await sleep(300);
    };
    const settleCalls = async () => { let n = -1; for (let i = 0; i < 20 && n !== apiCalls.length; i++) { n = apiCalls.length; await sleep(400); } return apiCalls.slice(); };
    // The requests on load, before the orbit (frontend BEFORE_ORBIT's dashboard and its ordering module, from git) and now.
    OVERRIDE["/dashboard.html"] = execFileSync("git", ["show", BEFORE_ORBIT + ":dashboard.html"], { cwd: FRONTEND, maxBuffer: 1 << 27 });
    OVERRIDE["/scripts/bf-dashboard-order.js"] = execFileSync("git", ["show", BEFORE_ORBIT + ":scripts/bf-dashboard-order.js"], { cwd: FRONTEND, maxBuffer: 1 << 27 });
    apiCalls = [];
    await openPage(cdp, origin, "dashboard.html", {});
    const before = await settleCalls();
    delete OVERRIDE["/dashboard.html"]; delete OVERRIDE["/scripts/bf-dashboard-order.js"];
    apiCalls = []; exceptions.length = 0;
    await openPage(cdp, origin, "dashboard.html", {});
    await orbitReady();
    const after = await settleCalls();
    // GETs only: each cross-origin read here also sends a CORS preflight (OPTIONS), listed but not counted.
    const gets = l => l.filter(c => /^GET /.test(c));
    const extra = gets(after); gets(before).forEach(c => { const i = extra.indexOf(c); if (i !== -1) extra.splice(i, 1); });
    console.log("    requests on load: before (" + BEFORE_ORBIT + ") " + gets(before).length + " GET, " + before.length + " with preflights [" + gets(before).join(", ") + "]");
    console.log("    requests on load: now " + gets(after).length + " GET, " + after.length + " with preflights [" + gets(after).join(", ") + "]");
    fs.writeFileSync(path.join(TOP_OUT, "requests.json"), JSON.stringify({ before: before, now: after }, null, 2));
    check("the top half adds exactly one read on load, GET /api/dashboard/top (" + gets(before).length + " GETs before, " + gets(after).length + " now)",
      gets(after).length === gets(before).length + 1 && extra.length === 1 && extra[0] === "GET /api/dashboard/top", extra.join(", "));
    check("no script error from bf-orbit.js", !exceptions.some(e => /bf-orbit/.test(e)), exceptions.filter(e => /bf-orbit/.test(e)).join(" | "));

    const PORTAL_KEYS = ["grow", "sell", "connect", "agents", "oracle"];
    const orbitState = () => evaluate(cdp, "(function(){var b=window.__bf,O=window.BFOrbit;var ps=[].slice.call(document.querySelectorAll('.orbit-portal'));" +
      "return {open:O.state.open, pressed:ps.filter(function(p){return p.getAttribute('aria-pressed')==='true'}).map(function(p){return p.getAttribute('data-portal')})," +
      // NAMED (Nov 10 2026, visual match): every portal is drawn the same size and none is dimmed, so the old "drawn
      // largest" and "others dimmed" readings became: where each disc sits on the ring (in viewBox units), each
      // portal's opacity, which portals show a halo, and each label's box against its circle's box.
      "slots:ps.map(function(p){var st=document.getElementById('orbitStage').getBoundingClientRect(),s=st.width/680,r=p.querySelector('.orbit-disc').getBoundingClientRect();" +
      "return [p.getAttribute('data-portal'), Math.round((r.left+r.width/2-st.left)/s*10)/10, Math.round((r.top+r.height/2-st.top)/s*10)/10]})," +
      "opacity:ps.map(function(p){return getComputedStyle(p).opacity}).join()," +
      "halos:ps.filter(function(p){return b.shown(p.querySelector('.orbit-halo'))}).map(function(p){return p.getAttribute('data-portal')})," +
      "labels:ps.map(function(p){var d=p.querySelector('.orbit-disc').getBoundingClientRect(),l=p.querySelector('.orbit-portal-name').getBoundingClientRect();" +
      "return [p.getAttribute('data-portal'), p.querySelector('.orbit-portal-name').textContent, Math.round(l.top-d.bottom), Math.round(l.height), Math.round(Math.abs((l.left+l.width/2)-(d.left+d.width/2)))]})," +
      "gridShown:b.shown(document.getElementById('orbitGrid')), gridPortal:document.getElementById('orbitGrid').getAttribute('data-portal')," +
      "grid:[].map.call(document.querySelectorAll('#orbitGrid > *'),function(x){return x.getAttribute('data-card')||(x.id==='agentDirectoryLanding'?'agent-directory':'?')})," +
      "tools:(O.PORTALS.filter(function(p){return p.key===O.state.open})[0]||{tools:[]}).tools, mains:O.state.mains.slice()};})()");
    // The lower-left slot an opened portal turns to: (340 - 275 sin 36, 160 + 110 cos 36) in the 680-wide viewBox.
    const FRONT = [340 - 275 * Math.sin(36 * Math.PI / 180), 160 + 110 * Math.cos(36 * Math.PI / 180)];
    const atFront = (st, k) => { const s = st.slots.find(x => x[0] === k); return !!s && Math.abs(s[1] - FRONT[0]) < 3 && Math.abs(s[2] - FRONT[1]) < 3; };
    const labelsUnder = st => st.labels.every(l => l[2] >= 0 && l[3] <= 18 && l[4] <= 2);
    const renders = await evaluate(cdp, "(function(){var b=window.__bf;return {svg:b.shown(document.getElementById('orbitSvg')), core:b.shown(document.getElementById('orbitCore'))," +
      "portals:[].filter.call(document.querySelectorAll('.orbit-portal'),function(p){return b.shown(p)}).length, rings:document.querySelectorAll('#orbitSvg ellipse').length," +
      "main:[].map.call(document.querySelectorAll('#orbitMain > .orbit-main-box'),function(x){return x.getAttribute('data-card')}), core_text:document.getElementById('orbitCore').textContent};})()");
    check("the orbit renders: the ring, the core and five portals displayed", renders.svg && renders.core && renders.portals === 5 && renders.rings >= 2, JSON.stringify(renders));
    const coreParts = await evaluate(cdp, "[].map.call(document.querySelectorAll('#orbitCore > span, #orbitCore > strong'),function(x){return x.textContent})");
    check("the core reads This week, 29, tracked visits, All tools, and no \"%\"", JSON.stringify(coreParts) === JSON.stringify(["This week", "29", "tracked visits", "All tools"]) && renders.core_text.indexOf("%") === -1, JSON.stringify(coreParts));
    const panel = await evaluate(cdp, "(function(){var p=document.getElementById('orbitPanel'),cs=getComputedStyle(p),s=document.querySelector('.orbit-search');" +
      "return {radius:cs.borderTopLeftRadius, stars:document.querySelectorAll('#orbitStars .orbit-star').length, pw:p.getBoundingClientRect().width, ph:p.getBoundingClientRect().height, holds:p.contains(document.getElementById('orbitStage'))&&p.contains(s)," +
      "ring:[].map.call(document.querySelectorAll('#orbitSvg ellipse.orbit-ring, #orbitSvg ellipse.orbit-ring-inner'),function(e){return e.getAttribute('rx')+'/'+e.getAttribute('ry')}).join()," +
      "pill:getComputedStyle(s).borderTopLeftRadius, key:(s.querySelector('kbd.orbit-key')||{}).textContent, refresh:[(document.getElementById('orbitRefresh')||{}).getAttribute&&document.getElementById('orbitRefresh').getAttribute('aria-label'), s.contains(document.getElementById('orbitRefresh')), (document.getElementById('orbitRefresh')||{}).textContent]," +
      "hint:/Press \\/ to search/.test(document.getElementById('orbitTop').textContent)};})()");
    // NAMED (Nov 11 2026, still stars): the eight plain dots became 14 to 18 still Oracle stars.
    // NAMED (Nov 11 2026, more and even stars): 14 to 18 became the density rule's count for the panel's own size.
    check("a starfield panel (radius 18 px, the density rule's count of still Oracle stars: " + skyCount(panel.pw, panel.ph) + ") holds the orbit and the search bar",
      panel.radius === "18px" && panel.stars === skyCount(panel.pw, panel.ph) && panel.holds, JSON.stringify(panel));
    check("the rings are 275/110 and 150/60 (2.5 to 1)", panel.ring === "275/110,150/60", panel.ring);
    check("the search pill (radius 16 px) holds the \"/\" key cap and an icon Refresh named \"Refresh\"; no \"Press / to search\", no text button",
      panel.pill === "16px" && panel.key === "/" && panel.refresh[0] === "Refresh" && panel.refresh[1] === true && panel.refresh[2] === "" && !panel.hint, JSON.stringify(panel));
    check("the main boxes are Analytics and Store", renders.main.join() === "analytics,store", renders.main.join());
    const marks = await evaluate(cdp, "(function(){var b=window.__bf;return " + JSON.stringify(PORTAL_KEYS) + ".map(function(k){var g=document.querySelector('.orbit-beam[data-portal=\"'+k+'\"]');" +
      "return [k, b.shown(document.getElementById('orbitBadge-'+k)) ? document.getElementById('orbitBadge-'+k).textContent : null, !!g && b.shown(g)]});})()");
    check("badges: Agents 2 and Sell 3, no other portal", JSON.stringify(marks.map(m => [m[0], m[1]])) === JSON.stringify([["grow", null], ["sell", "3"], ["connect", null], ["agents", "2"], ["oracle", null]]), JSON.stringify(marks));
    check("beams are displayed from Sell and Agents only", JSON.stringify(marks.map(m => m[2])) === JSON.stringify([false, true, false, true, false]), JSON.stringify(marks));
    const dotAnim = await evaluate(cdp, "getComputedStyle(document.querySelector('.orbit-beam[data-portal=\"agents\"] .orbit-beam-dot')).animationName");
    check("each beam's dot travels (an animation runs on it)", dotAnim === "orbitDot", dotAnim);

    // Each portal: open it, it alone is pressed, only its grid shows, and it turns to the front.
    let st0 = await orbitState();
    check("a first visit opens Sell (3 low stock beats 2 proposals)", st0.open === "sell", st0.open);
    for (const k of ["sell", "grow", "connect", "agents", "oracle"]) {
      if (st0.open !== k) await evaluate(cdp, "document.querySelector('.orbit-portal[data-portal=\"" + k + "\"]').click(), true");
      await sleep(900);
      const st = await orbitState();
      const want = st.tools.filter(t => st.mains.indexOf(t) === -1);
      check("portal " + k + ": pressed alone, none dimmed, only its grid shown (" + want.length + " boxes)",
        st.open === k && st.pressed.join() === k && st.opacity === "1,1,1,1,1" && st.gridShown && st.gridPortal === k && st.grid.slice().sort().join() === want.slice().sort().join(), JSON.stringify({ pressed: st.pressed, opacity: st.opacity, grid: st.grid, want }));
      check("portal " + k + ": turned forward to the lower-left slot", atFront(st, k), JSON.stringify(st.slots));
      check("portal " + k + ": only it has the halo, and its label reads \"(open)\"", st.halos.join() === k && st.labels.filter(l => / \(open\)$/.test(l[1])).map(l => l[0]).join() === k, JSON.stringify({ halos: st.halos, labels: st.labels }));
      check("portal " + k + ": every label is one line, below its circle and centred under it", labelsUnder(st), JSON.stringify(st.labels));
      await shot(cdp, path.join(TOP_OUT, "orbit-" + k + ".png"), "#orbitTop");
      st0 = st;
    }
    // The AI Agent Directory box in the Agents grid (Nov 10 2026, visual match).
    await evaluate(cdp, "document.querySelector('.orbit-portal[data-portal=\"agents\"]').click(), true"); await sleep(900);
    const dir = await evaluate(cdp, "(function(){var box=document.querySelector('#orbitGrid #agentDirectoryLanding');if(!box) return null;var R=function(n){var r=n.getBoundingClientRect();return {l:r.left,r:r.right,t:r.top,b:r.bottom,w:r.width,h:r.height}};" +
      "var lis=[].slice.call(box.querySelectorAll('.orbit-dir-agent'));var icons=lis.map(function(li){return R(li.querySelector('.orbit-dir-icon'))});" +
      "var names=lis.map(function(li){var n=li.querySelector('.orbit-dir-name');return {text:n.textContent,box:R(n),li:R(li),lh:parseFloat(getComputedStyle(n).lineHeight)||14}});" +
      "var others=[].filter.call(document.querySelectorAll('#orbitGrid > *'),function(x){return x!==box}).map(function(x){return x.getBoundingClientRect().width});" +
      "var p=box.querySelector('.orbit-dir-copy'),cs=getComputedStyle(box);var inner=box.clientWidth-parseFloat(cs.paddingLeft)-parseFloat(cs.paddingRight);" +
      "return {box:R(box), others:others, icons:icons, names:names, copy:{text:p.textContent,w:p.getBoundingClientRect().width,h:p.getBoundingClientRect().height,lh:parseFloat(getComputedStyle(p).lineHeight)||20,inner:inner}," +
      "hub:R(document.querySelector('#orbitGrid #openAgentHubBtn')), full:R(document.querySelector('#orbitGrid #openAgentDirectoryBtn')), hubText:document.querySelector('#orbitGrid #openAgentHubBtn').textContent, fullText:document.querySelector('#orbitGrid #openAgentDirectoryBtn').textContent};})()");
    if (!dir) check("the Agents grid shows the AI Agent Directory box", false, "missing");
    else {
      const overlap = (a, b) => Math.min(a.r, b.r) - Math.max(a.l, b.l) > 0.5 && Math.min(a.b, b.b) - Math.max(a.t, b.t) > 0.5;
      const pairs = []; dir.icons.forEach((a, i) => dir.icons.forEach((b, j) => { if (i < j && overlap(a, b)) pairs.push(i + "-" + j); }));
      const gaps = []; dir.icons.forEach((a, i) => { const b = dir.icons[i + 1]; if (b && Math.abs(a.t - b.t) < 2) gaps.push(Math.round(b.l - a.r)); });
      const col = Math.min.apply(null, dir.others);
      check("Directory: the box spans two columns (about twice the one-column boxes)", dir.others.length > 0 && dir.box.w > 1.9 * col && dir.box.w < 2.3 * col, JSON.stringify({ box: dir.box.w, others: dir.others }));
      check("Directory: five 44 px agent circles, no two overlapping, at least 12 px apart", dir.icons.length === 5 && dir.icons.every(r => Math.round(r.w) === 44 && Math.round(r.h) === 44) && pairs.length === 0 && gaps.every(g => g >= 12),
        JSON.stringify({ pairs, gaps, sizes: dir.icons.map(r => Math.round(r.w) + "x" + Math.round(r.h)) }));
      check("Directory: SEO, Sales, Content, Analytics, Social, each on one line, under its circle and inside its column",
        dir.names.map(n => n.text).join() === "SEO,Sales,Content,Analytics,Social" &&
        dir.names.every((n, i) => n.box.h <= n.lh * 1.5 && n.box.t >= dir.icons[i].b - 0.5 && n.box.l >= n.li.l - 0.5 && n.box.r <= n.li.r + 0.5 &&
          Math.abs((n.box.l + n.box.r) / 2 - (dir.icons[i].l + dir.icons[i].r) / 2) <= 1.5), JSON.stringify(dir.names.map(n => [n.text, Math.round(n.box.h), Math.round(n.box.l), Math.round(n.box.r), Math.round(n.li.l), Math.round(n.li.r)])));
      check("Directory: the one line runs across the box's full width (at most two lines)", dir.copy.text === "Deploy specialists across SEO, sales, content, analytics and social." &&
        dir.copy.w >= dir.copy.inner - 2 && dir.copy.h <= dir.copy.lh * 2.2, JSON.stringify(dir.copy));
      check("Directory: \"Agent Hub\" and \"Full Directory\" side by side", dir.hubText === "Agent Hub" && dir.fullText === "Full Directory" && Math.abs(dir.hub.t - dir.full.t) < 2 && dir.full.l >= dir.hub.r,
        JSON.stringify({ hub: dir.hub, full: dir.full }));
      await shot(cdp, path.join(TOP_OUT, "agents-grid.png"), "#orbitGrid");
    }
    // The main boxes (Nov 10 2026, visual match).
    const mb = await evaluate(cdp, "[].map.call(document.querySelectorAll('#orbitMain > .orbit-main-box'),function(box){var R=function(n){if(!n) return null;var r=n.getBoundingClientRect();return {l:r.left,r:r.right,t:r.top,b:r.bottom}};" +
      "var big=box.querySelector('.orbit-big strong'),sec=box.querySelector('.orbit-second'),h=box.querySelector('.orbit-main-head h3'),sw=box.querySelector('.orbit-main-head .orbit-swap'),open=box.querySelector('a.bf-btn'),icon=box.querySelector('.orbit-main-head .bf-neon-icon'),spark=box.querySelector('.orbit-spark');" +
      "return {card:box.getAttribute('data-card'), descriptions:[].filter.call(box.querySelectorAll('p'),function(p){return !/orbit-big|orbit-second|orbit-live/.test(p.className)}).length," +
      "big:big?[big.textContent,getComputedStyle(big).fontSize,getComputedStyle(big).color,getComputedStyle(big).fontWeight]:null, second:sec?[sec.textContent,getComputedStyle(sec).color]:null," +
      "head:[R(h),R(sw),R(icon)], open:R(open), spark:R(spark)};})");
    const mbA = mb.find(x => x.card === "analytics") || {}, mbS = mb.find(x => x.card === "store") || {};
    const headOk = x => !!x.head && x.head.every(Boolean) && x.head[1].l > x.head[0].r && Math.min(x.head[0].b, x.head[1].b) > Math.max(x.head[0].t, x.head[1].t) && x.head[2].r <= x.head[0].l;
    check("main boxes: the icon and title left, Swap right, on one header row; no description", mb.length === 2 && mb.every(headOk) && mb.every(x => x.descriptions === 0), JSON.stringify(mb.map(x => [x.card, x.descriptions, x.head])));
    check("Analytics: 29 big and bold (26-28 px) in cyan, \"+81% on last week\" in green", !!mbA.big && mbA.big[0] === "29" && /^2[678](\.\d+)?px$/.test(mbA.big[1]) && mbA.big[2] === "rgb(34, 211, 238)" && Number(mbA.big[3]) >= 700 &&
      !!mbA.second && mbA.second[0] === "+81% on last week" && mbA.second[1] === "rgb(124, 240, 201)", JSON.stringify(mbA));
    check("Store: 3 (items low on stock) big in amber, \"14 orders this week\" in green", !!mbS.big && mbS.big[0] === "3" && /^2[678](\.\d+)?px$/.test(mbS.big[1]) && mbS.big[2] === "rgb(255, 196, 107)" &&
      !!mbS.second && mbS.second[0] === "14 orders this week" && mbS.second[1] === "rgb(124, 240, 201)", JSON.stringify(mbS));
    check("main boxes: the sparkline above the Open button, which sits at the bottom left", mb.every(x => x.spark && x.open && x.open.t >= x.spark.b - 1 && Math.abs(x.open.l - x.head[2].l) <= 2), JSON.stringify(mb.map(x => [x.spark, x.open, x.head[2]])));
    await shot(cdp, path.join(TOP_OUT, "main-boxes.png"), "#orbitMain");
    await evaluate(cdp, "document.querySelector('.orbit-portal[data-portal=\"oracle\"]').click(), true"); await sleep(900);

    await evaluate(cdp, "document.querySelector('.orbit-portal[data-portal=\"oracle\"]').click(), true"); await sleep(300);
    const folded = await orbitState();
    check("pressing the open portal again folds its grid", folded.open === null && !folded.gridShown && folded.pressed.length === 0, JSON.stringify(folded));
    const moon = await evaluate(cdp, "(function(){var m=document.querySelector('.orbit-portal[data-portal=\"oracle\"] .orbit-moon');return m ? [m.getAttribute('data-moon'), m.querySelector('title').textContent, window.BFOrbit.moonPhase(Date.now()).name] : null;})()");
    check("the Oracle portal shows tonight's moon, named in its title (" + (moon && moon[2]) + ")", !!moon && moon[0] === moon[2] && moon[1] === moon[2], JSON.stringify(moon));
    const d0 = await evaluate(cdp, "window.BFOrbit.state.base"); await sleep(1000); const d1 = await evaluate(cdp, "window.BFOrbit.state.base");
    check("folded, the orbit drifts (about 3 degrees a second)", d1 - d0 > 1.5 && d1 - d0 < 4.5, (d1 - d0).toFixed(2));

    // The core opens All tools.
    await evaluate(cdp, "document.getElementById('orbitCore').click(), true"); await sleep(300);
    const all = await evaluate(cdp, "(function(){return {shown:window.__bf.shown(document.getElementById('orbitAllTools')), groups:[].map.call(document.querySelectorAll('#orbitAllTools .orbit-group h3'),function(h){return h.textContent}), links:document.querySelectorAll('#orbitAllTools a').length};})()");
    check("the core opens All tools: Grow, Sell, Connect, Agents, Oracle, Utilities, 38 links", all.shown && all.groups.join() === "Grow,Sell,Connect,Agents,Oracle,Utilities" && all.links === 38, JSON.stringify(all));
    await shot(cdp, path.join(TOP_OUT, "all-tools.png"), "#orbitAllTools");
    await evaluate(cdp, "document.getElementById('orbitCore').click(), true"); await sleep(200);

    // "/" and the search, then Enter.
    await evaluate(cdp, "document.activeElement && document.activeElement.blur && document.activeElement.blur(), window.scrollTo(0,0), true");
    await cdp.send("Input.dispatchKeyEvent", { type: "keyDown", key: "/", code: "Slash", windowsVirtualKeyCode: 191, text: "/" });
    await cdp.send("Input.dispatchKeyEvent", { type: "keyUp", key: "/", code: "Slash", windowsVirtualKeyCode: 191 });
    await sleep(150);
    const focused = await evaluate(cdp, "[document.activeElement && document.activeElement.id, document.getElementById('orbitSearch').value]");
    check("\"/\" focuses \"Go to any tool...\" and types nothing", focused[0] === "orbitSearch" && focused[1] === "", JSON.stringify(focused));
    await cdp.send("Input.insertText", { text: "inv" });
    await sleep(250);
    const found = await evaluate(cdp, "[].map.call(document.querySelectorAll('#orbitResults li a'),function(a){return a.textContent})");
    check("typing \"inv\" lists Inventory", found.join() === "Inventory", found.join());
    await shot(cdp, path.join(TOP_OUT, "search.png"), "#orbitTop");
    const invHref = await evaluate(cdp, "window.BFOrbit.tools().inventory.href");
    await cdp.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await cdp.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    let landed = "";
    for (let i = 0; i < 40; i++) { landed = await evaluate(cdp, "location.pathname").catch(() => ""); if (landed && landed !== "/dashboard.html") break; await sleep(100); }
    check("Enter opens the tool (" + invHref + ")", landed === "/" + invHref.replace(/^\//, ""), landed);

    // Swap, then a reload keeps the choice.
    apiCalls = [];
    await openPage(cdp, origin, "dashboard.html", {});
    await orbitReady();
    await evaluate(cdp, "document.querySelectorAll('#orbitMain .orbit-swap')[1].click(), true"); await sleep(200);
    await evaluate(cdp, "document.querySelector('#orbitMain .orbit-swap-list button[data-tool=\"crm\"]').click(), true"); await sleep(300);
    const swapped = await evaluate(cdp, "[[].map.call(document.querySelectorAll('#orbitMain > .orbit-main-box'),function(x){return x.getAttribute('data-card')}).join(), localStorage.getItem('bf_main_boxes')]");
    check("Swap puts CRM System in the second main box and stores it in bf_main_boxes", swapped[0] === "analytics,crm" && swapped[1] === "[\"analytics\",\"crm\"]", JSON.stringify(swapped));
    await shot(cdp, path.join(TOP_OUT, "swap.png"), "#orbitMain");
    await cdp.send("Page.reload", {});
    await sleep(500);
    await orbitReady();
    const kept2 = await evaluate(cdp, "[].map.call(document.querySelectorAll('#orbitMain > .orbit-main-box'),function(x){return x.getAttribute('data-card')}).join()");
    check("after a reload the main boxes are still Analytics and CRM System", kept2 === "analytics,crm", kept2);
    await evaluate(cdp, "document.getElementById('orbitRefresh').click(), true");
    await sleep(800);
    check("Refresh reads GET /api/dashboard/top once more", apiCalls.filter(c => c === "GET /api/dashboard/top").length === 3, apiCalls.filter(c => /dashboard\/top/.test(c)).join(", "));

    // 1440 and 1024 px: nothing in the top half passes the screen's edge (Nov 10 2026, visual match).
    for (const W of [1440, 1024]) {
      await cdp.send("Emulation.setDeviceMetricsOverride", { width: W, height: 1000, deviceScaleFactor: 1, mobile: false });
      await openPage(cdp, origin, "dashboard.html", {});
      await orbitReady();
      await sleep(400);
      const over = await evaluate(cdp, "[].filter.call(document.querySelectorAll('#orbitTop, #orbitTop *'),function(n){var x=n.getBoundingClientRect();return x.width>0&&(x.right>" + (W + 1) + "||x.left<-1)}).map(function(n){return n.tagName+'#'+n.id+'.'+String(n.className&&n.className.baseVal!==undefined?n.className.baseVal:n.className).slice(0,40)})");
      check(W + " px: nothing in the top half passes the screen's edge", over.length === 0, over.join(" | "));
      await shot(cdp, path.join(TOP_OUT, "orbit-" + W + ".png"), "#orbitTop");
      await starsAt(W, path.join(TOP_OUT, "stars-" + W + ".png"));
    }

    // 390 px: a row of portals, stacked main boxes, one column.
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    await openPage(cdp, origin, "dashboard.html", {});
    await orbitReady();
    await evaluate(cdp, "document.querySelector('.orbit-portal[data-portal=\"sell\"]').getAttribute('aria-pressed')==='true' || document.querySelector('.orbit-portal[data-portal=\"sell\"]').click(), true");
    await sleep(300);
    const mob = await evaluate(cdp, "(function(){var b=window.__bf,r=function(n){var x=n.getBoundingClientRect();return [Math.round(x.left),Math.round(x.top),Math.round(x.width),Math.round(x.bottom)]};" +
      "return {portals:[].map.call(document.querySelectorAll('.orbit-portal'),r), svg:b.shown(document.getElementById('orbitSvg')), mains:[].map.call(document.querySelectorAll('#orbitMain > .orbit-main-box'),r)," +
      "grid:[].map.call(document.querySelectorAll('#orbitGrid > *'),r), scrollW:document.documentElement.scrollWidth," +
      "wide:[].filter.call(document.querySelectorAll('body *'),function(n){var x=n.getBoundingClientRect();return x.width>0&&x.right>391&&getComputedStyle(n).position!=='fixed'}).slice(0,8).map(function(n){var x=n.getBoundingClientRect();return n.tagName+'#'+n.id+'.'+String(n.className&&n.className.baseVal!==undefined?n.className.baseVal:n.className).slice(0,40)+' '+Math.round(x.left)+'-'+Math.round(x.right)})};})()");
    const tops = mob.portals.map(p => p[1]);
    check("390 px: the portals are one row (same top), the ring hidden", mob.portals.length === 5 && Math.max.apply(null, tops) - Math.min.apply(null, tops) <= 4 && !mob.svg, JSON.stringify(mob.portals));
    check("390 px: the main boxes stack", mob.mains.length === 2 && mob.mains[1][1] >= mob.mains[0][3] - 1 && mob.mains[0][0] === mob.mains[1][0], JSON.stringify(mob.mains));
    check("390 px: the grid is one column", mob.grid.length >= 2 && mob.grid.every(g => g[0] === mob.grid[0][0]) && mob.grid.every((g, i) => i === 0 || g[1] >= mob.grid[i - 1][3] - 1), JSON.stringify(mob.grid));
    const wideTop = await evaluate(cdp, "[].filter.call(document.querySelectorAll('#orbitTop, #orbitTop *'),function(n){var x=n.getBoundingClientRect();return x.width>0&&x.right>391}).map(function(n){return n.tagName+'#'+n.id+'.'+String(n.className&&n.className.baseVal!==undefined?n.className.baseVal:n.className).slice(0,40)})");
    check("390 px: nothing in the top half reaches past the screen's edge", wideTop.length === 0, wideTop.join(" | "));
    // The page as a whole, against the same page before the orbit: the top half may not widen it.
    const mobileWidth = async () => evaluate(cdp, "[document.documentElement.scrollWidth, [].filter.call(document.querySelectorAll('body *'),function(n){var x=n.getBoundingClientRect();return x.width>0&&x.right>391&&getComputedStyle(n).position!=='fixed'}).slice(0,3).map(function(n){return n.tagName+'#'+n.id})]");
    const nowW = await mobileWidth();
    await shot(cdp, path.join(TOP_OUT, "mobile.png"), "#orbitTop");
    await shot(cdp, path.join(TOP_OUT, "orbit-390.png"), "#orbitTop");
    await starsAt(390, path.join(TOP_OUT, "stars-390.png"));
    OVERRIDE["/dashboard.html"] = execFileSync("git", ["show", BEFORE_ORBIT + ":dashboard.html"], { cwd: FRONTEND, maxBuffer: 1 << 27 });
    OVERRIDE["/scripts/bf-dashboard-order.js"] = execFileSync("git", ["show", BEFORE_ORBIT + ":scripts/bf-dashboard-order.js"], { cwd: FRONTEND, maxBuffer: 1 << 27 });
    await openPage(cdp, origin, "dashboard.html", {});
    await sleep(600);
    const beforeW = await mobileWidth();
    delete OVERRIDE["/dashboard.html"]; delete OVERRIDE["/scripts/bf-dashboard-order.js"];
    console.log("    390 px page width: before (" + BEFORE_ORBIT + ") " + beforeW[0] + " [" + beforeW[1].join(", ") + "], now " + nowW[0] + " [" + nowW[1].join(", ") + "]");
    check("390 px: the page is no wider than before the orbit (" + beforeW[0] + " before, " + nowW[0] + " now)", nowW[0] <= Math.max(390, beforeW[0]), JSON.stringify({ beforeW, nowW }));
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false });

    /* ── ONE LIVING SKY (Nov 11 2026, one living sky): one fixed set that twinkles in place, in the Oracle's colours ── */
    console.log("\n══ one living sky: the same stars through everything, twinkling in place ══");
    const SKY_NOW = "(function(){var p=document.getElementById('orbitPanel').getBoundingClientRect(),gs=[].slice.call(document.querySelectorAll('#orbitStars g.orbit-star'));" +
      "return {h:+p.height.toFixed(2),w:+p.width.toFixed(2),same:gs.length>0&&gs[0].__bfMark===1,c:gs.map(function(g){var x=g.querySelector('.orbit-star-core').getBoundingClientRect();return [(x.left+x.right)/2-p.left,(x.top+x.bottom)/2-p.top]})}})()";
    const ANIMS = "(function(){var gs=[].slice.call(document.querySelectorAll('#orbitStars g.orbit-star'));var parts=0,groups=0,durs=[],props={},paused=0,running=0;" +
      "gs.forEach(function(g){groups+=g.getAnimations().length;[].slice.call(g.querySelectorAll('*')).forEach(function(n){n.getAnimations().forEach(function(a){parts++;if(n.classList.contains('orbit-star-halo'))durs.push(Math.round(a.effect.getTiming().duration));" +
      "if(a.playState==='paused')paused++;else if(a.playState==='running')running++;a.effect.getKeyframes().forEach(function(f){Object.keys(f).forEach(function(k){if(['offset','computedOffset','easing','composite'].indexOf(k)===-1)props[k+(k==='transform'?(/^scale\\([\\d.]+\\)$/.test(String(f[k]).trim())?':scale':':'+f[k]):'')]=1})})})})});" +
      "return {stars:gs.length,parts:parts,groups:groups,durs:durs,props:Object.keys(props).sort(),paused:paused,running:running,isPaused:document.getElementById('orbitStars').classList.contains('is-paused')}})()";
    // The stars as drawn, onto a canvas: the hue at the most coloured pixel of each star.
    const HUES = "new Promise(function(done){var s=document.getElementById('orbitStars'),p=s.getBoundingClientRect(),k=2,c=s.cloneNode(true);c.setAttribute('xmlns','http://www.w3.org/2000/svg');c.setAttribute('width',p.width);c.setAttribute('height',p.height);" +
      "var img=new Image();img.onload=function(){var cv=document.createElement('canvas');cv.width=Math.round(p.width*k);cv.height=Math.round(p.height*k);var x=cv.getContext('2d');x.scale(k,k);x.drawImage(img,0,0);" +
      "var hues={},seen=[];[].slice.call(s.querySelectorAll('g.orbit-star')).forEach(function(g){var co=g.querySelector('.orbit-star-core'),cx=Number(co.getAttribute('cx'))*k,cy=Number(co.getAttribute('cy'))*k,rr=Math.max(2,Math.ceil(Number(g.getAttribute('data-r'))*2.2*k));" +
      "var d=x.getImageData(Math.round(cx-rr),Math.round(cy-rr),2*rr+1,2*rr+1).data,best=null;for(var i=0;i<d.length;i+=4){if(d[i+3]<26)continue;var r=d[i]/255,gg=d[i+1]/255,b=d[i+2]/255,mx=Math.max(r,gg,b),mn=Math.min(r,gg,b),sat=mx?(mx-mn)/mx:0;if(!best||sat>best.sat)best={sat:sat,r:r,g:gg,b:b,mx:mx,mn:mn}}" +
      "if(!best||best.sat<0.3)return;var h,dl=best.mx-best.mn;if(best.mx===best.r)h=((best.g-best.b)/dl)%6;else if(best.mx===best.g)h=(best.b-best.r)/dl+2;else h=(best.r-best.g)/dl+4;h=(h*60+360)%360;seen.push(Math.round(h));hues[Math.round(h/30)%12]=1});" +
      "done({buckets:Object.keys(hues).length,hues:seen})};img.onerror=function(){done({buckets:-1,hues:[]})};img.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(new XMLSerializer().serializeToString(c))})";
    const sameSky = (a, b) => a.c.length === b.c.length && a.c.every((p, i) => Math.abs(p[0] - b.c[i][0]) <= 0.5 && Math.abs(p[1] - b.c[i][1]) <= 0.5);
    for (const W of [1440, 1024, 390]) {
      await cdp.send("Emulation.setDeviceMetricsOverride", W === 390 ? { width: 390, height: 844, deviceScaleFactor: 1, mobile: true } : { width: W, height: 1000, deviceScaleFactor: 1, mobile: false });
      await openPage(cdp, origin, "dashboard.html", {});
      await orbitReady();
      await sleep(600);
      await evaluate(cdp, "(document.querySelector('#orbitStars g.orbit-star').__bfMark=1, document.getElementById('orbitTop').scrollIntoView({block:'start'}), true)");
      await sleep(300);
      const base = await evaluate(cdp, SKY_NOW), log = [];
      const after = async name => { const now = await evaluate(cdp, SKY_NOW); log.push([name, sameSky(base, now) && now.same, now.h === base.h, now.h]); };
      const centreOf = sel => evaluate(cdp, "(function(){var x=document.querySelector(" + JSON.stringify(sel) + ").getBoundingClientRect();return [x.left+x.width/2,x.top+x.height/2]})()");
      let previewsShown = 0;
      for (const k of ["grow", "sell", "connect", "agents", "oracle"]) {
        const [x, y] = await centreOf(".orbit-portal[data-portal=\"" + k + "\"] .orbit-disc");
        await cdp.send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
        await sleep(1000);
        previewsShown += await evaluate(cdp, "(function(){var p=document.getElementById('orbitPreview');return !p.hidden&&p.getBoundingClientRect().height>0?1:0})()");
        await after("hover " + k);
        await cdp.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: 4, y: 4 });
        await sleep(200);
        await after("leave " + k);
      }
      for (const k of ["grow", "sell", "connect", "agents", "oracle"]) {
        const [x, y] = await centreOf(".orbit-portal[data-portal=\"" + k + "\"] .orbit-disc");
        await cdp.send("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 1 });
        await cdp.send("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: 1 });
        await sleep(900);
        await after("click " + k + " and its turn");
      }
      await cdp.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
      await cdp.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
      await sleep(400);
      await after("Escape");
      await cdp.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: 4, y: 4 });
      await sleep(6000);
      await after("6 s of drift and twinkle");
      await evaluate(cdp, "document.getElementById('orbitRefresh').click(), true");
      await sleep(900);
      await after("Refresh");
      await evaluate(cdp, "window.BFOrbit.load(), true");
      await sleep(900);
      await after("a data reload");
      const moved = log.filter(s => !s[1]).map(s => s[0]), grew = log.filter(s => !s[2]).map(s => s[0] + " " + s[3]);
      console.log("    " + W + " px: " + base.c.length + " stars, panel " + base.w + " x " + base.h + ", " + log.length + " steps, " + previewsShown + " previews shown");
      check(W + " px: one fixed set: after hovering each portal 1 s, clicking each (its turn waited for), Escape, 6 s, Refresh and a data reload, every star's centre is where it was (within 0.5 px), the same nodes",
        base.c.length > 0 && log.length === 19 && moved.length === 0, moved.join(", "));
      check(W + " px: the panel's height never changed (" + base.h + " px), with " + previewsShown + " of 5 previews shown on hover", grew.length === 0 && previewsShown === 5, grew.join(", "));
      const an = await evaluate(cdp, ANIMS);
      check(W + " px: the stars twinkle: every halo and core animated, the rays and glints too, on opacity and transform scale() only, nothing on a star's own group; seeded 2.5 to 6 s, not in unison (" + new Set(an.durs).size + " durations)",
        an.stars > 0 && an.parts >= 2 * an.stars && an.groups === 0 && an.props.every(p => p === "opacity" || p === "transform:scale") && an.props.indexOf("opacity") !== -1 &&
        an.durs.length === an.stars && an.durs.every(d => d >= 2500 && d <= 6000) && new Set(an.durs).size >= 0.8 * an.stars && an.running > 0, JSON.stringify(Object.assign({}, an, { durs: an.durs.slice(0, 8) })));
      const hues = await evaluate(cdp, HUES);
      check(W + " px: at least 3 distinct halo hues sampled from the stars as drawn (" + hues.hues.join(", ") + ")", hues.buckets >= 3, JSON.stringify(hues));
      if (W === 1440) {
        await evaluate(cdp, "window.scrollTo(0, document.documentElement.scrollHeight), true");
        await sleep(600);
        const off = await evaluate(cdp, ANIMS);
        await evaluate(cdp, "document.getElementById('orbitTop').scrollIntoView({block:'start'}), true");
        await sleep(600);
        const on = await evaluate(cdp, ANIMS);
        check("1440 px: the twinkle pauses with the panel off the screen and runs again when it is back", off.isPaused && off.paused === off.parts && off.running === 0 && !on.isPaused && on.running === on.parts,
          JSON.stringify({ off: [off.isPaused, off.paused, off.running], on: [on.isPaused, on.paused, on.running] }));
        if (await evaluate(cdp, "window.BFOrbit.state.open") !== "sell") { await evaluate(cdp, "window.BFOrbit.open('sell'), true"); await sleep(900); }
        await shot(cdp, path.join(TOP_OUT, "one-sky-sell.png"), "#orbitTop");
        const sellSky = await evaluate(cdp, SKY_NOW);
        await evaluate(cdp, "window.BFOrbit.open('oracle'), true");
        await sleep(900);
        await shot(cdp, path.join(TOP_OUT, "one-sky-oracle.png"), "#orbitTop");
        const oracleSky = await evaluate(cdp, SKY_NOW);
        check("1440 px: the same sky with Sell open and with Oracle open (one-sky-sell.png, one-sky-oracle.png)", sameSky(sellSky, oracleSky) && sameSky(base, oracleSky));
        await shot(cdp, path.join(TOP_OUT, "sparkle-a.png"), "#orbitTop");
        await sleep(1350);
        await shot(cdp, path.join(TOP_OUT, "sparkle-b.png"), "#orbitTop");
      }
    }
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false });

    // Reduced motion: no drift, the turn snaps, the dot still.
    await cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
    await openPage(cdp, origin, "dashboard.html", {});
    await orbitReady();
    await evaluate(cdp, "window.BFOrbit.fold(), true");
    const r0 = await evaluate(cdp, "document.querySelector('.orbit-portal[data-portal=\"grow\"]').style.transform"); await sleep(1200);
    const r1 = await evaluate(cdp, "document.querySelector('.orbit-portal[data-portal=\"grow\"]').style.transform");
    check("reduced motion: no drift", r0 === r1 && !!r0, r0 + " | " + r1);
    await evaluate(cdp, "document.querySelector('.orbit-portal[data-portal=\"connect\"]').click(), true"); await sleep(60);
    const snap1 = await orbitState(); await sleep(800); const snap2 = await orbitState();
    check("reduced motion: the turn snaps (Connect at the front at once, nothing moves after)", atFront(snap1, "connect") && JSON.stringify(snap1.slots) === JSON.stringify(snap2.slots), JSON.stringify(snap1.slots));
    const still = await evaluate(cdp, "getComputedStyle(document.querySelector('.orbit-beam[data-portal=\"agents\"] .orbit-beam-dot')).animationName");
    check("reduced motion: the beam's dot is still (no animation)", still === "none", still);
    // NAMED (Nov 11 2026, one living sky): no twinkle and no glint under reduced motion; each star shines steadily at full.
    const rmSky = await evaluate(cdp, ANIMS);
    const rmLook = await evaluate(cdp, "(function(){var gs=[].slice.call(document.querySelectorAll('#orbitStars g.orbit-star'));return {full:gs.every(function(g){return [].slice.call(g.querySelectorAll('.orbit-star-halo,.orbit-star-core')).every(function(n){return getComputedStyle(n).opacity==='1'})}),glints:[].filter.call(document.querySelectorAll('.orbit-star-glint'),function(n){return getComputedStyle(n).display!=='none'}).length}})()");
    check("reduced motion: no twinkle and no glint, every star at full shine (" + rmSky.stars + " stars, " + rmSky.parts + " animations)", rmSky.stars > 0 && rmSky.parts === 0 && rmLook.full && rmLook.glints === 0, JSON.stringify({ rmSky, rmLook }));
    await cdp.send("Emulation.setEmulatedMedia", { features: [] });

    // A member with no store.
    admin = false; topMode = "nostore";
    await openPage(cdp, origin, "dashboard.html", {});
    await orbitReady();
    const ns = await evaluate(cdp, "(function(){var s=document.querySelector('#orbitMain [data-card=\"store\"]');var a=s&&s.querySelector('a.orbit-connect');return {link:a?[a.textContent,a.getAttribute('href')]:null, text:s?s.innerText:'', sellBadge:window.__bf.shown(document.getElementById('orbitBadge-sell')), open:window.BFOrbit.state.open};})()");
    check("no store: \"Connect a store to see orders\" links store-agent.html, no orders figure, no Sell badge",
      !!ns.link && ns.link[0] === "Connect a store to see orders" && ns.link[1] === "store-agent.html" && !/orders this week/.test(ns.text) && !ns.sellBadge, JSON.stringify(ns));
    check("no store: the first visit opens Agents (2 proposals waiting)", ns.open === "agents", ns.open);
    await shot(cdp, path.join(TOP_OUT, "member-no-store.png"), "#orbitTop");
    topMode = "store";

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
  console.log("\nScreenshots: " + OUT + " and " + TOP_OUT);
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})();
