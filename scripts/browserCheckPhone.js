"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   browserCheckPhone — every member page on a phone, IN A REAL BROWSER (PH1,
   Nov 19 2026). The owner runs BizForce as an installed phone app (about 390
   px wide). This runs the installed Chrome, headless, over the Chrome DevTools
   Protocol (Node's own WebSocket and child_process; no package), the same way
   as scripts/browserCheckSocial.js.

   The frontend is served from disk on 127.0.0.1. Requests to the API host are
   answered from the fixtures below (browserCheckDashboard's, browserCheckAgents'
   and browserCheckSocial's: an owner named Rose, 18 agents, 20 runs, 11
   proposals, a connected Shopify store, analytics); every other outside
   request is refused. Math.random is seeded and the clock starts at a fixed
   time (Nov 19 2026, 17:00 UTC) and then runs, so a page draws the same and
   prints the same dates each run.

   THE PAGES are every page in lib/appMap.json (77), in batches of at most 15
   (PHONE_BATCH=1..6), or smaller batches (PHONE_SIZE=5 PHONE_BATCH=1..16), or a list
   (PHONE_PAGES=dashboard.html,oracle.html). PHONE_ONLY=phone runs only the
   three phone sizes and PHONE_ONLY=desktop only 1440, so a batch fits in a
   command on a busy machine.

   PHONE SIZES 360 x 780, 390 x 844 and 430 x 932: touch, a phone's user agent,
   deviceScaleFactor 2. DESKTOP 1440 x 900, with animations paused (injected
   CSS: animation-play-state paused, transition none) from the first paint.

   PHONE_MODE=before   STEP 1. Screenshots to <out>/before; per page and phone
                       width the defect list (below) to <out>/defects-before-<batch>.json;
                       at 1440 the bounding box of every visible element to
                       <out>/desktop-baseline-<batch>.json, measured twice 700
                       ms apart (an element that moved between the two, a JS
                       animation, is set aside as moving).
   PHONE_MODE=check    (the default) STEP 3. Screenshots to <out>/after, and
                       at each phone width, on every page:
                         no horizontal scroll;
                         no text cut off (an ellipsis, a line clamp, or text
                         clipped by its own box or a hidden-overflow ancestor;
                         this covers the header, the orbit, the agent tiles
                         and the dashboard cards);
                         no fixed element (the Guide button, the music button,
                         a toast) over a heading, text, a button or a link, at
                         rest and at the end of the page (the Guide is judged at
                         the end, where its spacer must keep it clear: mid-page
                         it floats over the scrolling content by design);
                         every tap target at least 44 x 44 (a link inside a
                         sentence is exempt, WCAG 2.5.8; a checkbox or radio is
                         measured by its label);
                         no decoration (stars, nebula glows, the mist) painted
                         over text (a decoration that moves on its own, an
                         aria-hidden fixed overlay, is set aside at 1440 only);
                         no empty gap over 48 px inside a card.
                       On the dashboard: the orbit's five portals sit on a
                       circle round the core (equal distance within 2 px),
                       every label is shown in full, no two labels overlap and
                       none overlaps the core, each disc is 44 px or more, no
                       empty space above the orbit, THIS WEEK and the goal
                       button under it at the card's width; the top bar's two
                       rows (brand, music, avatar; AGENTS, the orb, TERMAXIMUS)
                       with Settings and Sign Out off it; the R avatar opens a menu with Settings and Sign
                       Out, Settings goes to settings.html and Sign Out signs
                       out (bf_token removed, the sign-in page).
                       At 1440 every element of the baseline is matched by an
                       element of the same tag, id and text whose box is
                       within 1 px, and no new element is visible.

     CHROME_PATH            the browser (default: the usual Windows paths)
     BIZFORCE_FRONTEND_DIR  the frontend checkout
     PHONE_OUT              the folder (default Downloads\phone1)

   NOT PART OF THE SERVER SUITE (its name does not start with "check"): run it
   by hand. With no Chrome it prints SKIPPED and exits 0.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const OUT = process.env.PHONE_OUT || path.join(os.homedir(), "Downloads", "phone1");
const MODE = process.env.PHONE_MODE === "before" ? "before" : "check";
const API_HOST = "dynamic-prosperity-production-5382.up.railway.app";
const ONLY = process.env.PHONE_ONLY || "";   // "desktop" or "phone": one half of the run (a loaded machine runs fewer pages a minute)
const PHONES = ONLY === "desktop" ? [] : [[360, 780], [390, 844], [430, 932]];
const DESK = [1440, 900];
const IPHONE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

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

/* ── the pages ── */
const MAP = JSON.parse(fs.readFileSync(path.join(REPO, "lib", "appMap.json"), "utf8"));
const ALL = Object.keys(MAP.pages).map(k => String(MAP.pages[k].p || "/" + k).replace(/^\//, ""));
let PAGES = ALL, BATCH = "all";
if (process.env.PHONE_PAGES) { PAGES = process.env.PHONE_PAGES.split(",").map(s => s.trim()).filter(Boolean); BATCH = "list"; }
else if (process.env.PHONE_BATCH) { const b = Number(process.env.PHONE_BATCH), n = Math.min(15, Number(process.env.PHONE_SIZE) || 15); PAGES = ALL.slice((b - 1) * n, b * n); BATCH = (n === 15 ? "" : "s" + n + "-") + b; }
if (PAGES.length > 15) { console.log("At most 15 pages a run: set PHONE_BATCH=1.." + Math.ceil(ALL.length / 15) + " or PHONE_PAGES."); process.exit(1); }
const fileOf = (page, w, h) => page.replace(/[\/\\]/g, "_").replace(/\.html$/, "") + "-" + w + "x" + h + ".png";

/* ── fixtures (an owner named Rose; the checks' own answers) ── */
// The clock is fixed: the fixtures and the page both read 2026-11-19 17:00 UTC (the page's clock then runs on from there),
// so every date and time drawn is the same in every run.
const NOW = Date.UTC(2026, 10, 19, 17, 0, 0);
const ago = h => new Date(NOW - h * 3600000).toISOString();
const uid = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");
const ROSE = { id: uid(1), email: "rose@example.test", full_name: "Rose", username: "rose", role: "admin", created_at: ago(24 * 60) };
const AGENTS = [
  ["executive", "Executive"], ["ads", "Ads"], ["broker", "Broker"], ["community", "Community"], ["email", "Email"], ["etsy", "Etsy"],
  ["influencer", "Influencer"], ["operations", "Operations"], ["publicist", "Publicist"], ["rd", "R&D"], ["reputation", "Reputation"],
  ["store", "Store"], ["vertical_marketing", "Vertical Marketing"], ["analytics", "Analytics"], ["content", "Content"], ["sales", "Sales"],
  ["seo", "SEO"], ["social", "Social"]
].map(([type, name], i) => ({ agent_type: type, name: name + " Agent", status: i % 5 === 0 ? "running" : "idle", enabled: true, active: true, last_run_at: ago(i * 3 + 1), runs_7d: 3 + (i * 7) % 11 }));
const RUNS = [];
for (let i = 0; i < 20; i++) {
  const type = ["seo", "social", "content", "sales", "store"][i % 5];
  RUNS.push({ id: uid(1000 + i), agent_type: type, task_type: "general", status: i === 4 ? "failed" : "completed",
    title: ["Audit the bakery homepage", "Plan this week's posts", "Draft the spring cakes article", "Follow up warm leads", "Check low stock"][i % 5],
    input: "Weekly task", result: i === 4 ? null : "Done. Summary ready to review.", error: i === 4 ? "The store answered 500" : null,
    created_at: ago(i * 5 + 1), completed_at: ago(i * 5 + 0.8) });
}
const IG_URL = "https://www.instagram.com/reel/AbCdEf123/";
const VIDEOS = [
  { id: "22222222-2222-4222-8222-222222222222", label: "Spring cakes", bytes: 3 * 1048576, mime: "video/mp4", status: "ready", created_at: ago(30), instagram_status: "not_sent", instagram_post_url: null, facebook_status: "not_sent", facebook_post_url: null },
  { id: "44444444-4444-4444-8444-444444444444", label: "Bread day", bytes: 3 * 1048576, mime: "video/mp4", status: "ready", created_at: ago(60), instagram_status: "posted", instagram_post_url: IG_URL, facebook_status: "pending", facebook_post_url: null }
];
const REEL = { id: VIDEOS[0].id, bytes: 3145728 };
let pn = 0;
const prop = (action_type, title, payload, extra) => Object.assign({ id: "p" + (++pn), agent_type: "social", status: "pending", title: title, reasoning: "Suggested from this week's orders.",
  created_at: ago(pn * 2), execution_result: null, execution_error: null, action_type: action_type, payload: payload }, extra || {});
const PROPOSALS = [
  prop("publish_instagram_post", "Post the Spring cakes Reel to Instagram", { ig_user_id: "17841400000000000", kind: "reel", caption: "Spring cakes, fresh today. Come early!", video: REEL }),
  prop("publish_facebook_post", "Post the Spring cakes video to Facebook", { page_id: "100000000000001", kind: "video", message: "Spring cakes, fresh today.", video: REEL }),
  prop("publish_youtube_video", "Upload Spring cakes to YouTube", { channel_id: "UC123", title: "Spring cakes", description: "How we bake them, start to finish.", privacy: "private", made_for_kids: false, tags: ["cake", "bakery"], video: REEL }),
  prop("publish_tiktok_post", "Post Spring cakes to TikTok", { title: "Spring cakes", privacy_level: "SELF_ONLY", allow_comment: true, allow_duet: false, allow_stitch: false, video: REEL }),
  prop("publish_social_post", "Post about spring cakes on Bluesky", { platform: "bluesky", posts_as: "maplestreet.bsky.social", text: "Fresh spring cakes today at https://maplestreet.example/cakes" }),
  prop("publish_mastodon_post", "Post about spring cakes on Mastodon", { posts_as: "@maple@mastodon.social", text: "Spring cakes are here." }),
  prop("publish_blog_post", "Publish Spring cakes on the blog", { slug: "spring-cakes", meta_description: "Spring cakes at Maple Street.", body: "<p>Hello <a href='/menu'>menu</a></p>", internal_links: ["/menu", "/about"] }, { agent_type: "seo" }),
  prop("create_calendar_event", "Add the tasting to the calendar", { title: "Tasting", event_type: "meeting", notes: "Bring samples", jdn: 2461364, local_year: 2026, local_month: 11, local_day: 26 }, { agent_type: "executive" }),
  prop("update_store_item", "Raise the Spring cake price", { platform: "shopify", item_name: "Spring cake", field: "price", currency: "USD", measured: { from: 20, to: 22 } }, { agent_type: "store" }),
  prop("send_mailbox_reply", "Reply to Pat about the order", { to: "pat@example.com", from: "hello@maplestreet.example", subject: "Re: order", text: "Your order is ready." }, { agent_type: "mailbox" }),
  prop("publish_instagram_post", "Posted: the Bread day Reel", { ig_user_id: "17841400000000000", kind: "reel", caption: "Bread day.", video: REEL }, { status: "executed", execution_result: { published: true, permalink: IG_URL } })
];
const STORE = { id: "a1111111-1111-4111-8111-111111111111", platform: "shopify", store: "maple.myshopify.com", status: "connected", permission: "read_write", currency: "USD",
  connected_since: "2026-11-01T00:00:00Z", last_sync_at: ago(2), stock_scope: "location", location_name: "Main warehouse", location_id: "gid://shopify/Location/1" };
const ITEMS = Array.from({ length: 30 }, (_, k) => ({ id: "b0000000-0000-4000-8000-" + String(k + 1).padStart(12, "0"), name: "Spring cake " + (k + 1), sku: "CAKE-" + (k + 1),
  quantity_on_hand: k + 3, unit_price: (20 + k) + ".00", source: "shopify", store_connection_id: STORE.id, status: "active", unit: "unit", created_at: "2026-11-10T00:00:00Z" }));
function centerBody() {
  const counts = {};
  RUNS.forEach(r => { counts[r.agent_type] = counts[r.agent_type] || {}; counts[r.agent_type][r.status] = (counts[r.agent_type][r.status] || 0) + 1; });
  const verdicts = [], jobRuns = [];
  ["daily_store_proposals", "daily_self_reviews", "daily_youtube_retention", "ops_alert_scan", "store_sync", "nightly_backup"].forEach(n => {
    verdicts.push({ job_name: n, cadence: n === "ops_alert_scan" ? "every 30 minutes" : "daily", on_time: true, reason: null });
    jobRuns.push({ job_name: n, last_run_on: "2026-11-19", finished_at: ago(1), last_error: null });
  });
  return {
    generated_at: new Date(NOW).toISOString(), chaining_on: true,
    needs_you: { ok: true, data: { pending_proposals: { count: 2, rows: PROPOSALS.slice(0, 2).map(p => ({ id: p.id, title: p.title, agent_type: p.agent_type, created_at: p.created_at })) },
      failed_runs_7d: { count: 1, rows: [RUNS[4]] }, email_sender: { blocked_by: [] } } },
    plans: { ok: true, data: [] },
    plan_lists: { ok: true, data: { active: [], past_count: 0, past_after_days: 14, past_latest: [] } },
    activity: { ok: true, data: { since: ago(24 * 30), since_7d: ago(24 * 7), total: 20, by_agent: {}, counts_7d: counts, newest_runs: RUNS.slice(0, 10), newest_runs_20: RUNS, sales_dry_runs: 2 } },
    autopilot: { ok: true, data: { autonomy: [{ agent_type: "social", enabled: true, updated_at: ago(30) }, { agent_type: "seo", enabled: false, updated_at: ago(40) }],
      schedules: [{ agent_type: "social", task_type: "calendar", cadence: "weekly", hour_utc: 9, enabled: true, last_run_on: "2026-11-16" }] } },
    outbound: { ok: true, data: { email_sequences: [], social_drafts_by_status: { published: 1 }, content_published_30d: { count: 3 },
      social_latest: [{ id: uid(7000), status: "published", platform: "bluesky", preview: "Spring workshop seats are open", created_at: ago(20) }],
      articles_latest: [0, 1, 2].map(i => ({ id: uid(8000 + i), title: ["Spring cakes", "Our sourdough starter", "Wedding cake season"][i], status: "published", published_at: ago(24 * (i + 1)), created_at: ago(24 * (i + 2)) })) } },
    spend: { ok: true, data: { usd: 4.25, monthly_cap_usd: 60, resets_at: "2026-12-01T00:00:00.000Z", note: "Figures are estimates from token counts at list prices; the provider's bill can differ." } },
    usage: { ok: true, data: { model_calls_today: 12, model_calls_daily_cap: 250, model_calls_unavailable: null, subscription_active: true } },
    platform: { ok: true, data: { job_runs: jobRuns, jobs_on_time: verdicts, job_cadence: {}, radar_status: [{ source: "news", last_tick_finished_at: ago(1), last_outcome: "ok", last_error: null }], ceiling: { spent_usd: 3.1, cap_usd: 25 } } }
  };
}
function topBody() {
  return {
    generated_at: new Date(NOW).toISOString(),
    visits: { per_day: [3, 1, 0, 4, 2, 5, 1, 2, 6, 3, 4, 2, 5, 7], this_week: 29, last_week: 16, tracked: true },
    store: { connected: true, low_stock: { count: 3, names: ["Blue mug", "Tea tin", "Spoon"] }, orders_this_week: 14, orders_per_day: [1, 0, 2, 0, 1, 0, 1, 2, 3, 1, 2, 2, 3, 1] },
    proposals_pending: 2, cards: { count: 2, views_today: 12, views_7d: 31 }, certifications: { earned: 2, total: 8 },
    wallet: { balance: 1100, exists: true }, marketplace: { orders_this_week: 0 }, self_reviews: { latest_at: ago(30) }, mailbox: { connected: true },
    counts: { crm_customers: 18, prospects: 4, leads: 6, sms_subscribers: 0, campaigns: 1, routines: 2, saved_prompts: 3, purchases: 1, bizdoc_documents: 5 },
    media: { used_bytes: 52428800, cap_bytes: 1073741824 }, agents: { running_now: [] }, _unreadable: [], cached: false,
    goal: { set: false }
  };
}
function api(method, u) {
  const p = u.pathname;
  const since = "2026-11-07T10:00:00Z";
  if (p === "/api/auth/me") return { user: ROSE, access: { active: true, reason: "subscription" }, subscription: { status: "active", plan: "all_access", current_period_end: ago(-24 * 20), cancel_at_period_end: false } };
  if (p === "/api/auth/refresh") return { token: "phone-check-token", refresh_token: "phone-check-refresh", user: ROSE };
  if (p === "/api/dashboard/top") return topBody();
  if (p === "/api/dashboard/pulse") return { generated_at: new Date(NOW).toISOString(), since: new Date(NOW).toISOString(), running: [], events: [], links: ["grow|sell", "grow|connect", "grow|agents", "sell|connect", "sell|agents", "connect|agents"], _unreadable: [], cached: false };
  if (p === "/api/command-center") return centerBody();
  if (p === "/api/agents") return { agents: AGENTS };
  if (p === "/api/ai/tasks" && method === "GET") { const type = u.searchParams.get("agent_type") || u.searchParams.get("agent"); return { tasks: type ? RUNS.filter(r => r.agent_type === type) : RUNS }; }
  if (/^\/api\/ai\/tasks\/[^/]+$/.test(p)) return { task: RUNS.find(r => r.id === p.split("/").pop()) || RUNS[0] };
  if (p === "/api/proposals") { const st = u.searchParams.get("status"); return { proposals: st ? PROPOSALS.filter(x => x.status === st) : PROPOSALS }; }
  if (p === "/api/analytics/summary") return { stats: { tasksRun: 48, tasksCompleted: 45, contentItems: 23, subscribers: 312, optedIn: 287, campaigns: 4, blogItems: 12, smsItems: 9 } };
  if (p === "/api/store/connections" && method === "GET") return { connections: [STORE], shopify_available: true, etsy_available: true, amazon_available: true, amazon_draft: false };
  if (p === "/api/store/changes") return { changes: [] };
  if (p === "/api/inventory/items" && method === "GET") { const limit = Number(u.searchParams.get("limit") || 25), offset = Number(u.searchParams.get("offset") || 0); return { items: ITEMS.slice(offset, offset + limit), limit, offset, has_more: offset + limit < ITEMS.length }; }
  if (p === "/api/youtube/status") return { youtube_available: true, connected: true, status: "connected", channel_title: "Maple Street", since };
  if (p === "/api/tiktok/status") return { tiktok_available: true, connected: true, status: "connected", display_name: "Maple Street", since };
  if (p === "/api/instagram/status") return { instagram_available: true, connected: true, status: "connected", username: "maplestreet", since };
  if (p === "/api/facebook/status") return { facebook_available: true, connected: true, status: "connected", page_name: "Maple Street", since };
  if (p === "/api/videos" && method === "GET") return { videos: VIDEOS, max_bytes: 524288000, ready_max: 2 };
  if (p === "/api/media") return { media: [] };
  if (p === "/api/instagram/posts" || p === "/api/facebook/posts") return { posts: [] };
  if (p === "/api/tiktok/creator-info") return { creator_nickname: "Maple Street Bakery", privacy_level_options: ["PUBLIC_TO_EVERYONE", "MUTUAL_FOLLOW_FRIENDS", "SELF_ONLY"], comment_disabled: false, duet_disabled: false, stitch_disabled: false, max_video_post_duration_sec: 600 };
  if (p === "/api/business-profile") return { profile: { business_name: "Maple Street Bakery", industry: "Bakery", city: "Portland", website: "https://maplestreet.example" } };
  if (p === "/api/user/preferences") return { ok: true, preferences: {} };
  if (method !== "GET") return { ok: true };
  return {};
}

/* ── a small static server over the frontend ── */
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json",
  ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".webp": "image/webp", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".woff2": "font/woff2", ".mp3": "audio/mpeg", ".pdf": "application/pdf" };
function serve() {
  const root = path.resolve(FRONTEND);
  const server = http.createServer((req, res) => {
    let p;
    try { p = decodeURIComponent(new URL(req.url, "http://x").pathname); } catch (e) { res.writeHead(400); res.end(); return; }
    if (p.endsWith("/")) p += "index.html";
    let file = path.resolve(root, "." + p);
    if (!fs.existsSync(file) && fs.existsSync(file + ".html")) file += ".html";
    if (!file.startsWith(root) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end("not found"); return; }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(file).toLowerCase()] || "application/octet-stream", "Cache-Control": "no-store" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise(r => server.listen(0, "127.0.0.1", () => r(server)));
}

/* ── Chrome over the DevTools Protocol ── */
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function launch() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bf-phone-"));
  const proc = spawn(CHROME, ["--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + profile, "--no-first-run", "--no-default-browser-check",
    "--disable-gpu", "--disable-extensions", "--mute-audio", "--hide-scrollbars", "about:blank"], { stdio: "ignore" });
  const portFile = path.join(profile, "DevToolsActivePort");
  for (let i = 0; i < 150 && !fs.existsSync(portFile); i++) await sleep(100);
  if (!fs.existsSync(portFile)) throw new Error("Chrome did not open its debugging port");
  let port = "";
  for (let i = 0; i < 50 && !/^\d+$/.test(port); i++) { try { port = fs.readFileSync(portFile, "utf8").split("\n")[0].trim(); } catch (e) { /* still being written */ } if (!/^\d+$/.test(port)) await sleep(100); }
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

/* The owner signed in, a seeded Math.random, and (desktop) animations paused from the first paint. */
const SEED = "try{if(!sessionStorage.getItem('phone_check_out')){localStorage.setItem('bf_token','phone-check-token');localStorage.setItem('bf_user'," + J(J(ROSE)) + ");}}catch(e){}" +
  "(function(){var s=20261119;Math.random=function(){s=(s*1664525+1013904223)>>>0;return s/4294967296;};})();" +
  "(function(){var R=Date,start=R.now(),base=" + NOW + ";function now(){return base+(R.now()-start);}" +
  "function D(){var a=[].slice.call(arguments);if(!(this instanceof D))return new R(now()).toString();return a.length?new (Function.prototype.bind.apply(R,[null].concat(a)))():new R(now());}" +
  "D.prototype=R.prototype;D.now=now;D.UTC=R.UTC;D.parse=R.parse;window.Date=D;})();";
const PAUSE = "(function(){var css='*,*::before,*::after{animation-play-state:paused!important;transition:none!important}';" +
  "function put(){var r=document.documentElement;if(!r)return false;var s=document.createElement('style');s.setAttribute('data-phone-check','pause');s.textContent=css;r.appendChild(s);return true;}" +
  "if(!put()){new MutationObserver(function(m,o){if(put())o.disconnect();}).observe(document,{childList:true});}})();";

/* ── page-side measures ── */
// One sweep of the page at the current scroll: returns every defect kind STEP 1 lists.
const MEASURE = String.raw`(function(){
  var W = innerWidth, H = innerHeight, out = {};
  function shown(n){ for (var e = n; e && e.nodeType === 1; e = e.parentElement) { var c = getComputedStyle(e); if (c.display === "none" || c.visibility === "hidden" || c.opacity === "0") return false; } return true; }
  function name(n){ var c = n.className && n.className.baseVal !== undefined ? n.className.baseVal : n.className; return n.tagName.toLowerCase() + (n.id ? "#" + n.id : "") + (c ? "." + String(c).trim().split(/\s+/).slice(0, 2).join(".") : ""); }
  function txt(n){ return (n.innerText || n.textContent || "").replace(/\s+/g, " ").trim().slice(0, 40); }
  function ownText(n){ for (var c = n.firstChild; c; c = c.nextSibling) if (c.nodeType === 3 && c.nodeValue.trim()) return true; return false; }
  function box(r){ return Math.round(r.left) + "," + Math.round(r.top + scrollY) + " " + Math.round(r.width) + "x" + Math.round(r.height); }
  var all = [].slice.call(document.querySelectorAll("body *"));
  var vis = all.filter(function(n){ var r = n.getBoundingClientRect(); return r.width > 0 && r.height > 0 && shown(n); });
  // 1. horizontal scroll
  out.hscroll = document.documentElement.scrollWidth > W + 1 ? document.documentElement.scrollWidth : 0;
  out.wide = out.hscroll ? vis.filter(function(n){ var r = n.getBoundingClientRect(); if (r.right <= W + 1) return false;
    for (var e = n; e && e.nodeType === 1; e = e.parentElement) if (getComputedStyle(e).position === "fixed") return false;
    for (var p = n.parentElement; p && p !== document.body; p = p.parentElement) { var cs = getComputedStyle(p); if (/auto|scroll|hidden|clip/.test(cs.overflowX) && p.getBoundingClientRect().right <= W + 1) return false; }
    return true; }).slice(0, 5).map(function(n){ return name(n) + " " + box(n.getBoundingClientRect()); }) : [];
  // 2. text cut off: an ellipsis, a line clamp, or own text clipped by its own box
  out.clipped = vis.filter(function(n){ var c = getComputedStyle(n), r = n.getBoundingClientRect(); if (r.width < 3 || r.height < 3) return false;
    if (n.closest("svg") || !txt(n)) return false;
    var ell = c.textOverflow === "ellipsis" && /hidden|clip/.test(c.overflowX) && n.scrollWidth > n.clientWidth + 1;
    var clampd = c.webkitLineClamp && c.webkitLineClamp !== "none" && n.scrollHeight > n.clientHeight + 2;
    if (ell || clampd) return true;
    if (!ownText(n)) return false;
    var clipX = /hidden|clip/.test(c.overflowX) && n.scrollWidth > n.clientWidth + 1;
    var clipY = /hidden|clip/.test(c.overflowY) && n.scrollHeight > n.clientHeight + 2 && c.position !== "absolute";
    if (clipX || clipY) return true;
    // clipped by an ancestor's hidden overflow (a scrolling container is not a clip)
    for (var p = n.parentElement; p && p !== document.body; p = p.parentElement) { var pc = getComputedStyle(p);
      if (/auto|scroll/.test(pc.overflowX)) break;
      if (/hidden|clip/.test(pc.overflowX)) { var pr = p.getBoundingClientRect(); if (pr.width > 2 && (r.left < pr.left - 1 || r.right > pr.right + 1)) return true; break; } }
    return false; }).slice(0, 12).map(function(n){ return name(n) + " \"" + txt(n) + "\""; });
  // 3. fixed or floating elements over text or controls (at this scroll)
  var TAPSEL = "a[href],button,input:not([type=hidden]),select,textarea,[role=button],[role=tab],[role=switch],summary,[tabindex]:not([tabindex='-1'])";
  var fixed = vis.filter(function(n){ var c = getComputedStyle(n); if (c.position !== "fixed" && c.position !== "sticky") return false; if (c.pointerEvents === "none") return false;
    var r = n.getBoundingClientRect(); if (r.width * r.height > W * H * 0.5) return false; if (r.bottom <= 0 || r.top >= H) return false;
    var p = n.parentElement; while (p && p !== document.body) { var pc = getComputedStyle(p); if (pc.position === "fixed" || pc.position === "sticky") return false; p = p.parentElement; } return true; });
  out.over = [];
  fixed.forEach(function(f){ var fr = f.getBoundingClientRect(), fc = getComputedStyle(f);
    var hits = vis.filter(function(n){ if (f.contains(n) || n.contains(f)) return false; var c = getComputedStyle(n); if (c.position === "fixed" || c.position === "sticky") return false;
      var inFixed = false; for (var e = n.parentElement; e && e !== document.body; e = e.parentElement) { var ec = getComputedStyle(e); if (ec.position === "fixed" || ec.position === "sticky") { inFixed = true; break; } } if (inFixed) return false;
      if (!(ownText(n) || n.matches(TAPSEL) || /^H[1-6]$/.test(n.tagName))) return false;
      var r = n.getBoundingClientRect(); if (r.width < 2 || r.height < 2) return false;
      var ix = Math.min(r.right, fr.right) - Math.max(r.left, fr.left), iy = Math.min(r.bottom, fr.bottom) - Math.max(r.top, fr.top);
      if (ix <= 1 || iy <= 1) return false;
      // painted over it? the floating element must win the hit test at the shared area's centre
      var x = (Math.max(r.left, fr.left) + Math.min(r.right, fr.right)) / 2, y = (Math.max(r.top, fr.top) + Math.min(r.bottom, fr.bottom)) / 2;
      var top = document.elementFromPoint(x, y); return !!top && f.contains(top); });
    if (hits.length) out.over.push(name(f) + " " + (fc.position) + " over " + hits.slice(0, 3).map(function(n){ return name(n) + " \"" + txt(n).slice(0, 20) + "\""; }).join(", ")); });
  // 4. tap targets under 44 x 44
  out.small = [];
  vis.filter(function(n){ return n.matches(TAPSEL); }).forEach(function(n){
    var t = n, r;
    if (n.tagName === "INPUT" && /checkbox|radio/.test(n.type)) { t = n.closest("label") || (n.id && document.querySelector("label[for='" + n.id + "']")) || n; }
    r = t.getBoundingClientRect();
    if (r.right < 0 || r.left > document.documentElement.scrollWidth) return;
    var c = getComputedStyle(n); if (c.opacity === "0" && t === n) return;
    if (r.width <= 2 || r.height <= 2) return;
    if (n.tagName === "A" && c.display === "inline") { var par = n.parentElement; var pt = (par.innerText || "").replace(/\s+/g, " ").trim(); var lt = (n.innerText || "").replace(/\s+/g, " ").trim(); if (pt.length > lt.length + 8) return; }
    if (r.width < 44 - 0.5 || r.height < 44 - 0.5) out.small.push(name(t) + " \"" + txt(t).slice(0, 18) + "\" " + Math.round(r.width) + "x" + Math.round(r.height));
  });
  out.smallCount = out.small.length; out.small = out.small.slice(0, 15);
  // 5. decoration painted over text
  var DECO = /star|nebula|glow|spark|cosmic|galaxy|aurora|particle|twinkle|halo|orb-bg|backdrop|sky/i;
  var decos = vis.filter(function(n){ var c = getComputedStyle(n); var nm = String(n.id) + " " + String(n.className && n.className.baseVal !== undefined ? n.className.baseVal : n.className);
    return (n.tagName === "CANVAS" || DECO.test(nm)) && (c.position === "fixed" || c.position === "absolute") && !n.matches(TAPSEL) && !ownText(n) && !n.querySelector(TAPSEL); });
  var texts = vis.filter(function(n){ return ownText(n) && !n.closest("svg"); });
  out.deco = [];
  decos.forEach(function(d){ var dr = d.getBoundingClientRect(); if (dr.bottom <= 0 || dr.top >= H) return; var old = d.style.pointerEvents; d.style.setProperty("pointer-events", "auto", "important");
    var cover = texts.filter(function(n){ if (d.contains(n)) return false; var r = n.getBoundingClientRect(); if (r.bottom <= 0 || r.top >= H) return false;
      var x = Math.max(r.left, dr.left), x2 = Math.min(r.right, dr.right), y = Math.max(r.top, dr.top), y2 = Math.min(r.bottom, dr.bottom); if (x2 - x < 2 || y2 - y < 2) return false;
      var st = document.elementsFromPoint((x + x2) / 2, (y + y2) / 2); var di = -1, ni = -1;
      for (var i = 0; i < st.length; i++) { if (di < 0 && (st[i] === d || d.contains(st[i]))) di = i; if (ni < 0 && (st[i] === n || n.contains(st[i]))) ni = i; }
      return di >= 0 && ni >= 0 && di < ni; });
    d.style.pointerEvents = old;
    if (cover.length) out.deco.push(name(d) + " over " + cover.slice(0, 3).map(function(n){ return name(n) + " \"" + txt(n).slice(0, 20) + "\""; }).join(", ")); });
  // 6. empty gaps over 48 px inside a card
  out.gaps = [];
  vis.filter(function(n){ var nm = String(n.className && n.className.baseVal !== undefined ? n.className.baseVal : n.className); if (!/card|panel|tile|box|bf-section/i.test(nm)) return false;
    var c = getComputedStyle(n); var r = n.getBoundingClientRect(); if (r.height < 60 || r.width < 120) return false; if (n.closest("svg")) return false;
    return (c.backgroundColor !== "rgba(0, 0, 0, 0)" || c.backgroundImage !== "none" || parseFloat(c.borderTopWidth) > 0); }).forEach(function(card){
    var cr = card.getBoundingClientRect(), cc = getComputedStyle(card);
    // a display:contents child stands for its own children
    var flat = []; (function add(list){ [].forEach.call(list, function(k){ if (getComputedStyle(k).display === "contents") add(k.children); else flat.push(k); }); })(card.children);
    var kids = flat.filter(function(k){ var r = k.getBoundingClientRect(), c = getComputedStyle(k); return r.width > 0 && r.height > 0 && shown(k) && c.position !== "absolute" && c.position !== "fixed"; })
      .map(function(k){ return k.getBoundingClientRect(); }).sort(function(a, b){ return a.top - b.top; });
    if (!kids.length) return;
    var top = cr.top + parseFloat(cc.borderTopWidth), bottom = cr.bottom - parseFloat(cc.borderBottomWidth);
    var gaps = [], end = kids[0].top - top; if (end > 48) gaps.push("top " + Math.round(end));
    var reach = kids[0].bottom; for (var i = 1; i < kids.length; i++) { var g = kids[i].top - reach; if (g > 48) gaps.push(Math.round(g)); reach = Math.max(reach, kids[i].bottom); }
    if (bottom - reach > 48) gaps.push("bottom " + Math.round(bottom - reach));
    if (gaps.length) out.gaps.push(name(card) + " [" + gaps.join(",") + "]"); });
  out.gaps = out.gaps.slice(0, 10);
  return out;
})()`;

// Every visible element's box (document coordinates), measured twice 700 ms apart; one that moved is set aside.
const BOXES = String.raw`new Promise(function(done){
  function shown(n){ for (var e = n; e && e.nodeType === 1; e = e.parentElement) { var c = getComputedStyle(e); if (c.display === "none" || c.visibility === "hidden") return false; } return true; }
  var els = [].slice.call(document.querySelectorAll("body, body *")).filter(function(n){ return n.tagName !== "SCRIPT" && n.tagName !== "STYLE" && !n.closest("[data-phone-check]"); });
  function own(n){ var s = ""; for (var c = n.firstChild; c; c = c.nextSibling) if (c.nodeType === 3) s += c.nodeValue; return s.replace(/\s+/g, " ").trim().slice(0, 24); }
  function take(){ return els.map(function(n){ if (!n.isConnected || !shown(n)) return null; var r = n.getBoundingClientRect(); if (!(r.width > 0 || r.height > 0)) return null;
    return [Math.round((r.left + scrollX) * 10) / 10, Math.round((r.top + scrollY) * 10) / 10, Math.round(r.width * 10) / 10, Math.round(r.height * 10) / 10]; }); }
  var a = take();
  setTimeout(function(){ var b = take(), list = [];
    els.forEach(function(n, i){ if (!a[i] && !b[i]) return; var key = n.tagName.toLowerCase() + "|" + (n.id || "") + "|" + own(n).replace(/[0-9]/g, "#");
      // decoration: inside an aria-hidden overlay, or a fixed layer that takes no tap (the Termaximus mist)
      var deco = false; for (var q = n; q && q.nodeType === 1; q = q.parentElement) { var qc = getComputedStyle(q); if (qc.position === "fixed" && qc.pointerEvents === "none") { deco = true; break; } }
      for (var e = n; e && e.nodeType === 1; e = e.parentElement) { if (e.getAttribute("aria-hidden") === "true") { for (var f = e; f && f.nodeType === 1; f = f.parentElement) { var fp = getComputedStyle(f).position; if (fp === "fixed" || fp === "absolute") { deco = true; break; } } break; } }
      var moving = !a[i] || !b[i] || a[i].some(function(v, k){ return Math.abs(v - b[i][k]) > 0.5; });
      list.push([key, b[i] || a[i], moving || deco ? 1 : 0]); });
    done({ w: innerWidth, h: document.documentElement.scrollHeight, list: list }); }, 700);
})`;

/* ── open a page at a size ── */
async function open(cdp, origin, page, w, h, phone) {
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: phone ? 2 : 1, mobile: phone, screenWidth: w, screenHeight: h });
  await cdp.send("Emulation.setTouchEmulationEnabled", { enabled: phone, maxTouchPoints: phone ? 5 : 1 });
  await cdp.send("Emulation.setUserAgentOverride", { userAgent: phone ? IPHONE_UA : DESK_UA, platform: phone ? "iPhone" : "Win32" });
  await cdp.send("Page.navigate", { url: "about:blank" });
  await sleep(120);
  await cdp.send("Page.navigate", { url: origin + "/" + page });
  for (let i = 0; i < 80; i++) { try { if (await evaluate(cdp, "document.readyState === 'complete'")) break; } catch (e) { /* navigating */ } await sleep(100); }
  await sleep(phone ? 1600 : 1800);
}
async function shotPage(cdp, file, w) {
  const hgt = await evaluate(cdp, "Math.min(document.documentElement.scrollHeight, 9000)");
  const r = await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width: w, height: hgt, scale: 1 } });
  fs.writeFileSync(file, Buffer.from(r.data, "base64"));
}
let DESK_UA = "";

/* ── the dashboard's own checks (PH1) ── */
const ORBIT = String.raw`(function(){
  var core = document.getElementById("orbitCore"), stage = document.getElementById("orbitStage");
  var cr = core ? core.getBoundingClientRect() : null, sr = stage ? stage.getBoundingClientRect() : null;
  var ps = [].slice.call(document.querySelectorAll(".orbit-portal[data-portal]")).map(function(b){ var disc = b.querySelector(".orbit-disc"), lab = b.querySelector(".orbit-portal-name");
    var r = disc.getBoundingClientRect(), lr = lab.getBoundingClientRect(), lc = getComputedStyle(lab);
    return { name: b.getAttribute("data-portal"), cx: r.left + r.width / 2, cy: r.top + r.height / 2, w: r.width, h: r.height, label: lab.textContent.trim(),
      labelFull: lab.scrollWidth <= lab.clientWidth + 1 && lab.scrollHeight <= lab.clientHeight + 1 && lc.textOverflow !== "ellipsis" && !/hidden|clip/.test(lc.overflowX),
      labelIn: lr.left >= -0.5 && lr.right <= innerWidth + 0.5, lbox: [lr.left, lr.top, lr.right, lr.bottom] }; });
  var hit = function(a, b){ return a[0] < b[2] - 0.5 && a[2] > b[0] + 0.5 && a[1] < b[3] - 0.5 && a[3] > b[1] + 0.5; };
  var clash = [];
  ps.forEach(function(p, i){ ps.forEach(function(q, j){ if (j > i && hit(p.lbox, q.lbox)) clash.push(p.name + "/" + q.name); });
    if (cr && hit(p.lbox, [cr.left, cr.top, cr.right, cr.bottom])) clash.push(p.name + "/core"); });
  var below = document.querySelector(".orbit-below"), goal = document.getElementById("orbitGoalSet"), week = document.querySelector(".orbit-week");
  var br = below ? below.getBoundingClientRect() : null;
  return { core: cr ? { cx: cr.left + cr.width / 2, cy: cr.top + cr.height / 2, w: cr.width } : null, portals: ps, clash: clash,
    stageTop: sr ? Math.round(sr.top - document.getElementById("orbitPanel").getBoundingClientRect().top) : null,
    topGap: sr && ps.length ? Math.round(Math.min.apply(null, ps.map(function(p){ return p.cy - p.h / 2; })) - sr.top) : null,
    below: br ? { y: Math.round(br.top), w: Math.round(br.width), panelW: Math.round(document.getElementById("orbitPanel").clientWidth), stageBottom: Math.round(sr.bottom) } : null,
    goalIn: !!(goal && below && below.contains(goal)), goalH: goal ? Math.round(goal.getBoundingClientRect().height) : 0, week: week ? week.textContent : null,
    hscroll: document.documentElement.scrollWidth - innerWidth };
})()`;

(async () => {
  for (const d of ["before", "after"]) fs.mkdirSync(path.join(OUT, d), { recursive: true });
  const server = await serve();
  const origin = "http://127.0.0.1:" + server.address().port;
  const chrome = await launch();
  let cdp;
  const defects = {}, boxes = {};
  const exceptions = [];
  let currentPage = "";
  try {
    cdp = await connect(chrome.ws);
    cdp.on(async msg => {
      if (msg.method === "Runtime.exceptionThrown") { const d = msg.params.exceptionDetails; exceptions.push(currentPage + ": " + ((d.exception || {}).description || d.text).split("\n")[0]); return; }
      if (msg.method !== "Fetch.requestPaused") return;
      const { requestId, request } = msg.params;
      let u; try { u = new URL(request.url); } catch (e) { return; }
      try {
        if (u.origin === origin || u.protocol === "data:" || u.protocol === "blob:") await cdp.send("Fetch.continueRequest", { requestId });
        else if (u.hostname === API_HOST) {
          const body = request.method === "OPTIONS" ? "" : J(api(request.method, u));
          await cdp.send("Fetch.fulfillRequest", { requestId, responseCode: 200, body: Buffer.from(body).toString("base64"),
            responseHeaders: [{ name: "Content-Type", value: "application/json" }, { name: "Access-Control-Allow-Origin", value: "*" },
              { name: "Access-Control-Allow-Headers", value: "*" }, { name: "Access-Control-Allow-Methods", value: "GET,POST,PUT,PATCH,DELETE,OPTIONS" }] });
        } else await cdp.send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
      } catch (e) { /* the page moved on */ }
    });
    await cdp.send("Fetch.enable", { patterns: [{ urlPattern: "*" }] });
    await cdp.send("Runtime.enable");
    await cdp.send("Page.enable");
    await cdp.send("Network.enable");
    await cdp.send("Network.setBypassServiceWorker", { bypass: true });
    DESK_UA = (await cdp.send("Browser.getVersion")).userAgent.replace("HeadlessChrome", "Chrome");
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: SEED });

    const baselineFile = n => path.join(OUT, "desktop-baseline-" + n + ".json");
    let baseline = null;
    if (MODE === "check") {
      baseline = {};
      fs.readdirSync(OUT).filter(f => /^desktop-baseline-.*\.json$/.test(f)).forEach(f => Object.assign(baseline, JSON.parse(fs.readFileSync(path.join(OUT, f), "utf8"))));
    }

    console.log("browserCheckPhone (" + MODE + ", batch " + BATCH + ", " + PAGES.length + " pages)");
    for (const page of PAGES) {
      currentPage = page;
      console.log("\n  " + page);
      defects[page] = {};
      for (const [w, h] of PHONES) {
        await open(cdp, origin, page, w, h, true);
        const atRest = await evaluate(cdp, "scrollTo(0,0)," + MEASURE);
        await shotPage(cdp, path.join(OUT, MODE === "before" ? "before" : "after", fileOf(page, w, h)), w);
        await evaluate(cdp, "scrollTo(0,document.documentElement.scrollHeight),true");
        await sleep(350);
        const atEnd = await evaluate(cdp, MEASURE);
        const d = { hscroll: atRest.hscroll, wide: atRest.wide, clipped: atRest.clipped, overAtRest: atRest.over, overAtEnd: atEnd.over,
          small: atRest.small, smallCount: atRest.smallCount, deco: atRest.deco.concat(atEnd.deco.filter(x => atRest.deco.indexOf(x) === -1)), gaps: atRest.gaps };
        defects[page][w] = d;
        if (MODE === "before") {
          const n = (d.hscroll ? 1 : 0) + d.clipped.length + d.overAtRest.length + d.overAtEnd.length + d.smallCount + d.deco.length + d.gaps.length;
          console.log("    " + w + ": " + n + " finding(s)" + (d.hscroll ? ", scrolls sideways to " + d.hscroll : ""));
        } else {
          const at = page + " at " + w + ": ";
          check(at + "no horizontal scroll", !d.hscroll, J(d.wide));
          check(at + "no text cut off (ellipsis or clipped)", d.clipped.length === 0, J(d.clipped));
          const restOver = d.overAtRest.filter(x => !/^button#tmx-guide-fab /.test(x));
          check(at + "no fixed element over a heading, text, button or link (the Guide at the end of the page, every other one at rest too)", restOver.length === 0 && d.overAtEnd.length === 0, J(restOver.concat(d.overAtEnd)));
          check(at + "every tap target is at least 44 x 44", d.smallCount === 0, d.smallCount + " " + J(d.small));
          check(at + "decoration is under the text", d.deco.length === 0, J(d.deco));
          check(at + "no empty gap over 48 px inside a card", d.gaps.length === 0, J(d.gaps));
          if (page === "dashboard.html") await dashboardChecks(cdp, origin, w, h);
        }
      }
      // the desktop
      if (ONLY === "phone") continue;
      await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: PAUSE }).then(async ({ identifier }) => {
        await open(cdp, origin, page, DESK[0], DESK[1], false);
        await evaluate(cdp, "scrollTo(0,0),true");
        const b = await evaluate(cdp, BOXES);
        await shotPage(cdp, path.join(OUT, MODE === "before" ? "before" : "after", fileOf(page, DESK[0], DESK[1])), DESK[0]);
        await cdp.send("Page.removeScriptToEvaluateOnNewDocument", { identifier });
        if (MODE === "before") { boxes[page] = b; console.log("    1440: " + b.list.length + " visible elements recorded (" + b.list.filter(x => x[2]).length + " moving, set aside)"); }
        else desktopCompare(page, baseline[page], b);
      });
    }
    if (MODE === "before") {
      if (ONLY !== "desktop") fs.writeFileSync(path.join(OUT, "defects-before-" + BATCH + ".json"), J(defects, null, 1));
      if (ONLY !== "phone") fs.writeFileSync(baselineFile(BATCH), J(boxes));
    } else if (ONLY !== "desktop") fs.writeFileSync(path.join(OUT, "defects-after-" + BATCH + ".json"), J(defects, null, 1));
  } finally {
    try { cdp && cdp.close(); } catch (e) { /* gone */ }
    try { chrome.proc.kill(); } catch (e) { /* gone */ }
    server.close();
  }
  const ex = exceptions.filter((v, i, a) => a.indexOf(v) === i);
  if (ex.length) console.log("\n  page exceptions (reported, not counted): " + J(ex.slice(0, 10)));
  if (MODE === "before") console.log("\nRecorded " + PAGES.length + " pages to " + OUT);
  else console.log("\n" + (failures === 0 ? "ALL " + passes + " CHECKS PASSED" : failures + " FAILED, " + passes + " passed"));
  setTimeout(() => process.exit(MODE === "check" && failures ? 1 : 0), 300);
})().catch(e => { console.log("ERROR " + e.stack); setTimeout(() => process.exit(1), 300); });

/* At 1440 every baseline element is matched (same tag, id and own text, box within 1 px), and nothing new shows. */
function desktopCompare(page, base, now) {
  if (!base) { check(page + " at 1440: a desktop baseline exists", false, "none recorded"); return; }
  const movingKeys = new Set(base.list.filter(x => x[2]).map(x => x[0]).concat(now.list.filter(x => x[2]).map(x => x[0])));
  const pool = new Map();
  now.list.filter(x => !movingKeys.has(x[0])).forEach(x => { if (!pool.has(x[0])) pool.set(x[0], []); pool.get(x[0]).push(x[1]); });
  const missing = [];
  base.list.filter(x => !movingKeys.has(x[0])).forEach(x => {
    const list = pool.get(x[0]) || [];
    const i = list.findIndex(b => b.every((v, k) => Math.abs(v - x[1][k]) <= 1));
    if (i === -1) missing.push(x[0] + " " + x[1].join(","));
    else list.splice(i, 1);
  });
  const extra = [];
  pool.forEach((list, k) => list.forEach(b => extra.push(k + " " + b.join(","))));
  check(page + " at 1440: every element's box equals the baseline within 1 px (" + base.list.length + " elements, " + movingKeys.size + " moving set aside), page height " + base.h + " = " + now.h,
    missing.length === 0 && extra.length === 0 && Math.abs(base.h - now.h) <= 1, J({ missing: missing.slice(0, 8), extra: extra.slice(0, 8), missingCount: missing.length, extraCount: extra.length }));
}

async function dashboardChecks(cdp, origin, w, h) {
  await evaluate(cdp, "scrollTo(0,0),true");
  await sleep(300);
  const o = await evaluate(cdp, ORBIT);
  const at = "dashboard at " + w + ": ";
  const dist = o.core ? o.portals.map(p => Math.hypot(p.cx - o.core.cx, p.cy - o.core.cy)) : [];
  check(at + "the orbit has a core and five portals", !!o.core && o.portals.length === 5, J(o));
  check(at + "the five portals sit on a circle round the core (distance equal within 2 px)", dist.length === 5 && Math.max.apply(null, dist) - Math.min.apply(null, dist) <= 2, J(dist.map(Math.round)));
  check(at + "each portal disc is at least 44 px", o.portals.length === 5 && o.portals.every(p => p.w >= 44 && p.h >= 44), J(o.portals.map(p => p.name + " " + Math.round(p.w) + "x" + Math.round(p.h))));
  check(at + "all five labels are shown in full, inside the screen", o.portals.length === 5 && o.portals.every(p => p.label && p.labelFull && p.labelIn && p.ell !== "ellipsis"), J(o.portals.map(p => [p.name, p.label, p.labelFull, p.labelIn])));
  check(at + "no two labels overlap, and none overlaps the core", o.clash.length === 0, J(o.clash));
  check(at + "no empty space above the orbit (the top disc within 52 px of the stage's top)", o.topGap !== null && o.topGap <= 52, J({ topGap: o.topGap, stageTop: o.stageTop }));
  check(at + "THIS WEEK and the goal button sit under the orbit at the card's full width", !!o.below && o.below.y >= o.below.stageBottom - 1 && Math.abs(o.below.w - (o.below.panelW - 24)) <= 2 && o.goalIn && o.goalH >= 44 && /this week/i.test(o.week || ""), J({ below: o.below, goalIn: o.goalIn, goalH: o.goalH, week: o.week }));
  // A: the top bar's two rows
  const bar = await evaluate(cdp, "(function(){function c(sel){var n=document.querySelector(sel);if(!n)return null;var r=n.getBoundingClientRect();return {l:Math.round(r.left),r:Math.round(r.right),t:Math.round(r.top),b:Math.round(r.bottom),cy:Math.round(r.top+r.height/2),h:Math.round(r.height),shown:r.width>0&&getComputedStyle(n).display!=='none'};}" +
    "return {brand:c('.topbar-brand'),music:c('.topbar > .bfm-float'),avatar:c('#userAvatar'),agents:c('#agentsNavBtn'),orb:c('#oracleNavBtn'),tmx:c('#tmxPresenceToggle'),settings:c('#settingsNavBtn'),logout:c('.topbar .logout'),bar:c('.topbar'),num:(document.querySelector('.topbar-agents-num')||{}).textContent};})()");
  const row1 = [bar.brand, bar.music, bar.avatar], row2 = [bar.agents, bar.orb, bar.tmx];
  check(at + "top bar row 1: the logo and BizForce AI on the left, the music button and the R avatar on the right, on one centre line", row1.every(x => x && x.shown) &&
    Math.max.apply(null, row1.map(x => x.cy)) - Math.min.apply(null, row1.map(x => x.cy)) <= 2 && bar.brand.l < bar.music.l && bar.music.r <= bar.avatar.l && bar.avatar.r <= bar.bar.r, J(bar));
  check(at + "top bar row 2: AGENTS, the orb and TERMAXIMUS, the same height, under row 1, evenly across the full width", row2.every(x => x && x.shown) &&
    row2.every(x => x.h === row2[0].h && x.t >= bar.avatar.b) && Math.abs((bar.orb.l - bar.agents.r) - (bar.tmx.l - bar.orb.r)) <= 2 && bar.agents.l - bar.bar.l <= 24 && bar.bar.r - bar.tmx.r <= 24, J(row2));
  check(at + "Settings and Sign Out are off the top bar (in the avatar menu); the agent count reads 18", !bar.settings.shown && !bar.logout.shown && bar.num === "18", J([bar.settings, bar.logout, bar.num]));
  // the avatar menu
  const menu = await evaluate(cdp, "(function(){var a=document.getElementById('userAvatar');if(!a)return null;a.click();return new Promise(function(r){setTimeout(function(){var m=document.getElementById('bfAvatarMenu');" +
    "var items=m?[].filter.call(m.querySelectorAll('a,button'),function(n){var b=n.getBoundingClientRect();return b.width>=44&&b.height>=44&&getComputedStyle(m).display!=='none';}).map(function(n){return n.textContent.trim();}):[];" +
    "r({open:!!m&&getComputedStyle(m).display!=='none'&&m.getBoundingClientRect().height>0,items:items,expanded:a.getAttribute('aria-expanded')});},250);});})()");
  check(at + "tapping the R avatar opens a menu with Settings and Sign Out", !!menu && menu.open && menu.items.indexOf("Settings") !== -1 && menu.items.indexOf("Sign Out") !== -1 && menu.expanded === "true", J(menu));
  if (w !== 390) return;
  const settings = await evaluate(cdp, "(function(){var m=document.getElementById('bfAvatarMenu');var s=[].filter.call(m.querySelectorAll('a'),function(n){return n.textContent.trim()==='Settings';})[0];return s?s.getAttribute('href'):null;})()");
  check(at + "Settings in the menu goes to settings.html", settings === "settings.html", J(settings));
  await evaluate(cdp, "(function(){var m=document.getElementById('bfAvatarMenu');var s=[].filter.call(m.querySelectorAll('a'),function(n){return n.textContent.trim()==='Settings';})[0];s.click();return true;})()");
  await sleep(1500);
  const url1 = await evaluate(cdp, "location.pathname");
  check(at + "tapping Settings opens the Settings page", url1 === "/settings.html", url1);
  await open(cdp, origin, "dashboard.html", w, h, true);
  await evaluate(cdp, "document.getElementById('userAvatar').click(),true");
  await sleep(300);
  await evaluate(cdp, "sessionStorage.setItem('phone_check_out','1'),true");
  await evaluate(cdp, "(function(){var m=document.getElementById('bfAvatarMenu');var s=[].filter.call(m.querySelectorAll('button'),function(n){return n.textContent.trim()==='Sign Out';})[0];s.click();return true;})()");
  await sleep(1800);
  const after = await evaluate(cdp, "({path:location.pathname,token:(function(){try{return localStorage.getItem('bf_token');}catch(e){return 'x';}})()})");
  check(at + "tapping Sign Out signs out (bf_token removed, off the dashboard)", after.token === null && after.path !== "/dashboard.html", J(after));
  // sign the owner back in for the next size
  await evaluate(cdp, "sessionStorage.removeItem('phone_check_out')," + J(SEED) + ",true").catch(() => null);
  await evaluate(cdp, SEED + "true");
}
