"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   browserCheckSocial — the Social page clean-up IN A REAL BROWSER (Nov 12
   2026). jsdom applies no stylesheet, so checkSocialVideoPanel can prove the
   classes and the rules but not what the browser draws. This runs the
   installed Chrome, headless, over the Chrome DevTools Protocol (Node's own
   WebSocket and child_process; no package), the same way as
   scripts/browserCheckAgents.js.

   The frontend is served from disk on 127.0.0.1; requests to the API host are
   answered from the fixtures below; every other outside request is refused.

     1. YouTube connected, TikTok set up but not connected, Instagram and
        Facebook not connected; 2 videos. The Accounts tab: Your videos is its
        own card above the YouTube card; each row has the YouTube chip only.
        "Prepare for YouTube": getComputedStyle on every control in the form
        is the shared style (the page's field glass, border, radius, padding
        and the page's own font), never the browser default a bare control of
        the same kind gets on the same page; the select draws no native
        appearance; "Made for kids?" draws as two segments with no fieldset
        border; the AI helper is full width, under its label, with "Draft with
        AI" under it.
     2. All four connected: the TikTok, Instagram and Facebook forms, the same
        computed checks.
     3. 390 px: with each form open in turn, nothing passes the screen's edge.
   Screenshots to <out>: videos-card.png, youtube-form.png, tiktok-form.png,
   instagram-form.png, facebook-form.png, videos-390.png.

   NAMED (Nov 13 2026, S2):
     4. Instagram and Facebook chips from GET /api/videos' status: posted with
        a link to the post, waiting for approval, not sent; drawn like the
        YouTube and TikTok chips.
     5. proposals.html with one card of each main kind: every value is in the
        page's own font; the View payload block is monospace; values stay
        readable (4.5:1) on every theme preset.
     6. 390 px: the Guide button is a 44 px or larger round button named
        "Guide", bottom-right inside the screen, and at rest and at the scroll
        end it covers no header, tab, heading, form field, button or the Your
        videos card, on the Social page, the dashboard, an agent page (SEO),
        the card maker, proposals and the public card page.
   S2 screenshots to <s2>: proposals-card.png, videos-chips-ig-fb.png,
   guide-390-social.png, guide-390-dashboard.png, guide-390-proposals.png.

   NAMED (Nov 13 2026, S3):
     7. All four connected, one video in each status: not sent "Prepare for
        <Platform>"; waiting and publishing disabled with the reason beside it
        (and a Proposals link when waiting); posted "Post again on <Platform>";
        failed "Try again on <Platform>". "Post again on YouTube" opens the
        styled confirm dialog over the page (fixed, centered, focus on Cancel,
        Escape closes it); "Post again" opens the form.
     8. proposals.html: the date line reads at 4.5:1 or better on its card on 3
        theme presets, at its old size and place.
   S3 screenshots to <s3>: videos-post-again.png, post-again-confirm.png,
   proposals-date.png.

   NOT PART OF THE SERVER SUITE (its name does not start with "check"): run it
   by hand, last. With no Chrome it prints SKIPPED and exits 0.
     CHROME_PATH            the browser (default: the usual Windows paths)
     BIZFORCE_FRONTEND_DIR  the frontend checkout
     SOCIAL_CLEAN_OUT       the screenshot folder (default Downloads\social-clean)
     SOCIAL_S2_OUT          the S2 screenshot folder (default Downloads\s2)
     SOCIAL_S3_OUT          the S3 screenshot folder (default Downloads\s3)
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn, execFileSync } = require("child_process");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const OUT = process.env.SOCIAL_CLEAN_OUT || path.join(os.homedir(), "Downloads", "social-clean");
const OUT2 = process.env.SOCIAL_S2_OUT || path.join(os.homedir(), "Downloads", "s2");
const OUT3 = process.env.SOCIAL_S3_OUT || path.join(os.homedir(), "Downloads", "s3");
const API_HOST = "dynamic-prosperity-production-5382.up.railway.app";
const PAGE = "agents/social.html";

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
const J = JSON.stringify;

/* ── fixtures (the same two videos as checkSocialVideoPanel) ── */
const V_NEW = { id: "22222222-2222-4222-8222-222222222222", label: "Spring cakes", bytes: 3 * 1048576, mime: "video/mp4", status: "ready",
  youtube_video_id: null, youtube_url: null, uploaded_at: null, created_at: "2026-11-07T10:00:00Z", upload_unfinished: false,
  tiktok_status: null, tiktok_posted_at: null, tiktok_post_url: null, tiktok_upload_unfinished: false };
const V_SENT = Object.assign({}, V_NEW, { id: "33333333-3333-4333-8333-333333333333", label: "Autumn menu", mime: "video/webm",
  youtube_video_id: "dQw4w9WgXcQ", youtube_url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ", uploaded_at: "2026-11-07T11:00:00Z",
  tiktok_status: "posted", tiktok_posted_at: "2026-11-07T11:00:00Z", tiktok_post_url: "https://www.tiktok.com/player/v1/7300000000000000001" });
const CREATOR = { creator_nickname: "Maple Street Bakery", privacy_level_options: ["PUBLIC_TO_EVERYONE", "MUTUAL_FOLLOW_FRIENDS", "SELF_ONLY"],
  comment_disabled: false, duet_disabled: true, stitch_disabled: false,
  privacy_words: { PUBLIC_TO_EVERYONE: "Everyone", MUTUAL_FOLLOW_FRIENDS: "Friends", SELF_ONLY: "Only you" } };
// NAMED (Nov 13 2026, S2): Instagram's and Facebook's status, as GET /api/videos now carries it.
const IG_URL = "https://www.instagram.com/reel/AbCdEf123/", FB_URL = "https://www.facebook.com/100000000000001/videos/300000000000003/";
const NONE = { instagram_status: "not_sent", instagram_post_url: null, instagram_error: null, facebook_status: "not_sent", facebook_post_url: null, facebook_error: null };
Object.assign(V_NEW, NONE); Object.assign(V_SENT, NONE);
const V_IG = Object.assign({}, V_NEW, { id: "44444444-4444-4444-8444-444444444444", label: "Bread day", instagram_status: "posted", instagram_post_url: IG_URL, facebook_status: "pending" });
const V_FB = Object.assign({}, V_NEW, { id: "55555555-5555-4555-8555-555555555555", label: "Pie week", instagram_status: "pending", facebook_status: "posted", facebook_post_url: FB_URL });
let VIDEOS = [V_NEW, V_SENT];
// NAMED (Nov 13 2026, S3): one MP4 in each status, every platform; <platform>_proposal as GET /api/videos now carries it.
const P0 = { youtube_proposal: null, tiktok_proposal: null, instagram_proposal: null, facebook_proposal: null };
const S3_NOT = Object.assign({}, V_NEW, P0, { id: "61111111-1111-4111-8111-111111111111", label: "Not sent yet" });
const S3_POSTED = Object.assign({}, V_NEW, P0, { id: "62222222-2222-4222-8222-222222222222", label: "Posted everywhere",
  youtube_video_id: "dQw4w9WgXcQ", youtube_url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ", uploaded_at: "2026-11-07T11:00:00Z",
  tiktok_status: "posted", tiktok_posted_at: "2026-11-07T11:00:00Z", tiktok_post_url: "https://www.tiktok.com/player/v1/7300000000000000001",
  instagram_status: "posted", instagram_post_url: IG_URL, facebook_status: "posted", facebook_post_url: FB_URL });
const S3_WAIT = Object.assign({}, V_NEW, P0, { id: "63333333-3333-4333-8333-333333333333", label: "Waiting for approval",
  youtube_proposal: "pending", tiktok_proposal: "pending", instagram_status: "pending", instagram_proposal: "pending", facebook_status: "pending", facebook_proposal: "pending" });
const S3_PUB = Object.assign({}, V_NEW, P0, { id: "64444444-4444-4444-8444-444444444444", label: "Publishing now",
  youtube_proposal: "publishing", tiktok_status: "processing", instagram_status: "publishing", instagram_proposal: "publishing", facebook_status: "publishing" });
const S3_FAIL = Object.assign({}, V_NEW, P0, { id: "65555555-5555-4555-8555-555555555555", label: "Failed last time",
  tiktok_status: "failed", instagram_status: "failed", instagram_error: "The video is too short for a Reel.", facebook_status: "failed", facebook_error: "The Page token expired." });
const S3_VIDEOS = [S3_NOT, S3_POSTED, S3_WAIT, S3_PUB, S3_FAIL];
// One card of each main kind (proposals.html), pending unless said.
let pn = 0;
const prop = (action_type, title, payload, extra) => Object.assign({ id: "p" + (++pn), agent_type: "social", status: "pending", title: title, reasoning: "Suggested from this week's orders.",
  created_at: "2026-11-13T09:00:00Z", execution_result: null, execution_error: null, action_type: action_type, payload: payload }, extra || {});
const REEL = { id: V_NEW.id, bytes: 3145728 };
const PROPOSALS = [
  prop("publish_instagram_post", "Post the Spring cakes Reel to Instagram", { ig_user_id: "17841400000000000", kind: "reel", caption: "Spring cakes, fresh today. Come early!", video: REEL }),
  prop("publish_facebook_post", "Post the Spring cakes video to Facebook", { page_id: "100000000000001", kind: "video", message: "Spring cakes, fresh today.", video: REEL }),
  prop("publish_youtube_video", "Upload Spring cakes to YouTube", { channel_id: "UC123", title: "Spring cakes", description: "How we bake them, start to finish.", privacy: "private", made_for_kids: false, tags: ["cake", "bakery"], video: REEL }),
  prop("publish_tiktok_post", "Post Spring cakes to TikTok", { title: "Spring cakes", privacy_level: "SELF_ONLY", allow_comment: true, allow_duet: false, allow_stitch: false, video: REEL }),
  prop("publish_social_post", "Post about spring cakes on Bluesky", { platform: "bluesky", posts_as: "maplestreet.bsky.social", text: "Fresh spring cakes today at https://maplestreet.example/cakes" }),
  prop("publish_mastodon_post", "Post about spring cakes on Mastodon", { posts_as: "@maple@mastodon.social", text: "Spring cakes are here." }),
  prop("publish_blog_post", "Publish Spring cakes on the blog", { slug: "spring-cakes", meta_description: "Spring cakes at Maple Street.", body: "<p>Hello <a href='/menu'>menu</a></p>", internal_links: ["/menu", "/about"] }, { agent_type: "seo" }),
  prop("create_calendar_event", "Add the tasting to the calendar", { title: "Tasting", event_type: "meeting", notes: "Bring samples", jdn: 2461358, local_year: 2026, local_month: 11, local_day: 20 }, { agent_type: "executive" }),
  prop("update_store_item", "Raise the Spring cake price", { platform: "shopify", item_name: "Spring cake", field: "price", currency: "USD", measured: { from: 20, to: 22 } }, { agent_type: "store" }),
  prop("send_mailbox_reply", "Reply to Pat about the order", { to: "pat@example.com", from: "hello@maplestreet.example", subject: "Re: order", text: "Your order is ready." }, { agent_type: "mailbox" }),
  prop("publish_instagram_post", "Posted: the Bread day Reel", { ig_user_id: "17841400000000000", kind: "reel", caption: "Bread day.", video: REEL },
    { status: "executed", execution_result: { published: true, permalink: IG_URL } })
];
let ON = {};
function answer(method, p) {
  const st = c => (c ? "connected" : "not_connected");
  const since = "2026-11-07T10:00:00Z";
  if (p === "/api/youtube/status") return { youtube_available: true, connected: !!ON.youtube, status: st(ON.youtube), channel_title: "Maple Street", since };
  if (p === "/api/tiktok/status") return { tiktok_available: true, connected: !!ON.tiktok, status: st(ON.tiktok), display_name: "Maple Street", since };
  if (p === "/api/instagram/status") return { instagram_available: true, connected: !!ON.instagram, status: st(ON.instagram), username: "maplestreet", since };
  if (p === "/api/facebook/status") return { facebook_available: true, connected: !!ON.facebook, status: st(ON.facebook), page_name: "Maple Street", since };
  if (p === "/api/videos" && method === "GET") return { videos: VIDEOS, max_bytes: 52428800, ready_max: 2 };
  if (p === "/api/proposals") return { proposals: PROPOSALS };
  if (p === "/api/media") return { media: [] };
  if (p === "/api/instagram/posts" || p === "/api/facebook/posts") return { posts: [] };
  if (p === "/api/tiktok/creator-info") return CREATOR;
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
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bf-social-clean-"));
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
async function openPage(cdp, origin, on, width) {
  ON = on;
  await cdp.send("Emulation.setDeviceMetricsOverride", { width, height: width < 600 ? 844 : 1000, deviceScaleFactor: 1, mobile: width < 600 });
  await cdp.send("Page.navigate", { url: "about:blank" });
  await sleep(150);
  await cdp.send("Page.navigate", { url: origin + "/" + PAGE });
  for (let i = 0; i < 100; i++) {
    if (await evaluate(cdp, "document.readyState === 'complete' && !!document.getElementById('agTab-accounts') && document.querySelectorAll('#ytVideoList li[data-video-id]').length === " + VIDEOS.length)) break;
    await sleep(100);
  }
  await sleep(400);
  await evaluate(cdp, "document.getElementById('agTab-accounts').click(), true");
  await sleep(300);
  await evaluate(cdp, HELPERS);
}
// A PNG of one element (its whole box, scrolled or not).
async function shotOf(cdp, selectorExpr, file) {
  const box = await evaluate(cdp, "(function(){var n=" + selectorExpr + ";n.scrollIntoView({block:'start'});var r=n.getBoundingClientRect();return {x:r.left+scrollX,y:r.top+scrollY,w:r.width,h:r.height};})()");
  await sleep(200);
  const r = await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true,
    clip: { x: Math.max(0, box.x - 8), y: Math.max(0, box.y - 8), width: Math.ceil(box.w + 16), height: Math.ceil(box.h + 16), scale: 1 } });
  fs.writeFileSync(file, Buffer.from(r.data, "base64"));
}

/* Page-side helpers, installed once per page. */
const HELPERS = `
window.__sc = {
  shown: function (n) { if (!n) return false; for (var e = n; e && e.nodeType === 1; e = e.parentElement) { if (getComputedStyle(e).display === "none") return false; } return true; },
  wide: function (W) { return [].filter.call(document.querySelectorAll("body *"), function (n) { var x = n.getBoundingClientRect(); if (!(x.width > 0 && x.right > W + 1)) return false;
      for (var e = n; e && e.nodeType === 1; e = e.parentElement) { var c = getComputedStyle(e); if (c.position === "fixed" || c.visibility === "hidden" || c.opacity === "0") return false; }
      for (var p = n.parentElement; p && p !== document.body; p = p.parentElement) { var cs = getComputedStyle(p); if (/auto|scroll|hidden|clip/.test(cs.overflowX)) { var b = p.getBoundingClientRect(); if (b.right <= W + 1) return false; } }
      return window.__sc.shown(n); })
    .slice(0, 6).map(function (n) { var x = n.getBoundingClientRect(); return n.tagName + "#" + n.id + "." + String(n.className && n.className.baseVal !== undefined ? n.className.baseVal : n.className).slice(0, 30) + " " + Math.round(x.left) + "-" + Math.round(x.right); }); },
  row: function (id) { return document.querySelector('#ytVideoList li[data-video-id="' + id + '"]'); },
  prepare: function (id, label) { var b = [].filter.call(window.__sc.row(id).querySelectorAll("button"), function (x) { return x.textContent === label; })[0]; if (b) b.click(); return !!b; },
  style: function (n) { var c = getComputedStyle(n); return { tag: n.tagName, type: n.type || "", id: n.id, bg: c.backgroundColor, border: c.borderTopColor, bw: c.borderTopWidth, radius: c.borderTopLeftRadius,
    font: c.fontFamily, size: c.fontSize, pl: c.paddingLeft, app: c.appearance, color: c.color, accent: c.accentColor, w: Math.round(n.getBoundingClientRect().width) }; },
  // the same kind of control with no class, on this page: what the browser draws by default
  bare: function (tag, type) { var n = document.createElement(tag); if (type) n.type = type; if (tag === "select") n.appendChild(document.createElement("option"));
    document.querySelector(".page").appendChild(n); var s = window.__sc.style(n); n.parentNode.removeChild(n); return s; }
};
true`;

const SHARED = { bg: "rgba(10, 14, 30, 0.6)", border: "rgba(244, 114, 182, 0.3)", bw: "1px", radius: "10px" };
// Every visible control in the open form (or a given root) against the shared style and against the browser's own default.
async function formStyle(cdp, rootExpr, name) {
  const st = await evaluate(cdp, "(function(){var root=" + rootExpr + ";var b=window.__sc;var body=getComputedStyle(document.body).fontFamily;" +
    "var ctl=[].filter.call(root.querySelectorAll('input,textarea,select'),function(n){return b.shown(n)&&!n.classList.contains('sf-seg-input')});" +
    "return {body:body,list:ctl.map(b.style),bareTA:b.bare('textarea'),bareSel:b.bare('select'),bareIn:b.bare('input','text')," +
    "fieldsets:root.querySelectorAll('fieldset').length,segs:[].map.call(root.querySelectorAll('.sf-seg-opt span'),function(s){var c=getComputedStyle(s);return {bg:c.backgroundImage==='none'?c.backgroundColor:'gradient',border:c.borderTopColor,radius:c.borderTopLeftRadius}})," +
    "segInputs:[].map.call(root.querySelectorAll('.sf-seg-input'),function(n){var r=n.getBoundingClientRect();return Math.round(r.width)+'x'+Math.round(r.height)+' '+getComputedStyle(n).opacity})};})()");
  const text = st.list.filter(c => c.tag !== "INPUT" || (c.type !== "checkbox" && c.type !== "radio"));
  const boxes = st.list.filter(c => c.tag === "INPUT" && c.type === "checkbox");
  const bad = text.filter(c => !(c.bg === SHARED.bg && c.border === SHARED.border && c.bw === SHARED.bw && c.radius === SHARED.radius && c.font === st.body && !/monospace/i.test(c.font)));
  check(name + ": every text field, textarea and select (" + text.length + ") draws the shared style: rgba(10,14,30,.6) glass, the pink 1px border, 10px radius, the page's own font",
    text.length >= 2 && bad.length === 0, J(bad.length ? bad : st.body));
  check(name + ": ...and NOT the browser's default for the same control on this page (textarea font " + J(st.bareTA.font) + ", select background " + st.bareSel.bg + ")",
    text.every(c => { const d = c.tag === "TEXTAREA" ? st.bareTA : (c.tag === "SELECT" ? st.bareSel : st.bareIn); return c.bg !== d.bg && c.font !== (c.tag === "TEXTAREA" ? st.bareTA.font : "x"); }) &&
    /monospace/i.test(st.bareTA.font), J([st.bareTA, st.bareSel]));
  const sels = text.filter(c => c.tag === "SELECT");
  check(name + ": every select (" + sels.length + ") draws no native appearance on a dark ground", sels.every(c => c.app === "none" && c.bg === SHARED.bg), J(sels));
  if (boxes.length) check(name + ": every checkbox (" + boxes.length + ") is 18px in the page's accent", boxes.every(c => c.w === 18 && c.accent === "rgb(244, 114, 182)"), J(boxes));
  check(name + ": no fieldset border anywhere in it", st.fieldsets === 0);
  return st;
}
async function helperGeometry(cdp, rootExpr, name) {
  const g = await evaluate(cdp, "(function(){var root=" + rootExpr + ";var l=[].filter.call(root.querySelectorAll('label'),function(x){return x.textContent==='Describe the video for the AI writer'})[0];if(!l)return null;" +
    "var t=document.getElementById(l.getAttribute('for'));var u=t.nextElementSibling;var btn=u&&u.querySelector('button');var f=t.parentElement.getBoundingClientRect(),lr=l.getBoundingClientRect(),tr=t.getBoundingClientRect(),br=btn?btn.getBoundingClientRect():null;" +
    "var form=t.closest('.sf-form').getBoundingClientRect();var c=getComputedStyle(t);" +
    "return {formW:Math.round(form.width),fieldW:Math.round(f.width),taW:Math.round(tr.width),taL:Math.round(tr.left),lL:Math.round(lr.left),lBottom:Math.round(lr.bottom),taTop:Math.round(tr.top),taBottom:Math.round(tr.bottom)," +
    "btnTop:br?Math.round(br.top):null,btnL:br?Math.round(br.left):null,btn:btn?btn.textContent:null,rows:t.rows,font:c.fontFamily,ph:t.placeholder};})()");
  check(name + ": the AI helper is full width under its label, \"Draft with AI\" directly under it, in the page's font",
    !!g && Math.abs(g.taW - g.fieldW) <= 1 && Math.abs(g.fieldW - g.formW) <= 1 && g.lBottom <= g.taTop && g.lL === g.taL && g.btnTop >= g.taBottom && g.btnTop - g.taBottom <= 16 &&
    g.btnL === g.taL && /^Draft/.test(g.btn) && g.rows === 3 && !/monospace/i.test(g.font) && g.ph === "For example: a 30-second clip showing our herbal oil and how to use it", J(g));
}

/* NAMED (Nov 13 2026, S2): any page, waiting until the Guide button is on it. */
async function openAny(cdp, origin, page, width) {
  await cdp.send("Emulation.setDeviceMetricsOverride", { width, height: width < 600 ? 844 : 1000, deviceScaleFactor: 1, mobile: width < 600 });
  await cdp.send("Page.navigate", { url: "about:blank" });
  await sleep(150);
  await cdp.send("Page.navigate", { url: origin + "/" + page });
  for (let i = 0; i < 100; i++) {
    if (await evaluate(cdp, "document.readyState === 'complete' && !!document.getElementById('tmx-guide-fab')")) break;
    await sleep(100);
  }
  await sleep(1300);   // past the Guide's own settle (load + 800 ms)
  await evaluate(cdp, HELPERS);
}
// The Guide button against what it must never cover, at the current scroll.
const GUIDE_PROBE = "(function(){var fab=document.getElementById('tmx-guide-fab');if(!fab)return {none:true};var f=fab.getBoundingClientRect(),c=getComputedStyle(fab);" +
  "var sel='header,nav,[role=tablist],[role=tab],h1,h2,h3,input:not([type=hidden]),textarea,select,button,a[href],.btn,#videosCard,.tabs,.tab-row';" +
  "var hits=[].filter.call(document.querySelectorAll(sel),function(n){if(n===fab||fab.contains(n)||n.closest('[id^=tmx-guide]'))return false;" +
  "if(!window.__sc.shown(n))return false;var cs=getComputedStyle(n);if(cs.visibility==='hidden'||cs.opacity==='0')return false;var r=n.getBoundingClientRect();if(!(r.width>0&&r.height>0))return false;" +
  "return r.left<f.right-0.5&&r.right>f.left+0.5&&r.top<f.bottom-0.5&&r.bottom>f.top+0.5;}).slice(0,6).map(function(n){var r=n.getBoundingClientRect();return n.tagName+'#'+n.id+'.'+String(n.className).slice(0,30)+' '+Math.round(r.top)+'-'+Math.round(r.bottom)+' '+Math.round(r.left)+'-'+Math.round(r.right);});" +
  "return {at:Math.round(f.left)+','+Math.round(f.top),w:Math.round(f.width),h:Math.round(f.height),right:Math.round(innerWidth-f.right),bottom:Math.round(innerHeight-f.bottom),left:Math.round(f.left),radius:c.borderTopLeftRadius,z:c.zIndex,pos:c.position," +
  "name:fab.getAttribute('aria-label'),shown:window.__sc.shown(fab),hits:hits,scrollY:Math.round(scrollY),end:Math.round(document.documentElement.scrollHeight-innerHeight)};})()";
async function guideAt390(cdp, origin, page, name, shotFile, prepare) {
  await openAny(cdp, origin, page, 390);
  if (prepare) await prepare();
  const top = await evaluate(cdp, "scrollTo(0,0)," + GUIDE_PROBE);
  check("390 px, " + name + ": the Guide button is a round " + top.w + "x" + top.h + " px button named \"Guide\", bottom-right inside the screen, over the page (z-index 40)",
    !top.none && top.shown && top.w >= 44 && top.h >= 44 && top.radius === "50%" && top.name === "Guide" && top.right >= 16 && top.bottom >= 16 && top.left > 195 &&
    top.pos === "fixed" && top.z === "40", J(top));
  check("390 px, " + name + ": at rest (button at " + top.at + ") it covers no header, tab, heading, form field, button or link" + (page === PAGE ? " and not the Your videos card" : ""), !top.none && top.hits.length === 0, J(top.hits));
  if (shotFile) {
    const r = await cdp.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(OUT2, shotFile), Buffer.from(r.data, "base64"));
  }
  await evaluate(cdp, "scrollTo(0,document.documentElement.scrollHeight),true");
  await sleep(300);
  const end = await evaluate(cdp, GUIDE_PROBE);
  check("390 px, " + name + ": at the scroll end (" + end.scrollY + " px, button at " + end.at + ") it covers none of them either", !end.none && end.hits.length === 0 && end.scrollY >= end.end - 1, J(end));
}
// WCAG contrast of two "rgb(a)" strings, the first laid over the second.
function contrast(fg, bg) {
  const p = s => (String(s).match(/[\d.]+/g) || [0, 0, 0, 1]).map(Number);
  const b = p(bg), f0 = p(fg), a = f0.length > 3 ? f0[3] : 1;
  const f = [0, 1, 2].map(i => f0[i] * a + b[i] * (1 - a));
  const L = c => { const v = c.map(x => { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); }); return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2]; };
  const l1 = L(f), l2 = L(b.slice(0, 3));
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}

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
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{localStorage.setItem('bf_token','browser-check-token');localStorage.setItem('bf_user',JSON.stringify({id:'00000000-0000-4000-8000-000000000001',role:'member'}));}catch(e){}" });

    /* ── 1. YouTube connected, TikTok not ── */
    console.log("\n══ 1. YouTube connected, TikTok not; 2 videos (1440 px) ══");
    await openPage(cdp, origin, { youtube: true }, 1440);
    const c1 = await evaluate(cdp, "(function(){var b=window.__sc,card=document.getElementById('videosCard');return {shown:b.shown(card),next:card.nextElementSibling&&card.nextElementSibling.id," +
      "inYt:document.getElementById('ytConnect').contains(card),above:card.getBoundingClientRect().bottom<=document.getElementById('ytConnect').getBoundingClientRect().top," +
      "chips:[].map.call(document.querySelectorAll('#ytVideoList .sf-chip'),function(c){var s=getComputedStyle(c);return c.textContent+'|'+s.color+'|'+s.borderTopLeftRadius})," +
      "prepares:[].map.call(document.querySelectorAll('#ytVideoList button[data-prepare]'),function(x){return x.textContent})};})()");
    check("Your videos is its own displayed card, directly above the YouTube card, not inside it", c1.shown && c1.next === "ytConnect" && !c1.inYt && c1.above, J(c1));
    // NAMED (Nov 13 2026, S3): BEFORE the uploaded video had no YouTube button (prepares was "Prepare for YouTube" alone); NOW it
    // offers "Post again on YouTube" (asked first, section 7). The new video's "Prepare for YouTube" is unchanged.
    check("each row has the YouTube chip only, drawn as a pill in a theme colour; no TikTok chip; \"Prepare for YouTube\" on the new video, \"Post again on YouTube\" on the uploaded one",
      c1.chips.length === 2 && c1.chips.every(x => /^YouTube: (not sent|uploaded)\|rgb\(/.test(x) && /\|999px$/.test(x)) && c1.prepares.join() === "Prepare for YouTube,Post again on YouTube", J(c1));
    check("no script error on the page", exceptions.length === 0, exceptions.join(" | "));
    await shotOf(cdp, "document.getElementById('videosCard')", path.join(OUT, "videos-card.png"));
    await evaluate(cdp, "window.__sc.prepare('" + V_NEW.id + "','Prepare for YouTube')");
    await sleep(300);
    const panelExpr = "document.querySelector('#ytVideoList .sf-panel')";
    check("\"Prepare for YouTube\" opens one form, headed \"YouTube upload\"",
      await evaluate(cdp, "document.querySelectorAll('#ytVideoList .sf-panel').length===1&&document.querySelector('#ytVideoList .sf-panel-head').textContent==='YouTube upload'"));
    await formStyle(cdp, panelExpr, "YouTube form");
    await helperGeometry(cdp, panelExpr, "YouTube form");
    const kids = await evaluate(cdp, "(function(){var g=document.querySelector('#ytVideoList [role=radiogroup]');var spans=[].map.call(g.querySelectorAll('.sf-seg-opt span'),function(s){var c=getComputedStyle(s);return {t:s.textContent,border:c.borderTopColor,radius:c.borderTopLeftRadius,h:Math.round(s.getBoundingClientRect().height)}});" +
      "var lab=document.getElementById(g.getAttribute('aria-labelledby'));var radios=[].map.call(g.querySelectorAll('input'),function(n){var r=n.getBoundingClientRect();return Math.round(r.width)+'x'+Math.round(r.height)});" +
      "var gr=g.getBoundingClientRect(),lr=lab.getBoundingClientRect();g.querySelector('input').focus();g.querySelector('input').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true}));" +
      "var on=[].map.call(g.querySelectorAll('input'),function(n){return n.checked});var onSpan=getComputedStyle(g.querySelector('input:checked + span')).backgroundImage;" +
      "return {spans:spans,label:lab.textContent,labelAbove:lr.bottom<=gr.top,radios:radios,fieldset:!!g.closest('fieldset'),on:on,onSpan:/gradient/.test(onSpan)};})()");
    check("\"Made for kids?\": a label above two segments drawn like the site's tabs (10px radius, a soft border), the radios hidden in them, no fieldset",
      kids.label === "Made for kids?" && kids.labelAbove && kids.spans.map(x => x.t).join() === "Yes,No" && kids.spans.every(x => x.radius === "10px" && x.h >= 30) &&
      kids.radios.every(x => x === "1x1") && !kids.fieldset, J(kids));
    check("...the arrow key chooses Yes, and the chosen segment draws the button gradient", J(kids.on) === J([true, false]) && kids.onSpan, J(kids));
    await shotOf(cdp, "document.querySelector('#ytVideoList li[data-video-id=\"" + V_NEW.id + "\"]')", path.join(OUT, "youtube-form.png"));

    /* ── 2. all four connected ── */
    console.log("\n══ 2. TikTok, Instagram and Facebook connected (1440 px) ══");
    await openPage(cdp, origin, { youtube: true, tiktok: true, instagram: true, facebook: true }, 1440);
    const c2 = await evaluate(cdp, "[].map.call(document.querySelectorAll('#ytVideoList li[data-video-id=\"" + V_NEW.id + "\"] .sf-chip'),function(c){return c.textContent})");
    // NAMED (Nov 13 2026, S2): Instagram and Facebook say what they have of the video (not sent here), not what the file allows.
    check("all four connected: four chips on the new video", J(c2) === J(["YouTube: not sent", "TikTok: not sent", "Instagram: not sent", "Facebook: not sent"]), J(c2));
    const dim = await evaluate(cdp, "(function(){var row=window.__sc.row('" + V_SENT.id + "');var bs=[].filter.call(row.querySelectorAll('button[data-prepare]'),function(b){return b.disabled});" +
      "var on=[].filter.call(window.__sc.row('" + V_NEW.id + "').querySelectorAll('button[data-prepare]'),function(b){return !b.disabled})[0];" +
      "var fb=getComputedStyle(document.getElementById('ytFile'),'::file-selector-button');" +
      "return {off:bs.map(function(b){return b.textContent+'|'+getComputedStyle(b).opacity}),on:getComputedStyle(on).opacity,pick:{bg:fb.backgroundColor,font:fb.fontFamily,radius:fb.borderTopLeftRadius},body:getComputedStyle(document.body).fontFamily};})()");
    check("a WebM row's Instagram and Facebook buttons are disabled and drawn dimmed; an enabled one is not",
      dim.off.length === 2 && dim.off.every(x => /\|0\.45$/.test(x)) && dim.on === "1", J(dim));
    check("the file picker's button draws the page's dark style and font, not the browser's grey button",
      dim.pick.bg === "rgba(12, 16, 36, 0.9)" && dim.pick.font === dim.body && dim.pick.radius === "8px", J(dim));
    const forms = [["Prepare for TikTok", "TikTok post", "tiktok-form.png"], ["Prepare for Instagram", "Instagram Reel", "instagram-form.png"], ["Prepare for Facebook", "Facebook video post", "facebook-form.png"]];
    for (const [btn, head, file] of forms) {
      await evaluate(cdp, "window.__sc.prepare('" + V_NEW.id + "'," + J(btn) + ")");
      await sleep(500);
      const open = await evaluate(cdp, "(function(){var p=document.querySelectorAll('#ytVideoList .sf-panel');return {n:p.length,head:p[0]?p[0].querySelector('.sf-panel-head').textContent:null};})()");
      check("\"" + btn + "\" opens one form, headed \"" + head + "\"", open.n === 1 && open.head === head, J(open));
      await formStyle(cdp, panelExpr, head + " form");
      await helperGeometry(cdp, panelExpr, head + " form");
      await shotOf(cdp, "document.querySelector('#ytVideoList li[data-video-id=\"" + V_NEW.id + "\"]')", path.join(OUT, file));
    }
    check("no script error on the page", exceptions.length === 0, exceptions.join(" | "));

    /* ── 3. 390 px ── */
    console.log("\n══ 3. 390 px ══");
    await openPage(cdp, origin, { youtube: true, tiktok: true, instagram: true, facebook: true }, 390);
    const w0 = await evaluate(cdp, "({wide:window.__sc.wide(390),docW:document.documentElement.scrollWidth})");
    check("390 px, no form open: nothing passes the screen's edge", w0.wide.length === 0 && w0.docW <= 390, J(w0));
    for (const [btn] of [["Prepare for YouTube"]].concat(forms)) {
      await evaluate(cdp, "window.__sc.prepare('" + V_NEW.id + "'," + J(btn) + ")");
      await sleep(500);
      const w = await evaluate(cdp, "(function(){var p=document.querySelector('#ytVideoList .sf-panel');var ctl=[].filter.call(p.querySelectorAll('input,textarea,select'),function(n){return window.__sc.shown(n)&&!n.classList.contains('sf-seg-input')}).map(function(n){return Math.round(n.getBoundingClientRect().right)});" +
        "return {wide:window.__sc.wide(390),docW:document.documentElement.scrollWidth,maxRight:Math.max.apply(null,ctl.concat([0])),panelRight:Math.round(p.getBoundingClientRect().right)};})()");
      check("390 px, \"" + btn + "\" open: nothing passes the screen's edge; every field fits inside the form", w.wide.length === 0 && w.docW <= 390 && w.maxRight <= w.panelRight && w.panelRight <= 390, J(w));
      if (btn === "Prepare for YouTube") await shotOf(cdp, "document.getElementById('videosCard')", path.join(OUT, "videos-390.png"));
    }
    check("no script error on the page", exceptions.length === 0, exceptions.join(" | "));

    /* ── 4. Instagram and Facebook chips (NAMED Nov 13 2026, S2) ── */
    console.log("\n══ 4. Instagram and Facebook chips: posted with a link, waiting for approval, not sent (1440 px) ══");
    fs.mkdirSync(OUT2, { recursive: true });
    VIDEOS = [V_IG, V_FB, V_NEW];
    await openPage(cdp, origin, { youtube: true, tiktok: true, instagram: true, facebook: true }, 1440);
    const c4 = await evaluate(cdp, "(function(){var b=window.__sc;function info(id){var row=b.row(id);return {chips:[].map.call(row.querySelectorAll('.sf-chip'),function(c){var s=getComputedStyle(c);" +
      "return c.textContent+'|'+s.borderTopLeftRadius+'|'+s.fontFamily+'|'+s.fontSize+'|'+s.paddingLeft})," +
      "links:[].map.call(row.querySelectorAll('a'),function(a){return a.href})};}return {a:info('" + V_IG.id + "'),b:info('" + V_FB.id + "'),c:info('" + V_NEW.id + "')};})()");
    const words = r => r.chips.map(x => x.split("|")[0]);
    check("posted on Instagram, waiting on Facebook: \"Instagram: posted\" and \"Facebook: waiting for your approval\", with a link to the Instagram post only",
      J(words(c4.a)) === J(["YouTube: not sent", "TikTok: not sent", "Instagram: posted", "Facebook: waiting for your approval"]) &&
      c4.a.links.indexOf(IG_URL) !== -1 && !c4.a.links.some(h => /facebook\.com/.test(h)), J(c4.a));
    check("waiting on Instagram, posted on Facebook: the other way round, with a link to the Facebook post only",
      J(words(c4.b)) === J(["YouTube: not sent", "TikTok: not sent", "Instagram: waiting for your approval", "Facebook: posted"]) &&
      c4.b.links.indexOf(FB_URL) !== -1 && !c4.b.links.some(h => /instagram\.com/.test(h)), J(c4.b));
    check("sent nowhere: \"Instagram: not sent\" and \"Facebook: not sent\", no link", J(words(c4.c)) === J(["YouTube: not sent", "TikTok: not sent", "Instagram: not sent", "Facebook: not sent"]) && c4.c.links.length === 0, J(c4.c));
    const looks = [].concat(c4.a.chips, c4.b.chips, c4.c.chips).map(x => x.split("|").slice(1).join("|"));
    check("every Instagram and Facebook chip is drawn exactly like the YouTube and TikTok chips (pill, font, size, padding)", new Set(looks).size === 1 && /^999px\|/.test(looks[0]), J(Array.from(new Set(looks))));
    await shotOf(cdp, "document.getElementById('videosCard')", path.join(OUT2, "videos-chips-ig-fb.png"));
    VIDEOS = [V_NEW, V_SENT];
    check("no script error on the page", exceptions.length === 0, exceptions.join(" | "));

    /* ── 5. proposal cards (NAMED Nov 13 2026, S2) ── */
    console.log("\n══ 5. proposals.html: one card of each main kind, the site font (1440 px) ══");
    await openAny(cdp, origin, "proposals.html", 1440);
    for (let i = 0; i < 50 && (await evaluate(cdp, "document.querySelectorAll('.proposal-card').length")) !== PROPOSALS.length; i++) await sleep(100);
    const f5 = await evaluate(cdp, "(function(){var body=getComputedStyle(document.body).fontFamily;var cards=document.querySelectorAll('.proposal-card');var off=[],n=0;" +
      "[].forEach.call(cards,function(card){[].forEach.call(card.querySelectorAll('*'),function(el){var own=[].some.call(el.childNodes,function(c){return c.nodeType===3&&c.textContent.trim()});" +
      "if(!own||el.closest('details.payload-toggle > pre'))return;n++;var ff=getComputedStyle(el).fontFamily;if(ff!==body)off.push(el.tagName+'.'+el.className+' '+ff);});});" +
      "[].forEach.call(document.querySelectorAll('details.payload-toggle'),function(d){d.open=true});" +
      "var raw=[].map.call(document.querySelectorAll('details.payload-toggle > pre'),function(p){return getComputedStyle(p).fontFamily});" +
      "var links=[].map.call(document.querySelectorAll('.proposal-card a.pf-value'),function(a){var r=a.getBoundingClientRect(),p=a.closest('.proposal-card').getBoundingClientRect();return {href:a.href,ff:getComputedStyle(a).fontFamily,inside:r.right<=p.right+0.5}});" +
      "return {cards:cards.length,body:body,n:n,off:off.slice(0,8),raw:raw,links:links};})()");
    check("all " + PROPOSALS.length + " cards drawn (Instagram, Facebook, YouTube, TikTok, Bluesky, Mastodon, blog, calendar, store, mailbox, a posted one)", f5.cards === PROPOSALS.length, J(f5.cards));
    check("every one of the " + f5.n + " text-bearing elements on the cards is in the page's own font (" + f5.body.slice(0, 40) + "...), the raw payload aside",
      f5.n > 60 && f5.off.length === 0 && !/monospace/i.test(f5.body), J(f5.off));
    check("each View payload block (" + f5.raw.length + ") is monospace", f5.raw.length === PROPOSALS.length && f5.raw.every(x => /monospace/i.test(x)), J(f5.raw.slice(0, 2)));
    check("the posted Instagram address is a link in the page's font that wraps inside its card", f5.links.some(l => l.href === IG_URL) && f5.links.every(l => l.ff === f5.body && l.inside), J(f5.links));
    check("no script error on the page", exceptions.length === 0, exceptions.join(" | "));
    await evaluate(cdp, "[].forEach.call(document.querySelectorAll('details.payload-toggle'),function(d,i){d.open=(i===0)}),true");
    await shotOf(cdp, "document.querySelector('.proposal-card')", path.join(OUT2, "proposals-card.png"));
    const presets = await evaluate(cdp, "window.BFTheme?window.BFTheme.PRESETS.map(function(p){return p.id}):[]");
    const lows = [];
    for (const id of presets) {
      const m = await evaluate(cdp, "(function(){var B=window.BFTheme,p=B.PRESETS.filter(function(x){return x.id==='" + id + "'})[0];var t=B.tokensFor(p.theme,null,window);" +
        "for(var k in t)document.documentElement.style.setProperty(k,t[k]);var probe=document.createElement('div');probe.style.background='var(--bf-bg, #000)';document.body.appendChild(probe);" +
        "var bg=getComputedStyle(probe).backgroundColor;probe.remove();var card=getComputedStyle(document.querySelector('.proposal-card')).backgroundColor;" +
        "var els=document.querySelectorAll('.proposal-card .pf-value, .proposal-card .payload-fields li, .proposal-card pre.exec-block');" +
        "return {bg:bg,card:card,colors:[].map.call(els,function(e){return e.className+'|'+getComputedStyle(e).color})};})()");
      const back = (() => { const pc = (String(m.card).match(/[\d.]+/g) || []).map(Number), pb = (String(m.bg).match(/[\d.]+/g) || [0, 0, 0]).map(Number), a = pc.length > 3 ? pc[3] : 1;
        return "rgb(" + [0, 1, 2].map(i => pc[i] * a + pb[i] * (1 - a)).join(",") + ")"; })();
      m.colors.forEach(x => { const [cls, col] = x.split("|"); const r = contrast(col, back); if (r < 4.5) lows.push(id + " ." + cls + " " + col + " " + r.toFixed(2)); });
    }
    check("on every theme preset (" + presets.length + "), every value, list item and text block reads at 4.5:1 or better on its card", presets.length >= 10 && lows.length === 0, J(lows.slice(0, 8)));

    /* ── 6. the Guide button at 390 px (NAMED Nov 13 2026, S2) ── */
    console.log("\n══ 6. the Guide button at 390 px: compact, named, covering nothing ══");
    ON = { youtube: true, tiktok: true, instagram: true, facebook: true };
    await guideAt390(cdp, origin, PAGE, "the Social page (Accounts, Your videos)", "guide-390-social.png", async () => {
      for (let i = 0; i < 50 && !(await evaluate(cdp, "document.querySelectorAll('#ytVideoList li[data-video-id]').length === 2")); i++) await sleep(100);
      // a tap: the click, then the pointerup the Guide settles on
      await evaluate(cdp, "document.getElementById('agTab-accounts').click(), document.dispatchEvent(new PointerEvent('pointerup', { bubbles: true })), true");
      await sleep(400);
    });
    await guideAt390(cdp, origin, "dashboard.html", "the dashboard", "guide-390-dashboard.png");
    await guideAt390(cdp, origin, "agents/seo.html", "an agent page (SEO)");
    await guideAt390(cdp, origin, "digital-cards.html", "the card maker");
    await guideAt390(cdp, origin, "proposals.html", "proposals", "guide-390-proposals.png");
    await guideAt390(cdp, origin, "card-view.html?slug=maple-street", "the public card page");
    await openAny(cdp, origin, "proposals.html", 1440);
    const desk = await evaluate(cdp, GUIDE_PROBE + "");
    const deskText = await evaluate(cdp, "(function(){var t=document.querySelector('#tmx-guide-fab .tmx-guide-fab-text');var i=document.querySelector('#tmx-guide-fab .tmx-guide-fab-icon');" +
      "return {text:t?getComputedStyle(t).position+'|'+Math.round(t.getBoundingClientRect().width):null,icon:i?getComputedStyle(i).display:null,spacer:getComputedStyle(document.getElementById('tmx-guide-fab-spacer')).display};})()");
    check("1440 px: the desktop Guide button is unchanged (its word shown, no icon, no spacer)",
      !!deskText.text && !/^absolute/.test(deskText.text) && deskText.icon === "none" && deskText.spacer === "none", J([deskText, desk.w, desk.h]));

    /* ── 7. Post again, Try again, waiting and publishing (NAMED Nov 13 2026, S3) ── */
    console.log("\n══ 7. one video in each status, all four connected: the buttons and the Post again dialog (1440 px) ══");
    fs.mkdirSync(OUT3, { recursive: true });
    VIDEOS = S3_VIDEOS;
    await openPage(cdp, origin, { youtube: true, tiktok: true, instagram: true, facebook: true }, 1440);
    const b7 = await evaluate(cdp, "(function(){var b=window.__sc,out={};" + J(S3_VIDEOS.map(v => v.id)) + ".forEach(function(id){var row=b.row(id);" +
      "out[id]=[].map.call(row.querySelectorAll('button[data-prepare]'),function(x){var why=x.getAttribute('aria-describedby')?document.getElementById(x.getAttribute('aria-describedby')):null;" +
      "var link=why&&why.nextElementSibling&&why.nextElementSibling.tagName==='A'?why.nextElementSibling:null;var r=x.getBoundingClientRect(),w=why?why.getBoundingClientRect():null;" +
      "return {t:x.textContent,off:x.disabled,op:getComputedStyle(x).opacity,why:why?why.textContent:null,whyShown:why?b.shown(why)&&w.width>0:null,beside:why?(w.left>=r.right-1&&Math.abs((w.top+w.bottom)/2-(r.top+r.bottom)/2)<=12):null," +
      "link:link?link.textContent+'|'+link.getAttribute('href'):null}})});return out;})()");
    const texts = id => b7[id].map(x => x.t + (x.off ? " (off)" : ""));
    const WORDS = ["YouTube", "TikTok", "Instagram", "Facebook"];
    check("not sent: \"Prepare for YouTube\", \"Prepare for TikTok\", \"Prepare for Instagram\", \"Prepare for Facebook\", each enabled",
      J(texts(S3_NOT.id)) === J(WORDS.map(w => "Prepare for " + w)), J(b7[S3_NOT.id]));
    check("posted: \"Post again on YouTube\", \"Post again on TikTok\", \"Post again on Instagram\", \"Post again on Facebook\", each enabled",
      J(texts(S3_POSTED.id)) === J(WORDS.map(w => "Post again on " + w)), J(b7[S3_POSTED.id]));
    check("failed: \"Try again on TikTok\", \"Try again on Instagram\", \"Try again on Facebook\" (YouTube has no failed state: \"Prepare for YouTube\")",
      J(texts(S3_FAIL.id)) === J(["Prepare for YouTube", "Try again on TikTok", "Try again on Instagram", "Try again on Facebook"]), J(b7[S3_FAIL.id]));
    check("waiting: every button disabled and dimmed, \"Waiting for your approval\" drawn beside it, with \"Open Proposals\" to /proposals.html",
      b7[S3_WAIT.id].length === 4 && b7[S3_WAIT.id].every(x => x.off && x.op === "0.45" && x.why === "Waiting for your approval" && x.whyShown && x.beside && x.link === "Open Proposals|/proposals.html"), J(b7[S3_WAIT.id]));
    check("publishing: every button disabled, \"Publishing\" drawn beside it, no Proposals link",
      b7[S3_PUB.id].length === 4 && b7[S3_PUB.id].every(x => x.off && x.why === "Publishing" && x.whyShown && x.beside && x.link === null), J(b7[S3_PUB.id]));
    check("no script error on the page", exceptions.length === 0, exceptions.join(" | "));
    await shotOf(cdp, "document.getElementById('videosCard')", path.join(OUT3, "videos-post-again.png"));
    const key = async (k, shift) => {
      const code = { Escape: 27, Tab: 9 }[k];
      await cdp.send("Input.dispatchKeyEvent", { type: "keyDown", key: k, code: k, windowsVirtualKeyCode: code, modifiers: shift ? 8 : 0 });
      await cdp.send("Input.dispatchKeyEvent", { type: "keyUp", key: k, code: k, windowsVirtualKeyCode: code, modifiers: shift ? 8 : 0 });
      await sleep(150);
    };
    await evaluate(cdp, "window.__sc.prepare('" + S3_POSTED.id + "','Post again on YouTube')");
    await sleep(300);
    const DLG = "(function(){var back=document.querySelector('.sf-dialog-back');if(!back)return null;var d=back.querySelector('[role=dialog]');var r=d.getBoundingClientRect(),cb=getComputedStyle(back),cd=getComputedStyle(d);" +
      "var lab=document.getElementById(d.getAttribute('aria-labelledby'));return {pos:cb.position,z:cb.zIndex,cover:Math.round(back.getBoundingClientRect().width)+'x'+Math.round(back.getBoundingClientRect().height)," +
      "cx:Math.round((r.left+r.right)/2),cy:Math.round((r.top+r.bottom)/2),w:Math.round(r.width),modal:d.getAttribute('aria-modal'),label:lab?lab.textContent:null,font:cd.fontFamily,body:getComputedStyle(document.body).fontFamily," +
      "buttons:[].map.call(d.querySelectorAll('button'),function(x){return x.textContent+'|'+x.className}),focus:document.activeElement?document.activeElement.textContent:null,panels:document.querySelectorAll('#ytVideoList .sf-panel').length};})()";
    const d7 = await evaluate(cdp, DLG);
    check("\"Post again on YouTube\" opens the confirm dialog over the whole page (fixed, z-index 1000), centred, in the page's font, labelled \"This video is already on YouTube. Post it again?\", focus on Cancel, no form yet",
      !!d7 && d7.pos === "fixed" && d7.z === "1000" && d7.cover === "1440x1000" && Math.abs(d7.cx - 720) <= 2 && Math.abs(d7.cy - 500) <= 2 && d7.modal === "true" &&
      d7.label === "This video is already on YouTube. Post it again?" && d7.font === d7.body && J(d7.buttons) === J(["Post again|action-btn", "Cancel|action-btn action-btn--ghost"]) &&
      d7.focus === "Cancel" && d7.panels === 0, J(d7));
    const s7 = await cdp.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(OUT3, "post-again-confirm.png"), Buffer.from(s7.data, "base64"));
    const trail7 = [];
    for (const sh of [false, false, true]) { await key("Tab", sh); trail7.push(await evaluate(cdp, "document.activeElement.textContent")); }
    check("real Tab and Shift+Tab keys stay on the dialog's two buttons", J(trail7) === J(["Post again", "Cancel", "Post again"]), J(trail7));
    await key("Escape");
    const e7 = await evaluate(cdp, "({open:!!document.querySelector('.sf-dialog-back'),panels:document.querySelectorAll('#ytVideoList .sf-panel').length,focus:document.activeElement.textContent})");
    check("a real Escape closes it: no form, focus back on \"Post again on YouTube\"", !e7.open && e7.panels === 0 && e7.focus === "Post again on YouTube", J(e7));
    await evaluate(cdp, "window.__sc.prepare('" + S3_POSTED.id + "','Post again on YouTube')");
    await sleep(300);
    await evaluate(cdp, "[].filter.call(document.querySelectorAll('.sf-dialog-back button'),function(x){return x.textContent==='Post again'})[0].click(),true");
    await sleep(500);
    const o7 = await evaluate(cdp, "(function(){var p=document.querySelectorAll('#ytVideoList .sf-panel');return {open:!!document.querySelector('.sf-dialog-back'),n:p.length,head:p[0]?p[0].querySelector('.sf-panel-head').textContent:null};})()");
    check("\"Post again\" closes the dialog and opens the YouTube upload form", !o7.open && o7.n === 1 && o7.head === "YouTube upload", J(o7));
    check("no script error on the page", exceptions.length === 0, exceptions.join(" | "));
    VIDEOS = [V_NEW, V_SENT];

    /* ── 8. the proposal date line (NAMED Nov 13 2026, S3) ── */
    console.log("\n══ 8. proposals.html: the date line on 3 themes (1440 px) ══");
    await openAny(cdp, origin, "proposals.html", 1440);
    for (let i = 0; i < 50 && (await evaluate(cdp, "document.querySelectorAll('.proposal-card').length")) !== PROPOSALS.length; i++) await sleep(100);
    // Chrome computes color-mix() as color(srgb r g b) with 0..1 channels.
    const rgbOf = s => { const m = /^color\(srgb ([\d.]+) ([\d.]+) ([\d.]+)(?: \/ ([\d.]+))?\)$/.exec(String(s));
      return m ? "rgba(" + [m[1], m[2], m[3]].map(x => Math.round(Number(x) * 255)).join(",") + "," + (m[4] === undefined ? 1 : m[4]) + ")" : String(s); };
    const dates = [];
    for (const id of ["original", "arctic", "nebula"]) {
      const m = await evaluate(cdp, "(function(){var B=window.BFTheme,p=B.PRESETS.filter(function(x){return x.id==='" + id + "'})[0];var t=B.tokensFor(p.theme,null,window);" +
        "for(var k in t)document.documentElement.style.setProperty(k,t[k]);var probe=document.createElement('div');probe.style.background='var(--bf-bg, #000)';document.body.appendChild(probe);" +
        "var bg=getComputedStyle(probe).backgroundColor;probe.remove();var c=document.querySelector('.proposal-card');var d=c.querySelector('.proposal-date');var cs=getComputedStyle(d);" +
        "var dr=d.getBoundingClientRect(),pr=d.parentElement.getBoundingClientRect();" +
        "return {bg:bg,card:getComputedStyle(c).backgroundColor,color:cs.color,size:cs.fontSize,root:getComputedStyle(document.documentElement).fontSize,right:Math.round(pr.right-dr.right),text:d.textContent};})()");
      const pc = (String(m.card).match(/[\d.]+/g) || []).map(Number), pb = (String(m.bg).match(/[\d.]+/g) || [0, 0, 0]).map(Number), a = pc.length > 3 ? pc[3] : 1;
      const back = "rgb(" + [0, 1, 2].map(i => pc[i] * a + pb[i] * (1 - a)).join(",") + ")";
      dates.push({ id, color: m.color, ratio: Math.round(contrast(rgbOf(m.color), back) * 100) / 100, size: m.size, root: m.root, right: m.right, text: m.text });
    }
    console.log("      date line contrast: " + dates.map(d => d.id + " " + d.ratio.toFixed(2)).join(", "));
    check("the date line reads at 4.5:1 or better on its card on original, arctic and nebula, each a different colour from its theme's accent",
      dates.length === 3 && dates.every(d => d.ratio >= 4.5) && new Set(dates.map(d => d.color)).size === 3, J(dates));
    check("...at its old size (.72rem) and place (pushed to the header's right end), with a date in it",
      dates.every(d => Math.abs(parseFloat(d.size) - 0.72 * parseFloat(d.root)) < 0.05 && d.right <= 1 && /\d/.test(d.text)), J(dates));
    await shotOf(cdp, "document.querySelector('.proposal-card')", path.join(OUT3, "proposals-date.png"));
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
  console.log("\nScreenshots: " + OUT + ", " + OUT2 + " and " + OUT3);
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})();
