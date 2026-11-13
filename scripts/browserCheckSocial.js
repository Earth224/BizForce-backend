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

   NOT PART OF THE SERVER SUITE (its name does not start with "check"): run it
   by hand, last. With no Chrome it prints SKIPPED and exits 0.
     CHROME_PATH            the browser (default: the usual Windows paths)
     BIZFORCE_FRONTEND_DIR  the frontend checkout
     SOCIAL_CLEAN_OUT       the screenshot folder (default Downloads\social-clean)
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn, execFileSync } = require("child_process");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const OUT = process.env.SOCIAL_CLEAN_OUT || path.join(os.homedir(), "Downloads", "social-clean");
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
let ON = {};
function answer(method, p) {
  const st = c => (c ? "connected" : "not_connected");
  const since = "2026-11-07T10:00:00Z";
  if (p === "/api/youtube/status") return { youtube_available: true, connected: !!ON.youtube, status: st(ON.youtube), channel_title: "Maple Street", since };
  if (p === "/api/tiktok/status") return { tiktok_available: true, connected: !!ON.tiktok, status: st(ON.tiktok), display_name: "Maple Street", since };
  if (p === "/api/instagram/status") return { instagram_available: true, connected: !!ON.instagram, status: st(ON.instagram), username: "maplestreet", since };
  if (p === "/api/facebook/status") return { facebook_available: true, connected: !!ON.facebook, status: st(ON.facebook), page_name: "Maple Street", since };
  if (p === "/api/videos" && method === "GET") return { videos: [V_NEW, V_SENT], max_bytes: 52428800, ready_max: 2 };
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
    if (await evaluate(cdp, "document.readyState === 'complete' && !!document.getElementById('agTab-accounts') && document.querySelectorAll('#ytVideoList li[data-video-id]').length === 2")) break;
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
    check("each row has the YouTube chip only, drawn as a pill in a theme colour; no TikTok chip",
      c1.chips.length === 2 && c1.chips.every(x => /^YouTube: (not sent|uploaded)\|rgb\(/.test(x) && /\|999px$/.test(x)) && c1.prepares.join() === "Prepare for YouTube", J(c1));
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
    check("all four connected: four chips on the new video", J(c2) === J(["YouTube: not sent", "TikTok: not sent", "Instagram: can post as a Reel", "Facebook: can post as a video"]), J(c2));
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
