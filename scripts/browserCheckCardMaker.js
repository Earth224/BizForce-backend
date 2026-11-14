"use strict";
/* ════════════════════════════════════════════════════════════════════════
   browserCheckCardMaker — the Digital Card maker and the public card IN A
   REAL BROWSER (Nov 11 2026, card QR optional, editor tabs). It runs the
   installed Chrome, headless, over the Chrome DevTools Protocol (Node's own
   WebSocket and child_process; no package), in the style of
   scripts/browserCheckDashboard.js.

   The frontend is served from disk by a small static server on 127.0.0.1
   (card-view.html also at /c/jane-doe, as the server serves it). Every
   request to the API host is answered from a stub: one saved card, "Jane
   Doe", with the QR off unless a step turns it on. The page's three pinned
   libraries (qrcode 1.4.4, html2canvas 1.4.1, jsPDF 2.5.1) are let through
   to their CDN, where the browser checks them against the page's SRI hashes,
   so the real QR and the real snapshots are drawn; every other outside
   request is refused.

   The maker, at 1440 px:
     - no QR by default, horizontal and upright: the QR block and its "Scan to
       connect" label are not displayed, nothing of a QR is drawn, and the
       text column takes the card's width (no empty box);
     - the PNG, the print file and the shared image (html2canvas, captured
       before the file is made) hold no QR when it is off, and hold it when on;
     - the switch on: the QR is drawn, and each corner puts it in that corner
       of the card, horizontal and upright;
     - each tab shows only its panel; the left Card Details panel, the theme
       swatches and the action row stay shown;
     - the generator draws the typed link, refuses javascript:, and
       "Download QR (PNG)" and "(SVG)" make a 1024 px PNG and an SVG with no
       request (every request the page makes is counted);
     - no sideways overflow at 1440 and 390 px; at 390 the tab row scrolls
       inside itself.
   The public card (/c/jane-doe, 390 px): no QR with show_qr missing; the QR in
   its corner with show_qr true.

   Screenshots to CARD_MAKER_OUT (default Downloads\card-maker):
   no-qr-horizontal.png, no-qr-vertical.png, qr-on-bottom-right.png,
   tab-text.png, tab-frame.png, tab-background.png, tab-motion.png,
   tab-qr.png, maker-390.png, public-no-qr.png and public-qr.png (both at 768 px, see
   below), and public-390.png.

   NAMED (Nov 11 2026, card exports and phone layout): the exports, against the
   preview. The PNG, print file and shared image used to be covered by a solid
   slab (html2canvas 1.4.1 cannot draw the border's CSS mask); they now render
   with cardExportOptions(), whose onclone draws the ring on a canvas. With
   every animation frozen, for each border style (Glow, None, Neon Pulse, Gold,
   Holo Rainbow), horizontal and upright, QR off and on (bottom-right), a
   screenshot of the preview is compared with the real Download PNG: the mean
   absolute pixel difference under MAD, the name's contrast at least NAME in
   both, and the export's leading colour family the preview's, within SLAB
   points (no slab). A control renders without the onclone and must fail.
   Share as Image once (its 1200 x 630 frame), Export Print File once (the
   PDF's page decoded to an image, a 3.5 x 2 in page for a horizontal card).
   The two notes this harness used to print are now checks: the public card
   at 390, 768 and 1440 px is a centred column (centre within 2 px, the
   footer below, no sideways scroll), and the maker at 390 px has nothing past
   the edge, its upload rows wrapped. More screenshots: export-glow-h.png,
   export-gold-v.png, export-holo-h-qr.png, share-image.png, print-page.png,
   public-390-centred.png, maker-390-fixed.png.
   NAMED (Nov 11 2026, polish): gradient names in the exports. The onclone
   swaps each background-clip:text element for a canvas drawing the same text
   with the same gradient. For the dark, midnight, forest and ember themes and
   the Gradient text effect, both orientations, over the name region: MAD
   under 14, the export's hue spread within 15% of the preview's, and the mean
   per-pixel hue difference under 3 degrees. A control drawing the old
   first-colour fill must fail. Screenshots export-name-gradient-h.png and
   export-name-gradient-v.png to Downloads\polish.

   NAMED (Nov 13 2026, horizontal default): a card is horizontal unless its owner
   saved it vertical. At 1440 px: a member's first card (no card saved) opens with
   the Horizontal toggle alone selected, a 1.75 : 1 preview and horizontal in what
   a save would send, and its Download PNG and print page (252 x 144 pt) are
   horizontal; a saved card with no orientation, saved horizontal, or with an
   unknown value opens the same; a card saved vertical reopens vertical (toggle,
   9 : 16 preview, save) with a vertical PNG and a 144 x 252 pt page. The
   public card at 390, 768 and 1440 px: horizontal (1.75 : 1, the buttons under
   the card) with no orientation or saved horizontal, and the upright full-height
   card when saved vertical. Every frame is recorded before it is painted
   (requestAnimationFrame), and a horizontal card, in the maker or on the public
   page, must never have had an upright one. Screenshots: default-horizontal.png,
   saved-vertical.png and public-horizontal.png (390 px, no orientation saved).

   NOT PART OF THE SERVER SUITE (its name does not start with "check"): run it
   by hand, last. With no Chrome it prints SKIPPED and exits 0.
     CHROME_PATH            the browser (default: the usual Windows paths)
     BIZFORCE_FRONTEND_DIR  the frontend checkout
     CARD_MAKER_OUT         the screenshot folder
   ════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn, execFileSync } = require("child_process");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const OUT = process.env.CARD_MAKER_OUT || path.join(os.homedir(), "Downloads", "card-maker");
const API_HOST = "dynamic-prosperity-production-5382.up.railway.app";
// The page's own pinned library addresses, read from the page: only these go out, and the browser checks their SRI.
const MAKER_HTML = fs.readFileSync(path.join(FRONTEND, "digital-cards.html"), "utf8");
const LIBS = [...MAKER_HTML.matchAll(/<script src="(https:\/\/[^"]+)" integrity="sha384-[^"]+" crossorigin="anonymous"><\/script>/g)].map(m => m[1]);

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

/* ── the stub: one saved card ── */
let cardLayout = {};   // the saved card's media_layout, set per step
let noCards = false;   // NAMED (Nov 13 2026, horizontal default): true answers GET /api/digital-cards with no card (a member's first card)
let q5Extras = false;  // NAMED (Nov 13 2026, Q5b): every button on the public card (Wallet, lead form, Support)
const Q5_OUT = process.env.CARD_Q5_OUT || path.join(os.homedir(), "Downloads", "q5");
function cardRow() {
  return { id: "aaaaaaaa-0000-4000-8000-000000000001", slug: "jane-doe", share_token: null, full_name: "Jane Doe", job_title: "Founder", company: "Northwind Tea",
    email: "jane@example.test", phone: "+1 555 0100", website: "https://example.test", theme: "dark", media_layout: cardLayout,
    show_email: true, show_phone: true, show_photo: false, discoverable: false, lead_form_on: false };
}
function apiAnswer(pathname) {
  if (pathname === "/api/digital-cards") return { cards: noCards ? [] : [cardRow()] };
  // NAMED (Nov 13 2026, Q5b): q5Extras turns on the Wallet button, the lead form and a support link, so every button shows.
  if (/^\/api\/cards\/slug\//.test(pathname)) return q5Extras
    ? { card: Object.assign(cardRow(), { google_wallet: true, lead_form: true, form_token: "check-form-token", form_issued_at: "2026-11-13T00:00:00Z" }),
        support_links: [{ kind: "paypal", url: "https://paypal.me/janedoe", label: "PayPal" }] }
    : { card: cardRow(), support_links: [] };
  if (/\/stats$/.test(pathname)) return { days: [], totals: { last_7_days: { views: 0, qr_views: 0 }, last_30_days: { views: 0, qr_views: 0 } } };
  if (/^\/api\/card-leads\//.test(pathname)) return { leads: [] };
  if (pathname === "/api/auth/me") return { user: { id: "aaaaaaaa-0000-4000-8000-000000000009", email: "owner@example.test", role: "member" }, access: { active: true } };
  return {};
}

/* ── a small static server over the frontend ── */
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json",
  ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".webp": "image/webp", ".jpg": "image/jpeg", ".woff2": "font/woff2", ".mp3": "audio/mpeg" };
function serve() {
  const root = path.resolve(FRONTEND);
  const server = http.createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    if (/^\/c\/[a-z0-9-]+\/?$/.test(p)) p = "/card-view.html";
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
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bf-card-maker-"));
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
async function viewport(cdp, w, h, mobile) { await cdp.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile: !!mobile }); await sleep(250); }
async function open(cdp, origin, page, ready) {
  await cdp.send("Page.navigate", { url: "about:blank" });
  await sleep(150);
  await cdp.send("Storage.clearDataForOrigin", { origin, storageTypes: "session_storage" }).catch(() => {});
  await cdp.send("Page.navigate", { url: origin + "/" + page });
  for (let i = 0; i < 150; i++) { if (await evaluate(cdp, "document.readyState === 'complete' && (" + ready + ")").catch(() => false)) break; await sleep(100); }
  await sleep(500);
  await evaluate(cdp, HELPERS);
}
// A screenshot of the viewport after scrolling a node to the top, or of a node's own box (clip).
async function shot(cdp, file, selector, clip) {
  await evaluate(cdp, "(function(){var n=document.querySelector(" + JSON.stringify(selector) + "); if(n) n.scrollIntoView({block:'start'}); window.scrollBy(0,-16); return true;})()");
  await sleep(250);
  const params = { format: "png" };
  if (clip) {
    const r = await evaluate(cdp, "(function(){var b=document.querySelector(" + JSON.stringify(selector) + ").getBoundingClientRect();return {x:b.left+scrollX,y:b.top+scrollY,w:b.width,h:b.height};})()");
    params.clip = { x: Math.max(0, r.x - 16), y: Math.max(0, r.y - 16), width: r.w + 32, height: r.h + 32, scale: 1 };
    params.captureBeyondViewport = true;
  }
  const res = await cdp.send("Page.captureScreenshot", params);
  fs.writeFileSync(path.join(OUT, file), Buffer.from(res.data, "base64"));
}

/* Page-side helpers, installed once per page. */
const HELPERS = `
window.__bf = {
  shown: function (n) { if (!n) return false; for (var e = n; e && e.nodeType === 1; e = e.parentElement) { if (getComputedStyle(e).display === "none" || e.hidden) return false; } var r = n.getBoundingClientRect(); return r.width > 0 && r.height > 0; },
  rect: function (n) { var r = n.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height, cx: r.left + r.width / 2, cy: r.top + r.height / 2 }; },
  // where a node sits on a card: which half, left or right and top or bottom
  corner: function (node, card) { var a = __bf.rect(node), c = __bf.rect(card); return (a.cy < c.cy ? "top" : "bottom") + "-" + (a.cx < c.cx ? "left" : "right"); },
  // dark and light pixels in a canvas: a drawn QR has both
  drawn: function (cv) { try { var d = cv.getContext("2d").getImageData(0, 0, cv.width, cv.height).data, hi = 0, lo = 0; for (var i = 0; i < d.length; i += 4) { if (d[i + 3] < 128) continue; var v = d[i] + d[i + 1] + d[i + 2]; if (v > 600) hi++; else if (v < 150) lo++; } return hi > 50 && lo > 50; } catch (e) { return false; } },
  // the share of bright pixels (a QR's light modules on the dark themes) in a box of a snapshot canvas
  bright: function (cv, box, scale) { var x = Math.round(box.x * scale), y = Math.round(box.y * scale), w = Math.max(1, Math.round(box.w * scale)), h = Math.max(1, Math.round(box.h * scale));
    var d = cv.getContext("2d").getImageData(x, y, w, h).data, n = 0, b = 0; for (var i = 0; i < d.length; i += 4) { n++; if (d[i] > 200 && d[i + 1] > 200 && d[i + 2] > 200) b++; } return n ? b / n : 0; },
  overflow: function () { return document.documentElement.scrollWidth - window.innerWidth; }
};
true`;
// In the maker: capture every html2canvas snapshot and every file the page saves, instead of saving it.
const CAPTURE = `(function(){
  window.__snaps = []; window.__saves = [];
  var h2c = window.html2canvas;
  // NAMED (Nov 11 2026, card exports and phone layout): the border layer is no longer left out. The page's exports now swap
  // its CSS mask (which html2canvas 1.4.1 cannot draw) for a mask-free ring themselves, so every snapshot is taken whole,
  // with the page's own options, exactly as the file is made.
  window.html2canvas = function (el, o) { return h2c(el, o).then(function (cv) { window.__snaps.push(cv); return cv; }); };
  HTMLAnchorElement.prototype.click = function () { if (this.download) window.__saves.push({ name: this.download, href: this.href }); };
  // The print file's PDF, as jsPDF would save it.
  window.__pdfs = [];
  try { var J = window.jspdf && window.jspdf.jsPDF; if (J) { var keep = function (n) { window.__pdfs.push({ name: n, uri: this.output("datauristring") }); return this; }; J.API.save = keep; if (J.prototype) J.prototype.save = keep; } } catch (e) {}
  try { Object.defineProperty(navigator, "share", { value: undefined, configurable: true }); Object.defineProperty(navigator, "canShare", { value: undefined, configurable: true }); } catch (e) {}
  return typeof h2c === "function";
})()`;
// Where the QR box sits, relative to the card, in snapshot pixels (before the snapshot moves anything).
const QR_BOX = `(function(){ var c = document.getElementById("cardPreview").getBoundingClientRect(), q = document.querySelector("#cardQrBlock .card-qr-wrap").getBoundingClientRect();
  return { x: q.left - c.left, y: q.top - c.top, w: q.width, h: q.height }; })()`;

/* NAMED (Nov 11 2026, card exports and phone layout): an export against the preview, in the page. Both images are drawn at
   the card's own size; inside the card's rounded edge (html2canvas fills the corners white, the screen shows the page):
   mad, the mean absolute difference per colour channel (0 to 255); the name's contrast in each (the spread of brightness,
   5th to 95th percentile, over .card-name's box); and how much of each one colour holds (the largest share of pixels in
  the same colour family: dark, grey or one of twelve 30-degree hues). src, when given, is the card's place in the export (the shared image letterboxes it). */
const FREEZE = `(function(){ var s = document.getElementById("__freeze") || document.createElement("style"); s.id = "__freeze";
  s.textContent = "*,*::before,*::after{animation:none !important;transition:none !important}"; document.head.appendChild(s); return true; })()`;
const COMPARE = `window.__cmp = function (prevUrl, expUrl, src) {
  var load = function (u) { return new Promise(function (ok, no) { var i = new Image(); i.onload = function () { ok(i); }; i.onerror = no; i.src = u; }); };
  var card = document.getElementById("cardPreview"), w = card.offsetWidth, h = card.offsetHeight, cr = card.getBoundingClientRect();
  var nb = document.querySelector("#cardPreview .card-name").getBoundingClientRect(), box = { x: Math.round(nb.left - cr.left), y: Math.round(nb.top - cr.top), w: Math.round(nb.width), h: Math.round(nb.height) };
  var rad = parseFloat(getComputedStyle(card).borderTopLeftRadius) || 0;
  var inside = function (x, y) { var cx = Math.min(Math.max(x, rad), w - rad), cy = Math.min(Math.max(y, rad), h - rad); return (x - cx) * (x - cx) + (y - cy) * (y - cy) <= (rad - 1.5) * (rad - 1.5) || (x >= rad && x <= w - rad) || (y >= rad && y <= h - rad); };
  // a pixel's colour family: dark, grey, or one of twelve 30-degree hues
  var family = function (r, g, b) { var mx = Math.max(r, g, b), mn = Math.min(r, g, b); if (mx < 60) return "dark"; if ((mx - mn) / mx < 0.25) return "grey";
    var d = mx - mn, h = mx === r ? ((g - b) / d) % 6 : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; return "hue" + Math.floor(((h * 60 + 360) % 360) / 30) * 30; };
  return Promise.all([load(prevUrl), load(expUrl)]).then(function (ims) {
    var px = ims.map(function (im, k) { var cv = document.createElement("canvas"); cv.width = w; cv.height = h; var x = cv.getContext("2d"); x.imageSmoothingEnabled = true; x.imageSmoothingQuality = "high";
      if (k === 1 && src) x.drawImage(im, src.x, src.y, src.w, src.h, 0, 0, w, h); else x.drawImage(im, 0, 0, w, h); return x.getImageData(0, 0, w, h).data; });
    var diff = 0, n = 0, bins = [{}, {}], top = [0, 0];
    for (var y = 0; y < h; y++) for (var x = 0; x < w; x++) { if (!inside(x + 0.5, y + 0.5)) continue; var i = (y * w + x) * 4; n++;
      diff += Math.abs(px[0][i] - px[1][i]) + Math.abs(px[0][i + 1] - px[1][i + 1]) + Math.abs(px[0][i + 2] - px[1][i + 2]);
      for (var k = 0; k < 2; k++) { var b = family(px[k][i], px[k][i + 1], px[k][i + 2]); bins[k][b] = (bins[k][b] || 0) + 1; } }
    var topOf = function (bn) { var best = null; Object.keys(bn).forEach(function (f) { if (!best || bn[f] > bn[best]) best = f; }); return best; };
    var fam = [topOf(bins[0]), topOf(bins[1])]; top = [bins[0][fam[0]], bins[1][fam[1]]];
    var contrast = function (d) { var v = []; for (var y = box.y; y < box.y + box.h; y++) for (var x = box.x; x < box.x + box.w; x++) { var i = (y * w + x) * 4; v.push(0.2126 * d[i] + 0.7152 * d[i + 1] + 0.0722 * d[i + 2]); }
      v.sort(function (a, b) { return a - b; }); return v.length ? Math.round(v[Math.floor(v.length * 0.95)] - v[Math.floor(v.length * 0.05)]) : 0; };
    return { mad: Math.round(diff / Math.max(1, n * 3) * 100) / 100, namePrev: contrast(px[0]), nameExp: contrast(px[1]), topPrev: Math.round(top[0] / n * 1000) / 10, topExp: Math.round(top[1] / n * 1000) / 10, famPrev: fam[0], famExp: fam[1], w: w, h: h };
  });
};
/* NAMED (Nov 11 2026, polish): the gradient text, region by region. Over the box of the elements sel names (the name, or
   the Gradient Text effect's lines), padded 2 px: the mean absolute difference, and the hue spread (the 5th to 95th
   percentile of the hue of the text's coloured pixels, saturation over .35 and brightness over 90) in each image. */
window.__cmpText = function (prevUrl, expUrl, sel) {
  var load = function (u) { return new Promise(function (ok, no) { var i = new Image(); i.onload = function () { ok(i); }; i.onerror = no; i.src = u; }); };
  var card = document.getElementById("cardPreview"), w = card.offsetWidth, h = card.offsetHeight, cr = card.getBoundingClientRect();
  var u = null; document.querySelectorAll(sel).forEach(function (n) { var b = n.getBoundingClientRect(); if (!b.width) return;
    u = u ? { l: Math.min(u.l, b.left), t: Math.min(u.t, b.top), r: Math.max(u.r, b.right), b: Math.max(u.b, b.bottom) } : { l: b.left, t: b.top, r: b.right, b: b.bottom }; });
  if (!u) return Promise.resolve(null);
  var S = 3, x0 = Math.max(0, Math.floor((u.l - cr.left - 2) * S)), y0 = Math.max(0, Math.floor((u.t - cr.top - 2) * S)), x1 = Math.min(w * S, Math.ceil((u.r - cr.left + 2) * S)), y1 = Math.min(h * S, Math.ceil((u.b - cr.top + 2) * S));
  return Promise.all([load(prevUrl), load(expUrl)]).then(function (ims) {
    var px = ims.map(function (im) { var cv = document.createElement("canvas"); cv.width = w * S; cv.height = h * S; var x = cv.getContext("2d"); x.imageSmoothingEnabled = true; x.imageSmoothingQuality = "high";
      x.drawImage(im, 0, 0, w * S, h * S); return x.getImageData(x0, y0, x1 - x0, y1 - y0).data; });
    var diff = 0, n = px[0].length / 4, hues = [[], []], hd = 0, hn = 0;
    for (var i = 0; i < px[0].length; i += 4) {
      diff += Math.abs(px[0][i] - px[1][i]) + Math.abs(px[0][i + 1] - px[1][i + 1]) + Math.abs(px[0][i + 2] - px[1][i + 2]);
      for (var k = 0; k < 2; k++) { var r = px[k][i], g = px[k][i + 1], b = px[k][i + 2], mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
        if (mx < 90 || d / mx < 0.35) continue;
        var hh = mx === r ? ((g - b) / d) % 6 : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; hues[k].push((hh * 60 + 360) % 360); if (k === 1 && hues[0].length && hues[0].__at === i) { var dh = Math.abs(hues[0][hues[0].length - 1] - hues[1][hues[1].length - 1]); hd += Math.min(dh, 360 - dh); hn++; } if (k === 0) hues[0].__at = i; }
    }
    var spread = function (v) { if (v.length < 20) return 0; v.sort(function (a, b) { return a - b; }); return Math.round(v[Math.floor(v.length * 0.95)] - v[Math.floor(v.length * 0.05)]); };
    return { mad: Math.round(diff / Math.max(1, n * 3) * 100) / 100, spreadPrev: spread(hues[0]), spreadExp: spread(hues[1]), hueDiff: hn ? Math.round(hd / hn * 10) / 10 : 999, coloured: [hues[0].length, hues[1].length], box: [x0, y0, x1 - x0, y1 - y0] };
  });
}; true`;
// The print file's PDF: its page box and its one page-filling image, decoded (FlateDecode, PNG predictors) and written as a PNG.
const zlib = require("zlib");
function pdfPage(uri) {
  const pdf = Buffer.from(uri.slice(uri.indexOf(",") + 1), "base64"), text = pdf.toString("latin1");
  const media = (/\/MediaBox \[([^\]]+)\]/.exec(text) || ["", ""])[1].trim().split(/\s+/).map(Number);
  let img = null;
  for (let at = text.indexOf("/Subtype /Image"); at !== -1 && !img; at = text.indexOf("/Subtype /Image", at + 1)) {
    const objStart = text.lastIndexOf(" obj", at), sPos = text.indexOf("stream", at), d = text.slice(objStart, sPos);
    if (!/\/ColorSpace \/DeviceRGB/.test(d)) continue;
    let start = sPos + 6; if (text[start] === "\r") start++; if (text[start] === "\n") start++;
    const len = (/\/Length (\d+)/.exec(d) || [])[1], end = len ? start + Number(len) : text.indexOf("endstream", start);
    img = { w: +/\/Width (\d+)/.exec(d)[1], h: +/\/Height (\d+)/.exec(d)[1], pred: +((/\/Predictor (\d+)/.exec(d) || [0, 0])[1]),
      data: /\/FlateDecode/.test(d) ? zlib.inflateSync(pdf.subarray(start, end)) : Buffer.from(pdf.subarray(start, end)) };   // jsPDF may store the pixels raw
  }
  if (!img) { const at = text.indexOf("/Subtype /Image"); return { media, png: null, dict: at === -1 ? "no image" : text.slice(Math.max(0, at - 200), at + 300).replace(/[^\x20-\x7e]/g, ".") }; }
  const bpp = 3, stride = img.w * bpp, raw = Buffer.alloc(stride * img.h);
  if (img.pred >= 10) {
    let prev = Buffer.alloc(stride);
    for (let y = 0; y < img.h; y++) {
      const f = img.data[y * (stride + 1)], row = img.data.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1)), out = raw.subarray(y * stride, (y + 1) * stride);
      for (let x = 0; x < stride; x++) {
        const a = x >= bpp ? out[x - bpp] : 0, b = prev[x], c = x >= bpp ? prev[x - bpp] : 0;
        const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c), paeth = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
        out[x] = (row[x] + (f === 0 ? 0 : f === 1 ? a : f === 2 ? b : f === 3 ? (a + b) >> 1 : paeth)) & 255;
      }
      prev = out;
    }
  } else img.data.copy(raw);
  const lines = Buffer.alloc((stride + 1) * img.h);
  for (let y = 0; y < img.h; y++) { lines[y * (stride + 1)] = 0; raw.copy(lines, y * (stride + 1) + 1, y * stride, (y + 1) * stride); }
  const chunk = (type, body) => { const len = Buffer.alloc(4); len.writeUInt32BE(body.length); const tb = Buffer.concat([Buffer.from(type), body]); const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(tb) >>> 0); return Buffer.concat([len, tb, crc]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(img.w, 0); ihdr.writeUInt32BE(img.h, 4); ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const png = Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(lines)), chunk("IEND", Buffer.alloc(0))]);
  return { media, w: img.w, h: img.h, png };
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
  const requests = [], refused = [];
  try {
    cdp = await connect(chrome.ws);
    cdp.on(async msg => {
      if (msg.method !== "Fetch.requestPaused") return;
      const { requestId, request } = msg.params;
      const u = new URL(request.url);
      requests.push(request.method + " " + request.url);
      try {
        if (u.origin === origin || u.protocol === "data:" || u.protocol === "blob:") await cdp.send("Fetch.continueRequest", { requestId });
        else if (LIBS.indexOf(request.url) !== -1) await cdp.send("Fetch.continueRequest", { requestId });
        else if (u.hostname === API_HOST) {
          const body = request.method === "OPTIONS" ? "" : JSON.stringify(apiAnswer(u.pathname));
          await cdp.send("Fetch.fulfillRequest", { requestId, responseCode: 200, body: Buffer.from(body).toString("base64"),
            responseHeaders: [{ name: "Content-Type", value: "application/json" }, { name: "Access-Control-Allow-Origin", value: "*" },
              { name: "Access-Control-Allow-Headers", value: "*" }, { name: "Access-Control-Allow-Methods", value: "GET,POST,PUT,DELETE,OPTIONS" }] });
        } else { refused.push(request.url); await cdp.send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" }); }
      } catch (e) { /* the page moved on */ }
    });
    const exceptions = [];
    cdp.on(msg => { if (msg.method === "Runtime.exceptionThrown") exceptions.push((msg.params.exceptionDetails.exception || {}).description || msg.params.exceptionDetails.text); });
    await cdp.send("Fetch.enable", { patterns: [{ urlPattern: "*" }] });
    await cdp.send("Runtime.enable");
    await cdp.send("Page.enable");
    await cdp.send("Browser.setDownloadBehavior", { behavior: "deny" }).catch(() => {});
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{localStorage.setItem('bf_token','browser-check-token');localStorage.setItem('bf_user',JSON.stringify({id:'aaaaaaaa-0000-4000-8000-000000000009',role:'member'}));}catch(e){}" });
    // NAMED (Nov 13 2026, horizontal default): every frame, before it is painted, records the card's orientation whenever it
    // changes: the maker's preview (orient-vertical) and the public card's page (#cardViewport.cv-vertical), and whether the
    // card is displayed yet. A horizontal card must never have a vertical frame.
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "window.__orientLog=[];(function t(){try{var p=document.getElementById('cardPreview'),v=document.getElementById('cardViewport');" +
      "if(p){var s=(p.classList.contains('orient-vertical')?'V':'H')+(v&&v.classList.contains('cv-vertical')?'v':'h')+(getComputedStyle(p).display==='none'?'-':'+'),l=window.__orientLog;" +
      "if(!l.length||l[l.length-1]!==s)l.push(s);}}catch(e){}if(performance.now()<15000)requestAnimationFrame(t);})();" });
    check("the page's three pinned libraries are read from it (qrcode, html2canvas, jsPDF)", LIBS.length === 3 && /qrcode@1\.4\.4/.test(LIBS[0]) && /html2canvas@1\.4\.1/.test(LIBS[1]) && /jspdf\/2\.5\.1/.test(LIBS[2]), LIBS.join(" "));

    /* ── the maker, QR off by default ── */
    console.log("\n══ the maker, 1440 px: no QR by default ══");
    await viewport(cdp, 1440, 1000);
    cardLayout = {};
    await open(cdp, origin, "digital-cards.html", "/Card loaded/.test((document.getElementById('saveStatus')||{}).textContent||'') && !!window.QRCode && !!window.html2canvas");
    check("the maker loaded the saved card and the real libraries (QRCode.toCanvas, toDataURL and toString; html2canvas; jsPDF)",
      await evaluate(cdp, "typeof QRCode.toCanvas === 'function' && typeof QRCode.toDataURL === 'function' && typeof QRCode.toString === 'function' && typeof html2canvas === 'function' && !!window.jspdf"));
    check("the saved card has no show_qr: the switch is off, and the generator is not opened", await evaluate(cdp, "document.getElementById('qrShowToggle').checked === false && document.getElementById('cardPreview').classList.contains('qr-off')"));
    for (const orient of ["horizontal", "vertical"]) {
      await evaluate(cdp, "applyCardOrientation(" + JSON.stringify(orient) + "), true");
      await sleep(300);
      const st = await evaluate(cdp, `(function(){ var p = document.getElementById("cardPreview"), inner = p.querySelector(".card-inner"), left = p.querySelector(".card-left");
        var cs = getComputedStyle(inner), room = inner.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
        var labels = [].filter.call(p.querySelectorAll("*"), function (n) { return n.children.length === 0 && /scan to connect/i.test(n.textContent) && __bf.shown(n); }).length;
        return { block: __bf.shown(document.getElementById("cardQrBlock")), labels: labels, video: __bf.shown(document.getElementById("cardVideoQR")), drawn: __bf.drawn(document.getElementById("qrCanvas")),
          leftW: Math.round(left.getBoundingClientRect().width), room: Math.round(room), vertical: p.classList.contains("orient-vertical") }; })()`);
      check(orient + ": no QR by default: no QR block, no \"Scan to connect\", no video QR, nothing drawn, and the text takes the card's full width (no empty box)",
        !st.block && st.labels === 0 && !st.video && !st.drawn && Math.abs(st.leftW - st.room) <= 1 && st.vertical === (orient === "vertical"), JSON.stringify(st));
      await shot(cdp, "no-qr-" + orient + ".png", "#cardPreview", true);
    }
    await evaluate(cdp, "applyCardOrientation('horizontal'), true");
    await sleep(200);

    /* ── the exports, off ── */
    console.log("\n══ the PNG, print file and shared image: none when off ══");
    check("html2canvas is captured before a file is made", await evaluate(cdp, CAPTURE));
    await evaluate(cdp, "downloadCard().then(function(){return exportPrintFile();}).then(function(){return shareCardImage();}).then(function(){return true;})");
    await sleep(500);
    // the box where the QR would be when on: switch it on to measure, then off again
    await evaluate(cdp, "setShowQr(true), true"); await sleep(200);
    const box = await evaluate(cdp, QR_BOX);
    await evaluate(cdp, "setShowQr(false), true"); await sleep(200);
    const offShares = await evaluate(cdp, "window.__snaps.map(function (cv) { return Math.round(__bf.bright(cv, " + JSON.stringify(box) + ", 3) * 1000) / 1000; })");
    const offSaves = await evaluate(cdp, "window.__saves.map(function (s) { return s.name; })");
    check("off: the PNG, the print file and the shared image are each taken of the card with the QR's corner empty (under 2% bright pixels there)",
      offShares.length === 3 && offShares.every(v => v < 0.02), JSON.stringify({ offShares, offSaves }));

    /* ── on, each corner ── */
    console.log("\n══ the switch on: drawn, in each corner ══");
    await evaluate(cdp, "document.getElementById('edTab-qr').click(), document.getElementById('qrShowToggle').click(), true");
    await sleep(500);
    const on = await evaluate(cdp, "({ checked: document.getElementById('qrShowToggle').checked, block: __bf.shown(document.getElementById('cardQrBlock')), drawn: __bf.drawn(document.getElementById('qrCanvas')), label: __bf.shown(document.querySelector('#cardQrBlock .card-qr-label')) })");
    check("on: the QR is drawn with its \"Scan to connect\" label", on.checked && on.block && on.drawn && on.label, JSON.stringify(on));
    const corners = {};
    for (const orient of ["horizontal", "vertical"]) {
      await evaluate(cdp, "applyCardOrientation(" + JSON.stringify(orient) + "), true");
      for (const c of ["top-left", "top-right", "bottom-left", "bottom-right"]) {
        await evaluate(cdp, "document.querySelector(\"[data-qr-corner='" + c + "']\").click(), true");
        await sleep(200);
        corners[orient + " " + c] = await evaluate(cdp, "__bf.corner(document.querySelector('#cardQrBlock .card-qr-wrap'), document.getElementById('cardPreview'))");
      }
    }
    check("each corner button puts the QR in that corner of the card, horizontal and upright", Object.keys(corners).every(k => k.split(" ")[1] === corners[k]), JSON.stringify(corners));
    await evaluate(cdp, "applyCardOrientation('horizontal'), true");
    await evaluate(cdp, "document.querySelector(\"[data-qr-corner='bottom-right']\").click(), true");
    await sleep(300);
    await shot(cdp, "qr-on-bottom-right.png", "#cardPreview", true);
    await evaluate(cdp, "window.__snaps.length = 0, true");
    await evaluate(cdp, "downloadCard().then(function(){return exportPrintFile();}).then(function(){return shareCardImage();}).then(function(){return true;})");
    await sleep(500);
    const box2 = await evaluate(cdp, QR_BOX);
    const onShares = await evaluate(cdp, "window.__snaps.map(function (cv) { return Math.round(__bf.bright(cv, " + JSON.stringify(box2) + ", 3) * 1000) / 1000; })");
    check("on: the PNG, the print file and the shared image each hold the QR in its corner (over 15% bright pixels there)", onShares.length === 3 && onShares.every(v => v > 0.15), JSON.stringify(onShares));
    await evaluate(cdp, "document.getElementById('qrShowToggle').click(), true");
    await sleep(200);
    check("the switch off again: the QR goes", await evaluate(cdp, "!__bf.shown(document.getElementById('cardQrBlock')) && document.getElementById('cardPreview').classList.contains('qr-off')"));

    /* ── the tabs ── */
    console.log("\n══ the tabs: each shows only its panel; the rest stays ══");
    const TABS = ["text", "frame", "background", "motion", "qr"];
    for (const t of TABS) {
      await evaluate(cdp, "document.getElementById('edTab-" + t + "').click(), true");
      await sleep(250);
      const st = await evaluate(cdp, "({ shown: " + JSON.stringify(TABS) + ".filter(function (n) { return __bf.shown(document.getElementById('edPanel-' + n)); }), hash: location.hash," +
        " stay: ['fName', 'cardPreview', 'saveBtn', 'printExportBtn', 'shareImageBtn', 'bleedCheck', 'cardStats', 'cardLeads'].filter(function (id) { return !__bf.shown(document.getElementById(id)); })" +
        ".concat(__bf.shown(document.querySelector('.theme-selector')) ? [] : ['themes']).concat(__bf.shown(document.querySelector('.action-row')) ? [] : ['actions']) })");
      check(t + ": only its panel is displayed, the address is #ed-" + t + ", and the left panel, preview, swatches and action row stay shown",
        st.shown.join() === t && st.hash === "#ed-" + t && st.stay.length === 0, JSON.stringify(st));
      await shot(cdp, "tab-" + t + ".png", "#cardEdTabs");
    }

    /* ── the generator ── */
    console.log("\n══ the QR Code tab's generator ══");
    await evaluate(cdp, "document.getElementById('edTab-qr').click(), true");
    const typed = async v => { await evaluate(cdp, "(function(){var i=document.getElementById('qrGenUrl'); i.value=" + JSON.stringify(v) + "; i.dispatchEvent(new Event('input',{bubbles:true})); return true;})()"); await sleep(250);
      return evaluate(cdp, "({ drawn: __bf.drawn(document.getElementById('qrGenCanvas')), off: document.getElementById('qrGenPngBtn').disabled, note: document.getElementById('qrGenNote').textContent })"); };
    const bad = await typed("javascript:alert(1)");
    check("javascript: is refused: nothing drawn, the downloads off, the note says to type an http or https link", !bad.drawn && bad.off && /https:\/\//.test(bad.note), JSON.stringify(bad));
    const own = await typed("");
    check("empty: the card's own link is drawn", own.drawn && !own.off && /public link/.test(own.note), JSON.stringify(own));
    const good = await typed("https://example.test/menu");
    check("a typed https link is drawn", good.drawn && !good.off, JSON.stringify(good));
    const before = requests.length;
    await evaluate(cdp, "window.__saves.length = 0, document.getElementById('qrGenPngBtn').click(), document.getElementById('qrGenSvgBtn').click(), true");
    await sleep(800);
    const files = await evaluate(cdp, `Promise.all(window.__saves.map(function (s) {
      if (s.name === "qr-code.png") return new Promise(function (res) { var im = new Image(); im.onload = function () { res({ name: s.name, w: im.naturalWidth, h: im.naturalHeight, data: s.href.indexOf("data:image/png") === 0 }); }; im.onerror = function () { res({ name: s.name, bad: true }); }; im.src = s.href; });
      return fetch(s.href).then(function (r) { return r.text(); }).then(function (t) { return { name: s.name, blob: s.href.indexOf("blob:") === 0, svg: /^<svg[^>]*xmlns="http:\\/\\/www\\.w3\\.org\\/2000\\/svg"/.test(t) && /<path/.test(t), len: t.length }; });
    }))`);
    const made = requests.slice(before).filter(r => !/ (data|blob):/.test(r));
    check("Download QR (PNG) saves qr-code.png, a 1024 px PNG made in the page", files.some(f => f.name === "qr-code.png" && f.data && f.w >= 1000 && f.w === f.h), JSON.stringify(files));
    check("Download QR (SVG) saves qr-code.svg, an SVG with its modules, made in the page", files.some(f => f.name === "qr-code.svg" && f.blob && f.svg), JSON.stringify(files));
    check("the downloads made no request", made.length === 0, made.join(" | "));
    await typed("");

    /* ── NAMED (Nov 11 2026, card exports and phone layout): the exports match the preview ── */
    console.log("\n══ the exports match the preview: every border style, both orientations, QR off and on ══");
    await evaluate(cdp, FREEZE);
    await evaluate(cdp, COMPARE);
    await cdp.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: 2, y: 2 });
    // The preview card on the screen, at the exports' 3x, as a PNG data URL.
    const previewShot = async () => {
      await evaluate(cdp, "document.getElementById('cardPreview').scrollIntoView({block:'center'}), true");
      await sleep(250);
      const r = await evaluate(cdp, "(function(){var b=document.getElementById('cardPreview').getBoundingClientRect();return {x:b.left+scrollX,y:b.top+scrollY,w:b.width,h:b.height};})()");
      const res = await cdp.send("Page.captureScreenshot", { format: "png", clip: { x: r.x, y: r.y, width: r.w, height: r.h, scale: 3 }, captureBeyondViewport: true });
      return "data:image/png;base64," + res.data;
    };
    const MAD = 14, NAME = 60, SLAB = 10;   // the thresholds: mean difference under 14 of 255; name contrast over 60 in both; no more than 10 points more one-colour than the preview
    // not the old slab: the export's largest colour family is the preview's own, holding within 10 points of the same share
    const oneColourOk = r => !!r.famPrev && r.famExp === r.famPrev && Math.abs(r.topExp - r.topPrev) <= SLAB;
    const cmpRows = [];
    const named = { "glow|horizontal|off": "export-glow-h.png", "gold|vertical|off": "export-gold-v.png", "holo-rainbow|horizontal|on": "export-holo-h-qr.png" };
    for (const style of ["glow", "none", "neon-pulse", "gold", "holo-rainbow"]) for (const orient of ["horizontal", "vertical"]) for (const qr of ["off", "on"]) {
      await evaluate(cdp, "applyBorderStyle(" + JSON.stringify(style) + "); applyCardOrientation(" + JSON.stringify(orient) + "); setShowQr(" + (qr === "on") + "); " + (qr === "on" ? "setQrCorner('bottom-right'); " : "") + "true");
      await sleep(450);
      const prev = await previewShot();
      await evaluate(cdp, "window.__saves.length = 0, window.__snaps.length = 0, true");
      await evaluate(cdp, "downloadCard().then(function(){return true;})");
      const file = await evaluate(cdp, "(window.__saves.filter(function(s){return s.name==='bizforce-card.png';})[0]||{}).href||''");
      const r = file ? await evaluate(cdp, "window.__cmp(" + JSON.stringify(prev) + ", " + JSON.stringify(file) + ")") : { mad: 999 };
      const key = style + "|" + orient + "|" + qr;
      cmpRows.push(Object.assign({ key }, r));
      if (named[key]) fs.writeFileSync(path.join(OUT, named[key]), Buffer.from(file.slice(file.indexOf(",") + 1), "base64"));
      console.log("    " + key.padEnd(30) + " mad " + String(r.mad).padStart(6) + "  name " + r.namePrev + "/" + r.nameExp + "  one colour " + r.famPrev + " " + r.topPrev + "%/" + r.famExp + " " + r.topExp + "%");
    }
    const badRows = cmpRows.filter(r => !(r.mad < MAD && r.namePrev > NAME && r.nameExp > NAME && oneColourOk(r)));
    check("Download PNG matches the preview for Glow, None, Neon Pulse, Gold and Holo Rainbow, horizontal and vertical, QR off and on (20): mean difference under " + MAD + "/255 (worst " +
      Math.max(...cmpRows.map(r => r.mad)) + "), the name's contrast over " + NAME + " in both, and not one colour like the old slab (its largest colour family the preview's own, within " + SLAB + " points)", cmpRows.length === 20 && badRows.length === 0, JSON.stringify(badRows));
    /* NAMED (Nov 11 2026, polish): the gradient name. Every theme's name, and the Gradient Text effect's lines, exported in
       their gradient: over that text's own region, a mean difference under 14 and a hue spread within 15% of the preview's. */
    console.log("\n══ gradient text in the exports: every theme's name, and the Gradient Text effect ══");
    const SPREAD = 0.15, textRows = [];
    const POLISH = path.join(os.homedir(), "Downloads", "polish");
    fs.mkdirSync(POLISH, { recursive: true });
    await evaluate(cdp, "applyBorderStyle('glow'); setShowQr(false); true");
    for (const orient of ["horizontal", "vertical"]) for (const look of ["dark", "midnight", "forest", "ember", "gradient-effect"]) {
      const fx = look === "gradient-effect";
      await evaluate(cdp, "setTheme(" + JSON.stringify(fx ? "dark" : look) + "); applyTextEffect(" + JSON.stringify(fx ? "gradient" : "none") + "); applyCardOrientation(" + JSON.stringify(orient) + "); true");
      await sleep(450);
      const prev = await previewShot();
      await evaluate(cdp, "window.__saves.length = 0, window.__snaps.length = 0, true");
      await evaluate(cdp, "downloadCard().then(function(){return true;})");
      const file = await evaluate(cdp, "(window.__saves.filter(function(s){return s.name==='bizforce-card.png';})[0]||{}).href||''");
      const sel = fx ? "#cardPreview .card-company, #cardPreview .card-job" : "#cardPreview .card-name";
      const r = file ? await evaluate(cdp, "window.__cmpText(" + JSON.stringify(prev) + ", " + JSON.stringify(file) + ", " + JSON.stringify(sel) + ")") : null;
      const key = look + "|" + orient;
      textRows.push(Object.assign({ key }, r || { mad: 999, spreadPrev: 0, spreadExp: 0 }));
      if (look === "dark") fs.writeFileSync(path.join(POLISH, orient === "horizontal" ? "export-name-gradient-h.png" : "export-name-gradient-v.png"), Buffer.from(file.slice(file.indexOf(",") + 1), "base64"));
      console.log("    " + key.padEnd(28) + " mad " + String(r && r.mad).padStart(6) + "  hue spread " + (r && r.spreadPrev) + "/" + (r && r.spreadExp) + "  hue difference " + (r && r.hueDiff) + "  coloured px " + (r && r.coloured.join("/")));
    }
    // within 15% of the preview's spread, the spreads being whole degrees (so never closer than 1 degree can be asked of a 3 degree spread)
    const HUE = 3;   // and, pixel by pixel where both are coloured, a mean hue difference under 3 degrees (measured: 0.1 to 1.3; the old first-colour fill 4.5 and 10.3)
    const spreadOk = r => r.spreadPrev > 0 && Math.abs(r.spreadExp - r.spreadPrev) <= Math.max(SPREAD * r.spreadPrev, 1) && r.hueDiff < HUE;
    const badText = textRows.filter(r => !(r.mad < MAD && spreadOk(r)));
    check("gradient text: each theme's name (dark, midnight, forest, ember) and the Gradient Text effect, horizontal and vertical (10), exported in its gradient: over its region, mean difference under " + MAD +
      " (worst " + Math.max(...textRows.map(r => r.mad)) + ") and a hue spread within 15% of the preview's, and a mean hue difference under " + HUE + " degrees (polish\\export-name-gradient-h.png, -v.png)", textRows.length === 10 && badText.length === 0, JSON.stringify(badText));
    // The control: the copy as it was (gradient text filled with its first colour) must fail the same test.
    const OLD_FILL = "(function(){var el=document.getElementById('cardPreview');return html2canvas(el,{scale:3,useCORS:true,allowTaint:false,onclone:function(doc){" +
      "var L=document.querySelectorAll('#cardPreview *'),C=[].filter.call(doc.querySelectorAll('#cardPreview *'),function(n){return !/pseudoelement/i.test(n.tagName)});" +
      "for(var i=0;i<L.length&&L.length===C.length;i++){var s=getComputedStyle(L[i]);if((s.webkitBackgroundClip||s.backgroundClip)!=='text')continue;var g=parseCssGradient(cssBackgroundLayer(s.backgroundImage)),f=g?g.stops[0].color:'#fff';" +
      "C[i].style.setProperty('background','none','important');C[i].style.setProperty('-webkit-background-clip','border-box','important');C[i].style.setProperty('background-clip','border-box','important');" +
      "C[i].style.setProperty('-webkit-text-fill-color',f,'important');C[i].style.setProperty('color',f,'important')}" +
      "var live=document.querySelector('#cardPreview .card-brand-border'),copy=doc.querySelector('#cardPreview .card-brand-border');if(live&&copy){copy.parentNode.insertBefore(brandRingCanvas(live,doc,3),copy);" +
      "['-webkit-mask','mask','background','box-shadow','animation'].forEach(function(p){copy.style.setProperty(p,'none','important')})}}}).then(function(c){return c.toDataURL('image/png')})})()";
    const ctlRows = [];
    for (const [look, orient] of [["gradient-effect", "horizontal"], ["midnight", "vertical"]]) {
      const fx = look === "gradient-effect";
      await evaluate(cdp, "setTheme(" + JSON.stringify(fx ? "dark" : look) + "); applyTextEffect(" + JSON.stringify(fx ? "gradient" : "none") + "); applyCardOrientation(" + JSON.stringify(orient) + "); true");
      await sleep(450);
      const prev = await previewShot(), old = await evaluate(cdp, OLD_FILL);
      const sel = fx ? "#cardPreview .card-company, #cardPreview .card-job" : "#cardPreview .card-name";
      ctlRows.push(Object.assign({ key: look + "|" + orient }, await evaluate(cdp, "window.__cmpText(" + JSON.stringify(prev) + ", " + JSON.stringify(old) + ", " + JSON.stringify(sel) + ")")));
    }
    console.log("    control (the old first-colour fill): " + ctlRows.map(r => r.key + " mad " + r.mad + " hue spread " + r.spreadPrev + "/" + r.spreadExp + " hue difference " + r.hueDiff).join("; "));
    check("the control fails the same test: the old first-colour fill loses the gradient (so the test can see it)", ctlRows.every(r => !(r.mad < MAD && spreadOk(r))), JSON.stringify(ctlRows));
    await evaluate(cdp, "setTheme('dark'); applyTextEffect('none'); applyCardOrientation('horizontal'); true"); await sleep(300);

    // The old slab, for the record: html2canvas with no onclone, on the same card.
    await evaluate(cdp, "applyBorderStyle('glow'); applyCardOrientation('horizontal'); setShowQr(false); true"); await sleep(300);
    const prevG = await previewShot();
    const slabUrl = await evaluate(cdp, "html2canvas(document.getElementById('cardPreview'), { scale: 3, useCORS: true, allowTaint: false }).then(function (cv) { return cv.toDataURL('image/png'); })");
    const slab = await evaluate(cdp, "window.__cmp(" + JSON.stringify(prevG) + ", " + JSON.stringify(slabUrl) + ")");
    console.log("    control: html2canvas without the ring swap (the old exports): mad " + slab.mad + ", name " + slab.namePrev + "/" + slab.nameExp + ", one colour " + slab.famPrev + " " + slab.topPrev + "%/" + slab.famExp + " " + slab.topExp + "%");
    check("the control fails the same test: without the ring swap html2canvas paints the old slab (so the test can see it)", !(slab.mad < MAD && slab.nameExp > NAME && oneColourOk(slab)), JSON.stringify(slab));
    // Share as Image: the 1200 x 630 frame, the card letterboxed in it as shareCardImage draws it.
    await evaluate(cdp, "applyBorderStyle('gold'); applyCardOrientation('horizontal'); setShowQr(true); setQrCorner('bottom-right'); true"); await sleep(450);
    const prevS = await previewShot();
    await evaluate(cdp, "window.__saves.length = 0, true");
    await evaluate(cdp, "shareCardImage().then(function(){return true;})");
    const share = await evaluate(cdp, "(window.__saves.filter(function(s){return s.name==='bizforce-card-share.png';})[0]||{}).href||''");
    const shareDims = share ? await evaluate(cdp, "new Promise(function(ok){var i=new Image();i.onload=function(){ok([i.width,i.height]);};i.src=" + JSON.stringify(share) + ";})") : [0, 0];
    const src = await evaluate(cdp, "(function(){var c=document.getElementById('cardPreview'),cw=Math.round(c.getBoundingClientRect().width*3),ch=Math.round(c.getBoundingClientRect().height*3),s=Math.min((1200-96)/cw,(630-96)/ch),w=Math.round(cw*s),h=Math.round(ch*s);return {x:Math.round((1200-w)/2),y:Math.round((630-h)/2),w:w,h:h};})()");
    const rs = share ? await evaluate(cdp, "window.__cmp(" + JSON.stringify(prevS) + ", " + JSON.stringify(share) + ", " + JSON.stringify(src) + ")") : { mad: 999 };
    if (share) fs.writeFileSync(path.join(OUT, "share-image.png"), Buffer.from(share.slice(share.indexOf(",") + 1), "base64"));
    console.log("    share (gold, QR on)            mad " + rs.mad + "  name " + rs.namePrev + "/" + rs.nameExp + "  one colour " + rs.topPrev + "%/" + rs.topExp + "%  frame " + shareDims.join(" x "));
    check("Share as Image: a 1200 x 630 frame whose card matches the preview (mean difference " + rs.mad + ", under " + MAD + "; name contrast over " + NAME + "; not one-colour)",
      shareDims[0] === 1200 && shareDims[1] === 630 && rs.mad < MAD && rs.nameExp > NAME && oneColourOk(rs), JSON.stringify({ rs, shareDims }));
    // Export Print File: the PNG it saves and the PDF's page, decoded to an image.
    await evaluate(cdp, "applyBorderStyle('holo-rainbow'); applyCardOrientation('horizontal'); setShowQr(false); document.getElementById('bleedCheck').checked = false; true"); await sleep(450);
    const prevP = await previewShot();
    await evaluate(cdp, "window.__saves.length = 0, window.__pdfs.length = 0, true");
    await evaluate(cdp, "exportPrintFile().then(function(){return true;})");
    const pdf = await evaluate(cdp, "(window.__pdfs[0]||{}).uri||''");
    const page = pdf ? pdfPage(pdf) : { media: [], png: null };
    let rp = { mad: 999 };
    if (page.png) {
      fs.writeFileSync(path.join(OUT, "print-page.png"), page.png);
      rp = await evaluate(cdp, "window.__cmp(" + JSON.stringify(prevP) + ", " + JSON.stringify("data:image/png;base64," + page.png.toString("base64")) + ")");
    }
    console.log("    print page (holo, PDF)         mad " + rp.mad + "  name " + rp.namePrev + "/" + rp.nameExp + "  one colour " + rp.topPrev + "%/" + rp.topExp + "%  page " + page.media.join(" ") + " pt, image " + page.w + " x " + page.h + (page.dict ? " | " + page.dict : ""));
    check("Export Print File: the PDF's page is 3.5 x 2 in (252 x 144 pt) and, rendered to an image, matches the preview (mean difference " + rp.mad + ", under " + MAD + "; name contrast over " + NAME + "; not one-colour)",
      page.media.join() === "0,0,252,144" && rp.mad < MAD && rp.nameExp > NAME && oneColourOk(rp), JSON.stringify({ rp, media: page.media }));
    await evaluate(cdp, "document.getElementById('__freeze').remove(), applyBorderStyle('glow'), applyCardOrientation('horizontal'), setShowQr(false), true");
    await sleep(300);

    /* ── no overflow; 390 px ── */
    console.log("\n══ no sideways overflow at 1440 and 390 px ══");
    check("1440 px: the page does not scroll sideways", (await evaluate(cdp, "__bf.overflow()")) <= 0, String(await evaluate(cdp, "__bf.overflow()")));
    await viewport(cdp, 390, 844, true);
    await sleep(400);
    const narrow = await evaluate(cdp, "({ over: __bf.overflow(), col: Math.round(document.querySelector('.preview-panel').getBoundingClientRect().right), list: (function(){ var l = document.getElementById('cardEdTablist'), cs = getComputedStyle(l); return { sw: l.scrollWidth, cw: l.clientWidth, ox: cs.overflowX, wrap: cs.flexWrap, right: Math.round(l.getBoundingClientRect().right) }; })() })");
    check("390 px: the page does not scroll sideways, and the tab row stays on one line within its column, scrolling sideways itself",
      narrow.over <= 0 && narrow.list.ox === "auto" && narrow.list.wrap === "nowrap" && narrow.list.right <= narrow.col && narrow.list.sw > narrow.list.cw - 1, JSON.stringify(narrow));
    // NAMED (Nov 11 2026, card exports and phone layout): the note (a 434 px column, its right 68 px clipped) became checks.
    const fit = await evaluate(cdp, `(function(){ var W = window.innerWidth, out = [];
      var clipped = function (n) { for (var a = n.parentElement; a && a !== document.body; a = a.parentElement) { var ox = getComputedStyle(a).overflowX; if (ox !== "visible" && a.getBoundingClientRect().right <= W + 1) return true; } return false; };
      [].forEach.call(document.querySelectorAll("body *"), function (n) { var r = n.getBoundingClientRect(); if (r.width > 0 && r.height > 0 && r.right > W + 1 && getComputedStyle(n).position !== "fixed" && !clipped(n)) out.push((n.id || n.className || n.tagName) + " " + Math.round(r.right)); });
      var rows = [].map.call(document.querySelectorAll(".form-panel .vid-upload-row"), function (row) { var tops = [].filter.call(row.children, function (c) { return c.getBoundingClientRect().height > 0; }).map(function (c) { return Math.round(c.getBoundingClientRect().top); });
        return { wrap: getComputedStyle(row).flexWrap, lines: new Set(tops).size, fits: row.scrollWidth <= row.clientWidth + 1, right: Math.round(row.getBoundingClientRect().right) }; });
      var body = document.body, keep = body.style.overflowX; body.style.overflowX = "visible"; var bare = document.documentElement.scrollWidth - W; body.style.overflowX = keep;
      return { past: out.slice(0, 8), rows: rows, col: Math.round(document.querySelector(".form-panel").getBoundingClientRect().width), bare: bare }; })()`);
    console.log("    390 px: the left column " + fit.col + " px; upload rows " + fit.rows.map(r => r.lines + " line" + (r.lines > 1 ? "s" : "")).join(", ") + "; without body's overflow-x the page would be " + fit.bare + " px too wide");
    check("390 px: nothing in the card maker passes the screen's edge (the column " + fit.col + " px), and nothing is clipped by body's overflow-x either (" + fit.bare + " px)", fit.past.length === 0 && fit.bare <= 0 && fit.col <= 390 - 24, JSON.stringify(fit));
    check("390 px: the upload rows wrap (flex-wrap: wrap), at least one onto a second line, each within the column", fit.rows.length >= 3 && fit.rows.every(r => r.wrap === "wrap" && r.fits && r.right <= 390) && fit.rows.some(r => r.lines >= 2), JSON.stringify(fit.rows));
    await evaluate(cdp, "document.getElementById('edTab-text').click(), true");
    await shot(cdp, "maker-390.png", "#cardPreview");
    await evaluate(cdp, "document.querySelector('.form-panel .vid-upload-row').scrollIntoView({block:'center'}), true");
    await sleep(250);
    const mres = await cdp.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(OUT, "maker-390-fixed.png"), Buffer.from(mres.data, "base64"));

    /* ── the public card ── */
    console.log("\n══ the public card, 390 px ══");
    cardLayout = {};
    await open(cdp, origin, "c/jane-doe", "/Jane Doe/.test((document.getElementById('pName')||{}).textContent||'')");
    const pubOff = await evaluate(cdp, `(function(){ var p = document.getElementById("cardPreview");
      var labels = [].filter.call(p.querySelectorAll("*"), function (n) { return n.children.length === 0 && /scan to connect/i.test(n.textContent) && __bf.shown(n); }).length;
      return { block: __bf.shown(document.getElementById("cvQrBlock")), labels: labels, drawn: __bf.drawn(document.getElementById("qrCanvas")), over: __bf.overflow() }; })()`);
    check("public card, show_qr missing: no QR, no \"Scan to connect\", nothing drawn, no sideways scroll", !pubOff.block && pubOff.labels === 0 && !pubOff.drawn && pubOff.over <= 0, JSON.stringify(pubOff));
    // NAMED (Nov 11 2026, card exports and phone layout): the note (the card about 150 px left of the screen) became checks, at three widths.
    const CENTRED = `(function(){ var v = document.getElementById("cardViewport").getBoundingClientRect(), f = document.querySelector(".bf-legal-footer"), fr = f ? f.getBoundingClientRect() : null;
      return { mid: Math.round((v.left + v.width / 2) * 10) / 10, half: document.documentElement.clientWidth / 2, left: Math.round(v.left), footerTop: fr ? Math.round(fr.top) : null, cardBottom: Math.round(v.bottom),
        footerText: f ? f.textContent.trim().slice(0, 20) : "", over: __bf.overflow(), dir: getComputedStyle(document.body).flexDirection }; })()`;
    const centred = {};
    centred[390] = await evaluate(cdp, CENTRED);
    await shot(cdp, "public-390.png", "body");
    await evaluate(cdp, "window.scrollTo(0,0), true");
    const cres = await cdp.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(OUT, "public-390-centred.png"), Buffer.from(cres.data, "base64"));
    for (const [W, H] of [[768, 1024], [1440, 1000]]) {
      await viewport(cdp, W, H, false);
      await open(cdp, origin, "c/jane-doe", "/Jane Doe/.test((document.getElementById('pName')||{}).textContent||'')");
      centred[W] = await evaluate(cdp, CENTRED);
    }
    await viewport(cdp, 390, 844, true);
    console.log("    public card centre against the screen's: " + Object.keys(centred).map(W => W + " px " + centred[W].mid + "/" + centred[W].half + " (footer at " + centred[W].footerTop + ", card ends " + centred[W].cardBottom + ")").join("; "));
    check("public card at 390, 768 and 1440 px: a column, the card centred (its centre within 2 px of the screen's), the legal footer below it, no sideways scroll",
      Object.keys(centred).length === 3 && Object.values(centred).every(c => c.dir === "column" && Math.abs(c.mid - c.half) <= 2 && c.footerTop !== null && c.footerTop >= c.cardBottom && c.footerText.length > 0 && c.over <= 0), JSON.stringify(centred));
    await open(cdp, origin, "c/jane-doe", "/Jane Doe/.test((document.getElementById('pName')||{}).textContent||'')");
    cardLayout = { show_qr: true, qr_corner: "bottom-right" };
    await open(cdp, origin, "c/jane-doe", "/Jane Doe/.test((document.getElementById('pName')||{}).textContent||'')");
    const pubOn = await evaluate(cdp, `({ block: __bf.shown(document.getElementById("cvQrBlock")), drawn: __bf.drawn(document.getElementById("qrCanvas")),
      label: __bf.shown(document.querySelector("#cvQrBlock .card-qr-label")), corner: __bf.corner(document.querySelector("#cvQrBlock .card-qr-wrap"), document.getElementById("cardPreview")), over: __bf.overflow() })`);
    check("public card, show_qr true, bottom-right: the QR is drawn with its label in the bottom right", pubOn.block && pubOn.drawn && pubOn.label && pubOn.corner === "bottom-right" && pubOn.over <= 0, JSON.stringify(pubOn));
    const pubCorners = {};
    for (const c of ["top-left", "top-right", "bottom-left"]) {
      cardLayout = { show_qr: true, qr_corner: c };
      await open(cdp, origin, "c/jane-doe", "/Jane Doe/.test((document.getElementById('pName')||{}).textContent||'')");
      pubCorners[c] = await evaluate(cdp, "__bf.corner(document.querySelector('#cvQrBlock .card-qr-wrap'), document.getElementById('cardPreview'))");
    }
    check("public card: each other corner puts the QR there", Object.keys(pubCorners).every(k => pubCorners[k] === k), JSON.stringify(pubCorners));
    // The two screenshots at 768 px, where the card and the footer beside it both fit on the screen.
    await viewport(cdp, 768, 1024, false);
    for (const [name, ml] of [["public-no-qr.png", {}], ["public-qr.png", { show_qr: true, qr_corner: "bottom-right" }]]) {
      cardLayout = ml;
      await open(cdp, origin, "c/jane-doe", "/Jane Doe/.test((document.getElementById('pName')||{}).textContent||'')");
      await sleep(300);
      await shot(cdp, name, "body");
    }

    /* ── NAMED (Nov 13 2026, horizontal default) ── */
    console.log("\n══ horizontal by default; a saved orientation kept (the maker, its exports, the public card) ══");
    // The maker's state: the preview's class, the toggle, what a save would send, the preview's shape, and every frame's record.
    const MAKER_ORIENT = `(function(){ var p = document.getElementById("cardPreview"), r = p.getBoundingClientRect(), on = document.querySelectorAll("[data-orient].active");
      return { vertical: p.classList.contains("orient-vertical"), toggle: on.length === 1 ? on[0].getAttribute("data-orient") : on.length + " active", saved: getFields().media_layout.orientation,
        ratio: Math.round(r.width / r.height * 100) / 100, frames: (window.__orientLog || []).map(function (s) { return s.charAt(0); }).join("") }; })()`;
    // The exports of the card as it stands: the Download PNG's size and the print file's PDF page (points).
    const exportsNow = async () => {
      await evaluate(cdp, CAPTURE);
      await evaluate(cdp, "window.__saves.length = 0, window.__pdfs.length = 0, document.getElementById('bleedCheck').checked = false, true");
      await evaluate(cdp, "downloadCard().then(function(){return exportPrintFile();}).then(function(){return true;})");
      await sleep(400);
      const png = await evaluate(cdp, `new Promise(function (ok) { var s = window.__saves.filter(function (x) { return x.name === "bizforce-card.png"; })[0];
        if (!s) return ok(null); var i = new Image(); i.onload = function () { ok([i.naturalWidth, i.naturalHeight]); }; i.onerror = function () { ok(null); }; i.src = s.href; })`);
      const pdfUri = await evaluate(cdp, "(window.__pdfs[0]||{}).uri||''");
      return { png, pngRatio: png ? Math.round(png[0] / png[1] * 100) / 100 : null, page: pdfUri ? pdfPage(pdfUri).media.join(" ") : null };
    };
    const makerReady = "typeof cardLoadState !== 'undefined' && cardLoadState === 'ready' && !!window.html2canvas && !!window.jspdf";
    await viewport(cdp, 1440, 1000);

    // A member's first card: no card saved yet.
    noCards = true;
    await open(cdp, origin, "digital-cards.html", makerReady);
    const fresh = await evaluate(cdp, MAKER_ORIENT);
    check("a new card (none saved) opens horizontal: the Horizontal toggle alone is selected, the preview is not upright (" + fresh.ratio + " : 1), and a save would send horizontal",
      !fresh.vertical && fresh.toggle === "horizontal" && fresh.saved === "horizontal" && Math.abs(fresh.ratio - 1.75) <= 0.03, JSON.stringify(fresh));
    check("a new card: no frame was ever painted upright (frames " + fresh.frames + ")", fresh.frames.length >= 1 && fresh.frames.indexOf("V") === -1, fresh.frames);
    await evaluate(cdp, "window.scrollTo(0, 0), true");
    await sleep(250);
    const dres = await cdp.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(OUT, "default-horizontal.png"), Buffer.from(dres.data, "base64"));
    const freshEx = await exportsNow();
    check("a new card's exports are horizontal: the PNG wider than tall (" + (freshEx.png || []).join(" x ") + ") and the print file's page 3.5 x 2 in (252 x 144 pt)",
      !!freshEx.png && Math.abs(freshEx.pngRatio - 1.75) <= 0.03 && freshEx.page === "0 0 252 144", JSON.stringify(freshEx));
    noCards = false;

    // A saved card with no orientation, and one saved horizontal: both horizontal, and never upright on the way.
    const savedRows = {};
    for (const [label, ml] of [["no orientation saved", {}], ["saved horizontal", { orientation: "horizontal" }], ["an unknown orientation", { orientation: "sideways" }]]) {
      cardLayout = ml;
      await open(cdp, origin, "digital-cards.html", makerReady + " && /Card loaded/.test((document.getElementById('saveStatus')||{}).textContent||'')");
      savedRows[label] = await evaluate(cdp, MAKER_ORIENT);
    }
    check("a saved card with no orientation, saved horizontal, or with an unknown value opens horizontal (toggle, preview, save) and is never painted upright",
      Object.values(savedRows).every(s => !s.vertical && s.toggle === "horizontal" && s.saved === "horizontal" && Math.abs(s.ratio - 1.75) <= 0.03 && s.frames.indexOf("V") === -1), JSON.stringify(savedRows));

    // A card saved vertical stays vertical.
    cardLayout = { orientation: "vertical" };
    await open(cdp, origin, "digital-cards.html", makerReady + " && /Card loaded/.test((document.getElementById('saveStatus')||{}).textContent||'')");
    const vert = await evaluate(cdp, MAKER_ORIENT);
    check("a card saved vertical reopens vertical: the Vertical toggle alone selected, the preview upright (" + vert.ratio + " : 1), and a save keeps vertical",
      vert.vertical && vert.toggle === "vertical" && vert.saved === "vertical" && Math.abs(vert.ratio - 1 / 1.75) <= 0.01, JSON.stringify(vert));
    await evaluate(cdp, "window.scrollTo(0, 0), true");
    await sleep(250);
    const vres = await cdp.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(OUT, "saved-vertical.png"), Buffer.from(vres.data, "base64"));
    const vertEx = await exportsNow();
    check("a vertical card's exports are vertical: the PNG taller than wide (" + (vertEx.png || []).join(" x ") + ") and the print file's page 2 x 3.5 in (144 x 252 pt)",
      !!vertEx.png && Math.abs(vertEx.pngRatio - 1 / 1.75) <= 0.02 && vertEx.page === "0 0 144 252", JSON.stringify(vertEx));

    // The public card follows the saved orientation, horizontal when there is none.
    const PUBLIC_ORIENT = `(function(){ var v = document.getElementById("cardViewport"), p = document.getElementById("cardPreview"), r = p.getBoundingClientRect(), a = document.getElementById("cardActions").getBoundingClientRect();
      return { vertical: v.classList.contains("cv-vertical"), cardVertical: p.classList.contains("orient-vertical"), ratio: Math.round(r.width / r.height * 100) / 100, w: Math.round(r.width),
        buttonsBelow: a.top >= r.bottom - 1, over: __bf.overflow(), frames: (window.__orientLog || []).join(" ") }; })()`;
    const pubRows = {};
    for (const [W, H, mobile] of [[390, 844, true], [768, 1024, false], [1440, 1000, false]]) {
      await viewport(cdp, W, H, mobile);
      for (const [label, ml] of [["none", {}], ["horizontal", { orientation: "horizontal" }], ["vertical", { orientation: "vertical" }]]) {
        cardLayout = ml;
        await open(cdp, origin, "c/jane-doe", "/Jane Doe/.test((document.getElementById('pName')||{}).textContent||'')");
        pubRows[W + " " + label] = await evaluate(cdp, PUBLIC_ORIENT);
        if (W === 390 && label === "none") { await evaluate(cdp, "window.scrollTo(0, 0), true"); await sleep(250); const pres = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(OUT, "public-horizontal.png"), Buffer.from(pres.data, "base64")); }
      }
    }
    const pubH = Object.keys(pubRows).filter(k => !/vertical$/.test(k)), pubV = Object.keys(pubRows).filter(k => /vertical$/.test(k));
    check("public card with no orientation saved, or saved horizontal, at 390, 768 and 1440 px: horizontal (1.75 : 1), the buttons under the card, no sideways scroll, and never a vertical frame",
      pubH.length === 6 && pubH.every(k => { const r = pubRows[k]; return !r.vertical && !r.cardVertical && Math.abs(r.ratio - 1.75) <= 0.03 && r.buttonsBelow && r.over <= 0 && !/[Vv]/.test(r.frames); }),
      JSON.stringify(pubH.map(k => [k, pubRows[k]])));
    check("public card saved vertical, at 390, 768 and 1440 px: an upright business card, 1 : 1.75 (NAMED Nov 13 2026, Q5b: no longer the full-height card)",
      pubV.length === 3 && pubV.every(k => { const r = pubRows[k]; return r.vertical && r.cardVertical && Math.abs(r.ratio - 1 / 1.75) <= 0.01 && r.buttonsBelow && r.over <= 0; }), JSON.stringify(pubV.map(k => [k, pubRows[k]])));
    await viewport(cdp, 390, 844, true);
    cardLayout = {};

    /* ── NAMED (Nov 13 2026, Q5b): business-card sizing with no scroll, at six screen sizes, both orientations ── */
    console.log("\n══ Q5b. the public card fits the screen: card, buttons and footer, no scrollbar (a visitor, every button shown) ══");
    fs.mkdirSync(Q5_OUT, { recursive: true });
    // A visitor has no session: on ?visitor=1 the check's sign-in (registered first) is undone before the page runs.
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{if(/[?&]visitor=1/.test(location.search)){localStorage.removeItem('bf_token');localStorage.removeItem('bf_user');}}catch(e){}" });
    q5Extras = true;
    const FIT = `(function(){ var c = document.getElementById("cardPreview").getBoundingClientRect(), a = document.getElementById("cardActions").getBoundingClientRect(),
      f = document.querySelector("body > footer.bf-legal-footer").getBoundingClientRect(), de = document.documentElement;
      var btns = [].filter.call(document.querySelectorAll("#cardActions .cv-btn"), function (b) { return !b.hidden && getComputedStyle(b).display !== "none"; });
      return { w: Math.round(c.width), h: Math.round(c.height), ratio: c.width / c.height, cardTop: Math.round(c.top), cardBottom: Math.round(c.bottom), actTop: Math.round(a.top),
        footBottom: Math.round(f.bottom), docH: de.scrollHeight, docW: de.scrollWidth, vh: innerHeight, vw: innerWidth, nBtns: btns.length,
        btnsIn: btns.every(function (b) { var r = b.getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight && r.left >= 0 && r.right <= innerWidth; }),
        btnsUnder: btns.every(function (b) { return b.getBoundingClientRect().top >= c.bottom - 0.5; }) }; })()`;
    const SIZES = [[1440, 900], [1366, 768], [1280, 720], [768, 1024], [390, 844], [360, 740]];
    const fits = {};
    for (const [W, Hh] of SIZES) {
      await viewport(cdp, W, Hh, W < 600);
      for (const o of ["horizontal", "vertical"]) {
        cardLayout = { orientation: o };
        await open(cdp, origin, "c/jane-doe?visitor=1", "/Jane Doe/.test((document.getElementById('pName')||{}).textContent||'') && !document.getElementById('cvSupportBtn').hidden");
        await sleep(300);
        const r = await evaluate(cdp, FIT);
        fits[W + "x" + Hh + " " + o] = r;
        const shotName = { "1440x900 horizontal": "card-h-1440.png", "1440x900 vertical": "card-v-1440.png", "1366x768 vertical": "card-v-1366x768.png",
          "390x844 vertical": "card-v-390.png", "390x844 horizontal": "card-h-390.png" }[W + "x" + Hh + " " + o];
        if (shotName) { const s = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(Q5_OUT, shotName), Buffer.from(s.data, "base64")); }
      }
    }
    const fitRows = Object.keys(fits).map(k => [k, fits[k]]);
    console.log("    note  card sizes: " + fitRows.map(([k, r]) => k + " " + r.w + "x" + r.h).join("; "));
    check("no scrollbar at 1440x900, 1366x768, 1280x720, 768x1024, 390x844 and 360x740, both orientations: the page is no taller and no wider than the screen",
      fitRows.length === 12 && fitRows.every(([, r]) => r.docH <= r.vh && r.docW <= r.vw), JSON.stringify(fitRows.filter(([, r]) => !(r.docH <= r.vh && r.docW <= r.vw))));
    check("the card is a business card at every size: 1.75 : 1 lying down, 1 : 1.75 standing up, within 1%",
      fitRows.every(([k, r]) => Math.abs(r.ratio - (/vertical$/.test(k) ? 1 / 1.75 : 1.75)) / (/vertical$/.test(k) ? 1 / 1.75 : 1.75) <= 0.01),
      JSON.stringify(fitRows.map(([k, r]) => [k, r.ratio.toFixed(4)])));
    check("...within its caps: lying down at most 560 px wide and 92% of the screen; standing up at most 560 px tall",
      fitRows.every(([k, r]) => /vertical$/.test(k) ? r.h <= 560 && r.w <= r.vw * 0.92 + 1 : r.w <= 560 && r.w <= r.vw * 0.92 + 1), JSON.stringify(fitRows.map(([k, r]) => [k, r.w, r.h])));
    check("all five buttons (Support, Leave your details, Save Contact, Add to Google Wallet, Create Your Own) inside the screen, under the card, and the footer too",
      fitRows.every(([, r]) => r.nBtns === 5 && r.btnsIn && r.btnsUnder && r.footBottom <= r.vh), JSON.stringify(fitRows.filter(([, r]) => !(r.nBtns === 5 && r.btnsIn && r.btnsUnder && r.footBottom <= r.vh))));
    // Support and the lead form open inline under the buttons (1440 x 900, horizontal); the page may scroll only then.
    await viewport(cdp, 1440, 900, false);
    cardLayout = {};
    await open(cdp, origin, "c/jane-doe?visitor=1", "!document.getElementById('cvSupportBtn').hidden");
    const cardW0 = await evaluate(cdp, "Math.round(document.getElementById('cardPreview').getBoundingClientRect().width)");
    const opened = await evaluate(cdp, `(function(){ var R = function (id) { return document.getElementById(id).getBoundingClientRect(); };
      document.getElementById("cvSupportBtn").click();
      var p = document.getElementById("cvSupport"), a = R("cardActions"), r = R("cvSupport"), f = document.querySelector("body > footer.bf-legal-footer").getBoundingClientRect();
      var out = { shown: !p.hidden, pos: getComputedStyle(p).position, gap: Math.round(r.top - a.bottom), footBelow: f.top >= r.bottom - 0.5 };
      document.getElementById("cvLeadBtn").click(); var l = document.getElementById("cvLead"), lr = R("cvLead"), r2 = R("cvSupport"),
        f2 = document.querySelector("body > footer.bf-legal-footer").getBoundingClientRect();
      out.lead = { shown: !l.hidden, pos: getComputedStyle(l).position, belowSupport: lr.top >= r2.bottom - 0.5, footBelow: f2.top >= lr.bottom - 0.5 }; return out; })()`);
    // A resize with both panels open refits, and the card keeps its size: an open panel lets the page scroll instead.
    await viewport(cdp, 1440, 901, false); await sleep(200); await viewport(cdp, 1440, 900, false); await sleep(200);
    const cardW1 = await evaluate(cdp, "Math.round(document.getElementById('cardPreview').getBoundingClientRect().width)");
    check("with Support and the lead form open, a resize leaves the card its size (" + cardW0 + " -> " + cardW1 + " px)", cardW0 === cardW1 && cardW0 === 560, cardW0 + " " + cardW1);
    check("Support opens inline directly under the button row (static, 0-16 px below it), the footer pushed down below it",
      opened.shown && opened.pos === "static" && opened.gap >= 0 && opened.gap <= 16 && opened.footBelow, JSON.stringify(opened));
    check("the lead form opens inline under it too, the footer below both", opened.lead.shown && opened.lead.pos === "static" && opened.lead.belowSupport && opened.lead.footBelow, JSON.stringify(opened.lead));
    await evaluate(cdp, "document.getElementById('cvLeadBtn').click(), true");
    await sleep(250);
    { const s = await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true }); fs.writeFileSync(path.join(Q5_OUT, "card-support-open.png"), Buffer.from(s.data, "base64")); }
    // The owner, signed in, on a phone: the Guide's spacer may sit below the fold, but the card, its buttons and the footer are all in view.
    await viewport(cdp, 390, 844, true);
    cardLayout = { orientation: "vertical" };
    await open(cdp, origin, "c/jane-doe", "!document.getElementById('cvSupportBtn').hidden && !!document.getElementById('tmx-guide-fab')");
    await sleep(400);
    const ownPhone = await evaluate(cdp, FIT);
    check("signed in at 390 px (the Guide's spacer on the page): the card, every button and the footer are fully in view without scrolling",
      ownPhone.btnsIn && ownPhone.footBottom <= ownPhone.vh && ownPhone.cardTop >= 0 && ownPhone.cardBottom <= ownPhone.vh, JSON.stringify(ownPhone));
    // The maker's preview has the same ratios.
    await viewport(cdp, 1440, 1000, false);
    const prevRatio = {};
    for (const o of ["horizontal", "vertical"]) {
      cardLayout = { orientation: o };
      await open(cdp, origin, "digital-cards.html", makerReady + " && /Card loaded/.test((document.getElementById('saveStatus')||{}).textContent||'')");
      prevRatio[o] = await evaluate(cdp, "(function(){var r=document.getElementById('cardPreview').getBoundingClientRect();return {w:Math.round(r.width),h:Math.round(r.height),ratio:r.width/r.height};})()");
    }
    check("the maker's preview matches the public card: 1.75 : 1 (at most 560 px wide) and 1 : 1.75 (at most 320 x 560), within 1%",
      Math.abs(prevRatio.horizontal.ratio - 1.75) / 1.75 <= 0.01 && prevRatio.horizontal.w <= 560 && Math.abs(prevRatio.vertical.ratio - 1 / 1.75) * 1.75 <= 0.01 && prevRatio.vertical.h <= 561,
      JSON.stringify(prevRatio));
    q5Extras = false;
    cardLayout = {};

    const own2 = exceptions.filter(x => !/Failed to fetch|BlockedByClient|NetworkError|Load failed|check:/.test(x));
    check("no page script threw", own2.length === 0, own2.slice(0, 5).join(" | "));
    console.log("    note  refused outside requests: " + refused.length + (refused.length ? " (" + [...new Set(refused.map(u => new URL(u).hostname))].join(", ") + ")" : ""));
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
