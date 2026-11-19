"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   buildBrandAssets — writes the frontend's icons/ and brand/ from the one
   source of the marks, the frontend's scripts/bf-marks.js (LOGO1, Nov 18 2026).

     node scripts/buildBrandAssets.js --font <SpaceGrotesk[wght].ttf>

   Writes, in the frontend checkout beside this repo (BIZFORCE_FRONTEND_DIR
   overrides it):
     icons/icon.svg                 the Layered Stack on its rounded #070B18 tile (the source of truth)
     icons/favicon-32.png           the tile, stroke 12 (the mark's small-size weight)
     icons/icon-192.png, icon-512.png            the tile
     icons/apple-touch-icon.png (180)            the tile without rounding (iOS rounds it)
     icons/icon-maskable-192.png, -512.png       no rounding, the glyph at 80% inside the safe circle
     brand/<mark>-dark.svg, <mark>-light.svg     each mark, no tile (layered-stack, force-hex, agent-network)
     brand/<mark>-tile.svg                       each mark on its tile
     brand/<mark>-tile-1024.png, -512.png, -256.png
     brand/bizforce-logo-dark.svg, -light.svg    the Layered Stack and the wordmark "BizForce AI" in
                                                 Space Grotesk 700, the wordmark as outlined paths
     brand/bizforce-logo-dark-1024.png, ... -256.png (the width; transparent)
   The PNGs are drawn by headless Chrome (CHROME_PATH, or the usual paths).
   The font is Space Grotesk (SIL Open Font License), from
   github.com/google/fonts/ofl/spacegrotesk; it is read, never shipped: the
   wordmark is outlined.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(__dirname, "..", "..", "BizForce-fronyend");
const M = require(path.join(FRONTEND, "scripts", "bf-marks.js"));
const fontAt = process.argv.indexOf("--font");
const FONT = fontAt !== -1 ? process.argv[fontAt + 1] : process.env.BIZFORCE_WORDMARK_FONT;
if (!FONT || !fs.existsSync(FONT)) { console.error("Give the Space Grotesk font: --font <path>"); process.exit(1); }

const ICONS = path.join(FRONTEND, "icons");
const BRAND = path.join(FRONTEND, "brand");
fs.mkdirSync(BRAND, { recursive: true });

const NAMES = { logo: "layered-stack", approval: "force-hex", agents: "agent-network" };
const NOTE = { logo: "Layered Stack, the BizForce AI logo", approval: "Force Hex, the approval mark", agents: "Agent Network, the agents mark" };

function file(kind, o) {
  return M.svg(kind, Object.assign({ xmlns: true, ids: NAMES[kind] }, o));
}
function titled(svg, title) {
  return svg.replace(">", ' role="img" aria-label="' + title + '"><title>' + title + "</title>") + "\n";
}

/* ── the wordmark, outlined ── */
const fontkit = require("fontkit");
const face = fontkit.openSync(FONT).getVariation({ wght: 700 });
function wordmark(text, fontSize, x0, baseline) {
  const run = face.layout(text);
  const s = fontSize / face.unitsPerEm;
  let x = x0;
  const parts = [];
  run.glyphs.forEach(function (gl, i) {
    const pos = run.positions[i];
    const d = gl.path.scale(s, -s).translate(x + pos.xOffset * s, baseline - pos.yOffset * s).toSVG();
    parts.push({ ch: text[run.glyphs[i].stringIndex !== undefined ? run.glyphs[i].stringIndex : i], d: d, x: x });
    x += pos.xAdvance * s;
  });
  return { parts: parts, width: x - x0 };
}
function round(d) { return d.replace(/-?\d+\.\d+/g, function (n) { return String(Math.round(Number(n) * 100) / 100); }); }
function logoFile(tone) {
  const word = tone === "light" ? "#070B18" : "#F5F7FF";
  const ai = tone === "light" ? "#0E7490" : "#22D3EE";
  const head = wordmark("BizForce", 64, 136, 82);
  const tail = wordmark("AI", 64, 136 + head.width + 16, 82);
  const width = Math.ceil(136 + head.width + 16 + tail.width + 8);
  const mark = M.svg("logo", { ids: "bizforce-logo-" + tone, tone: tone });
  const inner = mark.replace(/^<svg[^>]*>/, "").replace(/<\/svg>$/, "");
  const title = "BizForce AI";
  return {
    width: width, height: 120,
    svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + width + ' 120" width="' + width + '" height="120" role="img" aria-label="' + title + '">' +
      "<title>" + title + "</title>" +
      "<!-- The Layered Stack and the wordmark: \"BizForce\" in Space Grotesk 700 with \"AI\" in " + ai + ", outlined. Built by the backend's scripts/buildBrandAssets.js. -->" +
      inner +
      '<path fill="' + word + '" d="' + round(head.parts.map(function (p) { return p.d; }).join("")) + '"/>' +
      '<path fill="' + ai + '" d="' + round(tail.parts.map(function (p) { return p.d; }).join("")) + '"/>' +
      "</svg>\n"
  };
}

/* ── Chrome ── */
const CANDIDATES = [process.env.CHROME_PATH,
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  path.join(process.env.LOCALAPPDATA || "", "Google\\Chrome\\Application\\chrome.exe"),
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"].filter(Boolean);
const CHROME = CANDIDATES.find(function (p) { try { return fs.statSync(p).isFile(); } catch (e) { return false; } });
if (!CHROME) { console.error("No Chrome found (set CHROME_PATH)."); process.exit(1); }
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function launch() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bf-brand-"));
  const proc = spawn(CHROME, ["--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + profile, "--no-first-run", "--no-default-browser-check",
    "--disable-gpu", "--disable-extensions", "--hide-scrollbars", "about:blank"], { stdio: "ignore" });
  const portFile = path.join(profile, "DevToolsActivePort");
  for (let i = 0; i < 150 && !fs.existsSync(portFile); i++) await sleep(100);
  let port = "";
  for (let i = 0; i < 50 && !/^\d+$/.test(port); i++) { try { port = fs.readFileSync(portFile, "utf8").split("\n")[0].trim(); } catch (e) { /* being written */ } if (!/^\d+$/.test(port)) await sleep(100); }
  let list = [];
  for (let i = 0; i < 50 && !list.some(t => t.type === "page"); i++) { try { list = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json(); } catch (e) { /* not yet */ } await sleep(100); }
  const ws = new WebSocket(list.find(t => t.type === "page").webSocketDebuggerUrl);
  let id = 0; const waiting = new Map();
  ws.onmessage = ev => { const m = JSON.parse(String(ev.data)); if (m.id && waiting.has(m.id)) { const w = waiting.get(m.id); waiting.delete(m.id); m.error ? w.reject(new Error(m.error.message)) : w.resolve(m.result); } };
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  const send = (method, params) => new Promise((resolve, reject) => { const n = ++id; waiting.set(n, { resolve, reject }); ws.send(JSON.stringify({ id: n, method, params: params || {} })); });
  return { proc, profile, ws, send };
}
async function png(cdp, svg, w, h, out) {
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile: false });
  const html = "<!doctype html><html><head><style>html,body{margin:0;background:transparent}svg{display:block;width:" + w + "px;height:" + h + "px}</style></head><body>" + svg + "</body></html>";
  await cdp.send("Page.navigate", { url: "data:text/html;base64," + Buffer.from(html).toString("base64") });
  await sleep(250);
  const r = await cdp.send("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width: w, height: h, scale: 1 } });
  fs.writeFileSync(out, Buffer.from(r.data, "base64"));
  console.log("wrote      " + path.relative(FRONTEND, out) + " (" + w + "x" + h + ")");
}
function write(out, text) { fs.writeFileSync(out, text); console.log("wrote      " + path.relative(FRONTEND, out)); }

(async function main() {
  // icons/icon.svg: the source of truth for the app icons.
  write(path.join(ICONS, "icon.svg"), titled(file("logo", { tile: true }), "BizForce AI").replace("<title>BizForce AI</title>",
    "<title>BizForce AI</title><!-- The Layered Stack on its #070B18 tile. The PNGs in this folder are drawn from bf-marks.js by the backend's scripts/buildBrandAssets.js; rebuild them, never edit them by hand. -->"));
  Object.keys(NAMES).forEach(function (kind) {
    write(path.join(BRAND, NAMES[kind] + "-dark.svg"), titled(file(kind, { tone: "dark" }), NOTE[kind] + " (dark backgrounds)"));
    write(path.join(BRAND, NAMES[kind] + "-light.svg"), titled(file(kind, { tone: "light" }), NOTE[kind] + " (light backgrounds)"));
    write(path.join(BRAND, NAMES[kind] + "-tile.svg"), titled(file(kind, { tile: true }), NOTE[kind] + " (app tile)"));
  });
  const logos = { dark: logoFile("dark"), light: logoFile("light") };
  Object.keys(logos).forEach(function (tone) { write(path.join(BRAND, "bizforce-logo-" + tone + ".svg"), logos[tone].svg); });

  const chrome = await launch();
  try {
    await chrome.send("Page.enable");
    await chrome.send("Emulation.setDefaultBackgroundColorOverride", { color: { r: 0, g: 0, b: 0, a: 0 } });
    await png(chrome, file("logo", { tile: true, stroke: 12 }), 32, 32, path.join(ICONS, "favicon-32.png"));
    await png(chrome, file("logo", { tile: true }), 192, 192, path.join(ICONS, "icon-192.png"));
    await png(chrome, file("logo", { tile: true }), 512, 512, path.join(ICONS, "icon-512.png"));
    await png(chrome, file("logo", { tile: "square" }), 180, 180, path.join(ICONS, "apple-touch-icon.png"));
    await png(chrome, file("logo", { tile: "square", scale: 0.8 }), 192, 192, path.join(ICONS, "icon-maskable-192.png"));
    await png(chrome, file("logo", { tile: "square", scale: 0.8 }), 512, 512, path.join(ICONS, "icon-maskable-512.png"));
    for (const kind of Object.keys(NAMES)) {
      for (const size of [1024, 512, 256]) await png(chrome, file(kind, { tile: true }), size, size, path.join(BRAND, NAMES[kind] + "-tile-" + size + ".png"));
    }
    for (const tone of Object.keys(logos)) {
      for (const size of [1024, 512, 256]) {
        await png(chrome, logos[tone].svg, size, Math.round(size * logos[tone].height / logos[tone].width), path.join(BRAND, "bizforce-logo-" + tone + "-" + size + ".png"));
      }
    }
  } finally {
    try { chrome.ws.close(); } catch (e) { /* closed */ }
    try { chrome.proc.kill(); } catch (e) { /* gone */ }
    await sleep(400);
    try { fs.rmSync(chrome.profile, { recursive: true, force: true }); } catch (e) { /* Chrome may hold a file */ }
  }
})().catch(function (e) { console.error(e && e.stack || e); process.exit(1); });
