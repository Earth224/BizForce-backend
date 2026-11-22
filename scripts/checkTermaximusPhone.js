"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkTermaximusPhone.js — Termaximus on the phone and the abyss (FX3,
   Nov 22 2026; the owner's canvas row 5: TmxHQ, TmxGuideOpen, TmxChatGuide,
   TmxChatOracle).

   WHAT THIS PROVES (the frontend's text, and bf-abyss.js run in a vm)
     A. THE ENGINE MOVED UNCHANGED: scripts/bf-abyss.js is the chat box's
        starfield engine from scripts/termaximus-presence.js at frontend
        e3e8ce0 (its lines 893-1144), line for line (comments aside), except
        seven named lines; every number is the same (the three layers' 70, 35
        and 16 are BASE_COUNTS); the presence no longer holds a copy and
        creates the chat's engine with no options (the chat's own counts).
     B. THE DENSITY AND THE RUN RULES (bf-abyss.js run): the chat's 288 x 340
        box gets 70/35/16; perArea gives round(count x area / 97920) (8/4/2
        on a 104 px disc); it runs only between start() and stop() and while
        the page is visible; under reduced motion it paints once and never runs.
     C. THE MIST ON THE PHONE: a fixed 56 px button (the 110 px mist scaled),
        16 px from the right, 16 px above the bar and the safe area, z-index 46
        (over the feed's 40 to 45, under the sheets' 50 and up), "Ask
        Termaximus", a tab stop, Enter and Space open it; the corner, the saved
        spot, dragging and keep-clear do not apply; css/bf-phone.css no longer
        sends it under the page; the whisper ends at its right edge.
     D. THE BOOK BUTTON GONE: no #tmx-guide-fab, no sheet, no restFab, no lift
        in bf-tabbar.js, no rules in bf-phone.css; the profile and the preview
        hide the Guide's tab instead.
     E. THE GUIDE AT EVERY WIDTH: the desktop's tab (no width hides it); on the
        phone the panel min(300px, 100vw - 48px), at most 70vh and clear of the
        bar, scrolling, the tab at its right edge, 0.3 s; outside tap, Escape
        and the tab close it.
     F. THE CHAT ON THE PHONE: 8 px each side, 10 px above the mist, at most
        420 px, the visual viewport for the keyboard; Reset hidden; no drag at
        760 px and below; the shooting star uses the box's real size.
     G. A FREE ACCOUNT: the mist opens the members panel (never the chat); the
        Guide shows tips only, no Insights section and no /api/insights/page.
     H. REDUCED MOTION: the void, the gold rim and the shooting star still; the
        ten transitions become one plain 0.2 s fade.
     I. WHERE THEY STAY HIDDEN: TMX_NO_MIST_PAGES and the signed-out guards as
        at e3e8ce0; the profile preview hides the mist, the chat and the Guide.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ══════════════════════════════════════════════════════════════════════════ */
const vm = require("vm");
const { execFileSync } = require("child_process");
const H = require("./_p21Harness");

const PRES = "scripts/termaximus-presence.js", GUIDE = "scripts/termaximus-guide.js", ABY = "scripts/bf-abyss.js", PHONE = "css/bf-phone.css";
const TAB = "scripts/bf-tabbar.js", SHELL = "scripts/bf-profile-shell.js", DESIGN = "scripts/bf-profile-design.js";
const BASE_REV = "e3e8ce0";

const MUTATIONS = {
  // A
  "engine-count-drift": [[ABY, "  var BASE_COUNTS = [70, 35, 16];", "  var BASE_COUNTS = [72, 35, 16];"]],
  "engine-drift-speed": [[ABY, "    var BASE_DRIFT_X = 8;", "    var BASE_DRIFT_X = 9;"]],
  "engine-line-changed": [[ABY, "minR: 0.4, maxR: 0.9, parallax: 0.15,", "minR: 0.5, maxR: 0.9, parallax: 0.15,"]],
  "engine-copy-left": [[PRES, "  function createTmxStarfield(canvas) {\n", "  function createTmxStarfield(canvas) {\n    function makeStar() {}\n"]],
  "chat-per-area": [[PRES, "      engine = window.BFAbyss.create(canvas);", "      engine = window.BFAbyss.create(canvas, { perArea: true });"]],
  // B
  "density-rounds-up": [[ABY, "return BASE_COUNTS.map(function (c) { return Math.round(c * ratio); });", "return BASE_COUNTS.map(function (c) { return Math.ceil(c * ratio); });"]],
  "per-area-ignored": [[ABY, "    var perArea = opts.perArea === true;", "    var perArea = false;"]],
  // C
  "mist-not-a-button": [[PRES, "  root.setAttribute(\"role\", \"button\");\n", ""]],
  "mist-no-label": [[PRES, "  root.setAttribute(\"aria-label\", \"Ask Termaximus\");", "  root.setAttribute(\"aria-label\", \"Termaximus\");"]],
  "mist-no-keys": [[PRES, "    if (e.target !== root || (e.key !== \"Enter\" && e.key !== \" \")) return;", "    if (e.target !== root || e.key !== \"Enter\") return;"]],
  "mist-too-high": [[PRES, "    z-index: 46; pointer-events: auto;", "    z-index: 1200; pointer-events: auto;"]],
  "mist-drags": [[PRES, "    if (tmxPhone()) { _tmxDragMoved = false; return; }   // NAMED (Nov 22 2026, FX3): no dragging on the phone", "    // NAMED (Nov 22 2026, FX3): no dragging on the phone"]],
  "mist-restores": [[PRES, "    if (tmxPhone()) return;   // NAMED (Nov 22 2026, FX3): the phone's mist keeps its place", "    // NAMED (Nov 22 2026, FX3): the phone's mist keeps its place"]],
  "mist-keeps-clear": [[PRES, "    if (tmxPhone()) { if (root.style.translate) root.style.translate = \"\"; return; }", "    if (false) { if (root.style.translate) root.style.translate = \"\"; return; }"]],
  "mist-under-page": [[PHONE, "  canvas.star-canvas, #starCanvas {", "  #tmx-presence-root { z-index: -1 !important; opacity: .6; pointer-events: none !important; }\n  canvas.star-canvas, #starCanvas {"]],
  "whisper-off-screen": [[PRES, "  #tmx-whisper { left: auto; right: 0; ", "  #tmx-whisper { "]],
  // D
  "book-button-back": [[GUIDE, "  var accessKnown = false;\n", "  var accessKnown = false;\n  var fab = document.createElement(\"button\"); fab.id = \"tmx-guide-fab\";\n"]],
  "tabbar-lift-back": [[TAB, "    \"html.bf-tabbar-on #bf-tabbar-spacer{display:block;", "    \"html.bf-tabbar-on #tmx-guide-fab{bottom:120px}\",\n    \"html.bf-tabbar-on #bf-tabbar-spacer{display:block;"]],
  "profile-shows-guide": [[SHELL, "\"#tmx-guide-root{display:none}\"", "\"#tmx-guide-fab{display:none}\""]],
  // E
  "guide-hidden-on-phone": [[GUIDE, "  #tmx-guide-root { flex-direction: row-reverse; align-items: center;", "  #tmx-guide-root { display: none; flex-direction: row-reverse; align-items: center;"]],
  "panel-wide": [[GUIDE, "width: min(300px, calc(100vw - 48px)); margin-left: 0;", "width: 300px; margin-left: 0;"]],
  "panel-over-bar": [[GUIDE, "    max-height: min(70vh, calc(100vh - 2 * (64px + env(safe-area-inset-bottom, 0px)))); }", "    max-height: 70vh; }"]],
  // F
  "chat-reset-shown": [[PRES, "    \"  #tmx-chat-reset { display: none !important; }\\n\" +\n", ""]],
  "chat-no-keyboard": [[PRES, "    window.visualViewport.addEventListener(\"resize\", tmxPhoneFit);\n", ""]],
  "chat-drags-on-phone": [[PRES, "  var TMX_CHAT_DRAG_MIN_W = 860;", "  var TMX_CHAT_DRAG_MIN_W = 320;"]],
  "closed-chat-drawn": [[PRES, "    \"  #tmx-chat:not(.tmx-chat-live), #tmx-chat:not(.tmx-chat-live)::before { visibility: hidden; animation-play-state: paused; }\\n\" +\n", ""]],
  "chat-never-live": [[PRES, "    chat.classList.add(\"tmx-chat-live\");   // FX3: drawn again on the phone before its opening starts\n", ""]],
  "close-keeps-live": [[PRES, "    chat.classList.remove(\"tmx-chat-live\");   // FX3: the close has ended; the phone stops drawing the box\n", ""]],
  "shoot-fixed-size": [[PRES, "    var CW = chat.clientWidth || 288, CH = chat.clientHeight || 340;", "    var CW = 288, CH = 340;"]],
  // G
  "free-opens-chat": [[PRES, "    if (tmxFree()) { tmxMembersPanel(); return; }\n    if (window.bfAccess && window.bfAccess.ready && !_tmxAccessKnown) {", "    if (window.bfAccess && window.bfAccess.ready && !_tmxAccessKnown) {"]],
  "free-asks-insights": [[GUIDE, "  function ensureInsight() {\n    if (guideFree()) return;\n", "  function ensureInsight() {\n"]],
  "free-sees-insights": [[GUIDE, "#tmx-guide-root.tmx-guide-free .tmx-guide-section--insights { display: none; }", "#tmx-guide-root.tmx-guide-free .tmx-guide-section--insights { display: block; }"]],
  // H
  "void-moves-reduced": [[PRES, "    \"  #tmx-chat, #tmx-chat::before, #tmx-chat-title-name.tmx-thinking { animation: none !important; }\\n\" +\n", ""]],
  "shoot-flies-reduced": [[PRES, "    if (!_chatOpen || tmxStill()) {", "    if (!_chatOpen) {"]],
  "ten-styles-reduced": [[PRES, "    _currentStyle = tmxStill() ? -1 : Math.floor(Math.random() * 10);", "    _currentStyle = Math.floor(Math.random() * 10);"]],
  "fade-slow": [[PRES, "tr: \"opacity 0.2s ease\", dur: 200 };", "tr: \"opacity 0.5s ease\", dur: 500 };"]],
  // I
  "mist-on-oracle": [[PRES, "\"oracle\", \"mychart\",", "\"mychart\","]],
  "preview-shows-guide": [[DESIGN, "#tmx-presence-root,#tmx-chat,#tmx-guide-root,.bfm-float{display:none!important}", "#tmx-presence-root,#tmx-chat,.bfm-float{display:none!important}"]]
};
const T = H.setup(__filename, MUTATIONS, [PRES, GUIDE, ABY, PHONE, TAB, SHELL, DESIGN, "sw.js", "dashboard.html"]);
const { FILES, check, J, has } = T;
const pres = FILES[PRES] || "", guide = FILES[GUIDE] || "", aby = FILES[ABY] || "", phoneCss = FILES[PHONE] || "";

function atRev(file) {
  try { return execFileSync("git", ["-C", H.FRONTEND, "show", BASE_REV + ":" + file], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).replace(/\r\n/g, "\n"); }
  catch (e) { return null; }
}
const noComments = t => String(t || "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
const norm = t => noComments(t).split("\n").map(l => l.replace(/\s+\/\/.*$/, "").replace(/^\s*\/\/.*$/, "").trim()).filter(Boolean);
function lineDiff(a, b) {
  const n = a.length, m = b.length, L = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = a[i] === b[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const removed = [], added = []; let i = 0, j = 0;
  while (i < n && j < m) { if (a[i] === b[j]) { i++; j++; } else if (L[i + 1][j] >= L[i][j + 1]) removed.push(a[i++]); else added.push(b[j++]); }
  while (i < n) removed.push(a[i++]); while (j < m) added.push(b[j++]);
  return { same: L[0][0], removed, added };
}
const numbers = lines => lines.join("\n").replace(/"[^"\n]*"/g, "").match(/\b\d+(?:\.\d+)?\b/g) || [];

/* ══ A ══ */
console.log("\n══ A. the engine moved unchanged ══");
const OLD_PRES = atRev(PRES);
const OLD_ENGINE = OLD_PRES ? OLD_PRES.split("\n").slice(892, 1144).join("\n") : null;
check("A1. the engine at " + BASE_REV + " is read (termaximus-presence.js lines 893-1144, createTmxStarfield to its end)",
  !!OLD_ENGINE && /^\s*\/\* ── Chat-box starfield engine/.test(OLD_ENGINE) && /function createTmxStarfield\(canvas\) \{/.test(OLD_ENGINE) && /return \{ start: start, stop: stop, resize: resize \};\n  \}\s*$/.test(OLD_ENGINE), OLD_ENGINE ? OLD_ENGINE.slice(-80) : "git show failed");
const D = OLD_ENGINE ? lineDiff(norm(OLD_ENGINE), norm(aby)) : { same: 0, removed: ["?"], added: ["?"] };
// the only lines of the old engine that changed (each named, with what replaced it)
const REMOVED_OK = [
  "function createTmxStarfield(canvas) {",                                              // -> function createAbyss(canvas, opts) {
  "if (!canvas) return { start: function () {}, stop: function () {} };",                // -> + resize: function () {}
  "if (!ctx) return { start: function () {}, stop: function () {} };",                   // -> + resize: function () {}
  "{ count: 70, minR: 0.4, maxR: 0.9, parallax: 0.15, offsetX: 0, offsetY: 0, stars: [] },",   // -> count: BASE_COUNTS[0]
  "{ count: 35, minR: 0.8, maxR: 1.6, parallax: 0.4,  offsetX: 0, offsetY: 0, stars: [] },",   // -> count: BASE_COUNTS[1]
  "{ count: 16, minR: 1.4, maxR: 2.6, parallax: 1.0,  offsetX: 0, offsetY: 0, stars: [] }",    // -> count: BASE_COUNTS[2]
  "return { start: start, stop: stop, resize: resize };"                                  // -> + info: info
];
const ADDED_OK = [
  "(function () {", "\"use strict\";", "if (window.BFAbyss) return;",
  "var BASE_W = 288, BASE_H = 340;", "var BASE_COUNTS = [70, 35, 16];",
  "function countsFor(w, h) {", "var ratio = (w * h) / (BASE_W * BASE_H);", "return BASE_COUNTS.map(function (c) { return Math.round(c * ratio); });", "}",
  "function createAbyss(canvas, opts) {", "opts = opts || {};", "var perArea = opts.perArea === true;",
  "if (!canvas) return { start: function () {}, stop: function () {}, resize: function () {} };",
  "if (!ctx) return { start: function () {}, stop: function () {}, resize: function () {} };",
  "if (perArea && LAYERS) populate();",
  "{ count: BASE_COUNTS[0], minR: 0.4, maxR: 0.9, parallax: 0.15, offsetX: 0, offsetY: 0, stars: [] },",
  "{ count: BASE_COUNTS[1], minR: 0.8, maxR: 1.6, parallax: 0.4,  offsetX: 0, offsetY: 0, stars: [] },",
  "{ count: BASE_COUNTS[2], minR: 1.4, maxR: 2.6, parallax: 1.0,  offsetX: 0, offsetY: 0, stars: [] }",
  "var populatedFor = \"\";", "function populate() {", "if (!canvas.clientWidth || !canvas.clientHeight) return;", "var key = cssWidth + \"x\" + cssHeight;",
  "if (key === populatedFor) return;", "populatedFor = key;", "var counts = countsFor(cssWidth, cssHeight);", "LAYERS.forEach(function (layer, i) {",
  "layer.count = counts[i];", "layer.stars = [];", "for (var j = 0; j < layer.count; j++) layer.stars.push(makeStar(layer.minR, layer.maxR));", "});", "}",
  "if (perArea) {", "populate();", "} else {", "}",
  "function info() {", "return {", "running: running, desired: desired, width: cssWidth, height: cssHeight, reducedMotion: reducedMotion,",
  "counts: LAYERS.map(function (l) { return l.stars.length; })", "};",
  "return { start: start, stop: stop, resize: resize, info: info };", "}",
  "window.BFAbyss = { create: createAbyss, countsFor: countsFor, BASE: { width: BASE_W, height: BASE_H, counts: BASE_COUNTS.slice() } };", "}());"
];
check("A2. bf-abyss.js holds the old engine line for line (comments aside): " + D.same + " lines the same, only the seven named lines changed",
  !!OLD_ENGINE && J(D.removed) === J(REMOVED_OK) && D.same === norm(OLD_ENGINE).length - REMOVED_OK.length, J(D.removed));
check("A3. and adds only the named lines (the module, BASE_COUNTS, countsFor, perArea's populate, info, window.BFAbyss)",
  !!OLD_ENGINE && J(D.added) === J(ADDED_OK), J(D.added.filter((x, k) => x !== ADDED_OK[k]).slice(0, 4)));
const oldNums = OLD_ENGINE ? numbers(norm(OLD_ENGINE).filter(l => REMOVED_OK.indexOf(l) === -1)) : [];
const newNums = numbers(norm(aby).filter(l => ADDED_OK.indexOf(l) === -1));
const countsNow = (/\n  var BASE_COUNTS = \[(\d+), (\d+), (\d+)\];/.exec(aby) || []).slice(1).map(Number);
check("A4. every number unchanged: the shared lines' " + oldNums.length + " numbers in order, and BASE_COUNTS is the old layers' 70, 35, 16 (288 x 340, the old box)",
  oldNums.length > 100 && J(oldNums) === J(newNums) && J(countsNow) === J([70, 35, 16]) && has(aby, "  var BASE_W = 288, BASE_H = 340;") &&
  !!OLD_ENGINE && ["count: 70,", "count: 35,", "count: 16,"].every(s => OLD_ENGINE.indexOf(s) !== -1), J([oldNums.length, newNums.length, countsNow]));
const presCode = noComments(pres);
check("A5. the presence keeps no copy (no makeStar, drawStarAt, drawStarWrapped or TINTS) and creates the chat's engine with no options (the chat's own counts)",
  !/function makeStar|function drawStarAt|function drawStarWrapped|var TINTS/.test(presCode) && has(pres, "      engine = window.BFAbyss.create(canvas);") &&
  (presCode.match(/BFAbyss\.create\(/g) || []).length === 1 && has(pres, "tag.src = \"/scripts/bf-abyss.js\";"));
check("A6. the dashboard loads bf-abyss.js and the shell caches it", has(FILES["dashboard.html"], "<script src=\"/scripts/bf-abyss.js\"></script>\n<script src=\"/scripts/bf-oracle-moon.js\"></script>\n<script src=\"/scripts/bf-hq-views.js\"></script>") &&
  has(FILES["sw.js"], "  \"/scripts/bf-abyss.js\",\n"));

/* ══ B ══ */
console.log("\n══ B. the density and the run rules (bf-abyss.js run) ══");
function world(opts) {
  opts = opts || {};
  const frames = []; let hidden = !!opts.hidden; const listeners = {};
  const ctxCalls = { fill: 0, log: [] };
  const ctx = new Proxy({}, { get: (o, k) => {
    if (k === "createRadialGradient" || k === "createLinearGradient") return () => ({ addColorStop() {} });
    if (k === "fill" || k === "arc" || k === "fillRect" || k === "drawImage") return function () { ctxCalls.fill++; ctxCalls.log.push(k + "(" + [].slice.call(arguments).map(a => typeof a === "number" ? a.toFixed(3) : typeof a).join(",") + ")"); };
    if (k in o) return o[k];
    return () => {};
  }, set: (o, k, v) => { o[k] = v; return true; } });
  const canvas = { clientWidth: opts.w || 288, clientHeight: opts.h || 340, width: 0, height: 0, style: {}, getContext: () => ctx,
    getBoundingClientRect() { return { width: this.clientWidth, height: this.clientHeight, left: 0, top: 0 }; } };
  const mk = () => ({ width: 0, height: 0, style: {}, getContext: () => ctx });
  const doc = { createElement: mk, get hidden() { return hidden; }, visibilityState: "visible", addEventListener: (t, f) => { (listeners[t] = listeners[t] || []).push(f); }, removeEventListener() {} };
  const win = { devicePixelRatio: 2, document: doc, addEventListener() {}, removeEventListener() {},
    matchMedia: q => ({ matches: /reduce/.test(q) && !!opts.reduced, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
    requestAnimationFrame: f => { frames.push(f); return frames.length; }, cancelAnimationFrame() {}, performance: { now: () => Date.now() } };
  win.window = win;
  const sandbox = Object.assign({}, win, { window: win, document: doc, Math, Date, performance: win.performance, requestAnimationFrame: win.requestAnimationFrame,
    cancelAnimationFrame: win.cancelAnimationFrame, matchMedia: win.matchMedia, setTimeout, clearTimeout, console });
  vm.createContext(sandbox);
  try { vm.runInContext(aby, sandbox, { filename: ABY }); } catch (e) { return { error: e.message }; }
  const A = win.BFAbyss || sandbox.BFAbyss;
  return { A, canvas, frames, ctxCalls, setHidden: v => { hidden = v; (listeners.visibilitychange || []).forEach(f => f()); } };
}
{
  const w1 = world({ w: 288, h: 340 });
  const chatEngine = w1.A && w1.A.create(w1.canvas);
  const i1 = chatEngine && chatEngine.info();
  check("B1. the chat's box (288 x 340, no options): 70, 35 and 16 stars", !!i1 && J(i1.counts) === J([70, 35, 16]), J(i1 || w1.error));
  const w2 = world({ w: 104, h: 104 });
  const disc = w2.A && w2.A.create(w2.canvas, { perArea: true });
  const i2 = disc && disc.info();
  check("B2. perArea on the board's 104 px disc: 8, 4 and 2 (round(count x 10816 / 97920)); countsFor(374, 420) is the chat's density too",
    !!i2 && J(i2.counts) === J([8, 4, 2]) && J(w2.A.countsFor(104, 104)) === J([8, 4, 2]) && J(w2.A.countsFor(374, 420)) === J([70, 35, 16].map(c => Math.round(c * 374 * 420 / 97920))), J(i2 || w2.error));
  w2.canvas.clientWidth = 120; w2.canvas.clientHeight = 120; disc.resize();
  check("B3. a new size re-counts the stars at the same density (120 px: " + J(w2.A.countsFor(120, 120)) + ")", J(disc.info().counts) === J(w2.A.countsFor(120, 120)), J(disc.info()));
  check("B4. nothing runs before start()", !disc.info().running && w2.frames.length === 0, J([disc.info(), w2.frames.length]));
  disc.start();
  const started = disc.info().running && w2.frames.length > 0;
  w2.setHidden(true); const whileHidden = disc.info().running;
  w2.setHidden(false); const back = disc.info().running;
  disc.stop(); const stopped = disc.info().running;
  check("B5. start() runs it; a hidden page pauses it and a visible one resumes it; stop() ends it", started && !whileHidden && back && !stopped, J([started, whileHidden, back, stopped]));
  const w3 = world({ w: 104, h: 104, reduced: true });
  const still = w3.A && w3.A.create(w3.canvas, { perArea: true });
  // the engine's own rule (unchanged from the chat's): under reduced motion its clock, drift and twinkle are frozen, so each frame
  // draws the same picture; two frames 5 s apart must draw exactly the same calls
  const drawAt = ms => { const fr = w3.frames.shift(); if (!fr) return null; w3.ctxCalls.log = []; fr(ms); return w3.ctxCalls.log.join(";"); };
  let f1 = null, f2 = null, f3 = null;
  if (still) { still.resize(); still.start(); f1 = drawAt(1000); f2 = drawAt(1016); f3 = drawAt(6016); }
  check("B6. under reduced motion it is drawn still: frames 5 s apart draw exactly the same stars (no drift, no twinkle)",
    !!still && still.info().reducedMotion === true && !!f2 && f2.length > 50 && f2 === f3, J(still ? [still.info(), f2 && f2.length, f3 && f3.length, f2 === f3] : w3.error));
  // and without reduced motion the same two frames differ (the drift and the twinkle run)
  const w4 = world({ w: 104, h: 104 }), live = w4.A && w4.A.create(w4.canvas, { perArea: true });
  const drawAt4 = ms => { const fr = w4.frames.shift(); if (!fr) return null; w4.ctxCalls.log = []; fr(ms); return w4.ctxCalls.log.join(";"); };
  let g2 = null, g3 = null; if (live) { live.resize(); live.start(); drawAt4(1000); g2 = drawAt4(1016); g3 = drawAt4(6016); }
  check("B7. with motion allowed the same frames differ (the drift runs), so B6 is a real test", !!g2 && !!g3 && g2 !== g3, J([g2 && g2.length, g3 && g3.length]));
}

/* ══ C ══ */
console.log("\n══ C. the mist on the phone ══");
const phoneBlock = (() => { const a = pres.indexOf("  var TMX_PHONE = "), b = pres.indexOf("\"}\\n\";", a); return a < 0 || b < 0 ? "" : pres.slice(a, b); })();
check("C1. 760 px and below: fixed 56 px (the 110 px mist scaled from its bottom-right), 16 px from the right, 16 px above the bar and the safe area, no translate",
  has(pres, "  var TMX_PHONE_QUERY = \"(max-width: 760px)\";") && has(pres, "  var TMX_PHONE_MIST = 56, TMX_DESK_MIST = 110;") &&
  has(phoneBlock, "right: 16px !important; bottom: calc(16px + env(safe-area-inset-bottom, 0px)) !important;") &&
  has(phoneBlock, "html.bf-tabbar-on #tmx-presence-root { bottom: calc(56px + 16px + env(safe-area-inset-bottom, 0px)) !important; }") &&
  has(phoneBlock, "translate: none !important; transform: scale(\" + (TMX_PHONE_MIST / TMX_DESK_MIST).toFixed(7) + \"); transform-origin: 100% 100%;") &&
  has(pres, "].join(\"\\n\") + MIST_STILL + TMX_PHONE;"), J(phoneBlock.slice(0, 300)));
check("C2. z-index 46: over the page (Home's full-screen feed is 40 to 45), under the sheets (50 and up), the members panel (1000) and the chat",
  has(phoneBlock, "    z-index: 46; pointer-events: auto;"));
check("C3. a button: role button, \"Ask Termaximus\", a tab stop, Enter and Space open it, a visible focus ring",
  has(pres, "  root.setAttribute(\"role\", \"button\");\n") && has(pres, "  root.setAttribute(\"aria-label\", \"Ask Termaximus\");") && has(pres, "  root.setAttribute(\"tabindex\", \"0\");") &&
  has(pres, "    if (e.target !== root || (e.key !== \"Enter\" && e.key !== \" \")) return;") && has(pres, "    root.click();") && has(phoneBlock, "#tmx-presence-root:focus-visible { outline:"));
check("C4. on the phone the saved spot, dragging and keep-clear do not apply (the corner rule is overridden by the fixed place)",
  has(pres, "    if (tmxPhone()) return;   // NAMED (Nov 22 2026, FX3): the phone's mist keeps its place") &&
  has(pres, "    if (tmxPhone()) { _tmxDragMoved = false; return; }   // NAMED (Nov 22 2026, FX3): no dragging on the phone") &&
  has(pres, "    if (tmxPhone()) { if (root.style.translate) root.style.translate = \"\"; return; }") &&
  has(phoneBlock, "top: auto !important; left: auto !important;"));
check("C5. css/bf-phone.css no longer sends the mist under the page or blocks its stars' taps (its line 67 and the .tmx-star rule gone)",
  !/#tmx-presence-root|\.tmx-star/.test(noComments(phoneCss)));
check("C6. the whisper keeps its size and ends at the mist's right edge (inside the screen)", has(phoneBlock, "  #tmx-whisper { left: auto; right: 0; transform: scale(\" + (TMX_DESK_MIST / TMX_PHONE_MIST).toFixed(7) + \"); transform-origin: 100% 50%; }"));

/* ══ D ══ */
console.log("\n══ D. the book button gone ══");
const guideCode = noComments(guide);
check("D1. termaximus-guide.js has no book button, no sheet, no restFab", !/tmx-guide-fab|tmx-guide-sheet|restFab|placeFab/.test(guideCode));
check("D2. bf-tabbar.js lifts nothing for it and bf-phone.css holds no rule for it", !/tmx-guide-fab/.test(noComments(FILES[TAB])) && !/tmx-guide-fab/.test(noComments(phoneCss)));
check("D3. the phone profile hides the Guide's tab instead (as it hid the book button), and no file names the book button in code",
  has(FILES[SHELL], "\"#tmx-guide-root{display:none}\"") && !/tmx-guide-fab/.test(noComments(FILES[SHELL])));

/* ══ E ══ */
console.log("\n══ E. the Guide at every width ══");
const media = [...guideCode.matchAll(/"@media[^"]*\{",([\s\S]*?)\n    "\}",?/g)].map(m => m[1]);
check("E1. no width hides the Guide's tab (no display:none for #tmx-guide-root or #tmx-guide-tab in any media rule)",
  media.length >= 1 && media.every(b => !/#tmx-guide-(root|tab)[^{]*\{[^}]*display:\s*none/.test(b)), J(media.map(b => b.slice(0, 120))));
check("E2. the tab is the desktop's at every width: 32 px wide, 170 px or taller, at the left edge, in the middle",
  has(guide, "    \"  width: 32px;\",\n    \"  min-height: 170px;\",") && has(guide, "    \"#tmx-guide-root {\",\n    \"  position: fixed;\",\n    \"  top: 50%;\",\n    \"  left: 0;\",\n    \"  transform: translateY(-50%);\","));
check("E3. on the phone the panel opens from the left with the tab at its right edge: min(300px, 100vw - 48px), at most 70vh and clear of the bar, 0.3 s together",
  has(guide, "  #tmx-guide-root { flex-direction: row-reverse; align-items: center;") &&
  has(guide, "    transform: translate(calc(-1 * min(300px, 100vw - 48px)), -50%); transition: transform 0.3s ease; }") &&
  has(guide, "  #tmx-guide-root.tmx-guide-open { transform: translate(0, -50%); }") &&
  has(guide, "width: min(300px, calc(100vw - 48px)); margin-left: 0;") && has(guide, "    max-height: min(70vh, calc(100vh - 2 * (64px + env(safe-area-inset-bottom, 0px)))); }") &&
  has(guide, "    \"  overflow-y: auto;\","));
check("E4. it closes on an outside tap, Escape and the tab", /document\.addEventListener\("(pointerdown|click|mousedown|touchstart)"/.test(guideCode) && /"Escape"/.test(guideCode) && /tab\.addEventListener\("click"/.test(guideCode));

/* ══ F ══ */
console.log("\n══ F. the chat on the phone ══");
check("F1. 8 px from each side, its bottom 10 px above the mist, at most 420 px tall (the visible viewport less the top safe area and 16 px)",
  has(phoneBlock, "  #tmx-chat, #tmx-chat-glow-wrap { top: auto !important; left: 8px !important; right: 8px !important; width: auto !important;") &&
  has(phoneBlock, "height: var(--tmx-chat-h, min(420px, calc(100vh - env(safe-area-inset-top, 0px) - 16px))) !important;") &&
  has(pres, "    var bottom = Math.max(0, layoutH - mistTop) + 10;") && has(pres, "    var height = Math.min(420, visH - safeTop - 16,"));
check("F2. the keyboard: the visual viewport's resize and scroll refit it (above the keyboard, the input in view), and opening fits it",
  has(pres, "    window.visualViewport.addEventListener(\"resize\", tmxPhoneFit);\n") && has(pres, "    window.visualViewport.addEventListener(\"scroll\", tmxPhoneFit);") &&
  has(pres, "    if (keyboard > 0 && keyboard + 8 > bottom) bottom = keyboard + 8;") && has(pres, "    _chatOpen = true;\n    chat.classList.add(\"tmx-chat-live\");   // FX3: drawn again on the phone before its opening starts\n    tmxPhoneFit();"));
check("F3. Reset hidden and no dragging at 760 px and below (dragging needs more than 860 px)", has(phoneBlock, "  #tmx-chat-reset { display: none !important; }") &&
  has(pres, "  var TMX_CHAT_DRAG_MIN_W = 860;") && has(pres, "    return window.innerWidth > TMX_CHAT_DRAG_MIN_W;"));
// NAMED (Nov 22 2026, FX3): F5 added. The closed chat (opacity 0, its 24 px blur and two animations) spans the phone over the
// turning orbit; drawing it every frame stalled the browser's frames (the orbit's settle with it), so the phone hides it once
// its close has ended. Desktop is untouched (the rule is inside the 760 px block).
check("F5. on the phone the closed chat is not drawn (hidden and its animations paused until openChat marks it live; the end of every close clears the mark)",
  has(phoneBlock, "  #tmx-chat:not(.tmx-chat-live), #tmx-chat:not(.tmx-chat-live)::before { visibility: hidden; animation-play-state: paused; }\\n\" +\n") &&
  has(pres, "  function _clearFX() {\n    chat.classList.remove(\"tmx-chat-live\");") && (presCode.match(/tmx-chat-live/g) || []).length === 4 &&
  presCode.indexOf("chat.classList.add(\"tmx-chat-live\")") > presCode.indexOf("function openChat()") && presCode.indexOf("chat.classList.add(\"tmx-chat-live\")") < presCode.indexOf("function closeChat()") &&
  (presCode.match(/_clearFX\(\)/g) || []).length === 3);   // its definition and the two ends of a close
check("F4. the shooting star flies across the box's real size (288 x 340 only when it has none)", has(pres, "    var CW = chat.clientWidth || 288, CH = chat.clientHeight || 340;") && !/var CW = 288/.test(presCode));

/* ══ G ══ */
console.log("\n══ G. a free account ══");
check("G1. the mist opens the members panel, never the chat (and waits for the tier when it is not known yet)",
  has(pres, "  function openChat() {\n    if (tmxFree()) { tmxMembersPanel(); return; }\n    if (window.bfAccess && window.bfAccess.ready && !_tmxAccessKnown) {") &&
  has(pres, "        if (tmxFree()) { tmxMembersPanel(); return; }") && has(pres, "    if (window.bfAccess && typeof window.bfAccess.showPanel === \"function\") window.bfAccess.showPanel();"));
check("G2. the Guide: tips only, no Insights section and no /api/insights/page request",
  has(guide, "  function ensureInsight() {\n    if (guideFree()) return;\n") && has(guide, "#tmx-guide-root.tmx-guide-free .tmx-guide-section--insights { display: none; }") &&
  has(guide, "    root.classList.add(\"tmx-guide-free\");") && guideCode.indexOf("/api/insights/page") > guideCode.indexOf("  function ensureInsight() {"));

/* ══ H ══ */
console.log("\n══ H. reduced motion ══");
check("H1. the void, the gold rim (::before) and the thinking title still; the shooting star hidden and its timer draws nothing",
  has(pres, "    \"  #tmx-chat, #tmx-chat::before, #tmx-chat-title-name.tmx-thinking { animation: none !important; }\\n\" +\n") &&
  has(pres, "    \"  #tmx-chat-shoot { animation: none !important; opacity: 0 !important; }\\n\" +") && has(pres, "    if (!_chatOpen || tmxStill()) {"));
check("H2. the ten open and close transitions become one plain 0.2 s fade (openChat and closeChat both use it)",
  has(pres, "    _currentStyle = tmxStill() ? -1 : Math.floor(Math.random() * 10);") && has(pres, "tr: \"opacity 0.2s ease\", dur: 200 };") &&
  (presCode.match(/tmxFx\(\)/g) || []).length >= 3);

/* ══ I ══ */
console.log("\n══ I. where they stay hidden ══");
const oldGuide = atRev(GUIDE);
const line = (t, s) => (String(t || "").split("\n").filter(l => l.indexOf(s) !== -1)[0]) || null;
check("I1. TMX_NO_MIST_PAGES and the presence's skip as at " + BASE_REV, !!OLD_PRES && line(pres, "  var TMX_NO_MIST_PAGES = ") === line(OLD_PRES, "  var TMX_NO_MIST_PAGES = ") &&
  line(pres, "    var _tmxSkip  = ") === line(OLD_PRES, "    var _tmxSkip  = ") && !!line(pres, "  var TMX_NO_MIST_PAGES = "));
check("I2. the Guide signed out as at " + BASE_REV + " (no token: no Guide)", !!oldGuide && line(guide, "!localStorage.getItem(\"bf_token\")) return;") === line(oldGuide, "!localStorage.getItem(\"bf_token\")) return;") && !!line(guide, "!localStorage.getItem(\"bf_token\")) return;"));
check("I3. the profile preview hides the mist, the chat and the Guide", has(FILES[DESIGN], "#tmx-presence-root,#tmx-chat,#tmx-guide-root,.bfm-float{display:none!important}"));
T.finish();
