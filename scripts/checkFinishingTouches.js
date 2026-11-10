/* scripts/checkFinishingTouches.js — the owner's five finishing touches of Nov 8 2026, in the frontend:

   ══ What it proves ══════════════════════════════════════════════════════════
     V  THE MUSIC VISUAL IN "KEEP PLAYING BETWEEN PAGES" MODE (scripts/bf-music.js), in jsdom with a fake
        Web Audio, a fake BroadcastChannel and a fake API: the music plays in the pop-out while the page's
        own audio is paused, and the page's boombox display (its 48 spectrum bars, and its waveform) and
        speakers move with the frames the pop-out sends, about 30 a second, numbers only; they keep moving
        across a track change, a volume change and a page change; they go still when the pop-out pauses,
        and the pop-out sends nothing but one silent frame then. Under prefers-reduced-motion nothing is
        sent and the display is a still meter.
     I  THE MUSIC BUTTON (scripts/bf-boombox.js): one icon source, MUSIC_ICON, "the golden note" (Nov 9
        2026): a golden-ratio spiral as the note head, under a soft glow, with a music stem and flag; no
        colour in its markup; its CSS strokes the stem currentColor (the primary accent) and the spiral and
        glow the theme violet, var(--bf-accent-b, #a855f7), and no other colour; used on the dashboard and as the floating icon
        on other pages; the button is the header's round control (40 px, 50%, the accent border, a visible
        focus ring), named aria-label and title "Music player"; hover and focus fade a ring and the glow in
        by opacity only; while music plays the glow pulses (an opacity keyframe), the spiral lightens and a
        second ring shows; under reduced motion the glow is steady, and while hidden the pulse is paused;
        neither the two-circle boombox icon nor the note-and-wave icon is left.
        NAMED BEFORE → AFTER (Nov 9 2026, golden note icon): BEFORE, the note-and-wave icon whose wave
        drifted (bfm-note-wave), and a hover that switched the border at once.
     P  THE PLACEMENT: centred between the logo's right edge and the header's horizontal centre, level with
        the logo; narrower, never closer than 24 px to the logo and never over another header item.
        NAMED BEFORE → AFTER (Nov 9 2026, button kept in the top bar). BEFORE: with no room on the header's row
        it sat just below the header, under the logo. AFTER: the button is a child of the top bar's own element
        on every top-bar page (the dashboard; any page where it is pinned), level with the logo's centre (2 px),
        at the midpoint, at least 24 px from the logo, over no item, 32 px as the last resort, and measured
        again after the fonts, the load and any late header item; at 1920, 1440, 1280, 1024, 768 and 390 px in a
        mocked layout. Follow me on other pages keeps the floating icon.
     M  THE MIST (scripts/termaximus-presence.js): TMX_NO_MIST_PAGES is exactly the sign-in pages and the
        Oracle pages, and the mist shows on every other signed-in page (a sample), never logged out.
     O  THE ORACLE BACKGROUNDS: on oracle.html, mychart.html, synastry.html and the-third.html the
        bottom-right glow is 0 even under a member's theme, and the top-left glow is exactly what it was;
        no other page changes, and the base colour is untouched.

   MUTATE=<name> edits the frontend files IN MEMORY; MUTATE=all runs each in its own process.
   BIZFORCE_FRONTEND_DIR overrides the frontend location. No network (a tripwire), no database. */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const net = require("net");
const dns = require("dns");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkFinishingTouches: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkFinishingTouches: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const MUSIC = "scripts/bf-music.js", BOOMBOX = "scripts/bf-boombox.js", THEME = "scripts/bf-theme.js", PRESENCE = "scripts/termaximus-presence.js";
const UI = "css/bizforce-ui.css", DASH = "dashboard.html";
const ORACLE_PAGES = ["oracle.html", "mychart.html", "synastry.html", "the-third.html"];
const SIGN_IN_PAGES = ["index.html", "app.html", "reset-password.html", "verify-email.html"];
/* The frontend commit before these touches: the pages are compared with it line by line. */
const BEFORE = "82fc396";
/* The commit that put the mist's tag on the Oracle pages (for the boombox) and so brought the mist back to them. */
const REGRESSION = "ce8c338";

const MUTATIONS = {
  // the page's display reads its own paused audio, not the pop-out's frames
  "visual-reads-paused-element": [[MUSIC, "    var fromPopout = popoutAlive();\n", "    var fromPopout = false;\n"]],
  // the pop-out measures its frames and never sends them
  "frames-not-sent": [[MUSIC, "      post(levelsFrame());\n", "      levelsFrame();\n"]],
  // the pop-out keeps sending live frames while paused
  "frames-sent-when-paused": [[MUSIC, "      if (!R.playing) { post({ type: \"levels\", from: ID,", "      if (false) { post({ type: \"levels\", from: ID,"]],
  /* NAMED BEFORE → AFTER (Nov 9 2026, golden note icon). BEFORE: old-icon-restored put two circles in place of the
     note head, icon-hardcoded-color gave the svg a hex stroke, reduced-motion-ignored dropped the wave's still rule.
     AFTER: the golden note's own mutations below; icon-label-missing and placement-too-close are unchanged. */
  // the note-and-wave icon comes back in place of the golden note (its head, its wave and their clip)
  "old-icon-restored": [[BOOMBOX, "      '<g class=\"bfm-gn-spiral\" transform=\"translate(3 13.3) scale(.16)\" stroke-width=\"10\"><path d=\"M0 55 A55 55 0 0 1 55 0 A34 34 0 0 1 89 34 A21 21 0 0 1 68 55 A13 13 0 0 1 55 42 A8 8 0 0 1 63 34\"/></g>' +\n",
    "      '<defs><clipPath id=\"bfmNoteWaveClip\"><rect x=\"2\" y=\"15\" width=\"20\" height=\"8\"/></clipPath></defs>' +\n" +
    "      '<ellipse class=\"bfm-note-head\" cx=\"7.6\" cy=\"15\" rx=\"2.6\" ry=\"1.9\" transform=\"rotate(-22 7.6 15)\" fill=\"currentColor\" stroke=\"none\"/>' +\n" +
    "      '<g clip-path=\"url(#bfmNoteWaveClip)\"><path class=\"bfm-note-wave\" d=\"M-4 19c1.5 0 1.5-2 3-2s1.5 2 3 2 1.5-2 3-2 1.5 2 3 2\"/></g>' +\n"]],
  // the spiral's arcs are no longer the golden-ratio radii
  "spiral-path-changed": [[BOOMBOX, "stroke-width=\"10\"><path d=\"M0 55 A55 55 0 0 1 55 0 A34 34 0 0 1 89 34", "stroke-width=\"10\"><path d=\"M0 55 A55 55 0 0 1 55 0 A30 30 0 0 1 85 30"]],
  // the stem is shortened
  "stem-path-changed": [[BOOMBOX, "d=\"M17.24 18.74V2.6c1.6 1", "d=\"M17.24 18.74V5.6c1.6 1"]],
  // the icon is drawn in a fixed colour, not the theme's
  "icon-hex-color": [[BOOMBOX, "<path class=\"bfm-gn-stem\" d=", "<path class=\"bfm-gn-stem\" stroke=\"#d4af37\" d="]],
  // the glow switches on at once on hover, with no fade
  "hover-not-faded": [[BOOMBOX, "\".bfm-gn-glow{opacity:0;transition:opacity 200ms}\"", "\".bfm-gn-glow{opacity:0}\""]],
  // while music plays the glow holds still
  "glow-not-pulsing": [[BOOMBOX, ".bfm-gn-glow{animation:bfm-gn-pulse 2.4s ease-in-out infinite}", ".bfm-gn-glow{opacity:.3}"]],
  // the glow keeps pulsing under prefers-reduced-motion
  "reduced-motion-pulses": [[BOOMBOX, "@media (prefers-reduced-motion: reduce){.bfm-gn-glow{animation:none!important}", "@media (prefers-reduced-motion: reduce){"]],
  // the glow keeps pulsing while the tab is hidden
  "hidden-still-pulses": [[BOOMBOX, "    \".bfm[data-hidden=true] .bfm-gn-glow{animation-play-state:paused}\",\n", ""]],
  // the keyboard focus ring is gone
  "focus-ring-removed": [[BOOMBOX, "    \".bfm-icon:focus-visible{outline:2px solid var(--bf-accent-a, #22d3ee);outline-offset:2px}\",\n", ""]],
  /* NAMED (Nov 9 2026, violet spiral per the approved design): the two-tone golden note's own mutations. */
  // the spiral and its glow go back to the primary accent
  "spiral-not-violet": [[BOOMBOX, "\".bfm-gn-spiral,.bfm-gn-glow{stroke:var(--bf-accent-b, #a855f7)}\"", "\".bfm-gn-spiral,.bfm-gn-glow{stroke:currentColor}\""]],
  // the stem takes the violet
  "stem-violet": [[BOOMBOX, "\".bfm-gn-stem{stroke:currentColor}\"", "\".bfm-gn-stem{stroke:var(--bf-accent-b, #a855f7)}\""]],
  // a stray hex colour is added to the icon's CSS, in a rule of its own
  "stray-hex": [[BOOMBOX, "    \".bfm-gn-stem{stroke:currentColor}\",\n", "    \".bfm-gn-stem{stroke:currentColor}\",\n    \".bfm-icon:hover .bfm-gn-stem{stroke:#ffd700}\",\n"]],
  // a stroke colour is written into the svg markup itself
  "svg-inline-color": [[BOOMBOX, "<g class=\"bfm-gn-spiral\" transform=", "<g class=\"bfm-gn-spiral\" stroke=\"#a855f7\" transform="]],
  // the button loses its name
  "icon-label-missing": [[BOOMBOX, "data-act=\"bbx-open\" aria-label=\"Music player\" title=\"Music player\">", "data-act=\"bbx-open\">"]],
  // the button creeps back toward the logo
  "placement-too-close": [[BOOMBOX, "  var ICON_MIN_GAP = 24;", "  var ICON_MIN_GAP = 4;"]],
  /* NAMED (Nov 9 2026, button kept in the top bar): the button's own mutations. */
  // the drop-below-the-header fallback comes back for a crowded row
  "dropped-below-header": [[BOOMBOX, "    var left = side === \"right\" ? edge + gap : edge - gap - size;\n",
    "    if (size === ICON_SMALL) return { side: side, size: ICON_W, gap: 0, left: Math.round(logo.left), top: Math.round((wide ? bar.bottom : logo.bottom) + GAP) };\n    var left = side === \"right\" ? edge + gap : edge - gap - size;\n"]],
  // the button is mounted in the page, not in the bar
  "mounted-outside-bar": [[BOOMBOX, "      if (root.parentNode !== bar) bar.appendChild(root);", "      if (root.parentNode !== doc.body) doc.body.appendChild(root);"]],
  // it is centred on the bar's middle, not the logo's
  "not-vertically-centred": [[BOOMBOX, "top: Math.round(cy - size / 2) };", "top: Math.round((wide ? (bar.top + bar.bottom) / 2 : cy) - size / 2) };"]],
  // a third of the way to the centre, not halfway
  "midpoint-wrong": [[BOOMBOX, "var want = (side === \"right\" ? centre - edge : edge - centre) / 2;", "var want = (side === \"right\" ? centre - edge : edge - centre) / 3;"]],
  // at the last resort the 24 px minimum is no longer held
  "min-gap-broken": [[BOOMBOX, "gap = Math.max(ICON_MIN_GAP, Math.min(want - ICON_SMALL / 2, room - ICON_SMALL)); }", "gap = Math.min(want - ICON_SMALL / 2, room - ICON_SMALL); }"]],
  // on a narrow window the button leaves the bar
  "leaves-bar-when-narrow": [[BOOMBOX, "pinned() && !away() && !!barOf(); }", "pinned() && !away() && !!barOf() && window.innerWidth > PHONE_MAX; }"]],
  // measured once: no second look after the fonts, the load or a late header item
  "measured-before-load": [[BOOMBOX, "    if (!popout) watchBar();\n", ""]],
  // the mist comes back to the Oracle
  "mist-on-oracle": [[PRESENCE, "\"verify-email\", \"oracle\", \"mychart\"", "\"verify-email\", \"mychart\""]],
  // the mist shows on the sign-in page
  "mist-on-login": [[PRESENCE, "[\"index\", \"app\", \"reset-password\"", "[\"index\", \"reset-password\""]],
  // the mist is taken off an ordinary page too
  "mist-missing-elsewhere": [[PRESENCE, "\"synastry\", \"the-third\"];", "\"synastry\", \"the-third\", \"crm\"];"]],
  // the bottom-right glow returns on the Oracle page
  "bottom-right-glow-back": [["oracle.html", "    :root { --bf-glow-b-alpha: 0 !important; }\n", ""]],
  // the top-left glow is put out too
  "top-left-glow-removed": [["oracle.html", "    :root { --bf-glow-b-alpha: 0 !important; }\n", "    :root { --bf-glow-a-alpha: 0 !important; --bf-glow-b-alpha: 0 !important; }\n"]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
const read = rel => { const p = path.join(FRONTEND, rel); FILES[rel] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null; };
[MUSIC, BOOMBOX, THEME, PRESENCE, UI, DASH, "music-popout.html"].concat(ORACLE_PAGES, SIGN_IN_PAGES).forEach(read);
if (FILES[MUSIC] === null) { console.log("    FAIL  frontend not found at " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
function gitShow(rev, rel) {
  try { return lf(execFileSync("git", ["-C", FRONTEND, "show", rev + ":" + rel], { encoding: "utf8", maxBuffer: 32 << 20 })); }
  catch (e) { return null; }
}
const wait = ms => new Promise(r => setTimeout(r, ms));

let JSDOM, VirtualConsole;
try { ({ JSDOM, VirtualConsole } = require("jsdom")); } catch (e) { JSDOM = null; }

/* ════ the harness: a fake channel, a fake Web Audio, a fake API ════ */
const BUS = { chans: [], pending: 0, log: [] };
class FakeBC {
  constructor(name) { this.name = name; this.onmessage = null; this.closed = false; BUS.chans.push(this); }
  postMessage(m) {
    const data = JSON.stringify(m);
    if (this.win && this.win.__closed) return;
    BUS.log.push({ at: Date.now(), m: JSON.parse(data), from: this.win && this.win.__name });
    BUS.chans.filter(c => c !== this && c.name === this.name && !c.closed && !(c.win && c.win.__closed)).forEach(c => {
      BUS.pending++;
      setTimeout(() => { BUS.pending--; if (!c.closed && c.onmessage) { try { c.onmessage({ data: JSON.parse(data) }); } catch (e) { /* the page's own error */ } } }, 0);
    });
  }
  close() { this.closed = true; }
}
const settle = async () => { for (let i = 0; i < 40; i++) { await wait(5); if (!BUS.pending) { await wait(2); if (!BUS.pending) return; } } };
/* SOUND.level (0 … 255) drives the frequency bins and SOUND.wave (0 … 1) the main analyser's waveform, a sine. */
const SOUND = { level: 0, wave: 0 };
const node = extra => Object.assign({ out: [], connect(dst) { this.out.push(dst); return dst; } }, extra);
class FakeAudioContext {
  constructor() { this.sampleRate = 48000; this.state = "running"; this.destination = node({}); this.t = 0; }
  get currentTime() { return this.t; }
  createGain() { return node({ gain: { value: 1, setValueAtTime() {}, linearRampToValueAtTime() {}, setValueCurveAtTime() {}, cancelScheduledValues() {} } }); }
  createAnalyser() {
    return node({ fftSize: 2048, get frequencyBinCount() { return this.fftSize / 2; }, smoothingTimeConstant: 0,
      getByteFrequencyData(a) { for (let i = 0; i < a.length; i++) a[i] = i < 8 ? SOUND.level : Math.round(SOUND.level / 3); },
      getByteTimeDomainData(a) { for (let i = 0; i < a.length; i++) a[i] = Math.round(128 + 120 * SOUND.wave * Math.sin(i / 20)); } });
  }
  createMediaElementSource(el) { return node({ el }); }
  resume() { return Promise.resolve(); }
}
function fakeAudio() {
  return class FakeAudio {
    constructor() { this.paused = true; this.currentTime = 0; this.duration = 200; this.src = ""; this.volume = 1; this.listeners = {}; }
    addEventListener(n, f) { (this.listeners[n] = this.listeners[n] || []).push(f); }
    removeEventListener() {}
    play() { this.paused = false; return Promise.resolve(); }
    pause() { this.paused = true; }
    load() {}
    removeAttribute(k) { if (k === "src") this.src = ""; }
  };
}
const UID = "aaaaaaaa-0000-4000-8000-000000000001";
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
const TOKEN = "x." + Buffer.from(JSON.stringify({ id: UID })).toString("base64").replace(/=+$/, "") + ".y";
const T1 = "11111111-0000-4000-8000-000000000001", T2 = "11111111-0000-4000-8000-000000000002";
const LIBRARY = { tracks: [{ id: T1, title: "One", artist: "A", duration: 200 }, { id: T2, title: "Two", artist: "B", duration: 200 }], playlists: [], used_bytes: 0, cap_bytes: 1 << 28, file_max_bytes: 1 << 25 };
function fakeFetch(u, opts) {
  const url = new URL(String(u)), method = ((opts && opts.method) || "GET").toUpperCase();
  const reply = (status, body) => Promise.resolve({ ok: status < 400, status, json: async () => body });
  if (url.origin !== API) return reply(404, {});
  if (method === "GET" && url.pathname === "/api/music") return reply(200, LIBRARY);
  const m = /^\/api\/music\/tracks\/([^/]+)\/url$/.exec(url.pathname);
  if (m) return reply(200, { url: "https://files.example.invalid/object/sign/bf-music/" + m[1] + "?token=t", expires_at: new Date(Date.now() + 3600e3).toISOString() });
  if (url.pathname === "/api/music/player") return reply(200, method === "GET" ? { saved: false } : { ok: true });
  return reply(404, {});
}
/* A layout stub: an element's box is its data-rect ("left,top,width,height"); the player's root is its own size at
   the place it was put. Everything else has no box. */
function layoutStub(win, width) {
  const HE = win.HTMLElement.prototype;
  const rectAttr = el => { const v = el.getAttribute && el.getAttribute("data-rect"); if (!v) return null; const [l, t, w, h] = v.split(",").map(Number); return { l, t, w, h }; };
  const own = el => {
    /* NAMED (Nov 9 2026, button kept in the top bar): the button's last-resort size, 32 px, is its box too. */
    if (el.classList && el.classList.contains("bfm-float")) { const st = el.getAttribute("data-state"), sm = el.getAttribute("data-icon-size") === "small"; return st === "box" ? { w: 440, h: 250 } : st === "icon" ? (sm ? { w: 32, h: 32 } : { w: 40, h: 40 }) : { w: 300, h: 40 }; }
    const r = rectAttr(el); return r ? { w: r.w, h: r.h } : { w: 0, h: 0 };
  };
  Object.defineProperty(HE, "offsetWidth", { configurable: true, get() { return own(this).w; } });
  Object.defineProperty(HE, "offsetHeight", { configurable: true, get() { return own(this).h; } });
  HE.getBoundingClientRect = function () {
    const r = rectAttr(this);
    if (r) return { left: r.l, top: r.t, right: r.l + r.w, bottom: r.t + r.h, width: r.w, height: r.h, x: r.l, y: r.t };
    const z = own(this), l = parseFloat(this.style.left), t = parseFloat(this.style.top);
    let left = isNaN(l) ? 0 : l, top = isNaN(t) ? 0 : t;
    /* NAMED (Nov 9 2026, button kept in the top bar): inside the bar the root is placed in the bar's own coordinates */
    if (this.getAttribute("data-inbar") === "true" && this.parentElement) { const pb = this.parentElement.getBoundingClientRect(); left += pb.left; top += pb.top; }
    return { left, top, right: left + z.w, bottom: top + z.h, width: z.w, height: z.h, x: left, y: top };
  };
  Object.defineProperty(win, "innerWidth", { configurable: true, get: () => width });
  Object.defineProperty(win, "innerHeight", { configurable: true, get: () => 800 });
}
/* A 2D context that records what the display draws: the bars' heights and the waveform's points. */
function recorder(win) {
  return function () {
    const g = {
      cur: [], ys: [],
      clearRect() { this.cur = []; win.__draws = (win.__draws || 0) + 1; },
      fillRect(x, y, w, h) { this.cur.push(h); win.__bars = this.cur; },
      createLinearGradient() { return { addColorStop() {} }; },
      beginPath() { this.ys = []; }, moveTo(x, y) { this.ys.push(y); }, lineTo(x, y) { this.ys.push(y); },
      stroke() { win.__wave = this.ys.slice(); }
    };
    return g;
  };
}
const WINS = [];
const MIST_TAG = '<script src="/scripts/termaximus-presence.js"></script>';
const HEADER = '<header class="topbar" data-rect="0,0,1280,68"><div class="topbar-brand" data-bf-boombox-anchor data-rect="24,14,166,40">BizForce AI</div>' +
  '<div class="topbar-actions"><a href="agents-hub.html" data-rect="900,16,90,36">Agents</a><a href="oracle.html" data-rect="1000,11,46,46">Oracle</a>' +
  '<label data-rect="1060,20,120,28">Termaximus</label><div class="topbar-user" data-rect="1190,14,66,40">BF</div></div></header>';
async function openPage(o) {
  const page = o.popout ? "music-popout.html" : o.page || "dashboard.html";
  const body = o.popout ? '<div id="bfMusicPopout"></div>' : (o.header || (page === "dashboard.html" ? HEADER : "")) + "<main>page</main>" + MIST_TAG;
  const html = "<!DOCTYPE html><html><head><script>" + FILES[THEME] + "</script></head><body>" + body +
    "<script>" + FILES[BOOMBOX] + "</script><script>" + FILES[MUSIC] + "</script></body></html>";
  const raf = [];
  let w;
  const dom = new JSDOM(html, {
    url: "https://bizforceai.net/" + page, runScripts: "dangerously", pretendToBeVisual: true, virtualConsole: new VirtualConsole(),
    beforeParse(win) {
      w = win; win.__name = o.name || page;
      layoutStub(win, o.width || 1280);
      win.localStorage.setItem("bf_token", TOKEN);
      if (o.store) win.localStorage.setItem("bf_music", JSON.stringify(o.store));
      if (o.boombox) win.localStorage.setItem("bf_boombox", JSON.stringify(o.boombox));
      if (o.fonts) win.document.fonts = { ready: o.fonts };
      if (o.live) win.sessionStorage.setItem("bf_music_live", UID);
      win.matchMedia = q => ({ matches: !!o.reduce && /prefers-reduced-motion: reduce/.test(q), media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
      win.Audio = fakeAudio();
      win.AudioContext = FakeAudioContext;
      win.BroadcastChannel = class extends FakeBC { constructor(n) { super(n); this.win = win; } };
      win.requestAnimationFrame = f => { raf.push(f); return raf.length; };
      win.cancelAnimationFrame = () => {};
      win.HTMLCanvasElement.prototype.getContext = recorder(win);
      win.open = () => ({ closed: false });
      win.fetch = (u, opts) => { const p = fakeFetch(u, opts); p.catch(() => {}); return p; };
    }
  });
  w.__raf = raf; w.__dom = dom;
  WINS.push(w);
  await settle();
  return w;
}
function frames(w, n) { for (let i = 0; i < n; i++) { const list = w.__raf.splice(0); list.forEach(f => f((w.__ft = (w.__ft || 1000) + 1000 / 60))); } }
function closeOne(w) { w.__closed = true; try { w.close(); } catch (e) { /* closed */ } }
function closeAll() { WINS.forEach(closeOne); BUS.chans.forEach(c => c.close()); }
const tallest = w => Math.max.apply(null, (w.__bars || [0]).concat([0]));
const waveSpread = w => { const ys = w.__wave || []; return ys.length ? Math.max.apply(null, ys) - Math.min.apply(null, ys) : 0; };
const css = (w, el) => w.getComputedStyle(el);
const scaleOf = el => { const m = /scale\(([\d.]+)\)/.exec(el && el.style.transform || ""); return m ? Number(m[1]) : 1; };
/* Wait until the page has heard the pop-out playing and has fresh frames, then draw its frames at once. */
async function untilHeard(P, playing) {
  for (let i = 0; i < 300; i++) {
    const lv = P.BFMusic._levels();
    if (P.BFMusic.popoutAlive() && (playing ? lv.bass > 0.3 && P.__raf.length > 0 : true)) break;
    await wait(10);
  }
}

/* ════ V. the visual in keep-playing mode ════ */
async function visualChecks() {
  console.log("\n══ V. keep playing between pages: the page's boombox moves with the music the pop-out plays ══");
  check("V0. the four files were read: bf-music.js, bf-boombox.js, bf-theme.js, termaximus-presence.js", !!(FILES[MUSIC] && FILES[BOOMBOX] && FILES[THEME] && FILES[PRESENCE]));
  SOUND.level = 0; SOUND.wave = 0;
  const store = { v: 1, uid: UID, track_id: T1, position: 5, queue: [T1, T2] };
  const P = await openPage({ page: "tasks.html", live: true, store, name: "page" });
  const POP = await openPage({ popout: true, name: "popout" });
  SOUND.level = 210; SOUND.wave = 0.8;
  POP.BFMusic.playTrack(T1); await settle(); POP.BFMusic._tick(); await settle();
  await untilHeard(P, true);
  BUS.log.length = 0;
  frames(P, 20);
  const playingHere = P.BFMusic.playing(), heard = P.BFMusic._levels();
  check("V1. the music plays in the pop-out and the page's own audio is paused (the page is its remote)",
    POP.BFMusic.playing() && !playingHere && P.BFMusic.popoutAlive(), [POP.BFMusic.playing(), playingHere, P.BFMusic.popoutAlive()].join());
  check("V2. the page's display moves with the pop-out's music: its spectrum bars rise (the tallest " + tallest(P).toFixed(1) + " px of 26)",
    tallest(P) > 10, JSON.stringify((P.__bars || []).slice(0, 8)));
  check("V2. ... and its speakers too (the cone scale " + scaleOf(P.document.querySelector(".bbx-cone")).toFixed(3) + ")", scaleOf(P.document.querySelector(".bbx-cone")) > 1.03);
  check("V2. ... and its meters, left and right, from the pop-out's own meters", heard.left > 0.1 && heard.right > 0.1, JSON.stringify({ left: heard.left, right: heard.right }));
  P.BFMusic.setView("wave"); frames(P, 6);
  check("V3. in the Waveform view the page draws the pop-out's waveform (a spread of " + waveSpread(P).toFixed(1) + " px)", waveSpread(P) > 8, JSON.stringify((P.__wave || []).slice(0, 6)));
  P.BFMusic.setView("spectrum");
  await wait(340);
  const sent = BUS.log.filter(x => x.from === "popout" && x.m.type === "levels");
  const keysOk = sent.length > 0 && sent.every(x => JSON.stringify(Object.keys(x.m).sort()) === JSON.stringify(["bars", "bass", "from", "highs", "left", "level", "right", "type", "wave"]));
  const numbersOnly = sent.every(x => ["bass", "highs", "level", "left", "right"].every(k => typeof x.m[k] === "number" && x.m[k] >= 0 && x.m[k] <= 1) &&
    Array.isArray(x.m.bars) && x.m.bars.length === 48 && x.m.bars.every(v => typeof v === "number" && v >= 0 && v <= 1) &&
    Array.isArray(x.m.wave) && x.m.wave.length === 64 && x.m.wave.every(v => Number.isInteger(v) && v >= 0 && v <= 255));
  check("V4. the pop-out sends frames about 30 a second (" + sent.length + " in 340 ms, every " + (/var LEVELS_MS = (\d+);/.exec(FILES[MUSIC]) || [])[1] + " ms)", sent.length >= 4 && /var LEVELS_MS = 33;/.test(FILES[MUSIC]));
  check("V4. ... numbers only: bass, highs, level, left, right (0 … 1), 48 bars (0 … 1) and 64 waveform samples (0 … 255), and nothing else", keysOk && numbersOnly,
    sent.length ? JSON.stringify(Object.keys(sent[0].m)) : "no frames");
  check("V4. ... and the page keeps only the newest frame, drawn by its own requestAnimationFrame loop",
    /remoteLevels = takeFrame\(m\);/.test(FILES[MUSIC]) && /vizRaf = window\.requestAnimationFrame\(frame\);/.test(FILES[MUSIC]));

  POP.BFMusic.next(); await settle(); POP.BFMusic._tick(); await settle(); await untilHeard(P, true);
  P.__bars = []; frames(P, 10);
  check("V5. a track change in the pop-out keeps the page's display moving (" + tallest(P).toFixed(1) + " px)", tallest(P) > 10 && POP.BFMusic.state().track_id === T2);
  P.BFMusic.setVolume(0.3); await settle(); await wait(80); P.__bars = []; frames(P, 10);
  check("V5. ... and a volume change made on the page (relayed to the pop-out) too (" + tallest(P).toFixed(1) + " px)", tallest(P) > 10 && Math.abs(POP.BFMusic.state().volume - 0.3) < 1e-9);

  /* a page change: this page goes, the next one comes, and it moves with the music at once */
  closeOne(P); await settle();
  const P2 = await openPage({ page: "crm.html", live: true, store, name: "page2" });
  POP.BFMusic._tick(); await settle(); await untilHeard(P2, true);
  frames(P2, 20);
  check("V6. after a page change the next page's display moves with the music the pop-out is still playing (" + tallest(P2).toFixed(1) + " px)",
    POP.BFMusic.playing() && !P2.BFMusic.playing() && tallest(P2) > 10);

  /* pause: one silent frame, then nothing; the page goes still */
  /* the log is cleared once the pop-out has paused: a frame already in flight when the page pressed pause is not counted */
  P2.BFMusic.pause(); await settle();
  BUS.log.length = 0;
  POP.BFMusic._tick(); await settle();
  await wait(300);
  const after = BUS.log.filter(x => x.from === "popout" && x.m.type === "levels");
  const loud = after.filter(x => x.m.bass > 0 || x.m.level > 0 || (x.m.bars || []).some(v => v > 0));
  check("V7. paused (from the page's remote), the pop-out stops: at most one frame after the pause, silent, and no frame with sound in it",
    !POP.BFMusic.playing() && after.length <= 1 && loud.length === 0, after.length + " frames, " + loud.length + " with sound");
  frames(P2, 90);
  check("V7. ... and the page's display and speakers come to rest (the tallest bar " + tallest(P2).toFixed(1) + " px, the cone " + scaleOf(P2.document.querySelector(".bbx-cone")).toFixed(3) + ")",
    tallest(P2) <= 2.5 && scaleOf(P2.document.querySelector(".bbx-cone")) === 1);
  POP.BFMusic.play(); await settle(); POP.BFMusic._tick(); await settle(); await untilHeard(P2, true);
  P2.__bars = []; frames(P2, 10);
  check("V8. resumed, the page's display moves again (" + tallest(P2).toFixed(1) + " px)", POP.BFMusic.playing() && tallest(P2) > 10);
  POP.BFMusic.pause(); await settle();
  closeOne(P2); closeOne(POP); await settle();

  /* reduced motion: the pop-out sends nothing; the page's display is a still meter and asks for no frame */
  BUS.log.length = 0;
  const RP = await openPage({ page: "tasks.html", live: true, store, name: "rpage", reduce: true });
  const RPOP = await openPage({ popout: true, name: "rpopout", reduce: true });
  RPOP.BFMusic.playTrack(T1); await settle(); RPOP.BFMusic._tick(); await settle(); await wait(150);
  const rSent = BUS.log.filter(x => x.from === "rpopout" && x.m.type === "levels").length;
  const canvas = RP.document.querySelector(".bfm-viz");
  check("V9. under prefers-reduced-motion the pop-out sends no frames and the page's display is still (no animation frame asked for)",
    RPOP.BFMusic.playing() && rSent === 0 && canvas && canvas.getAttribute("data-viz") === "static" && RP.__raf.length === 0, rSent + " " + (canvas && canvas.getAttribute("data-viz")) + " " + RP.__raf.length);
  RPOP.BFMusic.pause(); await settle();
  closeOne(RP); closeOne(RPOP); await settle();
  SOUND.level = 0; SOUND.wave = 0;
}

/* ════ I. the music button ════ */
async function iconChecks() {
  console.log("\n══ I. the music button: one icon, the golden note, in the theme's colour ══");
  const BX = FILES[BOOMBOX];
  const D = await openPage({ name: "dash" });
  const icon = D.document.querySelector(".bfm-icon");
  const svg = icon && icon.querySelector("svg");
  const ICON = D.BFBoombox && D.BFBoombox.MUSIC_ICON;
  /* the icon as the browser holds it (an SVG's self-closing tags serialise with closing tags) */
  const parsed = (() => { const t = D.document.createElement("div"); t.innerHTML = ICON || ""; return t.innerHTML; })();
  check("I1. one source: BFBoombox.MUSIC_ICON is the icon inside the dashboard's button, and bf-boombox.js builds the button from it in one place",
    !!ICON && !!icon && icon.innerHTML === parsed && (BX.match(/\+ MUSIC_ICON \+/g) || []).length === 1, icon && icon.innerHTML.slice(0, 80));
  const others = (() => {
    const out = [];
    const walk = dir => fs.readdirSync(path.join(FRONTEND, dir), { withFileTypes: true }).forEach(e => {
      const rel = dir ? dir + "/" + e.name : e.name;
      if (e.isDirectory()) { if (!/^(\.git|node_modules|icons)$/.test(e.name)) walk(rel); }
      else if (/\.(html|js|css)$/.test(e.name) && rel !== BOOMBOX && /bfm-gn-|bfm-note-wave|bfm-icon-art|bbxIconBody|bbxIconChrome|bfm-icon-eq/.test(fs.readFileSync(path.join(FRONTEND, rel), "utf8"))) out.push(rel);
    });
    walk("");
    return out;
  })();
  check("I1. ... and no other frontend file draws a music icon of its own", others.length === 0, others.join(", "));
  const paints = svg ? Array.prototype.slice.call(svg.querySelectorAll("*")).concat([svg]).map(el => [el.getAttribute("stroke"), el.getAttribute("fill")]) : [];
  /* NAMED BEFORE → AFTER (Nov 9 2026, golden note icon). BEFORE: the svg itself carried stroke="currentColor". AFTER: the
     svg carries no colour at all (the owner's geometry), and the CSS strokes the stem, the spiral and the glow currentColor. */
  /* NAMED BEFORE → AFTER (Nov 9 2026, violet spiral per the approved design). BEFORE: one CSS rule stroked the stem, the
     spiral and the glow currentColor, and the svg could hold currentColor strokes. AFTER: the svg markup holds no colour at
     all (no stroke, color or style attribute, every fill "none"), the stem is stroked currentColor and the spiral and its
     glow the theme violet, var(--bf-accent-b, #a855f7), as BizForce writes the violet everywhere. */
  const markupNoColour = !!ICON && !/\s(stroke|color|style|stop-color)=/.test(ICON) && (ICON.match(/\sfill="[^"]*"/g) || []).every(f => f === " fill=\"none\"") &&
    !/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(|currentColor/i.test(ICON);
  const colourOk = paints.length > 0 && paints.every(([st, fi]) => st === null && [null, "none"].indexOf(fi) !== -1) && markupNoColour &&
    BX.indexOf("\".bfm-gn-stem{stroke:currentColor}\"") !== -1 && BX.indexOf("\".bfm-gn-spiral,.bfm-gn-glow{stroke:var(--bf-accent-b, #a855f7)}\"") !== -1;
  check("I2. the icon's markup holds no colour at all; its CSS strokes the stem currentColor (the primary accent) and the spiral and its glow the theme violet, var(--bf-accent-b, #a855f7)",
    colourOk, JSON.stringify(paints));
  /* the icon's own CSS: every rule naming the golden note's parts or the button's two rings */
  const iconCss = (BX.match(/"[^"\n]*(?:\.bfm-gn-|\.bfm-icon::|\.bfm-icon:hover::|\.bfm-icon:focus-visible::)[^\n]*",?\n/g) || []).join("");
  /* NAMED BEFORE → AFTER (Nov 9 2026, violet spiral per the approved design). BEFORE: no hex at all in the icon's CSS.
     AFTER: every colour is one of the project's accent forms, and the only hex is the violet's own fallback:
       the primary accent: currentColor, var(--bf-accent-a3, #00e5ff) or its channels rgba(var(--bf-accent-a3-rgb, 0, 229, 255),a);
       the violet: var(--bf-accent-b, #a855f7), only for the spiral, the glow and the playing ring (::after);
       white, only as the playing spiral's tint inside color-mix. */
  const ALLOWED_COLOURS = [/var\(--bf-accent-b, #a855f7\)/g, /var\(--bf-accent-a3, #00e5ff\)/g, /rgba\(var\(--bf-accent-a3-rgb, 0, 229, 255\),\.\d+\)/g, /\bcurrentColor\b/g, /color-mix\(in srgb,,? ?\d+%,white\)/g];
  const colourLeft = ALLOWED_COLOURS.reduce((t, re) => t.replace(re, ""), iconCss);
  const iconRules = iconCss.split("\n").filter(Boolean);
  const violetRules = iconRules.filter(r => /--bf-accent-b\b/.test(r));
  const violetWhere = violetRules.every(r => { const sel = r.slice(r.indexOf("\"") + 1, r.indexOf("{")); return !/bfm-gn-stem/.test(sel) && /\.bfm-gn-spiral|\.bfm-gn-glow|::after/.test(sel); });
  const stemRules = iconRules.filter(r => /\.bfm-gn-stem/.test(r.slice(0, r.indexOf("{"))));
  check("I2. ... every colour in the icon's CSS is the primary accent (currentColor, var(--bf-accent-a3, ...)) or, for the spiral, glow and playing ring only, var(--bf-accent-b, #a855f7); no other hex, rgb, hsl or named colour",
    iconCss.length > 0 && !/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(|\b(white|black|gold|violet|purple|cyan)\b/i.test(colourLeft) &&
    violetRules.length === 3 && violetWhere && stemRules.length === 1 && stemRules[0].indexOf("\".bfm-gn-stem{stroke:currentColor}\"") !== -1,
    JSON.stringify({ left: (colourLeft.match(/#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)|\b(white|black|gold|violet|purple|cyan)\b/ig) || []), violet: violetRules.length, stem: stemRules }));
  const rule = sel => { const i = BX.indexOf("\"" + sel + "{"); return i === -1 ? "" : BX.slice(i, BX.indexOf("}", i) + 1); };
  check("I2. ... the button's colour is the theme's accent token (var(--bf-accent-a3, #00e5ff)), and its border the accent's channels",
    /color:var\(--bf-accent-a3, #00e5ff\)/.test(rule(".bfm-icon")) && /border:1px solid rgba\(var\(--bf-accent-a3-rgb, 0, 229, 255\),\.32\)/.test(rule(".bfm-icon")), rule(".bfm-icon"));
  /* NAMED BEFORE → AFTER (Nov 9 2026, golden note icon). BEFORE: I3 pinned an eighth note (an ellipse head, bfm-note-stem)
     flowing into a sine wave (bfm-note-wave), stroke-width 1.8 on the svg, 22 x 22. AFTER: the owner's golden note, exactly. */
  const SPIRAL_D = "M0 55 A55 55 0 0 1 55 0 A34 34 0 0 1 89 34 A21 21 0 0 1 68 55 A13 13 0 0 1 55 42 A8 8 0 0 1 63 34";
  const STEM_D = "M17.24 18.74V2.6c1.6 1 3.9 1.9 3.9 4.8c0 1.3-.6 2.1-1.5 2.7";
  const one = sel => svg ? svg.querySelectorAll(sel).length : 0;
  const glowG = svg && svg.querySelector("g.bfm-gn-glow"), spiralG = svg && svg.querySelector("g.bfm-gn-spiral"), stemP = svg && svg.querySelector("path.bfm-gn-stem");
  const shape = svg ? {
    glow: one(".bfm-gn-glow"), spiral: one(".bfm-gn-spiral"), stem: one(".bfm-gn-stem"), paths: one("path"), circles: one("circle"), ellipses: one("ellipse"),
    glowD: glowG && glowG.querySelector("path") && glowG.querySelector("path").getAttribute("d"), spiralD: spiralG && spiralG.querySelector("path") && spiralG.querySelector("path").getAttribute("d"),
    stemD: stemP && stemP.getAttribute("d")
  } : {};
  check("I3. the icon is the golden note: the golden-ratio spiral (exact path) as the head, under its glow, and the stem and flag (exact path), on a 24 grid",
    shape.glow === 1 && shape.spiral === 1 && shape.stem === 1 && shape.paths === 3 && shape.glowD === SPIRAL_D && shape.spiralD === SPIRAL_D && shape.stemD === STEM_D &&
    svg.getAttribute("viewBox") === "0 0 24 24" && svg.getAttribute("width") === "24" && svg.getAttribute("height") === "24" &&
    svg.getAttribute("aria-hidden") === "true" && svg.getAttribute("focusable") === "false" && svg.getAttribute("class") === "bfm-icon-art" &&
    glowG.getAttribute("transform") === "translate(3 13.3) scale(.16)" && spiralG.getAttribute("transform") === "translate(3 13.3) scale(.16)" &&
    glowG.getAttribute("stroke-width") === "26" && spiralG.getAttribute("stroke-width") === "10" && stemP.getAttribute("stroke-width") === "1.7", JSON.stringify(shape));
  check("I4. neither old icon is left: no circle (the two-circle boombox) and no note head, wave or clip (the note-and-wave), in the button or in bf-boombox.js",
    shape.circles === 0 && shape.ellipses === 0 && !svg.querySelector("clipPath,[clip-path]") &&
    !/ICON_ART|bbxIconBody|bbxIconChrome|bfm-icon-eq|bfm-icon-sheen|bbx-icon-eq|bbx-icon-sheen|bfm-note-head|bfm-note-stem|bfm-note-wave|bfmNoteWaveClip/.test(BX.replace(/\/\*[\s\S]*?\*\//g, "")));
  check("I5. the button is named: aria-label and title \"Music player\", a real button",
    !!icon && icon.tagName === "BUTTON" && icon.getAttribute("type") === "button" && icon.getAttribute("aria-label") === "Music player" && icon.getAttribute("title") === "Music player",
    icon && icon.outerHTML.slice(0, 120));
  const uiBtn = (() => { const i = FILES[UI].indexOf(".topbar-icon-btn {"); return i === -1 ? "" : FILES[UI].slice(i, FILES[UI].indexOf("}", i)); })();
  check("I6. it matches the header's round control (css/bizforce-ui.css .topbar-icon-btn: 40 px, round, a one-pixel accent border, the dark glass)",
    /width: 40px;/.test(uiBtn) && /height: 40px;/.test(uiBtn) && /border-radius: 50%;/.test(uiBtn) && D.BFBoombox.ICON_W === 40 && D.BFBoombox.ICON_H === 40 &&
    /border-radius:50%/.test(rule(".bfm-icon")) && /background:rgba\(8,12,28,\.85\)/.test(rule(".bfm-icon")) && css(D, icon).width === "40px" && css(D, icon).height === "40px");
  /* NAMED BEFORE → AFTER (Nov 9 2026, golden note icon). BEFORE: I6 pinned a hover and focus rule that switched the
     border colour and box-shadow at once; I7 the wave's drift (bfm-note-wave, translateX, 3 s); I8 its reduced-motion
     rule. AFTER: the focus ring is kept (I6); the hover fades by opacity only (I7); the playing pulse (I8), reduced
     motion (I9) and the hidden pause (I10) are the golden note's; the floating icon is I11 (BEFORE I9). */
  check("I6. ... a visible focus ring, in the theme's accent",
    /"\.bfm-icon:focus-visible\{outline:2px solid var\(--bf-accent-a, #22d3ee\);outline-offset:2px\}"/.test(BX));
  const glowEl = icon && icon.querySelector(".bfm-gn-glow");
  const iconTransitions = iconCss.match(/transition:[^;}"]+/g) || [];
  check("I7. hover and focus fade in by opacity only (200 ms): the glow from 0 to .2, and a brighter ring over the border; nothing switches the border or shadow at once",
    BX.indexOf("\".bfm-gn-glow{opacity:0;transition:opacity 200ms}\"") !== -1 &&
    BX.indexOf("\".bfm-icon:hover .bfm-gn-glow,.bfm-icon:focus-visible .bfm-gn-glow{opacity:.2}\"") !== -1 &&
    BX.indexOf("\".bfm-icon::before,.bfm-icon::after{content:\\\"\\\";position:absolute;inset:-1px;border-radius:50%;pointer-events:none;opacity:0;transition:opacity 200ms}\"") !== -1 &&
    BX.indexOf("\".bfm-icon::before{border:1px solid rgba(var(--bf-accent-a3-rgb, 0, 229, 255),.6);box-shadow:0 0 16px rgba(var(--bf-accent-a3-rgb, 0, 229, 255),.25)}\"") !== -1 &&
    BX.indexOf("\".bfm-icon:hover::before,.bfm-icon:focus-visible::before{opacity:1}\"") !== -1 &&
    iconTransitions.length === 2 && iconTransitions.every(t => t === "transition:opacity 200ms") &&
    !/"\.bfm-icon:(hover|focus-visible)[^"]*\{[^}"]*(border-color|box-shadow|border:)/.test(BX) &&
    !!glowEl && css(D, glowEl).opacity === "0", JSON.stringify(iconTransitions) + " " + (glowEl && css(D, glowEl).opacity));
  const restAnim = css(D, glowEl).animation || "";
  D.BFMusic.playTrack(T1); D.document.dispatchEvent(new D.Event("pointerdown", { bubbles: true })); await settle();
  D.BFMusic.play(); await settle();
  const pulsing = D.BFMusic.playing() && /bfm-gn-pulse/.test(css(D, glowEl).animation || "");
  D.BFMusic.pause(); await settle();
  const stillAgain = !/bfm-gn-pulse/.test(css(D, glowEl).animation || "");
  const pulseKf = (BX.match(/@keyframes bfm-gn-pulse\{[\s\S]*?\}\}/) || [""])[0];
  check("I8. while music plays the glow pulses (an opacity keyframe, .22 to .45 over 2.4 s, ease-in-out), the spiral lightens and the ring takes the second accent at .55; paused, all at rest",
    !/bfm-gn-pulse/.test(restAnim) && pulsing && stillAgain &&
    pulseKf === "@keyframes bfm-gn-pulse{0%,100%{opacity:.22}50%{opacity:.45}}" && (pulseKf.match(/[\w-]+(?=:)/g) || []).every(p => p === "opacity") &&
    BX.indexOf("\".bfm-float[data-playing=true] .bfm-gn-glow{animation:bfm-gn-pulse 2.4s ease-in-out infinite}\"") !== -1 &&
    /* NAMED BEFORE → AFTER (Nov 9 2026, violet spiral per the approved design). BEFORE: the playing spiral and the playing
       ring were currentColor. AFTER: the theme violet, var(--bf-accent-b, #a855f7), the spiral tinted 70% violet, 30% white. */
    BX.indexOf("\".bfm-float[data-playing=true] .bfm-gn-spiral{stroke:var(--bf-accent-b, #a855f7);stroke:color-mix(in srgb,var(--bf-accent-b, #a855f7) 70%,white)}\"") !== -1 &&
    BX.indexOf("\".bfm-icon::after{border:1px solid var(--bf-accent-b, #a855f7)}\"") !== -1 &&
    BX.indexOf("\".bfm-float[data-playing=true] .bfm-icon::after{opacity:.55}\"") !== -1, [restAnim, pulsing, stillAgain, pulseKf].join(" | "));
  check("I9. under prefers-reduced-motion the glow never pulses: no animation, a steady .3 glow while playing",
    BX.indexOf("\"@media (prefers-reduced-motion: reduce){.bfm-gn-glow{animation:none!important}.bfm-float[data-playing=true] .bfm-gn-glow{opacity:.3}}\"") !== -1);
  check("I10. while the tab is hidden the pulse is paused (the root that carries data-hidden holds the glow)",
    BX.indexOf("\".bfm[data-hidden=true] .bfm-gn-glow{animation-play-state:paused}\"") !== -1 && !!glowEl && !!glowEl.closest(".bfm") &&
    !!D.document.querySelector(".bfm-float").closest(".bfm"));
  closeOne(D); await settle();
  /* the floating icon on another page is the same button */
  const Q = await openPage({ page: "crm.html", live: true, store: { v: 1, uid: UID, track_id: T1, position: 5 }, name: "floating" });
  Q.localStorage.setItem("bf_boombox", JSON.stringify({ state: "icon" }));
  const QB = Q.document.querySelector(".bfm-float");
  Q.BFMusic._box().setState("icon");
  const qi = Q.document.querySelector(".bfm-icon");
  check("I11. the floating icon on another page is the same button and the same icon",
    !!qi && qi.innerHTML === parsed && qi.getAttribute("aria-label") === "Music player" && QB.getAttribute("data-state") === "icon");
  closeOne(Q); await settle();
}

/* ════ P. the placement ════ */
async function placementChecks() {
  console.log("\n══ P. the music button sits between the logo and the header's centre ══");
  /* NAMED BEFORE → AFTER (Nov 9 2026, button kept in the top bar). BEFORE: the root's style.left/top. AFTER: its box on screen. */
  const spotOf = w => { const r = w.document.querySelector(".bfm-float").getBoundingClientRect(); return { left: r.left, top: r.top }; };
  const hit = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
  const items = w => Array.prototype.slice.call(w.document.querySelectorAll("header [data-rect]")).filter(el => !el.hasAttribute("data-bf-boombox-anchor") && el.tagName !== "HEADER").map(el => el.getBoundingClientRect());
  const gapToLogo = (p, logo) => { const dx = Math.max(0, p.left - logo.right), dy = Math.max(0, p.top - logo.bottom); return Math.sqrt(dx * dx + dy * dy); };
  const box = p => ({ left: p.left, top: p.top, right: p.left + 40, bottom: p.top + 40 });
  /* wide: the logo ends at 190, the header's centre is 640: the button is centred at 415, level with the logo's middle (34) */
  const W = await openPage({ name: "wide" });
  const pw = spotOf(W), logoW = W.document.querySelector("[data-bf-boombox-anchor]").getBoundingClientRect();
  check("P1. on a wide header (1280 px) it is centred between the logo's right edge and the header's centre, level with the logo: (395, 14)",
    pw.left === 395 && pw.top === 14 && W.BFBoombox.ICON_MIN_GAP === 24, JSON.stringify(pw));
  check("P1. ... well clear of the logo (" + (pw.left - logoW.right) + " px) and over no other header item", pw.left - logoW.right >= 24 && !items(W).some(b => hit(box(pw), b)));
  closeOne(W);
  /* narrower: the midpoint would be under 24 px from the logo; it keeps the 24 px */
  const NARROW = '<header class="topbar" data-rect="0,0,420,68"><div class="topbar-brand" data-bf-boombox-anchor data-rect="16,14,166,40">BizForce AI</div>' +
    '<div class="topbar-actions"><a href="agents-hub.html" data-rect="262,16,90,36">Agents</a><div class="topbar-user" data-rect="360,14,46,40">BF</div></div></header>';
  const N = await openPage({ name: "narrow", width: 420, header: NARROW });
  const pn = spotOf(N), logoN = N.document.querySelector("[data-bf-boombox-anchor]").getBoundingClientRect();
  check("P2. on a narrow header (420 px) it keeps exactly 24 px from the logo, level with it, and covers no other item: (206, 14)",
    pn.left === 206 && pn.top === 14 && pn.left - logoN.right === 24 && !items(N).some(b => hit(box(pn), b)), JSON.stringify(pn));
  closeOne(N);
  /* NAMED BEFORE → AFTER (Nov 9 2026, button kept in the top bar). BEFORE: P3, "on a crowded header (360 px) with no room
     on its row, it sits just below the header under the logo" at (16, 80). AFTER: there is no spot below the header: on
     that crowded header it stays in the bar, level with the logo, 24 px from it, at the last-resort 32 px. P1 and P2 keep
     their numbers; P1 and P2 now read the root's box, which is the same as its style.left/top on a bar at (0, 0). The
     crowded header is laid out as the browser now lays it out: the logo block's reservation (24 + 32 + 12 px with the bar's
     gap) keeps the first item at 250 or beyond (BEFORE: Agents at 220, the user at 290). */
  const CROWD = '<header class="topbar" data-rect="0,0,360,68"><div class="topbar-brand" data-bf-boombox-anchor data-rect="16,14,166,40">BizForce AI</div>' +
    '<div class="topbar-actions"><a href="agents-hub.html" data-rect="250,16,56,36">Agents</a><div class="topbar-user" data-rect="314,14,40,40">BF</div></div></header>';
  const C = await openPage({ name: "crowded", width: 360, header: CROWD });
  const CR = C.document.querySelector(".bfm-float"), cb = CR.getBoundingClientRect(), logoC = C.document.querySelector("[data-bf-boombox-anchor]").getBoundingClientRect();
  check("P3. on a crowded header (360 px) it stays IN the bar, a child of it, level with the logo, exactly 24 px from it, at the last-resort 32 px, over no item: (206, 18)",
    CR.parentElement === C.document.querySelector("header") && cb.left === 206 && cb.top === 18 && cb.width === 32 && cb.left - logoC.right === 24 &&
    !items(C).some(b => hit(cb, b)) && cb.bottom <= 68, JSON.stringify(cb));
  closeOne(C); await settle();
  await placementWidths();
}

/* ════ P. the music button kept in the top bar, at every width (Nov 9 2026) ════
   A mocked layout of the dashboard's top bar at a width, as the browser lays it out: padding 24 px (16 at 640 and
   narrower), a safe-area inset above (22 px) and 14 px below, so the bar's centre is NOT the logo's; the logo block
   166 x 40; the bar's items right-aligned in rows of 46 px (12 px apart), wrapping where the logo block's reservation
   (52 px) and the bar's gap (16 px) leave too little room; the logo centred on the rows. */
const TOPBAR_ITEMS = [["a", "Agents", 90, 36, 90], ["a", "Oracle", 46, 46, 46], ["label", "Termaximus", 150, 28, 120],
  ["div class=\"topbar-user\"", "BF", 66, 40, 46], ["a", "Settings", 80, 36, 80], ["button", "Sign Out", 90, 36, 90]];
function dashBar(W) {
  const phone = W <= 640, p = phone ? 16 : 24, padTop = 22, padBottom = 14, RESERVE = 52, FLEX_GAP = 16, ROW = 46, ROW_GAP = 12, GAP_X = 12;
  const logoL = p, logoR = p + 166, right = W - p, avail = right - (logoR + RESERVE + FLEX_GAP);
  const rows = [[]];
  let used = 0;
  TOPBAR_ITEMS.forEach(it => {
    const w = phone ? it[4] : it[2], need = rows[rows.length - 1].length ? used + GAP_X + w : w;
    if (rows[rows.length - 1].length && need > avail) { rows.push([]); used = w; } else used = need;
    rows[rows.length - 1].push({ tag: it[0], text: it[1], w, h: it[3] });
  });
  const contentH = rows.length * ROW + (rows.length - 1) * ROW_GAP, barH = padTop + contentH + padBottom;
  const logoT = padTop + (contentH - 40) / 2;
  let html = "";
  rows.forEach((row, i) => {
    const rowW = row.reduce((s, it) => s + it.w, 0) + (row.length - 1) * GAP_X, rowT = padTop + i * (ROW + ROW_GAP);
    let x = right - rowW;
    row.forEach(it => {
      const close = it.tag.split(" ")[0];
      html += "<" + it.tag + " data-rect=\"" + [x, rowT + (ROW - it.h) / 2, it.w, it.h].join(",") + "\">" + it.text + "</" + close + ">";
      x += it.w + GAP_X;
    });
  });
  return { rows: rows.length, html: "<header class=\"topbar\" data-rect=\"0,0," + W + "," + barH + "\"><div class=\"topbar-brand\" data-bf-boombox-anchor data-rect=\"" +
    [logoL, logoT, 166, 40].join(",") + "\">BizForce AI</div><div class=\"topbar-actions\">" + html + "</div></header>" };
}
/* The rule, written out here on its own: the centre halfway between the logo's right edge and the bar's centre, held
   between 24 px from the logo and GAP (12 px) short of the next item on the logo's row; 40 px, else 32 px. */
function expectedSpot(bar, logo, items) {
  const centre = (bar.left + bar.right) / 2, cy = (logo.top + logo.bottom) / 2, mid = (logo.right + centre) / 2;
  const next = Math.min.apply(null, [bar.right].concat(items.filter(b => b.top < cy + 20 && b.bottom > cy - 20 && b.left >= logo.right).map(b => b.left)));
  for (const size of [40, 32]) {
    const lo = logo.right + 24 + size / 2, hi = next - 12 - size / 2;
    if (lo <= hi || size === 32) return { size, cx: Math.min(Math.max(mid, lo), Math.max(hi, lo)), cy, mid, fits40: size === 40 };
  }
}
async function placementWidths() {
  const WIDTHS = [1920, 1440, 1280, 1024, 768, 390];
  const hit = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
  const rows = [], bad = { parent: [], vert: [], horiz: [], mid: [], gap: [], over: [], inside: [], size: [], reserve: [] };
  for (const W of WIDTHS) {
    const fx = dashBar(W);
    const w = await openPage({ name: "w" + W, width: W, header: fx.html });
    await wait(5); await settle();
    const head = w.document.querySelector("header.topbar"), logoEl = w.document.querySelector("[data-bf-boombox-anchor]"), R = w.document.querySelector(".bfm-float");
    const bar = head.getBoundingClientRect(), logo = logoEl.getBoundingClientRect(), b = R.getBoundingClientRect();
    const items = Array.prototype.slice.call(head.querySelectorAll("[data-rect]")).filter(el => el !== logoEl && el !== head).map(el => el.getBoundingClientRect());
    const e = expectedSpot(bar, logo, items), cx = (b.left + b.right) / 2, cy = (b.top + b.bottom) / 2;
    const cs = w.getComputedStyle(head), barGap = parseFloat(cs.columnGap || cs.gap) || 0;
    const row = { W, rows: fx.rows, at: [b.left, b.top, b.width], cx, cy, want: [Math.round(e.cx * 10) / 10, e.cy, e.size], logoRight: logo.right, mid: e.mid };
    rows.push(row);
    if (!(R.parentElement === head && R.getAttribute("data-inbar") === "true")) bad.parent.push(W);
    if (Math.abs(cy - e.cy) > 2) bad.vert.push(JSON.stringify(row));
    if (Math.abs(cx - e.cx) > 1) bad.horiz.push(JSON.stringify(row));
    if (e.fits40 && W >= 1024 && Math.abs(cx - e.mid) > 1) bad.mid.push(JSON.stringify(row));
    if (b.left - logo.right < 24) bad.gap.push(JSON.stringify(row));
    if (items.some(it => hit(b, it))) bad.over.push(JSON.stringify(row));
    if (!(b.left >= bar.left && b.right <= bar.right && b.top >= bar.top && b.bottom <= bar.bottom)) bad.inside.push(JSON.stringify(row));
    if (b.width !== e.size || b.height !== e.size) bad.size.push(JSON.stringify(row));
    if (parseFloat(logoEl.style.marginRight) + barGap !== 24 + 32 + 12) bad.reserve.push(W + ": " + logoEl.style.marginRight + " + " + barGap);
    closeOne(w);
  }
  console.log("      widths: " + rows.map(r => r.W + " -> (" + r.at.join(", ") + ") centre " + r.cx + "," + r.cy + " rows " + r.rows).join(" | "));
  check("P4. at 1920, 1440, 1280, 1024, 768 and 390 px the music button is a child of the top bar's own element (header.topbar), marked in the bar", bad.parent.length === 0, bad.parent.join(","));
  check("P5. ... its centre is within 2 px of the logo's centre, vertically (the bar's centre is 4 px off it)", bad.vert.length === 0, bad.vert.join(" | "));
  check("P6. ... its horizontal centre follows the midpoint rule: halfway between the logo's right edge and the bar's centre, held by the 24 px minimum and the next item", bad.horiz.length === 0, bad.horiz.join(" | "));
  check("P6. ... and on a wide bar (1024 px and up) it is exactly the midpoint", bad.mid.length === 0, bad.mid.join(" | "));
  check("P7. ... at least 24 px right of the logo block at every width", bad.gap.length === 0, bad.gap.join(" | "));
  check("P7. ... over no other item of the bar, and wholly inside the bar's box", bad.over.length === 0 && bad.inside.length === 0, bad.over.concat(bad.inside).join(" | "));
  const r390 = rows.find(r => r.W === 390), r1920 = rows.find(r => r.W === 1920);
  check("P8. 40 px where it fits, and the last-resort 32 px only where the logo's row is short (it is, at 390: " + (r390 && r390.at[2]) + " px)",
    bad.size.length === 0 && !!r390 && r390.at[2] === 32 && !!r1920 && r1920.at[2] === 40, bad.size.join(" | "));
  check("P8. the logo block keeps room beside it: its margin and the bar's gap make 24 + 32 + 12 px, so no item can come closer", bad.reserve.length === 0, bad.reserve.join(" | "));

  /* a late header item, and the fonts arriving: measured again, not only at the first look */
  let fontsDone;
  const fonts = new Promise(r => { fontsDone = r; });
  const L = await openPage({ name: "late", width: 1280, header: dashBar(1280).html, fonts });
  await wait(5); await settle();
  const LR = L.document.querySelector(".bfm-float"), Lhead = L.document.querySelector("header.topbar"), Llogo = L.document.querySelector("[data-bf-boombox-anchor]");
  const before = LR.getBoundingClientRect().left;
  const badge = L.document.createElement("span");
  badge.className = "bf-badge"; badge.textContent = "Pro"; badge.setAttribute("data-rect", "380,32,90,32");
  Lhead.appendChild(badge);
  await wait(20); await settle();
  const afterBadge = LR.getBoundingClientRect();
  check("P9. a header item that arrives late (a badge in the button's way) moves it: still in the bar, level with the logo, 12 px short of the badge (" + before + " -> " + afterBadge.left + ")",
    before === 395 && afterBadge.left === 328 && afterBadge.right <= 380 - 12 && LR.parentElement === Lhead, before + " " + JSON.stringify(afterBadge));
  Lhead.removeChild(badge);
  await wait(20); await settle();
  Llogo.setAttribute("data-rect", "24,22,206,40");
  fontsDone(); await wait(20); await settle();
  const afterFonts = LR.getBoundingClientRect();
  check("P9. ... and so do the fonts arriving (the logo block grows to 206 px): it is placed again from the new logo, at the midpoint (" + afterFonts.left + ")",
    afterFonts.left === Math.round((230 + 640) / 2 - 20), JSON.stringify(afterFonts));
  /* the bar and the boombox are not in the top bar; closing to the icon puts it back */
  L.document.querySelector("[data-act=bbx-open]").click();
  const opened = LR.parentElement === L.document.body && LR.getAttribute("data-inbar") === null && LR.getAttribute("data-state") === "tag";
  L.BFMusic._box().setState("icon");
  check("P10. opened to the bar it goes back to the page (as before), and back to the icon it is in the top bar again, in the same spot",
    opened && LR.parentElement === Lhead && LR.getBoundingClientRect().left === afterFonts.left, opened + " " + (LR.parentElement && LR.parentElement.tagName));
  closeOne(L); await settle();

  /* THE OTHER PAGES' TOP BAR (.top-nav: the back link at the left, the logo at the right end): the same rule, mirrored */
  const NAV = "<nav class=\"top-nav\" data-rect=\"0,0,1280,60\"><a href=\"dashboard.html\" class=\"back-link\" data-rect=\"24,18,130,24\">Executive HQ</a>" +
    "<span class=\"brand-badge\" data-bf-boombox-anchor data-rect=\"1166,20,90,20\">BizForce AI</span></nav>";
  const live = { v: 1, uid: UID, track_id: T1, position: 5, queue: [T1, T2], placement: "pinned" };
  const PN = await openPage({ page: "crm.html", name: "nav-pinned", width: 1280, header: NAV, live: true, store: live, boombox: { state: "icon" } });
  await wait(5); await settle();
  const PR = PN.document.querySelector(".bfm-float"), pb = PR.getBoundingClientRect(), navLogo = PN.document.querySelector("[data-bf-boombox-anchor]").getBoundingClientRect();
  const navMid = (navLogo.left + 640) / 2;
  check("P11. on another page with a top bar (.top-nav), the pinned music button is a child of that bar, on the logo's side facing the centre (left), level with it, at the midpoint",
    PR.parentElement === PN.document.querySelector("nav.top-nav") && PR.getAttribute("data-state") === "icon" && (pb.left + pb.right) / 2 === navMid &&
    (pb.top + pb.bottom) / 2 === (navLogo.top + navLogo.bottom) / 2 && navLogo.left - pb.right >= 24,
    (PR.parentElement && PR.parentElement.tagName) + " " + JSON.stringify(pb));
  closeOne(PN);
  const FN = await openPage({ page: "crm.html", name: "nav-follow", width: 1280, header: NAV, live: true, store: Object.assign({}, live, { placement: "follow" }), boombox: { state: "icon" } });
  await wait(5); await settle();
  const FR = FN.document.querySelector(".bfm-float");
  check("P11. ... and where the member chose Follow me it is the floating icon as before: on the page, not in the bar, fixed and draggable",
    FR.parentElement === FN.document.body && FR.getAttribute("data-inbar") === null && FR.getAttribute("data-pinned") === "false", FR.parentElement && FR.parentElement.tagName);
  closeOne(FN); await settle();

  /* no other way out of the bar, in the code */
  const BX = FILES[BOOMBOX];
  const planSrc = (BX.match(/  function iconPlan\([\s\S]*?\n  \}\n/) || [""])[0], barSrc = (BX.match(/    function placeInBar\(\)[\s\S]*?\n    \}\n/) || [""])[0];
  const placeSrc = (BX.match(/    function place\(\) \{[\s\S]*?\n    \}\n/) || [""])[0];
  check("P12. no code path puts it below or outside the bar: iconSpot and its drop-below are gone, the plan's only top is the logo's centre, the bar's only top is the plan's, and place() puts the button in the bar before anything else",
    !/iconSpot\(/.test(BX) && !/hr\.bottom/.test(BX) && !/\.bottom\s*\+\s*GAP/.test(planSrc + barSrc) && planSrc.length > 0 && (planSrc.match(/top:/g) || []).length === 1 && /top: Math\.round\(cy - size \/ 2\)/.test(planSrc) &&
    (barSrc.match(/root\.style\.top =/g) || []).length === 1 && /root\.style\.top = Math\.round\(plan\.top - br\.top/.test(barSrc) && /bar\.appendChild\(root\)/.test(barSrc) &&
    /^    function place\(\) \{\n      if \(popout\) return;\n      if \(inBar\(\)\) \{ root\.setAttribute\("data-dock", "desktop"\); placeInBar\(\); side\(\); return; \}/.test(placeSrc),
    [planSrc.length, barSrc.length, placeSrc.slice(0, 160)].join(" | "));
}

/* ════ M. the mist ════ */
function mistOn(pathname, signedIn) {
  const dom = new JSDOM("<!doctype html><html><head></head><body><h1>Page</h1></body></html>",
    { url: "https://bizforceai.net" + pathname, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: new VirtualConsole() });
  const w = dom.window;
  w.fetch = () => { const p = Promise.reject(new Error("no network in this check")); p.catch(() => {}); return p; };
  w.HTMLCanvasElement.prototype.getContext = () => null;
  w.matchMedia = () => ({ matches: false, addEventListener() {}, addListener() {} });
  if (signedIn !== false) w.localStorage.setItem("bf_token", TOKEN);
  try { w.eval(FILES[PRESENCE]); } catch (e) { /* the mist's own trouble after it was decided */ }
  const on = !!w.document.getElementById("tmx-presence-root");
  try { w.close(); } catch (e) { /* closed */ }
  return on;
}
function mistChecks() {
  console.log("\n══ M. the mist: everywhere signed in, except the sign-in pages and the Oracle pages ══");
  const m = /var TMX_NO_MIST_PAGES = (\[[^\]]*\]);/.exec(FILES[PRESENCE]);
  const list = m ? vm.runInNewContext(m[1]) : null;
  const WANT = ["index", "app", "reset-password", "verify-email", "oracle", "mychart", "synastry", "the-third"];
  check("M1. the one place that decides: TMX_NO_MIST_PAGES is exactly the sign-in pages and the Oracle pages",
    JSON.stringify(list) === JSON.stringify(WANT) && (FILES[PRESENCE].match(/TMX_NO_MIST_PAGES/g) || []).length === 2, JSON.stringify(list));
  check("M1. ... and it decides before anything is drawn (the first statement after it returns)",
    /var TMX_NO_MIST_PAGES = [^\n]+\n  try \{\n    var _tmxPath  = \(window\.location\.pathname \|\| ""\)\.toLowerCase\(\);\n    var _tmxFile  = [^\n]+\n    var _tmxSkip  = _tmxFile === "" \|\| TMX_NO_MIST_PAGES\.indexOf\(_tmxFile\) !== -1;\n    if \(_tmxSkip \|\| !localStorage\.getItem\("bf_token"\)\) return;/.test(FILES[PRESENCE]));
  const signIn = ["/", "/index.html", "/app.html", "/app", "/reset-password.html", "/verify-email.html"];
  const oracle = ["/oracle.html", "/oracle", "/mychart.html", "/synastry.html", "/the-third.html", "/the-third"];
  const elsewhere = ["/dashboard.html", "/crm.html", "/agents/sales.html", "/settings.html", "/calendar", "/proposals.html"];
  const onSignIn = signIn.filter(p => mistOn(p));
  check("M2. no mist on the sign-in pages (" + signIn.join(", ") + "), signed in or not", onSignIn.length === 0, onSignIn.join(", "));
  const onOracle = oracle.filter(p => mistOn(p));
  check("M3. no mist on the Oracle pages (" + oracle.join(", ") + ")", onOracle.length === 0, onOracle.join(", "));
  const missing = elsewhere.filter(p => !mistOn(p));
  check("M4. the mist shows on every other signed-in page (a sample: " + elsewhere.join(", ") + ")", missing.length === 0, missing.join(", "));
  check("M4. ... and never when signed out", !mistOn("/dashboard.html", false));
  const files = (FILES[PRESENCE] && SIGN_IN_PAGES.concat(ORACLE_PAGES)).filter(f => !FILES[f]);
  check("M5. the listed pages are real pages of the frontend", files.length === 0, files.join(", "));
  const before = ORACLE_PAGES.filter(f => { const t = gitShow(REGRESSION + "~1", f); return t === null || t.indexOf(MIST_TAG) !== -1; });
  const since = ORACLE_PAGES.filter(f => { const t = gitShow(REGRESSION, f); return t === null || t.indexOf(MIST_TAG) === -1; });
  check("M6. the Oracle pages are the four the mist skipped until " + REGRESSION + " put its tag on them (for the boombox): no tag before it, the tag since",
    before.length === 0 && since.length === 0, "before: " + before.join(",") + " since: " + since.join(","));
  const keepPlayer = ORACLE_PAGES.filter(f => FILES[f].indexOf(MIST_TAG) === -1);
  check("M7. the Oracle pages keep the tag, so the music player stays on them (scripts/bf-music.js looks for it); only the mist steps aside",
    keepPlayer.length === 0, keepPlayer.join(", "));
}

/* ════ O. the Oracle backgrounds ════ */
const stylesOf = html => (html.match(/<style[^>]*>[\s\S]*?<\/style>/g) || []).join("\n").replace(/\/\*[\s\S]*?\*\//g, "");
function rootDecls(html) {
  const out = { normal: {}, important: {} };
  const css = stylesOf(html), re = /(^|[\s}]):root\s*\{([^{}]*)\}/g;
  let m;
  while ((m = re.exec(css))) m[2].split(";").forEach(d => {
    const i = d.indexOf(":"); if (i === -1) return;
    const name = d.slice(0, i).trim(), raw = d.slice(i + 1).trim();
    if (!/^--/.test(name)) return;
    const imp = /!important$/.test(raw), value = raw.replace(/\s*!important$/, "").trim();
    (imp ? out.important : out.normal)[name] = value;
  });
  return out;
}
function ruleDefault(name) { const m = new RegExp("\"  " + name + ": ([^;]+);\\\\n\"").exec(FILES[THEME]); return m ? m[1] : null; }
async function themeInline(page) {
  /* the real theme engine on that page, wearing a member's theme with both corners lit */
  const theme = { v: 1, glow_a: "#ff3366", glow_a_alpha: 0.3, glow_b: "#3366ff", glow_b_alpha: 0.4 };
  const cache = JSON.stringify({ v: 1, uid: UID, fetched_at: Date.now() + 3600e3, state: { themes: [{ id: "th-1", name: "Mine", theme }], default_theme_id: "th-1", page_themes: {} } });
  const dom = new JSDOM("<!DOCTYPE html><html><head><script>" + FILES[THEME] + "</script></head><body></body></html>", {
    url: "https://bizforceai.net/" + page, runScripts: "dangerously", virtualConsole: new VirtualConsole(),
    beforeParse(win) {
      win.localStorage.setItem("bf_token", TOKEN); win.localStorage.setItem("bf_theme", cache);
      win.matchMedia = () => ({ matches: false, addEventListener() {}, addListener() {} });
      win.fetch = () => { const p = Promise.reject(new Error("no network")); p.catch(() => {}); return p; };
    }
  });
  await wait(5);
  const st = dom.window.document.documentElement.style;
  const out = { a: st.getPropertyValue("--bf-glow-a-alpha").trim(), b: st.getPropertyValue("--bf-glow-b-alpha").trim() };
  dom.window.close();
  return out;
}
/* The cascade for a token on <html>: an important page rule, then the inline theme, then a page rule, then the engine's default. */
function effective(name, decls, inline) {
  if (decls.important[name] !== undefined) return decls.important[name];
  if (inline && inline[name] !== undefined && inline[name] !== "") return inline[name];
  if (decls.normal[name] !== undefined) return decls.normal[name];
  return ruleDefault(name);
}
async function oracleChecks() {
  console.log("\n══ O. the Oracle pages: no bottom-right glow, the top-left glow kept, the same dark base ══");
  check("O0. the theme engine's defaults were read (top-left 0.14, bottom-right 0.18)", ruleDefault("--bf-glow-a-alpha") === "0.14" && ruleDefault("--bf-glow-b-alpha") === "0.18");
  const wrong = [];
  for (const f of ORACLE_PAGES.concat(["dashboard.html"])) {
    const now = rootDecls(FILES[f] || ""), old = rootDecls(gitShow(BEFORE, f) || "");
    const t = await themeInline(f);
    const inline = { "--bf-glow-a-alpha": t.a, "--bf-glow-b-alpha": t.b };
    const row = {
      page: f, theme: t,
      a: [effective("--bf-glow-a-alpha", now, inline), effective("--bf-glow-a-alpha", old, inline), effective("--bf-glow-a-alpha", now, null), effective("--bf-glow-a-alpha", old, null)],
      b: [effective("--bf-glow-b-alpha", now, inline), effective("--bf-glow-b-alpha", old, inline), effective("--bf-glow-b-alpha", now, null), effective("--bf-glow-b-alpha", old, null)]
    };
    const oracle = ORACLE_PAGES.indexOf(f) !== -1;
    const ok = t.a === "0.3" && t.b === "0.4" &&
      row.a[0] === row.a[1] && row.a[2] === row.a[3] &&                                   // the top-left: exactly what it was, with a theme and without
      (oracle ? Number(row.b[0]) === 0 && Number(row.b[2]) === 0 : row.b[0] === row.b[1] && row.b[2] === row.b[3]);
    if (!ok) wrong.push(JSON.stringify(row));
  }
  check("O1. on every Oracle page the bottom-right glow is 0, with a member's theme (both corners lit) and without; the top-left glow is exactly what it was, both ways",
    wrong.length === 0, wrong.join(" | "));
  const drift = ORACLE_PAGES.filter(f => {
    const was = gitShow(BEFORE, f), now = FILES[f];
    if (was === null || now === null) return true;
    const A = was.split("\n"), B = now.split("\n");
    const added = B.filter(l => A.indexOf(l) === -1), lost = A.filter(l => B.indexOf(l) === -1);
    return lost.length !== 0 || added.length !== 2 || added[1].trim() !== ":root { --bf-glow-b-alpha: 0 !important; }" || !/^\s*\/\* An Oracle page \(Nov 8 2026\)/.test(added[0]);
  });
  check("O2. each Oracle page changes by exactly its comment and that one line since " + BEFORE + ": the base colour and every other line as they were", drift.length === 0, drift.join(", "));
  const elsewhere = (() => {
    const out = [];
    fs.readdirSync(FRONTEND).filter(f => /\.html$/.test(f) && ORACLE_PAGES.indexOf(f) === -1).forEach(f => { if (/--bf-glow-b-alpha:\s*0\s*!important/.test(fs.readFileSync(path.join(FRONTEND, f), "utf8"))) out.push(f); });
    return out;
  })();
  check("O3. no other page turns its bottom-right glow off", elsewhere.length === 0, elsewhere.join(", "));
}

(async function main() {
  if (!JSDOM) { check("jsdom is installed (npm i in the backend)", false); finish(); return; }
  try {
    await visualChecks();
    await iconChecks();
    await placementChecks();
    mistChecks();
    await oracleChecks();
  } catch (e) { check("the check ran to the end", false, e && e.stack); }
  finish();
})();
function finish() {
  closeAll();
  console.log("\n══ Z. zero network ══");
  check("Z1. no socket was opened and no name was looked up", NETWORK.length === 0, NETWORK.join(","));
  console.log("\n" + (failures === 0 ? "ALL " + passes + " CHECKS PASSED" : "CHECKS FAILED: " + failures + " of " + (passes + failures)));
  process.exit(failures === 0 ? 0 : 1);
}
