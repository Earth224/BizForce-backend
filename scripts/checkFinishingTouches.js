/* scripts/checkFinishingTouches.js — the owner's five finishing touches of Nov 8 2026, in the frontend:

   ══ What it proves ══════════════════════════════════════════════════════════
     V  THE MUSIC VISUAL IN "KEEP PLAYING BETWEEN PAGES" MODE (scripts/bf-music.js), in jsdom with a fake
        Web Audio, a fake BroadcastChannel and a fake API: the music plays in the pop-out while the page's
        own audio is paused, and the page's boombox display (its 48 spectrum bars, and its waveform) and
        speakers move with the frames the pop-out sends, about 30 a second, numbers only; they keep moving
        across a track change, a volume change and a page change; they go still when the pop-out pauses,
        and the pop-out sends nothing but one silent frame then. Under prefers-reduced-motion nothing is
        sent and the display is a still meter.
     I  THE MUSIC BUTTON (scripts/bf-boombox.js): one icon source, MUSIC_ICON, an eighth note flowing into a
        sine wave, every stroke and fill currentColor, used on the dashboard and as the floating icon on
        other pages; the button is the header's round control (40 px, 50%, the accent border, a glow on hover
        and focus, a visible focus ring), named aria-label and title "Music player"; the wave drifts only
        while music plays, and never under reduced motion; the old two-circle boombox icon is gone.
     P  THE PLACEMENT: centred between the logo's right edge and the header's horizontal centre, level with
        the logo; narrower, never closer than 24 px to the logo and never over another header item.
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
  // the two-circle boombox icon comes back
  "old-icon-restored": [[BOOMBOX, "      '<ellipse class=\"bfm-note-head\" cx=\"7.6\" cy=\"15\" rx=\"2.6\" ry=\"1.9\" transform=\"rotate(-22 7.6 15)\" fill=\"currentColor\" stroke=\"none\"/>' +\n",
    "      '<circle cx=\"6\" cy=\"14\" r=\"4\" fill=\"currentColor\"/><circle cx=\"18\" cy=\"14\" r=\"4\" fill=\"currentColor\"/>' +\n"]],
  // the icon is drawn in a fixed colour, not the theme's
  "icon-hardcoded-color": [[BOOMBOX, "viewBox=\"0 0 24 24\" width=\"22\" height=\"22\" fill=\"none\" stroke=\"currentColor\"", "viewBox=\"0 0 24 24\" width=\"22\" height=\"22\" fill=\"none\" stroke=\"#22d3ee\""]],
  // the button loses its name
  "icon-label-missing": [[BOOMBOX, "data-act=\"bbx-open\" aria-label=\"Music player\" title=\"Music player\">", "data-act=\"bbx-open\">"]],
  // the button creeps back toward the logo
  "placement-too-close": [[BOOMBOX, "  var ICON_MIN_GAP = 24;", "  var ICON_MIN_GAP = 4;"]],
  // the wave keeps drifting under prefers-reduced-motion
  "reduced-motion-ignored": [[BOOMBOX, "    \"@media (prefers-reduced-motion: reduce){.bfm-note-wave{animation:none!important}}\",\n", ""]],
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
    if (el.classList && el.classList.contains("bfm-float")) { const st = el.getAttribute("data-state"); return st === "box" ? { w: 440, h: 250 } : st === "icon" ? { w: 40, h: 40 } : { w: 300, h: 40 }; }
    const r = rectAttr(el); return r ? { w: r.w, h: r.h } : { w: 0, h: 0 };
  };
  Object.defineProperty(HE, "offsetWidth", { configurable: true, get() { return own(this).w; } });
  Object.defineProperty(HE, "offsetHeight", { configurable: true, get() { return own(this).h; } });
  HE.getBoundingClientRect = function () {
    const r = rectAttr(this);
    if (r) return { left: r.l, top: r.t, right: r.l + r.w, bottom: r.t + r.h, width: r.w, height: r.h, x: r.l, y: r.t };
    const z = own(this), l = parseFloat(this.style.left), t = parseFloat(this.style.top);
    const left = isNaN(l) ? 0 : l, top = isNaN(t) ? 0 : t;
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
  console.log("\n══ I. the music button: one icon, a note flowing into a wave, in the theme's colour ══");
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
      else if (/\.(html|js|css)$/.test(e.name) && rel !== BOOMBOX && /bfm-note-wave|bfm-icon-art|bbxIconBody|bbxIconChrome|bfm-icon-eq/.test(fs.readFileSync(path.join(FRONTEND, rel), "utf8"))) out.push(rel);
    });
    walk("");
    return out;
  })();
  check("I1. ... and no other frontend file draws a music icon of its own", others.length === 0, others.join(", "));
  const paints = svg ? Array.prototype.slice.call(svg.querySelectorAll("*")).concat([svg]).map(el => [el.getAttribute("stroke"), el.getAttribute("fill")]) : [];
  const colourOk = paints.length > 0 && paints.every(([st, fi]) => [null, "none", "currentColor"].indexOf(st) !== -1 && [null, "none", "currentColor"].indexOf(fi) !== -1) &&
    svg.getAttribute("stroke") === "currentColor" && !/#[0-9a-f]{3,6}\b|rgba?\(/i.test(ICON || "x");
  check("I2. every stroke and fill of the icon is currentColor (no colour of its own), so the theme's accent colours it", colourOk, JSON.stringify(paints));
  const rule = sel => { const i = BX.indexOf("\"" + sel + "{"); return i === -1 ? "" : BX.slice(i, BX.indexOf("}", i) + 1); };
  check("I2. ... the button's colour is the theme's accent token (var(--bf-accent-a3, #00e5ff)), and its border the accent's channels",
    /color:var\(--bf-accent-a3, #00e5ff\)/.test(rule(".bfm-icon")) && /border:1px solid rgba\(var\(--bf-accent-a3-rgb, 0, 229, 255\),\.32\)/.test(rule(".bfm-icon")), rule(".bfm-icon"));
  const shape = svg ? { ellipse: svg.querySelectorAll("ellipse").length, stem: !!svg.querySelector("path.bfm-note-stem"), wave: !!svg.querySelector("path.bfm-note-wave"), circles: svg.querySelectorAll("circle").length } : {};
  check("I3. the icon is an eighth note (a head, its stem and flag) flowing into a sine wave across the base, one stroke weight (1.8), on a 24 grid",
    shape.ellipse === 1 && shape.stem && shape.wave && svg.getAttribute("viewBox") === "0 0 24 24" && svg.getAttribute("stroke-width") === "1.8" &&
    /M-4 19c1\.5 0 1\.5-2 3-2s1\.5 2 3 2/.test(svg.querySelector("path.bfm-note-wave").getAttribute("d")), JSON.stringify(shape));
  check("I4. no two-circle boombox icon anywhere: no circle in the button, and none of the old icon's parts in bf-boombox.js",
    shape.circles === 0 && !/ICON_ART|bbxIconBody|bbxIconChrome|bfm-icon-eq|bfm-icon-sheen|bbx-icon-eq|bbx-icon-sheen/.test(BX.replace(/\/\*[\s\S]*?\*\//g, "")));
  check("I5. the button is named: aria-label and title \"Music player\", a real button",
    !!icon && icon.tagName === "BUTTON" && icon.getAttribute("type") === "button" && icon.getAttribute("aria-label") === "Music player" && icon.getAttribute("title") === "Music player",
    icon && icon.outerHTML.slice(0, 120));
  const uiBtn = (() => { const i = FILES[UI].indexOf(".topbar-icon-btn {"); return i === -1 ? "" : FILES[UI].slice(i, FILES[UI].indexOf("}", i)); })();
  check("I6. it matches the header's round control (css/bizforce-ui.css .topbar-icon-btn: 40 px, round, a one-pixel accent border, the dark glass)",
    /width: 40px;/.test(uiBtn) && /height: 40px;/.test(uiBtn) && /border-radius: 50%;/.test(uiBtn) && D.BFBoombox.ICON_W === 40 && D.BFBoombox.ICON_H === 40 &&
    /border-radius:50%/.test(rule(".bfm-icon")) && /background:rgba\(8,12,28,\.85\)/.test(rule(".bfm-icon")) && css(D, icon).width === "40px" && css(D, icon).height === "40px");
  check("I6. ... a soft glow on hover and on focus, and a visible focus ring",
    /"\.bfm-icon:hover,\.bfm-icon:focus-visible\{border-color:rgba\(var\(--bf-accent-a3-rgb, 0, 229, 255\),\.6\);box-shadow:0 0 16px rgba\(var\(--bf-accent-a3-rgb, 0, 229, 255\),\.25\)\}"/.test(BX) &&
    /"\.bfm-icon:focus-visible\{outline:2px solid var\(--bf-accent-a, #22d3ee\);outline-offset:2px\}"/.test(BX));
  const waveEl = icon && icon.querySelector(".bfm-note-wave");
  const stillAtFirst = !/bfm-note-wave/.test(css(D, waveEl).animation || "");
  D.BFMusic.playTrack(T1); D.document.dispatchEvent(new D.Event("pointerdown", { bubbles: true })); await settle();
  D.BFMusic.play(); await settle();
  const drifting = D.BFMusic.playing() && /bfm-note-wave/.test(css(D, waveEl).animation || "");
  D.BFMusic.pause(); await settle();
  const stillAgain = !/bfm-note-wave/.test(css(D, waveEl).animation || "");
  check("I7. while music plays the wave drifts (a slow phase shift, one period every 3 s); paused, it is still",
    stillAtFirst && drifting && stillAgain && /"@keyframes bfm-note-wave\{from\{transform:translateX\(0\)\}to\{transform:translateX\(-6px\)\}\}"/.test(BX) &&
    /"\.bfm-float\[data-playing=true\] \.bfm-note-wave\{animation:bfm-note-wave 3s linear infinite\}"/.test(BX), [stillAtFirst, drifting, stillAgain].join());
  check("I8. under prefers-reduced-motion the wave never moves", /"@media \(prefers-reduced-motion: reduce\)\{\.bfm-note-wave\{animation:none!important\}\}"/.test(BX));
  closeOne(D); await settle();
  /* the floating icon on another page is the same button */
  const Q = await openPage({ page: "crm.html", live: true, store: { v: 1, uid: UID, track_id: T1, position: 5 }, name: "floating" });
  Q.localStorage.setItem("bf_boombox", JSON.stringify({ state: "icon" }));
  const QB = Q.document.querySelector(".bfm-float");
  Q.BFMusic._box().setState("icon");
  const qi = Q.document.querySelector(".bfm-icon");
  check("I9. the floating icon on another page is the same button and the same icon",
    !!qi && qi.innerHTML === parsed && qi.getAttribute("aria-label") === "Music player" && QB.getAttribute("data-state") === "icon");
  closeOne(Q); await settle();
}

/* ════ P. the placement ════ */
async function placementChecks() {
  console.log("\n══ P. the music button sits between the logo and the header's centre ══");
  const spotOf = w => { const r = w.document.querySelector(".bfm-float"); return { left: parseFloat(r.style.left), top: parseFloat(r.style.top) }; };
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
  /* crowded: no room on the header's row: below the header, under the logo, at least 24 px from it, over nothing */
  const CROWD = '<header class="topbar" data-rect="0,0,360,68"><div class="topbar-brand" data-bf-boombox-anchor data-rect="16,14,166,40">BizForce AI</div>' +
    '<div class="topbar-actions"><a href="agents-hub.html" data-rect="220,16,60,36">Agents</a><div class="topbar-user" data-rect="290,14,56,40">BF</div></div></header>';
  const C = await openPage({ name: "crowded", width: 360, header: CROWD });
  const pc = spotOf(C), logoC = C.document.querySelector("[data-bf-boombox-anchor]").getBoundingClientRect();
  check("P3. on a crowded header (360 px) with no room on its row, it sits just below the header under the logo: at least 24 px from the logo and over no header item",
    pc.left === 16 && pc.top === 80 && gapToLogo(pc, logoC) >= 24 && !items(C).some(b => hit(box(pc), b)), JSON.stringify(pc));
  closeOne(C); await settle();
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
