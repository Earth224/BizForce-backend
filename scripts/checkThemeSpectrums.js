/* scripts/checkThemeSpectrums.js — Block 4d: three-colour spectrums, the ten
   designed presets, every gradient on the app's pages following the theme,
   corner opacity and size, the photo editor, and the four motion styles.

   ══ What it proves ══════════════════════════════════════════════════════════
     S  THE DEFAULT IS TODAY'S, BYTE FOR BYTE. Every frontend file changed since
        frontend ${BEFORE} reads, with every Block 4d token resolved to its own
        fallback (scripts/_unthemed.js), exactly as it did then; the files
        edited by hand are named, each with its own proof. With no theme the
        engine sets no new token, and its tokens and readability for today's
        look are the old engine's, key for key.
     N  NOTHING LEFT IN THE OLD PALETTE. A scan of every frontend .html, .css
        and .js finds no #22d3ee, #a855f7, #06b6d4, #8b5cf6, #00e5ff, #7b2ff7
        (or their rgb()/rgba() channels) that is not a token's fallback, a
        guarded BFTheme.color() fallback, or on the named allow-list: the
        engine's own defaults, the backdrop's token values, public pages, a
        digital card's own look and a profile's own accent (both the member's
        data, shown as theirs).
     P  TEN DESIGNED PRESETS, plus Original: each complete (every preset key,
        each a valid value the server accepts unchanged), readable on noir as
        it is (no shade, no element corrected), and smooth: no two adjacent
        stops of any of its spectrums more than ${SMOOTH} apart in OKLab (the
        original two-stop blend is 0.358).
     M  THE MIDDLE TONE, recomputed from its documented words (OKLCH: mean
        lightness, mean chroma lifted 15%, hue at the midpoint of the shorter
        arc, a near-grey end giving no hue, brought into sRGB by lowering
        chroma), on the server and in the page alike; and a middle stop on the
        line (the ends' sRGB midpoint, within 2) draws nothing new.
     V  THE VALIDATOR'S NEW FIELDS: each number clamped to its range, each
        enum and colour refused when wrong, naming the key.
     O  CORNER OPACITY AND SIZE: opacity 0 draws nothing at the glow's centre,
        100 draws the colour itself; size moves where the glow fades out; the
        studio's sliders run 0–100% and 10–100%.
     F  THE PHOTO EDITOR: fill, fit and custom zoom, the focal point, blur (the
        layer grown so no soft rim shows) and feathered edges, as pure CSS from
        validated numbers, clamped; and readability still holds with them.
     A  MOTION: the four styles animate transform and opacity only, on the
        glow layer alone, at a pace and amplitude that is clearly visible at
        the default; paused while the tab is hidden; off under reduced motion
        (in the CSS and in the tokens).
     E  BFTheme.setLiveEnergy(0..1) exists, is clamped, and feeds the motion.
     L  OLD THEMES LOAD IDENTICALLY: a theme saved before Block 4d gives the
        same tokens from the new engine as from the old one, as saved and
        after the server's validator.

   MUTATE=<name> edits the files IN MEMORY; MUTATE=all runs each in its own
   process. BIZFORCE_FRONTEND_DIR overrides the frontend location. No network,
   no database. */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { execFileSync } = require("child_process");
const s = require("./_shared");
const { unthemed } = require("./_unthemed");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const BEFORE = "5dcfa3c";   // the frontend before Block 4d
const AFTER = "74f1d37";    // the frontend commit that landed Block 4d
const SMOOTH = 0.36;
const MUTATE = process.env.MUTATE || "";
const THEME = "scripts/bf-theme.js", STUDIO = "scripts/bf-theme-studio.js", SETTINGS = "settings.html", LIB = "lib/themes.js";
const PROFILE_JS = "scripts/agent-profile.js";
const UID = "aaaaaaaa-0000-4000-8000-000000000001";   // a member, for photo paths in their own folder

/* Each mutation: [file, from, to]. Every one must make a check fail. */
const MUTATIONS = {
  // a heading left on a hard-coded gradient
  "heading-hard-coded": [["bizdoc.html",
    ".modal-title{font-size:1.15rem;font-weight:800;background:linear-gradient(135deg,var(--bf-accent-a3, #00e5ff)var(--bf-accent-mid, ),var(--bf-accent-b, #a855f7))",
    ".modal-title{font-size:1.15rem;font-weight:800;background:linear-gradient(135deg,#00e5ff,#a855f7)"]],
  // a preset missing an element
  "preset-missing-element": [[THEME, "glow_mid_alpha: 0.05, mid_auto: false, match_all: false, btn_a: \"#986805\", btn_mid: \"#e0103a\", ",
    "glow_mid_alpha: 0.05, mid_auto: false, match_all: false, btn_a: \"#986805\", "]],
  // the corner opacity not applied
  "opacity-not-applied": [[THEME, "\"--bf-glow-a-alpha\": String(t.glow_a_alpha),", "\"--bf-glow-a-alpha\": String(DEFAULT_THEME.glow_a_alpha),"]],
  // the photo's focal point ignored
  "photo-position-ignored": [[THEME, String.raw`"    var(--bf-bg-image) var(--bf-bg-pos, center) / var(--bf-bg-size, cover) no-repeat,\n" +`,
    String.raw`"    var(--bf-bg-image) center / var(--bf-bg-size, cover) no-repeat,\n" +`]],
  // the feathered edge missing
  "feather-missing": [[THEME, String.raw`"    var(--bf-bg-feather, linear-gradient(transparent, transparent)),\n" +` + "\n", ""]],
  // motion left running under reduced motion
  "motion-under-reduced": [[THEME, String.raw`"  :root[data-bf-alive=\"1\"][data-bf-motion] body::before { inset: 0; animation: none; will-change: auto; }\n" +` + "\n", ""]],
  // motion animating a layout property
  "motion-layout-property": [[THEME, String.raw`"  50%  { transform: rotate(0deg) scale(`, String.raw`"  50%  { width: 110%; transform: rotate(0deg) scale(`]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const lf = t => t.replace(/\r\n/g, "\n");
function walk(dir, out) {
  for (const n of fs.readdirSync(dir)) {
    if (n === "node_modules" || n.startsWith(".")) continue;
    const p = path.join(dir, n), st = fs.statSync(p);
    if (st.isDirectory()) walk(p, out); else if (/\.(html|js|css)$/.test(n)) out.push(path.relative(FRONTEND, p).replace(/\\/g, "/"));
  }
  return out;
}
if (!fs.existsSync(path.join(FRONTEND, THEME))) { console.log("    FAIL  frontend not found at " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
const FILES = {};
walk(FRONTEND, []).forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8")); });
FILES[LIB] = lf(fs.readFileSync(path.join(REPO, LIB), "utf8"));
function gitShow(commit, f) {
  try { return lf(execFileSync("git", ["-C", FRONTEND, "show", commit + ":" + f], { encoding: "utf8", maxBuffer: 64 << 20, stdio: ["ignore", "pipe", "ignore"] })); }
  catch (e) { return null; }
}

if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* bf-theme.js in a small window: its document root's style and attributes are
   plain records, so what the engine sets is read back exactly. */
function loadEngine(src, opts) {
  opts = opts || {};
  const props = {}, attrs = {}, listeners = {};
  const root = {
    style: { setProperty(k, v) { props[k] = String(v); }, removeProperty(k) { delete props[k]; }, getPropertyValue(k) { return props[k] || ""; } },
    getAttribute(k) { return k in attrs ? attrs[k] : null; }, setAttribute(k, v) { attrs[k] = String(v); }, removeAttribute(k) { delete attrs[k]; }
  };
  const doc = {
    documentElement: root, readyState: "complete", hidden: !!opts.hidden,
    getElementById() { return null; }, createElement() { return {}; }, head: { insertBefore() {}, appendChild() {}, firstChild: null },
    addEventListener(n, f) { (listeners[n] = listeners[n] || []).push(f); }
  };
  const store = {};
  const win = {
    document: doc, location: { pathname: opts.path || "/crm.html", search: "", href: "https://bizforceai.net" + (opts.path || "/crm.html") },
    localStorage: { getItem(k) { return k in store ? store[k] : null; }, setItem(k, v) { store[k] = String(v); }, removeItem(k) { delete store[k]; } },
    matchMedia: q => ({ matches: !!opts.reduce && /prefers-reduced-motion: reduce/.test(q), addEventListener() {} }),
    getComputedStyle: () => ({ getPropertyValue: k => props[k] || "" }),
    atob: x => Buffer.from(x, "base64").toString("binary"), URL, URLSearchParams
  };
  win.window = win;
  const ctx = vm.createContext(Object.assign(win, { Object, Math, JSON, String, Number, Array, Promise, isFinite, Date, RegExp, Error, parseInt, parseFloat }));
  vm.runInContext(src, ctx);
  return { BT: win.BFTheme, props, attrs, listeners, doc, win };
}
let ENG, LIBX;
try { ENG = loadEngine(FILES[THEME]); } catch (e) { console.log("    FAIL  bf-theme.js did not run: " + e.message); process.exit(1); }
try {
  const Module = require("module"), file = path.join(REPO, LIB), m = new Module(file, module);
  m.filename = file; m.paths = Module._nodeModulePaths(path.dirname(file)); m._compile(FILES[LIB], file); LIBX = m.exports;
} catch (e) { console.log("    FAIL  lib/themes.js did not load: " + e.message); process.exit(1); }
const BT = ENG.BT, D = BT.DEFAULT_THEME;
const full = t => Object.assign({}, D, t);

/* ── OKLab, from Björn Ottosson's matrices, independent of both engines ─── */
const lin = c => { c /= 255; return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
const unlin = c => 255 * (c <= 0.0031308 ? 12.92 * c : 1.055 * Math.pow(c, 1 / 2.4) - 0.055);
const rgb = h => [1, 3, 5].map(i => parseInt(h.slice(i, i + 2), 16));
function oklab(h) {
  const [r, g, b] = rgb(h).map(lin);
  const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  const q = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * q, 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * q, 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * q];
}
function oklch(h) { const [L, a, b] = oklab(h); return [L, Math.hypot(a, b), (Math.atan2(b, a) * 180 / Math.PI + 360) % 360]; }
function srgbOfOklch(L, C, H) {
  const a = C * Math.cos(H * Math.PI / 180), b = C * Math.sin(H * Math.PI / 180);
  const l = Math.pow(L + 0.3963377774 * a + 0.2158037573 * b, 3), m = Math.pow(L - 0.1055613458 * a - 0.0638541728 * b, 3), q = Math.pow(L - 0.0894841775 * a - 1.2914855480 * b, 3);
  return [4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * q, -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * q, -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * q];
}
const inGamut = c => c.every(x => x >= -1e-4 && x <= 1 + 1e-4);
const dist = (x, y) => { const p = oklab(x), q = oklab(y); return Math.hypot(p[0] - q[0], p[1] - q[1], p[2] - q[2]); };
const hueGap = (x, y) => Math.abs(((y - x + 540) % 360) - 180);
/* The documented middle tone, from its own words: what it should be before rounding. */
function documentedMid(A, B) {
  const p = oklch(A), q = oklch(B);
  const L = (p[0] + q[0]) / 2;
  let C = (p[1] + q[1]) / 2, H;
  if (p[1] < 0.02 && q[1] < 0.02) H = p[2];
  else { C *= 1.15; H = p[1] < 0.02 ? q[2] : q[1] < 0.02 ? p[2] : (p[2] + (((q[2] - p[2] + 540) % 360) - 180) / 2 + 360) % 360; }
  return { L, C, H, grey: p[1] < 0.02 && q[1] < 0.02 };
}

/* ── S. the default is today's ────────────────────────────────────────── */
console.log("\n══ S. with no theme, every page is what it was at " + BEFORE + ", byte for byte ══");
/* The files Block 4d edited by hand, each with its own proof below or in checkThemes.js. */
const HAND = {
  [THEME]: "the engine: its tokens and readability for today's look are the old engine's (S3)",
  [STUDIO]: "the studio: section C of checkThemes.js runs it",
  [SETTINGS]: "the studio's page: checkThemes.js C and H3 pin its look, its preview and every theme line",
  "scripts/termaximus-guide.js": "two settings tips rewritten: checkThemes.js H3 pins its CSS, checkGuideStandard its tips",
  [PROFILE_JS]: "a chart colour left as var() by the browser is resolved (S2)"
};
/* NAMED BEFORE → AFTER (Oct 30 2026, the BizForce music player). BEFORE: S1 diffed the WORKING TREE against
   ${BEFORE}, so every later frontend edit (the music player's dashboard section, the rebuilt Terms) read as a
   Block 4d conversion gone wrong. AFTER: it proves Block 4d's own commit, ${BEFORE}..${AFTER}: the files that
   commit changed, as that commit left them. Later edits are proved by their own checks; the palette scan (N)
   still reads the working tree. */
let diffFiles = [];
try { diffFiles = execFileSync("git", ["-C", FRONTEND, "diff", "--name-only", BEFORE, AFTER], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim().split("\n").filter(Boolean); }
catch (e) { diffFiles = null; }
const proofWrong = [];
let proved = 0;
(diffFiles || []).forEach(f => {
  if (HAND[f] || !(f in FILES)) return;
  const was = gitShow(BEFORE, f);
  if (was === null) { proofWrong.push(f + ": new since " + BEFORE); return; }
  proved++;
  const at4d = gitShow(AFTER, f);
  if (at4d === null) { proofWrong.push(f + ": missing at " + AFTER); return; }
  const now = unthemed(at4d);
  if (now !== was) {
    const a = now.split("\n"), b = was.split("\n"); let i = 0; while (i < a.length && a[i] === b[i]) i++;
    proofWrong.push(f + " line " + (i + 1) + ": " + JSON.stringify((a[i] || "").slice(0, 120)) + " was " + JSON.stringify((b[i] || "").slice(0, 120)));
  }
});
check("S1. every one of the " + proved + " files Phase C converted reads, each token at its fallback, exactly as it did at " + BEFORE + " (as " + AFTER + " left it)",
  diffFiles !== null && proved >= 60 && proofWrong.length === 0, proofWrong.slice(0, 4).join(" || "));
check("S1. the files edited by hand are only the named five, each proved on its own: " + Object.keys(HAND).join(", "),
  diffFiles !== null && diffFiles.filter(f => HAND[f]).length === Object.keys(HAND).length);
const oldProfile = gitShow(BEFORE, PROFILE_JS) || "";
const NEW_V = /    var v = function \(name, fallback\) \{\n[\s\S]*?\n    \};\n/;
const OLD_V = "    var v = function (name, fallback) { var x = cs ? String(cs.getPropertyValue(name) || \"\").trim() : \"\"; return x || fallback; };\n";
check("S2. " + PROFILE_JS + ": the one hand edit is sigTheme's colour reader, which hands a chart a colour, never var(); the rest reads as it did",
  NEW_V.test(FILES[PROFILE_JS]) && unthemed(FILES[PROFILE_JS].replace(NEW_V, () => OLD_V)) === oldProfile && oldProfile.indexOf(OLD_V) !== -1);
const OLD = (() => { const t = gitShow(BEFORE, THEME); try { return t ? loadEngine(t) : null; } catch (e) { return null; } })();
const sameJson = (x, y) => JSON.stringify(x) === JSON.stringify(y);
/* Every key the old answer has, the new one has with the same value (the new one may say more: each element's
   middle, and the accents). */
const within = (was, now) => was !== null && typeof was === "object" ? !!now && typeof now === "object" && Object.keys(was).every(k => within(was[k], now[k])) : was === now;
check("S3. today's look: the new engine's tokens are the old engine's, key for key, and so is every figure of its readability",
  !!OLD && sameJson(BT.tokensFor(D, null, ENG.win), OLD.BT.tokensFor(OLD.BT.DEFAULT_THEME, null, OLD.win)) &&
  within(OLD.BT.readability(OLD.BT.DEFAULT_THEME), BT.readability(D)));
const defTok = BT.tokensFor(D, null, ENG.win);
check("S3. ... it sets no element token, no accent, no middle stop and no photo or motion token",
  BT.ELEMENT_TOKENS.every(t => !(t in defTok)) && BT.BACKDROP_4D_TOKENS.every(t => !(t in defTok)));
const ruleRoot = (() => { const m = /^:where\(:root\) \{([^}]*)\}/m.exec(BT.RULE); const o = {}; if (m) m[1].replace(/(--[a-z0-9-]+):\s*([^;]+);/g, (x, k, v) => { o[k] = v.trim(); }); return o; })();
check("S3. the rule's own defaults draw today's backdrop: the centre glow off, the corners at today's reach",
  ruleRoot["--bf-glow-m-alpha"] === "0" && ruleRoot["--bf-glow-a-reach"] === "38%" && ruleRoot["--bf-glow-b-reach"] === "40%" && ruleRoot["--bf-glow-m-reach"] === "45%");
check("S3. every middle stop on a page is var(--…-mid, ) with nothing as its fallback, so with no theme it draws nothing",
  Object.keys(FILES).every(f => !/var\(--(?:bf-(?:accent|btn|mark|guide)|tmx-chat-glow)-mid,(?! \))/.test(FILES[f])));

/* ── N. nothing left in the old palette ───────────────────────────────── */
console.log("\n══ N. no original-palette colour left on an app page that is not a token ══");
const HEXES = ["22d3ee", "06b6d4", "00e5ff", "a855f7", "8b5cf6", "7b2ff7"];
const CHANNELS = ["34,211,238", "6,182,212", "0,229,255", "168,85,247", "139,92,246", "123,47,247"];
const LIT = new RegExp("#(?:" + HEXES.join("|") + ")(?![0-9a-z])|rgba?\\(\\s*(?:" + CHANNELS.map(k => k.split(",").join("\\s*,\\s*")).join("|") + ")", "gi");
/* Ranges of `text` that are a rule whose selector matches `sel`, or a keyframes block. */
function ruleRanges(text, sel, keyframes) {
  const r = []; let m;
  if (keyframes) {
    const kf = /@keyframes\s+[\w-]+\s*\{/g;
    while ((m = kf.exec(text))) { let d = 0, j = m.index + m[0].length - 1; for (; j < text.length; j++) { if (text[j] === "{") d++; else if (text[j] === "}") { d--; if (d === 0) break; } } r.push([m.index, j + 1]); }
  }
  const rule = /([^{}]+)\{([^{}]*)\}/g;
  while ((m = rule.exec(text))) if (sel.test(m[1])) r.push([m.index, m.index + m[0].length]);
  return r;
}
const UNTHEMED_PAGES = LIBX.UNTHEMED;
/* The allow-list, each entry named. */
const ALLOWED_FILES = { [THEME]: "the engine: the token defaults themselves" };
const lineAt = (t, i) => t.slice(t.lastIndexOf("\n", i) + 1, t.indexOf("\n", i) === -1 ? t.length : t.indexOf("\n", i));
function allowedAt(f, t, i) {
  const before = t.slice(Math.max(0, i - 90), i);
  if (/var\(--[a-z0-9-]+,\s*$/i.test(before)) return "a token's fallback";
  if (/BFTheme\.color\((["'])--bf-accent-[a-z0-9]+\1, \1$/.test(before) || /BFTheme\.color\((["'])--bf-accent-[a-z0-9]+\1, \1[^"']*\1\) : \1$/.test(before)) return "a guarded BFTheme.color() fallback";
  if (/--bf-glow-[a-z0-9-]+\s*:\s*[^;{}]*$/.test(before)) return "a backdrop token's own value";
  if (/(?:\svalue|\sdata-color)=["']$/.test(before)) return "a colour input's starting value";
  if (/%23$/.test(before)) return "a data URI";
  const comments = /\/\*[\s\S]*?\*\/|<!--[\s\S]*?-->/g; let m;
  while ((m = comments.exec(t))) { if (m.index > i) break; if (i < m.index + m[0].length) return "a comment"; }
  if (f === "digital-cards.html") {
    if (ruleRanges(t, /\.card-|\.texture-|\.text-fx-|\.theme-btn|\.cust-/, true).some(([a, b]) => i >= a && i < b)) return "a digital card's own look";
  }
  if (f === "profile.html" && /accent|--pa\b|data-color|colorPicker/.test(lineAt(t, i))) return "the profile's own accent (the member's data)";
  return null;
}
const leftover = [], allowedCount = {};
let scanned = 0;
Object.keys(FILES).forEach(f => {
  if (f === LIB || ALLOWED_FILES[f]) return;
  if (/\.html$/.test(f) && UNTHEMED_PAGES.indexOf(path.basename(f)) !== -1) return;
  scanned++;
  const t = FILES[f]; let m; LIT.lastIndex = 0;
  while ((m = LIT.exec(t))) {
    const why = allowedAt(f, t, m.index);
    if (why) { allowedCount[why] = (allowedCount[why] || 0) + 1; continue; }
    leftover.push(f + ":" + t.slice(0, m.index).split("\n").length + " " + lineAt(t, m.index).trim().slice(0, 100));
  }
});
check("N1. the scan of " + scanned + " frontend files finds no original-palette colour outside the token defaults, public pages and the named exceptions (" +
  Object.keys(allowedCount).map(k => k + " " + allowedCount[k]).join("; ") + ")", leftover.length === 0 && scanned >= 80, leftover.slice(0, 5).join(" || "));
check("N1. ... and it would see one: the scan finds each of the six colours and their channels in the engine's defaults",
  HEXES.every(h => new RegExp("#" + h).test(FILES[THEME])) && CHANNELS.every(c => LIT.test(c.replace(/,/g, ", ").replace(/^/, "rgba(")) && !(LIT.lastIndex = 0)));
const chartGuards = Object.keys(FILES).filter(f => /BFTheme\.color\(["']--bf-accent-/.test(FILES[f]));
check("N2. charts and canvas colours read the tokens through BFTheme.color(), guarded so a page without the engine still draws (" + chartGuards.length + " files)",
  chartGuards.length >= 5 && chartGuards.every(f => (FILES[f].match(/BFTheme\.color\(/g) || []).length === (FILES[f].match(/typeof BFTheme !== "undefined" \? BFTheme\.color\(/g) || []).length));
ENG.props["--bf-accent-a"] = "#ff0000";
check("N2. BFTheme.color() gives the theme's colour when set, at the fallback's alpha for an rgba() fallback, and the fallback when not",
  BT.color("--bf-accent-a", "#22d3ee") === "#ff0000" && BT.color("--bf-accent-a", "rgba(34,211,238,0.35)") === "rgba(255, 0, 0, 0.35)" && BT.color("--bf-accent-b", "#a855f7") === "#a855f7",
  BT.color("--bf-accent-a", "rgba(34,211,238,0.35)"));
delete ENG.props["--bf-accent-a"];

/* ── P. the presets ───────────────────────────────────────────────────── */
console.log("\n══ P. Original and the ten designed presets: complete, readable on noir, smooth ══");
const P = BT.PRESETS;
const IDS = ["original", "solar-flare", "deep-reef", "nebula", "emerald-throne", "obsidian-rose", "arctic", "phoenix", "amethyst", "black-sun", "mono-silver"];
check("P1. eleven presets: Original and the ten designed (" + P.map(p => p.name).join(", ") + ")", sameJson(P.map(p => p.id), IDS));
const HEXK = k => typeof D[k] === "string" && /^#/.test(D[k]);
const incomplete = P.filter(p => BT.PRESET_KEYS.some(k => !(k in p.theme) || (HEXK(k) ? !/^#[0-9a-f]{6}$/.test(p.theme[k]) : typeof p.theme[k] !== typeof D[k])) ||
  Object.keys(p.theme).some(k => BT.PRESET_KEYS.indexOf(k) === -1)).map(p => p.id);
check("P2. each is complete: every one of the " + BT.PRESET_KEYS.length + " preset keys (corners, middle tone, every element and its middle, the accents, the mist), each a valid value",
  incomplete.length === 0 && ["glow_mid", "btn_mid", "accent_a", "accent_mid", "accent_b", "chat_glow_mid", "mist_whisper"].every(k => BT.PRESET_KEYS.indexOf(k) !== -1), incomplete.join(","));
const notAccepted = P.filter(p => { const v = LIBX.validateTheme(full(p.theme), UID); return !v.theme || BT.PRESET_KEYS.some(k => v.theme[k] !== p.theme[k]); }).map(p => p.id);
check("P2. ... and the server accepts each as it is, every value kept", notAccepted.length === 0, notAccepted.join(","));
const unreadable = P.map(p => { const r = BT.readability(full(p.theme)); return { id: p.id, r }; })
  .filter(x => x.r.scrim > 0 || x.r.elementsFixed || x.r.ratios.text < 7 || x.r.ratios.muted < 4.5).map(x => x.id + " (scrim " + x.r.scrim + ", text " + x.r.ratios.text.toFixed(2) + ", muted " + x.r.ratios.muted.toFixed(2) + ")");
check("P3. each is readable on noir as designed: body text 7:1, muted 4.5:1, and no shade or element correction needed", unreadable.length === 0, unreadable.join("; "));
const SPECTRA = [["glow_a", "glow_mid", "glow_b"], ["btn_a", "btn_mid", "btn_b"], ["mark_a", "mark_mid", "mark_b"], ["guide_a", "guide_mid", "guide_b"], ["accent_a", "accent_mid", "accent_b"], ["chat_glow_a", "chat_glow_mid", "chat_glow_b"]];
let worstStep = 0;
const rough = [];
P.filter(p => p.id !== "original").forEach(p => SPECTRA.forEach(sp => {
  for (let i = 0; i < 2; i++) { const d = dist(p.theme[sp[i]], p.theme[sp[i + 1]]); worstStep = Math.max(worstStep, d); if (d > SMOOTH) rough.push(p.id + " " + sp[i] + "→" + sp[i + 1] + " " + d.toFixed(3)); }
}));
const originalBlend = dist("#00e5ff", "#a855f7");
check("P4. each designed preset is smooth: no adjacent stops of its six spectrums more than " + SMOOTH + " apart in OKLab (worst " + worstStep.toFixed(3) +
  "; the original two-stop blend is " + originalBlend.toFixed(3) + ")", rough.length === 0 && originalBlend < SMOOTH, rough.join("; "));
check("P4. ... each has a real middle: its middle tone is off the line between its corners, so its spectrums have three colours",
  P.filter(p => p.id !== "original").every(p => !BT.onTheLine(p.theme.glow_a, p.theme.glow_mid, p.theme.glow_b)));
const distinctCorners = new Set(P.map(p => p.theme.glow_a + p.theme.glow_mid + p.theme.glow_b)).size;
check("P5. the eleven are distinct, and Original is today's look exactly", distinctCorners === 11 &&
  BT.PRESET_KEYS.every(k => k === "mid_auto" || P[0].theme[k] === D[k]) && sameJson(BT.tokensFor(full(P[0].theme), null, ENG.win), defTok));

/* ── M. the middle tone ───────────────────────────────────────────────── */
console.log("\n══ M. the middle tone: the OKLCH midpoint, on the server and in the page ══");
const PAIRS = [["#00e5ff", "#a855f7"], ["#ff7a18", "#ff2e63"], ["#ffb000", "#6b1f73"], ["#000000", "#ffffff"], ["#808080", "#ff0000"], ["#ff0000", "#00ffff"],
  ["#123456", "#fedcba"], ["#34d399", "#22c55e"], ["#0a0a0a", "#0b0b0b"], ["#3ff5e0", "#7a5a12"], ["#e8f8ff", "#3b6e9e"], ["#eef1f6", "#4a505b"]];
for (let i = 0; i < 28; i++) { const r = () => "#" + Math.floor(((Math.sin(i * 7.31 + PAIRS.length) + 1) / 2) * 0xffffff).toString(16).padStart(6, "0"); const a = r(); i++; PAIRS.push([a, r()]); }
const midWrong = [];
PAIRS.forEach(([A, B]) => {
  const got = LIBX.midTone(A, B), page = BT.midTone(A, B);
  if (got !== page) { midWrong.push(A + "+" + B + ": server " + got + ", page " + page); return; }
  if (!/^#[0-9a-f]{6}$/.test(got)) { midWrong.push(A + "+" + B + ": " + got); return; }
  const want = documentedMid(A, B), [L, C, H] = oklch(got);
  if (Math.abs(L - want.L) > 0.02) midWrong.push(A + "+" + B + " lightness " + L.toFixed(3) + " vs " + want.L.toFixed(3));
  if (C > want.C + 0.012) midWrong.push(A + "+" + B + " chroma " + C.toFixed(3) + " over " + want.C.toFixed(3));
  if (!want.grey && C > 0.04 && hueGap(H, want.H) > 4) midWrong.push(A + "+" + B + " hue " + H.toFixed(1) + " vs " + want.H.toFixed(1));
  // chroma lowered only as far as sRGB needs: 0.01 more would be out of gamut, or none was lowered
  if (!want.grey && C < want.C - 0.012 && inGamut(srgbOfOklch(want.L, C + 0.01, want.H))) midWrong.push(A + "+" + B + " chroma lowered more than sRGB needs (" + C.toFixed(3) + ")");
});
check("M1. the middle tone is the documented OKLCH midpoint (mean lightness, chroma lifted 15%, the shorter hue arc, into sRGB by lowering chroma), server and page alike (" + PAIRS.length + " pairs)",
  midWrong.length === 0, midWrong.slice(0, 4).join("; "));
const grey = documentedMid("#808080", "#ff0000"), gotGrey = oklch(LIBX.midTone("#808080", "#ff0000"));
check("M1. a near-grey end gives no hue: grey and red meet at red's hue", hueGap(gotGrey[2], oklch("#ff0000")[2]) < 4 && hueGap(grey.H, oklch("#ff0000")[2]) < 0.01);
check("M1. two greys stay grey, with no lift", oklch(LIBX.midTone("#000000", "#ffffff"))[1] < 0.01);
const onLine = BT.mixHex("#ff7a18", "#ff2e63", 0.5);
const offTok = BT.tokensFor(full({ btn_a: "#ff7a18", btn_mid: "#22c55e", btn_b: "#ff2e63" }), null, ENG.win);
const onTok = BT.tokensFor(full({ btn_a: "#ff7a18", btn_mid: onLine, btn_b: "#ff2e63" }), null, ENG.win);
check("M2. a middle stop on the line (the ends' midpoint " + onLine + ") draws nothing new: no middle token; one off it is a third stop (\", #hex\")",
  !("--bf-btn-mid" in onTok) && offTok["--bf-btn-mid"] === ", #22c55e" && BT.onTheLine("#ff7a18", "#fd5640", "#ff2e63") && !BT.onTheLine("#ff7a18", "#ff5841", "#ff2e63") &&
  ["#ff7a18", "#ff2e63", "#fd5640", "#ff5841"].every(x => LIBX.onTheLine("#ff7a18", x, "#ff2e63") === BT.onTheLine("#ff7a18", x, "#ff2e63")));
const auto = LIBX.validateTheme(full({ glow_a: "#ff7a18", glow_b: "#ff2e63", mid_auto: true, glow_mid: "#000000" }), UID).theme;
const own = LIBX.validateTheme(full({ glow_a: "#ff7a18", glow_b: "#ff2e63", mid_auto: false, glow_mid: "#123abc" }), UID).theme;
check("M3. with \"Derive from corners\" on, the middle tone is always midTone(A, B); turned off, the member's own is kept, on the server and in the page",
  auto.glow_mid === LIBX.midTone("#ff7a18", "#ff2e63") && own.glow_mid === "#123abc" &&
  BT.normalTheme(full({ glow_a: "#ff7a18", glow_b: "#ff2e63", mid_auto: true, glow_mid: "#000000" })).glow_mid === auto.glow_mid &&
  BT.normalTheme(full({ glow_a: "#ff7a18", glow_b: "#ff2e63", mid_auto: false, glow_mid: "#123abc" })).glow_mid === "#123abc");
const mt = BT.tokensFor(full({ glow_mid: "#22c55e", mid_auto: false, glow_mid_alpha: 0.2 }), null, ENG.win);
check("M4. the middle tone reaches the backdrop: a centre glow in it, at its own strength", mt["--bf-glow-m-rgb"] === "34, 197, 94" && mt["--bf-glow-m-alpha"] === "0.2" &&
  /radial-gradient\(circle at var\(--bf-glow-m-at\), rgba\(var\(--bf-glow-m-rgb\), var\(--bf-glow-m-alpha\)\), transparent var\(--bf-glow-m-reach\)\)/.test(BT.RULE));

/* ── V. the validator's new fields ────────────────────────────────────── */
console.log("\n══ V. lib/themes.js: the new fields, validated ══");
const v = x => LIBX.validateTheme(full(x), UID);
const clampWrong = [];
Object.keys(LIBX.RANGES).forEach(k => {
  const [lo, hi] = LIBX.RANGES[k];
  const a = v({ [k]: lo - 1000 }), b = v({ [k]: hi + 1000 }), c = v({ [k]: "5" }), d = v({ [k]: NaN });
  if (!a.theme || a.theme[k] !== lo) clampWrong.push(k + " low");
  if (!b.theme || b.theme[k] !== hi) clampWrong.push(k + " high");
  if (!c.error || c.key !== k) clampWrong.push(k + " text accepted");
  if (!d.error || d.key !== k) clampWrong.push(k + " NaN accepted");
  if (JSON.stringify(BT.RANGES[k]) !== JSON.stringify(LIBX.RANGES[k])) clampWrong.push(k + " page range differs");
});
check("V1. every number is clamped to its range, the same in the page (" + Object.keys(LIBX.RANGES).join(", ") + "), and text or NaN is refused naming the key",
  clampWrong.length === 0 && ["glow_a_size", "glow_mid_size", "photo_zoom", "photo_x", "photo_blur", "photo_feather", "motion_speed", "motion_intensity", "glow_mid_alpha"].every(k => LIBX.RANGES[k]), clampWrong.join(", "));
const enumWrong = [["photo_fit", "stretch"], ["photo_fit", "Fill"], ["motion", "spin"], ["motion", ""], ["mid_auto", "yes"], ["glow_mid", "#FFF"], ["glow_mid", "red;}"],
  ["btn_mid", "var(--x)"], ["accent_a", "url(x)"], ["accent_mid", 255], ["chat_glow_mid", "#12345"]].filter(([k, bad]) => { const r = v({ [k]: bad }); return !r.error || r.key !== k; });
check("V2. a wrong fit, motion style, middle-tone switch or middle/accent colour is refused, naming the key (11 cases)", enumWrong.length === 0, enumWrong.map(x => x.join("=")).join(", "));
const good = v({ photo_fit: "custom", photo_zoom: 150, photo_x: 20, photo_y: 80, photo_blur: 6, photo_feather: 25, motion: "nebula", motion_speed: 2, motion_intensity: 1,
  glow_a_size: 60, glow_mid_alpha: 0.3, accent_a: "#ff7a18", mid_auto: false, glow_mid: "#123abc" }).theme;
check("V2. ... and good values are kept exactly", !!good && good.photo_fit === "custom" && good.photo_zoom === 150 && good.motion === "nebula" && good.motion_speed === 2 &&
  good.glow_a_size === 60 && good.accent_a === "#ff7a18" && good.glow_mid === "#123abc");
check("V3. the page reads a stored theme the same way: unknown enum values fall back to the default, numbers clamp",
  BT.normalTheme(full({ photo_fit: "stretch", motion: "spin", photo_blur: 99, glow_a_alpha: 7 })).photo_fit === "fill" &&
  BT.normalTheme(full({ motion: "spin" })).motion === D.motion && BT.normalTheme(full({ photo_blur: 99 })).photo_blur === 20 && BT.normalTheme(full({ glow_a_alpha: 7 })).glow_a_alpha === 1);

/* ── O. corner opacity and size ───────────────────────────────────────── */
console.log("\n══ O. corner opacity 0–100% and size ══");
/* The colour at a glow's centre over the noir middle, from the rule's own layer and the tokens. */
function centreOf(tok, which) {
  const layer = new RegExp("rgba\\(var\\(--bf-glow-" + which + "-rgb\\), var\\(--bf-glow-" + which + "-alpha\\)\\), transparent var\\(--bf-glow-" + which + "-reach\\)").test(BT.RULE);
  if (!layer) return null;
  const ch = (tok["--bf-glow-" + which + "-rgb"] || ruleRoot["--bf-glow-" + which + "-rgb"]).split(",").map(Number), al = Number(tok["--bf-glow-" + which + "-alpha"]);
  return ch.map(c => Math.round(al * c));
}
const zero = BT.tokensFor(full({ glow_a: "#ff7a18", glow_a_alpha: 0 }), null, ENG.win), one = BT.tokensFor(full({ glow_a: "#ff7a18", glow_a_alpha: 1 }), null, ENG.win);
check("O1. opacity 0 draws nothing: the glow's centre is the noir middle itself", sameJson(centreOf(zero, "a"), [0, 0, 0]), JSON.stringify(centreOf(zero, "a")));
check("O1. opacity 100 is solid: the glow's centre is the colour itself (#ff7a18)", sameJson(centreOf(one, "a"), [255, 122, 24]), JSON.stringify(centreOf(one, "a")));
const half = BT.tokensFor(full({ glow_b: "#6366f1", glow_b_alpha: 0.5 }), null, ENG.win);
check("O1. ... and the other corner the same: 50% is half the colour", sameJson(centreOf(half, "b"), [Math.round(0.5 * 99), Math.round(0.5 * 102), Math.round(0.5 * 241)]));
const sz = BT.tokensFor(full({ glow_a_size: 70, glow_b_size: 15 }), null, ENG.win);
check("O2. a corner's size is where its glow fades out (--bf-glow-a-reach 70%, -b 15%); at today's size no token is set",
  sz["--bf-glow-a-reach"] === "70%" && sz["--bf-glow-b-reach"] === "15%" && !("--bf-glow-a-reach" in defTok));
const studioRange = id => { const m = new RegExp("<input[^>]*id=\"" + id + "\"[^>]*>").exec(FILES[SETTINGS]); return m ? m[0] : ""; };
check("O3. the studio's Opacity sliders run 0–100% and its Size sliders 10–100%, for both corners and the centre glow",
  ["tsGlowAAlpha", "tsGlowBAlpha", "tsGlowMidAlpha"].every(id => /min="0" max="100"/.test(studioRange(id))) &&
  ["tsGlowASize", "tsGlowBSize", "tsGlowMidSize"].every(id => /min="10" max="100"/.test(studioRange(id))));
const bright = BT.readability(full({ glow_a: "#ffff00", glow_a_alpha: 1, glow_b: "#ffffff", glow_b_alpha: 1 }));
check("O4. full opacity is still protected: body text 7:1 and muted 4.5:1 at the brightest point (scrim " + bright.scrim + ")", bright.ratios.text >= 7 && bright.ratios.muted >= 4.5 && bright.scrim > 0);

/* ── F. the photo editor ──────────────────────────────────────────────── */
console.log("\n══ F. the photo editor: zoom, focal point, fit, blur, feathered edges, as CSS ══");
const URL_OK = "https://x.supabase.co/storage/v1/object/public/bf-public/theme-photos/" + UID + "/1700000000000.jpg";
const ph = x => BT.tokensFor(full(Object.assign({ middle: "photo", photo: "theme-photos/" + UID + "/1700000000000.jpg", photo_luma: 0.3 }, x)), URL_OK, ENG.win);
const fill = ph({}), fit = ph({ photo_fit: "fit" }), custom = ph({ photo_fit: "custom", photo_zoom: 180, photo_x: 20, photo_y: 75 });
check("F1. Fill sets no size or position (the rule's cover, centred); Fit whole is contain; Custom is the zoom as the photo's width",
  !("--bf-bg-size" in fill) && !("--bf-bg-pos" in fill) && fit["--bf-bg-size"] === "contain" && custom["--bf-bg-size"] === "180% auto");
check("F2. the focal point is the background position (20% 75%), and the rule places the photo by it",
  custom["--bf-bg-pos"] === "20% 75%" && /var\(--bf-bg-image\) var\(--bf-bg-pos, center\) \/ var\(--bf-bg-size, cover\) no-repeat/.test(BT.RULE));
const blur = ph({ photo_blur: 8 });
check("F3. blur 8 px is filter: blur(8px) on the photo layer, the layer grown 16 px past each edge so no soft rim shows",
  blur["--bf-bg-blur"] === "blur(8px)" && blur["--bf-bg-inset"] === "-16px" && /html::before \{\n[^}]*inset: var\(--bf-bg-inset, 0\);[^}]*filter: var\(--bf-bg-blur, none\);/.test(BT.RULE));
const fe = ph({ photo_feather: 30 });
const htmlLayers = (/html::before \{[\s\S]*?background:\n([\s\S]*?);\n/.exec(BT.RULE) || [])[1] || "";
check("F4. feathered edges 30% are four gradients from the backdrop colour to clear, one from each side, drawn over the photo and under the dim",
  fe["--bf-bg-feather"] === ["to right", "to left", "to bottom", "to top"].map(d0 => "linear-gradient(" + d0 + ", var(--bf-bg) 0%, transparent 30%)").join(", ") &&
  /^\s*linear-gradient\(rgba\(0, 0, 0, var\(--bf-bg-dim\)\)[^\n]*\n\s*var\(--bf-bg-feather, linear-gradient\(transparent, transparent\)\),\n\s*var\(--bf-bg-image\)/.test(htmlLayers), htmlLayers.slice(0, 200));
check("F5. the photo controls draw only with a photo: a colour middle sets none of them",
  ["--bf-bg-size", "--bf-bg-pos", "--bf-bg-blur", "--bf-bg-feather"].every(k => !(k in BT.tokensFor(full({ photo_fit: "custom", photo_zoom: 200, photo_x: 0, photo_blur: 5, photo_feather: 20 }), null, ENG.win))));
const clampP = v({ middle: "photo", photo: "theme-photos/" + UID + "/1700000000000.jpg", photo_zoom: 9999, photo_x: -40, photo_y: 140, photo_blur: 99, photo_feather: 80 });
const vu = LIBX.validateTheme(Object.assign(full({}), { middle: "photo", photo: "theme-photos/" + UID + "/1700000000000.jpg", photo_zoom: 9999, photo_x: -40, photo_y: 140, photo_blur: 99, photo_feather: 80 }), UID).theme;
check("F6. every photo number is clamped on the server (zoom 300, focal point 0 and 100, blur 20, feather 50) and the CSS follows",
  !!vu && vu.photo_zoom === 300 && vu.photo_x === 0 && vu.photo_y === 100 && vu.photo_blur === 20 && vu.photo_feather === 50 &&
  ph({ photo_fit: "custom", photo_zoom: 9999, photo_blur: 99 })["--bf-bg-size"] === "300% auto" && ph({ photo_blur: 99 })["--bf-bg-blur"] === "blur(20px)", JSON.stringify(clampP.error || ""));
const rPlain = BT.readability(full({ middle: "photo", photo: "x", photo_luma: 0.9, dim: 0.2 })), rSoft = BT.readability(full({ middle: "photo", photo: "x", photo_luma: 0.9, dim: 0.2, photo_blur: 20, photo_feather: 50 }));
check("F7. readability counts the dim and holds with blur and feathering (they only average the photo with itself and the darker backdrop): a bright photo is still protected to 7:1 / 4.5:1",
  rSoft.ratios.text >= 7 && rSoft.ratios.muted >= 4.5 && rSoft.dim >= rPlain.dim && rPlain.dim > 0.2);
const ST = FILES[STUDIO];
check("F8. the studio's focal point moves by arrow keys (2%, 10% with Shift) and +/- zooms by 10%, live; dragging sets it by pointer",
  /var step = e\.shiftKey \? 10 : 2;/.test(ST) && /e\.key === "ArrowLeft"\) editing\.photo_x = clampTo\("photo_x", editing\.photo_x - step\)/.test(ST) &&
  /e\.key === "ArrowDown"\) editing\.photo_y = clampTo\("photo_y", editing\.photo_y \+ step\)/.test(ST) &&
  /e\.key === "\+" \|\| e\.key === "="\) return \(e\.preventDefault\(\), zoomBy\(10\)\)/.test(ST) && /e\.key === "-" \|\| e\.key === "_"\) return \(e\.preventDefault\(\), zoomBy\(-10\)\)/.test(ST) &&
  /editing\.photo_fit = "custom";\n\s*editing\.photo_zoom = clampTo\("photo_zoom", editing\.photo_zoom \+ step\);\n\s*render\(\);/.test(ST) &&
  /pad\.addEventListener\("pointerdown"/.test(ST) && /pad\.addEventListener\("pointermove", function \(e\) \{ if \(dragging\) focusAt\(e\); \}\)/.test(ST) &&
  /id="tsFocus"[^>]*tabindex="0"/.test(FILES[SETTINGS]) && ["tsZoom", "tsBlur", "tsFeather", "tsDim"].every(id => studioRange(id)));

/* ── A. motion ────────────────────────────────────────────────────────── */
console.log("\n══ A. Alive corners: four styles, transform and opacity only, paused when hidden, off under reduced motion ══");
const KEYFRAMES = {};
BT.RULE.replace(/@keyframes ([\w-]+) \{\n([\s\S]*?)\n\}/g, (x, name, body) => { KEYFRAMES[name] = body; });
const STYLE_KF = { breathe: "bf-glow-drift", drift: "bf-glow-orbit", aurora: "bf-glow-aurora", nebula: "bf-glow-nebula" };
check("A1. the four styles, Breathe, Drift, Aurora and Nebula, each with its own keyframes", sameJson(BT.MOTIONS.slice().sort(), Object.keys(STYLE_KF).sort()) &&
  Object.keys(STYLE_KF).every(k => KEYFRAMES[STYLE_KF[k]]));
const propsWrong = [];
Object.keys(KEYFRAMES).forEach(name => KEYFRAMES[name].replace(/\{([^}]*)\}/g, (x, body) => {
  body.split(";").map(d0 => d0.trim()).filter(Boolean).forEach(d0 => { const p0 = d0.split(":")[0].trim(); if (p0 !== "transform" && p0 !== "opacity") propsWrong.push(name + ": " + p0); });
}));
check("A2. every keyframe of every style animates transform and opacity only (nothing that lays out or repaints the page)", propsWrong.length === 0 && Object.keys(KEYFRAMES).length >= 4, propsWrong.join(", "));
const aliveAll = []; BT.RULE.replace(/(:root\[data-bf-alive="1"\][^{]*body::before) \{([^}]*)\}/g, (x, sel, body) => { aliveAll.push({ sel, body }); });
/* The rules that set an animation (not the ones that stop it). */
const aliveRules = aliveAll.filter(r => /animation: bf-glow-/.test(r.body));
const outsideMedia = BT.RULE.split("@media (prefers-reduced-motion: reduce)")[0];
const animTargets = []; outsideMedia.replace(/([^{}\n]+)\{[^}]*animation(?:-name)?:\s*([\w-]+)/g, (x, sel, name) => { animTargets.push(sel.trim()); });
check("A2. ... and only the glow layer (body::before) moves; the page, its text and the photo stay put",
  animTargets.length >= 4 && animTargets.every(t => /body::before$/.test(t)), animTargets.join(" | "));
/* The largest movement at the default (k = 1): translate in %, rotate in deg, opacity dip. */
function amplitude(body) {
  let move = 0, turn = 0, dip = 0;
  body.replace(/calc\((-?[\d.]+)% \* var\(--bf-motion-k/g, (x, n) => { move = Math.max(move, Math.abs(Number(n))); });
  body.replace(/calc\((-?[\d.]+)deg \* var\(--bf-motion-k/g, (x, n) => { turn = Math.max(turn, Math.abs(Number(n))); });
  body.replace(/opacity: calc\(1 - ([\d.]+) \* var\(--bf-motion-k/g, (x, n) => { dip = Math.max(dip, Number(n)); });
  return { move, turn, dip };
}
const dur = {}; aliveRules.forEach(r => { const m = /animation: (bf-glow-[\w-]+) (\d+)s/.exec(r.body); if (m) dur[m[1]] = Number(m[2]); });
const weak = Object.keys(STYLE_KF).filter(k => { const a = amplitude(KEYFRAMES[STYLE_KF[k]]); return !(a.move >= 2.5 || a.turn >= 4) || a.dip < 0.12 || !(dur[STYLE_KF[k]] >= 15 && dur[STYLE_KF[k]] <= 45); })
  .map(k => k + " " + JSON.stringify(amplitude(KEYFRAMES[STYLE_KF[k]])) + " " + dur[STYLE_KF[k]] + "s");
check("A3. clearly visible at the default: each style moves the glows 2.5% or turns them 4°, dims them by 12% or more, on a 15–45 s cycle", weak.length === 0, weak.join("; "));
const tSpeed = BT.tokensFor(full({ alive: true, motion: "aurora", motion_speed: 2, motion_intensity: 0.3 }), null, ENG.win);
check("A4. Speed divides the cycle (calc(Ns / var(--bf-motion-speed, 1))) and Intensity scales every amplitude (--bf-motion-k, intensity over the default 0.6)",
  tSpeed["--bf-motion"] === "aurora" && tSpeed["--bf-motion-speed"] === "2" && tSpeed["--bf-motion-k"] === "0.5" &&
  aliveRules.length >= 4 && aliveRules.every(r => /animation-duration: calc\(\d+s \/ var\(--bf-motion-speed, 1\)\)/.test(r.body)));
check("A4. Breathe (the old drift) at the default speed and intensity sets no motion token: the old look, unchanged",
  ["--bf-motion", "--bf-motion-speed", "--bf-motion-k"].every(k => !(k in BT.tokensFor(full({ alive: true }), null, ENG.win))));
const hid = loadEngine(FILES[THEME], { hidden: true });
hid.BT.applyState({ default_theme_id: "t", page_themes: {}, themes: [{ id: "t", theme: full({ alive: true, motion: "drift" }) }] });
const pausedAtStart = hid.attrs["data-bf-motion-paused"] === "1" && hid.attrs["data-bf-motion"] === "drift";
hid.doc.hidden = false; (hid.listeners.visibilitychange || []).forEach(f0 => f0());
const resumed = !("data-bf-motion-paused" in hid.attrs);
hid.doc.hidden = true; (hid.listeners.visibilitychange || []).forEach(f0 => f0());
check("A5. paused while the tab is hidden: the page is marked paused, unmarked when it shows, marked again when hidden, and the CSS stops the animation there",
  pausedAtStart && resumed && hid.attrs["data-bf-motion-paused"] === "1" &&
  /:root\[data-bf-alive="1"\]\[data-bf-motion\]\[data-bf-motion-paused="1"\] body::before \{\n\s*animation-play-state: paused;/.test(BT.RULE),
  JSON.stringify(hid.attrs));
const media = (/@media \(prefers-reduced-motion: reduce\) \{\n([\s\S]*?)\n\}/.exec(BT.RULE) || [])[1] || "";
const stopped = media.split("\n").filter(l => /animation: none/.test(l)).map(l => l.trim().split(" {")[0]);
const moving = aliveRules.map(r => r.sel);
check("A6. off under reduced motion, in the CSS: every selector that animates is matched by a rule there that sets animation: none",
  moving.length >= 4 && moving.every(sel => stopped.some(st => st === sel || (/\[data-bf-motion\] body::before$/.test(st) && /\[data-bf-motion="[a-z]+"\] body::before$/.test(sel)) ||
    (st === ':root[data-bf-alive="1"] body::before' && sel === st))) && stopped.indexOf(':root[data-bf-alive="1"][data-bf-motion] body::before') !== -1 &&
    stopped.indexOf(':root[data-bf-alive="1"] body::before') !== -1, stopped.join(" | "));
const rmE = loadEngine(FILES[THEME], { reduce: true });
const rmTok = rmE.BT.tokensFor(full({ alive: true, motion: "nebula", motion_speed: 3 }), null, rmE.win);
rmE.BT.applyState({ default_theme_id: "t", page_themes: {}, themes: [{ id: "t", theme: full({ alive: true, motion: "nebula" }) }] });
check("A6. ... and in the tokens: --bf-alive 0, no style, no attribute", rmTok["--bf-alive"] === "0" && !("--bf-motion" in rmTok) && !("data-bf-motion" in rmE.attrs) && rmE.attrs["data-bf-alive"] !== "1" &&
  rmE.props["--bf-alive"] === "0", JSON.stringify(rmE.attrs));

/* ── E. live energy ───────────────────────────────────────────────────── */
console.log("\n══ E. BFTheme.setLiveEnergy(0..1) ══");
const le = loadEngine(FILES[THEME]);
const seen = [le.BT.setLiveEnergy(0.5), le.props["--bf-live-energy"], le.BT.setLiveEnergy(7), le.props["--bf-live-energy"], le.BT.setLiveEnergy(-3), le.props["--bf-live-energy"],
  le.BT.setLiveEnergy("0.4"), le.BT.setLiveEnergy(NaN), le.BT.setLiveEnergy(Infinity), le.BT.liveEnergy()];
check("E1. setLiveEnergy exists, clamps to 0..1 (7 is 1, -3 is 0), refuses what is not a number (0), and sets --bf-live-energy only above 0",
  typeof le.BT.setLiveEnergy === "function" && sameJson(seen, [0.5, "0.5", 1, "1", 0, undefined, 0, 0, 0, 0]), JSON.stringify(seen));
check("E2. the energy raises every style's amplitude: each keyframe scales by (1 + var(--bf-live-energy, 0))",
  Object.keys(STYLE_KF).every(k => { const b = KEYFRAMES[STYLE_KF[k]]; return (b.match(/var\(--bf-motion-k, 1\)/g) || []).length > 0 &&
    (b.match(/var\(--bf-motion-k, 1\)/g) || []).length === (b.match(/var\(--bf-motion-k, 1\) \* \(1 \+ var\(--bf-live-energy, 0\)\)/g) || []).length; }));

/* ── L. old themes load identically ───────────────────────────────────── */
console.log("\n══ L. a theme saved before Block 4d draws what it drew ══");
const oldD = OLD ? JSON.parse(JSON.stringify(OLD.BT.DEFAULT_THEME)) : {};
const LEGACY = [
  {}, { glow_a: "#ff7a18", glow_b: "#ff2e63", glow_a_alpha: 0.18, glow_b_alpha: 0.16 },
  { glow_a: "#6366f1", glow_b: "#f5c542", middle: "colour", bg: "#0a0a24", alive: true },
  { btn_a: "#ff7a18", btn_b: "#ff2e63", mist_core: "#22c55e", chat_glow_a: "#f97316", chat_glow_b: "#db2777", guide_a: "#fb923c", guide_b: "#f472b6", mark_a: "#fb923c", mark_b: "#f43f5e" },
  { match_all: true, glow_a: "#ff0000", glow_b: "#0000ff" },
  { glow_a: "#ffff00", glow_b: "#ffff00", glow_a_alpha: 0.5, glow_b_alpha: 0.5, btn_a: "#ffff00", btn_b: "#eeee00", guide_a: "#000010", mark_b: "#010101" },
  { middle: "photo", photo: "theme-photos/" + UID + "/1700000000000.jpg", photo_luma: 0.9, dim: 0.2, alive: true },
  { match_all: true, glow_a: "#34d399", glow_b: "#a855f7", alive: true, middle: "colour", bg: "#101820" }
];
const legacyWrong = [];
LEGACY.forEach((c, i) => {
  if (!OLD) return;
  const t = Object.assign({}, oldD, c);
  const was = JSON.stringify(OLD.BT.tokensFor(t, URL_OK, OLD.win)), now = JSON.stringify(BT.tokensFor(t, URL_OK, ENG.win));
  if (was !== now) legacyWrong.push(i + " as saved: " + now.slice(0, 160) + " vs " + was.slice(0, 160));
  const val = LIBX.validateTheme(t, UID);
  if (!val.theme) { legacyWrong.push(i + " refused: " + val.error); return; }
  if (LIBX.KEYS_4D.some(k => k in val.theme)) legacyWrong.push(i + " gained Block 4d keys when stored");
  if (JSON.stringify(BT.tokensFor(val.theme, URL_OK, ENG.win)) !== was) legacyWrong.push(i + " after the validator differs");
  if (!within(OLD.BT.readability(t), BT.readability(t))) legacyWrong.push(i + " readability differs");
});
check("L1. " + LEGACY.length + " themes saved before Block 4d: the new engine's tokens and readability are the old engine's (" + BEFORE + "), as saved and after the server's validator, which keeps them legacy",
  !!OLD && legacyWrong.length === 0, legacyWrong.slice(0, 3).join(" || "));
const leg = BT.normalTheme(Object.assign({}, oldD, { glow_a: "#ff7a18", glow_b: "#ff2e63", match_all: true }));
check("L2. a legacy theme's middles are its ends' midpoints and its accents the original, even under Match everything",
  leg.mid_auto === false && leg.glow_mid === BT.mixHex("#ff7a18", "#ff2e63", 0.5) && leg.btn_mid === BT.mixHex(leg.btn_a, leg.btn_b, 0.5) &&
  leg.accent_a === D.accent_a && leg.accent_b === D.accent_b);

console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
process.exit(failures ? 1 : 0);
