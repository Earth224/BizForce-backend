/* ══════════════════════════════════════════════════════════════════════════
   checkThemes.js — the theme engine and the Theme Studio (Block 4a).

   WHAT IT PROVES
     A  Phase A. The 57 app pages and css/agent-shell.css draw the backdrop
        from ONE token rule (scripts/bf-theme.js), with no inline backdrop
        left, and bf-theme.js is the first thing in each page's <head>. With no
        theme saved, each page renders TODAY's backdrop: the rule's defaults
        plus the page's own :root tokens are substituted, every gradient is
        parsed (shape, position, colour, alpha, stops) and compared, layer by
        layer, with the page's body::before at frontend 1b12268, read from git.
        Public pages never load bf-theme.js and keep their own rule; the
        studio-side list of pages that never wear a theme (UNTHEMED) is the
        same in the server and the page script, and is exactly the app map's
        pages that do not load bf-theme.js. The tokens css/bizforce-ui.css
        declares equal the rule's defaults.
     B  bf-theme.js in jsdom: the cache is applied while <head> is parsed,
        before the first body element exists (before first paint); only for
        the member it belongs to; a fresh answer re-applies only when it
        differs; a per-page theme beats the main one, and resets take effect;
        profile.html showing someone else, and any UNTHEMED page, wears no
        visitor's theme; alive is off under prefers-reduced-motion, in the
        tokens and in the CSS; readability raises the shade until body text is
        7:1 and muted text 4.5:1 against the brightest point (a bright yellow
        pair, a bright photo), and does nothing for today's look.
     C  The studio in jsdom, on the Theme panel from settings.html, against the
        REAL routes lifted from server.js over a fake database: its checklist
        is the app map's themed pages in five groups; presets; the meter
        ("Readable" / "Auto-protected" with the ratios); Save as…; Apply to all,
        this page and selected pages; "Select all agent pages"; "Reset this
        page to the main theme"; "Reset everything to the original"; a wrong
        photo refused before upload; every control named for assistive tech.
     D  lib/themes.js: the closed schema refuses raw CSS, unknown keys, bad
        hex, foreign photo paths and unknown or public page keys; numbers are
        clamped; the scopes resolve; a photo over 5 MB or of the wrong type
        (by its bytes) is refused.
     E  The routes: each is requireAuth and rate-limited per account; bad input
        writes nothing; each write is the caller's own; the photo is stored in
        the member's own folder.
     F  Themes are in the data export (lib/yourData.js, run over a fake DB) and
        deleted with the account (DELETE_ORDER, and the photo found by
        lib/accountFiles.js's folder listing); migration 154 creates the table
        with RLS on and the two preference columns.
     G  bf_theme is a KEPT device key (bf-session.js and checkOfflineMode).

   MUTATE=<name> edits the files IN MEMORY; MUTATE=all runs each in its own
   process. BIZFORCE_FRONTEND_DIR overrides the frontend location. No network,
   no database: the routes run over a fake one.
   ══════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const BEFORE_COMMIT = "1b12268";   // the frontend before Phase A
const MUTATE = process.env.MUTATE || "";

const SERVER = "server.js", LIB = "lib/themes.js", YOURDATA = "lib/yourData.js", ACCFILES = "lib/accountFiles.js";
const MIG = "supabase/migrations/154_member_themes.sql", OFFCHECK = "scripts/checkOfflineMode.js";
const THEME = "scripts/bf-theme.js", STUDIO = "scripts/bf-theme-studio.js", SETTINGS = "settings.html";
const SESSION = "scripts/bf-session.js", UI = "css/bizforce-ui.css", SHELL = "css/agent-shell.css";
const PUBLIC_WITH_BACKDROP = ["seller.html", "blogindex.html", "blogpost.html", "listing.html", "suppressed.html", "vitality.html"];
const UID = "53e6b330-d31c-4958-a10b-516397e7b9c9";
const OTHER = "11111111-2222-4333-8444-555555555555";
const TAG = "<script src=\"/scripts/bf-theme.js\"></script>";

const MUTATIONS = {
  // an inline backdrop left on one page (A)
  "inline-backdrop-left": [["crm.html", "/* The backdrop is the token rule in scripts/bf-theme.js. */",
    "body::before{content:\"\";position:fixed;inset:0;background:radial-gradient(circle at 15% 10%,rgba(0,229,255,.14),transparent 38%),#070b18;z-index:0;pointer-events:none}"]],
  // a page's own glow drifts from what it was (A4 compares every layer with 1b12268)
  "page-look-changed": [["app.html", "--bf-glow-a-alpha: 0.18;", "--bf-glow-a-alpha: 0.19;"]],
  // the shared default moves (A4, on the 48 pages that use it)
  "default-position-moved": [[THEME, "    \"  --bf-glow-a-at: 15% 10%;\\n\" +", "    \"  --bf-glow-a-at: 15% 12%;\\n\" +"]],
  // the visitor's theme applied to a public page: seller.html loads the engine (A)
  "public-page-loads-theme": [["seller.html", "<head>\n", "<head>\n" + TAG + "\n"]],
  // ... or profile.html wears the visitor's theme on someone else's profile (B)
  "profile-visitor-theme": [[THEME, "      return !!id && id !== signedInId(win);", "      return false;"]],
  // raw CSS accepted as a colour (D)
  "raw-css-accepted": [[LIB, "var HEX = /^#[0-9a-f]{6}$/;", "var HEX = /^.+$/;"]],
  // a page key not validated (D, C, E)
  "page-key-unvalidated": [[LIB, "    if (typeof k !== \"string\" || allowed.indexOf(k) === -1) return", "    if (typeof k !== \"string\") return"]],
  // readability protection skipped (B, C)
  "readability-skipped": [[THEME, "    var dim = dimSteps / 100, scrim = scrimSteps / 100;", "    var dim = userDim, scrim = 0;"]],
  // alive under reduced motion (B, C)
  "alive-reduced-motion": [[THEME, "    var alive = t.alive === true && !reducedMotion(win || window);", "    var alive = t.alive === true;"],
    [THEME, "  :root[data-bf-alive=\\\"1\\\"] body::before { inset: 0; animation: none; will-change: auto; }\\n", "\\n"]],
  // the cache applied after paint (B)
  "cache-after-paint": [[THEME, "    if (cache && (!uid || cache.uid === uid)) applyState(cache.state, win, doc);",
    "    if (cache && (!uid || cache.uid === uid)) win.setTimeout(function () { applyState(cache.state, win, doc); }, 0);"]],
  // themes missing from the export (F)
  "themes-missing-from-export": [[YOURDATA, "  { table: \"member_themes\", group: \"account\",", "  { table: \"member_themes_gone\", group: \"account\","]],
  // a photo in another member's folder accepted (D)
  "foreign-photo-accepted": [[LIB, "  return !!m && m[1] === String(userId).toLowerCase();", "  return !!m;"]],
  // a photo's bytes not checked against its label (D, E)
  "photo-bytes-unchecked": [[LIB, "  if (actual !== declared) return", "  if (false) return"]],
  // a per-page theme ignored: every page wears the main one (B)
  "per-page-ignored": [[THEME, "    var id = (state.page_themes && state.page_themes[key]) || state.default_theme_id || null;", "    var id = state.default_theme_id || null;"]],
  // a route without its limiter (E)
  "route-unlimited": [[SERVER, "app.put(\"/api/themes/apply\", requireAuth, themesWriteLimiter, async function", "app.put(\"/api/themes/apply\", requireAuth, async function"]],
  // bf_theme dropped from the KEPT list (G)
  "kept-missing": [[OFFCHECK, "      bf_theme: \"the device's cache of the member's themes, applied before first paint\",\n", ""]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[SERVER, LIB, YOURDATA, ACCFILES, MIG, OFFCHECK].forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
function frontFile(f) {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.log("    FAIL  frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
  return lf(fs.readFileSync(p, "utf8"));
}
const ALL_PAGES = fs.readdirSync(FRONTEND).filter(f => f.endsWith(".html")).concat(
  fs.readdirSync(path.join(FRONTEND, "agents")).filter(f => f.endsWith(".html")).map(f => "agents/" + f));
ALL_PAGES.forEach(f => { FILES[f] = frontFile(f); });
[THEME, STUDIO, SESSION, UI, SHELL].forEach(f => { FILES[f] = frontFile(f); });
const APP_MAP = JSON.parse(fs.readFileSync(path.join(REPO, "lib/appMap.json"), "utf8"));

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
process.on("unhandledRejection", err => { failures++; console.log("    FAIL  an unhandled rejection: " + (err && err.message || err)); });

function compile(rel, text) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(text, file);
  return m.exports;
}
let LIBX, YD, AF;
try { LIBX = compile(LIB, FILES[LIB]); YD = compile(YOURDATA, FILES[YOURDATA]); AF = compile(ACCFILES, FILES[ACCFILES]); }
catch (e) { console.log("    FAIL  a lib did not load: " + e.message); process.exit(1); }

/* ── CSS reading ────────────────────────────────────────────────────────── */
function splitTop(text, sep) {
  const out = []; let depth = 0, cur = "";
  for (const c of text) {
    if (c === "(") depth++;
    if (c === ")") depth--;
    if (c === sep && depth === 0) { out.push(cur); cur = ""; } else cur += c;
  }
  out.push(cur);
  return out.map(x => x.trim()).filter(Boolean);
}
function declsOf(body) {
  const out = {};
  splitTop(body, ";").forEach(d => { const i = d.indexOf(":"); if (i > 0) out[d.slice(0, i).trim()] = d.slice(i + 1).trim(); });
  return out;
}
const stylesOf = html => (html.match(/<style\b[^>]*>[\s\S]*?<\/style>/gi) || []).map(x => x.replace(/^<style\b[^>]*>|<\/style>$/gi, "")).join("\n");
const noComments = css => css.replace(/\/\*[\s\S]*?\*\//g, "");
function rulesOf(css, selectorRe) {
  const out = []; const re = /([^{}]+)\{([^{}]*)\}/g; let m;
  const clean = noComments(css);
  while ((m = re.exec(clean))) if (selectorRe.test(m[1].trim())) out.push(declsOf(m[2]));
  return out;
}
function resolveVars(value, vars, depth) {
  depth = depth || 0;
  if (depth > 20) return value;
  let out = "", i = 0;
  while (i < value.length) {
    const at = value.indexOf("var(", i);
    if (at === -1) { out += value.slice(i); break; }
    out += value.slice(i, at);
    let d = 0, j = at + 3;
    for (; j < value.length; j++) { if (value[j] === "(") d++; if (value[j] === ")") { d--; if (d === 0) break; } }
    const inner = value.slice(at + 4, j);
    const comma = splitTop(inner, ",");
    const name = comma[0].trim(), fallback = inner.indexOf(",") !== -1 ? inner.slice(inner.indexOf(",") + 1).trim() : undefined;
    const v = vars[name] !== undefined ? vars[name] : fallback !== undefined ? fallback : "";
    out += resolveVars(v, vars, depth + 1);
    i = j + 1;
  }
  return out;
}
const NAMED = { transparent: [0, 0, 0, 0] };
function colourOf(text) {
  const t = text.trim().toLowerCase();
  if (NAMED[t]) return NAMED[t];
  let m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/.exec(t);
  if (m) return [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16), 1];
  m = /^rgba?\(([^)]*)\)$/.exec(t);
  if (m) { const p = m[1].split(",").map(x => parseFloat(x)); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; }
  return null;
}
const ws = t => t.replace(/\s+/g, " ").trim();
/* One background value to its visible layers: radial gradients (shape,
   position, stops) and the final colour. Invisible layers (every colour
   alpha 0, an image of none) are dropped. */
function layersOf(bg) {
  return splitTop(bg, ",").map(layer => {
    const L = layer.trim();
    if (/^none\b/.test(L)) return null;   // an image of none, sized or not, draws nothing
    const rg = /^radial-gradient\(([\s\S]*)\)$/.exec(L), lg = /^linear-gradient\(([\s\S]*)\)$/.exec(L);
    if (rg || lg) {
      const args = splitTop((rg || lg)[1], ",");
      let head = null;
      if (rg && / at /.test(" " + args[0] + " ") || (rg && /^(circle|ellipse)/.test(args[0]))) head = args.shift();
      const stops = args.map((a, i) => {
        const parts = a.trim().match(/^(rgba?\([^)]*\)|#[0-9a-fA-F]{6}|[a-z]+)\s*(.*)$/);
        return { c: colourOf(parts[1]), at: parts[2] ? ws(parts[2]) : i === 0 ? "0%" : i === args.length - 1 ? "100%" : "" };
      });
      if (stops.every(st => st.c && st.c[3] === 0)) return null;
      let shape = null, at = null;
      if (head) { const k = (" " + head).split(" at "); shape = ws(k[0]); at = ws(k.slice(1).join(" at ")); }
      return { kind: rg ? "radial" : "linear", shape, at, stops };
    }
    if (/^url\(/.test(L)) return { kind: "image", value: L };
    const c = colourOf(L);
    return c ? { kind: "colour", c } : { kind: "unknown", value: L };
  }).filter(Boolean);
}

/* ── A. Phase A ─────────────────────────────────────────────────────────── */
console.log("\n══ A. the 57 pages and agent-shell draw one token rule, and today's look by default ══");
const THEMED = ALL_PAGES.filter(f => FILES[f].indexOf(TAG) !== -1);
const RULE = (() => { const m = /var RULE =\n([\s\S]*?);\n/.exec(FILES[THEME]); try { return m ? vm.runInNewContext(m[1]) : ""; } catch (e) { return ""; } })();
check("A0. scripts/bf-theme.js carries the rule, with html::before and body::before", /html::before/.test(RULE) && /body::before/.test(RULE));
check("A1. 57 pages load scripts/bf-theme.js", THEMED.length === 57, THEMED.length);
const firstInHead = THEMED.filter(f => { const m = /<head>\s*([\s\S]*?)\n/.exec(FILES[f]); return !m || m[1].trim() !== TAG; });
check("A1. ... as the first element of <head>, before any style or script", firstInHead.length === 0, firstInHead.join(", "));
const inlineLeft = THEMED.concat([SHELL]).filter(f => /body::before\s*\{[^{}]*background/i.test(noComments(f === SHELL ? FILES[f] : stylesOf(FILES[f]))));
check("A2. no inline backdrop is left on any of them, nor in css/agent-shell.css", inlineLeft.length === 0, inlineLeft.join(", "));
const htmlBefore = THEMED.filter(f => /html::before/.test(noComments(stylesOf(FILES[f]))));
check("A2. no page restyles the rule's html::before layer", htmlBefore.length === 0, htmlBefore.join(", "));
const publicLoads = PUBLIC_WITH_BACKDROP.filter(f => FILES[f].indexOf("bf-theme.js") !== -1 || !/body::before\s*\{[^{}]*background/.test(stylesOf(FILES[f])));
check("A3. the public pages with a backdrop (seller, blog index and post, listing, suppressed, vitality) never load bf-theme.js and keep their own rule",
  publicLoads.length === 0, publicLoads.join(", "));
const frontUnthemed = (() => { const m = /var UNTHEMED = (\[[\s\S]*?\]);/.exec(FILES[THEME]); try { return m ? vm.runInNewContext(m[1]) : null; } catch (e) { return null; } })();
const mapKeys = Object.keys(APP_MAP.pages);
const keyOfFile = f => path.basename(f).toLowerCase();
const mapNotThemed = mapKeys.filter(k => !THEMED.some(f => keyOfFile(f) === k)).sort();
check("A3. UNTHEMED is the same in lib/themes.js and scripts/bf-theme.js", JSON.stringify(frontUnthemed) === JSON.stringify(LIBX.UNTHEMED));
check("A3. ... and is exactly the app map's pages that do not load bf-theme.js", JSON.stringify(LIBX.UNTHEMED.slice().sort()) === JSON.stringify(mapNotThemed),
  "map-not-themed: " + mapNotThemed.join(",") + " | UNTHEMED: " + LIBX.UNTHEMED.join(","));
check("A3. the themed pages the server accepts are the 57 that load bf-theme.js", JSON.stringify(LIBX.themedPages(APP_MAP)) === JSON.stringify(THEMED.map(keyOfFile).sort()));

const ruleRoot = rulesOf(RULE, /^:where\(:root\)$/)[0] || {};
const ruleHtml = rulesOf(RULE, /^html::before$/)[0] || {};
const ruleBody = rulesOf(RULE, /^body::before$/)[0] || {};
function before(f) {
  try { return lf(execFileSync("git", ["-C", FRONTEND, "show", BEFORE_COMMIT + ":" + f], { encoding: "utf8", maxBuffer: 16 << 20 })); }
  catch (e) { return null; }
}
const wrong = [], zWrong = [];
let compared = 0;
THEMED.concat([SHELL]).forEach(f => {
  const old = before(f);
  if (old === null) { wrong.push(f + ": not readable at " + BEFORE_COMMIT); return; }
  const oldCss = f === SHELL ? old : stylesOf(old);
  const oldRule = rulesOf(oldCss, /(^|[\s,}])body::before$/).filter(d => d.background)[0];
  if (!oldRule) { wrong.push(f + ": no body::before at " + BEFORE_COMMIT); return; }
  const oldVars = {}; rulesOf(oldCss, /^:root$/).forEach(d => Object.assign(oldVars, d));
  const oldLayers = layersOf(resolveVars(oldRule.background, oldVars));
  const vars = Object.assign({}, ruleRoot);
  rulesOf(f === SHELL ? FILES[f] : stylesOf(FILES[f]), /^:root$/).forEach(d => Object.assign(vars, d));
  const newLayers = layersOf(resolveVars(ruleBody.background || "", vars)).concat(layersOf(resolveVars(ruleHtml.background || "", vars)));
  compared++;
  if (JSON.stringify(newLayers) !== JSON.stringify(oldLayers)) wrong.push(f + ": " + JSON.stringify(newLayers) + " vs " + JSON.stringify(oldLayers));
  const oldZ = oldRule["z-index"] || "auto";
  const newZ = [resolveVars(ruleBody["z-index"] || "", vars), resolveVars(ruleHtml["z-index"] || "", vars)];
  if (newZ[0] !== oldZ || newZ[1] !== oldZ) zWrong.push(f + ": " + newZ.join("/") + " vs " + oldZ);
});
check("A4. with no theme, every one of the 57 pages and agent-shell renders the backdrop it had at " + BEFORE_COMMIT +
  ": the same gradients, positions, shapes, colours, alphas and stops, layer by layer (" + compared + " compared)",
  compared === 58 && wrong.length === 0, wrong.join(" || "));
check("A5. ... at the same z-index (run.html stays below its content at -1)", zWrong.length === 0, zWrong.join(", "));
check("A5. both layers are fixed, cover the viewport and never take a tap",
  [ruleHtml, ruleBody].every(d => d.position === "fixed" && d.inset === "0" && d["pointer-events"] === "none" && d.content === "\"\""));
const uiTokens = rulesOf(FILES[UI], /^:where\(:root\)$/)[0] || {};
const uiDiff = Object.keys(uiTokens).filter(k => uiTokens[k] !== ruleRoot[k]);
const uiBg = (rulesOf(FILES[UI], /^:root$/)[0] || {})["--bf-bg"];
check("A6. css/bizforce-ui.css declares the theme tokens at today's values, the same as the rule's (" + Object.keys(uiTokens).length + ", and --bf-bg)",
  Object.keys(uiTokens).length >= 9 && uiDiff.length === 0 && uiBg === ruleRoot["--bf-bg"], uiDiff.join(","));
const themeTokens = (() => { const m = /var THEME_TOKENS = (\[[\s\S]*?\]);/.exec(FILES[THEME]); try { return vm.runInNewContext(m[1]); } catch (e) { return []; } })();
check("A6. the tokens a theme sets are the brief's eight, plus the channels and the scrim",
  ["--bf-bg", "--bf-bg-image", "--bf-bg-dim", "--bf-glow-a", "--bf-glow-b", "--bf-glow-a-alpha", "--bf-glow-b-alpha", "--bf-alive"].every(t => themeTokens.indexOf(t) !== -1 && ruleRoot[t] !== undefined) &&
  themeTokens.every(t => ruleRoot[t] !== undefined), themeTokens.join(","));
check("A7. the photo is centred, covers, and sits on a fixed layer (no background-attachment: fixed, which repaints on scroll)",
  /var\(--bf-bg-image\) center \/ cover no-repeat/.test(ruleHtml.background || "") && !/background-attachment/.test(RULE));

/* ── B. bf-theme.js in a page ───────────────────────────────────────────── */
console.log("\n══ B. bf-theme.js: before first paint, the member's own, per page, public pages, motion, readability ══");
const b64 = o => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=+$/, "");
const tokenFor = id => "h." + b64({ id: id }) + ".s";
const T1 = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Ember", photo_url: null,
  theme: Object.assign({}, LIBX.DEFAULT_THEME, { glow_a: "#ff7a18", glow_b: "#ff2e63", glow_a_alpha: 0.18, glow_b_alpha: 0.16 }) };
const T2 = { id: "aaaaaaaa-0000-4000-8000-000000000002", name: "Royal", photo_url: null,
  theme: Object.assign({}, LIBX.DEFAULT_THEME, { glow_a: "#6366f1", glow_b: "#f5c542", middle: "colour", bg: "#0a0a24", alive: true }) };
const stateOf = (main, pages) => ({ themes: [T1, T2], default_theme_id: main, page_themes: pages || {}, pages: [] });

async function themePage(o) {
  const calls = [];
  const html = "<!DOCTYPE html><html" + (o.dataPage ? " data-bf-page=\"" + o.dataPage + "\"" : "") + "><head><script>" + FILES[THEME] + "</script><style>" + (o.style || "") + "</style></head>" +
    "<body><script>window.__firstBody = { glowA: document.documentElement.style.getPropertyValue('--bf-glow-a'), ruleFirst: document.head.firstElementChild && document.head.firstElementChild.id };</script><p>page</p></body></html>";
  const dom = new JSDOM(html, {
    url: o.url || "https://bizforceai.net/crm.html", runScripts: "dangerously", pretendToBeVisual: true,
    beforeParse(w) {
      if (o.token !== null) w.localStorage.setItem("bf_token", o.token || tokenFor(UID));
      if (o.cache) w.localStorage.setItem("bf_theme", JSON.stringify(o.cache));
      w.matchMedia = q => ({ matches: !!o.reduce && /prefers-reduced-motion: reduce/.test(q), addEventListener() {} });
      w.fetch = (u, opts) => {
        calls.push({ u: String(u), opts });
        const p = Promise.resolve({ ok: true, json: async () => JSON.parse(JSON.stringify(o.answer || stateOf(null))) });
        p.catch(() => {});
        return p;
      };
    }
  });
  await new Promise(r => setTimeout(r, 30));
  const w = dom.window, root = w.document.documentElement;
  return { w, dom, calls, get: n => root.style.getPropertyValue(n), alive: () => root.getAttribute("data-bf-alive") };
}
const cacheOf = (uid, state, ageMs) => ({ v: 1, uid: uid, fetched_at: Date.now() - (ageMs || 0), state: state });

(async () => {
  // B1: before first paint
  let p = await themePage({ cache: cacheOf(UID, stateOf(T1.id)) });
  check("B1. the cached theme's tokens are on <html> while <head> is parsed, before the first body element runs (no flash)",
    p.w.__firstBody && p.w.__firstBody.glowA === "#ff7a18", JSON.stringify(p.w.__firstBody));
  check("B1. the token rule is written first in <head>", p.w.__firstBody && p.w.__firstBody.ruleFirst === "bf-theme-rule");
  check("B1. a fresh cache asks the server nothing (once a minute at most)", p.calls.length === 0, p.calls.length);
  p = await themePage({});
  check("B2. with no cache and no theme, nothing is set: the page's own look", p.get("--bf-glow-a") === "" && p.alive() === null);
  p = await themePage({ cache: cacheOf(OTHER, stateOf(T1.id)), answer: stateOf(null) });
  check("B3. another member's cache is never applied", p.w.__firstBody.glowA === "" && p.get("--bf-glow-a") === "");
  check("B3. ... and the member's own themes are fetched instead", p.calls.length === 1 && /\/api\/themes$/.test(p.calls[0].u) &&
    /^Bearer /.test(p.calls[0].opts.headers.Authorization));
  p = await themePage({ token: null, cache: cacheOf(UID, stateOf(T1.id)) });
  check("B3. signed out, the device's cache is shown and nothing is fetched", p.get("--bf-glow-a") === "#ff7a18" && p.calls.length === 0);

  // B4: re-apply only when different
  p = await themePage({ cache: cacheOf(UID, stateOf(T1.id), 120000), answer: stateOf(T2.id) });
  check("B4. a stale cache is refreshed after load, and the new theme is applied", p.calls.length === 1 && p.get("--bf-glow-a") === "#6366f1");
  check("B4. ... and the cache now holds it", JSON.parse(p.w.localStorage.getItem("bf_theme")).state.default_theme_id === T2.id);
  p = await themePage({ cache: cacheOf(UID, stateOf(T1.id), 120000), answer: stateOf(T1.id) });
  check("B4. an answer that is the same changes nothing", p.w.BFTheme.applyState(stateOf(T1.id)) === false && p.get("--bf-glow-a") === "#ff7a18");

  // B5: per page, main, reset
  p = await themePage({ url: "https://bizforceai.net/crm.html", cache: cacheOf(UID, stateOf(T1.id, { "crm.html": T2.id })) });
  check("B5. a page's own theme beats the main one", p.get("--bf-glow-a") === "#6366f1");
  p = await themePage({ url: "https://bizforceai.net/wallet.html", cache: cacheOf(UID, stateOf(T1.id, { "crm.html": T2.id })) });
  check("B5. a page without one wears the main theme", p.get("--bf-glow-a") === "#ff7a18");
  p = await themePage({ url: "https://bizforceai.net/agents/seo", cache: cacheOf(UID, stateOf(null, { "seo.html": T2.id })) });
  check("B5. a page key is the app map's (file name; /agents/seo serves seo.html)", p.get("--bf-glow-a") === "#6366f1");
  p.w.BFTheme.applyState(stateOf(T1.id, {}));
  check("B5. a page reset to the main theme wears it at once", p.get("--bf-glow-a") === "#ff7a18");
  p.w.BFTheme.applyState(stateOf(null, {}));
  check("B5. reset everything: every token is removed and the original look returns", p.w.BFTheme.THEME_TOKENS.every(t => p.get(t) === ""));

  // B6: public views
  p = await themePage({ url: "https://bizforceai.net/profile.html?id=" + OTHER, cache: cacheOf(UID, stateOf(T1.id)), answer: stateOf(T1.id) });
  check("B6. profile.html showing someone else's profile wears none of the visitor's theme, and fetches nothing", p.get("--bf-glow-a") === "" && p.calls.length === 0);
  p = await themePage({ url: "https://bizforceai.net/profile.html?id=" + UID, cache: cacheOf(UID, stateOf(T1.id)) });
  check("B6. ... while the member's own profile wears their theme", p.get("--bf-glow-a") === "#ff7a18");
  const unthemedHit = [];
  for (const k of LIBX.UNTHEMED) {
    const q = await themePage({ url: "https://bizforceai.net/" + k, cache: cacheOf(UID, stateOf(T1.id)) });
    if (q.get("--bf-glow-a") !== "") unthemedHit.push(k);
    q.w.close();
  }
  check("B6. a public page (" + LIBX.UNTHEMED.length + " of them) never wears the visitor's theme, even if it loaded the engine", unthemedHit.length === 0, unthemedHit.join(","));

  // B7: alive and reduced motion
  p = await themePage({ url: "https://bizforceai.net/wallet.html", cache: cacheOf(UID, stateOf(T2.id)) });
  check("B7. alive corners: --bf-alive 1 and the drift attribute", p.get("--bf-alive") === "1" && p.alive() === "1");
  p = await themePage({ url: "https://bizforceai.net/wallet.html", cache: cacheOf(UID, stateOf(T2.id)), reduce: true });
  check("B7. under prefers-reduced-motion, alive is off: --bf-alive 0 and no attribute", p.get("--bf-alive") === "0" && p.alive() === null);
  const anim = /:root\[data-bf-alive="1"\] body::before \{([^}]*)\}/.exec(RULE);
  const kf = /@keyframes bf-glow-drift \{([\s\S]*?)\n\}/.exec(RULE);
  const secs = anim && /animation: bf-glow-drift (\d+)s/.exec(anim[1]);
  check("B7. the drift moves the glow layer only (body::before), by transform and opacity, on a 20–40 s cycle",
    !!anim && !!kf && secs && +secs[1] >= 20 && +secs[1] <= 40 &&
    (kf[1].match(/[a-z-]+(?=:)/g) || []).every(prop => prop === "transform" || prop === "opacity") &&
    !/html::before[^{]*\{[^}]*animation/.test(RULE));
  check("B7. the CSS also stops it under prefers-reduced-motion",
    /@media \(prefers-reduced-motion: reduce\) \{\s*:root\[data-bf-alive="1"\] body::before \{[^}]*animation: none/.test(RULE));

  // B8: readability
  const R = p.w.BFTheme.readability;
  const def = R(LIBX.DEFAULT_THEME);
  check("B8. today's look is readable as it is: no shade added", def.readable && !def.protected && def.dim === 0 && def.scrim === 0,
    JSON.stringify(def.ratios));
  const yellow = Object.assign({}, LIBX.DEFAULT_THEME, { glow_a: "#ffff00", glow_b: "#ffff00", glow_a_alpha: 0.5, glow_b_alpha: 0.5 });
  const ry = R(yellow);
  check("B8. a bright yellow pair is not readable as it is (body " + ry.before.text.toFixed(2) + ":1, muted " + ry.before.muted.toFixed(2) + ":1)", !ry.readable);
  check("B8. ... so it is protected until body text is 7:1 and muted text 4.5:1 (" + ry.ratios.text.toFixed(2) + ", " + ry.ratios.muted.toFixed(2) + "; scrim " + ry.scrim + ")",
    ry.protected && ry.scrim > 0 && ry.ratios.text >= 7 && ry.ratios.muted >= 4.5);
  const less = Object.assign({}, ry);
  const atLess = (() => { const t2 = R(yellow); return t2.scrim; })();
  check("B8. ... by the least shade that passes (0.01 less fails)", (() => {
    const T = p.w.BFTheme, a = T.rgbOf("#ffff00"), m = [7, 11, 24];
    const peakAt = sc => [0, 1, 2].map(i => (m[i] + 0.5 * (a[i] - m[i])) * (1 - sc));
    const fails = pt => T.contrast(T.rgbOf(T.TEXT), pt) < 7 || T.contrast(T.rgbOf(T.MUTED), pt) < 4.5;
    return fails(peakAt(Math.round(atLess * 100 - 1) / 100)) && !fails(peakAt(atLess));
  })(), less.scrim);
  const photo = Object.assign({}, LIBX.DEFAULT_THEME, { middle: "photo", photo: "theme-photos/" + UID + "/1700000000000.jpg", photo_luma: 0.9, dim: 0.2 });
  const rp = R(photo);
  check("B8. a bright photo (luminance 0.9) with a light dim raises the dim until it passes (dim " + rp.dim + ", body " + rp.ratios.text.toFixed(2) + ", muted " + rp.ratios.muted.toFixed(2) + ")",
    !rp.readable && rp.protected && rp.dim > 0.2 && rp.ratios.text >= 7 && rp.ratios.muted >= 4.5);
  const tp = p.w.BFTheme.tokensFor(yellow, null, p.w);
  check("B8. the protection reaches the page: --bf-scrim carries it", Number(tp["--bf-scrim"]) === ry.scrim && ry.scrim > 0);
  const tphoto = p.w.BFTheme.tokensFor(photo, "https://x.supabase.co/storage/v1/object/public/bf-public/theme-photos/" + UID + "/1700000000000.jpg", p.w);
  check("B8. ... and --bf-bg-dim for a photo, with the photo set as the middle image", Number(tphoto["--bf-bg-dim"]) === rp.dim && /^url\("https:\/\/x\.supabase\.co\//.test(tphoto["--bf-bg-image"]));
  const evil = p.w.BFTheme.tokensFor(photo, "https://x.test/a.jpg\") , url(\"https://evil", p.w);
  check("B8. a photo URL that could break out of url( ) is never used", evil["--bf-bg-image"] === "none");
  p.w.close();

  await studio();
})().catch(err => { failures++; console.log("    FAIL  checkThemes crashed: " + (err && err.stack || err)); finish(); });

/* ── the routes, lifted from server.js, over a fake database ────────────── */
function fakeDb() {
  const db = { member_themes: [], user_preferences: [], uploads: [], removed: [], writes: [] };
  let n = 0;
  function from(table) {
    const st = { filters: [], op: "select", payload: null, head: false };
    const pick = () => (db[table] || []).filter(r => st.filters.every(([c, v]) => r[c] === v));
    function run() {
      const clone = x => JSON.parse(JSON.stringify(x));
      if (st.op === "select") { const rows = pick(); return Promise.resolve({ data: st.head ? null : clone(rows), count: rows.length, error: null }); }
      db.writes.push({ table, op: st.op, payload: clone(st.payload), filters: st.filters.slice() });
      if (st.op === "insert") {
        n++;
        const row = Object.assign({ id: "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0"), created_at: "2026-10-29T00:00:" + String(n).padStart(2, "0") + "Z", updated_at: null }, clone(st.payload));
        db[table].push(row);
        return Promise.resolve({ data: [clone(row)], error: null });
      }
      if (st.op === "update") { pick().forEach(r => Object.assign(r, clone(st.payload))); return Promise.resolve({ data: null, error: null }); }
      if (st.op === "delete") { const gone = pick(); db[table] = db[table].filter(r => gone.indexOf(r) === -1); return Promise.resolve({ data: null, error: null }); }
      if (st.op === "upsert") {
        const key = st.conflict || "id";
        const had = db[table].filter(r => r[key] === st.payload[key])[0];
        if (had) Object.assign(had, clone(st.payload)); else db[table].push(clone(st.payload));
        return Promise.resolve({ data: null, error: null });
      }
      return Promise.resolve({ data: null, error: null });
    }
    const q = {
      select(cols, o) { if (st.op === "select" && o && o.head) st.head = true; return q; },
      eq(c, v) { st.filters.push([c, v]); return q; },
      order() { return q; },
      insert(p) { st.op = "insert"; st.payload = p; return q; },
      update(p) { st.op = "update"; st.payload = p; return q; },
      delete() { st.op = "delete"; return q; },
      upsert(p, o) { st.op = "upsert"; st.payload = p; st.conflict = o && o.onConflict; return q; },
      maybeSingle() { return run().then(r => ({ data: (r.data && r.data[0]) || null, error: r.error })); },
      single() { return run().then(r => ({ data: r.data && r.data[0], error: r.error })); },
      then(a, b) { return run().then(a, b); }
    };
    return q;
  }
  const storage = {
    from(bucket) {
      return {
        upload: async (p, buf, o) => { db.uploads.push({ bucket, path: p, size: buf.length, contentType: o && o.contentType }); return { error: null }; },
        remove: async paths => { db.removed.push(...paths); return { error: null }; },
        getPublicUrl: p => ({ data: { publicUrl: "https://x.supabase.co/storage/v1/object/public/" + bucket + "/" + p } })
      };
    }
  };
  return { db, client: { from, storage } };
}
function liftRoutes(fake) {
  const src = FILES[SERVER];
  const a = src.indexOf("/* ── Member themes (lib/themes.js, migration 154)");
  const endSig = "app.post(\"/api/themes/photo\"";
  const b0 = src.indexOf(endSig);
  const b = b0 === -1 ? -1 : src.indexOf("\n});\n", src.indexOf("\n  });\n", b0)) + 5;
  if (a === -1 || b0 === -1 || b < b0) throw new Error("the theme routes were not found in server.js");
  const routes = [], limiters = [];
  function requireAuth(req, res, next) { next(); }
  const ctx = {
    console: { log() {}, error() {}, warn() {} },
    require: name => { if (name === "./lib/themes") return LIBX; throw new Error("unexpected require " + name); },
    rateLimit: o => { const fn = function (req, res, next) { next(); }; fn.__limiter = o; limiters.push(fn); return fn; },
    multer: Object.assign(o => ({
      single: field => (req, res, cb) => {
        const f = req.__file;
        if (f && f.field !== field) { const e = new Error("Unexpected field"); e.code = "LIMIT_UNEXPECTED_FILE"; return cb(e); }
        if (f && o.limits && f.buffer.length > o.limits.fileSize) { const e = new Error("File too large"); e.code = "LIMIT_FILE_SIZE"; return cb(e); }
        req.file = f; cb();
      }
    }), { memoryStorage: () => ({}) }),
    supabase: fake.client, APP_MAP: APP_MAP, requireAuth: requireAuth, Buffer: Buffer, Date: Date, Promise: Promise,
    app: {}
  };
  ["get", "post", "put", "delete"].forEach(m => { ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes.push({ method: m, path: p, mw: args.slice(0, -1), handler: args[args.length - 1] }); }; });
  vm.createContext(ctx);
  vm.runInContext(src.slice(a, b), ctx);
  return { routes, limiters, requireAuth };
}
function match(routes, method, url) {
  for (const r of routes) {
    if (r.method !== method) continue;
    const names = [];
    const re = new RegExp("^" + r.path.replace(/:([a-z_]+)/g, (m, nm) => { names.push(nm); return "([^/]+)"; }) + "$");
    const m = re.exec(url);
    if (m) { const params = {}; names.forEach((nm, i) => { params[nm] = decodeURIComponent(m[i + 1]); }); return { r, params }; }
  }
  return null;
}
function callRoute(lifted, method, url, body, file, uid) {
  return new Promise((resolve, reject) => {
    const hit = match(lifted.routes, method, url);
    if (!hit) return resolve({ status: 404, body: { error: "no route" } });
    const req = { user: { id: uid || UID }, params: hit.params, body: body || {}, __file: file || null };
    const res = { statusCode: 200, status(c) { this.statusCode = c; return this; }, json(b) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(b)) }); return this; } };
    const p = hit.r.handler(req, res, err => reject(err || new Error("next() with no error")));
    if (p && p.catch) p.catch(reject);
  });
}

/* ── C. the studio ──────────────────────────────────────────────────────── */
async function studio() {
  console.log("\n══ C. the studio, against the real routes over a fake database ══");
  const fake = fakeDb();
  let lifted;
  try { lifted = liftRoutes(fake); } catch (e) { check("C0. the theme routes lift from server.js", false, e.message); return routesAndLib(null, null); }
  const panelAt = FILES[SETTINGS].indexOf("<section class=\"settings-panel\" id=\"panel-theme\"");
  const panelEnd = FILES[SETTINGS].indexOf("</section>", panelAt) + "</section>".length;
  check("C0. settings.html has the Theme panel, and a Theme entry in its navigation",
    panelAt !== -1 && /<button type="button" class="sidebar-item" data-target="theme">\s*<span>Theme<\/span>/.test(FILES[SETTINGS]));
  check("C0. settings.html loads bf-theme-studio.js after its own script, and #theme opens the section",
    FILES[SETTINGS].indexOf("<script src=\"/scripts/bf-theme-studio.js\"></script>") > FILES[SETTINGS].indexOf("var API_URL") &&
    /if \(window\.location\.hash === "#theme"\) activateSection\("theme"\);/.test(FILES[SETTINGS]));
  const panel = FILES[SETTINGS].slice(panelAt, panelEnd);
  async function open(o) {
    const calls = [];
    const html = "<!DOCTYPE html><html><head><script>" + FILES[THEME] + "</script></head><body>" + panel +
      "<script>var API_URL = \"https://api.test\";</script><script>" + FILES[STUDIO] + "</script></body></html>";
    const dom = new JSDOM(html, {
      url: o.url || "https://bizforceai.net/settings.html?page=crm.html", runScripts: "dangerously", pretendToBeVisual: true,
      beforeParse(w) {
        w.localStorage.setItem("bf_token", tokenFor(UID));
        w.matchMedia = q => ({ matches: !!o.reduce && /prefers-reduced-motion: reduce/.test(q), addEventListener() {} });
        w.fetch = (u, opts) => {
          const url = new URL(String(u));
          const method = ((opts && opts.method) || "GET").toLowerCase();
          calls.push(method + " " + url.pathname);
          const body = opts && typeof opts.body === "string" ? JSON.parse(opts.body) : undefined;
          const p = (url.pathname === "/api/themes" && method === "get" && o.failGet ? Promise.resolve({ status: 500, body: { error: "down" } }) :
            callRoute(lifted, method, url.pathname, body)).then(r => ({ ok: r.status < 400, status: r.status, json: async () => r.body }));
          p.catch(() => {});
          return p;
        };
      }
    });
    await new Promise(r => setTimeout(r, 40));
    return { w: dom.window, d: dom.window.document, calls, dom };
  }
  const settle = () => new Promise(r => setTimeout(r, 30));
  const st = await open({});
  const $ = id => st.d.getElementById(id);
  const boxes = st.d.querySelectorAll("#tsPageGroups input[type=checkbox]");
  const themed = LIBX.themedPages(APP_MAP);
  check("C1. on opening, the studio asks GET /api/themes", st.calls[0] === "get /api/themes", st.calls.join(","));
  check("C1. the page checklist is the app map's " + themed.length + " themed pages, from the server", boxes.length === themed.length &&
    Array.prototype.every.call(boxes, b => themed.indexOf(b.value) !== -1), boxes.length);
  const legends = Array.prototype.map.call(st.d.querySelectorAll("#tsPageGroups legend"), l => l.textContent);
  check("C1. in five groups: Dashboard & HQ · Agent pages · Money (wallet, billing, marketplace) · Content & tools · Account",
    JSON.stringify(legends) === JSON.stringify(["Dashboard & HQ", "Agent pages", "Money (wallet, billing, marketplace)", "Content & tools", "Account"]), legends.join(" · "));
  const groupsOk = LIBX.themedPageList(APP_MAP).every(p => {
    const box = st.d.querySelector("#tsPageGroups input[value=\"" + p.key + "\"]");
    return box && box.getAttribute("data-group") === p.group && box.parentNode.textContent.trim() === p.name;
  });
  check("C1. each page is named from its title in the app map, in its group", groupsOk);
  check("C1. \"This page\" is the page the member came from (?page=crm.html), named", $("tsThisPageName").textContent === "CRM", $("tsThisPageName").textContent);
  check("C2. the meter starts at \"Readable\", with the three ratios", $("tsMeterState").textContent === "Readable" &&
    /^Text \d+\.\d:1 · Muted text \d+\.\d:1 · Accent \d+\.\d:1$/.test($("tsMeterRatios").textContent), $("tsMeterRatios").textContent);
  const presets = Array.prototype.map.call(st.d.querySelectorAll(".ts-preset"), b => b.textContent.trim());
  check("C3. six preset cards: Default, Ember, Verdant, Royal, Rosé, Mono", JSON.stringify(presets) === JSON.stringify(["Default", "Ember", "Verdant", "Royal", "Rosé", "Mono"]), presets.join(","));
  const fire = (el, type) => el.dispatchEvent(new st.w.Event(type, { bubbles: true }));
  $("tsGlowAHex").value = "#ffff00"; fire($("tsGlowAHex"), "change");
  $("tsGlowBHex").value = "ffff00"; fire($("tsGlowBHex"), "change");
  $("tsGlowAAlpha").value = "50"; fire($("tsGlowAAlpha"), "input");
  $("tsGlowBAlpha").value = "50"; fire($("tsGlowBAlpha"), "input");
  const ratios = ($("tsMeterRatios").textContent.match(/(\d+\.\d):1/g) || []).map(x => parseFloat(x));
  check("C2. a bright yellow pair: the meter says \"Auto-protected\", and the ratios it shows pass (text ≥ 7, muted ≥ 4.5)",
    $("tsMeterState").textContent === "Auto-protected" && ratios[0] >= 7 && ratios[1] >= 4.5, $("tsMeterState").textContent + " " + $("tsMeterRatios").textContent);
  check("C2. ... and the preview carries the shade", Number($("tsPreview").style.getPropertyValue("--bf-scrim")) > 0);
  check("C2. the hex field and the colour picker agree, and \"ffff00\" is read as #ffff00", $("tsGlowBColor").value === "#ffff00" && $("tsGlowBHex").value === "#ffff00");
  $("tsGlowAHex").value = "red;}body{x"; fire($("tsGlowAHex"), "change");
  check("C2. a hex field that is not a colour is refused, and says how", $("tsGlowAHex").value === "#ffff00" && /six hex digits/.test($("tsMsg").textContent));
  st.d.querySelector(".ts-preset[data-preset=ember]").click();
  check("C3. a preset fills the controls and is shown pressed", $("tsGlowAHex").value === "#ff7a18" &&
    st.d.querySelector(".ts-preset[data-preset=ember]").getAttribute("aria-pressed") === "true" && $("tsName").value === "Ember");
  $("tsAlive").checked = true; fire($("tsAlive"), "change");
  check("C4. \"Alive corners\" makes the preview drift", $("tsPreview").getAttribute("data-alive") === "1");
  $("tsSaveAs").click(); await settle();
  const saved = fake.db.member_themes[0];
  check("C5. \"Save as…\" stores the theme, validated, under the member's id", fake.db.member_themes.length === 1 && saved.user_id === UID && saved.name === "Ember" &&
    saved.theme.glow_a === "#ff7a18" && saved.theme.alive === true);
  check("C5. ... lists it, and the editor is now editing it", st.d.querySelectorAll("#tsSavedList li").length === 1 && /Editing "Ember"/.test($("tsEditing").textContent));
  st.d.querySelector("input[name=tsScope][value=page]").click(); fire(st.d.querySelector("input[name=tsScope][value=page]"), "change");
  $("tsApply").click(); await settle();
  const prefs = () => fake.db.user_preferences.filter(r => r.user_id === UID)[0] || {};
  check("C6. Apply to \"This page\" gives CRM its own theme", prefs().page_themes && prefs().page_themes["crm.html"] === saved.id, JSON.stringify(prefs()));
  st.d.querySelector("input[name=tsScope][value=pages]").click(); fire(st.d.querySelector("input[name=tsScope][value=pages]"), "change");
  check("C6. \"Selected pages\" shows the checklist", $("tsPagePicker").hidden === false);
  $("tsSelectAgents").click();
  const agentKeys = LIBX.themedPageList(APP_MAP).filter(x => x.group === "agents").map(x => x.key);
  const ticked = Array.prototype.filter.call(boxes.length ? st.d.querySelectorAll("#tsPageGroups input") : [], b => b.checked).map(b => b.value);
  check("C6. \"Select all agent pages\" ticks exactly the " + agentKeys.length + " agent pages", JSON.stringify(ticked.slice().sort()) === JSON.stringify(agentKeys.slice().sort()), ticked.length);
  st.d.querySelector("#tsPageGroups input[value=\"wallet.html\"]").checked = true;
  $("tsApply").click(); await settle();
  check("C6. Apply to the ticked pages gives each of them the theme, and CRM keeps its own",
    agentKeys.concat(["wallet.html", "crm.html"]).every(k => prefs().page_themes[k] === saved.id) && Object.keys(prefs().page_themes).length === agentKeys.length + 2);
  st.d.querySelector("input[name=tsScope][value=all]").click(); fire(st.d.querySelector("input[name=tsScope][value=all]"), "change");
  $("tsApply").click(); await settle();
  check("C6. Apply to \"All pages\" makes it the main theme", prefs().default_theme_id === saved.id);
  check("C6. the settings page itself now wears it (the cache and the tokens are updated at once)", st.d.documentElement.style.getPropertyValue("--bf-glow-a") === "#ff7a18" &&
    JSON.parse(st.w.localStorage.getItem("bf_theme")).state.default_theme_id === saved.id);
  const rows = st.d.querySelectorAll("#tsAssignments li");
  check("C7. \"Pages and their themes\" lists each page with its own theme, with \"Reset this page to the main theme\"",
    rows.length === agentKeys.length + 2 && Array.prototype.every.call(rows, li => /Reset this page to the main theme/.test(li.textContent)) &&
    /Main theme: Ember\./.test($("tsMainTheme").textContent));
  const crmRow = Array.prototype.filter.call(rows, li => /^CRM — /.test(li.textContent))[0];
  if (crmRow) crmRow.querySelector("button").click();
  await settle();
  check("C7. resetting CRM puts it back on the main theme", prefs().page_themes["crm.html"] === undefined && prefs().default_theme_id === saved.id);
  $("tsResetAll").click(); await settle();
  check("C8. \"Reset everything to the original\" asks once more before acting", prefs().default_theme_id === saved.id && /Confirm/.test($("tsResetAll").textContent));
  $("tsResetAll").click(); await settle();
  check("C8. ... then every page is back on the original, the saved theme kept", prefs().default_theme_id === null && JSON.stringify(prefs().page_themes) === "{}" &&
    fake.db.member_themes.length === 1 && st.d.documentElement.style.getPropertyValue("--bf-glow-a") === "");
  Object.defineProperty($("tsPhotoFile"), "files", { configurable: true, value: [{ type: "image/gif", size: 1000, name: "a.gif" }] });
  fire($("tsPhotoFile"), "change"); await settle();
  check("C9. a GIF is refused before anything is uploaded", /JPEG, PNG or WebP/.test($("tsPhotoMsg").textContent) && st.calls.indexOf("post /api/themes/photo") === -1);
  Object.defineProperty($("tsPhotoFile"), "files", { configurable: true, value: [{ type: "image/jpeg", size: 6 * 1024 * 1024, name: "a.jpg" }] });
  fire($("tsPhotoFile"), "change"); await settle();
  check("C9. a photo over 5 MB is refused before anything is uploaded", /at most 5 MB/.test($("tsPhotoMsg").textContent) && st.calls.indexOf("post /api/themes/photo") === -1);
  const unnamed = Array.prototype.filter.call(st.d.querySelectorAll("#panel-theme input, #panel-theme button"), el => {
    if (el.getAttribute("aria-label") || el.getAttribute("aria-labelledby")) return false;
    if (el.id && st.d.querySelector("label[for=\"" + el.id + "\"]")) return false;
    if (el.closest("label")) return false;
    if (el.tagName === "BUTTON" && el.textContent.trim()) return false;
    return true;
  }).map(el => el.id || el.outerHTML.slice(0, 60));
  check("C10. every control in the studio has an accessible name (label, aria-label or its text)", unnamed.length === 0, unnamed.join(", "));
  check("C10. the meter and the messages are announced (role=status, aria-live=polite); presets say which is on (aria-pressed)",
    ["tsMeter", "tsMsg", "tsApplyMsg", "tsPhotoMsg"].every(id => $(id).getAttribute("role") === "status" && $(id).getAttribute("aria-live") === "polite") &&
    Array.prototype.every.call(st.d.querySelectorAll(".ts-preset"), b => b.tagName === "BUTTON" && b.hasAttribute("aria-pressed")));
  check("C10. the parts are fieldsets with their legends: \"Top-left glow\", \"Bottom-right glow\", \"Middle backdrop\"",
    JSON.stringify(Array.prototype.map.call(st.d.querySelectorAll(".ts-controls > fieldset > legend"), l => l.textContent)) === JSON.stringify(["Top-left glow", "Bottom-right glow", "Middle backdrop"]));
  st.w.close();
  const rm = await open({ reduce: true });
  rm.d.getElementById("tsAlive").checked = true; rm.d.getElementById("tsAlive").dispatchEvent(new rm.w.Event("change"));
  check("C11. under reduced motion the preview stays still, and says why", rm.d.getElementById("tsPreview").getAttribute("data-alive") === "0" &&
    /reduced motion/.test(rm.d.getElementById("tsAliveNote").textContent));
  check("C11. the preview's CSS also stops the drift under prefers-reduced-motion",
    /@media \(prefers-reduced-motion: reduce\) \{ \.ts-preview\[data-alive="1"\] \.ts-pv-glows \{[^}]*animation: none/.test(FILES[SETTINGS]));
  rm.w.close();
  await routesAndLib(lifted, fake);
}

/* ── D, E. lib/themes.js and the routes ─────────────────────────────────── */
async function routesAndLib(lifted) {
  console.log("\n══ D. lib/themes.js: the closed schema, the scopes, the photo ══");
  const v = x => LIBX.validateTheme(x, UID);
  check("D1. today's look and a full theme are accepted", !!v({}).theme && !!v(Object.assign({}, LIBX.DEFAULT_THEME, { glow_a: "#123abc", middle: "colour", bg: "#000000" })).theme);
  const refused = [
    ["raw CSS as a colour", { glow_a: "red;} body{background:url(https://evil)}" }],
    ["a CSS function as a colour", { bg: "url(https://evil/x.png)" }],
    ["short hex", { glow_b: "#fff" }],
    ["uppercase hex", { glow_b: "#FFFFFF" }],
    ["a bad hex digit", { glow_a: "#12345g" }],
    ["an unknown key", { css: "body{}" }],
    ["an unknown key carrying a URL", { background: "url(x)" }],
    ["a middle outside the enum", { middle: "gradient" }],
    ["alive as text", { alive: "yes" }],
    ["a number as text", { dim: "0.5" }],
    ["another member's photo", { middle: "photo", photo: "theme-photos/" + OTHER + "/1700000000000.jpg" }],
    ["a URL as the photo", { middle: "photo", photo: "https://evil.test/x.jpg" }],
    ["a path that climbs out of the folder", { middle: "photo", photo: "theme-photos/" + UID + "/../x.jpg" }],
    ["a photo outside theme-photos", { middle: "photo", photo: "avatars/" + UID + "/1700000000000.jpg" }],
    ["a photo backdrop with no photo", { middle: "photo" }]
  ].filter(([what, t]) => !v(t).error);
  check("D2. the validator refuses raw CSS, unknown keys, bad hex, foreign photo paths and the rest (15 cases)", refused.length === 0, refused.map(r => r[0]).join(", "));
  check("D2. a refusal names the key", v({ glow_a: "nope" }).key === "glow_a" && v({ evil: 1 }).key === "evil");
  check("D2. the member's own photo is accepted", !!v({ middle: "photo", photo: "theme-photos/" + UID + "/1700000000000.webp", photo_luma: 0.4 }).theme);
  const cl = v({ glow_a_alpha: 5, glow_b_alpha: -1, dim: 2, photo_luma: 9 }).theme;
  check("D3. numbers are clamped: alphas to 0 … 0.5, dim to 0 … 0.85, luminance to 0 … 1", cl && cl.glow_a_alpha === 0.5 && cl.glow_b_alpha === 0 && cl.dim === 0.85 && cl.photo_luma === 1);
  check("D3. a name is plain text of 1 … 60 characters", LIBX.validateName("  My\u0000 theme ").name === "My theme" && !!LIBX.validateName("").error && !!LIBX.validateName("x".repeat(61)).error);
  const allowed = LIBX.themedPages(APP_MAP);
  const badKeys = ["evil.html", "seller.html", "card-view.html", "terms.html", "../server.js", "CRM.HTML"].filter(k => !LIBX.validatePages([k], allowed).error);
  check("D4. page keys are checked against the app map's themed pages: unknown, public and odd keys refused", badKeys.length === 0, badKeys.join(","));
  check("D4. ... and real ones accepted", !!LIBX.validatePages(["crm.html", "seo.html", "wallet.html"], allowed).pages);
  const ids = ["t1", "t2"];
  const a1 = LIBX.applyScope({ default_theme_id: null, page_themes: {} }, { theme_id: "t1", scope: "all" }, allowed, ids).prefs;
  const a2 = LIBX.applyScope(a1, { theme_id: "t2", scope: "page", pages: ["crm.html"] }, allowed, ids).prefs;
  const a3 = LIBX.applyScope(a2, { theme_id: "t2", scope: "pages", pages: ["seo.html", "wallet.html"] }, allowed, ids).prefs;
  check("D5. scope all sets the main theme; page and pages give pages their own", a1.default_theme_id === "t1" && a2.page_themes["crm.html"] === "t2" &&
    a3.page_themes["seo.html"] === "t2" && a3.page_themes["wallet.html"] === "t2" && a3.default_theme_id === "t1");
  check("D5. a page's own theme beats the main one", LIBX.themeIdFor(a3, "crm.html") === "t2" && LIBX.themeIdFor(a3, "billing.html") === "t1");
  check("D5. \"This page\" is one page, and a theme must be the member's", !!LIBX.applyScope(a1, { theme_id: "t1", scope: "page", pages: ["crm.html", "seo.html"] }, allowed, ids).error &&
    !!LIBX.applyScope(a1, { theme_id: "someone-elses", scope: "all" }, allowed, ids).error && !!LIBX.applyScope(a1, { theme_id: "t1", scope: "everywhere" }, allowed, ids).error);
  const r1 = LIBX.resetScope(a3, { scope: "page", pages: ["crm.html"] }, allowed, ids).prefs;
  const r2 = LIBX.resetScope(a3, { scope: "all" }, allowed, ids).prefs;
  check("D5. reset puts a page back on the main theme, and \"all\" back to the original", r1.page_themes["crm.html"] === undefined && r1.page_themes["seo.html"] === "t2" &&
    r1.default_theme_id === "t1" && r2.default_theme_id === null && JSON.stringify(r2.page_themes) === "{}");
  const jpg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(20)]);
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(20)]);
  const webp = Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WEBP"), Buffer.alloc(20)]);
  const gif = Buffer.concat([Buffer.from("GIF89a"), Buffer.alloc(20)]);
  check("D6. a JPEG, PNG and WebP are accepted by their bytes", LIBX.checkPhoto({ buffer: jpg, mimetype: "image/jpeg" }).ext === "jpg" &&
    LIBX.checkPhoto({ buffer: png, mimetype: "image/png" }).ext === "png" && LIBX.checkPhoto({ buffer: webp, mimetype: "image/webp" }).ext === "webp");
  const big = Buffer.concat([jpg, Buffer.alloc(5 * 1024 * 1024)]);
  check("D6. a photo over 5 MB is refused", /5 MB/.test(LIBX.checkPhoto({ buffer: big, mimetype: "image/jpeg" }).error || ""));
  check("D6. a GIF, or a PNG labelled as a JPEG, is refused", !!LIBX.checkPhoto({ buffer: gif, mimetype: "image/gif" }).error && !!LIBX.checkPhoto({ buffer: png, mimetype: "image/jpeg" }).error &&
    !!LIBX.checkPhoto({ buffer: gif, mimetype: "image/png" }).error);

  console.log("\n══ E. the routes ══");
  if (!lifted) { check("E0. the routes could be lifted", false); return exportAndDelete(); }
  const want = [["get", "/api/themes"], ["post", "/api/themes"], ["put", "/api/themes/apply"], ["put", "/api/themes/:id"], ["delete", "/api/themes/:id"], ["post", "/api/themes/reset"], ["post", "/api/themes/photo"]];
  const got = lifted.routes.map(r => r.method + " " + r.path);
  check("E1. seven routes: GET/POST /api/themes, PUT/DELETE /api/themes/:id, PUT /api/themes/apply, POST /api/themes/reset, POST /api/themes/photo",
    JSON.stringify(got) === JSON.stringify(want.map(w => w.join(" "))), got.join(", "));
  const gated = lifted.routes.filter(r => r.mw[0] === lifted.requireAuth && r.mw[1] && r.mw[1].__limiter && /^(themes|themes-write|theme-photo):x$/.test(r.mw[1].__limiter.keyGenerator({ user: { id: "x" } })));
  check("E1. each is requireAuth, then a limiter keyed per account", gated.length === 7, lifted.routes.filter(r => gated.indexOf(r) === -1).map(r => r.method + " " + r.path).join(", "));
  check("E1. PUT /api/themes/apply is registered before PUT /api/themes/:id", got.indexOf("put /api/themes/apply") < got.indexOf("put /api/themes/:id"));
  const fake = fakeDb(); const L = liftRoutes(fake);
  let r = await callRoute(L, "post", "/api/themes", { name: "X", theme: { glow_a: "red;}" } });
  check("E2. a theme with raw CSS is refused with 400, and nothing is written", r.status === 400 && fake.db.writes.length === 0, JSON.stringify(r));
  r = await callRoute(L, "post", "/api/themes", { name: "Mine", theme: { glow_a: "#112233", unknownKey: 1 } });
  check("E2. an unknown key is refused", r.status === 400 && /Unknown theme key/.test(r.body.error) && fake.db.writes.length === 0);
  r = await callRoute(L, "post", "/api/themes", { name: "Mine", theme: { glow_a: "#112233", glow_a_alpha: 9 } });
  const row = fake.db.member_themes[0];
  check("E2. a good theme is stored, clamped, under the caller's id, and the answer lists it with the page list",
    r.status === 201 && row && row.user_id === UID && row.theme.glow_a === "#112233" && row.theme.glow_a_alpha === 0.5 &&
    r.body.created_id === row.id && r.body.pages.length === 57);
  fake.db.member_themes.push({ id: "bbbbbbbb-0000-4000-8000-000000000009", user_id: OTHER, name: "Theirs", theme: LIBX.DEFAULT_THEME });
  r = await callRoute(L, "get", "/api/themes");
  check("E3. GET answers only the caller's themes", r.body.themes.length === 1 && r.body.themes[0].id === row.id);
  r = await callRoute(L, "put", "/api/themes/apply", { theme_id: "bbbbbbbb-0000-4000-8000-000000000009", scope: "all" });
  check("E3. another member's theme cannot be applied", r.status === 400);
  const writesBefore = fake.db.writes.length;
  r = await callRoute(L, "put", "/api/themes/apply", { theme_id: row.id, scope: "pages", pages: ["crm.html", "evil.html"] });
  check("E3. an unknown page key is refused and nothing is written", r.status === 400 && fake.db.writes.length === writesBefore);
  r = await callRoute(L, "put", "/api/themes/apply", { theme_id: row.id, scope: "pages", pages: ["crm.html", "seo.html"] });
  const pr = () => fake.db.user_preferences.filter(x => x.user_id === UID)[0];
  check("E3. scope pages writes those pages' theme to the caller's preferences", r.status === 200 && pr().page_themes["crm.html"] === row.id && pr().page_themes["seo.html"] === row.id);
  r = await callRoute(L, "put", "/api/themes/" + "bbbbbbbb-0000-4000-8000-000000000009", { name: "Mine now" });
  check("E4. another member's theme cannot be renamed", r.status === 404 && fake.db.member_themes[1].name === "Theirs");
  r = await callRoute(L, "put", "/api/themes/not-an-id", { name: "x" });
  check("E4. an id that is not a uuid is a 404", r.status === 404);
  r = await callRoute(L, "post", "/api/themes/reset", { scope: "page", pages: ["crm.html"] });
  check("E5. reset of one page removes only it", pr().page_themes["crm.html"] === undefined && pr().page_themes["seo.html"] === row.id);
  r = await callRoute(L, "post", "/api/themes/reset", { scope: "all" });
  check("E5. reset all clears the main theme and every page", pr().default_theme_id === null && JSON.stringify(pr().page_themes) === "{}");
  await callRoute(L, "put", "/api/themes/apply", { theme_id: row.id, scope: "all" });
  r = await callRoute(L, "delete", "/api/themes/" + row.id);
  check("E6. deleting a theme deletes only the caller's row, and the pages and main theme that wore it go back",
    r.status === 200 && fake.db.member_themes.length === 1 && fake.db.member_themes[0].user_id === OTHER && pr().default_theme_id === null &&
    fake.db.writes.filter(w => w.table === "member_themes" && w.op === "delete").every(w => w.filters.some(f => f[0] === "user_id" && f[1] === UID)));
  const jpgFile = { field: "photo", mimetype: "image/jpeg", buffer: jpg };
  r = await callRoute(L, "post", "/api/themes/photo", {}, jpgFile);
  check("E7. a JPEG is stored in the member's own folder, theme-photos/<id>/<time>.jpg, in bf-public",
    r.status === 201 && fake.db.uploads.length === 1 && fake.db.uploads[0].bucket === "bf-public" && LIBX.ownPhotoPath(fake.db.uploads[0].path, UID) && r.body.path === fake.db.uploads[0].path,
    JSON.stringify(r));
  r = await callRoute(L, "post", "/api/themes/photo", {}, { field: "photo", mimetype: "image/jpeg", buffer: Buffer.concat([jpg, Buffer.alloc(5 * 1024 * 1024)]) });
  check("E7. a photo over 5 MB is refused (413) and nothing is stored", r.status === 413 && fake.db.uploads.length === 1);
  r = await callRoute(L, "post", "/api/themes/photo", {}, { field: "photo", mimetype: "image/gif", buffer: gif });
  check("E7. a GIF is refused (400)", r.status === 400 && fake.db.uploads.length === 1);
  r = await callRoute(L, "post", "/api/themes/photo", {}, { field: "photo", mimetype: "image/jpeg", buffer: png });
  check("E7. a PNG labelled as a JPEG is refused (400)", r.status === 400 && fake.db.uploads.length === 1);
  const photoPath = fake.db.uploads[0].path;
  r = await callRoute(L, "post", "/api/themes", { name: "Photo", theme: { middle: "photo", photo: photoPath, photo_luma: 0.3 } });
  const prow = fake.db.member_themes.filter(x => x.name === "Photo")[0];
  check("E8. a theme holding the member's photo is saved, and GET gives its public URL", r.status === 201 && /^https:\/\/x\.supabase\.co\/storage\/v1\/object\/public\/bf-public\/theme-photos\//.test(r.body.themes.filter(t => t.id === prow.id)[0].photo_url));
  r = await callRoute(L, "post", "/api/themes", { name: "Theirs", theme: { middle: "photo", photo: photoPath } }, null, OTHER);
  check("E8. another member cannot save a theme with that photo", r.status === 400 && r.body.key === "photo");
  r = await callRoute(L, "delete", "/api/themes/" + prow.id);
  check("E8. deleting the last theme that used a photo removes the photo", fake.db.removed.indexOf(photoPath) !== -1);
  return exportAndDelete();
}

/* ── F, G. export, deletion, migration, KEPT ────────────────────────────── */
async function exportAndDelete() {
  console.log("\n══ F. themes are exported and deleted with the account; the migration ══");
  const entry = YD.DATA.filter(d => d.table === "member_themes")[0];
  check("F1. lib/yourData.js lists member_themes, owned by user_id, deleted with the account", !!entry && JSON.stringify(entry.owner) === "[\"user_id\"]" && entry.onDelete === "delete" && entry.export !== false);
  check("F1. ... and it is on the delete order", YD.DELETE_ORDER.concat(YD.FINAL_DELETES).indexOf("member_themes") !== -1);
  const rowsByTable = { member_themes: [{ id: "t-1", user_id: UID, name: "Ember", theme: LIBX.DEFAULT_THEME }, { id: "t-2", user_id: OTHER, name: "Theirs", theme: LIBX.DEFAULT_THEME }],
    user_preferences: [{ user_id: UID, default_theme_id: "t-1", page_themes: { "crm.html": "t-1" } }] };
  function chain(table) {
    const filters = [];
    const q = new Proxy({}, { get(target, prop) {
      if (prop === "then") return (a, b) => Promise.resolve({ data: (rowsByTable[table] || []).filter(r => filters.every(([c, v]) => r[c] === v)), error: null }).then(a, b);
      if (prop === "eq") return (c, v) => { filters.push([c, v]); return q; };
      if (prop === "maybeSingle" || prop === "single") return () => q.then(r => ({ data: r.data[0] || null, error: null }));
      return () => q;
    } });
    return q;
  }
  let out = "";
  const manifest = await YD.exportAccountData({ supabase: { from: chain }, userId: UID, write: t => { out += t; } });
  let parsed = null; try { parsed = JSON.parse(out); } catch (e) { parsed = null; }
  const mt = parsed && parsed.tables && parsed.tables.member_themes;
  check("F2. the data export carries the member's themes, and only theirs", !!mt && mt.length === 1 && mt[0].name === "Ember" && manifest.complete,
    parsed ? JSON.stringify(mt) : "export did not parse");
  check("F2. ... and their main theme and pages, in user_preferences", parsed && parsed.tables.user_preferences && parsed.tables.user_preferences[0] &&
    parsed.tables.user_preferences[0].page_themes["crm.html"] === "t-1");
  const photoKey = "theme-photos/" + UID + "/1700000000000.jpg";
  const storage = { from(bucket) { return { list: async (prefix) => {
    if (bucket !== "bf-public") return { data: [], error: null };
    if (!prefix) return { data: [{ name: "theme-photos", id: null }, { name: "avatars", id: null }], error: null };
    if (prefix === "theme-photos/" + UID) return { data: [{ name: "1700000000000.jpg", id: "obj" }], error: null };
    return { data: [], error: null };
  } }; } };
  let owned = [];
  try { owned = await AF.filesOwnedBy({ supabase: { from: chain }, storage, userId: UID, publicUrlBase: "https://x.supabase.co" }); } catch (e) { owned = [{ error: e.message }]; }
  check("F3. the account delete finds the member's backdrop photo (lib/accountFiles.js, by its folder)", owned.some(f => f.bucket === "bf-public" && f.path === photoKey), JSON.stringify(owned).slice(0, 200));
  const mig = FILES[MIG];
  check("F4. migration 154 creates member_themes (id, user_id, name, theme jsonb, created_at, updated_at) with RLS on",
    /CREATE TABLE IF NOT EXISTS public\.member_themes \(/.test(mig) && ["id ", "user_id ", "name ", "theme ", "created_at ", "updated_at "].every(c => mig.indexOf("  " + c) !== -1) &&
    /theme\s+jsonb\s+NOT NULL/.test(mig) && /ALTER TABLE public\.member_themes ENABLE ROW LEVEL SECURITY;/.test(mig) && /REFERENCES public\.users\(id\) ON DELETE CASCADE/.test(mig));
  check("F4. ... and user_preferences gains default_theme_id and page_themes jsonb", /ADD COLUMN IF NOT EXISTS default_theme_id uuid REFERENCES public\.member_themes\(id\) ON DELETE SET NULL/.test(mig) &&
    /ADD COLUMN IF NOT EXISTS page_themes jsonb NOT NULL DEFAULT '\{\}'::jsonb/.test(mig));
  check("F4. it changes no existing row (no UPDATE, no DELETE)", !/^\s*(UPDATE|DELETE)\b/im.test(mig.replace(/^--.*$/gm, "")));

  console.log("\n══ G. bf_theme is a KEPT device key ══");
  const left = /LEFT ON PURPOSE[\s\S]*?\*\//.exec(FILES[SESSION]);
  const perUser = /var PER_USER_LOCAL = \[[\s\S]*?\];/.exec(FILES[SESSION]);
  check("G1. bf-session.js names bf_theme as left on purpose, and sign-out does not clear it", !!left && /bf_theme \(/.test(left[0]) && !!perUser && perUser[0].indexOf("bf_theme") === -1);
  check("G1. checkOfflineMode's KEPT inventory has bf_theme", /const KEPT = \{[\s\S]*?\n      bf_theme: "/.test(FILES[OFFCHECK]));
  check("G1. bf-theme.js stores under that one key", /var CACHE_KEY = "bf_theme";/.test(FILES[THEME]) && (FILES[THEME].match(/localStorage\.setItem\(/g) || []).length === 1);
  finish();
}

let finished = false;
function finish() {
  if (finished) return;
  finished = true;
  console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
}
