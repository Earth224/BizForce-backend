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
     G  bf_theme is the member's: sign-out clears it (bf-session.js
        PER_USER_LOCAL, run in jsdom, and checkOfflineMode's PER_USER), and a
        signed-out page applies none of it.
     H  Block 4b, the element palettes: the buttons, the mist, the chat glow,
        the guide's lettering and the wordmark.
        H1 lib/themes.js and bf-theme.js hold the same defaults, sections and
           Match everything rule; the validator covers every new key and
           refuses raw CSS in each.
        H2 Match everything derives EXACTLY by the documented rule (recomputed
           here from the rule's own words), on the server and in the page.
        H3 with no theme, every place renders today: each changed page, the
           shared CSS, the mist's and the guide's CSS, read with every element
           var() resolved to its fallback, is the text it was at 7e74ca8 (the
           NAMED differences listed there); the stars' colours are the old
           table's.
        H4 no hard-coded colour is left in those elements: the wordmark on
           every themed page that shows it (and the dashboard's two), every
           primary button gradient on every themed page, the guide's
           lettering, every colour the mist draws, the chat glow.
        H5 in jsdom: a theme sets each element's tokens, only for the parts
           not at the original; through all / page / pages; the mist's stops
           follow the documented lightness rule.
        H6 readability: unreadable button text, guide text or wordmark is
           corrected (white or near-black text, a shaded gradient, a lightened
           colour) to 4.5 / 4.5 / 3, never refused.
        H7 reduced motion stops the mist, its stars and the chat glow.
        H8 public pages and cards keep the owner's look: every UNTHEMED page
           and digital-cards' card swatches are as they were, and a public page
           wears no element token from the visitor's theme.
        C12 … C19 the studio's new sections, presets, Match my theme, Match
           everything, the resets, the preview and the meter.
     I  Block 4c, the theme routes reachable. Live, "Save as…" got a 404: the
        studio's base was window.API_URL or "", settings.html keeps API_URL
        inside its own function, so every request was a relative /api/themes,
        sent to Netlify. The fake pages here answer ONLY at the API's origin and
        a route server.js registers (anything else is a stray: I1), and the
        studio's fake page declares API_URL as settings.html does. I2 parses
        every request from the studio's and bf-theme.js's code and matches it,
        method and path, to server.js's routes before its catch-all 404; I3
        runs server.js's CORS middleware for bizforceai.net's preflight of each
        method; I1 runs every route in jsdom; I4 a failure names its status.

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
const ELEMENTS_BEFORE = "7e74ca8"; // the frontend before Block 4b (the element palettes)
/* NAMED BEFORE → AFTER (Oct 30 2026, the Executive command deck and no emojis): H3 and H8 compared each page's
   text TODAY with 7e74ca8, so any later edit to a page (a removed duplicate heading, an emoji drawn as an
   SVG) read as a theme change. AFTER: the 7e74ca8 proof is made on each page as it stood at THEMES_DONE, the
   frontend's last theme commit; and today's text must keep every theme-bearing line (a --bf- or --tmx- token
   or var(), the wordmark class, the engine's script tag) exactly as it was there, in order. A line added since
   may carry a theme token only through var(--token, fallback) (the deck's tabs wear the member's button
   colours that way), so with no theme it draws its fallback. A later edit that touches no such line passes;
   one that changes a colour, drops a wordmark's var(), or loads the engine on a public page does not. */
const THEMES_DONE = "8ec140e";
const MUTATE = process.env.MUTATE || "";

const SERVER = "server.js", LIB = "lib/themes.js", YOURDATA = "lib/yourData.js", ACCFILES = "lib/accountFiles.js";
const MIG = "supabase/migrations/154_member_themes.sql", OFFCHECK = "scripts/checkOfflineMode.js";
const THEME = "scripts/bf-theme.js", STUDIO = "scripts/bf-theme-studio.js", SETTINGS = "settings.html";
const SESSION = "scripts/bf-session.js", UI = "css/bizforce-ui.css", SHELL = "css/agent-shell.css";
const PRESENCE = "scripts/termaximus-presence.js", GUIDE = "scripts/termaximus-guide.js";
const PUBLIC_WITH_BACKDROP = ["seller.html", "blogindex.html", "blogpost.html", "listing.html", "suppressed.html", "vitality.html"];
const UID = "53e6b330-d31c-4958-a10b-516397e7b9c9";
const OTHER = "11111111-2222-4333-8444-555555555555";
const TAG = "<script src=\"/scripts/bf-theme.js\"></script>";
/* The API's one origin. The fake pages below answer ONLY there, at a path
   server.js registers; anything else (a relative "/api/themes", which goes to
   Netlify, or a path the server lacks) is recorded in STRAY, answered as
   Netlify answers it (404, not JSON), and fails I1. */
const API_ORIGIN = "https://dynamic-prosperity-production-5382.up.railway.app";
const STRAY = [];
const HIT = new Set();   // "METHOD /route/:path" the studio reached in jsdom
let OPEN_STUDIO = null;  // C's studio page opener, for I
const NETLIFY_404 = () => ({ ok: false, status: 404, json: async () => { throw new SyntaxError("Unexpected token '<'"); } });

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
  /* NAMED BEFORE → AFTER (Block 4d). BEFORE the anchor was "var alive = t.alive === true && !reducedMotion(win || window);".
     AFTER: tokensFor's line reads "!reducedMotion(win);" (win is set just above it, so a page without a window, the
     server's vm, never reaches window). The same mutation: alive is no longer turned off under reduced motion. */
  "alive-reduced-motion": [[THEME, "    var alive = t.alive === true && !reducedMotion(win);", "    var alive = t.alive === true;"],
    [THEME, "  :root[data-bf-alive=\\\"1\\\"] body::before { inset: 0; animation: none; will-change: auto; }\\n", "\\n"]],
  // the cache applied after paint (B)
  /* NAMED BEFORE → AFTER (Block 4b). BEFORE the anchor was "if (cache && (!uid || cache.uid === uid))": a signed-out
     page applied the cache. AFTER: "if (cache && uid && cache.uid === uid)"; only the member it belongs to. */
  "cache-after-paint": [[THEME, "    if (cache && uid && cache.uid === uid) applyState(cache.state, win, doc);",
    "    if (cache && uid && cache.uid === uid) win.setTimeout(function () { applyState(cache.state, win, doc); }, 0);"]],
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
  /* NAMED BEFORE → AFTER (Block 4b). BEFORE: "kept-missing" dropped bf_theme from checkOfflineMode's KEPT list.
     AFTER: bf_theme is on its PER_USER list, so the mutation drops it from there (G). */
  "offline-inventory-missing": [[OFFCHECK, "\"mcTargetGoalConversions\", \"bf_theme\"];", "\"mcTargetGoalConversions\"];"]],
  // ── Block 4b ──
  // the mist keeping a hard-coded colour (H4)
  "mist-hard-coded": [[PRESENCE, "    \"    rgba(var(--tmx-haze-1, 48,12,150),0.88)   0%,\",", "    \"    rgba(48,12,150,0.88)   0%,\","]],
  // the wordmark missed on one page (H4)
  /* NAMED BEFORE → AFTER (Block 4d). BEFORE the anchor was "var(--bf-mark-a, #22d3ee),var(--bf-mark-b, #a855f7)".
     AFTER: the wordmark gained its middle stop, "var(--bf-mark-a, #22d3ee)var(--bf-mark-mid, ),var(--bf-mark-b, #a855f7)".
     The same mutation: crm.html's wordmark back to a hard-coded gradient. */
  "wordmark-missed": [["crm.html", "background:linear-gradient(90deg,var(--bf-mark-a, #22d3ee)var(--bf-mark-mid, ),var(--bf-mark-b, #a855f7))", "background:linear-gradient(90deg,#22d3ee,#a855f7)"]],
  // Match everything using a different rule (H1, H2)
  /* NAMED BEFORE → AFTER (Block 4d). BEFORE the anchor was "guide_a: mixHex(a, W, 0.35), guide_b: mixHex(b, W, 0.35),".
     AFTER: the guide's middle sits between them, "guide_mid: mixHex(m, W, 0.35),". The same mutation: guide_a by 0.4. */
  "match-rule-changed": [[LIB, "    guide_a: mixHex(a, W, 0.35), guide_mid: mixHex(m, W, 0.35), guide_b: mixHex(b, W, 0.35),", "    guide_a: mixHex(a, W, 0.4), guide_mid: mixHex(m, W, 0.35), guide_b: mixHex(b, W, 0.35),"]],
  // button text left unreadable (H6, C)
  "button-text-unreadable": [[THEME, "    if (!btn.original && btn.before < BTN_MIN) {", "    if (false) {"]],
  // the visitor's theme on a public page (B6, H8)
  "public-page-visitor-theme": [[THEME, "    if (UNTHEMED.indexOf(key) !== -1) return true;", "    if (false) return true;"]],
  // bf_theme surviving sign-out (G)
  "theme-survives-signout": [[SESSION, "    \"mcTargetGoalConversions\",\n    \"bf_theme\"\n  ];", "    \"mcTargetGoalConversions\"\n  ];"]],
  // ── Block 4c: the theme routes reachable ──
  // the live bug: the studio's base back to window.API_URL or "", a relative /api/themes (B, C, I)
  "relative-themes-url": [[STUDIO, "  function api() { return T.apiOrigin(); }",
    "  function api() { return (typeof window.API_URL === \"string\" && window.API_URL) || \"\"; }"]],
  // a studio path the server does not register (I2, I1)
  "studio-path-unregistered": [[STUDIO, "call(\"POST\", \"/api/themes/reset\", { scope: \"all\" }, \"reset\")", "call(\"POST\", \"/api/themes/reset-all\", { scope: \"all\" }, \"reset\")"]],
  // the right path at the wrong method (I2, I1, C6)
  "studio-method-mismatch": [[STUDIO, "call(\"PUT\", \"/api/themes/apply\", body, \"apply\")", "call(\"POST\", \"/api/themes/apply\", body, \"apply\")"]],
  // PUT missing from CORS (I3)
  "cors-put-missing": [[SERVER, "res.setHeader(\"Access-Control-Allow-Methods\", \"GET,POST,PUT,PATCH,DELETE,OPTIONS\");", "res.setHeader(\"Access-Control-Allow-Methods\", \"GET,POST,PATCH,DELETE,OPTIONS\");"]],
  // a failure that hides its status again (I4)
  "error-hides-status": [[STUDIO, "throw new Error(\"Couldn't \" + what + \" (\" + res.status + (res.ok ? \", not JSON\" : \"\") + \"). Try again.\");", "throw new Error(\"That did not work. Try again.\");"]]
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
[THEME, STUDIO, SESSION, UI, SHELL, PRESENCE, GUIDE].forEach(f => { FILES[f] = frontFile(f); });
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
/* NAMED BEFORE → AFTER (Block 4d, the photo editor). BEFORE: both layers had "inset: 0". AFTER: the photo layer's
   inset is var(--bf-bg-inset, 0): 0 unless the photo is blurred, when it reaches 2 × the blur past each edge so the
   blur never shows a soft rim. With no theme it is still 0, which is what this pins. */
check("A5. both layers are fixed, cover the viewport and never take a tap",
  [ruleHtml, ruleBody].every(d => d.position === "fixed" && d.inset.replace(/^var\(--bf-bg-inset, 0\)$/, "0") === "0" && d["pointer-events"] === "none" && d.content === "\"\"") &&
  ruleBody.inset === "0");
const uiTokens = rulesOf(FILES[UI], /^:where\(:root\)$/)[0] || {};
const uiDiff = Object.keys(uiTokens).filter(k => uiTokens[k] !== ruleRoot[k]);
const uiBg = (rulesOf(FILES[UI], /^:root$/)[0] || {})["--bf-bg"];
check("A6. css/bizforce-ui.css declares the theme tokens at today's values, the same as the rule's (" + Object.keys(uiTokens).length + ", and --bf-bg)",
  Object.keys(uiTokens).length >= 9 && uiDiff.length === 0 && uiBg === ruleRoot["--bf-bg"], uiDiff.join(","));
const themeTokens = (() => { const m = /var THEME_TOKENS = (\[[\s\S]*?\]);/.exec(FILES[THEME]); try { return vm.runInNewContext(m[1]); } catch (e) { return []; } })();
check("A6. the tokens a theme sets are the brief's eight, plus the channels and the scrim",
  ["--bf-bg", "--bf-bg-image", "--bf-bg-dim", "--bf-glow-a", "--bf-glow-b", "--bf-glow-a-alpha", "--bf-glow-b-alpha", "--bf-alive"].every(t => themeTokens.indexOf(t) !== -1 && ruleRoot[t] !== undefined) &&
  themeTokens.every(t => ruleRoot[t] !== undefined), themeTokens.join(","));
/* NAMED BEFORE → AFTER (Block 4d, the photo editor). BEFORE: "var(--bf-bg-image) center / cover no-repeat".
   AFTER: "var(--bf-bg-image) var(--bf-bg-pos, center) / var(--bf-bg-size, cover) no-repeat": the member's focal point
   and zoom, which fall back to centred and covering, as before. */
check("A7. the photo is centred, covers, and sits on a fixed layer (no background-attachment: fixed, which repaints on scroll)",
  /var\(--bf-bg-image\) var\(--bf-bg-pos, center\) \/ var\(--bf-bg-size, cover\) no-repeat/.test(ruleHtml.background || "") && !/background-attachment/.test(RULE));

/* ── B. bf-theme.js in a page ───────────────────────────────────────────── */
console.log("\n══ B. bf-theme.js: before first paint, the member's own, per page, public pages, motion, readability ══");
const b64 = o => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=+$/, "");
const tokenFor = id => "h." + b64({ id: id }) + ".s";
const T1 = { id: "aaaaaaaa-0000-4000-8000-000000000001", name: "Ember", photo_url: null,
  theme: Object.assign({}, LIBX.DEFAULT_THEME, { glow_a: "#ff7a18", glow_b: "#ff2e63", glow_a_alpha: 0.18, glow_b_alpha: 0.16 }) };
const T2 = { id: "aaaaaaaa-0000-4000-8000-000000000002", name: "Royal", photo_url: null,
  theme: Object.assign({}, LIBX.DEFAULT_THEME, { glow_a: "#6366f1", glow_b: "#f5c542", middle: "colour", bg: "#0a0a24", alive: true }) };
/* Block 4b: a theme that colours every element (and leaves the corners at today's). */
const T3 = { id: "aaaaaaaa-0000-4000-8000-000000000003", name: "Parts", photo_url: null,
  theme: Object.assign({}, LIBX.DEFAULT_THEME, { btn_a: "#ff7a18", btn_b: "#ff2e63", btn_text: "#ffffff", mist_core: "#22c55e", mist_haze: "#14532d",
    mist_spark: "#fde68a", chat_glow_a: "#f97316", chat_glow_b: "#db2777", guide_a: "#fb923c", guide_b: "#f472b6", mark_a: "#fb923c", mark_b: "#f43f5e" }) };
const stateOf = (main, pages, themes) => ({ themes: themes || [T1, T2, T3], default_theme_id: main, page_themes: pages || {}, pages: [] });

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
        const method = ((opts && opts.method) || "GET").toUpperCase();
        if (String(u) !== API_ORIGIN + "/api/themes" || method !== "GET") { STRAY.push("bf-theme.js " + method + " " + u); return Promise.resolve(NETLIFY_404()); }
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
  /* NAMED BEFORE → AFTER (Block 4c). BEFORE: the URL had only to end in /api/themes. AFTER: it is exactly the API's
     origin + /api/themes; a relative or foreign one is a stray (I1). */
  check("B3. ... and the member's own themes are fetched instead, at " + API_ORIGIN + "/api/themes", p.calls.length === 1 && p.calls[0].u === API_ORIGIN + "/api/themes" &&
    /^Bearer /.test(p.calls[0].opts.headers.Authorization));
  p = await themePage({ token: null, cache: cacheOf(UID, stateOf(T1.id)) });
  /* NAMED BEFORE → AFTER (Block 4b). BEFORE: "signed out, the device's cache is shown and nothing is fetched"
     (--bf-glow-a #ff7a18). AFTER: signed out, nothing of a member's theme is applied: sign-out clears bf_theme, and a
     cache left by any other path is still not shown, so the sign-in page wears the original look. */
  check("B3. signed out, no cached theme is applied (the sign-in page shows the original look) and nothing is fetched",
    p.get("--bf-glow-a") === "" && p.w.BFTheme.THEME_TOKENS.every(t => p.get(t) === "") && p.calls.length === 0);

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
  /* NAMED BEFORE → AFTER (Block 4c). BEFORE: "loads bf-theme-studio.js after its own script" (after the text
     "var API_URL"), and the fake page declared a GLOBAL var API_URL = "https://api.test" — which the real page does not,
     so a studio relying on window.API_URL passed here and failed live. AFTER: the studio loads after bf-theme.js (whose
     apiOrigin it uses), and the fake page declares API_URL exactly as settings.html does: inside its own function. */
  const settingsDecl = /<script>\s*\(function \(\) \{\s*var API_URL = "([^"]+)";/.exec(FILES[SETTINGS]);
  check("C0. settings.html loads bf-theme-studio.js after bf-theme.js, and #theme opens the section",
    FILES[SETTINGS].indexOf("<script src=\"/scripts/bf-theme-studio.js\"></script>") > FILES[SETTINGS].indexOf(TAG) && FILES[SETTINGS].indexOf(TAG) !== -1 &&
    /if \(window\.location\.hash === "#theme"\) activateSection\("theme"\);/.test(FILES[SETTINGS]));
  check("C0. settings.html keeps its API_URL inside its own function (so window.API_URL is unset where the studio runs), and this fake page does the same",
    !!settingsDecl && settingsDecl[1] === API_ORIGIN && !/^var API_URL\s*=/m.test(FILES[SETTINGS]));
  const panel = FILES[SETTINGS].slice(panelAt, panelEnd);
  async function open(o) {
    const calls = [];
    const html = "<!DOCTYPE html><html><head><script>" + FILES[THEME] + "</script></head><body>" + panel +
      "<script>(function () { var API_URL = \"" + API_ORIGIN + "\"; })();</script><script>" + FILES[STUDIO] + "</script></body></html>";
    const dom = new JSDOM(html, {
      url: o.url || "https://bizforceai.net/settings.html?page=crm.html", runScripts: "dangerously", pretendToBeVisual: true,
      beforeParse(w) {
        w.localStorage.setItem("bf_token", tokenFor(UID));
        w.matchMedia = q => ({ matches: !!o.reduce && /prefers-reduced-motion: reduce/.test(q), addEventListener() {} });
        w.fetch = (u, opts) => {
          const method = ((opts && opts.method) || "GET").toLowerCase();
          if (String(u).indexOf(API_ORIGIN + "/") !== 0) { calls.push(method + " " + u); STRAY.push("studio " + method.toUpperCase() + " " + u + " (not the API's origin)"); return Promise.resolve(NETLIFY_404()); }
          const url = new URL(String(u));
          calls.push(method + " " + url.pathname);
          const hit = match(lifted.routes, method, url.pathname);
          if (!hit) STRAY.push("studio " + method.toUpperCase() + " " + url.pathname + " (not a route in server.js)");
          else HIT.add(method.toUpperCase() + " " + hit.r.path);
          if (o.netlify && method !== "get") return Promise.resolve(NETLIFY_404());
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
  OPEN_STUDIO = open;
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
  /* NAMED BEFORE → AFTER (Block 4d, ten designed presets). BEFORE: six preset cards, Default, Ember, Verdant, Royal,
     Rosé, Mono, and the studio flow below used Ember (#ff7a18). AFTER: Original and the ten designed presets, and the
     flow uses Solar Flare (corner #ffb000); each preset's design is proved in scripts/checkThemeSpectrums.js. */
  const PRESET_NAMES = ["Original", "Solar Flare", "Deep Reef", "Nebula", "Emerald Throne", "Obsidian Rose", "Arctic", "Phoenix", "Amethyst", "Black Sun", "Mono Silver"];
  check("C3. eleven preset cards: Original and the ten designed presets", JSON.stringify(presets) === JSON.stringify(PRESET_NAMES), presets.join(","));
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
  st.d.querySelector(".ts-preset[data-preset=solar-flare]").click();
  check("C3. a preset fills the controls and is shown pressed", $("tsGlowAHex").value === "#ffb000" &&
    st.d.querySelector(".ts-preset[data-preset=solar-flare]").getAttribute("aria-pressed") === "true" && $("tsName").value === "Solar Flare");
  $("tsAlive").checked = true; fire($("tsAlive"), "change");
  check("C4. \"Alive corners\" makes the preview drift", $("tsPreview").getAttribute("data-alive") === "1");
  $("tsSaveAs").click(); await settle();
  const saved = fake.db.member_themes[0];
  check("C5. \"Save as…\" stores the theme, validated, under the member's id", fake.db.member_themes.length === 1 && saved.user_id === UID && saved.name === "Solar Flare" &&
    saved.theme.glow_a === "#ffb000" && saved.theme.alive === true);
  check("C5. ... lists it, and the editor is now editing it", st.d.querySelectorAll("#tsSavedList li").length === 1 && /Editing "Solar Flare"/.test($("tsEditing").textContent));
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
  check("C6. the settings page itself now wears it (the cache and the tokens are updated at once)", st.d.documentElement.style.getPropertyValue("--bf-glow-a") === "#ffb000" &&
    JSON.parse(st.w.localStorage.getItem("bf_theme")).state.default_theme_id === saved.id);
  const rows = st.d.querySelectorAll("#tsAssignments li");
  check("C7. \"Pages and their themes\" lists each page with its own theme, with \"Reset this page to the main theme\"",
    rows.length === agentKeys.length + 2 && Array.prototype.every.call(rows, li => /Reset this page to the main theme/.test(li.textContent)) &&
    /Main theme: Solar Flare\./.test($("tsMainTheme").textContent));
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
  /* NAMED BEFORE → AFTER (Block 4d). BEFORE: three parts, "Top-left glow", "Bottom-right glow", "Middle backdrop".
     AFTER: "Middle tone" sits between the corners (the spectrum's centre) and "Motion" follows the backdrop. */
  check("C10. the parts are fieldsets with their legends: \"Top-left glow\", \"Middle tone\", \"Bottom-right glow\", \"Middle backdrop\", \"Motion\"",
    JSON.stringify(Array.prototype.map.call(st.d.querySelectorAll(".ts-controls > fieldset > legend"), l => l.textContent)) === JSON.stringify(["Top-left glow", "Middle tone", "Bottom-right glow", "Middle backdrop", "Motion"]));
  st.w.close();
  const rm = await open({ reduce: true });
  rm.d.getElementById("tsAlive").checked = true; rm.d.getElementById("tsAlive").dispatchEvent(new rm.w.Event("change"));
  check("C11. under reduced motion the preview stays still, and says why", rm.d.getElementById("tsPreview").getAttribute("data-alive") === "0" &&
    /reduced motion/.test(rm.d.getElementById("tsAliveNote").textContent));
  /* NAMED BEFORE → AFTER (Block 4d, motion styles). BEFORE: the rule's selector was the drift's alone,
     ".ts-preview[data-alive="1"] .ts-pv-glows". AFTER: it also names every style's selector ([data-motion]), so
     drift, aurora and nebula stop too. */
  check("C11. the preview's CSS also stops the drift under prefers-reduced-motion",
    /@media \(prefers-reduced-motion: reduce\) \{ \.ts-preview\[data-alive="1"\] \.ts-pv-glows, \.ts-preview\[data-alive="1"\]\[data-motion\] \.ts-pv-glows \{[^}]*animation: none/.test(FILES[SETTINGS]));
  check("C11. ... and the preview's mist and chat glow hold still there too",
    /@media \(prefers-reduced-motion: reduce\) \{ \.ts-pv-core, \.ts-pv-spark, \.ts-pv-star, \.ts-pv-chatglow \{ animation: none; \} \}/.test(FILES[SETTINGS]));
  rm.w.close();

  // ── Block 4b: every colour ──
  const ev = await open({});
  const e$ = id => ev.d.getElementById(id);
  const efire = (el, type) => el.dispatchEvent(new ev.w.Event(type, { bubbles: true }));
  const legendsEl = Array.prototype.map.call(ev.d.querySelectorAll("#tsElements > fieldset > legend"), l => l.textContent);
  /* NAMED BEFORE → AFTER (Block 4d, every gradient follows the theme). BEFORE: five sections, and each part's chips
     were the six old presets. AFTER: a sixth, "Headings and accents" (the --bf-accent-* tokens every app page's
     gradients now read), and each part's chips are the eleven presets. */
  check("C12. six sections, in the studio's style: \"Buttons\", \"Termaximus mist\", \"Chat glow\", \"Guide text\", \"BizForceAI wordmark\", \"Headings and accents\"",
    JSON.stringify(legendsEl) === JSON.stringify(["Buttons", "Termaximus mist", "Chat glow", "Guide text", "BizForceAI wordmark", "Headings and accents"]), legendsEl.join(" · "));
  const PART = ev.w.BFThemeStudio.PARTS;
  const sectionOk = Array.prototype.every.call(ev.d.querySelectorAll("#tsElements > fieldset"), fs => {
    const part = fs.getAttribute("data-el");
    const names = Array.prototype.map.call(fs.querySelectorAll(".ts-el-preset"), b => b.textContent.trim());
    const colours = PART[part].every(p => fs.querySelector("#" + p[1] + "Color[type=color]") && fs.querySelector("#" + p[1] + "Hex[type=text]"));
    const acts = Array.prototype.map.call(fs.querySelectorAll(".ts-el-actions button"), b => b.textContent.trim());
    return JSON.stringify(names) === JSON.stringify(PRESET_NAMES) && colours &&
      JSON.stringify(acts) === JSON.stringify(["Match my theme", part === "mist" ? "Reset mist to original" : "Reset this element"]);
  });
  check("C12. each has the eleven presets (Original and the ten designed), a colour picker and a hex field for each of its colours, \"Match my theme\" and its reset",
    sectionOk && PART.mist.length === 8);
  check("C12. the mist's eleven palettes reach every mist colour, each preset differing", (() => {
    const seen = ev.w.BFTheme.PRESETS.map(p => JSON.stringify(ev.w.BFThemeStudio.partPreset("mist", p.id)));
    return seen.length === 11 && new Set(seen).size === 11 && seen.every(x => Object.keys(JSON.parse(x)).length === 8);
  })());
  const pv = e$("tsPreview");
  check("C13. the live preview shows the mist, the chat glow, a button, a guide tip and the wordmark together",
    [".ts-pv-mist", ".ts-pv-chatglow", ".ts-pv-btn", ".ts-pv-guide", ".ts-pv-mark", ".ts-pv-core", ".ts-pv-haze", ".ts-pv-spark"].every(sel => pv.querySelector(sel)));
  check("C13. the preview starts from every element at the original, so it never shows the theme the page wears",
    pv.style.getPropertyValue("--bf-btn-a") === "#06b6d4" && pv.style.getPropertyValue("--tmx-core-1") === "255, 255, 255" && pv.style.getPropertyValue("--tmx-chat-glow-c") === "168, 85, 247");
  e$("tsBtnAHex").value = "#123456"; efire(e$("tsBtnAHex"), "change");
  const btnNow = ev.w.BFTheme.readability(Object.assign({}, ev.w.BFTheme.DEFAULT_THEME, { btn_a: "#123456" })).elements.buttons;
  check("C13. a part's colour shows at once in the preview (the button's gradient start #123456, as readability keeps its white lettering clear: " + btnNow.a + " → " + btnNow.b + ")",
    pv.style.getPropertyValue("--bf-btn-a") === btnNow.a && pv.style.getPropertyValue("--bf-btn-b") === btnNow.b && btnNow.a !== "#06b6d4" && btnNow.ratio >= 4.5);
  ev.d.querySelector(".ts-el-preset[data-el=mist][data-preset=solar-flare]").click();
  const emberMist = ev.w.BFThemeStudio.partPreset("mist", "solar-flare");
  check("C14. a mist palette fills every mist colour and is shown pressed, and the preview's mist follows",
    Object.keys(emberMist).every(k => ev.w.BFTheme.normalTheme({}) && e$(PART.mist.filter(p => p[0] === k)[0][1] + "Hex").value === emberMist[k]) &&
    ev.d.querySelector(".ts-el-preset[data-el=mist][data-preset=solar-flare]").getAttribute("aria-pressed") === "true" &&
    pv.style.getPropertyValue("--tmx-core-4") !== "60, 120, 255");
  e$("tsMistWhisperHex").value = "#00ff00"; efire(e$("tsMistWhisperHex"), "change");
  check("C14. full custom: one mist colour set by hand (the whisper) leaves the others, and the palette no longer shows pressed",
    e$("tsMistWhisperHex").value === "#00ff00" && e$("tsMistCoreHex").value === emberMist.mist_core &&
    ev.d.querySelector(".ts-el-preset[data-el=mist][data-preset=solar-flare]").getAttribute("aria-pressed") === "false");
  e$("tsGuideAHex").value = "red;}x"; efire(e$("tsGuideAHex"), "change");
  check("C14. a part's hex field refuses what is not a colour, and says how", e$("tsGuideAHex").value === "#22d3ee" && /six hex digits/.test(e$("tsMsg").textContent));
  e$("tsGlowAHex").value = "#ff7a18"; efire(e$("tsGlowAHex"), "change");
  e$("tsGlowBHex").value = "#ff2e63"; efire(e$("tsGlowBHex"), "change");
  ev.d.querySelector("[data-el-match=guide]").click();
  /* NAMED BEFORE → AFTER (Block 4d, three-colour spectrums). BEFORE: matchAll(A, B). AFTER: matchAll(A, B, M), where M is
     the middle tone, which (with "Derive from corners" on, the default) follows the corners as midTone(A, B); the rule
     now also gives each middle stop and the accents. */
  const rule = ev.w.BFTheme.matchAll("#ff7a18", "#ff2e63", ev.w.BFTheme.midTone("#ff7a18", "#ff2e63"));
  check("C15. \"Match my theme\" takes that part's colours from the corners by the rule (guide text " + rule.guide_a + " → " + rule.guide_b + "), and only that part",
    e$("tsGuideAHex").value === rule.guide_a && e$("tsGuideBHex").value === rule.guide_b && e$("tsBtnAHex").value === "#123456");
  e$("tsMatchAll").checked = true; efire(e$("tsMatchAll"), "change");
  const allKeys = Object.keys(rule);
  const shown = () => { const o = {}; Object.keys(PART).forEach(pt => PART[pt].forEach(p => { o[p[0]] = e$(p[1] + "Hex").value; })); return o; };
  check("C16. \"Match everything\": every part takes the rule's colours from the two corners at once", allKeys.every(k => shown()[k] === rule[k]));
  check("C16. ... and while it is on the parts' own controls rest", e$("tsBtnAHex").disabled && ev.d.querySelector(".ts-el-preset[data-el=mark][data-preset=amethyst]").disabled);
  e$("tsGlowAHex").value = "#6366f1"; efire(e$("tsGlowAHex"), "change");
  const rule2 = ev.w.BFTheme.matchAll("#6366f1", "#ff2e63", ev.w.BFTheme.midTone("#6366f1", "#ff2e63"));
  check("C16. change a corner and every part follows", allKeys.every(k => shown()[k] === rule2[k]));
  e$("tsName").value = "Matched"; e$("tsSaveAs").click(); await settle();
  const mrow = fake.db.member_themes.filter(r => r.name === "Matched")[0];
  check("C16. saved, the theme holds match_all and exactly the derived colours", !!mrow && mrow.theme.match_all === true && allKeys.every(k => mrow.theme[k] === rule2[k]));
  e$("tsMatchAll").checked = false; efire(e$("tsMatchAll"), "change");
  check("C16. turned off, the derived colours stay where they are, for hand-tuning", allKeys.every(k => shown()[k] === rule2[k]) && !e$("tsBtnAHex").disabled);
  e$("tsMarkBHex").value = "#abcdef"; efire(e$("tsMarkBHex"), "change");
  e$("tsUpdate").click(); await settle();
  const mrow2 = fake.db.member_themes.filter(r => r.name === "Matched")[0];
  check("C16. ... and saving then keeps them, with the one tuned by hand", mrow2.theme.match_all === false && mrow2.theme.mark_b === "#abcdef" && mrow2.theme.btn_a === rule2.btn_a);
  ev.d.querySelector("[data-el-reset=buttons]").click();
  check("C17. \"Reset this element\" puts that part back to the original (the buttons), and nothing else",
    e$("tsBtnAHex").value === "#06b6d4" && e$("tsBtnBHex").value === "#8b5cf6" && e$("tsBtnTextHex").value === "#ffffff" && e$("tsMarkBHex").value === "#abcdef");
  ev.d.querySelector("[data-el-reset=mist]").click();
  check("C17. \"Reset mist to original\" puts all eight mist colours back", PART.mist.every(p => e$(p[1] + "Hex").value === ev.w.BFTheme.DEFAULT_THEME[p[0]]) &&
    ev.d.querySelector(".ts-el-preset[data-el=mist][data-preset=original]").getAttribute("aria-pressed") === "true");
  e$("tsBtnAHex").value = "#888888"; efire(e$("tsBtnAHex"), "change");
  e$("tsBtnBHex").value = "#999999"; efire(e$("tsBtnBHex"), "change");
  e$("tsBtnTextHex").value = "#999999"; efire(e$("tsBtnTextHex"), "change");
  e$("tsGuideAHex").value = "#222244"; efire(e$("tsGuideAHex"), "change");
  const lines = Array.prototype.map.call(ev.d.querySelectorAll("#tsMeterElements li"), li => li.textContent);
  check("C18. the meter lists each part: unreadable button text is set to near-black and guide text lightened, shown as \"Auto-protected\", the colours kept",
    e$("tsMeterState").textContent === "Auto-protected" && /^Button text \d+\.\d:1, set to near-black so it stays clear\.$/.test(lines[0] || "") &&
    /^Guide text \d+\.\d:1, lightened so it stays clear\.$/.test(lines[1] || "") && /^Wordmark \d+\.\d:1/.test(lines[2] || "") &&
    e$("tsBtnTextHex").value === "#999999" && pv.style.getPropertyValue("--bf-btn-text") === "#050c1a", lines.join(" | "));
  check("C18. ... and the meter's ratios pass (button text 4.5, guide text 4.5, wordmark 3)", (() => {
    const r = lines.map(l => parseFloat((/(\d+\.\d):1/.exec(l) || [])[1]));
    return r[0] >= 4.5 && r[1] >= 4.5 && r[2] >= 3;
  })());
  e$("tsResetAll").click(); await settle(); e$("tsResetAll").click(); await settle();
  const defaults = ev.w.BFTheme.DEFAULT_THEME;
  check("C19. \"Reset everything to the original\" puts every part of the editor back too, and every page on the original",
    Object.keys(PART).every(pt => PART[pt].every(p => e$(p[1] + "Hex").value === defaults[p[0]])) && !e$("tsMatchAll").checked &&
    ev.w.BFTheme.ELEMENT_TOKENS.every(t => ev.d.documentElement.style.getPropertyValue(t) === ""));
  ev.w.close();
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
  /* NAMED BEFORE → AFTER (Block 4d, corner opacity). BEFORE: alphas clamped to 0 … 0.5 ("Strength"). AFTER: 0 … 1
     ("Opacity", the same number, so a saved theme reads the same; 1 is the colour itself at the glow's centre). */
  check("D3. numbers are clamped: alphas to 0 … 1, dim to 0 … 0.85, luminance to 0 … 1", cl && cl.glow_a_alpha === 1 && cl.glow_b_alpha === 0 && cl.dim === 0.85 && cl.photo_luma === 1);
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
    r.status === 201 && row && row.user_id === UID && row.theme.glow_a === "#112233" && row.theme.glow_a_alpha === 1 &&   // NAMED (Block 4d): BEFORE 0.5, the old ceiling; AFTER 1
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

  /* NAMED BEFORE → AFTER (Block 4b). BEFORE: "G. bf_theme is a KEPT device key": bf-session.js named it LEFT ON
     PURPOSE and checkOfflineMode listed it in KEPT. AFTER: it is the member's, on PER_USER_LOCAL and PER_USER, and
     sign-out clears it (run below). */
  console.log("\n══ G. bf_theme is the member's: sign-out clears it ══");
  const left = /LEFT ON PURPOSE[\s\S]*?\*\//.exec(FILES[SESSION]);
  const perUser = /var PER_USER_LOCAL = (\[[\s\S]*?\]);/.exec(FILES[SESSION]);
  let perUserList = [];
  try { perUserList = vm.runInNewContext(perUser[1]); } catch (e) { perUserList = []; }
  check("G1. bf-session.js clears bf_theme at sign-out (PER_USER_LOCAL), and no longer names it as left on purpose",
    perUserList.indexOf("bf_theme") !== -1 && !!left && left[0].indexOf("bf_theme") === -1);
  check("G1. checkOfflineMode lists bf_theme on PER_USER, not on KEPT", /const PER_USER = \[[^\]]*"bf_theme"[^\]]*\];/.test(FILES[OFFCHECK]) &&
    !/const KEPT = \{[^}]*\bbf_theme:/.test(FILES[OFFCHECK]));
  check("G1. bf-theme.js stores under that one key", /var CACHE_KEY = "bf_theme";/.test(FILES[THEME]) && (FILES[THEME].match(/localStorage\.setItem\(/g) || []).length === 1);
  {
    const dom = new JSDOM("<!DOCTYPE html><html><head></head><body></body></html>", { url: "https://bizforceai.net/settings.html", runScripts: "dangerously" });
    const w = dom.window;
    w.localStorage.setItem("bf_token", tokenFor(UID));
    w.localStorage.setItem("bf_theme", JSON.stringify(cacheOf(UID, stateOf(T1.id))));
    w.localStorage.setItem("tmx_presence_pos", "{\"x\":1}");
    const sc = w.document.createElement("script");
    sc.setAttribute("data-clear-only", "");
    sc.textContent = FILES[SESSION];
    w.document.head.appendChild(sc);
    let ran = false;
    try { w.BFSession.clearDevice(); ran = true; } catch (e) { ran = false; }
    check("G2. signing out (bf-session.js clearDevice, run in jsdom) removes bf_theme with the token, and leaves a display choice",
      ran && w.localStorage.getItem("bf_theme") === null && w.localStorage.getItem("bf_token") === null && w.localStorage.getItem("tmx_presence_pos") !== null);
    w.close();
  }
  const p0 = await themePage({ token: null, cache: cacheOf(UID, stateOf(T3.id, {}, [T3])) });
  check("G3. and the sign-in page after it wears none of the member's look, element tokens included", p0.w.BFTheme.THEME_TOKENS.every(t => p0.get(t) === ""));
  p0.w.close();
  return elements();
}

/* ── H. Block 4b: the element palettes ──────────────────────────────────── */
function gitShow(commit, f) {
  try { return lf(execFileSync("git", ["-C", FRONTEND, "show", commit + ":" + f], { encoding: "utf8", maxBuffer: 16 << 20 })); }
  catch (e) { return null; }
}
/* Every element var() resolved to its fallback: what the page draws with no theme. */
const ELEMENT_VAR = /var\(--(?:bf-btn-a|bf-btn-b|bf-btn-text|bf-mark-a|bf-mark-b|bf-guide-a|bf-guide-b|tmx-[a-z0-9-]+), ([^()]+?)\)/g;
const unthemed = t => t.replace(ELEMENT_VAR, "$1");
const BARE = /#[0-9a-fA-F]{3,8}\b|rgba?\(\s*\d/;
/* The documented Match everything rule, recomputed from its own words. */
function ruleMix(x, y, w) {
  const a = [1, 3, 5].map(i => parseInt(x.slice(i, i + 2), 16)), b = [1, 3, 5].map(i => parseInt(y.slice(i, i + 2), 16));
  return "#" + a.map((c, i) => Math.round(c + w * (b[i] - c)).toString(16).padStart(2, "0")).join("");
}
/* NAMED BEFORE → AFTER (Block 4d, three-colour spectrums). BEFORE: documentedRule(A, B), 17 colours, the mist's pulse
   mix(mix(A, B, .5), W, .3). AFTER: documentedRule(A, B, M), M the middle tone (mix(A, B, .5) when none is given, which
   is the old rule), 24 colours: each middle stop M (guide's mix(M, W, .35)), the accents A, M, B, and the pulse
   mix(M, W, .3), as lib/themes.js's header now documents. Compared key by key, in sorted order. */
function documentedRule(A, B, M) {
  const W = "#ffffff", m = M || ruleMix(A, B, 0.5);
  return { btn_a: A, btn_mid: m, btn_b: B, btn_text: W, mark_a: A, mark_mid: m, mark_b: B,
    guide_a: ruleMix(A, W, 0.35), guide_mid: ruleMix(m, W, 0.35), guide_b: ruleMix(B, W, 0.35),
    chat_glow_a: A, chat_glow_mid: m, chat_glow_b: B, accent_a: A, accent_mid: m, accent_b: B,
    mist_core: A, mist_haze: B, mist_pulse: ruleMix(m, W, 0.3), mist_spark: ruleMix(A, W, 0.6),
    mist_star: ruleMix(B, W, 0.85), mist_dust: ruleMix(B, W, 0.5), mist_trail: ruleMix(A, W, 0.7), mist_whisper: ruleMix(B, W, 0.75) };
}
const sortedJson = o => JSON.stringify(Object.keys(o).sort().map(k => [k, o[k]]));
/* Every Block 4d token form resolved to its fallback (scripts/_unthemed.js), then every element var(). */
const resolved4d = t => unthemed(require("./_unthemed").unthemed(t));
const styleArray = t => { const m = /style\.textContent = \[\n([\s\S]*?)\n  \]\.join\("\\n"\)/.exec(t); return m ? m[1] : null; };
function ruleBodies(css, selRe) {
  const out = []; const re = /([^{}]+)\{([^{}]*)\}/g; let m;
  while ((m = re.exec(css))) { const sel = m[1].replace(/\/\*[\s\S]*?\*\//g, "").trim(); if (selRe.test(sel)) out.push({ sel, body: m[2] }); }
  return out;
}
/* The rules of the mist's style array, read from its string literals. */
function mistCss(text) {
  const arr = styleArray(text);
  if (!arr) return "";
  try { return vm.runInNewContext("[" + arr.replace(/"\s*\+\s*_tmxCorner\.(root|chat)/g, "\"") + "]").join("\n"); } catch (e) { return ""; }
}

async function elements() {
  console.log("\n══ H. the element palettes: buttons, the mist, the chat glow, the guide's lettering, the wordmark ══");
  const FRONT_DEFAULT = (() => { const m = /var DEFAULT_THEME = (\{[\s\S]*?\});/.exec(FILES[THEME]); try { return vm.runInNewContext("(" + m[1] + ")"); } catch (e) { return null; } })();
  const FRONT_ELEMENTS = (() => { const m = /var ELEMENTS = (\{[\s\S]*?\});/.exec(FILES[THEME]); try { return vm.runInNewContext("(" + m[1] + ")"); } catch (e) { return null; } })();
  /* NAMED BEFORE → AFTER (Block 4d). BEFORE: five sections and 18 keys (buttons 3, mist 8, chat glow 2, guide 2,
     wordmark 2, match_all). AFTER: a sixth section, accent (Headings and accents: accent_a, accent_mid, accent_b), and a
     middle stop in buttons, chat glow, guide and wordmark: 25 keys. */
  check("H1. lib/themes.js and bf-theme.js hold the same defaults (" + Object.keys(LIBX.DEFAULT_THEME).length + " keys) and the same six sections",
    JSON.stringify(FRONT_DEFAULT) === JSON.stringify(LIBX.DEFAULT_THEME) && JSON.stringify(FRONT_ELEMENTS) === JSON.stringify(LIBX.ELEMENTS) &&
    JSON.stringify(Object.keys(LIBX.ELEMENTS)) === JSON.stringify(["buttons", "mist", "chat", "guide", "mark", "accent"]));
  const NEW_KEYS = LIBX.ELEMENT_KEYS.concat(["match_all"]);
  check("H1. the brief's keys are all there: buttons 4, mist 8, chat glow 3, guide 3, wordmark 3, accents 3, and match_all", NEW_KEYS.length === 25 &&
    NEW_KEYS.every(k => Object.prototype.hasOwnProperty.call(LIBX.DEFAULT_THEME, k)), NEW_KEYS.join(","));
  const v = x => LIBX.validateTheme(x, UID);
  const notRefused = [];
  LIBX.ELEMENT_KEYS.forEach(k => {
    [["raw CSS", "red;} body{background:url(https://evil)}"], ["a CSS function", "url(https://evil/x.png)"], ["short hex", "#fff"], ["uppercase", "#FFFFFF"],
     ["a var()", "var(--x)"], ["a number", 255]].forEach(([what, bad]) => { const r = v({ [k]: bad }); if (!r.error || r.key !== k) notRefused.push(k + " " + what); });
    if (!v({ [k]: "#123abc" }).theme) notRefused.push(k + " (a good colour refused)");
  });
  ["yes", 1, null, "true"].forEach(bad => { const r = v({ match_all: bad }); if (!r.error || r.key !== "match_all") notRefused.push("match_all " + JSON.stringify(bad)); });
  check("H1. the validator covers every new key: raw CSS, url(), var(), short or uppercase hex and numbers are refused, naming the key (" + (LIBX.ELEMENT_KEYS.length * 6 + 4) + " cases)",
    notRefused.length === 0, notRefused.join(", "));
  const old = { theme: { glow_a: "#00e5ff" } };   // a theme saved before Block 4b
  /* NAMED BEFORE → AFTER (Block 4d). BEFORE: every element key read as today's value. AFTER: so does every Block 4b
     key; the Block 4d keys (the middles, the accents) are left out, so the theme stays legacy and draws its two-stop
     gradients (scripts/checkThemeSpectrums.js proves it draws exactly what it drew). */
  check("H1. a theme saved before the new keys existed reads with today's values for them", !!v(old.theme).theme &&
    LIBX.ELEMENT_KEYS.every(k => LIBX.KEYS_4D.indexOf(k) !== -1 ? !(k in v(old.theme).theme) : v(old.theme).theme[k] === LIBX.DEFAULT_THEME[k]));

  // H2: Match everything
  const pairs = [["#00e5ff", "#a855f7"], ["#ff7a18", "#ff2e63"], ["#000000", "#ffffff"], ["#123456", "#fedcba"], ["#34d399", "#22c55e"], ["#0a0a0a", "#0b0b0b"]];
  const dom = new JSDOM("<!DOCTYPE html><html><head><script>" + FILES[THEME] + "</script></head><body></body></html>", { url: "https://bizforceai.net/crm.html", runScripts: "dangerously" });
  const BT = dom.window.BFTheme;
  const ruleWrong = pairs.filter(([A, B]) => [undefined, "#336699"].some(M =>
    sortedJson(LIBX.matchAll(A, B, M)) !== sortedJson(documentedRule(A, B, M)) || sortedJson(BT.matchAll(A, B, M)) !== sortedJson(documentedRule(A, B, M))));
  check("H2. Match everything derives exactly by the documented rule, on the server and in the page (" + pairs.length + " corner pairs, with and without a middle tone, 24 colours each)", ruleWrong.length === 0, ruleWrong.join(" | "));
  const sent = Object.assign({}, LIBX.DEFAULT_THEME, { glow_a: "#ff7a18", glow_b: "#ff2e63", match_all: true, btn_a: "#000000", mist_core: "#111111" });
  const saved = v(sent).theme;
  const wantRule = documentedRule("#ff7a18", "#ff2e63", LIBX.midTone("#ff7a18", "#ff2e63"));   // NAMED (Block 4d): the middle tone follows the corners
  check("H2. with Match everything on, the server stores the derived colours, whatever was sent for them", !!saved &&
    Object.keys(wantRule).every(k => saved[k] === wantRule[k]));
  const n = BT.normalTheme(Object.assign({}, sent));
  check("H2. ... and the page derives the same", Object.keys(wantRule).every(k => n[k] === saved[k]));
  const off = v(Object.assign({}, saved, { match_all: false, guide_a: "#abcdef" })).theme;
  check("H2. turned off, the derived colours are kept as saved (a starting point), and a hand-tuned one stays", !!off && off.match_all === false &&
    off.btn_a === "#ff7a18" && off.mist_haze === "#ff2e63" && off.guide_a === "#abcdef");

  // H3: today's look
  const pageFiles = ALL_PAGES.filter(f => FILES[f].indexOf(TAG) !== -1);
  const changed = [], wrongText = [];
  const THEME_LINE = /--bf-|--tmx-|bf-wordmark|bf-theme/;
  const themeLines = t => t.split("\n").filter(l => THEME_LINE.test(l)).join("\n");
  const drift = [];
  ALL_PAGES.concat([UI]).forEach(f => {
    const done = gitShow(THEMES_DONE, f);
    if (done === null) { if (THEME_LINE.test(FILES[f])) drift.push(f + ": not readable at " + THEMES_DONE); return; }
    /* NAMED BEFORE → AFTER (Block 4d, every gradient follows the theme). BEFORE: today's lines as they stand. AFTER:
       today's lines with the Block 4d token forms read as their fallbacks (scripts/_unthemed.js), so a converted
       colour and an added empty middle stop are the line as built; checkThemeSpectrums.js pins those forms. */
    /* NAMED (Block 4d): settings.html's own preview backdrop (from ".ts-pv-middle, .ts-pv-glows" to its reduced-motion
       rule) was rebuilt by hand to show the photo editor and the four motion styles; it is the studio's, not the page's
       backdrop, and section C and checkThemeSpectrums.js pin it. Every other theme line of settings.html stays pinned. */
    const cutPreview = t => {
      if (f !== SETTINGS) return t;
      const a = t.indexOf(".ts-pv-middle, .ts-pv-glows {"), m = t.indexOf("@media (prefers-reduced-motion: reduce) { .ts-preview[data-alive=\"1\"] .ts-pv-glows", a), b = t.indexOf("\n", m);
      return a === -1 || m === -1 ? t : t.slice(0, a) + t.slice(b);
    };
    const now = themeLines(cutPreview(require("./_unthemed").unthemed(FILES[f]))).split("\n"), was = themeLines(cutPreview(done)).split("\n").filter(Boolean);
    let j = 0; const added = [];
    now.forEach(l => { if (j < was.length && l === was[j]) j++; else if (l) added.push(l); });
    if (j < was.length) drift.push(f + ": lost or changed " + JSON.stringify(was[j].slice(0, 140)));
    // an added line: each theme token in it is a var() with a fallback, and it is no engine tag
    added.filter(l => l.indexOf(TAG) !== -1 || /var\(--(?:bf|tmx)-[a-z0-9-]+\)/.test(l) || l.replace(/var\(--(?:bf|tmx)-[a-z0-9-]+, [^()]+?\)/g, "").match(/--(?:bf|tmx)-/))
      .forEach(l => drift.push(f + ": added " + JSON.stringify(l.trim().slice(0, 140))));
  });
  check("H3. since " + THEMES_DONE + " (the last theme commit) no page and not css/bizforce-ui.css changed a theme-bearing line: every --bf- and --tmx- token, wordmark and engine tag is as built",
    drift.length === 0, drift.join(" || "));
  const NAMED_SOLID = "background:linear-gradient(90deg,#22d3ee,#22d3ee);-webkit-background-clip:text;background-clip:text;color:transparent";
  pageFiles.concat([UI]).forEach(f => {
    if (f === SETTINGS) return;
    const was = gitShow(ELEMENTS_BEFORE, f), done = gitShow(THEMES_DONE, f);
    if (was === null || done === null) { wrongText.push(f + ": not readable at " + (was === null ? ELEMENTS_BEFORE : THEMES_DONE)); return; }
    if (was === done) return;
    changed.push(f);
    let now = unthemed(done);
    /* NAMED: artists and services drew a solid #22d3ee wordmark; it is now a gradient with both ends #22d3ee, which
       paints the same colour, so the member's two wordmark colours can reach it. */
    if (f === "artists.html" || f === "services.html") now = now.split(NAMED_SOLID).join("color:#22d3ee");
    /* NAMED: the dashboard's "BIZFORCE AI" eyebrow gains the class bf-wordmark, and css/bizforce-ui.css the rule for it
       and a comment documenting the element tokens. */
    if (f === "dashboard.html") now = now.split("hq-eyebrow hero-pill bf-wordmark").join("hq-eyebrow hero-pill");
    if (f === UI) {
      now = now.replace(/\/\* THE ELEMENT TOKENS \(Block 4b\)[\s\S]*?\*\/\n\n/, "");
      now = now.split("/* The dashboard's \"BIZFORCE AI\" eyebrow is the wordmark too. */\n.hq-eyebrow.bf-wordmark {\n  color: #22d3ee;\n}\n\n").join("");
    }
    if (now !== was) {
      const a = now.split("\n"), b = was.split("\n"); let i = 0; while (i < a.length && a[i] === b[i]) i++;
      wrongText.push(f + " line " + (i + 1) + ": " + JSON.stringify((a[i] || "").slice(0, 160)) + " was " + JSON.stringify((b[i] || "").slice(0, 160)));
    }
  });
  check("H3. with no theme, each of the " + changed.length + " changed pages and css/bizforce-ui.css is, element var()s read as their fallbacks, exactly the text it was at " +
    ELEMENTS_BEFORE + ": every wordmark and button keeps its colours, its place, its size and its motion", changed.length >= 50 && wrongText.length === 0, wrongText.join(" || "));
  const setWas = gitShow(ELEMENTS_BEFORE, SETTINGS) || "";
  const pick = (css, re) => ruleBodies(stylesOf(css), re).map(r => r.body).join("|");
  check("H3. settings.html (which also gains the studio's new sections): its wordmark and its buttons are as they were",
    // NAMED (Block 4d): BEFORE unthemed(), AFTER resolved4d(): the middle stop and the accents read as their fallbacks too
    resolved4d(pick(FILES[SETTINGS], /^\.brand-badge$/)) === pick(setWas, /^\.brand-badge$/) && resolved4d(pick(FILES[SETTINGS], /^\.btn$/)) === pick(setWas, /^\.btn$/) &&
    pick(setWas, /^\.btn$/).length > 0);
  const oldMist = gitShow(ELEMENTS_BEFORE, PRESENCE) || "", oldGuide = gitShow(ELEMENTS_BEFORE, GUIDE) || "";
  check("H3. the mist's and the chat glow's CSS, resolved, is exactly today's (scripts/termaximus-presence.js)", !!styleArray(oldMist) && resolved4d(styleArray(FILES[PRESENCE]) || "") === styleArray(oldMist));   // NAMED (Block 4d): BEFORE unthemed(), AFTER resolved4d()
  check("H3. the guide's CSS, resolved, is exactly today's (scripts/termaximus-guide.js)", !!styleArray(oldGuide) && resolved4d(styleArray(FILES[GUIDE]) || "") === styleArray(oldGuide));   // NAMED (Block 4d): BEFORE unthemed(), AFTER resolved4d()
  const oldStars = (() => { const m = /var STARS = (\[[\s\S]*?\n  \]);/.exec(oldMist); try { return vm.runInNewContext(m[1]); } catch (e) { return null; } })();
  const newStars = (() => { const m = /var STARS = (\[[\s\S]*?\n  \]);/.exec(FILES[PRESENCE]); try { return vm.runInNewContext(m[1]); } catch (e) { return null; } })();
  const tones = (() => { const m = /var STAR_TONES = (\{[\s\S]*?\});/.exec(FILES[PRESENCE]); try { return vm.runInNewContext("(" + m[1] + ")"); } catch (e) { return null; } })();
  const toHex = ch => "#" + ch.split(",").map(x => Number(x).toString(16).padStart(2, "0")).join("");
  const starWrong = !oldStars || !newStars || !tones || oldStars.length !== newStars.length ? ["tables not read"] : oldStars.map((o, i) => {
    const nw = newStars[i], t = tones[nw[3]];
    if (!t) return i + ": no tone";
    const glow = "rgba(" + t[3].replace(/\s/g, "") + "," + nw[4].toFixed(2) + ")";
    const same = o[3] === toHex(t[1]) && o[4] === glow && JSON.stringify(o.slice(0, 3).concat(o.slice(5))) === JSON.stringify(nw.slice(0, 3).concat(nw.slice(5)));
    return same ? null : i + ": " + o[3] + " " + o[4] + " vs " + toHex(t[1]) + " " + glow;
  }).filter(Boolean);
  check("H3. the twelve sparkle stars keep their colours, glows, places, sizes and timings (the old table, row by row)", starWrong.length === 0, starWrong.join("; "));
  const tonesMatchMist = tones && JSON.stringify([tones.star[1], tones.star[3]]) === JSON.stringify(BT.MIST.star) && JSON.stringify([tones.spark[1], tones.spark[3]]) === JSON.stringify(BT.MIST.spark);
  check("H3. ... and their fallbacks are bf-theme.js's mist stops for the white and gold stars", !!tonesMatchMist);

  // H4: no hard-coded colour left in the elements
  const MARK_RULE = /^(\.brand-badge|\.site-brand|\.brand h1|\.topbar-brand-text|\.hq-eyebrow\.bf-wordmark)$/;
  const MARK_EL = /class="(?:[^"]*\s)?(brand-badge|site-brand|topbar-brand-text|bf-wordmark)(?:\s[^"]*)?"|<section class="brand">\s*<h1>/;
  const markMissing = [];
  let markPages = 0;
  pageFiles.forEach(f => {
    if (!MARK_EL.test(FILES[f])) return;
    markPages++;
    const css = stylesOf(FILES[f]) + (/bizforce-ui\.css/.test(FILES[f]) ? "\n" + FILES[UI] : "");
    const rules = ruleBodies(noComments(css), MARK_RULE).filter(r => /color|background/.test(r.body));
    const bad = rules.filter(r => BARE.test(r.body.replace(ELEMENT_VAR, "")));
    const uses = rules.some(r => /var\(--bf-mark-a, /.test(r.body));
    if (!uses || bad.length) markMissing.push(f + (bad.length ? ": " + bad.map(r => r.sel + "{" + r.body.slice(0, 90) + "}").join(" ") : ": no wordmark token"));
  });
  check("H4. the wordmark reads --bf-mark-a / --bf-mark-b, with no colour of its own left, on every one of the " + markPages + " themed pages that show it (the dashboard's topbar and eyebrow, the home page, sign-in and every badge)",
    markPages >= 50 && markMissing.length === 0, markMissing.join(" || "));
  const GRAD_BARE = /linear-gradient\(\s*\d+deg\s*,\s*#[0-9a-fA-F]{3,6}\s*,\s*#[0-9a-fA-F]{3,6}\s*\)/;
  const btnLeft = [];
  let btnRules = 0;
  pageFiles.concat([UI]).forEach(f => {
    const css = noComments(f === UI ? FILES[f] : stylesOf(FILES[f]));
    ruleBodies(css, /btn|button|cta/i).forEach(r => {
      if (/theme-btn/.test(r.sel)) return;   // NAMED: digital-cards' card-theme swatches are a card's look
      if (/var\(--bf-btn-a, /.test(r.body)) { btnRules++; if (/(^|[;\s])color\s*:\s*#/.test(r.body)) btnLeft.push(f + " " + r.sel + " (its lettering)"); return; }
      if (GRAD_BARE.test(r.body)) btnLeft.push(f + " " + r.sel.slice(-50));
    });
  });
  check("H4. every primary button gradient on every themed page reads --bf-btn-a / --bf-btn-b, and its lettering --bf-btn-text (" + btnRules + " button rules)",
    btnRules >= 50 && btnLeft.length === 0, btnLeft.join(", "));
  const guideCss = (() => { try { return vm.runInNewContext("[" + styleArray(FILES[GUIDE]) + "]").join("\n"); } catch (e) { return ""; } })();
  const GUIDE_RULES = /^(#tmx-guide-tab-text|#tmx-guide-panel \.tmx-guide-header-text|#tmx-guide-panel \.tmx-guide-label|#tmx-guide-panel \.tmx-guide-section--insights \.tmx-guide-label|#tmx-guide-panel \.tmx-guide-list li::marker|#tmx-guide-sheet-title|#tmx-guide-sheet \.tmx-guide-list li::marker)$/;
  const gRules = ruleBodies(guideCss, GUIDE_RULES);
  const gBad = gRules.filter(r => BARE.test(r.body.replace(ELEMENT_VAR, "")) || !/var\(--bf-guide-[ab], /.test(r.body));
  check("H4. the guide's lettering (tab, heading, labels, markers, the phone sheet's title) reads --bf-guide-a / --bf-guide-b, with no colour of its own (" + gRules.length + " rules)",
    gRules.length === 7 && gBad.length === 0, gBad.map(r => r.sel).join(", "));
  const mc = mistCss(FILES[PRESENCE]);
  const MIST_RULES = /^(#tmx-core|#tmx-core::after|#tmx-soul|\.tmx-blob-[abc]|#tmx-gold-[abc]|#tmx-shoot|#tmx-whisper|#tmx-chat-glow|\d+%(, ?\d+%)?)$/;
  const mRules = ruleBodies(mc.replace(/@keyframes tmx-soul-cycle \{/, ""), MIST_RULES).filter(r => /background|color|box-shadow/.test(r.body) && !/translate|transform|opacity: 0\.\d+; transform/.test(r.body));
  const mBad = mRules.filter(r => BARE.test(r.body.replace(ELEMENT_VAR, "")));
  check("H4. every colour the mist draws (core, bloom, colour cycle, three blobs, gold streaks and dust, shooting star, whisper) and the chat glow reads a --tmx- token (" + mRules.length + " rules)",
    mRules.length >= 14 && mBad.length === 0, mBad.map(r => r.sel + "{" + r.body.slice(0, 80)).join(" || "));
  const starBuild = (() => { const a = FILES[PRESENCE].indexOf("  STARS.forEach(function (s) {"), b = FILES[PRESENCE].indexOf("  });", a); return a === -1 ? "" : FILES[PRESENCE].slice(a, b); })();
  check("H4. ... and the stars are built from those tokens only, with no colour literal", starBuild.length > 0 && !BARE.test(starBuild) && /STAR_TONES\[s\[3\]\]/.test(starBuild));
  const declared = BT.ELEMENT_TOKENS;
  /* NAMED BEFORE → AFTER (Block 4d). BEFORE: the drawn tokens were the Block 4b seven and the --tmx- ones, read from the
     pages and the CSS. AFTER: also each middle stop (var(--bf-btn-mid, ) and the rest, an empty fallback) and the
     accents, drawn by var() in CSS and by BFTheme.color("--bf-accent-…") in the pages' scripts (charts). */
  const drawnText = FILES[PRESENCE] + guideCss + Object.keys(FILES).filter(f => /\.html$|\.css$|\.js$/.test(f)).map(f => FILES[f]).join("\n");
  const used = (drawnText.match(/var\(--(?:bf-btn-a|bf-btn-b|bf-btn-text|bf-mark-a|bf-mark-b|bf-guide-a|bf-guide-b|bf-(?:btn|mark|guide|accent)-mid|bf-accent-[ab][23]?(?:-rgb)?|tmx-[a-z0-9-]+),/g) || [])
    .concat((drawnText.match(/BFTheme\.color\("--bf-accent-[a-z0-9-]+",/g) || []).map(x => "var(" + x.slice(15, -2) + ","));
  const usedNames = Array.from(new Set(used.map(u => u.slice(4, -1)))).concat(["--tmx-star-1", "--tmx-star-2", "--tmx-spark-1", "--tmx-spark-2"]);
  check("H4. every element token a theme can set is drawn somewhere, and every one drawn is a token a theme sets (" + declared.length + ")",
    declared.every(t => usedNames.indexOf(t) !== -1) && usedNames.every(t => declared.indexOf(t) !== -1), declared.filter(t => usedNames.indexOf(t) === -1).concat(usedNames.filter(t => declared.indexOf(t) === -1)).join(","));
  const rr = RULE;
  check("H4. none of the element tokens has a default in the rule, so each place keeps its own colour", declared.every(t => rr.indexOf(t + ":") === -1));

  // H5: tokens, scopes, mist stops
  let p = await themePage({ cache: cacheOf(UID, stateOf(null)) });
  check("H5. with no theme, no element token is set on any page", BT.ELEMENT_TOKENS.every(t => p.get(t) === ""));
  p.w.close();
  const tok = BT.tokensFor(T3.theme, null, dom.window);
  const families = { buttons: ["--bf-btn-a", "--bf-btn-b", "--bf-btn-text"], mark: ["--bf-mark-a", "--bf-mark-b"], guide: ["--bf-guide-a", "--bf-guide-b"], chat: ["--tmx-chat-glow-a", "--tmx-chat-glow-b", "--tmx-chat-glow-c"],
    mist: ["--tmx-core-1", "--tmx-haze-1", "--tmx-spark-1"] };
  const hasAll = (get, list) => list.every(t => get(t) !== "" && get(t) !== undefined);
  check("H5. a theme that colours every part sets each part's tokens: buttons, wordmark, guide text, chat glow, mist",
    Object.keys(families).every(k => hasAll(x => tok[x], families[k])) && tok["--bf-btn-a"] === "#ff7a18" && tok["--bf-mark-b"] === "#f43f5e" && tok["--tmx-chat-glow-a"] === "249, 115, 22");
  check("H5. ... and only the mist parts it changed (core, haze, gold sparks): the rest of the mist keeps today's", ["core", "haze", "spark"].every(pt => BT.MIST[pt].every((s0, i) => tok["--tmx-" + pt + "-" + (i + 1)] !== undefined)) &&
    ["pulse", "star", "dust", "trail", "whisper"].every(pt => BT.MIST[pt].every((s0, i) => tok["--tmx-" + pt + "-" + (i + 1)] === undefined)));
  const lk = c => (Math.max(...c) + Math.min(...c)) / 2 / 255;
  const ch = t => t.split(",").map(Number);
  const stopWrong = [];
  Object.keys(BT.MIST).forEach(pt => {
    const key = ch(BT.MIST[pt][BT.MIST[pt].map(s0 => toHex(s0)).indexOf(LIBX.DEFAULT_THEME["mist_" + pt])] || "0,0,0");
    const C = [34, 197, 94];
    const got = BT.stopsFor(pt, "#22c55e");
    BT.MIST[pt].forEach((s0, i) => {
      const t = lk(ch(s0)) - lk(key);
      const want = (t > 0 ? C.map(c => c + (t / (1 - lk(key))) * (255 - c)) : t < 0 ? C.map(c => c + (-t / lk(key)) * (0 - c)) : C).map(Math.round).join(", ");
      if (!got || got[i] !== want) stopWrong.push(pt + "-" + (i + 1) + " " + (got && got[i]) + " vs " + want);
    });
    if (BT.stopsFor(pt, LIBX.DEFAULT_THEME["mist_" + pt]) !== null) stopWrong.push(pt + " at its original sets stops");
  });
  check("H5. a mist colour gives each of its part's stops that colour moved to the stop's own lightness today (all 37 stops), and its original sets none",
    stopWrong.length === 0 && Object.keys(BT.MIST).reduce((a, k) => a + BT.MIST[k].length, 0) === 37, stopWrong.slice(0, 4).join("; "));
  p = await themePage({ url: "https://bizforceai.net/crm.html", cache: cacheOf(UID, stateOf(T1.id, { "crm.html": T3.id, "seo.html": T3.id })) });
  const crm = p;
  check("H5. scope \"this page\" / \"selected pages\": CRM, given the parts theme, wears every part's tokens", Object.keys(families).every(k => hasAll(crm.get, families[k])) && crm.get("--bf-btn-a") === "#ff7a18");
  crm.w.close();
  p = await themePage({ url: "https://bizforceai.net/agents/seo", cache: cacheOf(UID, stateOf(T1.id, { "crm.html": T3.id, "seo.html": T3.id })) });
  check("H5. ... and so does the other ticked page (seo)", Object.keys(families).every(k => hasAll(p.get, families[k])));
  p.w.close();
  p = await themePage({ url: "https://bizforceai.net/wallet.html", cache: cacheOf(UID, stateOf(T1.id, { "crm.html": T3.id, "seo.html": T3.id })) });
  check("H5. ... while a page wearing the main theme (corners only) wears no element token", BT.ELEMENT_TOKENS.every(t => p.get(t) === "") && p.get("--bf-glow-a") === "#ff7a18");
  p.w.BFTheme.applyState(stateOf(T3.id, {}));
  check("H5. scope \"all pages\": the parts theme as the main theme reaches that page too", Object.keys(families).every(k => hasAll(p.get, families[k])));
  p.w.BFTheme.applyState(stateOf(null, {}));
  check("H5. reset everything: every element token is removed again", BT.ELEMENT_TOKENS.every(t => p.get(t) === ""));
  p.w.close();

  // H6: readability
  const R = th => BT.readability(Object.assign({}, LIBX.DEFAULT_THEME, th));
  const okOrig = R({});
  check("H6. today's look: nothing is changed, and the meter's figures are there (buttons the original; guide " + okOrig.elements.guide.ratio.toFixed(2) + ":1, wordmark " + okOrig.elements.mark.ratio.toFixed(2) + ":1)",
    okOrig.elements.buttons.original && !okOrig.elementsFixed && okOrig.elements.guide.ratio >= 4.5 && okOrig.elements.mark.ratio >= 3);
  const grey = R({ btn_a: "#888888", btn_b: "#999999", btn_text: "#999999" });
  const tg = BT.tokensFor(Object.assign({}, LIBX.DEFAULT_THEME, { btn_a: "#888888", btn_b: "#999999", btn_text: "#999999" }), null, dom.window);
  check("H6. button text the colour of its button (1:1) is set to near-black, 4.5:1 or more on both ends, and the page gets that (" + grey.elements.buttons.ratio.toFixed(2) + ":1)",
    grey.elements.buttons.fix === "text" && grey.elements.buttons.text === "#050c1a" && grey.elements.buttons.ratio >= 4.5 && tg["--bf-btn-text"] === "#050c1a");
  /* NAMED BEFORE → AFTER (Block 4d). BEFORE: the two ends alone. AFTER: the middle stop too, the ends' midpoint (a
     two-stop button, as before); left at the default it would be the original blue between two indigos. */
  const darkBtn = R({ btn_a: "#1e1b4b", btn_mid: "#282566", btn_b: "#312e81", btn_text: "#1e1b4b" });
  check("H6. dark button text on a dark button is set to white", darkBtn.elements.buttons.fix === "text" && darkBtn.elements.buttons.text === "#ffffff" && darkBtn.elements.buttons.ratio >= 4.5);
  const split = R({ btn_a: "#555555", btn_b: "#bbbbbb", btn_text: "#999999" });
  check("H6. a gradient neither white nor near-black can read on both ends is shaded, the least that passes, with white text (shade " + split.elements.buttons.shade + ", " + split.elements.buttons.ratio.toFixed(2) + ":1)",
    split.elements.buttons.fix === "shade" && split.elements.buttons.text === "#ffffff" && split.elements.buttons.ratio >= 4.5 &&
    BT.contrast(BT.rgbOf("#ffffff"), BT.rgbOf(split.elements.buttons.b)) >= 4.5 && (() => {
      const less = Math.round(split.elements.buttons.shade * 100 - 1) / 100, b0 = BT.rgbOf("#bbbbbb");
      return BT.contrast(BT.rgbOf("#ffffff"), b0.map(c => c * (1 - less))) < 4.5;
    })());
  const gd = R({ guide_a: "#222244", guide_b: "#a855f7", mark_a: "#101010", mark_b: "#a855f7" });
  check("H6. guide text too dark for its panel is lightened to 4.5:1 (" + gd.elements.guide.ratio.toFixed(2) + "), and a wordmark too dark for the header to 3:1 (" + gd.elements.mark.ratio.toFixed(2) + ")",
    gd.elements.guide.fix === "lighten" && gd.elements.guide.ratio >= 4.5 && gd.elements.mark.fix === "lighten" && gd.elements.mark.ratio >= 3 && gd.elementsFixed);
  const brightBack = R({ middle: "colour", bg: "#ffffff", guide_a: "#7c3aed", guide_b: "#7c3aed", mark_a: "#7c3aed", mark_b: "#7c3aed" });
  check("H6. on a white middle (the backdrop protected first), guide text and the wordmark still reach their marks", brightBack.elements.guide.ratio >= 4.5 && brightBack.elements.mark.ratio >= 3);
  check("H6. nothing is refused: the stored colours stay as chosen", !!v({ btn_text: "#999999", btn_a: "#888888", btn_b: "#999999", guide_a: "#222244", mark_a: "#101010" }).theme &&
    v({ btn_text: "#999999" }).theme.btn_text === "#999999");

  // H7: motion
  const still = (() => { const m = /var MIST_STILL = ([\s\S]*?);\n/.exec(FILES[PRESENCE]); try { return vm.runInNewContext(m[1]); } catch (e) { return ""; } })();
  const animated = ruleBodies(mc, /^[#.][a-z-]+(::after)?$/).filter(r => /animation\s*:/.test(r.body)).map(r => r.sel.replace(/-[abc]$/, ""));
  const stillSel = (/@media \(prefers-reduced-motion: reduce\) \{\s*([^{]+)\{ animation: none !important; \}/.exec(still) || [])[1] || "";
  const notStilled = Array.from(new Set(animated)).filter(sel => sel !== "#tmx-chat" && stillSel.indexOf(sel) === -1 && !(sel === ".tmx-blob" && /\.tmx-blob\b/.test(stillSel)));
  check("H7. under prefers-reduced-motion every animated part of the mist and the chat glow stops (" + Array.from(new Set(animated)).length + " animated selectors), the shooting star stays hidden",
    /style\.textContent = \[[\s\S]*?\]\.join\("\\n"\) \+ MIST_STILL;/.test(FILES[PRESENCE]) && notStilled.length === 0 && /#tmx-shoot \{ animation: none !important; opacity: 0 !important; \}/.test(still), notStilled.join(","));
  check("H7. ... and the stars stop wandering (the 35 s regrouping is skipped)", /setInterval\(function \(\) \{\n    \/\* Under reduced motion the stars stay where they are\. \*\/\n    if \(window\.matchMedia && window\.matchMedia\("\(prefers-reduced-motion: reduce\)"\)\.matches\) return;/.test(FILES[PRESENCE]));
  check("H7. the mist and the chat glow keep their animations otherwise (the same keyframes and timings as today, H3), and the alive corners are as built (B7)",
    /animation: tmx-chat-glow-breathe 5s ease-in-out infinite;/.test(mc) && /animation: tmx-core-glow 5\.5s ease-in-out infinite;/.test(mc));

  // H8: public pages and cards
  const pubChanged = LIBX.UNTHEMED.filter(k => { const f = ALL_PAGES.filter(x => keyOfFile(x) === k)[0]; return !f || gitShow(ELEMENTS_BEFORE, f) !== gitShow(THEMES_DONE, f) ||
    themeLines(FILES[f]) !== themeLines(gitShow(THEMES_DONE, f)) || FILES[f].indexOf(TAG) !== -1; });
  check("H8. every public page (" + LIBX.UNTHEMED.length + ") was exactly as it was through the theme work, keeps every theme-bearing line since, and loads no engine: their wordmarks and buttons keep the owner's look", pubChanged.length === 0, pubChanged.join(","));
  const dcWas = gitShow(ELEMENTS_BEFORE, "digital-cards.html") || "";
  check("H8. digital cards keep their own look: the card-theme swatches and the card's watermark are untouched",
    pick(FILES["digital-cards.html"], /theme-btn/) === pick(dcWas, /theme-btn/) && pick(dcWas, /theme-btn/).length > 0 &&
    pick(FILES["digital-cards.html"], /^\.card-watermark$/) === pick(dcWas, /^\.card-watermark$/));
  const pubHit = [];
  for (const k of ["seller.html", "listing.html", "blogpost.html", "card-view.html", "support.html"]) {
    const q = await themePage({ url: "https://bizforceai.net/" + k, cache: cacheOf(UID, stateOf(T3.id)) });
    if (BT.ELEMENT_TOKENS.some(t => q.get(t) !== "")) pubHit.push(k);
    q.w.close();
  }
  p = await themePage({ url: "https://bizforceai.net/profile.html?id=" + OTHER, cache: cacheOf(UID, stateOf(T3.id)) });
  if (BT.ELEMENT_TOKENS.some(t => p.get(t) !== "")) pubHit.push("profile.html?id=other");
  p.w.close();
  check("H8. a public page, or someone else's profile, wears none of the visitor's element colours, even if it loaded the engine", pubHit.length === 0, pubHit.join(","));
  dom.window.close();
  if (OPEN_STUDIO) await reach(OPEN_STUDIO); else check("I0. the studio could be opened for I", false);
  finish();
}

/* ── I. Block 4c: every theme request reaches the API ──────────────────────
   The live bug: on bizforceai.net "Save as…" said "That did not work. Try
   again." with a 404 for api/themes. The studio's base was window.API_URL or
   "", and settings.html keeps its API_URL inside its own function, so every
   request was a relative /api/themes, sent to Netlify. I proves the studio and
   bf-theme.js call the API's origin at the exact paths and methods server.js
   registers (parsed from server.js, before its catch-all 404), that CORS lets
   bizforceai.net send each of those methods with Authorization, and that a
   failure names its status. */
function serverRoutes() {
  const src = FILES[SERVER], out = [], re = /\napp\.(get|post|put|delete|patch)\(\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(src))) out.push({ method: m[1].toUpperCase(), path: m[2], at: m.index });
  return out;
}
/* The route Express would run for METHOD url: the first registered one that matches. */
function expressPick(routes, method, url) {
  return routes.find(r => r.method === method && new RegExp("^" + r.path.replace(/:[A-Za-z_]+/g, "[^/]+") + "$").test(url)) || null;
}
function studioRequests() {
  const out = [], src = FILES[STUDIO].replace(/\/\*[\s\S]*?\*\//g, "");
  let m;
  const reCall = /\bcall\("(GET|POST|PUT|DELETE|PATCH)", "(\/api\/[^"]*)"(\s*\+\s*encodeURIComponent\([^)]*\))?/g;
  while ((m = reCall.exec(src))) out.push({ from: "bf-theme-studio.js", method: m[1], path: m[2] + (m[3] ? ":id" : "") });
  const reSend = /\bsend\("[^"]+", "(\/api\/[^"]*)", \{ method: "(GET|POST|PUT|DELETE|PATCH)"/g;
  while ((m = reSend.exec(src))) out.push({ from: "bf-theme-studio.js", method: m[2], path: m[1] });
  const literals = (src.match(/"\/api\//g) || []).length;
  const tsrc = FILES[THEME].replace(/\/\*[\s\S]*?\*\//g, "");
  const reTheme = /\bfetch\(origin \+ "(\/api\/[^"]*)", \{ headers:/g;
  while ((m = reTheme.exec(tsrc))) out.push({ from: "bf-theme.js", method: "GET", path: m[1] });
  return { calls: out, studioLiterals: literals, themeLiterals: (tsrc.match(/"\/api\//g) || []).length };
}
async function reach(open) {
  console.log("\n══ I. every theme request reaches the API: its origin, server.js's exact paths and methods, CORS, a failure that names its status ══");
  const routes = serverRoutes();
  const catchAll = FILES[SERVER].indexOf("\napp.use(function (req, res) {\n  return res.status(404)");
  const themeRoutes = routes.filter(r => r.path.indexOf("/api/themes") === 0);
  check("I2. server.js registers the seven theme routes, each before its catch-all 404",
    themeRoutes.length === 7 && catchAll !== -1 && themeRoutes.every(r => r.at < catchAll), themeRoutes.map(r => r.method + " " + r.path).join(", "));
  const req = studioRequests();
  const sample = T1.id;
  const picked = req.calls.map(c => {
    const url = c.path.replace(":id", sample);
    const r = expressPick(routes, c.method, url);
    return Object.assign({}, c, { route: r });
  });
  const missing = picked.filter(c => !c.route || c.route.path.indexOf("/api/themes") !== 0 || c.route.at > catchAll ||
    (c.path.endsWith(":id") && !/\/:[A-Za-z_]+$/.test(c.route.path)));
  check("I2. every request the studio and bf-theme.js make (" + picked.length + ", parsed from their code) is a route server.js registers, at that method and path",
    picked.length >= 9 && missing.length === 0 && req.studioLiterals === picked.filter(c => c.from === "bf-theme-studio.js").length &&
    req.themeLiterals === picked.filter(c => c.from === "bf-theme.js").length,
    missing.map(c => c.from + " " + c.method + " " + c.path + " → " + (c.route ? c.route.method + " " + c.route.path : "no route")).join("; ") +
    " | literals " + req.studioLiterals + "/" + req.themeLiterals + ", parsed " + picked.length);
  console.log("      " + picked.map(c => c.method + " " + c.path + " → " + (c.route ? c.route.path : "none")).join("\n      "));
  check("I2. PUT /api/themes/apply is registered before PUT /api/themes/:id, so \"apply\" is never read as an id",
    (expressPick(routes, "PUT", "/api/themes/apply") || {}).path === "/api/themes/apply");
  check("I2. the studio sends every request through one function (send), and bf-theme.js through apiOrigin: one fetch( each",
    (FILES[STUDIO].match(/\bfetch\(/g) || []).length === 1 && /return fetch\(base \+ path, opts\)/.test(FILES[STUDIO]) &&
    (FILES[THEME].match(/\bfetch\(/g) || []).length === 1);

  // CORS, run: the middleware lifted from server.js answers bizforceai.net's preflight for each method
  const src = FILES[SERVER];
  const ca = src.indexOf("function corsAllowedOrigins(env) {");
  const mwAt = src.indexOf("app.use(function (req, res, next) {\n  const origin = req.headers.origin;", ca);
  const mwEnd = src.indexOf("\n  next();\n});\n", mwAt);
  let mw = null;
  try {
    const ctx = { isProductionEnv: () => true, process: { env: {} }, app: { use(fn) { mw = fn; } } };
    vm.createContext(ctx);
    vm.runInContext(src.slice(ca, mwEnd + "\n  next();\n});\n".length), ctx);
  } catch (e) { mw = null; }
  const methods = Array.from(new Set(picked.map(c => c.method)));
  const corsBad = [];
  if (!mw || ca === -1 || mwAt === -1 || mwEnd === -1) corsBad.push("the CORS middleware was not found in server.js");
  else for (const meth of methods.concat(["OPTIONS"])) {
    const res = { headers: {}, code: 200, ended: false, setHeader(k, v) { this.headers[k.toLowerCase()] = String(v); }, status(c) { this.code = c; return this; }, end() { this.ended = true; } };
    let nexted = false;
    mw({ method: "OPTIONS", headers: { origin: "https://bizforceai.net", "access-control-request-method": meth, "access-control-request-headers": "authorization,content-type" } }, res, () => { nexted = true; });
    const allowM = (res.headers["access-control-allow-methods"] || "").split(",").map(x => x.trim().toUpperCase());
    const allowH = (res.headers["access-control-allow-headers"] || "").split(",").map(x => x.trim().toLowerCase());
    if (res.headers["access-control-allow-origin"] !== "https://bizforceai.net" || allowM.indexOf(meth) === -1 ||
      allowH.indexOf("authorization") === -1 || allowH.indexOf("content-type") === -1 || res.code !== 204 || !res.ended || nexted) corsBad.push(meth + " " + JSON.stringify(res.headers));
  }
  check("I3. CORS (server.js's middleware, run): bizforceai.net's preflight is answered 204 for " + methods.join(", ") + ", with Authorization and Content-Type allowed",
    corsBad.length === 0 && methods.length >= 4 && /\nconst allowedOrigins = corsAllowedOrigins\(process\.env\);\n\napp\.use\(function \(req, res, next\) \{/.test(src) &&
    mwAt < themeRoutes[0].at && !/app\.use\(cors\(/.test(src), corsBad.join("; "));

  // the studio, run: every route it calls is reached at the API's origin
  const st = await open({});
  const $ = id => st.d.getElementById(id);
  const settle = () => new Promise(r => setTimeout(r, 30));
  $("tsName").value = "Reach";
  $("tsSaveAs").click(); await settle();
  $("tsUpdate").click(); await settle();
  const li = () => Array.prototype.filter.call(st.d.querySelectorAll("#tsSavedList li"), x => /Reach/.test(x.textContent))[0];
  const btn = (row, text) => row && Array.prototype.filter.call(row.querySelectorAll("button"), b => b.textContent === text)[0];
  const rb = btn(li(), "Rename"); if (rb) rb.click();
  const input = st.d.querySelector("#tsSavedList li input[type=text]");
  if (input) input.value = "Reached";
  const sb = btn(input && input.parentNode, "Save name"); if (sb) sb.click(); await settle();
  const renamed = /Renamed\./.test($("tsMsg").textContent);
  st.w.URL.createObjectURL = () => "blob:x"; st.w.URL.revokeObjectURL = () => {};
  st.w.HTMLCanvasElement.prototype.getContext = () => { throw new Error("no canvas in jsdom"); };   // the studio then assumes the brightest
  st.w.Image = function () { const img = this; setTimeout(() => img.onload && img.onload(), 0); };
  Object.defineProperty($("tsPhotoFile"), "files", { configurable: true, value: [new st.w.File([Buffer.from([0xff, 0xd8, 0xff, 0xe0])], "a.jpg", { type: "image/jpeg" })] });
  st.d.getElementById("tsPhotoFile").dispatchEvent(new st.w.Event("change", { bubbles: true })); await settle(); await settle();
  const delRow = Array.prototype.filter.call(st.d.querySelectorAll("#tsSavedList li"), x => /Reached/.test(x.textContent))[0];
  const db = btn(delRow, "Delete"); if (db) { db.click(); db.click(); } await settle();
  const deleted = /deleted\./.test($("tsMsg").textContent);
  st.w.close();
  const needed = Array.from(new Set(picked.filter(c => c.route).map(c => c.method + " " + c.route.path)));
  const notHit = needed.filter(x => !HIT.has(x));
  check("I1. run in jsdom, the studio reached every one of those routes (" + needed.length + ") at " + API_ORIGIN + " — save as, save, rename, the photo, delete, apply, reset, load",
    notHit.length === 0 && renamed && deleted, "not reached: " + notHit.join(", ") + " | renamed " + renamed + ", deleted " + deleted);

  // a failure names its status
  const nf = await open({ netlify: true });
  nf.d.getElementById("tsSaveAs").click(); await settle();
  const nfMsg = nf.d.getElementById("tsMsg").textContent;
  nf.w.close();
  check("I4. a 404 that is not the API's answer (Netlify's) says so with its status: \"Couldn't save (404). Try again.\"", nfMsg === "Couldn't save (404). Try again.", nfMsg);
  const fg = await open({ failGet: true });
  const fgMsg = fg.d.getElementById("tsMsg").textContent;
  fg.w.close();
  check("I4. the server's own words are kept, with the status: \"down (500)\"", fgMsg === "down (500)", fgMsg);

  check("I1. no request from bf-theme.js or the studio, in any test above, went anywhere but the API's origin at a route server.js registers",
    STRAY.length === 0, Array.from(new Set(STRAY)).slice(0, 8).join("; "));
}

let finished = false;
function finish() {
  if (finished) return;
  finished = true;
  console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
}
