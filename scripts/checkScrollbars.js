/* scripts/checkScrollbars.js — one scrollbar look on every BizForce page.

   ══ What it proves ══════════════════════════════════════════════════════════
     S1  THE RULE: css/bizforce-ui.css holds the one scrollbar rule, between
         "BF-SCROLLBARS:BEGIN" and "BF-SCROLLBARS:END": about 8 px, a
         translucent noir track, a thumb in the theme's gradient
         (var(--bf-accent-a) -> var(--bf-accent-mid) -> var(--bf-accent-b)) with
         a glow, a hover state, rounded, and Firefox's scrollbar-width and
         scrollbar-color.
     S2  THE SAME TEXT EVERYWHERE: frontend scripts/bf-theme.js (SCROLLBARS),
         the backend's lib/legalPages.js (the four built legal pages), and the
         inline <style id="bf-scrollbars"> on a page that loads neither
         bf-theme.js nor css/bizforce-ui.css hold it byte for byte; so do the
         backend's lib/scrollbars.js and the pages built from it (the legal pages
         and the support page).
     S3  EVERY PAGE: each .html page in the frontend (the root and agents/;
         the Google site-verification file is not a page) gets it, by
         bf-theme.js, by css/bizforce-ui.css or inline.
     S4  NOTHING ELSE: no other ::-webkit-scrollbar rule, scrollbar-width or
         scrollbar-color in any page, script or stylesheet, so no default grey
         or blue bar and no panel of its own (the Termaximus guide panel and
         the chat use the one rule).
     S5  IN A PAGE: bf-theme.js, run in jsdom, adds <style id="bf-scrollbars">
         with that text once (not again when it runs twice, nor over an inline
         copy), and the rule reaches every element (the * selector).

   MUTATE=<name> edits the files IN MEMORY; MUTATE=all runs each in its own
   process. BIZFORCE_FRONTEND_DIR overrides the frontend location. No network,
   no database. */
"use strict";
const fs = require("fs");
const path = require("path");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const UI = "F:css/bizforce-ui.css", THEME = "F:scripts/bf-theme.js", LEGAL = "lib/legalPages.js", SB = "lib/scrollbars.js", SUPPORT = "lib/supportPage.js";

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
function keyPath(key) { return key.indexOf("F:") === 0 ? path.join(FRONTEND, key.slice(2)) : path.join(REPO, key); }
function walk(dir, rel, out) {
  for (const name of fs.readdirSync(dir)) {
    if (name === "node_modules" || name === ".git" || name === "icons") continue;
    const p = path.join(dir, name), r = rel ? rel + "/" + name : name;
    if (fs.statSync(p).isDirectory()) walk(p, r, out);
    else if (/\.(html|js|css)$/.test(name)) out.push(r);
  }
  return out;
}
if (!fs.existsSync(path.join(FRONTEND, "css", "bizforce-ui.css"))) { console.log("    FAIL  frontend not found at " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
const FRONT = walk(FRONTEND, "", []).sort();
FRONT.forEach(r => { FILES["F:" + r] = lf(fs.readFileSync(path.join(FRONTEND, r), "utf8")); });
[LEGAL, SB, SUPPORT].forEach(k => { FILES[k] = lf(fs.readFileSync(keyPath(k), "utf8")); });

/* Each mutation: [file, from, to]. Every one must make a check fail. */
const MUTATIONS = {
  // the scrollbar rule missing on one page (your-data.html loads neither bf-theme.js nor bizforce-ui.css)
  "missing-on-one-page": [["F:your-data.html", '<style id="bf-scrollbars">\n', '<style id="bf-scrollbars-gone">\n']],
  // bf-theme.js no longer adds it
  "theme-does-not-add": [[THEME, "      bars.textContent = SCROLLBARS;\n", ""]],
  // a copy drifting from the stylesheet's text (the thumb's glow dropped in bf-theme.js)
  "copy-drifts": [[THEME, "border:2px solid transparent;border-radius:8px;box-shadow:inset 0 0 6px rgba(var(--bf-accent-a-rgb, 34, 211, 238),.55)}", "border:2px solid transparent;border-radius:8px}"]],
  // the default grey bar back on a panel (oracle.html)
  "override-returns": [["F:oracle.html", "    .oracle-profile-panel.is-open {", "    .oracle-profile-panel::-webkit-scrollbar-thumb { background: #888; }\n    .oracle-profile-panel.is-open {"]],
  // the thumb in a fixed colour, not the theme's gradient
  "thumb-not-themed": [[UI, "::-webkit-scrollbar-thumb{background:linear-gradient(180deg,var(--bf-accent-a, #22d3ee)var(--bf-accent-mid, ),var(--bf-accent-b, #a855f7));", "::-webkit-scrollbar-thumb{background:#5b6b8c;"]],
  // Firefox left with its own bar
  "no-firefox": [[UI, "*{scrollbar-width:thin;scrollbar-color:var(--bf-accent-a, #22d3ee) rgba(8,12,24,.55)}\n", ""]],
  // a built legal page without it
  "legal-without": [[LEGAL, "    '<style id=\"bf-scrollbars\">',\n    SCROLLBARS,\n    \"</style>\",\n", ""]],
  // the support page built without it
  "support-without": [[SUPPORT, "    '<style id=\"bf-scrollbars\">',\n    SCROLLBARS,\n    '</style>',\n", ""]],
  // the guide panel styling its own bar again
  "guide-own-bar": [["F:scripts/termaximus-guide.js", "    \"#tmx-guide-root.tmx-guide-open #tmx-guide-panel {\",", "    \"#tmx-guide-panel { scrollbar-color: #555 #222; }\",\n    \"#tmx-guide-root.tmx-guide-open #tmx-guide-panel {\","]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
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

/* the block: from the BEGIN comment to the END comment, inclusive */
function blockIn(text) {
  const a = text.indexOf("/* BF-SCROLLBARS:BEGIN"), b = text.indexOf("/* BF-SCROLLBARS:END */");
  return a === -1 || b === -1 || b < a ? null : text.slice(a, b + "/* BF-SCROLLBARS:END */".length);
}
/* a JS string constant's value: var|const NAME = "...";  */
function constant(src, name) {
  const m = new RegExp("(?:var|const) " + name + " = (\"(?:[^\"\\\\]|\\\\.)*\");").exec(src || "");
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch (e) { return null; }
}

async function main() {
  console.log("\n══ S1. the rule ══");
  const RULE = blockIn(FILES[UI]) || "";
  const has = re => re.test(RULE);
  check("S1. css/bizforce-ui.css holds the one rule (BF-SCROLLBARS:BEGIN … END)", !!RULE && FILES[UI].split("BF-SCROLLBARS:BEGIN").length === 2, RULE.slice(0, 80));
  check("S1. about 8 px, on both axes", has(/::-webkit-scrollbar\{width:8px;height:8px\}/));
  check("S1. a translucent noir track, rounded", has(/::-webkit-scrollbar-track\{background:rgba\(8,12,24,\.55\);border-radius:8px\}/));
  check("S1. the thumb is the theme's gradient, accent a -> mid -> b, rounded, with a glow",
    has(/::-webkit-scrollbar-thumb\{background:linear-gradient\(180deg,var\(--bf-accent-a, #22d3ee\)var\(--bf-accent-mid, \),var\(--bf-accent-b, #a855f7\)\);[^}]*border-radius:8px;box-shadow:inset 0 0 6px rgba\(var\(--bf-accent-a-rgb/) &&
    has(/::-webkit-scrollbar-thumb:horizontal\{background:linear-gradient\(90deg,var\(--bf-accent-a, #22d3ee\)var\(--bf-accent-mid, \),var\(--bf-accent-b, #a855f7\)\)/));
  check("S1. a hover state that brightens the glow", has(/::-webkit-scrollbar-thumb:hover\{[^}]*box-shadow:[^}]*0 0 8px rgba\(var\(--bf-accent-a-rgb, 34, 211, 238\),\.7\)\}/));
  check("S1. Firefox: thin, in the theme's accent over the noir track", has(/\*\{scrollbar-width:thin;scrollbar-color:var\(--bf-accent-a, #22d3ee\) rgba\(8,12,24,\.55\)\}/));
  /* --bf-accent-mid carries its own leading comma (bf-theme.js), so "a var(--bf-accent-mid, ), b" is a two- or three-stop gradient */
  const themeMid = /out\["--bf-accent-mid"\] = ", " \+/.test(FILES[THEME]);
  check("S1. the mid stop follows bf-theme.js's --bf-accent-mid, which brings its own comma (an empty fallback leaves two stops)", themeMid);

  console.log("\n══ S2. the same text everywhere ══");
  const inTheme = constant(FILES[THEME], "SCROLLBARS"), inLegal = constant(FILES[SB], "SCROLLBARS");
  check("S2. scripts/bf-theme.js's SCROLLBARS is the stylesheet's text, byte for byte", !!inTheme && inTheme === RULE, inTheme && inTheme.slice(0, 80));
  check("S2. the backend's lib/scrollbars.js holds the same text, and the legal pages (lib/legalPages.js) carry it inline",
    !!inLegal && inLegal === RULE && /const \{ SCROLLBARS \} = require\("\.\/scrollbars"\);/.test(FILES[LEGAL]) &&
    /'<style id="bf-scrollbars">',\n    SCROLLBARS,\n    "<\/style>",\n    "<\/head>",/.test(FILES[LEGAL]));
  check("S2. ... and so does the support page, live or built (lib/supportPage.js)",
    /const \{ SCROLLBARS \} = require\("\.\/scrollbars"\);/.test(FILES[SUPPORT]) && /'<style id="bf-scrollbars">',\n    SCROLLBARS,\n    '<\/style>',\n    '<\/head>',/.test(FILES[SUPPORT]));

  console.log("\n══ S3. every page ══");
  const pages = FRONT.filter(r => /\.html$/.test(r) && !/^google[0-9a-f]+\.html$/.test(r));
  const how = {}, missing = [], drift = [];
  for (const r of pages) {
    const h = FILES["F:" + r];
    const theme = /<script src="\/scripts\/bf-theme\.js"><\/script>/.test(h), ui = /<link[^>]+href="\/?css\/bizforce-ui\.css"/.test(h);
    const m = /<style id="bf-scrollbars">\n([\s\S]*?)\n<\/style>/.exec(h);
    if (m && m[1] !== RULE) drift.push(r);
    const way = theme ? "theme" : ui ? "stylesheet" : m ? "inline" : null;
    if (!way) missing.push(r); else how[way] = (how[way] || 0) + 1;
  }
  check("S3. every page gets the rule (" + pages.length + " pages: " + Object.keys(how).map(k => how[k] + " by " + k).join(", ") + ")",
    missing.length === 0 && pages.length >= 70, missing.join(", "));
  check("S3. every inline copy is the same text", drift.length === 0, drift.join(", "));
  const inlinePages = pages.filter(r => /<style id="bf-scrollbars">/.test(FILES["F:" + r]));
  check("S3. the inline copy is only where neither bf-theme.js nor css/bizforce-ui.css loads (" + inlinePages.length + " pages)",
    inlinePages.every(r => !/bf-theme\.js|css\/bizforce-ui\.css/.test(FILES["F:" + r].split(RULE).join(""))) &&
    ["card-view.html", "terms.html", "privacy.html", "refund.html", "contact.html", "your-data.html"].every(r => inlinePages.indexOf(r) !== -1), inlinePages.join(", "));

  console.log("\n══ S4. nothing else ══");
  const strip = (t) => { const b = blockIn(t); let out = b ? t.split(b).join("") : t; const tc = constant(t, "SCROLLBARS"); if (tc) out = out.split(JSON.stringify(tc)).join(""); return out; };
  const others = [];
  for (const r of FRONT) {
    const t = strip(FILES["F:" + r]);
    const hit = /::-webkit-scrollbar|scrollbar-width\s*:|scrollbar-color\s*:/.exec(t);
    if (hit) others.push(r + ": " + t.slice(Math.max(0, hit.index - 40), hit.index + 40).replace(/\s+/g, " "));
  }
  check("S4. no page, script or stylesheet styles a scrollbar of its own (the guide panel and the chat use the one rule)", others.length === 0, others.join(" | "));
  check("S4. ... nor the legal and support page builders", [LEGAL, SUPPORT].every(k => !/::-webkit-scrollbar|scrollbar-width\s*:|scrollbar-color\s*:/.test(strip(FILES[k]))));

  console.log("\n══ S5. in a page ══");
  let JSDOM = null;
  try { JSDOM = require("jsdom").JSDOM; } catch (e) { JSDOM = null; }
  if (!JSDOM) { check("S5. jsdom is installed (npm i in the backend)", false); }
  else {
    const open = (extraHead) => new JSDOM("<!DOCTYPE html><html><head>" + (extraHead || "") + "<script>" + FILES[THEME] + "</script></head><body><div style=\"overflow:auto\">x</div></body></html>",
      { url: "https://bizforceai.net/crm.html", runScripts: "dangerously", beforeParse(w) { w.matchMedia = () => ({ matches: false, addEventListener() {}, addListener() {} }); w.fetch = () => new Promise(() => {}); } });
    const A = open();
    const st = A.window.document.querySelectorAll("style#bf-scrollbars");
    check("S5. bf-theme.js adds <style id=\"bf-scrollbars\"> with the rule, once", st.length === 1 && st[0].textContent === RULE, st.length);
    const B = open('<style id="bf-scrollbars">\n' + RULE + "\n</style>");
    check("S5. ... and not again over a page's inline copy", B.window.document.querySelectorAll("style#bf-scrollbars").length === 1);
    const C = open("<script>" + FILES[THEME] + "</script>");
    check("S5. ... nor when bf-theme.js runs twice", C.window.document.querySelectorAll("style#bf-scrollbars").length === 1);
    const sheet = st[0] && st[0].sheet;
    const sels = sheet ? Array.prototype.map.call(sheet.cssRules, r => r.selectorText).filter(Boolean) : [];
    check("S5. the rule parses and reaches every element (*, and the bare ::-webkit-scrollbar parts)",
      sels.indexOf("*") !== -1 && sels.filter(x => /^::-webkit-scrollbar/.test(x)).length >= 5, sels.join(" "));
    [A, B, C].forEach(d => d.window.close());
  }

  console.log("\n" + passes + " passed, " + failures + " failed");
  console.log(failures ? "CHECKS FAILED" : "ALL CHECKS PASSED");
  process.exit(failures ? 1 : 0);
}
main().catch(e => { console.log("    FAIL  the check crashed: " + (e && e.stack || e)); process.exit(1); });
