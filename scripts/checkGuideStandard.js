"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkGuideStandard — every Termaximus guide entry meets one standard, every
   page that loads the guide has its own entry, and phones get the same tips.

   Frontend "Every Termaximus guide rewritten to one standard, on every page
   and on phones" rewrote all 35 entries of scripts/termaximus-guide.js
   (PAGE_GUIDANCE) to the standard proposed in the Oct 27 2026 diagnostic §2,
   gave the 10 pages that fell back to the generic "Explore this page…" text
   their own entries, loaded the guide on 11 working pages that lacked it, and
   added a "Guide" button with a bottom sheet for screens of 860px and less,
   where the side panel is hidden.

   THE STANDARD, as asserted here:
     S1  every entry has 4 tips, 5 at most, each at most 160 characters, and
         the entry's first tip names the page's main action (Do), with a
         quoted label;
     S2  every label a tip quotes ("…") is found on that page or in a local
         script the page loads;
     S3  no tip restates the page's <h1> (contains a heading of two or more
         words, or opens with the heading or with "This is"), and none shares
         a run of five words with the page's hero subtitle;
     S4  no sentence appears twice anywhere in the guide, and no tip repeats a
         sentence of the COMMON line;
     S5  GUIDE_COMMON is defined once and, rendered in jsdom, appears exactly
         once under the tips of each page that carries the "Last run" line
         (every one an agent page), and on no other page;
     S6  every page that loads the guide, and on which it displays, has its own
         entry; the generic default text is gone from the guide, and a page
         without an entry mounts no guide at all;
     S7  the 11 pages load the guide (settings, crm, inventory, proposals,
         prospecting, calendar, messages, mychart, self-reviews, synastry,
         your-data), and the legal pages do not;
     S8  NAMED (Nov 22 2026, FX3): BEFORE a "Guide" button with a bottom
         sheet at 860px and less, where the panel was hidden. AFTER no button
         and no sheet anywhere; the Guide's tab shows at every width (no
         media rule hides it), on every page that shows the guide; on the
         phone (760px and less) the panel opens from the left with the tab at
         its right edge, min(300px, 100vw - 48px), at most 70vh and clear of
         the bar; the tab opens and closes it, and an outside tap and Escape
         close it; a free account's guide has no Insights section and makes
         no /api/insights/page request, a member's asks once on opening;
     S9  NAMED (Nov 22 2026, FX3): BEFORE the button's box cleared the mist's
         corners. AFTER the tab's box (left edge, middle, 32 x 170), at nine
         phone and tablet sizes with and without a 34px inset, touches none
         of the mist's four desktop corners nor the phone mist (56 px, 16 px
         from the right, above the bar); the open chat is drawn above it.

   Pages and scripts are read as text; each page's guide is RUN in jsdom (its
   own scripts stripped, so nothing else runs and no request is made). No
   network, no model call, no database.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const GUIDE = "scripts/termaximus-guide.js", PRESENCE = "scripts/termaximus-presence.js", SERVER = "server.js";
const IN_AGENTS = ["seo.html", "sales.html", "content.html", "social.html", "analytics.html", "lead-radar.html", "sms.html"];
const fileOfKey = k => IN_AGENTS.indexOf(k) !== -1 ? "agents/" + k : k;
const NEWLY_GUIDED = ["settings.html", "crm.html", "inventory.html", "proposals.html", "prospecting.html", "calendar.html",
  "messages.html", "mychart.html", "self-reviews.html", "synastry.html", "your-data.html"];
const LEGAL = ["privacy.html", "terms.html", "refund.html"];
const GUIDE_TAG = '<script src="/scripts/termaximus-guide.js"></script>';

const MUTATIONS = {
  // a sixth tip on the dashboard (S1)
  // NAMED (Nov 10 2026, orbit top half): sixth-tip and duplicate-sentence follow the rewritten dashboard tips. BEFORE
  // sixth-tip was anchored on "To delegate new work, ..." and duplicate-sentence inserted "Name or industry wrong? ...
  // every agent reads this profile."; both tips became one, which is now the anchor and the inserted duplicate.
  "sixth-tip": [[GUIDE, '      "Name or industry wrong? Press \\"Expand Profile\\" and edit it. For new work, open \\"Agent Hub\\" or \\"Full Directory\\"; each lists all 18 agents."\n',
    '      "Name or industry wrong? Press \\"Expand Profile\\" and edit it. For new work, open \\"Agent Hub\\" or \\"Full Directory\\"; each lists all 18 agents.",\n      "Check back after each task finishes."\n']],
  // a 200-character tip (S1)
  "long-tip": [[GUIDE, '"Press \\"Download my data\\" for a copy of everything BizForce stores about you."',
    '"Press \\"Download my data\\" for a copy of everything BizForce stores about you, which arrives as one file holding your profile, your runs, your wallet history, your listings and your messages, all of it."']],
  // a tip naming a button that does not exist (S2)
  "ghost-button": [[GUIDE, 'press \\"Draft the framework\\"', 'press \\"Draft the term sheet\\"']],
  // a sentence another entry already has (S4)
  "duplicate-sentence": [[GUIDE, '"Lost in another month? Press \\"Today\\" to come back."',
    '"Name or industry wrong? Press \\"Expand Profile\\" and edit it. For new work, open \\"Agent Hub\\" or \\"Full Directory\\"; each lists all 18 agents."']],
  // a page loads the guide and has no entry (S6)
  "page-without-entry": [["contact.html", "</body>", GUIDE_TAG + "\n</body>"]],
  // NAMED (Nov 22 2026, FX3): BEFORE "mobile-button-removed" (the book button, gone). AFTER the tab is hidden on the phone (S8)
  "tab-hidden-on-phone": [[GUIDE, '    "  #tmx-guide-root { flex-direction: row-reverse; align-items: center;",', '    "  #tmx-guide-root { display: none; flex-direction: row-reverse; align-items: center;",']],
  // ── further guards ──
  // the generic default comes back for a page with no entry (S6)
  "default-restored": [[GUIDE, "      if (PAGE_GUIDANCE[withExtension]) return PAGE_GUIDANCE[withExtension];\n    }\n    return null;",
    "      if (PAGE_GUIDANCE[withExtension]) return PAGE_GUIDANCE[withExtension];\n    }\n    return [\"Explore this page — Termaximus will surface guidance here as it learns the terrain.\"];"]],
  // the COMMON line shows on every page, not only agent pages (S5)
  "common-everywhere": [[GUIDE, "(document.getElementById(\"lastRunText\") ? '<p class=\"tmx-guide-common\"", "(true ? '<p class=\"tmx-guide-common\""]],
  // a tip restates its page's heading (S3)
  "restates-h1": [[GUIDE, '"Press \\"+ Add Customer\\", fill in', '"Customers: press \\"+ Add Customer\\", fill in']],
  // an entry drops to three tips (S1)
  /* NAMED BEFORE → AFTER (Oct 30 2026): the calendar had four tips, "Lost in another month?" last; db265c2 added a fifth
     ("Agent runs") after it, so the old anchor (that tip with no comma) matched nothing. The mutation still leaves the
     calendar three tips: it drops "Lost in another month?" and "Agent runs", and "Recurring annually" ends the list. */
  "three-tips": [[GUIDE, '      "Lost in another month? Press \\"Today\\" to come back.",\n      "Press \\"Agent runs\\" to see when your agent schedules come due; it only reads, and a paused or switched-off schedule shows nothing, with why."\n', ""],
    [GUIDE, '      "Tick \\"Recurring annually\\" for a birthday or an anniversary, and it repeats every year from one save.",\n',
    '      "Tick \\"Recurring annually\\" for a birthday or an anniversary, and it repeats every year from one save."\n']],
  // one of the 11 pages stops loading the guide (S7)
  "unguided-again": [["crm.html", GUIDE_TAG + "\n", ""]],
  // NAMED (Nov 22 2026, FX3): BEFORE fab-over-mist, fab-over-modals, sheet-not-dialog, focus-not-returned, swipe-ignored, fab-on-desktop
  // and fab-never-moves (the book button and its sheet, gone). AFTER the Guide's tab and panel at every width (S8, S9)
  "panel-not-beside-tab": [[GUIDE, '    "  #tmx-guide-root { flex-direction: row-reverse; align-items: center;",', '    "  #tmx-guide-root { align-items: center;",']],
  "panel-too-wide": [[GUIDE, "width: min(300px, calc(100vw - 48px)); margin-left: 0;", "width: 300px; margin-left: 0;"]],
  "panel-over-bar": [[GUIDE, "    max-height: min(70vh, calc(100vh - 2 * (64px + env(safe-area-inset-bottom, 0px)))); }", "    max-height: 92vh; }"]],
  "escape-ignored": [[GUIDE, '    if (isOpen && e.key === "Escape") setOpen(false);\n', ""]],
  "outside-tap-ignored": [[GUIDE, "    if (isOpen && !root.contains(e.target)) setOpen(false);\n", ""]],
  "free-asks-insights": [[GUIDE, "  function ensureInsight() {\n    if (guideFree()) return;\n", "  function ensureInsight() {\n"]],
  "free-keeps-insights": [[GUIDE, "    if (s && s.parentNode) s.parentNode.removeChild(s);\n", ""]],
  "member-loses-insights": [[GUIDE, "    accessKnown = true;\n    if (!guideFree()) return;\n", "    accessKnown = true;\n"]],
  "book-button-back": [[GUIDE, "  var accessKnown = false;\n", "  var accessKnown = false;\n  var fab = document.createElement(\"button\"); fab.id = \"tmx-guide-fab\"; document.body.appendChild(fab);\n"]],
  "tab-at-the-bottom": [[GUIDE, '    "#tmx-guide-root {",\n    "  position: fixed;",\n    "  top: 50%;",', '    "#tmx-guide-root {",\n    "  position: fixed;",\n    "  top: 88%;",']],
  "mist-on-the-tab": [[PRESENCE, "right: 16px !important; bottom: calc(16px + env(safe-area-inset-bottom, 0px)) !important;", "right: calc(100vw - 72px) !important; bottom: calc(16px + env(safe-area-inset-bottom, 0px)) !important;"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const FILES = {};
const HTML_PAGES = [];
(function walk(dir) {
  fs.readdirSync(path.join(FRONTEND, dir), { withFileTypes: true }).forEach(d => {
    const rel = dir ? dir + "/" + d.name : d.name;
    if (d.isDirectory()) { if (!/^(\.|node_modules$)/.test(d.name)) walk(rel); }
    else if (/\.html$/i.test(d.name)) HTML_PAGES.push(rel);
  });
})("");
function readFront(f) {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.log("    FAIL  frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
  FILES[f] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
}
HTML_PAGES.concat([GUIDE, PRESENCE]).forEach(readFront);
fs.readdirSync(path.join(FRONTEND, "scripts")).filter(f => /\.js$/.test(f)).forEach(f => { if (!FILES["scripts/" + f]) readFront("scripts/" + f); });
FILES[SERVER] = fs.readFileSync(path.join(REPO, SERVER), "utf8").replace(/\r\n/g, "\n");
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

/* ── reading the guide ─────────────────────────────────────────────────── */
const G = FILES[GUIDE];
const KEYS = (G.match(/\n    "([a-z0-9-]+\.html)": \[/g) || []).map(m => /"([^"]+)"/.exec(m)[1]);
function tipsFor(key) {
  const esc = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp('\\n    "' + esc + '": (\\[[\\s\\S]*?\\n    \\])').exec(G);
  try { return m ? vm.runInNewContext(m[1]) : []; } catch (e) { return []; }
}
const ENTRIES = {};
KEYS.forEach(k => { ENTRIES[k] = tipsFor(k); });
const COMMON_DECLS = G.match(/\n  var GUIDE_COMMON = ("(?:[^"\\]|\\.)*");/g) || [];
const COMMON = COMMON_DECLS.length ? vm.runInNewContext(/= ("(?:[^"\\]|\\.)*");/.exec(COMMON_DECLS[0])[1]) : "";
const ALL = [];
KEYS.forEach(k => ENTRIES[k].forEach((t, i) => ALL.push({ key: k, file: fileOfKey(k), i, t })));

// Page text helpers.
const decode = t => t.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&rsquo;/g, "’").replace(/&nbsp;/g, " ")
  .replace(/&#x([0-9a-f]+);/gi, (m, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&#(\d+);/g, (m, d) => String.fromCodePoint(+d));
const stripTags = t => decode(t.replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
const loadsGuide = f => FILES[f].indexOf(GUIDE_TAG) !== -1;
// The local scripts a page loads ("/scripts/x.js" or "../scripts/x.js").
const localScripts = f => (FILES[f].match(/<script src="([^"]+)"/g) || []).map(m => /"([^"]+)"/.exec(m)[1])
  .map(src => src.replace(/^(\.\.\/|\/)/, "")).filter(src => /^scripts\/[\w.-]+\.js$/.test(src) && FILES[src]);
// The guide's early return: it never displays on app.html or "/".
const EARLY = (/var _tmxLogin = [^;\n]*?\|\| (\/[^\n]*?\/)\.test\(_tmxPath\);/.exec(G) || ["", ""])[1];
const EARLY_RE = EARLY ? vm.runInNewContext(EARLY) : null;
const guideShows = f => loadsGuide(f) && !!EARLY_RE && !EARLY_RE.test("/" + f.toLowerCase());
const SHOWN = HTML_PAGES.filter(guideShows);
const AGENT_URLS = (() => {
  const i = FILES[SERVER].indexOf("\nconst AGENT_PAGE_URLS = {"), j = FILES[SERVER].indexOf("\n};", i);
  return i === -1 ? [] : (FILES[SERVER].slice(i, j).match(/:\s*"([^"]+)"/g) || []).map(m => /"([^"]+)"/.exec(m)[1].replace(/^\//, ""));
})();

/* ── S1. counts and lengths ─────────────────────────────────────────────── */
console.log("\n══ S1. 4 tips (5 at most), each at most 160 characters ══");
check("S1. the guide's entries were read: at least 56, every one of them parsed", KEYS.length >= 56 && KEYS.every(k => ENTRIES[k].length > 0), KEYS.length + " keys");
const badCount = KEYS.filter(k => ENTRIES[k].length < 4 || ENTRIES[k].length > 5);
check("S1. every entry has 4 or 5 tips", badCount.length === 0, badCount.map(k => k + "=" + ENTRIES[k].length).join(", "));
const tooLong = ALL.filter(x => typeof x.t !== "string" || x.t.length > 160 || x.t.trim().length < 20);
check("S1. every tip is a sentence of at most 160 characters", tooLong.length === 0, tooLong.map(x => x.key + "#" + x.i + " (" + String(x.t).length + ")").join(", "));
const noDo = KEYS.filter(k => !/"[^"]+"/.test(ENTRIES[k][0]) && k !== "artists.html" && k !== "mychart.html" && k !== "index.html");
check("S1. every entry's first tip (Do) names its action by a quoted label (artists, mychart and the signed-in index have no button to name: a card, the chart, a redirect)",
  noDo.length === 0, noDo.join(", "));
check("S1. COMMON is short too: at most 160 characters", COMMON.length > 0 && COMMON.length <= 160, COMMON.length);

/* ── S2. every quoted label exists ──────────────────────────────────────── */
console.log("\n══ S2. every quoted label is on its page or in a script it loads ══");
// The guide itself is a script every guided page loads; it is never evidence for its own labels.
function sourcesOf(file) { return [FILES[file], decode(FILES[file])].concat(localScripts(file).filter(f => f !== GUIDE).map(f => FILES[f])); }
function labelFound(label, file) {
  const e = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp("(^|[^A-Za-z0-9])" + e + "($|[^A-Za-z0-9])");
  return sourcesOf(file).some(src => re.test(src));
}
const quoted = t => (t.match(/"([^"]+)"/g) || []).map(q => q.slice(1, -1));
const missing = [];
ALL.forEach(x => quoted(x.t).forEach(l => { if (!FILES[x.file] || !labelFound(l, x.file)) missing.push(x.key + "#" + x.i + ' "' + l + '"'); }));
check("S2. every quoted label in every tip exists on its page or in a local script it loads", missing.length === 0, missing.join(" | "));
const quotedCount = ALL.reduce((n, x) => n + quoted(x.t).length, 0);
check("S2. the label reader found labels to test (at least 150)", quotedCount >= 150, quotedCount);
const COMMON_PAGES = SHOWN.filter(f => /id="lastRunText"/.test(FILES[f]));
const commonMissing = COMMON_PAGES.filter(f => quoted(COMMON).some(l => !labelFound(l, f)));
check("S2. COMMON's quoted labels exist on every page it is shown on", COMMON_PAGES.length > 0 && commonMissing.length === 0, commonMissing.join(", "));

/* ── S3. no tip restates its page's heading ─────────────────────────────── */
console.log("\n══ S3. no tip restates its page's <h1> or hero ══");
const words = t => decode(t).toLowerCase().replace(/[^a-z0-9\s]/g, " ").split(/\s+/).filter(Boolean);
function headingsOf(file) {
  return (FILES[file].match(/<h1[^>]*>[\s\S]*?<\/h1>/g) || []).map(stripTags)
    .filter(h => h && !/['"+]|escapeHtml|^[—–-]$|^Loading/.test(h) && !/^Please log in/i.test(h));
}
function heroOf(file) {
  return (FILES[file].match(/<p class="(?:agent-subtitle|hero-sub|mychart-subtitle)"[^>]*>[\s\S]*?<\/p>/g) || []).map(stripTags).filter(Boolean);
}
function restates(tip, file) {
  const t = tip.toLowerCase(), out = [];
  headingsOf(file).forEach(h => {
    const hl = h.toLowerCase();
    if (words(h).length >= 2 && t.indexOf(hl) !== -1) out.push("contains h1 \"" + h + "\"");
    if (t.indexOf(hl) === 0) out.push("opens with h1 \"" + h + "\"");
  });
  if (/^this (page )?is\b/i.test(tip)) out.push("opens with \"This is\"");
  const tw = words(tip);
  heroOf(file).forEach(sub => {
    const sw = words(sub).join(" ");
    for (let i = 0; i + 5 <= tw.length; i++) if ((" " + sw + " ").indexOf(" " + tw.slice(i, i + 5).join(" ") + " ") !== -1) { out.push("shares \"" + tw.slice(i, i + 5).join(" ") + "\" with the hero"); break; }
  });
  return out;
}
const restated = ALL.map(x => ({ x, why: FILES[x.file] ? restates(x.t, x.file) : ["no page"] })).filter(r => r.why.length);
check("S3. no tip contains or opens with its page's heading, and none shares five words in a row with the hero",
  restated.length === 0, restated.map(r => r.x.key + "#" + r.x.i + ": " + r.why.join(", ")).join(" | "));
const headed = KEYS.filter(k => FILES[fileOfKey(k)] && headingsOf(fileOfKey(k)).length);
check("S3. headings were read for most pages (at least 45)", headed.length >= 45, headed.length);

/* ── S4. no sentence repeats ────────────────────────────────────────────── */
console.log("\n══ S4. no sentence repeats across the guide ══");
const sentences = t => t.split(/(?<=[.!?])\s+(?=[A-Z"])/).map(x => x.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim()).filter(x => x.split(" ").length >= 3);
const seen = {}, dupes = [];
ALL.forEach(x => sentences(x.t).forEach(sn => { if (seen[sn] && seen[sn] !== x.key + "#" + x.i) dupes.push(seen[sn] + " = " + x.key + "#" + x.i + ": " + sn.slice(0, 60)); else seen[sn] = x.key + "#" + x.i; }));
check("S4. no sentence appears twice in the guide, within an entry or across entries", dupes.length === 0, dupes.join(" | "));
const commonEcho = ALL.filter(x => sentences(x.t).some(sn => sentences(COMMON).indexOf(sn) !== -1));
check("S4. no tip repeats a sentence of the COMMON line", commonEcho.length === 0, commonEcho.map(x => x.key + "#" + x.i).join(", "));
const OLD_TEMPLATE = /Each run is saved — open your latest from the Last run link|Business Profile \(set via the Content Agent\)/;
check("S4. the two template lines the diagnostic found in many entries are gone from every tip", ALL.every(x => !OLD_TEMPLATE.test(x.t)),
  ALL.filter(x => OLD_TEMPLATE.test(x.t)).map(x => x.key + "#" + x.i).join(", "));

/* ── rendering each page's guide in jsdom ───────────────────────────────── */
const ORIGIN = "https://bizforceai.net";
function render(file, opts) {
  opts = opts || {};
  const html = FILES[file].replace(/<script\b[\s\S]*?<\/script>/gi, "");
  const dom = new JSDOM(html, { url: ORIGIN + "/" + file, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  w.localStorage.setItem("bf_token", "t");
  w.fetch = () => { const p = Promise.reject(new Error("no network in this check")); p.catch(() => {}); return p; };
  if (opts.before) opts.before(w);
  let error = "";
  try { w.eval(FILES[GUIDE]); } catch (e) { error = e.message; }
  return { w, doc: w.document, error };
}
const RENDERED = {};
SHOWN.forEach(f => { RENDERED[f] = render(f); });
const listOf = (doc, sel) => [...doc.querySelectorAll(sel + " .tmx-guide-list li")].map(li => li.innerHTML.replace(/&amp;/g, "&").replace(/&quot;/g, '"'));

/* ── S5. COMMON ─────────────────────────────────────────────────────────── */
console.log("\n══ S5. the COMMON line, once, under agent pages only ══");
check("S5. GUIDE_COMMON is declared once and says both shared truths (runs are saved under \"Last run\"; agents read the Business Profile set on the Content Agent page)",
  COMMON_DECLS.length === 1 && /\"Last run\"/.test(COMMON) && /Business Profile you set on the Content Agent page/.test(COMMON), COMMON);
check("S5. COMMON's text appears in the guide's source only in its declaration",
  G.split("Every agent reads the Business Profile you set on the Content Agent page").length - 1 === 1 && G.split("Each run is saved").length - 1 === 1);
const renderErrors = SHOWN.filter(f => RENDERED[f].error);
check("S5. the guide ran on every page that shows it", renderErrors.length === 0, renderErrors.map(f => f + ": " + RENDERED[f].error).join(" | "));
const commonWrong = SHOWN.filter(f => {
  const n = RENDERED[f].doc.querySelectorAll("#tmx-guide-panel [data-tmx-guide-common]").length;
  return n !== (COMMON_PAGES.indexOf(f) !== -1 ? 1 : 0);
});
/* NAMED BEFORE → AFTER (Oct 30 2026, the Executive command deck). BEFORE: at least 17 pages carried "Last run",
   and the one agent page without it was the Content Agent. AFTER: at least 16; executive-agent.html lost its toolbar
   Last-run line (a duplicate of the deck's History tab, which lists every run), so it shows no COMMON line either. */
check("S5. in the panel, COMMON appears exactly once on each page with the \"Last run\" line and on no other page",
  COMMON_PAGES.length >= 16 && commonWrong.length === 0, commonWrong.join(", "));
const commonText = COMMON_PAGES.filter(f => { const el = RENDERED[f].doc.querySelector("#tmx-guide-panel [data-tmx-guide-common]"); return !el || el.textContent !== COMMON; });
check("S5. it reads exactly as declared, below the page's own tips", commonText.length === 0 &&
  COMMON_PAGES.every(f => { const el = RENDERED[f].doc.querySelector("#tmx-guide-panel [data-tmx-guide-common]"); return el && el.previousElementSibling && el.previousElementSibling.matches("ul.tmx-guide-list"); }),
  commonText.join(", "));
const commonNonAgent = COMMON_PAGES.filter(f => AGENT_URLS.indexOf(f) === -1);
check("S5. every page with the \"Last run\" line is a registered agent page (AGENT_PAGE_URLS)", AGENT_URLS.length === 18 && commonNonAgent.length === 0, commonNonAgent.join(", "));
check("S5. the two agent pages without it are the Content Agent, which says in its own first tip where the profile is set, and the Executive deck, whose tips name its History tab",
  JSON.stringify(AGENT_URLS.filter(f => COMMON_PAGES.indexOf(f) === -1).sort()) === '["agents/content.html","executive-agent.html"]' &&
  /Business Profile/.test((ENTRIES["content.html"] || [""])[0]) && /deck: true,/.test(FILES["executive-agent.html"]) &&
  (ENTRIES["executive-agent.html"] || []).some(t => /"History" lists this agent's runs/.test(t)));

/* ── S6. every guided page has its entry; no default ────────────────────── */
console.log("\n══ S6. every page that shows the guide has its own entry ══");
const noEntry = SHOWN.filter(f => !KEYS.some(k => fileOfKey(k) === f));
check("S6. every page that loads the guide, and on which it displays, has its own entry", noEntry.length === 0, noEntry.join(", "));
const orphan = KEYS.filter(k => !FILES[fileOfKey(k)] || !guideShows(fileOfKey(k)));
check("S6. no entry is for a page that does not show the guide", orphan.length === 0, orphan.join(", "));
check("S6. the generic default is gone: no \"Explore this page\", no DEFAULT_GUIDANCE, and resolveGuidance answers null for an unknown page",
  !/Explore this page|DEFAULT_GUIDANCE/.test(G) && /\n    return null;\n  \}/.test(G));
const bare = render("blogindex.html");
check("S6. a page with no entry mounts no guide at all: no panel, no button, no sheet (rendered: blogindex.html with the guide run on it)",
  !bare.error && !bare.doc.getElementById("tmx-guide-root") && !bare.doc.getElementById("tmx-guide-fab") && !bare.doc.getElementById("tmx-guide-sheet"), bare.error);
const panelMismatch = SHOWN.filter(f => {
  const k = KEYS.filter(x => fileOfKey(x) === f)[0];
  return !k || JSON.stringify(listOf(RENDERED[f].doc, "#tmx-guide-panel")) !== JSON.stringify(ENTRIES[k]);
});
check("S6. on every page the panel shows exactly that page's entry", panelMismatch.length === 0, panelMismatch.join(", "));
const anyDefault = SHOWN.filter(f => /Explore this page/.test(RENDERED[f].doc.body.innerHTML));
check("S6. no rendered page shows the default text", anyDefault.length === 0, anyDefault.join(", "));

/* ── S7. the 11 pages load the guide; legal pages do not ────────────────── */
console.log("\n══ S7. the 11 working pages load the guide; the legal pages do not ══");
const notLoaded = NEWLY_GUIDED.filter(f => !FILES[f] || FILES[f].split(GUIDE_TAG).length - 1 !== 1 || !guideShows(f));
check("S7. settings, crm, inventory, proposals, prospecting, calendar, messages, mychart, self-reviews, synastry and your-data each load it once, and it displays",
  notLoaded.length === 0, notLoaded.join(", "));
const tagBeforeFooter = NEWLY_GUIDED.filter(f => FILES[f].indexOf(GUIDE_TAG + "\n") === -1 || FILES[f].indexOf(GUIDE_TAG) > FILES[f].indexOf('<script src="/scripts/bf-legal-footer.js"></script>'));
check("S7. on each, the tag sits on its own line before the legal footer's", tagBeforeFooter.length === 0, tagBeforeFooter.join(", "));
check("S7. the legal pages do not load it", LEGAL.every(f => FILES[f] && !loadsGuide(f)), LEGAL.filter(f => !FILES[f] || loadsGuide(f)).join(", "));
// NAMED (Oct 28 2026, member support): BEFORE 56 pages showed the guide and 57 loaded it. AFTER 57 and 58: the
// support page (support.html, also served at /support/<username>) loads it and has its own entry.
// NAMED (Nov 4 2026, the Media Library, migration 167): BEFORE 57 shown and 58 loading. AFTER 58 and 59: media.html
// loads the guide and has its own entry (four tips).
// NAMED (Nov 5 2026, mailbox connection, migration 169): BEFORE 58 shown and 59 loading. AFTER 59 and 60: mailbox.html
// (Your Inbox) loads the guide and has its own entry (four tips).
// NAMED (Nov 26 2026, FX4M, the owner's order): BEFORE 59 shown and 60 loading. AFTER 60 and 61: inbox.html loads the guide
// (its tag on its own line before the legal footer) and has its own entry (four tips).
check("S7. the guide displays on 60 pages now: 46 loaded it before (app.html among them, where it never displays), plus the 11, plus support.html, plus media.html, plus mailbox.html, plus inbox.html",
  SHOWN.length === 60 && HTML_PAGES.filter(loadsGuide).length === 61 && SHOWN.indexOf("media.html") !== -1 && SHOWN.indexOf("mailbox.html") !== -1 &&
  SHOWN.indexOf("inbox.html") !== -1 && FILES["inbox.html"].indexOf(GUIDE_TAG + "\n<footer") !== -1 && (ENTRIES["inbox.html"] || []).length === 4,
  SHOWN.length + " shown, " + HTML_PAGES.filter(loadsGuide).length + " loading");

/* ── S8. the Guide's tab at every width ────────────────────────────────── */
// NAMED (Nov 22 2026, FX3): BEFORE "S8. phones: the Guide button and the bottom sheet" (a button and a sheet at 860px and less, the panel
// hidden there). AFTER the book button and its sheet are gone; the tab is the desktop's at every width, and on the phone the panel opens
// from the left with the tab at its right edge (the owner's board TmxGuideOpen).
(async () => {
console.log("\n══ S8. the Guide's tab at every width ══");
const CSS = (() => {
  const i = G.indexOf("  style.textContent = ["), j = G.indexOf('  ].join("\\n");', i);
  try { return vm.runInNewContext(G.slice(i + "  style.textContent = ".length, j + 3)).join("\n"); } catch (e) { return ""; }
})();
const rule = sel => { const C = "\n" + CSS, i = C.indexOf("\n" + sel + " {"); return i === -1 ? "" : C.slice(i, C.indexOf("\n}", i)); };   // the first rule starts the text
const medias = CSS.split("@media").slice(1).map(x => "@media" + x.slice(0, x.indexOf("\n}")));
check("S8. the CSS was read: the tab, the panel and one phone rule", CSS.length > 2000 && !!rule("#tmx-guide-tab") && !!rule("#tmx-guide-panel") && medias.length === 1 && /^@media \(max-width: 760px\) \{/.test(medias[0]), CSS.length + " " + medias.length);
check("S8. no media rule hides the tab or the guide (it shows at every width), and nothing names a book button or a sheet",
  medias.every(m => !/#tmx-guide-(root|tab|panel)[^{]*\{[^}]*display:\s*none/.test(m)) && !/tmx-guide-fab|tmx-guide-sheet/.test(CSS) && !/tmx-guide-fab|tmx-guide-sheet/.test(G.replace(/\/\*[\s\S]*?\*\//g, "")), medias.join(" | "));
const ph = medias[0] || "";
check("S8. on the phone the panel opens from the left, the tab at its right edge: min(300px, 100vw - 48px), at most 70vh and clear of the bar, 0.3 s",
  /#tmx-guide-root \{ flex-direction: row-reverse; align-items: center;/.test(ph) && ph.indexOf("transform: translate(calc(-1 * min(300px, 100vw - 48px)), -50%); transition: transform 0.3s ease; }") !== -1 &&
  ph.indexOf("#tmx-guide-root.tmx-guide-open { transform: translate(0, -50%); }") !== -1 && ph.indexOf("width: min(300px, calc(100vw - 48px)); margin-left: 0;") !== -1 &&
  ph.indexOf("max-height: min(70vh, calc(100vh - 2 * (64px + env(safe-area-inset-bottom, 0px)))); }") !== -1 && /\n  overflow-y: auto;/.test(rule("#tmx-guide-panel")), ph);
const noTab = SHOWN.filter(f => !RENDERED[f].doc.getElementById("tmx-guide-tab") || !RENDERED[f].doc.getElementById("tmx-guide-panel") || RENDERED[f].doc.getElementById("tmx-guide-fab") || RENDERED[f].doc.getElementById("tmx-guide-sheet"));
check("S8. every page that shows the guide gets the tab and the panel, and no book button or sheet (" + SHOWN.length + " pages)", SHOWN.length > 40 && noTab.length === 0, noTab.join(", "));
const D = RENDERED["dashboard.html"], dd = D.doc, root = dd.getElementById("tmx-guide-root"), tab = dd.getElementById("tmx-guide-tab");
const W = D.w;
const opened = () => root.classList.contains("tmx-guide-open") && tab.getAttribute("aria-expanded") === "true";
const steps = [];
if (root && tab) {
  tab.click(); steps.push(["the tab opens it", opened()]);
  tab.click(); steps.push(["the tab closes it", !opened()]);
  tab.click(); dd.body.click(); steps.push(["a tap outside closes it", !opened()]);
  tab.click(); root.querySelector("#tmx-guide-panel").click(); steps.push(["a tap inside keeps it open", opened()]);
  dd.dispatchEvent(new W.KeyboardEvent("keydown", { key: "Escape", bubbles: true })); steps.push(["Escape closes it", !opened()]);
}
check("S8. the panel runs: " + steps.map(x => x[0]).join("; "), steps.length === 5 && steps.every(x => x[1]), steps.filter(x => !x[1]).map(x => x[0]).join(" | "));
// a free account and a member (scripts/bf-access.js's API: ready, tier()); fetch counted
async function accessRun(tier, withReady) {
  const asked = [];
  const r = render("dashboard.html", { before: w => {
    w.fetch = u => { asked.push(String(u)); const p = Promise.reject(new Error("no network in this check")); p.catch(() => {}); return p; };
    w.bfAccess = { tier: () => tier }; if (withReady) w.bfAccess.ready = Promise.resolve({ tier: tier });
  } });
  await new Promise(res => setTimeout(res, 20));
  const tb = r.doc.getElementById("tmx-guide-tab"); if (tb) tb.click();
  await new Promise(res => setTimeout(res, 20));
  return { error: r.error, asked: asked.filter(u => /\/api\/insights\/page/.test(u)).length, insights: !!r.doc.querySelector("#tmx-guide-panel .tmx-guide-section--insights"),
    free: r.doc.getElementById("tmx-guide-root").classList.contains("tmx-guide-free"), tips: listOf(r.doc, "#tmx-guide-panel").length };
}
const free = await accessRun("free", true), freeNoReady = await accessRun("free", false), member = await accessRun("member", true);
check("S8. a free account: the page's tips only (no Insights section, the panel marked free) and no /api/insights/page request on opening",
  !free.error && free.tips >= 4 && !free.insights && free.free && free.asked === 0 && freeNoReady.asked === 0, JSON.stringify([free, freeNoReady]));
check("S8. a member: the Insights section kept, and one /api/insights/page request on opening", !member.error && member.insights && !member.free && member.asked === 1, JSON.stringify(member));

/* ── S9. the tab clears the mist ───────────────────────────────────────── */
// NAMED (Nov 22 2026, FX3): BEFORE "S9. the button's box clears the mist, its chat, and every modal" (the book button, bottom-left). AFTER the
// tab: the left edge, in the middle, 32 x 170 at least, at every width; the desktop mist's four corners and the phone's mist never touch it.
console.log("\n══ S9. the tab's box clears the mist and its chat ══");
const px = (r, prop) => { const m = new RegExp("\\n  " + prop + ": (?:calc\\()?(\\d+)px").exec(r); return m ? +m[1] : null; };
const RR = rule("#tmx-guide-root"), TR = rule("#tmx-guide-tab");
const TAB = { left: px(RR, "left") === null && /\n  left: 0;/.test(RR) ? 0 : px(RR, "left"), middle: /\n  top: 50%;/.test(RR) && /\n  transform: translateY\(-50%\);/.test(RR), width: px(TR, "width"), height: px(TR, "min-height") };
check("S9. the tab's box was read: the left edge, in the middle, 32 wide, 170 tall at least", TAB.left === 0 && TAB.middle && TAB.width === 32 && TAB.height === 170, JSON.stringify(TAB));
const P = FILES[PRESENCE];
const CORNERS = (() => {
  const m = /var MIST_CORNERS = (\{[\s\S]*?\n  \});/.exec(P);
  try { return m ? vm.runInNewContext("(" + m[1] + ")") : {}; } catch (e) { return {}; }
})();
const MIST = { w: +((/#tmx-presence-root \{[\s\S]*?width: (\d+)px;/.exec(P) || [])[1]), h: +((/#tmx-presence-root \{[\s\S]*?height: (\d+)px;/.exec(P) || [])[1]) };
const PHONE_MIST = (() => { const m = /\n  var TMX_PHONE_MIST = (\d+), TMX_DESK_MIST = (\d+);/.exec(P); const r = /#tmx-presence-root \{ top: auto !important; left: auto !important; right: (\d+)px !important; bottom: calc\((\d+)px \+ env\(safe-area-inset-bottom, 0px\)\) !important;/.exec(P);
  return m && r ? { size: +m[1], right: +r[1], bottom: +r[2] } : null; })();
check("S9. the mist was read: its four desktop corners (110 x 110) and the phone's 56 px mist, 16 px from the right",
  Object.keys(CORNERS).sort().join(",") === "bottom-left,bottom-right,top-left,top-right" && MIST.w === 110 && MIST.h === 110 && !!PHONE_MIST && PHONE_MIST.size === 56 && PHONE_MIST.right === 16, JSON.stringify([Object.keys(CORNERS), MIST, PHONE_MIST]));
function boxFrom(spec, w, h, vw, vh) {
  const v = k => { const m = new RegExp("\\b" + k + ":\\s*(\\d+)px").exec(spec); return m ? +m[1] : null; };
  const left = v("left") !== null ? v("left") : vw - v("right") - w;
  const top = v("top") !== null ? v("top") : vh - v("bottom") - h;
  return { left, top, right: left + w, bottom: top + h };
}
const hit = (a, b) => a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;
const VIEWPORTS = [[320, 568], [360, 640], [375, 667], [390, 844], [393, 873], [412, 915], [414, 896], [768, 1024], [860, 1180]];
const clashes = [];
VIEWPORTS.forEach(([vw, vh]) => [0, 34].forEach(inset => {
  const tb = { left: TAB.left, right: TAB.left + TAB.width, top: vh / 2 - TAB.height / 2, bottom: vh / 2 + TAB.height / 2 };
  if (vw > 760) Object.keys(CORNERS).forEach(c => { if (hit(tb, boxFrom(CORNERS[c].root, MIST.w, MIST.h, vw, vh))) clashes.push(vw + "x" + vh + "+" + inset + " mist " + c); });
  else { const b = vh - 56 - inset - PHONE_MIST.bottom; const m = { left: vw - PHONE_MIST.right - PHONE_MIST.size, right: vw - PHONE_MIST.right, top: b - PHONE_MIST.size, bottom: b };
    if (hit(tb, m)) clashes.push(vw + "x" + vh + "+" + inset + " phone mist"); }
}));
check("S9. at " + VIEWPORTS.length + " sizes, with and without a 34px inset, the tab touches none of the mist's places (the phone's mist at 760 px and less)", clashes.length === 0, clashes.join(", "));
const CHAT_Z = +((/"#tmx-chat \{",[\s\S]*?"  z-index: (\d+);"/.exec(P) || [])[1]);
const ROOT_Z = +((/\n  z-index: (\d+);/.exec(RR) || [])[1]);
check("S9. the tab keeps the desktop's z-index (" + ROOT_Z + ") at every width, the open chat is drawn above it, and the phone's mist (46) below it",
  ROOT_Z === 999990 && CHAT_Z > ROOT_Z && /\n    "    z-index: 46; pointer-events: auto;/.test(P), JSON.stringify([ROOT_Z, CHAT_Z]));

console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check crashed: " + (e && e.stack || e)); process.exit(1); });
