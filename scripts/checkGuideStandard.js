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
     S8  phones: a <button> "Guide" with aria-label, aria-haspopup,
         aria-controls and aria-expanded; a role="dialog" sheet with
         aria-modal and aria-labelledby, holding the same tips; it opens on
         the button, moves focus into the sheet, keeps Tab there, and closes
         on Close, a tap on the backdrop, Escape and a 60px downward swipe
         (not a 30px one), handing focus back to the button; the CSS shows the
         button and hides the panel at 860px and less, and nowhere else;
     S9  the button's computed box, at nine phone and tablet sizes with and
         without a 34px safe-area inset, touches none of the mist's four
         default corners (MIST_CORNERS in termaximus-presence.js) or their chat
         panels; its z-index is below every modal overlay on every page; and a
         mist dragged onto it moves it to the bottom-right (placeFab, run in
         jsdom with measured boxes stubbed).

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
  "sixth-tip": [[GUIDE, '      "To delegate new work, open \\"Agent Hub\\" or \\"Full Directory\\"; each lists all 18 agents."\n',
    '      "To delegate new work, open \\"Agent Hub\\" or \\"Full Directory\\"; each lists all 18 agents.",\n      "Check back after each task finishes."\n']],
  // a 200-character tip (S1)
  "long-tip": [[GUIDE, '"Press \\"Download my data\\" for a copy of everything BizForce stores about you."',
    '"Press \\"Download my data\\" for a copy of everything BizForce stores about you, which arrives as one file holding your profile, your runs, your wallet history, your listings and your messages, all of it."']],
  // a tip naming a button that does not exist (S2)
  "ghost-button": [[GUIDE, 'press \\"Draft the framework\\"', 'press \\"Draft the term sheet\\"']],
  // a sentence another entry already has (S4)
  "duplicate-sentence": [[GUIDE, '"Lost in another month? Press \\"Today\\" to come back."',
    '"Name or industry wrong? Press \\"Expand Profile\\" and edit it; every agent reads this profile."']],
  // a page loads the guide and has no entry (S6)
  "page-without-entry": [["contact.html", "</body>", GUIDE_TAG + "\n</body>"]],
  // the phone button is never added to the page (S8)
  "mobile-button-removed": [[GUIDE, "  document.body.appendChild(fab);\n", ""]],
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
  // the button is moved up into the mist's bottom-left corner (S9)
  "fab-over-mist": [[GUIDE, '    "  bottom: calc(16px + env(safe-area-inset-bottom, 0px));",\n    "  width: 88px;",', '    "  bottom: calc(130px + env(safe-area-inset-bottom, 0px));",\n    "  width: 88px;",']],
  // the button is raised over every modal overlay (S9)
  "fab-over-modals": [[GUIDE, '    "  z-index: 40;",\n    "  align-items: center;",', '    "  z-index: 999990;",\n    "  align-items: center;",']],
  // the sheet loses its dialog role (S8)
  "sheet-not-dialog": [[GUIDE, '  sheet.setAttribute("role", "dialog");\n', ""]],
  // closing the sheet leaves focus where it was (S8)
  "focus-not-returned": [[GUIDE, "    if (next) sheetClose.focus();\n    else fab.focus();\n", "    if (next) sheetClose.focus();\n"]],
  // a swipe no longer closes the sheet (S8)
  "swipe-ignored": [[GUIDE, "    if (dy >= 60) setSheet(false);\n", "    if (dy >= 6000) setSheet(false);\n"]],
  // the button shows on desktops too (S8)
  "fab-on-desktop": [[GUIDE, '    "#tmx-guide-fab {",\n    "  display: none;",', '    "#tmx-guide-fab {",\n    "  display: inline-flex;",']],
  // a dragged mist no longer moves the button aside (S9)
  "fab-never-moves": [[GUIDE, "    if (touching) fab.classList.add(\"tmx-guide-fab--right\");\n", ""]]
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
check("S7. the guide displays on 57 pages now: 46 loaded it before (app.html among them, where it never displays), plus the 11, plus support.html",
  SHOWN.length === 57 && HTML_PAGES.filter(loadsGuide).length === 58, SHOWN.length + " shown, " + HTML_PAGES.filter(loadsGuide).length + " loading");

/* ── S8. phones: the button and the sheet ───────────────────────────────── */
console.log("\n══ S8. phones: the Guide button and the bottom sheet ══");
const CSS = (() => {
  const i = G.indexOf("  style.textContent = ["), j = G.indexOf('  ].join("\\n");', i);
  try { return vm.runInNewContext(G.slice(i + "  style.textContent = ".length, j + 3)).join("\n"); } catch (e) { return ""; }
})();
const rule = sel => { const i = CSS.indexOf("\n" + sel + " {"); return i === -1 ? "" : CSS.slice(i, CSS.indexOf("\n}", i)); };
const media = (() => { const i = CSS.indexOf("@media (max-width: 860px) {"); return i === -1 ? "" : CSS.slice(i, CSS.indexOf("\n}", i)); })();
check("S8. the CSS was read", CSS.length > 2000 && !!rule("#tmx-guide-fab"), CSS.length);
check("S8. the button is hidden by default and shown only at 860px and less, where the panel is hidden",
  /\n  display: none;/.test(rule("#tmx-guide-fab")) && /#tmx-guide-root \{ display: none; \}/.test(media) && /#tmx-guide-fab \{ display: inline-flex; \}/.test(media) &&
  (CSS.match(/#tmx-guide-fab \{ display: inline-flex; \}/g) || []).length === 1 && (CSS.match(/@media/g) || []).length === 1, media);
const D = RENDERED["dashboard.html"];
const dd = D.doc, fab = dd.getElementById("tmx-guide-fab"), sheet = dd.getElementById("tmx-guide-sheet"), backdrop = dd.getElementById("tmx-guide-sheet-backdrop");
const closeBtn = dd.getElementById("tmx-guide-sheet-close");
check("S8. the button exists: a <button type=button> reading \"Guide\", with aria-label, aria-haspopup=dialog, aria-controls=tmx-guide-sheet and aria-expanded=false",
  !!fab && fab.tagName === "BUTTON" && fab.type === "button" && fab.textContent === "Guide" && /Termaximus Guide/.test(fab.getAttribute("aria-label") || "") &&
  fab.getAttribute("aria-haspopup") === "dialog" && fab.getAttribute("aria-controls") === "tmx-guide-sheet" && fab.getAttribute("aria-expanded") === "false");
check("S8. the sheet exists, closed: role=dialog, aria-modal=true, aria-labelledby naming its title, hidden with its backdrop",
  !!sheet && sheet.getAttribute("role") === "dialog" && sheet.getAttribute("aria-modal") === "true" &&
  !!dd.getElementById(sheet.getAttribute("aria-labelledby") || "x") && sheet.hidden === true && !!backdrop && backdrop.hidden === true);
check("S8. the sheet holds the same tips as the panel, on every page", SHOWN.every(f => JSON.stringify(listOf(RENDERED[f].doc, "#tmx-guide-sheet")) === JSON.stringify(listOf(RENDERED[f].doc, "#tmx-guide-panel")) &&
  RENDERED[f].doc.querySelectorAll("#tmx-guide-sheet [data-tmx-guide-common]").length === RENDERED[f].doc.querySelectorAll("#tmx-guide-panel [data-tmx-guide-common]").length),
  SHOWN.filter(f => JSON.stringify(listOf(RENDERED[f].doc, "#tmx-guide-sheet")) !== JSON.stringify(listOf(RENDERED[f].doc, "#tmx-guide-panel"))).join(", "));
check("S8. the close control is a labelled button inside the sheet", !!closeBtn && closeBtn.tagName === "BUTTON" && sheet.contains(closeBtn) && !!closeBtn.getAttribute("aria-label"));
const W = D.w;
const key = (el, k) => el.dispatchEvent(new W.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));
function touch(el, type, y) {
  const ev = new W.Event(type, { bubbles: true, cancelable: true });
  const pt = [{ clientY: y }];
  Object.defineProperty(ev, type === "touchend" ? "changedTouches" : "touches", { value: pt });
  if (type === "touchend") Object.defineProperty(ev, "touches", { value: [] });
  el.dispatchEvent(ev);
}
const isOpen = () => sheet && sheet.hidden === false && backdrop.hidden === false && fab.getAttribute("aria-expanded") === "true" &&
  dd.documentElement.classList.contains("tmx-guide-sheet-open");
const isClosed = () => sheet && sheet.hidden === true && backdrop.hidden === true && fab.getAttribute("aria-expanded") === "false" &&
  !dd.documentElement.classList.contains("tmx-guide-sheet-open");
const steps = [];
if (fab && sheet && closeBtn) {
  fab.focus(); fab.click();
  steps.push(["opens on the button, focus moves into the sheet", isOpen() && dd.activeElement === closeBtn]);
  key(closeBtn, "Tab");
  steps.push(["Tab keeps focus in the sheet", isOpen() && dd.activeElement === closeBtn]);
  key(closeBtn, "Escape");
  steps.push(["Escape closes it, focus back on the button", isClosed() && dd.activeElement === fab]);
  fab.click(); closeBtn.click();
  steps.push(["Close closes it, focus back on the button", isClosed() && dd.activeElement === fab]);
  fab.click(); backdrop.click();
  steps.push(["a tap on the backdrop closes it, focus back on the button", isClosed() && dd.activeElement === fab]);
  const head = sheet.querySelector(".tmx-guide-sheet-head");
  fab.click(); touch(head, "touchstart", 300); touch(head, "touchmove", 330); touch(head, "touchend", 330);
  steps.push(["a 30px swipe springs back and leaves it open", isOpen() && sheet.style.transform === ""]);
  touch(head, "touchstart", 300); touch(head, "touchmove", 380); touch(head, "touchend", 380);
  steps.push(["a 80px downward swipe closes it, focus back on the button", isClosed() && dd.activeElement === fab]);
}
check("S8. the sheet runs: " + steps.map(x => x[0]).join("; "), steps.length === 7 && steps.every(x => x[1]), steps.filter(x => !x[1]).map(x => x[0]).join(" | "));
check("S8. the sheet makes no request: the Insights section is only in the desktop panel", !!sheet && !sheet.querySelector("#tmx-guide-insight-text") && !!dd.querySelector("#tmx-guide-panel #tmx-guide-insight-text"));
check("S8. while the sheet is open, the mist and its chat are hidden (their z-index is above the sheet's)",
  /html\.tmx-guide-sheet-open #tmx-presence-root, html\.tmx-guide-sheet-open #tmx-chat, html\.tmx-guide-sheet-open #tmx-chat-glow-wrap \{\n  visibility: hidden !important;/.test(CSS));
const fabMissing = SHOWN.filter(f => !RENDERED[f].doc.getElementById("tmx-guide-fab") || !RENDERED[f].doc.getElementById("tmx-guide-sheet"));
check("S8. every page that shows the guide gets the button and the sheet", fabMissing.length === 0, fabMissing.join(", "));

/* ── S9. the button clears the mist and every page control ──────────────── */
console.log("\n══ S9. the button's box clears the mist, its chat, and every modal ══");
const px = (r, prop) => { const m = new RegExp("\\n  " + prop + ": (?:calc\\()?(\\d+)px").exec(r); return m ? +m[1] : null; };
const FR = rule("#tmx-guide-fab");
const FAB = { left: px(FR, "left"), bottom: px(FR, "bottom"), width: px(FR, "width"), height: px(FR, "height"),
  safeArea: /\n  bottom: calc\(\d+px \+ env\(safe-area-inset-bottom, 0px\)\);/.test(FR) };
check("S9. the button's box was read: left 16, bottom 16 (plus the safe-area inset), 88 × 44",
  FAB.left === 16 && FAB.bottom === 16 && FAB.width === 88 && FAB.height === 44 && FAB.safeArea, JSON.stringify(FAB));
const P = FILES[PRESENCE];
const CORNERS = (() => {
  const m = /var MIST_CORNERS = (\{[\s\S]*?\n  \});/.exec(P);
  try { return m ? vm.runInNewContext("(" + m[1] + ")") : {}; } catch (e) { return {}; }
})();
const MIST = { w: +((/#tmx-presence-root \{[\s\S]*?width: (\d+)px;/.exec(P) || [])[1]), h: +((/#tmx-presence-root \{[\s\S]*?height: (\d+)px;/.exec(P) || [])[1]) };
const CHAT = { w: 288, h: +((/"#tmx-chat \{",[\s\S]*?"  height: (\d+)px;"/.exec(P) || [])[1]) };
check("S9. the mist's four corners and its size were read from termaximus-presence.js (110 × 110; the chat 288 wide, 340 tall)",
  Object.keys(CORNERS).sort().join(",") === "bottom-left,bottom-right,top-left,top-right" && MIST.w === 110 && MIST.h === 110 && CHAT.h === 340 &&
  /width: min\(288px, calc\(100vw - 16px\)\);/.test(P), JSON.stringify([Object.keys(CORNERS), MIST, CHAT]));
function boxFrom(spec, w, h, vw, vh) {
  const v = k => { const m = new RegExp("\\b" + k + ":\\s*(\\d+)px").exec(spec); return m ? +m[1] : null; };
  const left = v("left") !== null ? v("left") : vw - v("right") - w;
  const top = v("top") !== null ? v("top") : vh - v("bottom") - h;
  return { left, top, right: left + w, bottom: top + h };
}
const hit = (a, b) => a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;
const VIEWPORTS = [[320, 568], [360, 640], [375, 667], [390, 844], [393, 873], [412, 915], [414, 896], [768, 1024], [860, 1180]];
const clashes = [], chatOver = [];
VIEWPORTS.forEach(([vw, vh]) => [0, 34].forEach(inset => {
  const f = { left: FAB.left, right: FAB.left + FAB.width, top: vh - FAB.bottom - inset - FAB.height, bottom: vh - FAB.bottom - inset };
  Object.keys(CORNERS).forEach(c => {
    const mist = boxFrom(CORNERS[c].root, MIST.w, MIST.h, vw, vh), chat = boxFrom(CORNERS[c].chat, Math.min(CHAT.w, vw - 16), CHAT.h, vw, vh);
    if (hit(f, mist)) clashes.push(vw + "x" + vh + "+" + inset + " mist " + c);
    if (hit(f, chat)) chatOver.push(vw + "x" + vh + "+" + inset + " " + c);
  });
}));
check("S9. at " + VIEWPORTS.length + " sizes, with and without a 34px inset, the button touches none of the mist's four default corners",
  Object.keys(CORNERS).length === 4 && clashes.length === 0, clashes.join(", "));
// The mist's chat panel, once opened, reaches down to the button on short screens (the top corners). It is drawn above
// the button, so it covers it while open and the button never sits on the chat.
const CHAT_Z = +((/"#tmx-chat \{",[\s\S]*?"  z-index: (\d+);"/.exec(P) || [])[1]);
check("S9. where the open chat panel reaches the button (" + chatOver.length + " of " + VIEWPORTS.length * 2 * 4 + " size and corner cases), the chat is drawn above it",
  CHAT_Z > 40 * 1000 && chatOver.every(c => /top-/.test(c)), CHAT_Z + " " + chatOver.filter(c => !/top-/.test(c)).join(", "));
const zOf = r => +((/\n  z-index: (\d+);/.exec(r) || [])[1]);
const FAB_Z = zOf(FR);
const OVERLAY_Z = [];
HTML_PAGES.forEach(f => {
  const re = /\.(?:modal-overlay|pf-overlay|bp-modal-overlay|quiz-overlay|pf-custom-panel)\s*\{[^}]*?z-index:\s*(\d+)/g; let m;
  while ((m = re.exec(FILES[f]))) OVERLAY_Z.push([f, +m[1]]);
});
const TERMS_Z = +((/\.bf-terms-notice\{[^}]*?z-index:(\d+)/.exec(FILES["scripts/bf-legal-footer.js"] || "") || [])[1]);
check("S9. the button's z-index (40) is below every page's modal overlays and customize panel (" + OVERLAY_Z.length + " read) and the terms notice",
  FAB_Z === 40 && OVERLAY_Z.length >= 8 && OVERLAY_Z.every(([, z]) => z > FAB_Z) && TERMS_Z > FAB_Z,
  FAB_Z + " vs " + OVERLAY_Z.filter(([, z]) => !(z > FAB_Z)).map(x => x.join("=")).join(", ") + " terms " + TERMS_Z);
// placeFab, run: a mist on the button moves it right; a mist elsewhere leaves it left.
function placed(mistBox) {
  const r = render("dashboard.html", { before: w => {
    const m = w.document.createElement("div"); m.id = "tmx-presence-root"; w.document.body.appendChild(m);
    const orig = w.HTMLElement.prototype.getBoundingClientRect;
    w.HTMLElement.prototype.getBoundingClientRect = function () {
      if (this.id === "tmx-guide-fab") return { left: 16, right: 104, top: 607, bottom: 651, width: 88, height: 44 };
      if (this.id === "tmx-presence-root") return mistBox;
      return orig.call(this);
    };
  } });
  return r.error ? "error " + r.error : r.doc.getElementById("tmx-guide-fab").className;
}
const onIt = placed({ left: 30, right: 140, top: 580, bottom: 690, width: 110, height: 110 });
const away = placed({ left: 85, right: 195, top: 200, bottom: 310, width: 110, height: 110 });
check("S9. a mist dragged onto the button moves it to the bottom-right; one elsewhere leaves it bottom-left",
  onIt === "tmx-guide-fab--right" && away === "", JSON.stringify([onIt, away]));
check("S9. the bottom-right placement keeps the same 16px inset", /#tmx-guide-fab\.tmx-guide-fab--right \{\n  left: auto;\n  right: 16px;/.test(CSS));

console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
process.exit(failures ? 1 : 0);
