"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkAppShell.js — P2-1 (Nov 19 2026): the phone app shell.

     B  scripts/bf-tabbar.js run in jsdom: where the bar shows and where it
        does not (the brief's list), its five items, the active tab, the
        Inbox badge; a page it is not on is left exactly as it was
     L  layout: phone only (every bar rule inside max-width 760px), 56 px plus
        the safe area, above the page and below dialogs, the music player's
        sheet and the Guide's panel; the Guide button 56 px higher and its
        spacer 136 px; the page's end (the legal footer) above the spacer;
        every target 44 px
     C  the Create sheet: Post and Video "Coming soon" and inert; the other six
        open their real creators; a dialog with Escape and a focus trap;
        nothing created. The creators read ?create, and a listing's kind
        reaches POST /api/marketplace/listings.
     J  bf-session.js loads the bar on signed-in pages
     W  sw.js: SHELL_REV "p21" (P2-2 made it "p22"), the new scripts and pages in the offline shell
     U  what P2-1 must not change: the Oracle pages, the music player, the
        Layered Stack logo, HQ1's dashboard views, the phone stylesheet, every
        font (as at the frontend's 1803344); NAMED (Nov 21 2026, FX2): bf-hq-views.js
        (the Sun), bf-orbit.js (the first settle) and dashboard.html (the Sun's
        look) differ by FX2's own hunks alone, listed in checkAppShell.fx2.json
        ([file, now, before]); with each undone, exactly once, each is still the
        old file byte for byte

   It also prints the show and hide list as built (SHOWN / HIDDEN lines).

   Run: node scripts/checkAppShell.js      MUTATE=<name> | all
   Nothing here touches the live database or the network.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const H = require("./_p21Harness");

const P20_COMMIT = "1803344";   // the frontend before P2-1
// NAMED (Nov 21 2026, FX2): FX2's hunks in three of the unchanged files, [file, now, before] (U1)
const FX2_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.fx2.json"), "utf8"));
// NAMED (Nov 22 2026, FX3 part D): the dashboard's five agent icons now drawn from scripts/bf-agent-marks.js, and its
// tag, [file, now, before] (U1); checkAgentMarks proves each icon is exactly as it was
const FX3D_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.fx3d.json"), "utf8"));
// NAMED (Nov 22 2026, FX3): FX3's own hunks in five of the unchanged files (the abyss sun in bf-hq-views.js and dashboard.html,
// the drift clock in bf-orbit.js, the book button's rules gone from css/bf-phone.css and termaximus-guide.js, the Guide on the
// phone), [file, now, before] (U1); undone after part D's, they return each file to frontend e3e8ce0 exactly
const FX3_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.fx3.json"), "utf8"));
// NAMED (Nov 22 2026, FX3B): FX3B's hunks in two of the unchanged files (bf-orbit.js: the first portal's boxes built before
// the settle and the drift's longer lead; css/bizforce-ui.css: the five unused agent icon rules removed), [file, now, before]
// (U1); undone first, they return each file to frontend d3b1f6f exactly
// NAMED (Nov 23 2026, LR-1): Mastodon lead search is removed, so two sentences lost "Mastodon": the dashboard's Lead Radar card and the Guide's
// Lead Radar switches tip. Each pair is [file, now, was]; undone first (it is the newest), each found exactly once.
const LR1_SWAPS = [
  ["dashboard.html", "  <p>Buying-intent posts from Bluesky, scored and ranked. Runs on a single social account and is enabled only for the account that owns it.</p>",
    "  <p>Buying-intent posts from Bluesky, and Mastodon when switched on, scored and ranked. Runs on a single social account and is enabled only for the account that owns it.</p>"],
  ["scripts/termaximus-guide.js", "\"New Bluesky finds arrive every 5 minutes; YouTube and scoring each wait on their own switch. Press \\\"Refresh\\\" to load.\",",
    "\"New Bluesky finds arrive every 5 minutes; Mastodon, YouTube and scoring each wait on their own switch. Press \\\"Refresh\\\" to load.\","]
];
const FX3B_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.fx3b.json"), "utf8"));
// NAMED (Nov 23 2026, LR-2): Lead Radar for every member: the dashboard's Lead Radar card (its sentence, and the box's new-lead count
// read from GET /api/leads/summary by a member) and the Guide's Lead Radar and Sales tips. [file, now, was]; undone before LR-1's
// (they are the newest), each found exactly once, they return both files to frontend 968b529 exactly.
const LR2_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.lr2.json"), "utf8"));
// NAMED (Nov 25 2026, HOTFIX-G1): BEFORE LR-3B's two hunks in termaximus-guide.js (the Guide's 40 px of left room on the phone:
// its CSS rule and the class that turned it on, checkAppShell.lr3b.json) were undone here. HOTFIX-G1 removed that room (it
// shifted every phone page 40 px right), so the Guide is again byte for byte as at frontend f73aec1, and the hunk file is gone.
// AFTER, HOTFIX-G1's own hunk in css/bf-phone.css (one rule per control the Guide's tab covered, inside the file's one
// @media (max-width: 760px) block). [file, now, was]; undone before all the others (it is the newest), found exactly once, it
// returns bf-phone.css to frontend 63e9b7a (and f73aec1) exactly.
const G1_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.g1.json"), "utf8"));
// NAMED (Nov 26 2026, FX4A): the owner asked for the Oracle pages to be fixed on phones, so oracle.html, mychart.html and
// calendar.html change, with dashboard.html (AI Agent Tasks on a phone) and css/bf-phone.css (the boombox's controls out of
// the 44 px rule; the Oracle chat row and sync card). FX4A's hunks: [file, now, was]; undone before all the others (they are
// the newest), each found exactly once, they return the five files to frontend 44daec4 exactly (checkHqViews U1 reads them too).
const FX4A_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.fx4a.json"), "utf8"));
// NAMED (Nov 26 2026, FX4M): the owner chose that music carries on across pages and stops on Home, and the Guide tab on the
// Inbox, so scripts/bf-music.js (16 hunks), scripts/termaximus-guide.js (the Inbox's tips, 1 hunk) and css/bf-phone.css (the
// Inbox's four controls cleared from under the tab, 1 hunk) change. FX4M's hunks: [file, now, was]; undone before all the
// others (they are the newest), each found exactly once, they return the three files to frontend 53becf5 exactly.
const FX4M_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.fx4m.json"), "utf8"));
// NAMED (Nov 26 2026, FX4S): the phone music library trap freed, so scripts/bf-boombox.js changes (2 hunks: the phone drawer only in
// the open boombox, and the library not reopened at a phone launch). FX4S's hunks: [file, now, was]; undone before all the others
// (they are the newest), each found exactly once, they return the file to frontend c62c1d3 exactly.
const FX4S_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.fx4s.json"), "utf8"));
// NAMED (Nov 26 2026, FX4B): My Chart fits the phone (mychart.html, 6 hunks), the Oracle's Profile and Celestial panels solid on
// a phone (oracle.html, 1 hunk), and in FX4B2 the chart's pinch, double-tap zoom and pan on a phone (mychart.html). FX4B's hunks:
// [file, now, was]; undone before all the others (they are the newest), each found exactly once, they return the two files to
// frontend 5708bfb exactly.
const FX4B_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.fx4b.json"), "utf8"));
// NAMED (Nov 27 2026, FX4B4): My Chart opens on the whole chart on a phone, and the sigil card's heading is "Your Sigil"
// (mychart.html, 9 hunks, [file, now, was]); undone before FX4B's (they are the newest), each found exactly once, they
// return mychart.html to frontend d3e0f57 exactly.
const FX4B4_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.fx4b4.json"), "utf8"));
// NAMED (Nov 25 2026, LR-4): music-popout.html scrolled sideways on a phone (401 px at 360; LR-4 PART E asks for none): its
// boombox is drawn smaller on a phone (a rule inside @media (max-width: 760px) and the script that sets its scale). [file, now,
// was]; undone before LR-3B's (they are the newest), each found exactly once, they return music-popout.html to frontend 5f560dd
// exactly, so the player and its button icon stay byte for byte as at 1803344.
const LR4_SWAPS = JSON.parse(fs.readFileSync(path.join(__dirname, "checkAppShell.lr4.json"), "utf8"));
const PRESENCE = "scripts/termaximus-presence.js", GUIDE = "scripts/termaximus-guide.js";
// NAMED (Nov 20 2026, P2-2): the only lines P2-2 added to dashboard.html (see U1).
const P22_DASH_LINES = [
  "<!-- P2-2: the owner alone sees the moderation queue's waiting count here, only when above 0 (scripts/bf-safety.js ownerCount) -->",
  "<p class=\"owner-moderation\" id=\"ownerModeration\" hidden style=\"text-align:center;margin:0 0 12px\"></p>",
  "<script src=\"/scripts/bf-safety.js\"></script>",
  "<script>if (window.BFSafety) window.BFSafety.ownerCount(document.getElementById(\"ownerModeration\"));</script>"
];
const BAR = "scripts/bf-tabbar.js", SESSION = "scripts/bf-session.js", SW = "sw.js", SERVER = "@server.js";
const MARKET = "marketplace.html", GARAGE = "garage-sale.html", CAMPAIGNS = "campaigns.html";
const UNCHANGED = ["oracle.html", "mychart.html", "calendar.html", "synastry.html", "the-third.html", "scripts/bf-music.js", "scripts/bf-marks.js",
  "scripts/bf-hq-views.js", "scripts/bf-orbit.js", "dashboard.html", "css/bf-phone.css", "css/bizforce-ui.css", "scripts/termaximus-guide.js", "music-popout.html"];

const MUTATIONS = {
  // NAMED (Nov 25 2026, HOTFIX-G1): the Guide's page-wide 40 px room put back, and HOTFIX-G1's bf-phone.css hunk changed
  "g1-room-back": [["scripts/termaximus-guide.js", "    \"  #tmx-guide-tab { min-width: 32px; }\",\n", "    \"  #tmx-guide-tab { min-width: 32px; }\",\n    \"  html.tmx-guide-room body { padding-left: 40px !important; }\",\n"]],
  // NAMED (Nov 26 2026, FX4A): an Oracle page changed outside FX4A's hunks (calendar.html's phone rule widened)
  "fx4a-hunk-changed": [["calendar.html", "      .cal-nav-row > .cal-agent-runs-btn { max-width: 66px; }\n", "      .cal-nav-row > .cal-agent-runs-btn { max-width: 96px; }\n"]],
  // NAMED (Nov 26 2026, FX4A): synastry.html, not one of FX4A's pages, edited
  "fx4a-synastry-edited": [["synastry.html", "</head>", "<!-- x --></head>"]],
  "g1-hunk-changed": [["css/bf-phone.css", "  #toggleAiMailbox { margin-left: 16px; }\n", "  #toggleAiMailbox { margin-left: 18px; }\n"]],
  // NAMED (Nov 25 2026, LR-4): music-popout.html changed outside LR-4's two hunks (the music script), and a hunk no longer found
  "lr4-popout-player-changed": [["music-popout.html", "<script src=\"/scripts/bf-music.js\"></script>\n<script>\n", "<script src=\"/scripts/bf-music.js?v=2\"></script>\n<script>\n"]],
  "lr4-popout-hunk-changed": [["music-popout.html", "transform-origin:top center;", "transform-origin:center;"]],
  "shown-on-oracle": [[BAR, "    \"oracle.html\", \"mychart.html\", \"calendar.html\", \"synastry.html\", \"the-third.html\"\n", "    \"mychart.html\", \"calendar.html\", \"synastry.html\", \"the-third.html\"\n"]],
  "shown-on-legal": [[BAR, "    \"terms.html\", \"privacy.html\", \"refund.html\", \"contact.html\",\n", "    \"terms.html\", \"refund.html\", \"contact.html\",\n"]],
  "shown-on-campaign-link": [[BAR, "\"/campaign/\", \"/c/\", ", "\"/c/\", "]],
  "ignores-page-off": [[BAR, "    if (document.documentElement.getAttribute(\"data-bf-tabbar\") === \"off\") return false;\n", ""]],
  "shown-signed-out": [[BAR, "    if (!token()) return false;\n    if (HIDDEN_PAGES", "    if (HIDDEN_PAGES"]],
  "wrong-active": [[BAR, "\"profile.html\": \"profile\", \"settings.html\": \"profile\"", "\"profile.html\": \"profile\", \"settings.html\": \"hq\""]],
  "four-tabs": [[BAR, "    { key: \"home\", label: \"Home\", href: \"/home.html\" },\n", ""]],
  "bar-on-desktop": [[BAR, "    \"#bf-tabbar,#bf-tabbar-spacer{display:none}\",\n", "    \"#bf-tabbar{display:flex}\",\n"]],
  "bar-over-dialogs": [[BAR, "align-items:stretch;background:rgba(7,11,24,.97);", "align-items:stretch;z-index:2147483646;background:rgba(7,11,24,.97);"]],
  // NAMED (Nov 22 2026, FX3): BEFORE "guide-not-raised" and "guide-spacer-short" (the book button's lift and its spacer, both gone).
  // AFTER the bar lifts nothing for a button, the mist sits 16 px above the bar, under it in the stack, and the Guide's tab over it
  "book-button-lift-back": [[BAR, "    \"html.bf-tabbar-on #bf-tabbar-spacer{display:block;", "    \"html.bf-tabbar-on #tmx-guide-fab{bottom:calc(56px + 16px + env(safe-area-inset-bottom, 0px))}\",\n    \"html.bf-tabbar-on #bf-tabbar-spacer{display:block;"]],
  "mist-on-the-bar": [[PRESENCE, "  html.bf-tabbar-on #tmx-presence-root { bottom: calc(56px + 16px + env(safe-area-inset-bottom, 0px)) !important; }", "  html.bf-tabbar-on #tmx-presence-root { bottom: calc(16px + env(safe-area-inset-bottom, 0px)) !important; }"]],
  "mist-over-bar": [[PRESENCE, "    z-index: 46; pointer-events: auto;", "    z-index: 95; pointer-events: auto;"]],
  "guide-under-bar": [[GUIDE, "    \"  z-index: 999990;\",", "    \"  z-index: 80;\","]],
  "no-safe-area": [[BAR, "html.bf-tabbar-on #bf-tabbar-spacer{display:block;height:calc(56px + env(safe-area-inset-bottom, 0px))}", "html.bf-tabbar-on #bf-tabbar-spacer{display:block;height:56px}"]],
  "small-tabs": [[BAR, "#bf-tabbar .bf-tab{flex:1 1 0;min-width:44px;min-height:44px;", "#bf-tabbar .bf-tab{flex:1 1 0;min-width:44px;min-height:30px;"]],
  "styles-everywhere": [[BAR, "    if (!wanted()) return;   // a page the bar is not on", "    addStyle();\n    if (!wanted()) return;   // a page the bar is not on"]],
  "badge-on-zero": [[BAR, "    badge.hidden = count === 0;", "    badge.hidden = false;"]],
  // NAMED (Nov 20 2026, FX1): BEFORE the anchor was Post's "soon: true," P2-3 removed (a MUTATION ANCHOR ERROR since); AFTER
  // Post's own address, the composer, sent elsewhere (C opts pins "post:/compose.html")
  "post-not-soon": [[BAR, "{ key: \"post\", title: \"Post\", sub: \"Photo or text to your followers\", href: \"/compose.html\",", "{ key: \"post\", title: \"Post\", sub: \"Photo or text to your followers\", href: \"/run.html\","]],
  "service-wrong-kind": [[BAR, "href: \"/marketplace.html?create=service\"", "href: \"/marketplace.html?create=product\""]],
  "no-escape": [[BAR, "      if (e.key === \"Escape\") { e.preventDefault(); closeCreate(); return; }\n", ""]],
  "not-a-dialog": [[BAR, "    sheet.setAttribute(\"role\", \"dialog\");\n", ""]],
  "session-no-bar": [[SESSION, "  function loadMusicPlayer() {\n    loadTabBar();\n", "  function loadMusicPlayer() {\n"]],
  "market-kind-dropped": [[MARKET, "    if (!editingId && createKind) body.listing_kind = createKind;\n", ""]],
  "server-kind-ignored": [[SERVER, "      seller_id: req.user.id, title, description: description || \"\", listing_kind: listingKind,", "      seller_id: req.user.id, title, description: description || \"\","]],
  "server-kind-unchecked": [[SERVER, "    if (listingKind !== \"product\" && listingKind !== \"service\") return res.status(400)", "    if (false) return res.status(400)"]],
  "garage-no-create": [[GARAGE, "if (new URLSearchParams(window.location.search).get(\"create\") === \"item\") {", "if (false) {"]],
  "campaign-no-create": [[CAMPAIGNS, "if (new URLSearchParams(window.location.search).get(\"create\") === \"campaign\") {", "if (false) {"]],
  // NAMED (Nov 20 2026, P2-2): BEFORE "p21". AFTER "p22": the report, block and mute menu (bf-safety.js), moderation.html and copyright.html in the shell.
  // NAMED (Nov 20 2026, P2-3): BEFORE "p22". AFTER "p23": posts, the Following feed, Talk and follows (bf-feed.js, bf-composer.js) and compose.html in the shell.
  // NAMED (Nov 20 2026, FX1): BEFORE "p23". AFTER "fx1": Home's feed and the Profile as the approved design pictures.
  // NAMED (Nov 20 2026, P3-1): BEFORE "fx1". AFTER "p31": free accounts (the members panel, the verification banner, landing by tier).
  // NAMED (Nov 21 2026, P3-2): BEFORE "p31". AFTER "p32": the Verified badge (bf-verified.js), and the members panel on media and business ID.
  // NAMED (Nov 21 2026, FX2): BEFORE "p32". AFTER "fx2": the feed's Tip and product strip, the Profile's banner, the Agent Directory's views (bf-agents-views.js) and the Oracle's Sun.
  // NAMED (Nov 21 2026, P3-1B): BEFORE "fx2". AFTER "p31b": the free-account rules (bf-access.js Buy sheet and members intercepts, the Create sheet's Members tags, the composer's photo rule and Show in Google, Talk's members box).
  // NAMED (Nov 21 2026, P3-1C): BEFORE SHELL_REV "p31b". AFTER "p31c" (the wallet's member-welcome sentence and ledger labels).
  // NAMED (Nov 22 2026, FX3): BEFORE SHELL_REV "p31c". AFTER "fx3" (the abyss sun, Termaximus on the phone, the agent cards).
  // NAMED (Nov 23 2026, LR-1): BEFORE "p33"; AFTER "lr1" (approve each reply before it posts, the Lead Radar sign-in prompt, tidy-ups). sw.js now carries its note on the SHELL_REV line, so the line may end in a // comment.
  // NAMED (Nov 27 2026, FX4B4): BEFORE "fx4b"; AFTER "fx4b4" (My Chart on phones opens on the whole chart, double-tap or pinch to zoom in; the sigil card's heading Your Sigil). FX4B: BEFORE "fx4s"; AFTER "fx4b" (My Chart on phones opens with the Divine Triangle filling the width, drag, double-tap and pinch to see every house; the Oracle's Profile and Celestial panels solid on phones). FX4S: BEFORE "fx4m"; AFTER "fx4s" (the phone music library shows only in the open boombox and is not reopened at a phone launch). FX4M: BEFORE "fx4a"; AFTER "fx4m" (music carries on across pages and stops on Home; the Guide tab on the Inbox). FX4A: BEFORE "h1b"; AFTER "fx4a" (the boombox, AI Agent Tasks, the Oracle pages and the calendar on phones). H1B: BEFORE "h1"; AFTER "h1b" (no mist on Home or the composer; room under the mist at the end of card-view and proposals). H1: BEFORE "g1"; AFTER "h1" (the home tabs, Search and the storefront badge). HOTFIX-G1: BEFORE "lr4b"; AFTER "g1" (phone layouts restored; only the controls under the Guide tab moved). LR-4B: BEFORE "lr4"; AFTER "lr4b" (the storefront menu draws whichever loads first). LR-4: BEFORE "lr3b"; AFTER "lr4" (Get found). LR-3B: BEFORE "lr3"; AFTER "lr3b" (nothing to tap under the Guide tab on the phone). LR-3: BEFORE "lr2b"; AFTER "lr3" (Inbound, the storefront Message button). LR-2B: BEFORE "lr2"; LR-2: BEFORE "lr1b".
  "sw-old-rev": [[SW, "var SHELL_REV = \"fx4b4\";",   // NAMED (Nov 23 2026, P3-3): BEFORE "fx3b"; AFTER "p33" (Share, Offer or Need, the Need post and I can help, the Market filter). NAMED (Nov 22 2026, FX3B): BEFORE "fx3"; AFTER "fx3b"
    "var SHELL_REV = \"hq1\";"]],
  "sw-no-bar": [[SW, "  \"/scripts/bf-tabbar.js\", \"/scripts/bf-profile-shell.js\", \"/scripts/bf-local-settings.js\",\n", "  \"/scripts/bf-profile-shell.js\", \"/scripts/bf-local-settings.js\",\n"]],
  // NAMED (Nov 20 2026, FX1): BEFORE the anchor had no comma after "inbox.html" (P2-2 added one; a MUTATION ANCHOR ERROR since)
  "sw-no-pages": [[SW, "  \"home.html\", \"inbox.html\",   //", "  //"]],
  "oracle-touched": [["oracle.html", "</body>", "<div id=\"x\"></div></body>"]],
  "music-icon-touched": [["scripts/bf-music.js", "z-index:2147483000;", "z-index:2147483001;"]]
};

const T = H.setup(__filename, MUTATIONS, [BAR, SESSION, SW, SERVER, MARKET, GARAGE, CAMPAIGNS].concat(UNCHANGED));
const { FILES, check, has, J } = T;
let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }
const settle = ms => new Promise(r => setTimeout(r, ms || 20));

/* The brief's list, as written: where the bar must not be. */
const BRIEF_HIDDEN = ["app.html", "reset-password.html", "verify-email.html", "terms.html", "privacy.html", "refund.html", "contact.html",
  "music-popout.html", "card-view.html", "blogpost.html", "blogindex.html", "oracle.html", "mychart.html", "calendar.html", "synastry.html", "the-third.html"];
const BRIEF_PREFIX_PATHS = ["/campaign/abcdefghijklmnop", "/c/acme-hats", "/card/abc", "/support/rose", "/blog/rose", "/blog/rose/first-post", "/listing/wool-hat"];

async function page(pathname, opts) {
  opts = opts || {};
  const html = "<!doctype html><html" + (opts.off ? " data-bf-tabbar=\"off\"" : "") + "><head></head><body><main>Page</main>" +
    (opts.guide ? "<div id=\"tmx-guide-fab\"></div>" : "") + "<footer class=\"bf-legal-footer\"></footer>" + (opts.guide ? "<div id=\"tmx-guide-fab-spacer\"></div>" : "") + "</body></html>";
  const dom = new JSDOM(html, { url: "https://bizforceai.net" + pathname, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  if (opts.signedIn !== false) w.localStorage.setItem("bf_token", "x.eyJpZCI6IjEifQ.y");
  w.matchMedia = q => ({ matches: opts.desktop ? false : /max-width: 760px/.test(q), media: q, addEventListener() {}, removeEventListener() {} });
  const fetched = [];
  w.fetch = (u) => { fetched.push(String(u)); return Promise.resolve({ ok: true, json: () => Promise.resolve({ badge: opts.badge === undefined ? 0 : opts.badge }) }); };
  w.eval(FILES[BAR]);
  if (w.document.readyState === "loading") await new Promise(r => w.document.addEventListener("DOMContentLoaded", r));
  await settle(5);
  return { w, doc: w.document, fetched, bar: () => w.document.getElementById("bf-tabbar") };
}

(async () => {
  /* ══ B ══ */
  console.log("\n══ B. where the bar shows ══");
  const MAP = JSON.parse(fs.readFileSync(path.join(H.REPO, "lib", "appMap.json"), "utf8"));
  const PAGES = Object.keys(MAP.pages).map(k => String(MAP.pages[k].p || "/" + k).replace(/^\//, "")).filter(p => /\.html$/.test(p));
  const wrong = [], shown = [], hidden = [];
  for (const p of PAGES) {
    const t = await page("/" + p);
    const on = !!t.bar();
    const want = BRIEF_HIDDEN.indexOf(p) === -1;
    (on ? shown : hidden).push(p);
    if (on !== want) wrong.push(p + (on ? " shown" : " hidden"));
  }
  for (const p of BRIEF_PREFIX_PATHS) { const on = !!(await page(p)).bar(); (on ? shown : hidden).push(p); if (on) wrong.push(p + " shown"); }
  check("B1. signed in on a phone: the bar is on every page of the app map except the brief's list, and on none of the public addresses (" + PAGES.length + " pages, " + BRIEF_PREFIX_PATHS.length + " addresses)", wrong.length === 0, wrong.join(","));
  check("B2. signed out it is on no page (listing.html and seller.html included)", await (async () => { for (const p of ["/dashboard.html", "/listing.html", "/seller.html", "/home.html", "/marketplace.html"]) if ((await page(p, { signedIn: false })).bar()) return false; return true; })());
  check("B3. a page with data-bf-tabbar=\"off\" has none", !(await page("/dashboard.html", { off: true })).bar());
  const hid = await page("/oracle.html");
  check("B4. a page it is not on is left exactly as it was: no element, no style, no class", !hid.doc.getElementById("bf-tabbar-style") && !hid.doc.getElementById("bf-tabbar-spacer") && !hid.doc.documentElement.classList.contains("bf-tabbar-on"));
  const d = await page("/dashboard.html");
  const items = Array.from(d.bar().children).map(n => n.getAttribute("data-tab") + ":" + (n.getAttribute("href") || n.tagName));
  check("B5. five items: Home, HQ, + (Create), Inbox, Profile", J(items) === J(["home:/home.html", "hq:/dashboard.html", "create:BUTTON", "inbox:/inbox.html", "profile:/profile.html"]), J(items));
  const active = async p => { const a = (await page(p)).doc.querySelector("#bf-tabbar [aria-current=page]"); return a ? a.getAttribute("data-tab") : null; };
  const act = { "/home.html": "home", "/dashboard.html": "hq", "/run.html": "hq", "/marketplace.html": "hq", "/inbox.html": "inbox", "/messages.html": "inbox", "/proposals.html": "inbox", "/profile.html": "profile", "/settings.html": "profile" };
  const actWrong = [];
  for (const p of Object.keys(act)) { const got = await active(p); if (got !== act[p]) actWrong.push(p + "=" + got); }
  check("B6. the active tab: Home on home; Inbox on inbox, messages and proposals; Profile on profile and settings; HQ on the dashboard and the tools", actWrong.length === 0, actWrong.join(","));
  const plus = d.doc.querySelector("#bf-tabbar [data-tab=create]");
  check("B7. + is a button that opens a dialog, labelled Create", plus.getAttribute("aria-label") === "Create" && plus.getAttribute("aria-haspopup") === "dialog");
  const b3 = await page("/dashboard.html", { badge: 3 }); await settle();
  const badge = b3.doc.querySelector("#bf-tabbar .bf-tab-badge");
  check("B8. the Inbox badge: the unread count from /api/inbox/counts, said in the link's name", !badge.hidden && badge.textContent === "3" && badge.parentNode.getAttribute("aria-label") === "Inbox, 3 unread" && /\/api\/inbox\/counts$/.test(b3.fetched[0] || ""), J(b3.fetched));
  b3.w.BFTabbar.setBadge(0);
  const zero = badge.hidden;
  b3.w.BFTabbar.setBadge(150);
  check("B9. no badge at zero; over 99 it reads 99+", zero === true && badge.textContent === "99+" && !badge.hidden);
  const desk = await page("/dashboard.html", { desktop: true }); await settle();
  check("B10. on a desktop the badge is never asked for", desk.fetched.length === 0);

  /* ══ L ══ */
  console.log("\n══ L. layout ══");
  const css = (d.doc.getElementById("bf-tabbar-style") || {}).textContent || "";
  const outside = css.replace(/@media \(max-width: 760px\)\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}/g, "");
  const outsideSelectors = (outside.match(/(^|\})([^{}]+)\{/g) || []).map(x => x.replace(/^\}/, "").replace(/\{$/, "").trim());
  check("B11. on a desktop the bar is never shown: outside the phone query only display:none for it and its spacer, and the Create sheet's own rules",
    has(outside, "#bf-tabbar,#bf-tabbar-spacer{display:none}") && outsideSelectors.every(sel => sel === "#bf-tabbar,#bf-tabbar-spacer" || sel.split(",").every(x => /^#bf-create/.test(x.trim()))), J(outsideSelectors));
  check("L1. 56 px plus the safe area, fixed to the bottom, the page's own spacer the same", has(css, "height:calc(56px + env(safe-area-inset-bottom, 0px));") && has(css, "html.bf-tabbar-on #bf-tabbar-spacer{display:block;height:calc(56px + env(safe-area-inset-bottom, 0px))}") && has(css, "position:fixed;left:0;right:0;bottom:0;z-index:90;"));
  const music = FILES["scripts/bf-music.js"] || "";
  const z = Number((/#bf-tabbar\{[^}]*z-index:(\d+)/.exec(css) || /bottom:0;z-index:(\d+)/.exec(css) || [])[1]);
  // NAMED (Nov 22 2026, FX3): BEFORE "above the page (the Guide button is 40) ... the Guide's panel (2147483600)" (the book button and its sheet,
  // gone). AFTER above the mist (46 on the phone) and below the Create sheet, the music player's sheet and the Guide's tab and panel (999990)
  const mistZ = Number((/\n    "    z-index: (\d+); pointer-events: auto;/.exec(FILES[PRESENCE] || "") || [])[1]);
  const guideZ = Number((/"#tmx-guide-root \{",\n    "  position: fixed;",\n    "  top: 50%;",\n    "  left: 0;",\n    "  transform: translateY\(-50%\);",\n    "  z-index: (\d+);",/.exec(FILES[GUIDE] || "") || [])[1]);
  check("L2. above the page and the mist (" + mistZ + ") and below dialogs: the Create sheet (2147483301), the music player's sheet (2147483000), the Guide's tab and panel (" + guideZ + ")",
    z === 90 && mistZ === 46 && z > mistZ && z < guideZ && guideZ === 999990 && z < 2147483000 && has(css, "#bf-create{position:fixed;z-index:2147483301;") && has(music, "2147483000") &&
    !/z-index:\s*(?:[0-9]{3,})/.test((/align-items:stretch;[^"]*?backdrop-filter:blur\(12px\)\}/.exec(css) || [""])[0]), J(z));
  // NAMED (Nov 22 2026, FX3): BEFORE "L3. the Guide button sits 56 px higher and its spacer grows to 136 px" and "L4. a page with the Guide
  // uses its spacer, not a second one" (the book button, gone). AFTER the mist sits 16 px above the bar, and the bar's own spacer is the page's only one.
  check("L3. with the bar on, the mist sits 16 px above it (56 + 16 and the safe area); the bar lifts no book button", has(FILES[PRESENCE], "  html.bf-tabbar-on #tmx-presence-root { bottom: calc(56px + 16px + env(safe-area-inset-bottom, 0px)) !important; }") &&
    !/tmx-guide-fab/.test(css));
  check("L4. the bar's spacer is the page's only one: no Guide spacer, none hidden for it", !/tmx-guide-fab-spacer/.test(css) && !/tmx-guide-fab-spacer/.test(FILES[GUIDE] || "") && has(css, "html.bf-tabbar-on #bf-tabbar-spacer{display:block;height:calc(56px + env(safe-area-inset-bottom, 0px))}"));
  const kids = Array.from(d.doc.body.children).map(n => n.id || n.className || n.tagName);
  check("L5. the legal footer sits above the bar's spacer (the spacer and the bar come after it)", kids.indexOf("bf-legal-footer") < kids.indexOf("bf-tabbar-spacer") && kids.indexOf("bf-tabbar-spacer") > -1, J(kids));
  check("L6. every bar target is at least 44 px; the + is 52 x 34 with radius 11 in the brand gradient",
    has(css, "#bf-tabbar .bf-tab{flex:1 1 0;min-width:44px;min-height:44px;") && has(css, "#bf-tabbar .bf-tab-plus{display:flex;align-items:center;justify-content:center;width:52px;height:34px;border-radius:11px;") &&
    has(css, "background:linear-gradient(90deg,var(--bf-accent-a, #22d3ee),var(--bf-accent-b, #8b5cf6))}") && has(css, "#bf-create .bf-create-close{width:44px;height:44px;min-width:44px;"));
  check("L7. the bar's font is the system stack, so no font is added", has(css, "font-family:system-ui,-apple-system,\"Segoe UI\",Arial,sans-serif;") && !/@font-face|fonts\.googleapis/.test(FILES[BAR] || ""));

  /* ══ C ══ */
  console.log("\n══ C. the Create sheet ══");
  plus.click();
  const sheet = d.doc.getElementById("bf-create");
  const opts = sheet ? Array.from(sheet.querySelectorAll("[data-create]")).map(n => n.getAttribute("data-create") + ":" + (n.getAttribute("href") || (n.getAttribute("aria-disabled") === "true" ? "soon" : "?"))) : [];
  check("C1. a modal dialog, titled Create", sheet && !sheet.hidden && sheet.getAttribute("role") === "dialog" && sheet.getAttribute("aria-modal") === "true" && d.doc.getElementById("bf-create-title").textContent === "Create");
  // NAMED (Nov 20 2026, P2-3): BEFORE Post was Coming soon too. AFTER Post opens the composer (/compose.html; a desktop opens it as a modal); Video stays Coming soon.
  check("C2. Video is Coming soon and goes nowhere; Post opens the composer; the rest open their real creators",
    J(opts) === J(["post:/compose.html", "video:soon", "product:/marketplace.html?create=product", "service:/marketplace.html?create=service", "agent:/run.html",
      "campaign:/campaigns.html?create=campaign", "garage:/garage-sale.html?create=item", "card:/digital-cards.html"]), J(opts));
  const soon = Array.from(sheet.querySelectorAll(".is-soon"));
  check("C3. each Coming soon item says so and is not a link or a button", soon.length === 1 && soon.every(n => n.tagName === "DIV" && /Coming soon/.test(n.textContent) && !n.querySelector("a,button")));
  check("C4. focus goes into the sheet; Escape closes it and returns focus to +", d.doc.activeElement === sheet.querySelector("a.bf-create-opt") &&
    (sheet.dispatchEvent(new d.w.KeyboardEvent("keydown", { key: "Escape", bubbles: true })), sheet.hidden === true && d.doc.activeElement === plus));
  d.w.BFTabbar.openCreate(plus);
  const all = sheet.querySelectorAll("a[href],button");
  all[all.length - 1].focus();
  const tab = new d.w.KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true });
  all[all.length - 1].dispatchEvent(tab);
  check("C5. Tab from the last item comes back to the first (focus stays in the dialog)", tab.defaultPrevented && d.doc.activeElement === all[0]);
  d.doc.getElementById("bf-create-backdrop").click();
  check("C6. a tap outside closes it", sheet.hidden === true);
  check("C7. the sheet sends no request and creates nothing (it only links)", d.fetched.every(u => /\/api\/inbox\/counts$/.test(u)) && !/method:\s*"POST"/.test(FILES[BAR]));
  const off = await page("/oracle.html");
  off.w.BFTabbar.openCreate(null);
  check("C8. home.html can open it on any width (BFTabbar.openCreate), even where the bar is not shown", !!off.doc.getElementById("bf-create") && !off.doc.getElementById("bf-create").hidden);
  const mk = FILES[MARKET] || "";
  check("C9. marketplace.html?create=product|service opens the new-listing form with the kind set, and sends listing_kind",
    has(mk, "    if (!editingId && createKind) body.listing_kind = createKind;\n") && /function openCreateFromLink\(\) \{[\s\S]{0,600}createKind = kind;/.test(mk) && has(mk, "openCreateFromLink();"));
  const SRC = FILES[SERVER] || "";
  check("C10. POST /api/marketplace/listings keeps the kind: absent is product, anything but product or service is a 400",
    has(SRC, "const listingKind = req.body.listing_kind === undefined || req.body.listing_kind === null || req.body.listing_kind === \"\" ? \"product\" : req.body.listing_kind;") &&
    has(SRC, "    if (listingKind !== \"product\" && listingKind !== \"service\") return res.status(400)") && has(SRC, "      seller_id: req.user.id, title, description: description || \"\", listing_kind: listingKind,"));
  check("C11. garage-sale.html?create=item and campaigns.html?create=campaign open their forms",
    /get\("create"\) === "item"\) \{[\s\S]{0,200}openCreateModal\(/.test(FILES[GARAGE]) && /get\("create"\) === "campaign"\) \{[\s\S]{0,200}openCreateModal\(/.test(FILES[CAMPAIGNS]));

  /* ══ J ══ */
  console.log("\n══ J. bf-session.js ══");
  const sess = FILES[SESSION] || "";
  check("J1. every signed-in page bf-session.js guards loads the bar, with the music player", has(sess, "  function loadMusicPlayer() {\n    loadTabBar();\n") &&
    has(sess, "    tag.src = \"/scripts/bf-tabbar.js\";\n    tag.defer = true;") && has(sess, "if (window.BFTabbar || document.querySelector(\"script[src$='/scripts/bf-tabbar.js']\")) return;"));
  const FE = H.FRONTEND;
  const loads = PAGES.filter(p => { try { return /bf-session\.js/.test(fs.readFileSync(path.join(FE, p), "utf8")); } catch (e) { return false; } });
  const noSession = PAGES.filter(p => loads.indexOf(p) === -1);
  console.log("    SHOWN (signed in, phone; " + shown.filter(p => loads.indexOf(p) !== -1).length + "): " + shown.filter(p => loads.indexOf(p) !== -1).join(" "));
  console.log("    HIDDEN by the list (" + hidden.length + "): " + hidden.join(" "));
  console.log("    NO BAR because the page does not load bf-session.js (" + noSession.length + "): " + noSession.join(" "));
  check("J2. home.html and inbox.html load bf-session.js", loads.indexOf("home.html") !== -1 && loads.indexOf("inbox.html") !== -1);

  /* ══ W ══ */
  console.log("\n══ W. the offline shell ══");
  const sw = FILES[SW] || "";
  // NAMED (Nov 20 2026, P2-2): BEFORE "p21". AFTER "p22": the report, block and mute menu (bf-safety.js), moderation.html and copyright.html in the shell.
  // NAMED (Nov 20 2026, P2-3): BEFORE "p22". AFTER "p23": posts, the Following feed, Talk and follows (bf-feed.js, bf-composer.js) and compose.html in the shell.
  // NAMED (Nov 20 2026, FX1): BEFORE "p23". AFTER "fx1": Home's feed and the Profile as the approved design pictures.
  // NAMED (Nov 20 2026, P3-1): BEFORE "fx1". AFTER "p31": free accounts (the members panel, the verification banner, landing by tier).
  // NAMED (Nov 21 2026, P3-2): BEFORE "p31". AFTER "p32": the Verified badge (bf-verified.js), and the members panel on media and business ID.
  // NAMED (Nov 21 2026, FX2): BEFORE "p32". AFTER "fx2": the feed's Tip and product strip, the Profile's banner, the Agent Directory's views (bf-agents-views.js) and the Oracle's Sun.
  // NAMED (Nov 21 2026, P3-1B): BEFORE "fx2". AFTER "p31b": the free-account rules (bf-access.js Buy sheet and members intercepts, the Create sheet's Members tags, the composer's photo rule and Show in Google, Talk's members box).
  // NAMED (Nov 21 2026, P3-1C): BEFORE SHELL_REV "p31b". AFTER "p31c" (the wallet's member-welcome sentence and ledger labels).
  // NAMED (Nov 22 2026, FX3): BEFORE SHELL_REV "p31c". AFTER "fx3" (the abyss sun, Termaximus on the phone, the agent cards).
  // NAMED (Nov 22 2026, FX3B): BEFORE "fx3"; AFTER "fx3b"
  // NAMED (Nov 23 2026, P3-3): BEFORE "fx3b"; AFTER "p33" (Share, Offer or Need, the Need post and I can help, the Market filter)
  // NAMED (Nov 23 2026, LR-1): BEFORE "p33"; AFTER "lr1" (approve each reply before it posts, the Lead Radar sign-in prompt, tidy-ups). sw.js now carries its note on the SHELL_REV line, so the line may end in a // comment.
  // NAMED (Nov 27 2026, FX4B4): BEFORE "fx4b"; AFTER "fx4b4" (My Chart on phones opens on the whole chart, double-tap or pinch to zoom in; the sigil card's heading Your Sigil). FX4B: BEFORE "fx4s"; AFTER "fx4b" (My Chart on phones opens with the Divine Triangle filling the width, drag, double-tap and pinch to see every house; the Oracle's Profile and Celestial panels solid on phones). FX4S: BEFORE "fx4m"; AFTER "fx4s" (the phone music library shows only in the open boombox and is not reopened at a phone launch). FX4M: BEFORE "fx4a"; AFTER "fx4m" (music carries on across pages and stops on Home; the Guide tab on the Inbox). FX4A: BEFORE "h1b"; AFTER "fx4a" (the boombox, AI Agent Tasks, the Oracle pages and the calendar on phones). H1B: BEFORE "h1"; AFTER "h1b" (no mist on Home or the composer; room under the mist at the end of card-view and proposals). H1: BEFORE "g1"; AFTER "h1" (the home tabs, Search and the storefront badge). HOTFIX-G1: BEFORE "lr4b"; AFTER "g1" (phone layouts restored; only the controls under the Guide tab moved). LR-4B: BEFORE "lr4"; AFTER "lr4b" (the storefront menu draws whichever loads first). LR-4: BEFORE "lr3b"; AFTER "lr4" (Get found). LR-3B: BEFORE "lr3"; AFTER "lr3b" (nothing to tap under the Guide tab on the phone). LR-3: BEFORE "lr2b"; AFTER "lr3" (Inbound, the storefront Message button). LR-2B: BEFORE "lr2"; LR-2: BEFORE "lr1b".
  check("W1. SHELL_REV \"fx4b4\" in the cache's name", /var SHELL_REV = "fx4b4";[ \t]*(?:\/\/[^\n]*)?\nvar CACHE = "bf-shell-" \+ BUILD \+ "-" \+ SHELL_REV;/.test(sw));
  check("W2. the bar, the profile header and Settings, Local are in the shell", has(sw, "  \"/scripts/bf-tabbar.js\", \"/scripts/bf-profile-shell.js\", \"/scripts/bf-local-settings.js\",\n"));
  // NAMED (Nov 20 2026, P2-2): BEFORE the line ended the list; AFTER a comma follows it, and P2-2's two pages come next.
  check("W3. Home and the Inbox are offline pages", has(sw, "  \"home.html\", \"inbox.html\",   // NAMED (Nov 19 2026, P2-1)"));

  /* ══ U ══ */
  console.log("\n══ U. unchanged since " + P20_COMMIT + " ══");
  const changed = UNCHANGED.filter(f => {
    let old;
    try { old = execFileSync("git", ["-C", FE, "show", P20_COMMIT + ":" + f], { encoding: "utf8", maxBuffer: 64 << 20, stdio: ["ignore", "pipe", "ignore"] }).replace(/\r\n/g, "\n"); } catch (e) { return true; }
    // NAMED (Nov 20 2026, P2-2): dashboard.html gained the owner's moderation count, four lines and nothing else
    // (P22_DASH_LINES); with exactly those removed it must still be byte for byte the old file.
    let now = FILES[f];
    if (f === "dashboard.html") P22_DASH_LINES.forEach(function (l) { now = now.split(l + "\n").length === 2 ? now.replace(l + "\n", "") : now + "\u0000missing"; });
    // NAMED (Nov 26 2026, FX4B): FX4B's hunks undone first of all, the same way
    // NAMED (Nov 27 2026, FX4B4): FX4B4's hunks undone before FX4B's, the same way
    FX4B4_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + " fx4b4 hunk missing"; });
    FX4B_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + " fx4b hunk missing"; });
    // NAMED (Nov 26 2026, FX4S): FX4S's hunks undone next, the same way
    FX4S_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + " fx4s hunk missing"; });
    // NAMED (Nov 26 2026, FX4M): FX4M's hunks undone next, the same way
    FX4M_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + " fx4m hunk missing"; });
    // NAMED (Nov 26 2026, FX4A): FX4A's hunks undone before all the others, the same way
    FX4A_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + " fx4a hunk missing"; });
    // NAMED (Nov 25 2026, HOTFIX-G1): HOTFIX-G1's hunk undone before all the others, the same way
    G1_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + " g1 hunk missing"; });
    // NAMED (Nov 25 2026, LR-4): LR-4's hunks undone before all the others, the same way
    LR4_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + " lr4 hunk missing"; });
    // NAMED (Nov 25 2026, HOTFIX-G1): BEFORE LR-3B's hunks were undone here (checkAppShell.lr3b.json); AFTER none (see G1_SWAPS)
    // NAMED (Nov 23 2026, LR-2): LR-2's hunks undone before all the others, the same way
    LR2_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + " lr2 hunk missing"; });
    // NAMED (Nov 23 2026, LR-1): LR-1's two hunks undone first, the same way
    LR1_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + "\u0000lr1 hunk missing"; });
    // NAMED (Nov 22 2026, FX3B): FX3B's hunks undone before all the others, the same way
    FX3B_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + "\u0000fx3b hunk missing"; });
    // NAMED (Nov 22 2026, FX3 part D): its hunks undone first, the same way
    FX3D_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + "\u0000fx3d hunk missing"; });
    // NAMED (Nov 22 2026, FX3): then FX3's own hunks, the same way
    FX3_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + "\u0000fx3 hunk missing"; });
    // NAMED (Nov 21 2026, FX2): FX2's hunks undone (each must be found exactly once), then the same byte-for-byte equality
    FX2_SWAPS.filter(x => x[0] === f).forEach(([, a, b]) => { const i = now.indexOf(a); now = i >= 0 && now.indexOf(a, i + 1) < 0 ? now.slice(0, i) + b + now.slice(i + a.length) : now + "\u0000fx2 hunk missing"; });
    return old !== now;
  });
  check("U1. the Oracle pages, the music player (its button icon), the Layered Stack logo (bf-marks.js), HQ1's dashboard views, the phone and UI stylesheets and the Guide are byte for byte as at " + P20_COMMIT,
    changed.length === 0, changed.join(","));
  let diffNames = [];
  try { diffNames = execFileSync("git", ["-C", FE, "diff", "--name-only", P20_COMMIT, "--"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(Boolean); } catch (e) { diffNames = ["git failed"]; }
  let addedFonts = "";
  try { addedFonts = execFileSync("git", ["-C", FE, "diff", P20_COMMIT, "--", "*.html", "*.css", "*.js"], { encoding: "utf8", maxBuffer: 64 << 20, stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(l => /^\+/.test(l) && /@font-face|fonts\.googleapis|fonts\.gstatic|font-family:\s*["']?(?!system-ui|inherit|var\()/i.test(l)).join("\n"); } catch (e) { addedFonts = "git failed"; }
  check("U2. no font is added or changed by any edited page (new rules use the system stack or inherit)", addedFonts === "", addedFonts.slice(0, 300));
  // NAMED (Nov 26 2026, FX4A): BEFORE no Oracle page might be edited; AFTER oracle.html, mychart.html and calendar.html may, by FX4A's
  // hunks alone (U1 holds them to that, byte for byte), and synastry.html and the-third.html still may not.
  check("U3. no Oracle page is among the edited files but FX4A's three (oracle, mychart, calendar; their hunks alone, U1)", !diffNames.some(f => /^(synastry|the-third)\.html$/.test(f)) &&
    diffNames.filter(f => /^(oracle|mychart|calendar)\.html$/.test(f)).every(f => FX4A_SWAPS.some(x => x[0] === f)), diffNames.join(","));

  T.finish();
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
