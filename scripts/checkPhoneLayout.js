"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkPhoneLayout — PH1 (Nov 19 2026): every member page on a phone, read from
   the files (no browser; scripts/browserCheckPhone.js measures the pages in
   Chrome at 360, 390 and 430 px and holds the desktop to its baseline).

     P  the breakpoint: css/bf-phone.css is ONE @media (max-width: 760px)
        block with nothing outside it but comments, so a desktop never applies
        any of it; every page in lib/appMap.json links it last in its head
        and has viewport-fit=cover;
     A  the dashboard's top bar on a phone: two rows (brand, music, avatar;
        AGENTS, the orb, TERMAXIMUS), Settings and Sign Out off the bar and in
        the avatar's menu (#bfAvatarMenu: a Settings link, a Sign Out button
        calling logout()), the menu only under (max-width: 760px);
     B  the orbit on a phone is the desktop's orbit on a circle: phoneView,
        PHONE_QUERY 760, no narrow() row, the drift and the sparks the same,
        the ring's drawing shown, labels wrapping in full, THIS WEEK and the
        goal button under it;
     C  the Guide: 48 px, bottom-right inside the safe area, the page's end
        spacer shown;
     D  the music button in the header row on a phone (the dashboard's bar,
        every other page's header row), never floating;
     E  the agent pages: the live tiles wrap (no ellipsis), one column at 390
        px and below, the tab row's edge fade, the Last run row;
     F  the dashboard cards: 16 px padding, the 44 px icon, title and Swap on
        one row;
     G  the decoration (stars, nebula glows, the mist) behind the text, no tap;
     H  the shell: 100dvh after a 100vh fallback, no field under 16 px, the
        safe area at the top (the dashboard's bar and every other page);
     S  sw.js: the shell's version bumped (SHELL_REV "ph1") and bf-phone.css
        cached for offline;
     N  no emoji in any file PH1 added or changed.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const PHONE = "css/bf-phone.css", DASH = "dashboard.html", ORBIT = "scripts/bf-orbit.js", BOX = "scripts/bf-boombox.js";
const PROFILE = "scripts/agent-profile.js", SW = "sw.js", GUIDE = "scripts/termaximus-guide.js";
const PRESENCE = "scripts/termaximus-presence.js";   // NAMED (Nov 22 2026, FX3): the phone's mist is drawn there now

const MUTATIONS = {
  // a phone rule outside the media block reaches the desktop (P)
  "rule-outside-media": [[PHONE, "@media (max-width: 760px) {\n", ".bf-legal-footer { position: relative; }\n@media (max-width: 760px) {\n"]],
  // the breakpoint drifts to 640 px (P)
  "breakpoint-640": [[PHONE, "@media (max-width: 760px) {\n", "@media (max-width: 640px) {\n"]],
  // a page stops linking the phone stylesheet (P)
  "page-without-phone-css": [["terms.html", "<link rel=\"stylesheet\" href=\"/css/bf-phone.css\">", ""]],
  // a page loses viewport-fit=cover (P, H)
  "viewport-not-cover": [["inventory.html", ", viewport-fit=cover", ""]],
  // Settings and Sign Out stay on the phone's top bar (A)
  "settings-on-bar": [[DASH, "    #settingsNavBtn,.topbar .logout{display:none}\n", ""]],
  // the avatar menu has no Sign Out (A)
  "menu-without-signout": [[DASH, "  out.addEventListener(\"click\", function () { close(false); logout(); });\n", ""]],
  // the avatar menu opens on a desktop too (A)
  "menu-on-desktop": [[DASH, "  function onPhone() { return !!mq && mq.matches; }", "  function onPhone() { return true; }"]],
  // the top bar is not two rows (A)
  "topbar-one-row": [[DASH, "    .topbar::after{content:\"\";order:4;flex:0 0 100%;height:0}\n", ""]],
  // the phone's orbit is the old row again: the ring's drawing hidden (B)
  "orbit-svg-hidden": [[DASH, "    .orbit-panel{padding:12px 12px 14px}\n", "    .orbit-panel{padding:12px 12px 14px}\n    .orbit-svg{display:none}\n"]],
  // labels are cut again (B)
  "labels-ellipsis": [[DASH, "white-space:normal;width:84px;text-align:center;", "white-space:nowrap;width:84px;text-align:center;text-overflow:ellipsis;"]],
  // the phone's view is an ellipse, not a circle (B)
  "orbit-ellipse": [[ORBIT, "rx: r, ry: r,", "rx: r, ry: Math.round(r * 0.4),"]],
  // the orbit stands still on the phone (B)
  "phone-no-drift": [[ORBIT, "  function drifting() { return !state.open && !state.hover && !state.focus && !reduced() && !document.hidden; }", "  function drifting() { return !state.open && !state.hover && !state.focus && !reduced() && !document.hidden && !phone(); }"]],
  // NAMED (Nov 22 2026, FX3): BEFORE "guide-56" and "guide-no-inset" (the book button's size and inset, gone). AFTER:
  // the book button comes back (C)
  "book-button-back": [[PHONE, "  canvas.star-canvas, #starCanvas {", "  #tmx-guide-fab { width: 48px; height: 48px; min-width: 48px; min-height: 48px; }\n  canvas.star-canvas, #starCanvas {"]],
  // the mist grows past 56 px (C)
  "mist-64": [[PRESENCE, "  var TMX_PHONE_MIST = 56, TMX_DESK_MIST = 110;", "  var TMX_PHONE_MIST = 64, TMX_DESK_MIST = 110;"]],
  // the mist ignores the safe area (C)
  "mist-no-inset": [[PRESENCE, "right: 16px !important; bottom: calc(16px + env(safe-area-inset-bottom, 0px)) !important;", "right: 16px !important; bottom: 16px !important;"]],
  // a Guide spacer comes back (C)
  "guide-spacer-back": [[GUIDE, "  var accessKnown = false;\n", "  var accessKnown = false;\n  var fabSpacer = document.createElement(\"div\"); fabSpacer.id = \"tmx-guide-fab-spacer\";\n"]],
  // the Guide's tab moves to the bottom (C)
  "guide-tab-low": [[GUIDE, "    \"#tmx-guide-root {\",\n    \"  position: fixed;\",\n    \"  top: 50%;\",", "    \"#tmx-guide-root {\",\n    \"  position: fixed;\",\n    \"  top: 90%;\","]],
  // the music button floats over the page on a phone (D)
  "music-floats": [[BOX, "      if (phoneRow() && state === \"icon\" && !home) { var row = headerRow(); if (row) { toRow(row); return; } }\n", ""]],
  // the live tiles are cut to an ellipsis again (E)
  "tiles-ellipsis": [[PROFILE, "'@media (max-width:760px){.ap-live-v,.ap-live-s{overflow:visible;text-overflow:clip;white-space:normal;overflow-wrap:anywhere}' +", "'@media (max-width:760px){.ap-live-v,.ap-live-s{overflow:hidden}' +"]],
  // the tab row has no edge fade (E)
  "tabs-no-fade": [[PROFILE, "-webkit-mask-image:linear-gradient(90deg,#000 calc(100% - 32px),transparent);mask-image:linear-gradient(90deg,#000 calc(100% - 32px),transparent)", "opacity:1"]],
  // the cards keep their 60 px icon on its own row (F)
  "card-icon-60": [[DASH, "    .orbit-main-head .bf-hq-icon,.orbit-main-box .bf-card-icon{width:44px;height:44px;flex:0 0 44px;margin:0}\n", ""]],
  // the stars sit over the text and take taps (G)
  "stars-over-text": [[PHONE, "  canvas.star-canvas, #starCanvas { z-index: -1 !important; pointer-events: none !important; opacity: .75; }\n", ""]],
  // NAMED (Nov 22 2026, FX3): BEFORE "mist-over-text" (the mist under the page). AFTER the old rule sending it under the page comes back (G)
  "mist-under-page-back": [[PHONE, "  canvas.star-canvas, #starCanvas {", "  #tmx-presence-root { z-index: -1 !important; opacity: .6; pointer-events: none !important; }\n  canvas.star-canvas, #starCanvas {"]],
  // the corner stars over the text (G)
  "corner-over-text": [[PHONE, "  .corner-star, #oracleCornerStar { z-index: -1 !important;", "  .corner-star, #oracleCornerStar { z-index: 2 !important;"]],
  // 100dvh without its 100vh fallback (H)
  "dvh-no-fallback": [[PHONE, "  html, body { min-height: 100vh; min-height: 100dvh; }", "  html, body { min-height: 100dvh; }"]],
  // a field under 16 px (H)
  "input-15px": [[PHONE, "select, textarea { font-size: 16px !important; }", "select, textarea { font-size: 15px !important; }"]],
  // the pages' header ignores the notch (H)
  "no-safe-top": [[PHONE, "padding-top: env(safe-area-inset-top, 0px);", "padding-top: 0;"]],
  // the shell's cache is not bumped (S)
  // NAMED (Nov 19 2026, HQ1): SHELL_REV is "hq1" now (BEFORE "ph1"); bumped again, never back to empty.
  // NAMED (Nov 19 2026, P2-1): BEFORE "hq1". AFTER "p21": the bottom bar, Home, the Inbox, the profile header and Settings, Local in the shell (checkAppShell W).
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
  // NAMED (Nov 23 2026, LR-1B): BEFORE "lr1"; AFTER "lr1b" (suppressed.html noindex).
  "sw-not-bumped": [[SW, "var SHELL_REV = \"lr1b\";",   // NAMED (Nov 23 2026, P3-3): BEFORE "fx3b"; AFTER "p33" (Share, Offer or Need, the Need post and I can help, the Market filter). NAMED (Nov 22 2026, FX3B): BEFORE "fx3"; AFTER "fx3b"
    "var SHELL_REV = \"\";"]],
  // bf-phone.css is not cached for offline (S)
  "sw-without-phone-css": [[SW, "  \"/css/bf-phone.css\",", ""]],
  // an emoji slips into the phone stylesheet (N)
  // (a mobile phone, built from its code point so this file holds none: checkNoEmoji N2)
  // NAMED (Nov 22 2026, FX3): BEFORE anchored on "/* ── C. The Guide:" (that comment went with the book button's rules). AFTER on G's
  "emoji": [[PHONE, "/* ── G. Decoration behind the text:", "/* " + String.fromCodePoint(0x1F4F1) + " ── G. Decoration behind the text:"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const MAP = JSON.parse(fs.readFileSync(path.join(REPO, "lib", "appMap.json"), "utf8"));
const PAGES = Object.keys(MAP.pages).map(k => String(MAP.pages[k].p || "/" + k).replace(/^\//, ""));
const FILES = {};
const read = f => { try { return fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n"); } catch (e) { return null; } };
[PHONE, DASH, ORBIT, BOX, PROFILE, SW, GUIDE, PRESENCE].concat(PAGES).forEach(f => { if (!(f in FILES)) FILES[f] = read(f); });
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(name, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + name); }
  else { failures++; console.log("    FAIL  " + name + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const J = v => JSON.stringify(v);
const css = FILES[PHONE] || "";
const noComments = t => t.replace(/\/\*[\s\S]*?\*\//g, "");
// the body of the first @media (max-width: 760px) { ... } block of a CSS text, by brace matching
function mediaBody(t, q) {
  let head = "@media " + q + " {", a = t.indexOf(head);
  if (a < 0) { head = "@media " + q + "{"; a = t.indexOf(head); }
  if (a < 0) return null;
  let depth = 0;
  for (let i = a + head.length - 1; i < t.length; i++) {
    if (t[i] === "{") depth++;
    else if (t[i] === "}" && --depth === 0) return { body: t.slice(a + head.length, i), start: a, end: i + 1 };
  }
  return null;
}
const has = (t, x) => typeof t === "string" && t.indexOf(x) !== -1;
const once = (t, x) => typeof t === "string" && t.split(x).length === 2;

/* ── P. the breakpoint ── */
console.log("\n══ P. one breakpoint, 760 px, and nothing for the desktop ══");
const bare = noComments(css);
const M = mediaBody(bare, "(max-width: 760px)");
check("P1. css/bf-phone.css is one @media (max-width: 760px) block; outside it there is nothing but comments", !!M && bare.slice(0, M.start).trim() === "" && bare.slice(M.end).trim() === "", M ? J([bare.slice(0, M.start).trim().slice(0, 60), bare.slice(M.end).trim().slice(0, 60)]) : "no block");
check("P2. no nested @media inside it widens the reach (only the one query)", !!M && !/@media/.test(M.body));
// Hand-written pages carry the NAMED comment; the pages the backend builds (lib/legalPages.js, lib/supportPage.js) the bare link.
const LINK_RE = /<link rel="stylesheet" href="\/css\/bf-phone\.css">(<!-- NAMED \(Nov 19 2026, PH1\)[^\n]*-->)?\n<\/head>/;
const noLink = PAGES.filter(p => FILES[p] !== null && (!LINK_RE.test(FILES[p]) || FILES[p].split("/css/bf-phone.css").length !== 2));
const missing = PAGES.filter(p => FILES[p] === null);
check("P3. every page in lib/appMap.json (" + PAGES.length + ") links css/bf-phone.css once, last in its head", PAGES.length >= 70 && missing.length === 0 && noLink.length === 0, J({ noLink, missing }));
const noCover = PAGES.filter(p => FILES[p] !== null && !/<meta name="viewport" content="width=device-width,\s*initial-scale=1(\.0)?,[^"]*viewport-fit=cover"/.test(FILES[p]));
check("P4. every page's viewport meta is width=device-width, initial-scale=1, ..., viewport-fit=cover", noCover.length === 0, J(noCover));
const DASH_PH1 = (/<style id="ph1Phone">([\s\S]*?)<\/style>/.exec(FILES[DASH] || "") || ["", ""])[1];
const dashBare = noComments(DASH_PH1), DM = mediaBody(dashBare, "(max-width: 760px)");
check("P5. dashboard.html's phone block: every rule inside @media (max-width: 760px) but the menu's own hiding (.topbar-menu{display:none})",
  !!DM && dashBare.slice(0, DM.start).trim() === ".topbar-menu{display:none}" && dashBare.slice(DM.end).trim() === "", DM ? J(dashBare.slice(0, DM.start).trim()) : "no block");
const ORBIT_CSS = (/<style id="orbitStyle">([\s\S]*?)<\/style>/.exec(FILES[DASH] || "") || ["", ""])[1];
const code = t => (t || "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
check("P6. the orbit's phone rules are at 760 px, none left at 640 px (the orbit's style and bf-orbit.js's code)", /\n  @media \(max-width: 760px\)\{/.test(ORBIT_CSS) &&
  !/\(max-width: ?640px\)/.test(code(ORBIT_CSS)) && !/\(max-width: ?640px\)/.test(code(FILES[ORBIT])),
  J([code(ORBIT_CSS).match(/.{30}\(max-width: ?640px\)/g), code(FILES[ORBIT]).match(/.{30}\(max-width: ?640px\)/g)]));

/* ── A. the dashboard's top bar ── */
console.log("\n══ A. the dashboard's top bar: two rows and the avatar's menu ══");
const dm = DM ? DM.body : "";
check("A1. two rows: the bar wraps, .topbar-actions is display:contents, a full-width break (order 4) between the brand, music and avatar (1 to 3) and AGENTS, the orb and TERMAXIMUS (5 to 7)",
  /\.topbar\{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;/.test(dm) && /\.topbar-actions\{display:contents\}/.test(dm) &&
  /\.topbar-brand\{order:1;/.test(dm) && /\.topbar > \.bfm-float\[data-inbar\]\{order:2;/.test(dm) && /\.topbar-user\{order:3;/.test(dm) &&
  /\.topbar::after\{content:"";order:4;flex:0 0 100%;height:0\}/.test(dm) && /\.topbar-agents-pill\{order:5;flex:1 1 0;[^}]*height:46px/.test(dm) &&
  /\.topbar-oracle-gate\{order:6;flex:0 0 46px\}/.test(dm) && /\.topbar-tmx-toggle\{order:7;flex:1 1 0;[^}]*height:46px/.test(dm));
check("A2. Settings and Sign Out are off the phone's bar; the R avatar is a 44 px button", /#settingsNavBtn,\.topbar \.logout\{display:none\}/.test(dm) && /\.topbar-avatar\{width:44px;height:44px;cursor:pointer/.test(dm));
const MENU = (/\(function avatarMenu\(\) \{[\s\S]*?\n\}\(\)\);/.exec(FILES[DASH] || "") || [""])[0];
check("A3. the avatar's menu (#bfAvatarMenu, role menu): a Settings link to settings.html and a Sign Out button that calls logout()",
  has(MENU, "menu.id = \"bfAvatarMenu\";") && has(MENU, "menu.setAttribute(\"role\", \"menu\");") && has(MENU, "settings.href = \"settings.html\";") && has(MENU, "settings.textContent = \"Settings\";") &&
  has(MENU, "out.textContent = \"Sign Out\";") && has(MENU, "out.addEventListener(\"click\", function () { close(false); logout(); });"));
check("A4. the menu only on a phone: the avatar becomes a button (aria-haspopup, aria-expanded) only under (max-width: 760px), and above it every attribute it added is removed",
  has(MENU, "window.matchMedia(\"(max-width: 760px)\")") && has(MENU, "function onPhone() { return !!mq && mq.matches; }") &&
  has(MENU, "if (!onPhone()) return;") && has(MENU, "[\"role\", \"tabindex\", \"aria-haspopup\", \"aria-controls\", \"aria-expanded\", \"aria-label\"].forEach(function (k) { av.removeAttribute(k); });"));
check("A5. Escape and a tap outside close it", has(MENU, "if (e.key === \"Escape\") close(true);") && has(MENU, "if (!menu.contains(e.target) && e.target !== av) close(false);"));

/* ── B. the orbit ── */
console.log("\n══ B. the orbit on a phone is the desktop's, on a circle ══");
const O = FILES[ORBIT] || "";
check("B1. bf-orbit.js has the phone's view: PHONE_QUERY (max-width: 760px), phoneView(w) with rx = ry (a circle), discs of r 26 (52 px), labels 84 px",
  has(O, "var PHONE_QUERY = \"(max-width: 760px)\";") && has(O, "function phoneView(w) {") && has(O, "rx: r, ry: r,") && /discR: 26, labelW: 84,/.test(O) && has(O, "var VIEW_WIDE = VIEW;"));
check("B2. the old row is gone: no narrow() in the code; the same drift, turn and spark on a phone", !/narrow\(\)\s*[;{)&|?]/.test(O.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, "")) &&
  has(O, "  function drifting() { return !state.open && !state.hover && !state.focus && !reduced() && !document.hidden; }") && has(O, "    if (reduced()) { state.turn = null; state.base += delta; place(); flushSparks(); return; }"));
check("B3. the view follows the width: setView on load and on resize, the ring's drawing laid out again on the same nodes", has(O, "  buildOrbit();\n  setView();\n  size();") &&
  has(O, "window.addEventListener(\"resize\", function () { if (setView()) starsDrawn = \"\"; size(); place(); });") && has(O, "function layoutRing() {"));
const om = (/\n  @media \(max-width: 760px\)\{([\s\S]*?)\n  \}/.exec(ORBIT_CSS) || ["", ""])[1];
check("B4. the phone's orbit CSS: the drawing shown, labels wrapping in full (84 px, above the halos), the core sized by --oc, no ellipsis",
  om.length > 0 && !/\.orbit-svg\{display:none\}/.test(om) && /\.orbit-portal-name\{[^}]*white-space:normal;width:84px;[^}]*overflow:visible;z-index:2/.test(om) &&
  /\.orbit-core\{width:var\(--oc, 80px\);height:var\(--oc, 80px\)/.test(om) && !/ellipsis/.test(om));
check("B5. THIS WEEK and the goal button under the orbit at the card's width (.orbit-below), hidden above 760 px; the empty space above gone (padding 12)",
  /\n  \.orbit-below\{display:none\}/.test(ORBIT_CSS) && /\.orbit-below\{display:flex;flex-direction:column;/.test(om) && /\.orbit-below \.orbit-goal-set\{[^}]*width:100%;height:44px/.test(om) &&
  /\.orbit-panel\{padding:12px 12px 14px\}/.test(om) && has(O, "below = el(\"div\", \"orbit-below\");") && has(O, "if (VIEW.phone && goalBtn.parentNode !== below) below.appendChild(goalBtn);"));

/* ── C. the Guide ── */
console.log("\n══ C. the Guide ══");
const mb = M ? M.body : "";
// NAMED (Nov 22 2026, FX3): BEFORE "C1. the Guide is 48 px, bottom-right inside the safe area, round" and "C2. every page ends with the Guide's
// spacer (80 px and the bottom inset)" (the book button, gone). AFTER no book button; the bottom-right is the mist, a 56 px button inside the
// safe area; the Guide is its tab at the left edge, in the middle, so the page's end needs no spacer.
const PR = FILES[PRESENCE] || "", GD = (FILES[GUIDE] || "").replace(/\/\*[\s\S]*?\*\//g, "");
check("C1. no book button; bottom-right is the mist: 56 px (the 110 px mist scaled), 16 px from the right, inside the bottom safe area",
  !/tmx-guide-fab/.test(mb) && !/tmx-guide-fab/.test(GD) && has(PR, "  var TMX_PHONE_MIST = 56, TMX_DESK_MIST = 110;") &&
  has(PR, "  #tmx-presence-root { top: auto !important; left: auto !important; right: 16px !important; bottom: calc(16px + env(safe-area-inset-bottom, 0px)) !important;"));
check("C2. no Guide spacer: nothing fixed sits at the page's end (the Guide's tab is at the left edge, in the middle)",
  !/tmx-guide-fab-spacer/.test(mb) && !/tmx-guide-fab-spacer/.test(GD) &&
  has(FILES[GUIDE], "    \"#tmx-guide-root {\",\n    \"  position: fixed;\",\n    \"  top: 50%;\",\n    \"  left: 0;\",\n    \"  transform: translateY(-50%);\","));

/* ── D. the music button ── */
console.log("\n══ D. the music button in the header row ══");
const B = FILES[BOX] || "";
check("D1. on a phone the music button is in the header row: the dashboard's bar lays it out (no coordinates), every other page's header row holds it at its right end",
  has(B, "var PHONE_ROW_QUERY = \"(max-width: 760px)\";") && has(B, "if (phoneRow() && state === \"icon\" && !home) { var row = headerRow(); if (row) { toRow(row); return; } }") &&
  has(B, "[\"left\", \"top\", \"right\", \"bottom\"].forEach(function (k) { root.style.removeProperty(k); });") &&
  has(B, ".bfm-float[data-inheader=true]{position:relative!important;left:auto!important;top:auto!important;right:auto!important;bottom:auto!important;margin-left:auto;z-index:auto}"));
check("D2. with no stage remembered a phone starts at the icon (in the header row), not the bar over the foot of the page", has(B, "function stageOf(s, home) { return STAGES.indexOf(s) !== -1 ? s : (home || phoneRow() ? \"icon\" : \"tag\"); }"));

/* ── E. the agent pages ── */
console.log("\n══ E. the agent pages ══");
const P = FILES[PROFILE] || "";
check("E1. the live tiles: figure and line wrap in full up to 760 px (no ellipsis), one column at 390 px and below",
  has(P, "'@media (max-width:760px){.ap-live-v,.ap-live-s{overflow:visible;text-overflow:clip;white-space:normal;overflow-wrap:anywhere}' +") && has(P, "'@media (max-width:390px){.ap-live-grid{grid-template-columns:1fr}}' +"));
check("E2. the tab row scrolls with a visible fade at its right edge, its end padded clear of it", has(P, "\"@media (max-width:760px){#agTabs .deck-tabs-scroll{padding-inline-end:32px;scroll-padding-inline:0 32px;\" +") &&
  has(P, "mask-image:linear-gradient(90deg,#000 calc(100% - 32px),transparent)}}\";"));
check("E3. the Last run row on its own line (its date a 44 px link), REFRESH DATA and OPEN DASHBOARD side by side, the same height",
  /\.toolbar:has\(> \.toolbar-meta\) \{ flex-direction: column;/.test(mb) && /\.toolbar > \.toolbar-meta a \{ display: inline-flex; align-items: center; min-height: 44px; \}/.test(mb) &&
  /\.toolbar:has\(> \.toolbar-meta\) > div:last-child \{ display: grid !important; grid-template-columns: 1fr 1fr;/.test(mb));

/* ── F. the dashboard cards ── */
console.log("\n══ F. the dashboard cards ══");
check("F1. 16 px of even padding; the 44 px icon, the title and Swap on one row; the feature cards a two-column grid (icon, title) over the rest",
  /\.orbit-main-box\.card\.bf-card,\.orbit-grid \.card\.bf-card,\.orbit-alltools\{padding:16px\}/.test(dm) && /\.orbit-main-head\{gap:12px;margin-bottom:6px;align-items:center\}/.test(dm) &&
  /\.orbit-main-head \.bf-hq-icon,\.orbit-main-box \.bf-card-icon\{width:44px;height:44px;flex:0 0 44px;margin:0\}/.test(dm) &&
  /\.orbit-grid \.bf-feature-card\{display:grid;grid-template-columns:44px minmax\(0,1fr\);/.test(dm));

/* ── G. decoration ── */
console.log("\n══ G. the decoration behind the text ══");
// NAMED (Nov 22 2026, FX3): BEFORE "the mist, the star canvases and the corner stars sit under the page". AFTER the mist is a button over the
// page (C1, scripts/checkTermaximusPhone.js C), so bf-phone.css holds no rule for it or its stars; the canvases and corner stars stay under.
check("G1. the star canvases and the corner stars sit under the page (z-index -1), faded, and take no tap; no rule here sends the mist under it",
  !/#tmx-presence-root|\.tmx-star/.test(mb.replace(/\/\*[\s\S]*?\*\//g, "")) &&
  /canvas\.star-canvas, #starCanvas \{ z-index: -1 !important; pointer-events: none !important; opacity: \.75; \}/.test(mb) &&
  /\.corner-star, #oracleCornerStar \{ z-index: -1 !important; pointer-events: none !important; opacity: \.55; \}/.test(mb));
check("G2. the legal footer sits above the decoration (z-index 1)", /\.bf-legal-footer \{ position: relative; z-index: 1; \}/.test(mb));

/* ── H. the shell ── */
console.log("\n══ H. the app shell ══");
check("H1. 100dvh after a 100vh fallback, for the page and every full-height panel", /html, body \{ min-height: 100vh; min-height: 100dvh; \}/.test(mb) &&
  (mb.match(/100dvh/g) || []).length >= 6 && !/(^|[;{]\s*)(max-)?(min-)?height: calc\(100dvh[^;]*;\s*\}/.test(mb.replace(/height: calc\(100vh[^;]*; (max-)?(min-)?height: calc\(100dvh/g, "")));
check("H2. no field under 16 px (iOS would zoom): every input but checkbox, radio, range, colour and hidden, every select and textarea at 16 px",
  /input:not\(\[type=checkbox\]\):not\(\[type=radio\]\):not\(\[type=range\]\):not\(\[type=color\]\):not\(\[type=hidden\]\),\s*select, textarea \{ font-size: 16px !important; \}/.test(mb));
check("H3. the safe area at the top: the dashboard's bar pads env(safe-area-inset-top), every other page's html does",
  /\.topbar\{[^}]*padding:calc\(10px \+ env\(safe-area-inset-top, 0px\)\)/.test(dm) && /html:not\(:has\(header\.topbar\)\) \{ padding-top: env\(safe-area-inset-top, 0px\);/.test(mb));
check("H4. every control at least 44 px: the zero-specificity floor for buttons, tabs, links that stand alone and fields", /:where\(button, \[role=button\], \[role=tab\],[\s\S]*?\{ min-height: 44px; \}/.test(mb));

/* ── S. the service worker ── */
console.log("\n══ S. the service worker ══");
const W = FILES[SW] || "";
// NAMED (Nov 19 2026, HQ1): BEFORE "ph1". AFTER "hq1", the dashboard's HQ1 scripts added to the shell (checkHqViews W1).
// NAMED (Nov 19 2026, P2-1): BEFORE "hq1". AFTER "p21": the bottom bar, Home, the Inbox, the profile header and Settings, Local in the shell (checkAppShell W).
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
// NAMED (Nov 23 2026, LR-1B): BEFORE "lr1"; AFTER "lr1b" (suppressed.html noindex).
check("S1. the shell's cache version is bumped: SHELL_REV \"lr1b\" (PH1's \"ph1\", bumped by HQ1, P2-1, P2-2, P2-3, FX1 and LR-1) in the cache's name", /var SHELL_REV = "lr1b";[ \t]*(?:\/\/[^\n]*)?\nvar CACHE = "bf-shell-" \+ BUILD \+ "-" \+ SHELL_REV;/.test(W));
check("S2. css/bf-phone.css is cached with the shell, for a page opened offline", /\n  "\/css\/bf-phone\.css",/.test(W));

/* ── N. no emoji ── */
console.log("\n══ N. no emoji ══");
const EMOJI = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}\u{1F1E6}-\u{1F1FF}]/u;
// agent-profile.js: only the lines PH1 added (the file's older text is checkNoEmoji's), between and on its PH1 markers.
const ph1Profile = (() => {
  const out = [], a = P.indexOf("        // PH1 (Nov 19 2026, the agent pages on a phone)."), b = P.indexOf("'@media (max-width:390px){.ap-live-grid{grid-template-columns:1fr}}' +", a);
  const c = P.indexOf("      /* PH1 (Nov 19 2026): on a phone the Run, Schedule"), d = P.indexOf("transparent)}}\";", c);
  if (a >= 0 && b > a) out.push(P.slice(a, b + 80)); else out.push("(missing)");
  if (c >= 0 && d > c) out.push(P.slice(c, d + 20)); else out.push("(missing)");
  return out.join("\n");
})();
const blocks = { [PHONE]: css, "dashboard.html (ph1Phone)": DASH_PH1 + MENU, [ORBIT]: O, [BOX]: B, [PROFILE + " (PH1 lines)"]: ph1Profile, [SW]: W };
const withEmoji = Object.keys(blocks).filter(k => EMOJI.test(blocks[k] || ""));
check("N1. no emoji in the phone stylesheet, the dashboard's phone block or the scripts PH1 changed", withEmoji.length === 0, J(withEmoji));

if (failures) { console.log("\nCHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
console.log("\nALL " + passes + " CHECKS PASSED");
process.exit(0);
