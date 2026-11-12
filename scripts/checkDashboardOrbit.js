"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkDashboardOrbit — the dashboard's top half as an orbit (Nov 10 2026,
   orbit top half).

   Frontend "Dashboard top half: orbit of five portals, swappable main boxes
   (Analytics, Store), living grid, All tools, quick search, moon phase"
   replaced the 29-tile feature grid and the AI Agent Directory card with
   scripts/bf-orbit.js over dashboard.html's <template id="orbitTools">, drawn
   from ONE GET /api/dashboard/top.

   THE PAGE RUNS IN JSDOM: the orbit's markup (its style, section and
   template) with bf-orbit.js, over fixture answers, a fake animation clock
   and a stubbed matchMedia. No network.

     O1  structure: every one of the 29 old tiles, and the directory card, is
         in the template byte for byte as it was at BASELINE, and in exactly
         one portal or Utilities; each portal's grid shows them with the same
         link and button label; the ordering module and its keys are gone;
         the top bar and everything from Business Profile down are BASELINE's;
     O2  badges and beams: Agents shows the proposals waiting, Sell the low
         stock; no badge at 0; a beam only from a portal with a badge;
     O3  the moon: named and lit correctly on known dates;
     O4  the main boxes: Analytics and Store with their figures and 14-day
         lines, "Connect a store to see orders" with no store; Swap, stored in
         localStorage bf_main_boxes and read back; a main box is never
         repeated in its portal's grid;
     O5  busiest first, the busiest drawn wide;
     O6  no invented number, no unread claim;
     O7  All tools: Grow, Sell, Connect, Agents, Oracle, Utilities;
     O8  the "/" key and the search; no conflict with the guide or Termaximus;
     O9  reduced motion: no drift, the turn snaps, the beam dot still;
     O10 transform and opacity only;
     O11 phones: a row of portals, stacked boxes, one column;
     O12 textContent only;
     O13 one fetch on load, one per Refresh, none per portal;
     O14 NAMED (Nov 10 2026, visual match): the approved mockup's look. The
         starfield panel and its stars, the rings' proportions (275/110 and
         150/60), each label under its circle, the open portal's halo and
         "(open)" with no dimming, the core's text with no percentage, the
         search pill's contents, the main boxes' layout and the AI Agent
         Directory box's layout.
     O15 NAMED (Nov 11 2026, still stars): the Oracle's abyss stars, STILL. The
         copy draws with oracle.html's own drawStarAt and makeStar numbers (read
         from that file), each star a halo, a core and, on the large bright
         ones, thin cross rays; nothing animates or transitions them; seeded,
         so they do not jump; the eight plain dots gone.
         NAMED (Nov 11 2026, more and even stars): at 1440, 1024 and 390 px, in
         the boxes Chrome measured, the count is the density rule (40 on the
         1152 x 565 panel, 18 to 48); each quadrant 20-30% and each half
         40-60% of them; sizes within 10 points of 60/30/10 with Oracle's
         layer counts; no two large ones in neighbouring cells; one star a
         cell; none closer than 60% of a cell; none on a portal, the core, a
         label or the search; the same places on every load.
         NAMED (Nov 11 2026, one living sky): ONE fixed set. Every star stays
         where it is, byte for byte and the very same nodes, through hover and
         focus on each portal, every preview shown and hidden, a click on each
         portal, Escape, a full turn, six seconds of drift and twinkle,
         Refresh, a data reload and a height-only change; only a width change
         lays them out again; the same set on two loads. None in the reserved
         row above the search (the preview and status lines, at a fixed
         height, so the panel's height never changes), nor under any portal,
         open halo or label with " (open)", wherever they drift. "Still"
         became "no POSITION animation": they twinkle in place, the halo and
         core by opacity (1 to .55), the rays by opacity and a scale of .8 to
         1.15 about the star's centre, the large ones' glint every 6 to 14 s;
         keyframes on opacity and scale only; each star's own 2.5 to 6 s and
         start; paused while hidden; none under reduced motion. The Oracle's
         colours: white 5/6 and cyan, violet and gold 1/18 each (its pickTint),
         within 10 points, at least three tints at every size, a tinted core
         lightened toward white, not white.

   NAMED (Nov 10 2026, visual match), pins moved: the directory card is no
   longer BASELINE's byte for byte (it was rebuilt for one grid cell; O1 now
   checks its parts and links); the beam dot travels 275 (O2); a main box
   shows one big number, one green line and no description (O4); the core
   reads THIS WEEK, the number, "tracked visits", All tools (O7); pressing a
   portal no longer dims the others (O8); "the front" is the lower-left slot,
   BFOrbit.frontBase(key) (O9).

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
// The frontend commit before the orbit (the Command Center's real-browser fix).
const BASELINE = "889cb13";

const DASH = "dashboard.html", ORBIT = "scripts/bf-orbit.js", GUIDE = "scripts/termaximus-guide.js", PRESENCE = "scripts/termaximus-presence.js";
// NAMED (Nov 11 2026, polish): the backend's own server.js and lib/yourData.js, for the retired card order (O1b).
const SERVER = "B:server.js", YOURDATA = "B:lib/yourData.js";

const MUTATIONS = {
  // a tile left out of every portal (O1)
  "tile-dropped": [[ORBIT, "\"prospecting\", \"sms-drip\"] },", "\"prospecting\"] },"]],
  // a tile's link changed (O1)
  "tile-link-changed": [[DASH, "  <a href=\"crm.html\" class=\"bf-btn\" onclick=\"event.stopPropagation()\">Open CRM</a>", "  <a href=\"crm-new.html\" class=\"bf-btn\" onclick=\"event.stopPropagation()\">Open CRM</a>"]],
  // a badge shown at 0 (O2)
  "badge-at-zero": [[ORBIT, "      badge[p.key].hidden = !(k > 0);\n", "      badge[p.key].hidden = false;\n"]],
  // a beam from a portal with no badge (O2)
  "beam-without-badge": [[ORBIT, "      var on = k > 0;\n", "      var on = true;\n"]],
  // the sidereal month in place of the synodic one (O3)
  "moon-wrong": [[ORBIT, "  var SYNODIC_DAYS = 29.530588853;", "  var SYNODIC_DAYS = 27.321661;"]],
  // a main box repeated in its portal's grid (O4)
  "main-box-duplicated": [[ORBIT, "var slugs = portal.tools.filter(function (s) { return state.mains.indexOf(s) === -1 && TOOL[s]; });",
    "var slugs = portal.tools.filter(function (s) { return TOOL[s]; });"]],
  // Swap not stored (O4)
  "swap-not-stored": [[ORBIT, "    writeLocal(JSON.stringify(state.mains));\n", ""]],
  // a number for a box the route gave nothing for (O6)
  "invented-number": [[ORBIT, "      default: return null;\n", "      default: return { text: \"12 updates\", value: 12 };\n"]],
  // the inbox claims unread mail (O6)
  "unread-shown": [[ORBIT, "        return { text: mb.connected ? \"Connected\" : \"Not connected\", value: 0 };", "        return { text: mb.connected ? \"3 unread\" : \"Not connected\", value: 3 };"]],
  // "/" taken while typing in a field (O8)
  "slash-in-input": [[ORBIT, "    if (editable(e.target) || editable(document.activeElement)) return false;\n", ""]],
  // under reduced motion the orbit still turns (O9)
  "reduced-motion-moves": [[ORBIT, "    if (reduced() || narrow()) { state.turn = null;", "    if (narrow()) { state.turn = null;"]],
  // a transition on a layout property (O10)
  "non-transform-animation": [[DASH, "transform-origin:0 0;font:inherit;cursor:pointer;transition:opacity .3s ease}", "transform-origin:0 0;font:inherit;cursor:pointer;transition:opacity .3s ease,left .6s ease-out,top .6s ease-out}"]],
  // NAMED (Nov 10 2026, visual match): the twelve below are the approved look (O14).
  // the portal labels back inside the circles
  "labels-inside-circles": [[DASH, ".orbit-portal-name{position:absolute;left:50%;top:calc(50% + var(--os) * 42px);", ".orbit-portal-name{position:absolute;left:50%;top:50%;"]],
  // no stars on the panel
  // NAMED (Nov 11 2026, still stars): the stars are drawn by drawStars() now, so "no stars" removes that call.
  "no-starfield": [[ORBIT, "  drawStars();\n", ""]],
  // NAMED (Nov 11 2026, still stars): the three below are the still Oracle stars (O15).
  // the stars twinkle
  // NAMED (Nov 11 2026, one living sky): "no animation" became "no POSITION animation": the star's own group (its place)
  // animated, a drift of a few pixels.
  "stars-animated": [[DASH, "  .orbit-star{animation:none !important}\n", "  .orbit-star{animation:orbitStarDrift 3s ease-in-out infinite}\n  @keyframes orbitStarDrift{50%{transform:translate(2px,1px)}}\n"]],
  // plain white dots again, with no halo
  "stars-plain-dots": [[ORBIT, "    g.appendChild(sv(\"circle\", { cx: x, cy: y, r: (L.r * O.haloR).toFixed(3), fill: \"url(#\" + id + \"h)\", \"class\": \"orbit-star-halo\" }));\n", "    g.appendChild(sv(\"circle\", { cx: x, cy: y, r: L.r.toFixed(3), fill: \"#fff\", \"class\": \"orbit-star-halo\" }));\n"]],
  // the ring's band no longer kept clear, so a star can sit where a portal drifts
  // NAMED (Nov 11 2026, more and even stars): the ring's circles of r 43 became the discs' boxes along the ring (stars-on-ring-band
  // below), so star-over-portal now drops the phone row's discs.
  // NAMED (Nov 11 2026, one living sky): the phone disc's box is measured once into `disc`, and its open halo kept clear around
  // it (the halo's circle holds the box, so the disc is uncovered only when both are gone).
  "star-over-portal": [[ORBIT, "        g.boxes.push(disc);\n", ""], [ORBIT, "        g.circles.push({ x: disc.x + disc.w / 2, y: disc.y + disc.h / 2, r: hr });\n", ""]],
  // NAMED (Nov 11 2026, more and even stars): the fuller, even sky (O15 at 1440, 1024 and 390 px).
  "stars-clustered-low": [[ORBIT, "x0 = col * grid.cw, y0 = row * grid.ch;", "x0 = col * grid.cw, y0 = g.h / 2 + row * grid.ch / 2;"]],
  "stars-one-quadrant": [[ORBIT, "x0 = col * grid.cw, y0 = row * grid.ch;", "x0 = col * grid.cw / 2, y0 = row * grid.ch / 2;"]],
  "stars-random-each-load": [[ORBIT, "var rnd = seeded(STAR_LAYOUT_SEED + 7919 * (row * grid.cols + col)), ", "var rnd = Math.random, "]],
  // NAMED (Nov 11 2026, one living sky): the band is the open halo's circle (r 43) and the open disc's box at every degree;
  // the halo holds the box, so the band is gone only when both are.
  "stars-on-ring-band": [[ORBIT, "        g.boxes.push({ x: x - (VIEW.portalR + 3) * scale, y: y - (VIEW.portalR + 3) * scale, w: 2 * (VIEW.portalR + 3) * scale, h: 2 * (VIEW.portalR + 3) * scale });\n", ""],
    [ORBIT, "        g.circles.push({ x: x, y: y, r: STAR_KEEP.haloR * scale });\n", ""]],
  // NAMED (Nov 11 2026, one living sky): ONE fixed set that twinkles in place, in the Oracle's colours (O15).
  // a hover lays the stars out again
  "hover-redraws": [[ORBIT, "  function showPreview(key) { preview.textContent = previewText(key); preview.hidden = false; }", "  function showPreview(key) { preview.textContent = previewText(key); preview.hidden = false; starsDrawn = \"\"; drawStars(); }"]],
  // opening a portal lays them out again
  "click-redraws": [[ORBIT, "    state.open = key;\n    writeSession(key);\n", "    state.open = key;\n    writeSession(key);\n    starsDrawn = \"\"; drawStars();\n"]],
  // each open portal its own sky
  "seed-per-portal": [[ORBIT, "    var key = starsWidth();\n", "    var key = starsWidth() + \"|\" + state.open;\n"],
    [ORBIT, "var rnd = seeded(STAR_LAYOUT_SEED + 7919 * (row * grid.cols + col)), ", "var rnd = seeded(STAR_LAYOUT_SEED + 31 * String(state.open).length + 7919 * (row * grid.cols + col)), "],
    [ORBIT, "    state.open = key;\n    writeSession(key);\n", "    state.open = key;\n    writeSession(key);\n    drawStars();\n"]],
  // the preview grows the panel when it shows
  "preview-resizes-panel": [[DASH, "  .orbit-say{height:2.6rem;", "  .orbit-say{min-height:0;"]],
  // a height-only change lays them out again
  "height-change-redraws": [[ORBIT, "    var key = starsWidth();\n", "    var key = starsWidth() + \"x\" + Math.round(panel.getBoundingClientRect().height);\n"]],
  // the reserved row above the search not kept clear
  "star-in-preview-row": [[ORBIT, "    if (say) g.boxes.push(box(say, 4));\n", ""]],
  // a label's " (open)" not kept clear
  "star-under-open-label": [[ORBIT, "    return (most * STAR_KEEP.titleCh + \" (open)\".length * STAR_KEEP.openCh) / 2 + STAR_KEEP.labelPad;", "    return (most * STAR_KEEP.titleCh) / 2;"]],
  // Refresh lays them out again
  "refresh-redraws": [[ORBIT, "  refresh.addEventListener(\"click\", function () { load(); });", "  refresh.addEventListener(\"click\", function () { starsDrawn = \"\"; drawStars(); load(); });"]],
  // the twinkle moves a star
  "twinkle-moves-star": [[DASH, "  @keyframes orbitTwinkle{0%,100%{opacity:1}50%{opacity:.55}}", "  @keyframes orbitTwinkle{0%,100%{opacity:1}50%{opacity:.55;transform:translate(1px,-1px)}}"]],
  // every star pulses together
  "twinkle-in-unison": [[ORBIT, "    var dur = T.minDur + rnd() * (T.maxDur - T.minDur), delay = -rnd() * dur,", "    var dur = 4, delay = 0,"]],
  // the twinkle runs under reduced motion
  "twinkle-under-reduced-motion": [[DASH, "    .orbit-star *{animation:none !important}\n    .orbit-star-glint{display:none}\n", ""]],
  // the twinkle runs on in a hidden tab
  "twinkle-not-paused-hidden": [[ORBIT, "  document.addEventListener(\"visibilitychange\", starsPause);\n", ""]],
  // every star white
  "one-colour-sky": [[ORBIT, "s.tint = tints[i] ? STAR_TINTS[tints[i] - 1] : STAR_WHITE;", "s.tint = STAR_WHITE;"]],
  // a tinted star's core washed to white
  "white-core-washout": [[ORBIT, "    var c = tinted ? mixWhite(t, T.coreMix) :", "    var c = tinted ? STAR_WHITE :"]],
  "stars-too-close": [[ORBIT, "var minGap = STAR_SKY.spacing * Math.min(grid.cw, grid.ch), ", "var minGap = 0, "]],
  "stars-fixed-count": [[ORBIT, "var n = starCount(g.w, g.h), ", "var n = 16, "]],
  "stars-all-large": [[ORBIT, "    return [small, n - small - large, large];\n", "    return [0, 0, n];\n"]],
  // the outer ring drawn rounder than the mockup
  "ring-ratio-wrong": [[ORBIT, "rx: 275, ry: 110, innerRx: 150, innerRy: 60,", "rx: 250, ry: 125, innerRx: 150, innerRy: 60,"]],
  // the open portal without its halo
  "open-halo-missing": [[DASH, ".orbit-portal:not(.is-open) .orbit-halo{display:none}", ".orbit-halo{display:none}"]],
  // the other portals dimmed again
  "others-dimmed": [[ORBIT, "      portalBtn[p.key].classList.toggle(\"is-open\", on);\n", "      portalBtn[p.key].classList.toggle(\"is-open\", on);\n      portalBtn[p.key].classList.toggle(\"is-dim\", !on);\n"]],
  // the core showing a percentage
  "core-shows-percent": [[ORBIT, "    else { figure = String(v.this_week); words", "    else { figure = String(v.this_week) + \"%\"; words"]],
  // "Press / to search" written under the search again
  "press-slash-text-back": [[DASH, "<p class=\"orbit-status\" id=\"orbitStatus\" role=\"status\"></p>", "<p class=\"orbit-hint\">Press / to search</p>\n      <p class=\"orbit-status\" id=\"orbitStatus\" role=\"status\"></p>"]],
  // the big Refresh button back
  "big-refresh-back": [[DASH, "<button type=\"button\" class=\"orbit-refresh\" id=\"orbitRefresh\" aria-label=\"Refresh\" title=\"Refresh\">", "<button type=\"button\" class=\"orbit-refresh bf-btn\" id=\"orbitRefresh\">Refresh"]],
  // a main box keeps its long description
  "main-box-description-back": [[ORBIT, "      Array.prototype.slice.call(box.querySelectorAll(\"p\")).forEach(function (p) { p.parentNode.removeChild(p); });\n", ""]],
  // the agents in five fixed 20 px columns, as when the old card was squeezed into one cell
  "agent-icons-overlap": [[DASH, ".orbit-dir-agents{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:14px 16px}", ".orbit-dir-agents{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(5,20px);gap:0}"]],
  // each agent's column narrower than its name, so the names overprint
  "agent-labels-merged": [[DASH, "gap:6px;flex:0 0 auto;min-width:56px}", "gap:6px;flex:0 0 auto;width:20px;min-width:0}"]],
  // the two directory buttons stacked
  "directory-buttons-stacked": [[DASH, ".orbit-dir-actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:auto}", ".orbit-dir-actions{display:flex;flex-direction:column;gap:10px;margin-top:auto}"]],
  // every portal press reads the route again (O13)
  "fetch-per-portal": [[ORBIT, "  function toggle(key) { if (state.open === key) fold(); else openPortal(key, true); }",
    "  function toggle(key) { load(); if (state.open === key) fold(); else openPortal(key, true); }"]],
  // markup written from text (O12)
  "innerHTML-used": [[ORBIT, "if (text !== undefined && text !== null) x.textContent = String(text); return x; }", "if (text !== undefined && text !== null) x.innerHTML = String(text); return x; }"]],
  // the music button's anchor moved out of the top bar (O1)
  "music-button-moved": [[DASH, "<div class=\"topbar-brand\" data-bf-boombox-anchor>", "<div class=\"topbar-brand\">"]],
  // something below the top half changed (O1)
  "below-top-half-changed": [[DASH, "<section id=\"businessProfileSection\" class=\"bf-section\">", "<p>A new line.</p>\n<section id=\"businessProfileSection\" class=\"bf-section\">"]],
  // NAMED (Nov 11 2026, polish): the retired card order read again by GET /api/user/preferences (O1b)
  // NAMED (Nov 11 2026, orbit stage 2): BEFORE the select ended at agent_card_order. AFTER the five goal columns follow it.
  "order-setting-read": [[SERVER, ".select(\"termaximus_active, mist_position, notifications_enabled, preferred_language, agent_card_order, goal_metric, goal_weekly_target, goal_currency, goal_time_zone, goal_set_at\")",
    ".select(\"termaximus_active, mist_position, notifications_enabled, preferred_language, agent_card_order, goal_metric, goal_weekly_target, goal_currency, goal_time_zone, goal_set_at, dashboard_card_order, dashboard_card_custom\")"]],
  // ... and written again by PUT /api/user/preferences (O1b)
  "order-setting-written": [[SERVER, "    if (req.body.notifications_enabled !== undefined) {\n",
    "    if (req.body.dashboard_card_order !== undefined) updates.dashboard_card_order = req.body.dashboard_card_order;\n    if (req.body.notifications_enabled !== undefined) {\n"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[DASH, ORBIT, GUIDE, PRESENCE].forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});
[SERVER, YOURDATA].forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(REPO, f.slice(2)), "utf8")); });
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}
const UI_CSS = lf(fs.readFileSync(path.join(FRONTEND, "css/bizforce-ui.css"), "utf8"));
const BASE = lf(execFileSync("git", ["show", BASELINE + ":" + DASH], { cwd: FRONTEND, maxBuffer: 1 << 27 }).toString("utf8"));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 500) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));

/* ── the old tiles, from BASELINE ── */
const baseGridA = BASE.indexOf("<div class=\"bf-feature-grid cards\">\n") + "<div class=\"bf-feature-grid cards\">\n".length;
const baseGridB = BASE.indexOf("</div>\n<script src=\"/scripts/bf-dashboard-order.js\"></script>");
const BASE_TILES = BASE.slice(baseGridA, baseGridB);
const OLD = [];
{
  const re = /<div class="bf-feature-card card bf-card" data-card="([a-z-]+)"[^>]*>\n[\s\S]*?\n<\/div>\n/g; let m;
  while ((m = re.exec(BASE_TILES))) {
    const a = /<a href="([^"]+)" class="bf-btn"[^>]*>([^<]+)<\/a>/.exec(m[0]);
    OLD.push({ slug: m[1], text: m[0], href: a[1], label: a[2], title: /<h3>([^<]+)<\/h3>/.exec(m[0])[1] });
  }
}
const BASE_DIR = BASE.slice(BASE.indexOf("<div id=\"agentDirectoryLanding\""), BASE.indexOf("<!-- Recent Activity was removed here."));

/* ── fixtures ── */
const TOP = () => ({
  generated_at: "2027-01-20T10:20:00.000Z", days: [],
  visits: { per_day: [0, 0, 0, 2, 4, 0, 0, 0, 0, 0, 5, 0, 0, 4], this_week: 9, last_week: 6, tracked: true },
  store: { connected: true, low_stock: { count: 3, names: ["Blue mug", "Tea tin", "Spoon"] }, orders_this_week: 6, orders_per_day: [0, 4, 0, 0, 0, 4, 0, 0, 1, 0, 0, 0, 3, 2] },
  proposals_pending: 2, cards: { count: 3, views_today: 12, views_7d: 18 }, certifications: { earned: 3, total: 8 }, wallet: { balance: 240, exists: true },
  marketplace: { orders_this_week: 1 }, self_reviews: { latest_at: "2027-01-18T09:00:00.000Z" }, mailbox: { connected: true },
  counts: { crm_customers: 18, prospects: 0, leads: null, sms_subscribers: 5, campaigns: 0, routines: 2, saved_prompts: 4, purchases: 7, bizdoc_documents: 1 },
  media: { used_bytes: 3145728, cap_bytes: 1073741824 }, agents: { running_now: ["seo"] }, _unreadable: ["counts.leads (Lead Radar reads the owner account's leads only)"], cached: false
});
const QUIET = () => Object.assign(TOP(), { proposals_pending: 0, store: { connected: false, low_stock: { count: 0, names: [] }, orders_this_week: 0, orders_per_day: Array(14).fill(0) },
  visits: { per_day: Array(14).fill(0), this_week: 0, last_week: 0, tracked: false } });

const a0 = FILES[DASH].indexOf("<style id=\"orbitStyle\">"), b0 = FILES[DASH].indexOf("</template>") + "</template>".length;
const ORBIT_MARKUP = a0 >= 0 && b0 > a0 ? FILES[DASH].slice(a0, b0) : "";
const CSS = (/<style id="orbitStyle">([\s\S]*?)<\/style>/.exec(FILES[DASH]) || ["", ""])[1];

function page(o) {
  o = o || {};
  const dom = new JSDOM("<!DOCTYPE html><html><head></head><body><textarea id=\"elsewhere\"></textarea><div id=\"editable\" contenteditable=\"true\"></div>" + ORBIT_MARKUP + "</body></html>",
    { url: "https://bizforceai.net/dashboard.html", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  try { w.localStorage.setItem("bf_token", "check-token"); Object.keys(o.local || {}).forEach(k => w.localStorage.setItem(k, o.local[k])); } catch (e) { /* none */ }
  try { Object.keys(o.session || {}).forEach(k => w.sessionStorage.setItem(k, o.session[k])); } catch (e) { /* none */ }
  const fetches = [];
  w.API_URL = "https://api.test";
  w.fetch = (url, init) => {
    fetches.push(String(url));
    const body = o.fail ? null : JSON.parse(JSON.stringify(o.top || TOP()));
    const p = Promise.resolve({ ok: !o.fail, status: o.fail ? 500 : 200, json: () => Promise.resolve(body || { error: "x" }) });
    p.catch(() => {});
    return p;
  };
  const frames = [];
  w.requestAnimationFrame = cb => { frames.push(cb); return frames.length; };
  w.cancelAnimationFrame = () => {};
  const media = { reduce: !!o.reduce, narrow: !!o.narrow };
  w.matchMedia = q => ({ matches: (/reduced-motion: reduce/.test(q) && media.reduce) || (/max-width: 640px/.test(q) && media.narrow), addEventListener() {}, addListener() {} });
  // NAMED (Nov 11 2026, more and even stars): the stage's width may be given (o.stageW), as Chrome measured it; 600 otherwise.
  Object.defineProperty(w.HTMLElement.prototype, "clientWidth", { configurable: true, get() { return this.id === "orbitStage" ? (o.stageW || 600) : 0; } });
  if (o.rects) w.Element.prototype.getBoundingClientRect = function () { return o.rects(this); };
  // NAMED (Nov 11 2026, one living sky): the panel's visibility on the screen and the tab's, set by the check.
  const io = [];
  w.IntersectionObserver = function (cb) { io.push(cb); this.observe = () => {}; this.disconnect = () => {}; };
  let hidden = false;
  Object.defineProperty(w.document, "hidden", { configurable: true, get: () => hidden });
  let err = null;
  try { w.eval(FILES[ORBIT]); } catch (e) { err = e; }
  let clock = 0;
  function run(ms) {   // advance the fake animation clock by ms, frame by frame
    const end = clock + ms;
    while (clock < end) {
      clock += 16;
      const q = frames.splice(0); if (!q.length) { clock = end; break; }
      q.forEach(cb => cb(clock));
    }
  }
  return { dom, w, d: w.document, fetches, err, run, media, frames, io, setHidden: v => { hidden = !!v; } };
}
const settle = () => new Promise(r => setTimeout(r, 30));
const texts = (d, sel) => Array.prototype.map.call(d.querySelectorAll(sel), x => x.textContent);
const gridSlugs = d => Array.prototype.map.call(d.querySelectorAll("#orbitGrid > *"), x => x.getAttribute("data-card") || (x.id === "agentDirectoryLanding" ? "agent-directory" : "?"));

(async () => {
  /* ── O1. structure ── */
  console.log("\n══ O1. every old box kept, in one place, with its link; the rest of the page unchanged ══");
  check("BASELINE's grid held 29 tiles", OLD.length === 29, OLD.length);
  check("the orbit's markup is on the page (style, section, template)", ORBIT_MARKUP.length > 5000);
  const tpl = (/<template id="orbitTools">([\s\S]*?)<\/template>/.exec(FILES[DASH]) || ["", ""])[1];
  const notKept = OLD.filter(t => tpl.indexOf(t.text) === -1 || FILES[DASH].split(t.text).length !== 2).map(t => t.slug);
  check("each of the 29 tiles is in the template byte for byte, once", notKept.length === 0, notKept.join(", "));
  // NAMED (Nov 10 2026, visual match): rebuilt for one grid cell, so its parts and links are checked, not its bytes.
  const tplDir = (/<div id="agentDirectoryLanding"[\s\S]*?\n<\/div>\n/.exec(tpl) || [""])[0];
  const baseBtn = id => (new RegExp("<button type=\"button\" id=\"" + id + "\"[^\\n]*<\\/button>").exec(BASE_DIR) || ["?"])[0];
  check("the AI Agent Directory card is in the template once, with BASELINE's \"Agent Hub\" and \"Full Directory\" buttons byte for byte", BASE_DIR.length > 1000 &&
    FILES[DASH].split("id=\"agentDirectoryLanding\"").length === 2 && tplDir.indexOf(baseBtn("openAgentHubBtn")) !== -1 && tplDir.indexOf(baseBtn("openAgentDirectoryBtn")) !== -1 &&
    /id="openAgentHubBtn"[^>]*onclick="window\.location\.href='agents-hub\.html';">Agent Hub</.test(tplDir) && /id="openAgentDirectoryBtn"[^>]*onclick="window\.location\.href='ai-agents\.html';">Full Directory</.test(tplDir));
  /* NAMED (Nov 11 2026, polish) O1b: the retired card order is gone from the server too. user_preferences keeps its two
     columns (dropping them is a migration, left to the owner), but no code reads, writes, answers or exports them: the
     code is read without its comments, and the Your data entry is required and read as the server runs it. */
  const noComments = t => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
  const SV_CODE = noComments(FILES[SERVER]);
  const prefGet = (/app\.get\("\/api\/user\/preferences"[\s\S]*?\n\}\);\n/.exec(SV_CODE) || [""])[0], prefPut = (/app\.put\("\/api\/user\/preferences"[\s\S]*?\n\}\);\n/.exec(SV_CODE) || [""])[0];
  check("O1b GET /api/user/preferences neither reads nor answers dashboard_card_order or dashboard_card_custom (its select names the five settings it serves)",
    prefGet.length > 200 && !/dashboard_card/.test(prefGet) &&
    // NAMED (Nov 11 2026, orbit stage 2): BEFORE the five settings. AFTER the weekly goal's five columns too (migration 183), after them.
    prefGet.indexOf(".select(\"termaximus_active, mist_position, notifications_enabled, preferred_language, agent_card_order, goal_metric, goal_weekly_target, goal_currency, goal_time_zone, goal_set_at\")") !== -1, prefGet.slice(0, 300));
  check("O1b PUT /api/user/preferences never writes them (an old page sending them is ignored), and no server code names them", prefPut.length > 200 && !/dashboard_card/.test(prefPut) &&
    !/dashboard_card_order|dashboard_card_custom|DASHBOARD_CARD|dashboardCardCustomProblem/.test(SV_CODE), (SV_CODE.match(/[^\n]*dashboard_card[^\n]*/g) || []).slice(0, 3).join(" | "));
  const ydEntry = (() => { try { const m = { exports: {} }; new Function("module", "exports", "require", FILES[YOURDATA])(m, m.exports, n => require(n.charAt(0) === "." ? path.join(REPO, "lib", n) : n)); return (m.exports.DATA || []).filter(e => e.table === "user_preferences")[0]; } catch (e) { return { err: e.message }; } })();
  check("O1b Your data exports user_preferences without them: its entry reads named columns, the retired two left out",
    !!ydEntry && typeof ydEntry.select === "string" && !/dashboard_card/.test(ydEntry.select) && ["user_id", "preferred_language", "agent_card_order", "page_themes", "music_player"].every(c => ydEntry.select.split(/\s*,\s*/).indexOf(c) !== -1),
    JSON.stringify(ydEntry && (ydEntry.select || ydEntry.err)));
  check("the feature grid, its ordering module and its two keys are gone from the page",FILES[DASH].indexOf("bf-dashboard-order.js") === -1 && !/bf_dashboard_order|bf_dashboard_custom/.test(FILES[DASH] + FILES[ORBIT]) &&
    FILES[DASH].indexOf("<div class=\"bf-feature-grid cards\">") === -1);
  const P = page();
  check("bf-orbit.js runs", !P.err, P.err && P.err.message);
  await settle();
  const O = P.w.BFOrbit || {};
  const groups = (O.PORTALS || []).concat(O.UTILITIES ? [O.UTILITIES] : []);
  const placed = {};
  groups.forEach(g => g.tools.forEach(t => { placed[t] = (placed[t] || []).concat(g.key); }));
  const wantMap = {
    grow: ["analytics", "self-reviews", "certifications", "lead-radar", "prospecting", "sms-drip"],
    sell: ["store", "inventory", "marketplace", "services", "crm", "bfc-wallet", "receipts", "crowdfunding", "my-purchases", "garage-sale"],
    connect: ["mailbox", "messages", "business-chat", "digital-cards", "business-identity", "profile-page", "artists"],
    agents: ["agent-directory", "agent-proposals", "integrations", "routines", "saved-prompts"],
    oracle: ["oracle", "mychart", "synastry", "the-third"],
    utilities: ["billing", "media-library", "bizdoc", "calendar", "settings", "your-data"]
  };
  check("the portal map is Grow, Sell, Connect, Agents, Oracle and Utilities as briefed", JSON.stringify(groups.map(g => [g.key, g.tools])) === JSON.stringify(Object.keys(wantMap).map(k => [k, wantMap[k]])),
    JSON.stringify(groups.map(g => [g.key, g.tools])));
  const misplaced = OLD.map(t => t.slug).concat(["agent-directory"]).filter(sl => !placed[sl] || placed[sl].length !== 1);
  check("every old tile and the directory is in exactly one portal or Utilities", misplaced.length === 0, misplaced.join(", "));
  const tools = O.tools ? O.tools() : {};
  check("the template holds a box for every tool of every group (38)", Object.keys(placed).every(sl => !!tools[sl]) && Object.keys(placed).length === 38, Object.keys(placed).filter(sl => !tools[sl]).join(","));
  // every portal's grid shows its tiles with the old link and label (main boxes shown above, so clear them for this pass)
  const Q = page({ local: { bf_main_boxes: JSON.stringify(["billing", "settings"]) } });
  await settle();
  const seen = {};
  for (const g of Q.w.BFOrbit.PORTALS) {
    Q.w.BFOrbit.open(g.key);
    Array.prototype.forEach.call(Q.d.querySelectorAll("#orbitGrid > [data-card]"), box => {
      const a = box.querySelector("a.bf-btn");
      seen[box.getAttribute("data-card")] = { href: a && a.getAttribute("href"), label: a && a.textContent, title: (box.querySelector("h3") || {}).textContent };
    });
  }
  const wrongLink = OLD.filter(t => t.slug !== "billing" && t.slug !== "media-library" && t.slug !== "bizdoc")
    .filter(t => !seen[t.slug] || seen[t.slug].href !== t.href || seen[t.slug].label !== t.label || seen[t.slug].title !== t.title).map(t => t.slug + " " + JSON.stringify(seen[t.slug]));
  check("in its portal's grid every old tile keeps its title, link and button label (26 in portals)", wrongLink.length === 0, wrongLink.join(" | "));
  Q.d.getElementById("orbitCore").click();
  const allLinks = {};
  Array.prototype.forEach.call(Q.d.querySelectorAll("#orbitAllTools a"), a => { allLinks[a.textContent] = a.getAttribute("href"); });
  const utilWrong = OLD.filter(t => ["billing", "media-library", "bizdoc"].indexOf(t.slug) !== -1).filter(t => allLinks[t.title] !== t.href).map(t => t.slug);
  check("the three Utilities tiles keep their links in All tools", utilWrong.length === 0, utilWrong.join(","));
  const header = t => { const i = t.indexOf("<header class=\"topbar bf-glass-panel\">"); return i < 0 ? "" : t.slice(i, t.indexOf("</header>", i) + 9); };
  check("the top bar, with the music button's anchor, is BASELINE's byte for byte", header(BASE).length > 500 && header(FILES[DASH]) === header(BASE));
  const hero = t => t.slice(t.indexOf("<header class=\"hero hq-hero\">"), t.indexOf("<div class=\"bf-start-panel\" id=\"subscribeStartPanel\""));
  check("the hero, the status and the paid banner are BASELINE's byte for byte", hero(BASE).length > 300 && hero(FILES[DASH]) === hero(BASE));
  // from the comment that closes the top half (in both versions), so nothing slips in above Business Profile either
  const below = t => { const i = t.indexOf("<!-- Recent Activity was removed here."); return i < 0 ? "" : t.slice(i); };
  /* NAMED (Nov 11 2026, polish): BEFORE below the top half was BASELINE's byte for byte. AFTER it is BASELINE's with two
     edits and nothing else: #taskPrompt spans both columns by class (bf-span-2) instead of an inline grid-column:1/3 (which
     made a second column on a phone), and the Command Center's style gains the phone-fit rules. */
  const POLISH_BELOW = [
    ["<textarea\nid=\"taskPrompt\"\nplaceholder=\"Tell your AI agent what to do...\"\nstyle=\"\npadding:18px;\nfont-size:16px;\nborder-radius:12px;\nborder:none;\nmin-height:180px;\ngrid-column:1/3;\n\"></textarea>",
      "<textarea\nid=\"taskPrompt\"\nclass=\"bf-span-2\"\nplaceholder=\"Tell your AI agent what to do...\"\nstyle=\"\npadding:18px;\nfont-size:16px;\nborder-radius:12px;\nborder:none;\nmin-height:180px;\n\"></textarea>"],
    [".cc-deck #agentMemorySection{margin:0}\n</style>",
      ".cc-deck #agentMemorySection{margin:0}\n" +
      "/* NAMED (Nov 11 2026, polish): nothing wider than a phone. The AI Agent Tasks form's controls keep to their column\n" +
      "   (#taskPrompt spans both columns by .bf-span-2, which the phone rule folds to one; its old inline grid-column:1/3 made\n" +
      "   a second column there, 400 px wide on a 390 px screen); the Command Center's tab row scrolls inside itself; and the\n" +
      "   top bar's actions wrap rather than push past the edge at 360 px. */\n" +
      ".bf-form-grid input,.bf-form-grid select,.bf-form-grid textarea{box-sizing:border-box;max-width:100%;min-width:0}\n" +
      ".cc-deck .deck-tabs{max-width:100%;min-width:0}\n" +
      "@media (max-width:640px){\n  .bf-form-grid{grid-template-columns:minmax(0,1fr)}\n  .topbar{flex-wrap:wrap}\n  .topbar-actions{min-width:0;flex:1 1 auto}\n}\n</style>"]];
  const basePolished = (() => { try { return POLISH_BELOW.reduce((t, e) => s.replaceOnce(t, e[0], e[1], "polish edit"), below(BASE)); } catch (e) { return "polish edit did not apply: " + e.message; } })();
  check("everything after the top half, Business Profile down, is BASELINE's byte for byte, but for the two named phone-fit edits", below(BASE).length > 10000 && below(FILES[DASH]) === basePolished &&
    below(FILES[DASH]).indexOf("<section id=\"businessProfileSection\"") !== -1, basePolished.slice(0, 80));

  /* ── O2. badges and beams ── */
  console.log("\n══ O2. badges where something needs the member, and beams only from them ══");
  const badgeOf = (d, k) => { const b = d.getElementById("orbitBadge-" + k); return b && !b.hidden ? b.textContent : null; };
  const beamOn = (d, k) => { const g = d.querySelector(".orbit-beam[data-portal=\"" + k + "\"]"); return !!g && !g.hasAttribute("hidden") && g.style.display !== "none"; };
  check("Agents shows 2 (proposals waiting) and Sell 3 (low stock)", badgeOf(P.d, "agents") === "2" && badgeOf(P.d, "sell") === "3", JSON.stringify([badgeOf(P.d, "agents"), badgeOf(P.d, "sell")]));
  check("Grow, Connect and Oracle show no badge", ["grow", "connect", "oracle"].every(k => badgeOf(P.d, k) === null));
  check("a beam runs from Agents and from Sell, and from no other portal", beamOn(P.d, "agents") && beamOn(P.d, "sell") && ["grow", "connect", "oracle"].every(k => !beamOn(P.d, k)));
  check("each beam is a curve to the core with a travelling dot", ["agents", "sell"].every(k => { const g = P.d.querySelector(".orbit-beam[data-portal=\"" + k + "\"]"); return g.querySelector("path.orbit-beam-line") && g.querySelector("circle.orbit-beam-dot"); }) &&
    /@keyframes orbitDot\{0%\{transform:translate\(0px,275px\);opacity:0\}/.test(CSS));
  const Z = page({ top: QUIET() });
  await settle();
  check("with nothing waiting: no badge at all, and no beam", ["grow", "sell", "connect", "agents", "oracle"].every(k => badgeOf(Z.d, k) === null && !beamOn(Z.d, k)));
  check("the badge is named for screen readers through aria-describedby", P.d.querySelector(".orbit-portal[data-portal=\"agents\"]").getAttribute("aria-describedby") === "orbitBadge-agents");

  /* ── O3. the moon ── */
  console.log("\n══ O3. tonight's moon, from the date ══");
  const KNOWN = [["2024-04-08T18:21:00Z", "New moon"], ["2024-04-15T19:13:00Z", "First quarter"], ["2024-04-23T23:49:00Z", "Full moon"], ["2024-05-01T11:27:00Z", "Last quarter"],
    ["2024-04-11T12:00:00Z", "Waxing crescent"], ["2024-04-19T12:00:00Z", "Waxing gibbous"], ["2024-04-27T12:00:00Z", "Waning gibbous"], ["2024-05-05T12:00:00Z", "Waning crescent"],
    ["2025-01-29T12:36:00Z", "New moon"], ["2025-03-14T06:55:00Z", "Full moon"], ["2026-11-24T14:53:00Z", "Full moon"]];
  const moonWrong = KNOWN.filter(([at, name]) => !O.moonPhase || O.moonPhase(Date.parse(at)).name !== name).map(([at, name]) => at + " " + name + " got " + (O.moonPhase && O.moonPhase(Date.parse(at)).name));
  check("the phase is named right on " + KNOWN.length + " known dates (new, full, both quarters, crescents, gibbous)", moonWrong.length === 0, moonWrong.join(" | "));
  const ill = at => O.moonPhase(Date.parse(at)).illumination;
  check("lit fraction: under 3% at a new moon, over 97% at a full moon, 40-60% at the quarters", ill(KNOWN[0][0]) < 0.03 && ill(KNOWN[2][0]) > 0.97 &&
    Math.abs(ill(KNOWN[1][0]) - 0.5) < 0.1 && Math.abs(ill(KNOWN[3][0]) - 0.5) < 0.1, [ill(KNOWN[0][0]), ill(KNOWN[2][0]), ill(KNOWN[1][0]), ill(KNOWN[3][0])].map(x => x.toFixed(3)).join(","));
  const wax = O.moonPath(0.3, 20, 20, 14), wane = O.moonPath(0.7, 20, 20, 14), cres = O.moonPath(0.1, 20, 20, 14);
  check("waxing is lit on the right, waning on the left (the outer arc's sweep)", / A 14 14 0 0 1 20 34 /.test(wax) && / A 14 14 0 0 0 20 34 /.test(wane), wax + " | " + wane);
  check("the terminator: a crescent bulges toward the lit side, a gibbous away from it, and at a quarter it is a straight line",
    / 0 0 0 20 6 Z$/.test(cres) && / 0 0 1 20 6 Z$/.test(wax) && / A 0\.000 14 /.test(O.moonPath(0.25, 20, 20, 14)), cres + " | " + wax);
  const moonSvg = P.d.querySelector(".orbit-portal[data-portal=\"oracle\"] .orbit-moon");
  const tonight = O.moonPhase(Date.now()).name;
  check("the Oracle portal draws tonight's moon, named in its title (" + tonight + ")", !!moonSvg && moonSvg.getAttribute("data-moon") === tonight &&
    moonSvg.querySelector("title").textContent === tonight && !!moonSvg.querySelector("path.orbit-moon-lit"));

  /* ── O4. the main boxes ── */
  console.log("\n══ O4. the main boxes, Swap, and no box shown twice ══");
  const mains = d => Array.prototype.map.call(d.querySelectorAll("#orbitMain > .orbit-main-box"), b => b.getAttribute("data-card"));
  check("Analytics and Store are the two main boxes by default", JSON.stringify(mains(P.d)) === JSON.stringify(["analytics", "store"]), JSON.stringify(mains(P.d)));
  const an = P.d.querySelector("#orbitMain [data-card=\"analytics\"]"), stb = P.d.querySelector("#orbitMain [data-card=\"store\"]");
  // NAMED (Nov 10 2026, visual match): one big number and its label, one green line, the 14-day line; no description.
  const bigOf = b => { const x = b && b.querySelector(".orbit-big"); return x ? [x.querySelector("strong").textContent, x.querySelector("span").textContent] : null; };
  const secondOf = b => { const x = b && b.querySelector("p.orbit-second"); return x ? x.textContent : null; };
  const sparkPts = b => { const x = b.querySelector("svg.orbit-spark polyline.orbit-spark-line"); return x ? x.getAttribute("points").split(" ").length : 0; };
  check("Analytics: 9 big (tracked visits), \"+50% on last week\" (6 last week), and a 14-point line", JSON.stringify(bigOf(an)) === "[\"9\",\"tracked visits\"]" && secondOf(an) === "+50% on last week" && sparkPts(an) === 14,
    JSON.stringify([bigOf(an), secondOf(an), sparkPts(an)]));
  check("Store: 3 big (items low on stock), \"6 orders this week\", and a 14-point line", JSON.stringify(bigOf(stb)) === "[\"3\",\"items low on stock\"]" && secondOf(stb) === "6 orders this week" && sparkPts(stb) === 14,
    JSON.stringify([bigOf(stb), secondOf(stb), sparkPts(stb)]));
  check("each main box keeps its icon, title and Open button, and shows no description", [an, stb].every(b => b.querySelector(".bf-neon-icon") && b.querySelector("h3") && b.querySelector("a.bf-btn") &&
    Array.prototype.every.call(b.querySelectorAll("p"), p => /^orbit-(big|second|live)$/.test(p.className))) &&
    an.querySelector("a.bf-btn").getAttribute("href") === "/analytics-dashboard.html" && stb.querySelector("a.bf-btn").getAttribute("href") === "store-agent.html");
  const zs = Z.d.querySelector("#orbitMain [data-card=\"store\"]");
  const za = Z.d.querySelector("#orbitMain [data-card=\"analytics\"]");
  check("no store: 0 big (items low on stock), the link \"Connect a store to see orders\" to store-agent.html, no orders figure, no line", JSON.stringify(bigOf(zs)) === "[\"0\",\"items low on stock\"]" &&
    !!zs.querySelector("a.orbit-connect") && zs.querySelector("a.orbit-connect").textContent === "Connect a store to see orders" &&
    zs.querySelector("a.orbit-connect").getAttribute("href") === "store-agent.html" && !/orders this week/.test(zs.textContent) && !zs.querySelector("svg.orbit-spark"));
  check("no tracked link: 0 big (tracked visits), the link \"Add tracked links to see visits\" to the analytics page, no line", JSON.stringify(bigOf(za)) === "[\"0\",\"tracked visits\"]" &&
    !!za.querySelector("a.orbit-connect") && za.querySelector("a.orbit-connect").textContent === "Add tracked links to see visits" &&
    za.querySelector("a.orbit-connect").getAttribute("href") === "/analytics-dashboard.html" && !za.querySelector("svg.orbit-spark"));
  P.w.BFOrbit.open("grow");
  check("Analytics is not repeated in Grow's grid", gridSlugs(P.d).indexOf("analytics") === -1 && gridSlugs(P.d).length === 5, gridSlugs(P.d).join(","));
  P.w.BFOrbit.open("sell");
  check("Store is not repeated in Sell's grid", gridSlugs(P.d).indexOf("store") === -1 && gridSlugs(P.d).length === 9, gridSlugs(P.d).join(","));
  // Swap the Store box for CRM System
  const swapBtn = P.d.querySelectorAll("#orbitMain .orbit-swap")[1];
  swapBtn.click();
  const choices = Array.prototype.map.call(P.d.querySelectorAll("#orbitMain .orbit-swap-list button"), b => b.getAttribute("data-tool"));
  check("Swap lists every other tool (37)", choices.length === 37 && choices.indexOf("store") === -1, choices.length);
  P.d.querySelector("#orbitMain .orbit-swap-list button[data-tool=\"crm\"]").click();
  let stored = null; try { stored = P.w.localStorage.getItem("bf_main_boxes"); } catch (e) { stored = "unreadable"; }
  check("the choice is stored in localStorage bf_main_boxes", stored === JSON.stringify(["analytics", "crm"]), stored);
  check("the main boxes are now Analytics and CRM System, CRM with its live line", JSON.stringify(mains(P.d)) === JSON.stringify(["analytics", "crm"]) &&
    JSON.stringify(bigOf(P.d.querySelector("#orbitMain [data-card=\"crm\"]"))) === "[\"18\",\"customers\"]");
  check("CRM is no longer in Sell's grid, and Store is back in it", gridSlugs(P.d).indexOf("crm") === -1 && gridSlugs(P.d).indexOf("store") !== -1, gridSlugs(P.d).join(","));
  const R = page({ local: { bf_main_boxes: stored || "" } });
  await settle();
  check("a reload reads the choice back", JSON.stringify(mains(R.d)) === JSON.stringify(["analytics", "crm"]), JSON.stringify(mains(R.d)));
  P.d.querySelectorAll("#orbitMain .orbit-swap")[0].click();
  P.d.querySelector("#orbitMain .orbit-swap-list button[data-tool=\"crm\"]").click();
  check("choosing the other box's tool swaps the two", JSON.stringify(mains(P.d)) === JSON.stringify(["crm", "analytics"]), JSON.stringify(mains(P.d)));
  const bad = page({ local: { bf_main_boxes: "not json" } });
  await settle();
  check("an unreadable choice falls back to Analytics and Store", JSON.stringify(mains(bad.d)) === JSON.stringify(["analytics", "store"]));
  // no box anywhere twice
  const T = page();
  await settle();
  const twice = [];
  for (const g of T.w.BFOrbit.PORTALS) {
    T.w.BFOrbit.open(g.key);
    const on = Array.prototype.map.call(T.d.querySelectorAll("[data-card], #agentDirectoryLanding"), x => x.getAttribute("data-card") || "agent-directory");
    on.forEach((x, i) => { if (on.indexOf(x) !== i) twice.push(g.key + ":" + x); });
  }
  check("with any portal open, no box is on the page twice", twice.length === 0, twice.join(","));

  /* ── O5. busiest first ── */
  console.log("\n══ O5. busiest first, the busiest drawn wide ══");
  T.w.BFOrbit.open("sell");
  check("Sell: the boxes with a figure first, by figure (CRM 18, My Purchases 7, Inventory 3, Marketplace 1), then BFC Wallet's balance, then the rest in order",
    JSON.stringify(gridSlugs(T.d)) === JSON.stringify(["crm", "my-purchases", "inventory", "marketplace", "bfc-wallet", "services", "receipts", "crowdfunding", "garage-sale"]), gridSlugs(T.d).join(","));
  const wide = Array.prototype.map.call(T.d.querySelectorAll("#orbitGrid > .orbit-box-wide"), x => x.getAttribute("data-card"));
  check("only the busiest box is drawn wide", JSON.stringify(wide) === JSON.stringify(["crm"]), wide.join(","));
  T.w.BFOrbit.open("oracle");
  check("Oracle (no figures): the fixed order, nothing wide", JSON.stringify(gridSlugs(T.d)) === JSON.stringify(["oracle", "mychart", "synastry", "the-third"]) && !T.d.querySelector("#orbitGrid > .orbit-box-wide"));
  T.w.BFOrbit.open("connect");
  check("Connect: Digital Cards first with \"12 visits today\"", gridSlugs(T.d)[0] === "digital-cards" && /12 visits today/.test(T.d.querySelector("#orbitGrid [data-card=\"digital-cards\"]").textContent));

  /* ── O6. wording ── */
  console.log("\n══ O6. no invented number, no unread claim ══");
  const NO_FIGURE = ["services", "receipts", "garage-sale", "messages", "business-chat", "business-identity", "profile-page", "artists", "integrations", "oracle", "mychart", "synastry", "the-third"];
  const invented = [];
  for (const g of T.w.BFOrbit.PORTALS) {
    T.w.BFOrbit.open(g.key);
    NO_FIGURE.forEach(sl => { const b = T.d.querySelector("#orbitGrid [data-card=\"" + sl + "\"]"); if (b && b.querySelector(".orbit-live")) invented.push(sl + ": " + b.querySelector(".orbit-live").textContent); });
  }
  check("a box the route gives no figure for shows its description alone", invented.length === 0, invented.join(" | "));
  const fixtureNumbers = new Set(JSON.stringify(TOP()).match(/\d+(\.\d+)?/g));
  const lines = [];
  for (const g of T.w.BFOrbit.PORTALS) { T.w.BFOrbit.open(g.key); texts(T.d, "#orbitGrid .orbit-live").forEach(x => lines.push(x)); }
  const foreign = lines.filter(x => (x.match(/\d+(\.\d+)?/g) || []).some(num => !fixtureNumbers.has(num) && !/MB|GB|KB|Jan 18/.test(x)));
  check("every number in a live line is one the route gave (" + lines.length + " lines)", lines.length >= 12 && foreign.length === 0, foreign.join(" | "));
  T.w.BFOrbit.open("connect");
  check("Your Inbox says \"Connected\", nothing more", T.d.querySelector("#orbitGrid [data-card=\"mailbox\"] .orbit-live").textContent === "Connected");
  check("nowhere does the orbit claim unread or new mail", !/unread|new mail|new message/i.test(T.d.getElementById("orbitTop").textContent + texts(T.d, ".orbit-live").join(" ")) &&
    !/unread/i.test(FILES[ORBIT].replace(/\/\*[\s\S]*?\*\//g, "")));
  const F = page({ fail: true });
  await settle();
  check("an unreadable route: the boxes keep their descriptions, the orbit says so, and no figure is shown", F.d.querySelectorAll(".orbit-live").length === 0 &&
    /could not be read just now/.test(F.d.getElementById("orbitStatus").textContent) && F.d.querySelectorAll(".orbit-badge:not([hidden])").length === 0);

  /* ── O7. All tools ── */
  console.log("\n══ O7. the core opens All tools ══");
  const core = T.d.getElementById("orbitCore");
  // NAMED (Nov 10 2026, visual match): THIS WEEK, the number, "tracked visits", All tools, in that order; never a percentage.
  const coreParts = c => Array.prototype.filter.call(c.children, x => !x.hidden).map(x => x.textContent);
  check("the core is a button reading This week, 9, tracked visits, All tools", core.tagName === "BUTTON" && JSON.stringify(coreParts(core)) === JSON.stringify(["This week", "9", "tracked visits", "All tools"]),
    JSON.stringify(coreParts(core)));
  check("with no tracked link the core says \"No tracked visits yet\", and shows no number", JSON.stringify(coreParts(Z.d.getElementById("orbitCore"))) === JSON.stringify(["This week", "No tracked visits yet", "All tools"]),
    JSON.stringify(coreParts(Z.d.getElementById("orbitCore"))));
  core.click();
  const all = T.d.getElementById("orbitAllTools");
  const heads = texts(T.d, "#orbitAllTools .orbit-group h3");
  check("All tools opens, grouped Grow, Sell, Connect, Agents, Oracle, Utilities", !all.hidden && JSON.stringify(heads) === JSON.stringify(["Grow", "Sell", "Connect", "Agents", "Oracle", "Utilities"]) &&
    core.getAttribute("aria-expanded") === "true", heads.join(","));
  check("it lists all 38 tools, Utilities with Billing, Media Library, BizDoc, Calendar, Settings, Your Data", T.d.querySelectorAll("#orbitAllTools a").length === 38 &&
    JSON.stringify(texts(T.d, "#orbitAllTools [data-group=\"utilities\"] a")) === JSON.stringify(["Billing", "Media Library", "BizDoc", "Calendar", "Settings", "Your Data"]));
  core.click();
  check("pressing the core again closes it", all.hidden && core.getAttribute("aria-expanded") === "false");

  /* ── O8. the search keys ── */
  console.log("\n══ O8. \"/\" and the quick search ══");
  const K = page();
  await settle();
  const search = K.d.getElementById("orbitSearch");
  const key = (target, k, extra) => { const e = new K.w.KeyboardEvent("keydown", Object.assign({ key: k, bubbles: true, cancelable: true }, extra || {})); target.dispatchEvent(e); return e; };
  check("the search reads \"Go to any tool...\"", search.getAttribute("placeholder") === "Go to any tool...");
  let e1 = key(K.d.body, "/");
  check("\"/\" on the page focuses the search", K.d.activeElement === search && e1.defaultPrevented);
  search.blur();
  const ta = K.d.getElementById("elsewhere"); ta.focus();
  let e2 = key(ta, "/");
  check("\"/\" typed in a textarea is left alone", K.d.activeElement === ta && !e2.defaultPrevented);
  const ce = K.d.getElementById("editable"); ce.focus();
  let e3 = key(ce, "/");
  check("\"/\" in a contenteditable is left alone", !e3.defaultPrevented);
  ta.blur();
  let e4 = key(K.d.body, "/", { ctrlKey: true });
  let e5 = key(K.d.body, "/", { metaKey: true });
  check("Ctrl+/ and Meta+/ are left alone", !e4.defaultPrevented && !e5.defaultPrevented && K.d.activeElement !== search);
  search.focus(); search.value = "inv"; search.dispatchEvent(new K.w.Event("input", { bubbles: true }));
  check("typing filters by title: \"inv\" finds Inventory", JSON.stringify(texts(K.d, "#orbitResults li a")) === JSON.stringify(["Inventory"]) && !K.d.getElementById("orbitResults").hidden);
  search.value = "oracle"; search.dispatchEvent(new K.w.Event("input", { bubbles: true }));
  check("and by portal: \"oracle\" finds the four Oracle tools", JSON.stringify(texts(K.d, "#orbitResults li a")) === JSON.stringify(["Oracle", "My Chart", "Synastry", "The Third"]));
  key(search, "ArrowDown");
  check("ArrowDown moves the selection", K.d.querySelector("#orbitResults li[aria-selected=\"true\"] a").textContent === "My Chart" && search.getAttribute("aria-activedescendant") === "orbitResult-1");
  let went = null; K.w.BFOrbit.go = url => { went = url; };
  key(search, "Enter");
  check("Enter opens the selected tool", went === "mychart.html", went);
  key(search, "Escape");
  check("Escape closes the results", K.d.getElementById("orbitResults").hidden && search.value === "");
  const keyScripts = FILES[GUIDE] + FILES[PRESENCE];
  check("neither the guide nor Termaximus binds \"/\" (no conflict to resolve)", !/key\s*===\s*["']\/["']/.test(keyScripts) && !/["']Slash["']/.test(keyScripts));
  check("the guide's Escape is untouched: the orbit's Escape is bound on its own section, not the document", /root\.addEventListener\("keydown", function \(e\) \{\n    if \(e\.key !== "Escape"/.test(FILES[ORBIT]) &&
    !/document\.addEventListener\("keydown", function \(e\) \{[^}]*Escape/.test(FILES[ORBIT]));
  K.w.BFOrbit.open("grow");
  const growBtn = K.d.querySelector(".orbit-portal[data-portal=\"grow\"]");
  growBtn.focus();
  key(growBtn, "Escape");
  check("Escape inside the orbit folds the open portal's grid", K.w.BFOrbit.state.open === null && K.d.getElementById("orbitGrid").hidden);
  check("each portal is a button named \"Grow, 6 tools\" and so on, with aria-pressed", Array.prototype.every.call(K.d.querySelectorAll(".orbit-portal"), b => b.tagName === "BUTTON" && /^[A-Z][a-z]+, \d+ tools$/.test(b.getAttribute("aria-label")) && b.hasAttribute("aria-pressed")) &&
    K.d.querySelector(".orbit-portal[data-portal=\"grow\"]").getAttribute("aria-label") === "Grow, 6 tools");
  growBtn.click();
  // NAMED (Nov 10 2026, visual match): the others are no longer dimmed (O14 checks the halo and "(open)").
  check("pressing a portal opens it: aria-pressed true, its grid shown, none dimmed", growBtn.getAttribute("aria-pressed") === "true" && !K.d.getElementById("orbitGrid").hidden &&
    K.d.getElementById("orbitGrid").getAttribute("data-portal") === "grow" && K.d.querySelectorAll(".orbit-portal.is-dim").length === 0);
  growBtn.click();
  check("pressing the open portal again folds it", growBtn.getAttribute("aria-pressed") === "false" && K.d.getElementById("orbitGrid").hidden);
  let sess = null; K.d.querySelector(".orbit-portal[data-portal=\"connect\"]").click(); try { sess = K.w.sessionStorage.getItem("bf_orbit_portal"); } catch (e) { /* none */ }
  check("the open portal is remembered in sessionStorage bf_orbit_portal", sess === "connect", sess);
  const M = page({ session: { bf_orbit_portal: "oracle" } });
  await settle();
  check("a remembered portal opens again", M.w.BFOrbit.state.open === "oracle");
  check("a first visit opens the portal with the most attention (Sell: 3 low stock beats 2 proposals)", P.w.BFOrbit.firstPortal(TOP()) === "sell" && T.w.BFOrbit.firstPortal(Object.assign(TOP(), { proposals_pending: 9 })) === "agents");
  check("with nothing needing attention, Sell", Z.w.BFOrbit.state.open === "sell");
  const hover = (d, k) => { const b = d.querySelector(".orbit-portal[data-portal=\"" + k + "\"]"); b.dispatchEvent(new d.defaultView.MouseEvent("mouseenter")); return d.getElementById("orbitPreview"); };
  const pv = hover(T.d, "agents");
  check("hover shows a preview with the portal's top two figures", !pv.hidden && pv.textContent === "Agents: 4 saved prompts · 2 waiting for your approval", pv.textContent);

  /* ── O9. reduced motion ── */
  console.log("\n══ O9. reduced motion: no drift, the turn snaps, the dot still ══");
  const D = page({ top: QUIET(), session: { bf_orbit_portal: "x" } });
  await settle();
  D.w.BFOrbit.fold();
  const b0d = D.w.BFOrbit.state.base; D.run(1000); const b1d = D.w.BFOrbit.state.base;
  check("without reduced motion the portals drift: about 3 degrees a second (one turn in 120 s)", Math.abs((b1d - b0d) - 3) < 0.6, (b1d - b0d).toFixed(2));
  D.d.getElementById("orbitStage").dispatchEvent(new D.w.MouseEvent("mouseenter"));
  const h0 = D.w.BFOrbit.state.base; D.run(1000);
  check("hovering the orbit pauses the drift", D.w.BFOrbit.state.base === h0);
  D.d.getElementById("orbitStage").dispatchEvent(new D.w.MouseEvent("mouseleave"));
  D.w.BFOrbit.open("connect"); D.run(700);
  // NAMED (Nov 10 2026, visual match): "the front" is the lower-left slot, BFOrbit.frontBase(key).
  const front = ((D.w.BFOrbit.state.base - D.w.BFOrbit.frontBase("connect")) % 360 + 360) % 360;
  check("pressing a portal turns it to the front in about 600 ms", front < 0.5 || front > 359.5, front.toFixed(2));
  const RM = page({ reduce: true, top: TOP(), session: { bf_orbit_portal: "x" } });
  await settle();
  RM.w.BFOrbit.fold();
  const r0 = RM.w.BFOrbit.state.base; RM.run(2000);
  check("under reduced motion there is no drift", RM.w.BFOrbit.state.base === r0);
  RM.w.BFOrbit.open("agents");
  const rf = ((RM.w.BFOrbit.state.base - RM.w.BFOrbit.frontBase("agents")) % 360 + 360) % 360;
  check("under reduced motion the turn snaps: no animation, the portal at the front at once", RM.w.BFOrbit.state.turn === null && (rf < 0.01 || rf > 359.99), rf);
  check("under reduced motion the beam's dot is still (is-still, and the CSS stops it)", RM.d.querySelector(".orbit-beam[data-portal=\"agents\"]").classList.contains("is-still") &&
    /@media \(prefers-reduced-motion: reduce\)\{\s*\.orbit-beam-dot\{animation:none;/.test(CSS));
  const HD = page({ top: QUIET(), session: { bf_orbit_portal: "x" } });
  await settle();
  HD.w.BFOrbit.fold();
  Object.defineProperty(HD.d, "hidden", { configurable: true, get: () => true });
  HD.d.dispatchEvent(new HD.w.Event("visibilitychange"));
  const v0 = HD.w.BFOrbit.state.base; HD.run(1000);
  check("while the tab is hidden the orbit stands still", HD.w.BFOrbit.state.base === v0);

  /* ── O10. transform and opacity only ── */
  console.log("\n══ O10. transform and opacity only ══");
  const transitions = (CSS.match(/transition:[^;}]+/g) || []);
  check("every transition moves only opacity or transform", transitions.length > 0 && transitions.every(t => t.replace(/^transition:/, "").split(",").every(part => /^\s*(opacity|transform|none)\b/.test(part))), transitions.join(" | "));
  const frames = (CSS.match(/@keyframes [a-zA-Z]+\{[\s\S]*?\}\}/g) || []);
  // NAMED (Nov 11 2026, one living sky): one keyframe (the beam's dot) became four: the dot and the stars' twinkle, flare and glint.
  // NAMED (Nov 11 2026, orbit stage 2): BEFORE four. AFTER six: the satellites' slow turn (orbitSatSpin) and a phone portal's pulse (orbitPulse) too.
  check("every keyframe sets only transform and opacity (the beam's dot, the stars' twinkle, flare and glint, the satellites' turn and the portal pulse)", frames.length === 6 &&
    frames.map(k => /@keyframes ([a-zA-Z]+)/.exec(k)[1]).sort().join() === "orbitDot,orbitFlare,orbitGlint,orbitPulse,orbitSatSpin,orbitTwinkle" && frames.every(k => (k.replace(/@keyframes [a-zA-Z]+\{/, "").match(/[a-z-]+(?=:)/g) || []).every(p => p === "transform" || p === "opacity")), frames.join(" | "));
  const placeFn = s.definitionOf ? (FILES[ORBIT].match(/  function place\(\) \{[\s\S]*?\n  \}\n/) || [""])[0] : "";
  check("each frame writes only transforms (place: style.transform and a transform attribute)", placeFn.length > 100 && !/\.style\.(?!transform)[a-zA-Z]+\s*=|setAttribute\("(?!transform)/.test(placeFn), placeFn.slice(0, 200));

  /* ── O11. phones ── */
  console.log("\n══ O11. at 640 px and less ══");
  const mob = (/@media \(max-width: 640px\)\{([\s\S]*?)\n  \}/.exec(CSS) || ["", ""])[1];
  // The core takes its own line (flex-basis 100%) and the five portals share the next one, each a fifth of the width.
  check("the orbit becomes a row of portals with their labels (flex, the core on its own line, five equal portals, the ring hidden, no transforms)",
    /\.orbit-stage\{aspect-ratio:auto;display:flex;flex-wrap:wrap;[^}]*min-width:0;max-width:100%\}/.test(mob) && /\.orbit-svg\{display:none\}/.test(mob) &&
    /\.orbit-portal,\.orbit-core\{position:relative;transform:none !important\}/.test(mob) && /\.orbit-portal\{flex:1 1 0;min-width:0;width:auto;/.test(mob) &&
    /\.orbit-core\{order:-1;flex:1 1 100%;/.test(mob) && /orbit-portal-name/.test(FILES[ORBIT]));
  check("the main boxes stack and the grid is one column", /\.orbit-main\{grid-template-columns:1fr\}/.test(mob) && /\.orbit-grid\{grid-template-columns:1fr !important\}/.test(mob));
  const N = page({ narrow: true, session: { bf_orbit_portal: "x" } });
  await settle();
  N.w.BFOrbit.fold(); const n0 = N.w.BFOrbit.state.base; N.run(1000);
  check("on a phone the row does not drift", N.w.BFOrbit.state.base === n0);

  /* ── O12. textContent only ── */
  console.log("\n══ O12. text, never markup ══");
  check("bf-orbit.js writes no markup (innerHTML, outerHTML, insertAdjacentHTML, document.write)", !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(FILES[ORBIT].replace(/\/\*[\s\S]*?\*\//g, "")));
  const X = page({ top: Object.assign(TOP(), { visits: { per_day: Array(14).fill(0), this_week: "<b>9</b>", last_week: 0, tracked: true } }) });
  await settle();
  check("a server string carrying markup stays text", !X.d.querySelector("#orbitTop b") && !X.d.querySelector("#orbitMain b"));

  /* ── O13. one fetch ── */
  console.log("\n══ O13. one read on load and per Refresh, none per portal ══");
  const C = page();
  await settle();
  // NAMED (Nov 11 2026, orbit stage 2): BEFORE one request on load. AFTER two: /top and the first pulse (no since, so no old event); the pulse is
  // read again only on its own timer (checkOrbitStage2), never by a portal, All tools, Swap or Refresh.
  check("one GET /api/dashboard/top and one GET /api/dashboard/pulse on load, and no other request", C.fetches.length === 2 &&
    C.fetches.slice().sort().join() === "https://api.test/api/dashboard/pulse,https://api.test/api/dashboard/top", C.fetches.join(","));
  ["grow", "sell", "connect", "agents", "oracle"].forEach(k => C.d.querySelector(".orbit-portal[data-portal=\"" + k + "\"]").click());
  C.d.getElementById("orbitCore").click();
  C.d.querySelectorAll("#orbitMain .orbit-swap")[0].click();
  await settle();
  check("opening every portal, All tools and Swap reads nothing more", C.fetches.length === 2, C.fetches.length);
  C.d.getElementById("orbitRefresh").click();
  await settle();
  check("Refresh reads the route once more", C.fetches.length === 3 && C.fetches[2] === "https://api.test/api/dashboard/top", C.fetches.length);
  check("the page loads bf-orbit.js once, right after the template", FILES[DASH].split("<script src=\"/scripts/bf-orbit.js\"></script>").length === 2 &&
    FILES[DASH].indexOf("</template>\n<script src=\"/scripts/bf-orbit.js\"></script>") !== -1);

  /* ── O14. the approved look (NAMED Nov 10 2026, visual match) ── */
  console.log("\n══ O14. the approved look: starfield panel, rings, labels, halo, core, search, main boxes, directory ══");
  // a top-level rule's body, by its exact selector (the first one, outside the @media blocks)
  const rule = sel => { const i = CSS.indexOf("\n  " + sel + "{"); if (i < 0) return null; const a = i + 3 + sel.length + 1; return CSS.slice(a, CSS.indexOf("}", a)); };
  const L = page({ session: { bf_orbit_portal: "x" } });
  await settle();
  const svg = L.d.getElementById("orbitSvg");
  const panelCss = rule(".orbit-panel") || "";
  check("the panel: deep background, radius 18, 1 px accent border at 20%, holding the orbit and the search", /background:var\(--bf-bg, #060b1e\)/.test(panelCss) && /border-radius:18px/.test(panelCss) &&
    /border:1px solid rgba\(var\(--bf-accent-a-rgb, 34,211,238\),\.2\)/.test(panelCss) && !!L.d.querySelector("#orbitPanel #orbitStage") && !!L.d.querySelector("#orbitPanel .orbit-search #orbitSearch"), panelCss);
  // NAMED (Nov 11 2026, still stars): the eight plain dots became the Oracle's still stars, checked in O15.
  const ell = Array.prototype.map.call(svg.querySelectorAll("ellipse"), e => e.getAttribute("class") + " " + e.getAttribute("rx") + "/" + e.getAttribute("ry"));
  check("the rings: outer 275/110 (accent at 30%, 1 px), inner 150/60 (violet at 25%, dashed 3 6)", JSON.stringify(ell) === JSON.stringify(["orbit-ring 275/110", "orbit-ring-inner 150/60"]) &&
    rule(".orbit-ring") === "fill:none;stroke:rgba(var(--bf-accent-a-rgb, 34,211,238),.3);stroke-width:1" &&
    rule(".orbit-ring-inner") === "fill:none;stroke:rgba(var(--bf-accent-b-rgb, 208,140,255),.25);stroke-width:1;stroke-dasharray:3 6", JSON.stringify(ell));
  const nameCss = rule(".orbit-portal-name") || "";
  const labelsOut = Array.prototype.every.call(L.d.querySelectorAll(".orbit-portal"), b => { const nm = b.querySelector(".orbit-portal-name"); return !!nm && nm.parentNode === b && !b.querySelector(".orbit-disc .orbit-portal-name"); });
  check("each label sits about 42 units under its circle's centre (radius 27), outside the circle, bold and uppercase", labelsOut && L.w.BFOrbit.VIEW.labelDy === 42 && L.w.BFOrbit.VIEW.portalR === 27 &&
    /top:calc\(50% \+ var\(--os\) \* 42px\)/.test(nameCss) && /white-space:nowrap/.test(nameCss) && /font-weight:700/.test(nameCss) && /font-size:10\.5px/.test(nameCss) &&
    rule(".orbit-portal-title") === "text-transform:uppercase", nameCss);
  L.w.BFOrbit.open("connect");
  const nm = k => L.d.querySelector(".orbit-portal[data-portal=\"" + k + "\"] .orbit-portal-name").textContent;
  check("the open portal reads \"<Name> (open)\", the others their names alone", nm("connect") === "Connect (open)" && ["grow", "sell", "agents", "oracle"].every(k => nm(k) === k.charAt(0).toUpperCase() + k.slice(1)),
    ["grow", "sell", "connect", "agents", "oracle"].map(nm).join(","));
  check("the open portal's halo: r 38 at 10 wide (86 across), accent at 12%, shown only on the open portal", /width:calc\(var\(--os\) \* 86px\)/.test(rule(".orbit-halo") || "") &&
    /border:calc\(var\(--os\) \* 10px\) solid rgba\(var\(--bf-accent-a-rgb, 34,211,238\),\.12\)/.test(rule(".orbit-halo") || "") &&
    rule(".orbit-portal:not(.is-open) .orbit-halo") === "display:none" && L.d.querySelectorAll(".orbit-portal .orbit-halo").length === 5 &&
    rule(".orbit-portal.is-open .orbit-disc") === "inset:calc(var(--os) * -3px);border:1.8px solid var(--bf-accent-a, #22d3ee)");
  const dimmed = Array.prototype.filter.call(L.d.querySelectorAll(".orbit-portal"), b => b.classList.contains("is-dim") || (b.style.opacity !== "" && b.style.opacity !== "1"));
  check("no portal is dimmed: no is-dim, no opacity below 1, no rule for one", dimmed.length === 0 && !/is-dim/.test(CSS) && !/is-dim/.test(FILES[ORBIT].replace(/\/\*[\s\S]*?\*\//g, "")), dimmed.length);
  L.w.BFOrbit.fold();
  check("the core shows a count, never a percentage", !/%/.test(L.d.getElementById("orbitCore").textContent) && !/%/.test(P.d.getElementById("orbitCore").textContent),
    L.d.getElementById("orbitCore").textContent);
  const sb = L.d.querySelector("#orbitPanel .orbit-search");
  const rfb = L.d.getElementById("orbitRefresh");
  check("the search pill: \"Go to any tool...\", a \"/\" key cap and a small Refresh icon button inside it",
    !!sb && sb.querySelector("input").getAttribute("placeholder") === "Go to any tool..." && !!sb.querySelector("kbd.orbit-key") && sb.querySelector("kbd.orbit-key").textContent === "/" &&
    rfb.parentNode === sb && rfb.getAttribute("aria-label") === "Refresh" && rfb.getAttribute("title") === "Refresh" && rfb.textContent.trim() === "" && !!rfb.querySelector("svg") && !rfb.classList.contains("bf-btn") &&
    /border-radius:16px/.test(rule(".orbit-search") || "") && /background:#0a1128/.test(rule(".orbit-search") || ""));
  check("no \"Press / to search\" line anywhere in the top half", !/Press \/ to search/i.test(ORBIT_MARKUP + FILES[ORBIT]) && !/Press \/ to search/i.test(L.d.getElementById("orbitTop").textContent));
  const mb = L.d.querySelector("#orbitMain [data-card=\"analytics\"]");
  const head = mb && mb.querySelector(".orbit-main-head");
  check("a main box: the header row holds the icon, the title and Swap (in that order); then the big number, the green line, the line and Open",
    !!head && JSON.stringify(Array.prototype.map.call(head.children, x => x.tagName + (x.classList.contains("orbit-swap") ? ".swap" : x.classList.contains("bf-neon-icon") ? ".icon" : ""))) === JSON.stringify(["DIV.icon", "H3", "BUTTON.swap"]) &&
    /font-size:27px;font-weight:800/.test(rule(".orbit-big strong") || "") && /color:#7cf0c9/.test(rule(".orbit-main .orbit-main-box p.orbit-second") || "") &&
    /stroke-width:1\.8/.test(rule(".orbit-spark-line") || "") && /stroke-width:5;opacity:\.15/.test(rule(".orbit-spark-glow") || "") &&
    Array.prototype.every.call(L.d.querySelectorAll("#orbitMain > .orbit-main-box p"), p => /^orbit-(big|second|live)$/.test(p.className)));
  // The directory box (layout as rules: no layout engine here; the real-browser harness measures it).
  const dirTpl = (/<div id="agentDirectoryLanding"[\s\S]*?\n<\/div>\n/.exec((/<template id="orbitTools">([\s\S]*?)<\/template>/.exec(FILES[DASH]) || ["", ""])[1]) || [""])[0];
  const dirNames = (dirTpl.match(/<li class="orbit-dir-agent"><span class="bf-neon-icon bf-hq-icon orbit-dir-icon [a-z-]+" aria-hidden="true"><svg[\s\S]*?<\/svg><\/span><span class="orbit-dir-name">[A-Za-z]+<\/span><\/li>/g) || [])
    .map(x => />([A-Za-z]+)<\/span><\/li>$/.exec(x)[1]);
  check("the directory: icon and title, the one line, five agents (SEO, Sales, Content, Analytics, Social), two buttons", /class="orbit-dir bf-glass-panel bf-card"/.test(dirTpl) &&
    /<div class="orbit-dir-head">/.test(dirTpl) && /<h3>AI Agent Directory<\/h3>/.test(dirTpl) &&
    /<p class="orbit-dir-copy bf-compact-sub">Deploy specialists across SEO, sales, content, analytics and social\.<\/p>/.test(dirTpl) &&
    JSON.stringify(dirNames) === JSON.stringify(["SEO", "Sales", "Content", "Analytics", "Social"]) && /<div class="orbit-dir-actions">\s*<button[^\n]*Agent Hub<\/button>\s*<button[^\n]*Full Directory<\/button>\s*<\/div>/.test(dirTpl),
    JSON.stringify(dirNames));
  const agentsCss = rule(".orbit-dir-agents") || "", agentCss = rule(".orbit-dir-agent") || "";
  const colGap = Number(((/gap:(\d+)px (\d+)px/.exec(agentsCss)) || [0, 0, 0])[2]);
  check("the agents: a wrapping row, 44 px circles at least 12 px apart, never in fixed columns", /display:flex/.test(agentsCss) && /flex-wrap:wrap/.test(agentsCss) && !/grid/.test(agentsCss) && colGap >= 12 &&
    /width:44px;height:44px/.test(rule(".orbit-dir-agent .bf-hq-icon.orbit-dir-icon") || ""), agentsCss);
  check("each agent's column is at least as wide as its circle and its name, on one line", /flex:0 0 auto/.test(agentCss) && /min-width:56px/.test(agentCss) && !/(^|;)width:/.test(agentCss) &&
    /white-space:nowrap/.test(rule(".orbit-dir-name") || ""), agentCss);
  const actCss = rule(".orbit-dir-actions") || "";
  check("the two buttons side by side, and the box two columns wide (one on a phone)", /display:flex/.test(actCss) && !/flex-direction:column/.test(actCss) && rule(".orbit-grid .orbit-dir") === "grid-column:span 2" &&
    /\.orbit-grid \.orbit-box-wide,\.orbit-grid \.orbit-dir\{grid-column:auto\}/.test(CSS), actCss);
  check("the old landing's squeezing rules are gone from bizforce-ui.css", !/bf-directory-preview|bf-agent-icon-grid|bf-agent-icon-block|bf-agent-icon-lg|bf-hq-icon\.bf-agent-icon|bf-directory-heading/.test(UI_CSS));

  { // O15 in its own scope
  /* ── O15. the still Oracle stars (NAMED Nov 11 2026, still stars) ── */
  console.log("\n══ O15. the still Oracle stars: Oracle's shape, never animated, never on a portal, the core, a label or the search ══");
  const ORACLE = lf(fs.readFileSync(path.join(FRONTEND, "oracle.html"), "utf8"));
  const draw = (/function drawStarAt\(px, py, star, alpha\) \{[\s\S]*?\n    \}\n/.exec(ORACLE) || [""])[0];
  const make = (/function makeStar\(minR, maxR\) \{[\s\S]*?\n    \}\n/.exec(ORACLE) || [""])[0];
  const S0 = page();
  const B = S0.w.BFOrbit || {};
  const OS = B.ORACLE_STAR || {};
  // Oracle's own numbers, read from oracle.html's canvas starfield, against the copy's.
  const oracleNums = {
    haloR: /var haloR = star\.r \* ([\d.]+);/, haloAlpha: /\(alpha \* ([\d.]+)\) \+ "\)"\);\n      halo\.addColorStop\(1/, spikeLen: /var spikeLen   = star\.r \* ([\d.]+);/,
    spikeAlpha: /var spikeAlpha = alpha \* ([\d.]+);/, spikeWidth: /ctx\.lineWidth = ([\d.]+);/, coreR: /var coreR = star\.r \* ([\d.]+);/,
    coreEdgeAlpha: /\(alpha \* ([\d.]+)\) \+ "\)"\);\n      ctx\.fillStyle = core;/, brightAbove: /if \(star\.baseAlpha > ([\d.]+)\) \{/, brightMix: /\(255 - tint\.r\) \* ([\d.]+)\)/
  };
  const read = Object.keys(oracleNums).map(k => [k, Number((oracleNums[k].exec(draw) || [])[1]), OS[k]]);
  check("O15 the copy draws with oracle.html's drawStarAt numbers: halo 2.2 r at alpha x .5, rays 6 r each way .8 wide at alpha x .5, core .7 r fading to alpha x .15, whitened 60% above .7",
    draw.length > 500 && read.every(([, a, b]) => a === b && typeof b === "number"), JSON.stringify(read));
  const tints = ((/var TINTS = \[([\s\S]*?)\];/.exec(ORACLE) || ["", ""])[1].match(/\{ r: \d+,\s+g: \d+,\s+b: \d+\s*\}/g) || []).map(t => t.replace(/\s+/g, " "));
  const layers = (/var LAYERS = \[([\s\S]*?)\];/.exec(ORACLE) || ["", ""])[1].match(/minR: ([\d.]+), maxR: ([\d.]+)/g) || [];
  check("O15 and with makeStar's tints, sizes and alphas: the same three tints one star in six, the three layers' radii, alpha .12 + u^2 x .8, rays only when large and bright",
    JSON.stringify(tints.map(t => JSON.parse(t.replace(/(\w+):/g, "\"$1\":")))) === JSON.stringify(B.STAR_TINTS) &&
    JSON.stringify(layers.map(l => l.match(/[\d.]+/g).map(Number))) === JSON.stringify((B.STAR_LAYERS || []).map(l => [l.minR, l.maxR])) &&
    /if \(Math\.random\(\) < 1 \/ 6\)/.test(ORACLE) && /var baseAlpha = 0\.12 \+ Math\.pow\(Math\.random\(\), 2\) \* 0\.8;/.test(make) &&
    /spiked: \(r > \(minR \+ \(maxR - minR\) \* 0\.6\)\) && \(baseAlpha > 0\.6\)/.test(make) &&
    /var tint = rnd\(\) < 1 \/ 6 \?/.test(FILES[ORBIT]) && /var alpha = 0\.12 \+ Math\.pow\(rnd\(\), 2\) \* 0\.8;/.test(FILES[ORBIT]) &&
    /spiked: r > L\.minR \+ \(L\.maxR - L\.minR\) \* 0\.6 && alpha > 0\.6/.test(FILES[ORBIT]), JSON.stringify(tints));
  S0.dom.window.close();

  /* NAMED BEFORE → AFTER (Nov 11 2026, more and even stars). BEFORE: 14 to 18 stars on a synthetic 760 x 400 panel and
     a synthetic phone row. AFTER: the panel's own boxes as Chrome 156 measured them at 1440, 1024 and 390 px (the panel,
     the ring's stage, each portal, disc, label and title, the core and the search; the hidden results, status and preview
     lines at nothing), and the count is the owner's density rule: 40 on the 1152 x 565 panel, the same stars per square
     pixel elsewhere, never under 18 or over 48. Every other O15 promise is kept, at all three sizes. */
  const GEO = {
    1440: { narrow: false, panel: [0, 0, 1152, 610.2], stage: [86, 15, 980, 475.6], say: [256, 494.6, 640, 41.6], search: [316, 546.2, 520, 45], core: [527, 196.6, 98, 98],
      btn: [[160.2, 157.7, 77.8, 77.8], [304.1, 334.9, 77.8, 77.8], [770.1, 334.9, 77.8, 77.8], [914, 157.7, 77.8, 77.8], [537.1, 48.2, 77.8, 77.8]],
      disc: [[160.2, 157.7, 77.8, 77.8], [299.8, 330.6, 86.4, 86.4], [770.1, 334.9, 77.8, 77.8], [914, 157.7, 77.8, 77.8], [537.1, 48.2, 77.8, 77.8]],
      name: [[181.1, 250.8, 36.1, 12.6], [309.5, 428, 67.1, 12.6], [781.4, 428, 55.2, 12.6], [930, 250.8, 45.7, 12.6], [553.7, 141.3, 44.6, 12.6]],
      title: [[181.1, 249.8, 36.1, 14], [309.5, 427, 25.6, 14], [781.4, 427, 55.2, 14], [930, 249.8, 45.7, 14], [553.7, 140.3, 44.6, 14]] },
    1024: { narrow: false, panel: [0, 0, 976, 591.7], stage: [17, 15, 942, 457.1], say: [168, 476.1, 640, 41.6], search: [228, 527.7, 520, 45], core: [440.9, 189.5, 94.2, 94.2],
      btn: [[88.3, 152.2, 74.8, 74.8], [226.7, 322.5, 74.8, 74.8], [674.5, 322.5, 74.8, 74.8], [812.9, 152.2, 74.8, 74.8], [450.6, 46.9, 74.8, 74.8]],
      disc: [[88.3, 152.2, 74.8, 74.8], [222.6, 318.4, 83.1, 83.1], [674.5, 322.5, 74.8, 74.8], [812.9, 152.2, 74.8, 74.8], [450.6, 46.9, 74.8, 74.8]],
      name: [[107.6, 241.5, 36.1, 12.6], [230.6, 411.8, 67.1, 12.6], [684.3, 411.8, 55.2, 12.6], [827.4, 241.5, 45.7, 12.6], [465.7, 136.2, 44.6, 12.6]],
      title: [[107.6, 240.5, 36.1, 14], [230.6, 410.8, 25.6, 14], [684.3, 410.8, 55.2, 14], [827.4, 240.5, 45.7, 14], [465.7, 135.2, 44.6, 14]] },
    /* NAMED (Nov 11 2026, polish): BEFORE the phone panel was 342 x 300.6 (padding 28 / 14, the stage's 6 px below), with
       no room for a large rayed star. AFTER more open sky, re-measured in Chrome 156: padding 104 above and 56 below, 32 px
       under the portal row; 342 x 444.6, everything 76 px lower. Sell's label keeps its " (open)" width. */
    390: { narrow: true, panel: [0, 0, 342, 444.6], stage: [11, 105, 320, 180], say: [11, 289, 320, 41.6], search: [11, 340.6, 320, 45], core: [11, 109, 320, 64],
      btn: [[11, 181, 57.6, 72], [76.6, 181, 57.6, 72], [142.2, 181, 57.6, 72], [207.8, 181, 57.6, 72], [273.4, 181, 57.6, 72]],
      disc: [[16.8, 185, 46, 46], [82.4, 185, 46, 46], [148, 185, 46, 46], [213.6, 185, 46, 46], [279.2, 185, 46, 46]],
      name: [[23.8, 237, 32, 12], [76.8, 237, 57.3, 12], [146.8, 237, 48.3, 12], [216.6, 237, 39.9, 12], [282.8, 237, 38.9, 12]],
      title: [[23.8, 236, 32, 14], [76.8, 236, 22, 14], [146.8, 236, 48.3, 14], [216.6, 236, 39.9, 14], [282.8, 236, 38.9, 14]] }
  };
  const KEYS = ["grow", "sell", "connect", "agents", "oracle"];
  function rectsFor(G) {
    return function (node) {
      const box = a => ({ left: a[0], top: a[1], width: a[2], height: a[3], right: a[0] + a[2], bottom: a[1] + a[3], x: a[0], y: a[1] });
      if (node.id === "orbitPanel") return box(G.panel);
      if (node.id === "orbitStage") return box(G.stage);
      if (node.id === "orbitCore") return box(G.core);
      if (node.id === "orbitSay") return box(G.say);
      if (node.classList && node.classList.contains("orbit-search")) return box(G.search);
      const portal = node.closest && node.closest(".orbit-portal");
      const i = portal ? KEYS.indexOf(portal.getAttribute("data-portal")) : -1;
      if (i >= 0 && node.classList.contains("orbit-portal")) return box(G.btn[i]);
      if (i >= 0 && node.classList.contains("orbit-disc")) return box(G.disc[i]);
      if (i >= 0 && node.classList.contains("orbit-portal-name")) return box(G.name[i]);
      if (i >= 0 && node.classList.contains("orbit-portal-title")) return box(G.title[i]);
      return box([0, 0, 0, 0]);
    };
  }
  // NAMED (Nov 11 2026, one living sky): re-measured in Chrome 156 with the reserved row (#orbitSay, the preview and status
  // lines at a fixed height above the search); a page may be given its own copy of the boxes, to change the panel's size.
  const skyPage = (W0, G0) => { const G = G0 || GEO[W0]; return page({ narrow: G.narrow, rects: rectsFor(G), stageW: G.stage[2] }); };
  const starsOf = P0 => Array.prototype.map.call(P0.d.querySelectorAll("#orbitStars g.orbit-star"), g => {
    const core = g.querySelector("circle.orbit-star-core"), halo = g.querySelector("circle.orbit-star-halo");
    const r = Number(g.getAttribute("data-r")), a = Number(g.getAttribute("data-alpha")), spiked = g.getAttribute("data-spiked") === "1";
    return { g, r, a, spiked, size: g.getAttribute("data-size"), cell: g.getAttribute("data-cell"), x: Number(core && core.getAttribute("cx")), y: Number(core && core.getAttribute("cy")), core, halo, rays: g.querySelectorAll("rect.orbit-star-ray") };
  });
  // The owner's rule, written here and not read from the page: 40 on the 1152 x 565 panel, the same density, 18 to 48.
  const ruleCount = (w, h) => Math.max(18, Math.min(48, Math.round(40 * w * h / (1152 * 565))));
  const W = skyPage(1440);
  const wide = starsOf(W);
  const stops = (P0, fill) => { const id = (/url\(#([^)]+)\)/.exec(fill || "") || [])[1]; const gr = id && P0.d.getElementById(id); return gr ? Array.prototype.map.call(gr.querySelectorAll("stop"), st => [Number(st.getAttribute("offset")), st.getAttribute("stop-color"), Number(st.getAttribute("stop-opacity"))]) : []; };
  const near = (p, q) => Math.abs(p - q) < 0.002;
  // A tint lightened toward white by f, as an rgb() string; the Oracle's four colours.
  const lighten = (rgb, f) => "rgb(" + rgb.match(/\d+/g).map(Number).map(v => Math.round(v + (255 - v) * f)).join(",") + ")";
  const COLOURS = ["rgb(255,255,255)", "rgb(34,211,238)", "rgb(139,92,246)", "rgb(251,191,36)"];
  const shapeBad = wide.filter(st => {
    const h = stops(W, st.halo && st.halo.getAttribute("fill")), c = stops(W, st.core && st.core.getAttribute("fill"));
    const tint = h[0] && h[0][1];
    // NAMED (Nov 11 2026, one living sky): a white star is drawn as the Oracle draws it; a tinted one carries its tint
    // clearly: halo at alpha x .8, rays at alpha x .8, core's centre the tint 35% toward white, its edge at alpha x .6, alpha .5 at least.
    const tinted = !!tint && tint !== "rgb(255,255,255)";
    const okHalo = !!st.halo && near(Number(st.halo.getAttribute("r")), st.r * 2.2) && h.length === 2 && near(h[0][2], st.a * (tinted ? 0.8 : 0.5)) && h[1][2] === 0 && h[0][1] === h[1][1];
    const white = !!c[0] && (tinted ? c[0][1] === lighten(tint, 0.35) && st.a >= 0.5 : st.a > 0.7 ? c[0][1] === "rgb(255,255,255)" : c[0][1] === tint);
    const okCore = !!st.core && near(Number(st.core.getAttribute("r")), st.r * 0.7) && c.length === 2 && near(c[0][2], st.a) && near(c[1][2], st.a * (tinted ? 0.6 : 0.15)) && c[1][1] === tint && white;
    const okRays = st.spiked ? st.rays.length === 2 && Array.prototype.every.call(st.rays, ry => { const s2 = stops(W, ry.getAttribute("fill")); const wd = Number(ry.getAttribute("width")), ht = Number(ry.getAttribute("height"));
      return s2.length === 3 && s2[0][2] === 0 && near(s2[1][2], st.a * (tinted ? 0.8 : 0.5)) && s2[1][1] === tint && s2[2][2] === 0 && ((near(wd, 0.8) && Math.abs(ht - st.r * 12) < 0.01) || (near(ht, 0.8) && Math.abs(wd - st.r * 12) < 0.01)); }) &&
      !!st.g.querySelector("g.orbit-star-rays > rect.orbit-star-ray") : st.rays.length === 0;
    const okGlint = st.size === "large" ? !!st.g.querySelector("g.orbit-star-glint > circle") : !st.g.querySelector(".orbit-star-glint");
    return !(okHalo && okCore && okRays && okGlint);
  });
  check("O15 every star is Oracle's shape: a radial halo, a sharp core whitened on the brightest white ones and lightened toward white (not white) on the tinted ones, thin cross rays on the large bright ones (at least two), and a glint on each large one", shapeBad.length === 0 &&
    wide.filter(x => x.spiked && x.r >= 1.4).length >= 2, shapeBad.map(x => x.g.getAttribute("data-star")).join(","));
  // The colour each star is drawn in, read from its halo's gradient (not from its data-tint).
  const colourOf = (P0, st) => (stops(P0, st.halo.getAttribute("fill"))[0] || [])[1];
  const tintsSeen = new Set(wide.map(st => colourOf(W, st)));
  check("O15 in Oracle's colours only: white, cyan, violet and gold", [...tintsSeen].every(t => COLOURS.indexOf(t) !== -1) && tintsSeen.has("rgb(255,255,255)"), [...tintsSeen].join(" "));
  // NAMED (Nov 11 2026, one living sky): "none animated" became "no POSITION animation". The star's own group never
  // animates or transitions; only the halo, core, rays and glint do, each with ONE animation of its own, on keyframes that
  // change opacity and scale() and nothing else; the rays and glint scale about their own centre.
  const css0 = CSS.replace(/\/\*[\s\S]*?\*\//g, "");
  const starRules = (css0.match(/[^{}]*orbit-star[^{}]*\{[^}]*\}/g) || []).map(r => r.trim());
  const animRules = starRules.filter(r => /animation(?!-play-state)|transition/.test(r) && !/animation:none !important\}$|transition:none !important\}$/.test(r));
  const wantAnim = [".orbit-star-halo,.orbit-star-core{animation:orbitTwinkle var(--tw-dur, 4s) ease-in-out var(--tw-delay, 0s) infinite}",
    ".orbit-star-rays{animation:orbitFlare var(--tw-dur, 4s) ease-in-out var(--tw-delay, 0s) infinite}",
    ".orbit-star-glint{opacity:0;animation:orbitGlint var(--gl-dur, 10s) ease-in-out var(--gl-delay, 0s) infinite}"];
  const frames = {};
  (css0.match(/@keyframes (orbit(?:Twinkle|Flare|Glint|Star\w*))\{((?:[^{}]*\{[^}]*\})*)\}/g) || []).forEach(k => { const m = /@keyframes (\w+)\{([\s\S]*)\}$/.exec(k); frames[m[1]] = m[2]; });
  const declsOf = body => (body.match(/\{([^}]*)\}/g) || []).map(b => b.slice(1, -1)).join(";").split(";").filter(Boolean).map(d => d.split(":").map(x => x.trim()));
  const onlyOpacityScale = body => declsOf(body).every(([p, v]) => p === "opacity" || (p === "transform" && /^scale\([\d.]+\)$/.test(v)));
  const TW = B.STAR_TWINKLE || {};
  const ops = name => declsOf(frames[name] || "").filter(([p]) => p === "opacity").map(([, v]) => Number(v));
  const scales = name => declsOf(frames[name] || "").filter(([p]) => p === "transform").map(([, v]) => Number(/[\d.]+/.exec(v)[0]));
  check("O15 no POSITION animation: the star's group has animation:none and no transition; the halo and core twinkle, the rays flare and the glint flashes, each part with one animation, on keyframes of opacity and scale() only",
    starRules.indexOf(".orbit-star{animation:none !important}") !== -1 && starRules.indexOf(".orbit-star,.orbit-star *{transition:none !important}") !== -1 &&
    JSON.stringify(animRules) === JSON.stringify(wantAnim) && Object.keys(frames).sort().join() === "orbitFlare,orbitGlint,orbitTwinkle" &&
    Object.keys(frames).every(k => onlyOpacityScale(frames[k])) && !/@keyframes orbitTwinkle[^@]*transform/.test(css0) &&
    starRules.indexOf(".orbit-star-rays,.orbit-star-glint{transform-box:fill-box;transform-origin:center}") !== -1 && !/Math\.random/.test(FILES[ORBIT]),
    JSON.stringify({ animRules, frames }));
  check("O15 the twinkle is the brief's: halo and core between 55% and 100%, the rays' scale .8 to 1.15 with them, the glint brighter (to 1.25), matching STAR_TWINKLE",
    JSON.stringify(ops("orbitTwinkle").sort()) === JSON.stringify([0.55, 1]) && Math.min(...ops("orbitTwinkle")) === TW.low &&
    Math.min(...scales("orbitFlare")) === TW.flareMin && Math.max(...scales("orbitFlare")) === TW.flareMax && Math.max(...scales("orbitGlint")) === 1.25 &&
    Math.max(...ops("orbitGlint")) === 1 && Math.min(...ops("orbitGlint")) === 0 && TW.minDur === 2.5 && TW.maxDur === 6 && TW.glintMin === 6 && TW.glintMax === 14,
    JSON.stringify({ tw: ops("orbitTwinkle"), flare: scales("orbitFlare"), glint: scales("orbitGlint"), TW }));
  const rmBlock = (/@media \(prefers-reduced-motion: reduce\)\{([\s\S]*?)\n  \}/.exec(css0) || ["", ""])[1];
  check("O15 under reduced motion no twinkle and no glint: every star part's animation off, the glint not shown, so each shines steadily at full",
    /\n\s*\.orbit-star \*\{animation:none !important\}/.test(rmBlock) && /\n\s*\.orbit-star-glint\{display:none\}/.test(rmBlock), rmBlock);
  check("O15 the twinkle rests while hidden: one rule pauses every star part under .is-paused, toggled by visibilitychange and an IntersectionObserver",
    starRules.indexOf(".orbit-stars.is-paused .orbit-star *{animation-play-state:paused}") !== -1 && /document\.addEventListener\("visibilitychange", starsPause\);/.test(FILES[ORBIT]) &&
    /new IntersectionObserver\(/.test(FILES[ORBIT]));
  { // paused, measured on the page: the tab hidden, then the panel off the screen
    const H = skyPage(1440), sv0 = H.d.getElementById("orbitStars");
    const before = sv0.classList.contains("is-paused");
    H.setHidden(true); H.d.dispatchEvent(new H.w.Event("visibilitychange"));
    const whenHidden = sv0.classList.contains("is-paused");
    H.setHidden(false); H.d.dispatchEvent(new H.w.Event("visibilitychange"));
    const back = sv0.classList.contains("is-paused");
    H.io.forEach(cb => cb([{ isIntersecting: false }]));
    const offScreen = sv0.classList.contains("is-paused");
    H.io.forEach(cb => cb([{ isIntersecting: true }]));
    const onScreen = sv0.classList.contains("is-paused");
    check("O15 paused while the tab is hidden and while the panel is off the screen, running again when it is back", !before && whenHidden && !back && offScreen && !onScreen && H.io.length >= 1,
      JSON.stringify({ before, whenHidden, back, offScreen, onScreen, observers: H.io.length }));
    H.dom.window.close();
  }
  check("O15 drawn once at start (then on load, resize and a change in the panel's WIDTH), and laid out again only when the width changed",
    (FILES[ORBIT].match(/\n  drawStars\(\);\n/g) || []).length === 1 && /var key = starsWidth\(\);\n    if \(key === starsDrawn\) return;/.test(FILES[ORBIT]) &&
    /new ResizeObserver\(function \(\) \{ if \(starsWidth\(\) !== starsDrawn\) drawStars\(\); \}\)/.test(FILES[ORBIT]));
  check("O15 the stars keep Oracle's mix: STAR_LAYERS holds oracle.html's own counts (240, 120, 50), which give the small, medium and large shares",
    JSON.stringify((B.STAR_LAYERS || []).map(l => l.count)) === JSON.stringify(((/var LAYERS = \[([\s\S]*?)\];/.exec(ORACLE) || ["", ""])[1].match(/count: (\d+)/g) || []).map(c => Number(c.slice(7)))) &&
    JSON.stringify((B.STAR_LAYERS || []).map(l => l.count)) === "[240,120,50]");
  W.dom.window.close();
  // Clear of everything, measured here from the boxes, not by the layout's own list: wide, every place on the ring a portal
  // disc's box (r 30 open) or its label can drift to, and the core (r 34); phone, each disc, label and the core's box; both,
  // the search.
  // NAMED (Nov 11 2026, one living sky): and, in every open state, the open halo (r 43 x the scale) wherever a portal can
  // be, the widest label with " (open)" (the widest title plus " (open)" as Chrome measured it on Sell), the reserved row,
  // with each star's reach at its rays' longest flare (6 x 1.15).
  function clashes(list, G) {
    const bad = [];
    const hitBox = (st, b) => { const dx = Math.max(b[0] - st.x, 0, st.x - (b[0] + b[2])), dy = Math.max(b[1] - st.y, 0, st.y - (b[1] + b[3])); return dx * dx + dy * dy < st.reach * st.reach; };
    const maxTitle = Math.max(...G.title.map(t => t[2])), openW = G.name[1][2] - G.title[1][2], labelW = maxTitle + openW;
    list.forEach(st => {
      st.reach = st.r * (st.spiked ? 6 * 1.15 : 2.2);
      if (hitBox(st, G.search)) bad.push(st.g.getAttribute("data-star") + " on the search");
      if (hitBox(st, G.say)) bad.push(st.g.getAttribute("data-star") + " in the preview and status row");
      if (!G.narrow) {
        const sc = G.stage[2] / 680, ox = G.stage[0], oy = G.stage[1];
        for (let a = 0; a < 360; a += 1) {
          const rad = a * Math.PI / 180, px = ox + (340 + 275 * Math.sin(rad)) * sc, py = oy + (160 + 110 * Math.cos(rad)) * sc;
          if (hitBox(st, [px - 30 * sc, py - 30 * sc, 60 * sc, 60 * sc])) { bad.push(st.g.getAttribute("data-star") + " on a portal at " + a); break; }
          if (Math.hypot(st.x - px, st.y - py) < 43 * sc + st.reach) { bad.push(st.g.getAttribute("data-star") + " under an open halo at " + a); break; }
          if (hitBox(st, [px - labelW / 2, py + 42 * sc - 7, labelW, 14])) { bad.push(st.g.getAttribute("data-star") + " under an open label at " + a); break; }
        }
        if (Math.hypot(st.x - (ox + 340 * sc), st.y - (oy + 160 * sc)) < 34 * sc + st.reach) bad.push(st.g.getAttribute("data-star") + " on the core");
      } else {
        if (hitBox(st, G.core)) bad.push(st.g.getAttribute("data-star") + " on the core");
        for (let i = 0; i < 5; i++) {
          const d = G.disc[i], cell = G.btn[i];
          if (hitBox(st, d)) bad.push(st.g.getAttribute("data-star") + " on a portal");
          if (Math.hypot(st.x - (d[0] + d[2] / 2), st.y - (d[1] + d[3] / 2)) < 43 * 46 / 54 + st.reach) bad.push(st.g.getAttribute("data-star") + " under an open halo");
          if (hitBox(st, [cell[0], G.name[i][1], cell[2], G.name[i][3]])) bad.push(st.g.getAttribute("data-star") + " under an open label");
        }
      }
      const edge = G.narrow ? 3 : 0;
      if (st.x - st.reach < edge || st.y - st.reach < edge || st.x + st.reach > G.panel[2] - edge || st.y + st.reach > G.panel[3] - edge) bad.push(st.g.getAttribute("data-star") + " off the panel's edge");
    });
    return bad;
  }
  // NAMED (Nov 11 2026, one living sky): the preview and status lines share one row above the search, always there at a
  // fixed height, each line laid over it (absolutely) and cut at two lines, so showing or hiding either never changes the
  // panel's height (the browser harness measures it).
  const sayRow = (/<div class="orbit-say" id="orbitSay">\n\s*<p class="orbit-preview" id="orbitPreview" role="status" hidden><\/p>\n\s*<p class="orbit-status" id="orbitStatus" role="status"><\/p>\n\s*<\/div>\n\s*<div class="orbit-search" data-tmx-avoid>/.exec(ORBIT_MARKUP) || [""])[0];   // NAMED (Nov 11 2026, polish): the search is marked for the mist to keep clear of
  check("O15 a reserved row above the search holds the preview and status lines at a fixed height (2.6rem, each line over it and cut at two lines), the status stepping back while a preview shows",
    !!sayRow && ORBIT_MARKUP.split("id=\"orbitStatus\"").length === 2 && ORBIT_MARKUP.split("id=\"orbitPreview\"").length === 2 &&
    starRules.length > 0 && /\n  \.orbit-say\{height:2\.6rem;margin:4px auto 0;max-width:640px;line-height:1\.4\}/.test(CSS) &&
    /\n  \.orbit-say > p\{position:absolute;left:0;right:0;top:0;margin:0;[^}]*-webkit-line-clamp:2;max-height:2\.6rem\}/.test(CSS) &&
    /\n  \.orbit-preview:not\(\[hidden\]\) \+ \.orbit-status\{visibility:hidden\}/.test(CSS) && !/\.orbit-say\{[^}]*min-height/.test(CSS), sayRow.length);
  const skyReport = {};
  for (const W0 of [1440, 1024, 390]) {
    const G = GEO[W0], P1 = skyPage(W0), list = starsOf(P1), n = list.length, w = G.panel[2], h = G.panel[3];
    const sky = (P1.d.getElementById("orbitStars").getAttribute("data-sky") || "").split(",").map(Number);
    const cols = sky[1], rows = sky[2], cw = w / cols, ch = h / rows;
    skyReport[W0] = { count: n, cols, rows, skipped: sky[3], reused: sky[4], asMedium: sky[5], dimmed: sky[6], unplaced: sky[7] };
    const want = ruleCount(w, h);
    check("O15 " + W0 + " px: " + want + " stars, the density rule's count for a " + w + " x " + h + " panel (40 on 1152 x 565, 18 to 48)",
      n === want && sky[0] === want && sky[7] === 0, n + " " + sky.join(","));
    const q = [0, 0, 0, 0];
    list.forEach(st => q[(st.y < h / 2 ? 0 : 2) + (st.x < w / 2 ? 0 : 1)]++);
    check("O15 " + W0 + " px: each quadrant holds 20% to 30% of them, and each half 40% to 60% (top-left, top-right, bottom-left, bottom-right " + q.join(", ") + ")",
      n > 0 && q.every(v => v >= 0.2 * n && v <= 0.3 * n) && q[0] + q[1] >= 0.4 * n && q[0] + q[1] <= 0.6 * n && q[2] + q[3] >= 0.4 * n && q[2] + q[3] <= 0.6 * n, q.join(","));
    const mix = ["small", "medium", "large"].map(s => list.filter(st => st.size === s).length / Math.max(1, n) * 100);
    check("O15 " + W0 + " px: the sizes within 10 points of 60% small, 30% medium, 10% large bright (" + mix.map(v => v.toFixed(1)).join(" / ") + "), each large one with rays",
      Math.abs(mix[0] - 60) <= 10 && Math.abs(mix[1] - 30) <= 10 && Math.abs(mix[2] - 10) <= 10 && list.every(st => st.size !== "large" || st.spiked) && mix[0] + mix[1] + mix[2] > 99.9, mix.join(","));
    // the cell each star is in, from its position and the grid, not from its label
    const cellOf = st => Math.min(rows - 1, Math.floor(st.y / ch)) + "," + Math.min(cols - 1, Math.floor(st.x / cw));
    const cellsSeen = list.map(cellOf);
    check("O15 " + W0 + " px: one star at most in each cell of the " + cols + " x " + rows + " grid (an even grid, so each quadrant is whole cells), each where it says",
      cols >= 2 && rows >= 2 && cols % 2 === 0 && rows % 2 === 0 && new Set(cellsSeen).size === n && list.every((st, k) => st.cell === cellsSeen[k]), cellsSeen.join(" "));
    // NAMED (Nov 11 2026, polish): more open sky on a phone, so large rayed stars fit there too.
    if (W0 === 390) check("O15 390 px: at least 2 large rayed stars fit in the phone panel's sky (" + list.filter(st => st.size === "large" && st.spiked).length + "), none turned into a medium one",
      list.filter(st => st.size === "large" && st.spiked).length >= 2 && sky[5] === 0, JSON.stringify(skyReport[W0]));
    const larges = list.filter(st => st.size === "large").map(cellOf).map(c => c.split(",").map(Number));
    check("O15 " + W0 + " px: no two large bright stars in neighbouring cells", larges.every((a, i) => larges.every((b, j) => j <= i || Math.abs(a[0] - b[0]) > 1 || Math.abs(a[1] - b[1]) > 1)), JSON.stringify(larges));
    let md = Infinity; list.forEach((a, i) => list.forEach((b, j) => { if (j > i) md = Math.min(md, Math.hypot(a.x - b.x, a.y - b.y)); }));
    check("O15 " + W0 + " px: no two stars closer than 60% of a cell's smaller side (" + (0.6 * Math.min(cw, ch)).toFixed(1) + " px; closest " + md.toFixed(1) + ")", md >= 0.6 * Math.min(cw, ch) - 1e-9, md);
    const bad = clashes(list, G);
    check("O15 " + W0 + " px: none on a portal (anywhere it can drift), under an open halo or a label with \" (open)\", on the core, the search or the reserved preview and status row, and none past the panel's edge (3 px on the phone)", bad.length === 0, bad.join(", "));
    // NAMED (Nov 11 2026, one living sky): the Oracle's colours, read from each star's halo.
    const cols4 = COLOURS.map(c => list.filter(st => colourOf(P1, st) === c).length / Math.max(1, n) * 100);
    const oracleShare = [500 / 6, 100 / 18, 100 / 18, 100 / 18];
    check("O15 " + W0 + " px: the colours in the Oracle's shares within 10 points (white, cyan, violet, gold " + cols4.map(v => v.toFixed(1)).join(" / ") + " against 83.3 / 5.6 / 5.6 / 5.6), all three tints, none but white over 45%",
      cols4.every((v, k) => Math.abs(v - oracleShare[k]) <= 10) && cols4.slice(1).every(v => v > 0 && v <= 45) && Math.abs(cols4.reduce((a, b) => a + b, 0) - 100) < 0.01, cols4.join(","));
    // Each star's own twinkle: 2.5 to 6 s, a start within it, carried to the CSS; no two sets in step.
    const tw = list.map(st => ({ dur: Number(st.g.getAttribute("data-tw-dur")), delay: Number(st.g.getAttribute("data-tw-delay")), gl: st.g.getAttribute("data-gl-dur"), style: st.g.getAttribute("style") || "", size: st.size }));
    const phases = tw.map(t => -t.delay / t.dur), meanP = phases.reduce((a, b) => a + b, 0) / Math.max(1, n);
    const spread = Math.sqrt(phases.reduce((a, p) => a + (p - meanP) * (p - meanP), 0) / Math.max(1, n));
    check("O15 " + W0 + " px: each star its own seeded twinkle: 2.5 to 6 s, a start within it, set as --tw-dur and --tw-delay; durations and starts all but distinct (" + new Set(tw.map(t => t.dur)).size + " and " + new Set(tw.map(t => t.delay)).size + " of " + n + "), phases spread " + spread.toFixed(2) + "; the large ones glint every 6 to 14 s",
      n > 0 && tw.every(t => t.dur >= 2.5 && t.dur <= 6 && t.delay <= 0 && t.delay > -t.dur && t.style.indexOf("--tw-dur:" + t.dur + "s;--tw-delay:" + t.delay + "s") === 0 &&
        (t.size === "large" ? Number(t.gl) >= 6 && Number(t.gl) <= 14 && t.style.indexOf(";--gl-dur:" + t.gl + "s;--gl-delay:") !== -1 : t.gl === null)) &&
      new Set(tw.map(t => t.dur)).size >= 0.8 * n && new Set(tw.map(t => t.delay)).size >= 0.8 * n && spread > 0.15, JSON.stringify(tw.slice(0, 4)));
    // ONE fixed set: the very same star nodes, byte for byte, through everything a member does; only a width change lays out.
    const svgOf = P0 => P0.d.getElementById("orbitStars");
    const G1 = JSON.parse(JSON.stringify(G)), P3 = skyPage(W0, G1), sky3 = svgOf(P3), nodes0 = Array.prototype.slice.call(sky3.children), html0 = sky3.innerHTML;
    const same = () => sky3.innerHTML === html0 && sky3.children.length === nodes0.length && nodes0.every((nd, k) => sky3.children[k] === nd);
    const steps = [], step = (name) => steps.push([name, same()]);
    const portals = Array.prototype.slice.call(P3.d.querySelectorAll(".orbit-portal")), prev = P3.d.getElementById("orbitPreview");
    let previews = 0, hides = 0;
    portals.forEach(b => {
      const k = b.getAttribute("data-portal");
      b.dispatchEvent(new P3.w.MouseEvent("mouseenter")); previews += prev.hidden ? 0 : 1; step("hover " + k);
      b.dispatchEvent(new P3.w.MouseEvent("mouseleave")); hides += prev.hidden ? 1 : 0; step("leave " + k);
      b.dispatchEvent(new P3.w.FocusEvent("focus")); previews += prev.hidden ? 0 : 1; step("focus " + k);
      b.dispatchEvent(new P3.w.FocusEvent("blur")); hides += prev.hidden ? 1 : 0; step("blur " + k);
    });
    for (const b of portals) { b.click(); P3.run(800); step("click " + b.getAttribute("data-portal") + " and its turn"); }
    P3.d.getElementById("orbitTop").dispatchEvent(new P3.w.KeyboardEvent("keydown", { key: "Escape", bubbles: true })); step("Escape");
    const Bo = P3.w.BFOrbit; Bo.open("oracle"); P3.run(800); Bo.fold(); P3.run(Bo.DRIFT_MS + 100); step("a full turn of the drift");
    P3.run(6000); step("six seconds of drift and twinkle");
    P3.d.getElementById("orbitRefresh").click(); await settle(); P3.run(100); step("Refresh");
    Bo.load(); await settle(); P3.run(100); step("a data reload");
    G1.panel[3] += 60; P3.w.dispatchEvent(new P3.w.Event("resize")); P3.w.dispatchEvent(new P3.w.Event("load")); step("the panel 60 px taller (height only)");
    const kept = steps.filter(x => !x[1]).map(x => x[0]);
    check("O15 " + W0 + " px: ONE fixed set: every star the same node in the same place, byte for byte, after hover and focus on each portal (" + previews + " previews shown and hidden), a click on each, Escape, a full turn, 6 s of drift and twinkle, Refresh, a data reload and a height-only change",
      steps.length === 31 && kept.length === 0 && previews === 10 && hides === 10 && P3.fetches.length >= 3, kept.join(", ") + " | " + previews + "/" + hides + " " + P3.fetches.length);
    G1.panel[2] -= 40; P3.w.dispatchEvent(new P3.w.Event("resize"));
    check("O15 " + W0 + " px: a WIDTH change, and only that, lays them out again (new nodes for the panel 40 px narrower)", !same() && sky3.children.length > 0 && sky3.children[1] !== nodes0[1]);
    P3.dom.window.close();
    const P2 = skyPage(W0);
    check("O15 " + W0 + " px: seeded: a second load puts the very same set (every star, size and colour) in the same place",
      JSON.stringify(starsOf(P2).map(st => [st.x, st.y, st.r, colourOf(P2, st)])) === JSON.stringify(list.map(st => [st.x, st.y, st.r, colourOf(P1, st)])) && svgOf(P2).innerHTML === svgOf(P1).innerHTML);
    P1.dom.window.close(); P2.dom.window.close();
  }
  console.log("    sky  " + JSON.stringify(skyReport));
  check("O15 the old plain dots are gone: no STARS list, no circle.orbit-star in the ring's drawing, no white fill rule, no radial-gradient dots on a phone",
    !/var STARS = \[/.test(FILES[ORBIT]) && !/\.orbit-star\{fill:#fff\}/.test(CSS) && !/radial-gradient\(/.test(CSS) &&
    L.d.querySelectorAll("#orbitSvg .orbit-star, circle.orbit-star").length === 0);

  }
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.stack) || e)); process.exit(1); });
