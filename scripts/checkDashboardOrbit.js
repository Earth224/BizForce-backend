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
     O13 one fetch on load, one per Refresh, none per portal.

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
  "non-transform-animation": [[DASH, "    font:inherit;transition:opacity .3s ease}", "    font:inherit;transition:opacity .3s ease,left .6s ease-out,top .6s ease-out}"]],
  // every portal press reads the route again (O13)
  "fetch-per-portal": [[ORBIT, "  function toggle(key) { if (state.open === key) fold(); else openPortal(key, true); }",
    "  function toggle(key) { load(); if (state.open === key) fold(); else openPortal(key, true); }"]],
  // markup written from text (O12)
  "innerHTML-used": [[ORBIT, "if (text !== undefined && text !== null) x.textContent = String(text); return x; }", "if (text !== undefined && text !== null) x.innerHTML = String(text); return x; }"]],
  // the music button's anchor moved out of the top bar (O1)
  "music-button-moved": [[DASH, "<div class=\"topbar-brand\" data-bf-boombox-anchor>", "<div class=\"topbar-brand\">"]],
  // something below the top half changed (O1)
  "below-top-half-changed": [[DASH, "<section id=\"businessProfileSection\" class=\"bf-section\">", "<p>A new line.</p>\n<section id=\"businessProfileSection\" class=\"bf-section\">"]]
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
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}
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
  Object.defineProperty(w.HTMLElement.prototype, "clientWidth", { configurable: true, get() { return this.id === "orbitStage" ? 600 : 0; } });
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
  return { dom, w, d: w.document, fetches, err, run, media, frames };
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
  check("the AI Agent Directory card is in the template byte for byte, with \"Agent Hub\" and \"Full Directory\"", BASE_DIR.length > 1000 && tpl.indexOf(BASE_DIR) !== -1 &&
    /id="openAgentHubBtn"[^>]*onclick="window\.location\.href='agents-hub\.html';">Agent Hub</.test(tpl) && /id="openAgentDirectoryBtn"[^>]*onclick="window\.location\.href='ai-agents\.html';">Full Directory</.test(tpl));
  check("the feature grid, its ordering module and its two keys are gone from the page", FILES[DASH].indexOf("bf-dashboard-order.js") === -1 && !/bf_dashboard_order|bf_dashboard_custom/.test(FILES[DASH] + FILES[ORBIT]) &&
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
  check("everything after the top half, Business Profile down, is BASELINE's byte for byte", below(BASE).length > 10000 && below(FILES[DASH]) === below(BASE) &&
    below(FILES[DASH]).indexOf("<section id=\"businessProfileSection\"") !== -1);

  /* ── O2. badges and beams ── */
  console.log("\n══ O2. badges where something needs the member, and beams only from them ══");
  const badgeOf = (d, k) => { const b = d.getElementById("orbitBadge-" + k); return b && !b.hidden ? b.textContent : null; };
  const beamOn = (d, k) => { const g = d.querySelector(".orbit-beam[data-portal=\"" + k + "\"]"); return !!g && !g.hasAttribute("hidden") && g.style.display !== "none"; };
  check("Agents shows 2 (proposals waiting) and Sell 3 (low stock)", badgeOf(P.d, "agents") === "2" && badgeOf(P.d, "sell") === "3", JSON.stringify([badgeOf(P.d, "agents"), badgeOf(P.d, "sell")]));
  check("Grow, Connect and Oracle show no badge", ["grow", "connect", "oracle"].every(k => badgeOf(P.d, k) === null));
  check("a beam runs from Agents and from Sell, and from no other portal", beamOn(P.d, "agents") && beamOn(P.d, "sell") && ["grow", "connect", "oracle"].every(k => !beamOn(P.d, k)));
  check("each beam is a curve to the core with a travelling dot", ["agents", "sell"].every(k => { const g = P.d.querySelector(".orbit-beam[data-portal=\"" + k + "\"]"); return g.querySelector("path.orbit-beam-line") && g.querySelector("circle.orbit-beam-dot"); }) &&
    /@keyframes orbitDot\{0%\{transform:translate\(0px,250px\);opacity:0\}/.test(CSS));
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
  check("Analytics: 9 tracked visits this week, +3 against last week (6), and a 14-point line", /9 tracked visits this week/.test(an.textContent) && /\+3 against last week \(6\)/.test(an.textContent) &&
    an.querySelector("svg.orbit-spark polyline").getAttribute("points").split(" ").length === 14, an.textContent.replace(/\s+/g, " ").slice(-160));
  check("Store: 3 at or below reorder point, 6 orders this week, and a 14-point line", /3 at or below reorder point/.test(stb.textContent) && /6 orders this week/.test(stb.textContent) &&
    stb.querySelector("svg.orbit-spark polyline").getAttribute("points").split(" ").length === 14);
  check("each main box keeps its icon, title, description and Open button", [an, stb].every(b => b.querySelector(".bf-neon-icon") && b.querySelector("h3") && b.querySelector("p") && b.querySelector("a.bf-btn")) &&
    an.querySelector("a.bf-btn").getAttribute("href") === "/analytics-dashboard.html" && stb.querySelector("a.bf-btn").getAttribute("href") === "store-agent.html");
  const zs = Z.d.querySelector("#orbitMain [data-card=\"store\"]");
  const za = Z.d.querySelector("#orbitMain [data-card=\"analytics\"]");
  check("no store: \"Connect a store to see orders\", linking store-agent.html, and no orders figure", !!zs.querySelector("a.orbit-connect") && zs.querySelector("a.orbit-connect").textContent === "Connect a store to see orders" &&
    zs.querySelector("a.orbit-connect").getAttribute("href") === "store-agent.html" && !/orders this week/.test(zs.textContent));
  check("no tracked link: \"No tracked visits yet\", and no line", /No tracked visits yet/.test(za.textContent) && !za.querySelector("svg.orbit-spark"));
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
    /18 customers/.test(P.d.querySelector("#orbitMain [data-card=\"crm\"]").textContent));
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
  check("the core is a button reading This week, the tracked visits, and All tools", core.tagName === "BUTTON" && /This week/.test(core.textContent) && /9 tracked visits/.test(core.textContent) && /All tools/.test(core.textContent));
  check("with no tracked link the core says \"No tracked visits yet\"", /No tracked visits yet/.test(Z.d.getElementById("orbitCore").textContent));
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
  check("pressing a portal opens it: aria-pressed true, its grid shown, the others dimmed", growBtn.getAttribute("aria-pressed") === "true" && !K.d.getElementById("orbitGrid").hidden &&
    K.d.getElementById("orbitGrid").getAttribute("data-portal") === "grow" && K.d.querySelectorAll(".orbit-portal.is-dim").length === 4);
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
  const front = ((D.w.BFOrbit.state.base + 2 * 72) % 360 + 360) % 360;
  check("pressing a portal turns it to the front in about 600 ms", front < 0.5 || front > 359.5, front.toFixed(2));
  const RM = page({ reduce: true, top: TOP(), session: { bf_orbit_portal: "x" } });
  await settle();
  RM.w.BFOrbit.fold();
  const r0 = RM.w.BFOrbit.state.base; RM.run(2000);
  check("under reduced motion there is no drift", RM.w.BFOrbit.state.base === r0);
  RM.w.BFOrbit.open("agents");
  const rf = ((RM.w.BFOrbit.state.base + 3 * 72) % 360 + 360) % 360;
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
  check("every keyframe sets only transform and opacity", frames.length === 1 && frames.every(k => (k.replace(/@keyframes [a-zA-Z]+\{/, "").match(/[a-z-]+(?=:)/g) || []).every(p => p === "transform" || p === "opacity")), frames.join(" | "));
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
  check("one GET /api/dashboard/top on load, and no other request", C.fetches.length === 1 && C.fetches[0] === "https://api.test/api/dashboard/top", C.fetches.join(","));
  ["grow", "sell", "connect", "agents", "oracle"].forEach(k => C.d.querySelector(".orbit-portal[data-portal=\"" + k + "\"]").click());
  C.d.getElementById("orbitCore").click();
  C.d.querySelectorAll("#orbitMain .orbit-swap")[0].click();
  await settle();
  check("opening every portal, All tools and Swap reads nothing more", C.fetches.length === 1, C.fetches.length);
  C.d.getElementById("orbitRefresh").click();
  await settle();
  check("Refresh reads the route once more", C.fetches.length === 2, C.fetches.length);
  check("the page loads bf-orbit.js once, right after the template", FILES[DASH].split("<script src=\"/scripts/bf-orbit.js\"></script>").length === 2 &&
    FILES[DASH].indexOf("</template>\n<script src=\"/scripts/bf-orbit.js\"></script>") !== -1);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.stack) || e)); process.exit(1); });
