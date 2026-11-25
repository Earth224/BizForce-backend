"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkHqViews — HQ1 (Nov 19 2026): the phone dashboard's card views, the
   orbit toggle, the Oracle set's moon and gold, the saved choices, and the
   boombox's rule for sound on a page's load.

     R  migration 188: user_preferences.hq_card_view and hq_orbit, each NULL or
        one of its values by a named CHECK, safe to re-run; 188 is the only 188
        and THE HIGHEST migration (the other checks name it by its file name);
     S  GET and PUT /api/user/preferences, run in a vm with a fake database:
        GET answers both (null when never chosen or not a valid value); PUT
        leaves an absent key alone, stores null, stores a listed value, and
        refuses anything else with a 400 naming the valid values;
     Y  Your data: lib/yourData.js exports both columns and says so; the
        built privacy.html carries that sentence;
     V  the view row: the open portal's set title, Large, Compact and Grid,
        then the orbit button, each with an aria-label and aria-pressed;
     D  defaults: Compact and the orbit shown, for a member who has not chosen;
     T  the three views: Large is the orbit's own boxes; Compact and Grid are
        one row or tile per Large card, in the same order, each linking where
        the card's button links, for each of the five portals; the main boxes
        carry Swap (a 44 px overflow button) and it swaps;
     O  the orbit toggle: hidden, five chips in the orbit's order with the
        open one highlighted; a chip opens its portal; shown again, the same
        portal is open;
     C  the saved choices: a choice is kept on this device (bf_hq_view,
        bf_hq_orbit) and sent to the server; on a reload the device copy
        applies at once and the server's stored choice wins once it arrives;
        a choice the server does not hold yet is sent to it;
     P  phone only: every HQ1 rule that shows anything is inside
        @media (max-width: 760px); above it nothing is asked of the server
        (no /api/user/preferences, no /api/moon) and the orbit label stays as
        it was;
     M  the moon: scripts/bf-oracle-moon.js holds oracle.html's moon block and
        MOON_IMG_URL EXACTLY; it draws the ORACLE node and the ORACLE chip, with
        the live phase from GET /api/moon, each with its own ids; the centre,
        while ORACLE is open, is the Sun (NAMED, Nov 21 2026, FX2: BEFORE a
        third moon there): NASA SDO's photograph, saved locally under 120 KB,
        its source and credit in the code, a glow, and a shimmer that stops
        under reduced motion; the gold ring round it as it was;
     G  the gold: the chat box's (#tmx-chat::before in
        scripts/termaximus-presence.js), every stop, the size, the animation
        and its keyframes equal; still under reduced motion; on the rings, the
        "(open)" label, the set title and the Oracle tools' icons;
     U  no Oracle page changed since frontend 2666c0a;
     A  the boombox: sound on a page's load only with "Play when I open
        BizForce" on and no pause or stop in this visit, on every page that
        loads the boombox (all through scripts/bf-music.js);
     W  sw.js: SHELL_REV "hq1" and the two new scripts cached;
     N  no emoji in any file HQ1 added.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const PH1_COMMIT = "2666c0a";   // the frontend before HQ1
const DASH = "dashboard.html", ORBIT = "scripts/bf-orbit.js", VIEWS = "scripts/bf-hq-views.js", MOON = "scripts/bf-oracle-moon.js";
const MUSIC = "scripts/bf-music.js", PRESENCE = "scripts/termaximus-presence.js", SW = "sw.js", PRIVACY = "privacy.html", SESSION = "scripts/bf-session.js";
const ORACLE_PAGES = ["oracle.html", "mychart.html", "calendar.html", "synastry.html", "the-third.html"];
const SERVER = "@server.js", YOURDATA = "@lib/yourData.js", MIG = "@supabase/migrations/188_user_preferences_hq_view.sql";

const MUTATIONS = {
  "migration-check-name": [[MIG, "ADD CONSTRAINT user_preferences_hq_orbit_check", "ADD CONSTRAINT user_preferences_hq_orbit_chk"]],
  "migration-not-rerunnable": [[MIG, "ADD COLUMN IF NOT EXISTS hq_card_view text,", "ADD COLUMN hq_card_view text,"]],
  "route-put-no-400": [[SERVER, "if (req.body.hq_card_view !== null && HQ_CARD_VIEWS.indexOf(req.body.hq_card_view) === -1) {", "if (false) {"]],
  "route-null-not-stored": [[SERVER, "      updates.hq_orbit = req.body.hq_orbit;", "      if (req.body.hq_orbit !== null) updates.hq_orbit = req.body.hq_orbit;"]],
  // NAMED (Nov 21 2026, FX2): BEFORE anchored on the select's end, hq_orbit"); AFTER the select ends in agents_card_view (migration 200e), so on "hq_orbit, agents_card_view".
  // NAMED (Nov 23 2026, P3-3): need_alerts (migration 202b) now follows agents_card_view, last
  "route-get-drops-orbit": [[SERVER, "goal_time_zone, goal_set_at, hq_card_view, hq_orbit, agents_card_view, need_alerts\")", "goal_time_zone, goal_set_at, hq_card_view, agents_card_view, need_alerts\")"]],
  "route-get-unchecked": [[SERVER, "hq_card_view: HQ_CARD_VIEWS.indexOf(row.hq_card_view) !== -1 ? row.hq_card_view : null,", "hq_card_view: row.hq_card_view,"]],
  // NAMED (Nov 21 2026, FX2): BEFORE "..., hq_orbit, updated_at"; AFTER agents_card_view sits between them
  "yourdata-no-columns": [[YOURDATA, "goal_set_at, hq_card_view, hq_orbit, agents_card_view, updated_at", "goal_set_at, agents_card_view, updated_at"]],
  "view-row-no-orbit-button": [[VIEWS, "  btns.appendChild(orbitBtn);\n", ""]],
  "title-wrong": [[VIEWS, "agents: \"AGENT TOOLS\"", "agents: \"AGENTS TOOLS\""]],
  "view-no-aria-pressed": [[VIEWS, "viewBtn[v].setAttribute(\"aria-pressed\", state.view === v ? \"true\" : \"false\");", ""]],
  "default-large": [[VIEWS, "DEFAULT_VIEW = \"compact\"", "DEFAULT_VIEW = \"large\""]],
  "default-orbit-hidden": [[VIEWS, "DEFAULT_ORBIT = \"shown\"", "DEFAULT_ORBIT = \"hidden\""]],
  "list-skips-mains": [[VIEWS, "    return mains.concat(boxes);", "    return boxes;"]],
  "row-wrong-link": [[VIEWS, "    if (href) a.setAttribute(\"href\", href);", "    if (href) a.setAttribute(\"href\", \"#\");"]],
  "grid-one-column": [[DASH, "#orbitTop[data-hq-view=\"grid\"] .hq-list{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:10px}", "#orbitTop[data-hq-view=\"grid\"] .hq-list{display:grid;grid-template-columns:1fr;gap:10px}"]],
  "swap-missing": [[VIEWS, "      it.appendChild(more);\n", ""]],
  "chips-reversed": [[VIEWS, "  O.PORTALS.forEach(function (p) {\n    var b = el(\"button\", \"hq-chip\");", "  O.PORTALS.slice().reverse().forEach(function (p) {\n    var b = el(\"button\", \"hq-chip\");"]],
  "chip-no-highlight": [[VIEWS, "      chipBtn[p.key].setAttribute(\"aria-pressed\", on ? \"true\" : \"false\");\n      chipBtn[p.key].classList.toggle(\"is-open\", on);\n", ""]],
  "toggle-loses-portal": [[VIEWS, "    state.orbit = value; writeLocal(ORBIT_KEY, value);", "    state.orbit = value; O.fold(); writeLocal(ORBIT_KEY, value);"]],
  "no-device-copy": [[VIEWS, "state.swapping = -1; writeLocal(VIEW_KEY, value); apply();", "state.swapping = -1; apply();"]],
  "no-server-save": [[VIEWS, "apply(); return save({ hq_card_view: value }); }", "apply(); return null; }"]],
  "server-does-not-win": [[VIEWS, "        if (v) { state.view = v; writeLocal(VIEW_KEY, v); }", "        if (false) { state.view = v; writeLocal(VIEW_KEY, v); }"]],
  "desktop-asks-server": [[VIEWS, "    if (!phone() || state.server || typeof fetch !== \"function\")", "    if (state.server || typeof fetch !== \"function\")"]],
  // NAMED (Nov 21 2026, FX2): the hide list gained .hq-core-sun (its line carries a NAMED comment after the rule). NAMED (Nov 22 2026, FX3): now .hq-core-abyss
  "phone-rule-leaks": [[DASH, "  .hq-chips,.hq-view-row,.hq-list,.hq-moon,.hq-core-moon,.hq-core-abyss,.hq-gold-ring{display:none}", "  .hq-view-row{display:flex}\n  .hq-chips,.hq-view-row,.hq-list,.hq-moon,.hq-core-moon,.hq-core-abyss,.hq-gold-ring{display:none}"]],
  // NAMED (Nov 22 2026, FX3): BEFORE the Sun's mutations (sun-back-to-moon, sun-wrong-image, sun-no-credit, sun-shimmers-when-reduced,
  // sun-no-glow, sun-always-shown). AFTER the abyss sun's
  "abyss-back-to-moon": [[VIEWS, "      var c = el(\"span\", \"hq-core-abyss\");\n", "      var c = el(\"span\", \"hq-core-moon\"); c.setAttribute(\"data-hq-moon\", \"core\");\n"]],
  "abyss-not-the-chat-void": [[DASH, "        radial-gradient(ellipse at 50% 50%, rgba(4,2,48,0.16)   0%, transparent 64%),\n", "        radial-gradient(ellipse at 50% 50%, rgba(4,2,48,0.22)   0%, transparent 64%),\n"]],
  "abyss-wrong-sizes": [[DASH, "      background-size: 200% 200%, 200% 200%, 200% 200%, 240% 240%;\n      animation: tmx-chat-void 22s", "      background-size: 200% 200%, 200% 200%, 200% 200%, 200% 200%;\n      animation: tmx-chat-void 22s"]],
  "abyss-wrong-drift": [[DASH, "      animation: tmx-chat-void 22s ease-in-out infinite}", "      animation: tmx-chat-void 16s ease-in-out infinite}"]],
  "abyss-glows": [[DASH, "      animation: tmx-chat-void 22s ease-in-out infinite}", "      animation: tmx-chat-void 22s ease-in-out infinite;box-shadow:0 0 26px 6px rgba(255,150,50,.30)}"]],
  "abyss-moves-when-reduced": [[DASH, "    @media (prefers-reduced-motion: reduce){ .hq-core-abyss{animation:none !important} }\n", ""]],
  "abyss-always-shown": [[DASH, "    #orbitTop[data-hq-open=\"oracle\"] .hq-core-abyss{display:block;", "    #orbitTop .hq-core-abyss{display:block;"]],
  "abyss-no-stars": [[VIEWS, "      if (window.BFAbyss) abyss = window.BFAbyss.create(cv, { perArea: true });\n", ""]],
  "abyss-stars-not-per-area": [[VIEWS, "window.BFAbyss.create(cv, { perArea: true })", "window.BFAbyss.create(cv, {})"]],
  "abyss-keyframes-drift": [[DASH, "  @keyframes tmx-chat-void {\n    0%   { background-position: 15% 20%, 85% 80%, 50% 50%, 40% 60%; }", "  @keyframes tmx-chat-void {\n    0%   { background-position: 15% 20%, 85% 80%, 50% 50%, 45% 60%; }"]],
  "green-ring-shown": [[DASH, "    #orbitTop[data-hq-open=\"oracle\"] .orbit-core-halo,#orbitTop[data-hq-open=\"oracle\"] .orbit-core-arc,#orbitTop[data-hq-open=\"oracle\"] .orbit-goal-arc{display:none}\n", ""]],
  "abyss-runs-everywhere": [[VIEWS, "    abyssRun(open === \"oracle\" && phone() && state.orbit === \"shown\");", "    abyssRun(phone());"]],
  "moon-copy-drift": [[MOON, "    var SYNODIC_MONTH = 29.53058867;", "    var SYNODIC_MONTH = 29.53058868;"]],
  "moon-not-live": [[MOON, "      if (result) b.setReal(result);\n", ""]],
  "moon-shared-ids": [[MOON, "    return html.replace(/id=\"([^\"]+)\"/g", "    return html; return html.replace(/id=\"([^\"]+)\"/g"]],
  "moon-on-desktop": [[MOON, "    if (started || !phone()) return;", "    if (started) return;"]],
  "gold-stop-drift": [[DASH, "      #6b4e00 0%, #b8860b 14%, #fff6d5 24%, #d4af37 34%,", "      #6b4e00 0%, #b8860b 14%, #fff6d5 24%, #d4af37 36%,"]],
  "gold-animation-drift": [[DASH, "    animation: tmx-gold-shimmer 7s ease-in-out infinite;\n  }", "    animation: tmx-gold-shimmer 6s ease-in-out infinite;\n  }"]],
  "gold-moves-when-reduced": [[DASH, "  @media (prefers-reduced-motion: reduce){ .hq-gold,.hq-gold-ring{animation:none} }\n", ""]],
  "gold-title-not-applied": [[VIEWS, "    title.classList.toggle(\"hq-gold\", open === \"oracle\");\n", ""]],
  "gold-icons-not-applied": [[VIEWS, "      if (oracleTool(slug)) {", "      if (false) {"]],
  "oracle-page-edited": [["oracle.html", "<title>BizForce AI — The Oracle</title>", "<title>BizForce AI — The Oracle!</title>"]],
  "autoplay-resume-ungated": [[MUSIC, "      if (loadPlayAllowed() && S.was_playing && S.track_id && trackById(S.track_id)) {", "      if (S.was_playing && S.track_id && trackById(S.track_id)) {"]],
  "autoplay-ignores-pause": [[MUSIC, "  function loadPlayAllowed() { return S.autoplay === true && !held(); }", "  function loadPlayAllowed() { return S.autoplay === true; }"]],
  "pause-not-remembered": [[MUSIC, "  function pause() { hold(true); if (popoutAlive())", "  function pause() { if (popoutAlive())"]],
  "page-plays-itself": [["agents-hub.html", "</body>", "<script>window.addEventListener('load',function(){if(window.BFMusic)window.BFMusic.play();});</script></body>"]],
  // NAMED (Nov 19 2026, P2-1): BEFORE "hq1". AFTER "p21": the bottom bar, Home, the Inbox, the profile header and Settings, Local in the shell (checkAppShell W).
  // NAMED (Nov 20 2026, P2-2): BEFORE "p21". AFTER "p22": the report, block and mute menu (bf-safety.js), moderation.html and copyright.html in the shell.
  // NAMED (Nov 20 2026, P2-3): BEFORE "p22". AFTER "p23": posts, the Following feed, Talk and follows (bf-feed.js, bf-composer.js) and compose.html in the shell.
  // NAMED (Nov 20 2026, FX1): BEFORE "p23". AFTER "fx1": Home's feed and the Profile as the approved design pictures.
  // NAMED (Nov 20 2026, P3-1): BEFORE "fx1". AFTER "p31": free accounts (the members panel, the verification banner, landing by tier).
  // NAMED (Nov 21 2026, P3-2): BEFORE "p31". AFTER "p32": the Verified badge (bf-verified.js), and the members panel on media and business ID.
  // NAMED (Nov 21 2026, FX2): BEFORE "p32". AFTER "fx2": the feed's Tip and product strip, the Profile's banner, the Agent Directory's views (bf-agents-views.js) and the Oracle's Sun.
  // NAMED (Nov 21 2026, P3-1B): BEFORE "fx2". AFTER "p31b": the free-account rules (bf-access.js Buy sheet and members intercepts, the Create sheet's Members tags, the composer's photo rule and Show in Google, Talk's members box).
  // NAMED (Nov 22 2026, FX3B): BEFORE anchored on "fx3"; AFTER "fx3b"
  // NAMED (Nov 23 2026, P3-3): BEFORE "fx3b"; AFTER "p33" (Share, Offer or Need, the Need post and I can help, the Market filter)
  // NAMED (Nov 23 2026, LR-1): BEFORE "p33"; AFTER "lr1" (approve each reply before it posts, the Lead Radar sign-in prompt, tidy-ups). sw.js now carries its note on the SHELL_REV line, so the line may end in a // comment.
  // NAMED (Nov 25 2026, HOTFIX-G1): BEFORE "lr4b"; AFTER "g1" (phone layouts restored; only the controls under the Guide tab moved). LR-4B: BEFORE "lr4"; AFTER "lr4b" (the storefront menu draws whichever loads first). LR-4: BEFORE "lr3b"; AFTER "lr4" (Get found). LR-3B: BEFORE "lr3"; AFTER "lr3b" (nothing to tap under the Guide tab on the phone). LR-3: BEFORE "lr2b"; AFTER "lr3" (Inbound, the storefront Message button). LR-2B: BEFORE "lr2"; LR-2: BEFORE "lr1b".
  "sw-not-bumped": [[SW, "var SHELL_REV = \"g1\";", "var SHELL_REV = \"ph1\";"]],   // NAMED (Nov 22 2026, FX3): the anchor was still p31b (already stale at HEAD, where sw.js said p31c)
  // FX3B (Nov 22 2026): a moon whose photo failed shows again (drawn whole) at every repaint, until the error hides it
  "fx3b-moon-reveal": [[MOON, "    el.hidden = failed;\n", "    el.hidden = false;\n"]],
  // FX3B: no probe, so a moon whose photo failed never shows again
  "fx3b-moon-no-probe": [[MOON, "    if (img && failed) {\n", "    if (false) {\n"]],
  // FX3B: the probe shows the moon though its own photo failed after it
  "fx3b-moon-probe-blind": [[MOON, "if (!lost && img.parentNode && el.contains(img))", "if (img.parentNode && el.contains(img))"]],
  // (a crescent moon, built from its code point so this file holds none: checkNoEmoji N2)
  "emoji": [[VIEWS, "  var VIEW_KEY = \"bf_hq_view\"", "  /* " + String.fromCodePoint(0x1F319) + " */ var VIEW_KEY = \"bf_hq_view\""]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const MAP = JSON.parse(fs.readFileSync(path.join(REPO, "lib", "appMap.json"), "utf8"));
const PAGES = Object.keys(MAP.pages).map(k => String(MAP.pages[k].p || "/" + k).replace(/^\//, ""));
const FILES = {};
const readF = f => { try { return fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n"); } catch (e) { return null; } };
const readB = f => { try { return fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); } catch (e) { return null; } };
[DASH, ORBIT, VIEWS, MOON, MUSIC, PRESENCE, SW, PRIVACY, SESSION].concat(ORACLE_PAGES, PAGES).forEach(f => { if (!(f in FILES)) FILES[f] = readF(f); });
[SERVER, YOURDATA, MIG].forEach(f => { FILES[f] = readB(f.slice(1)); });
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(name, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + name); }
  else { failures++; console.log("    FAIL  " + name + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));
const J = v => JSON.stringify(v);
const has = (t, x) => typeof t === "string" && t.indexOf(x) !== -1;
const once = (t, x) => typeof t === "string" && t.split(x).length === 2;
const squash = t => String(t || "").replace(/\s+/g, " ").trim();
const settle = (ms) => new Promise(r => setTimeout(r, ms || 30));

/* ── the dashboard's HQ1 block ── */
const HQ_STYLE = (/<style id="hq1Phone">([\s\S]*?)<\/style>/.exec(FILES[DASH] || "") || ["", ""])[1];
const noComments = t => String(t).replace(/\/\*[\s\S]*?\*\//g, "");
function blockAt(t, head) {   // the text from head's "{" to its matching "}", by brace matching
  const a = t.indexOf(head);
  if (a < 0) return null;
  let depth = 0;
  for (let i = t.indexOf("{", a); i < t.length; i++) {
    if (t[i] === "{") depth++;
    else if (t[i] === "}" && --depth === 0) return { text: t.slice(a, i + 1), body: t.slice(t.indexOf("{", a) + 1, i), start: a, end: i + 1 };
  }
  return null;
}

(async () => {
  /* ══ R. migration 188 ══ */
  console.log("\n══ R. migration 188 ══");
  const mig = FILES[MIG] || "";
  const migNames = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(x => /^\d{3}_.*\.sql$/.test(x));
  const top = migNames.map(x => Number(x.slice(0, 3))).reduce((a, x) => Math.max(a, x), 0);
  // NAMED (Nov 19 2026, P2-1, migrations 189 and 190): BEFORE 188 was the highest. AFTER only 189_handles_and_place.sql and
  // 190_notifications_links.sql are above it, by name; "the highest" is checkHandles R1's.
  // NAMED (Nov 20 2026, P2-2, migrations 191 and 192): AFTER 191_safety.sql and 192_buy_listing_digital.sql are above them too, by
  // NAMED (Nov 20 2026, P2-3, migrations 193 and 194): 193_posts.sql (posts, post_media) and 194_social_graph.sql (follows, likes, saves, comments, share days, the count triggers) are allowed above the earlier highest too, by name; "the highest" is checkBuyListingDigital R1's.
  // NAMED (Nov 20 2026, P3-1, migrations 195 to 198): 195_users_email_canonical.sql (users.email_canonical, one account per inbox), 196_storage_account_tables.sql, 197_storage_account_functions.sql and 198_storage_account_backfill.sql (per-account storage totals; written in P3-1A as 196a/196b/196c and renamed) are allowed above the earlier highest too, by name; "the highest" (198) is checkBuyListingDigital R1's.
  // name; "the highest" is checkBuyListingDigital R1's.
  check("R1. 188_user_preferences_hq_view.sql is the only 188, and only 189_handles_and_place.sql, 190_notifications_links.sql, 191_safety.sql and 192_buy_listing_digital.sql are above it (checkBuyListingDigital R1)",
    // NAMED (Nov 21 2026, P3-2, migration 199): 199_verified_badge.sql (bf_profiles.verified_reason and verified_at, the Verified badge) is allowed above too, by name; "the highest" (199) is checkBuyListingDigital R1's.
    // NAMED (Nov 21 2026, FX2, migration 200): 200_categories_and_intent.sql (the shared categories table, post category, intent, need_place and need_when, marketplace_listings.category_slug, and 200e's agents_card_view, search_visible and the SEO fields; applied by hand Nov 21 2026) is allowed above too, by name; "the highest" (200) is checkBuyListingDigital R1's.
    // NAMED (Nov 21 2026, P3-1C, migration 201): 201_member_welcome.sql (the member welcome and the free-account clawback, once per account: two unique partial indexes on wallet_transactions) is allowed above too, by name; "the highest" (201) is checkBuyListingDigital R1's.
    top === 206 /* NAMED (Nov 25 2026, LR-4): BEFORE 205 */ /* NAMED (Nov 24 2026, LR-3): BEFORE 204 */ /* NAMED (Nov 23 2026, LR-2): BEFORE 203 */ && migNames.filter(x => /^188_/.test(x)).join() === "188_user_preferences_hq_view.sql" &&
    // NAMED (Nov 21 2026, P3-1C, migration 201): 201_member_welcome.sql (the member welcome and the free-account clawback, once per account: two unique partial indexes on wallet_transactions) is allowed above too, by name; "the highest" (201) is checkBuyListingDigital R1's.
    // NAMED (Nov 23 2026, P3-3, migration 202): 202_need_found_and_alerts.sql (posts.need_found_at, a Need marked Found, and user_preferences.need_alerts) is allowed too, by name.
    // NAMED (Nov 23 2026, LR-1, migration 203): 203_lr1_archived_and_sms_pending.sql (sales_lead_pipeline may be 'archived'; sms_subscribers.consent_status defaults to 'pending') is allowed too, by name.
    // NAMED (Nov 23 2026, LR-2, migration 204): 204_lr2_member_lead_radar.sql (lead_fingerprints, member_leads, member_lead_replies, lead_search_cache, threads_connections) is allowed too, by name.
    // NAMED (Nov 24 2026, LR-3, migration 205): 205_lr3_inbound.sql (inbound_items) is allowed too, by name.
    // NAMED (Nov 25 2026, LR-4, migration 206): 206_lr4_get_found.sql (show_in_google, indexnow_sent) is allowed too, by name.
    migNames.filter(x => Number(x.slice(0, 3)) > 188).join() === "189_handles_and_place.sql,190_notifications_links.sql,191_safety.sql,192_buy_listing_digital.sql,193_posts.sql,194_social_graph.sql,195_users_email_canonical.sql,196_storage_account_tables.sql,197_storage_account_functions.sql,198_storage_account_backfill.sql,199_verified_badge.sql,200_categories_and_intent.sql,201_member_welcome.sql,202_need_found_and_alerts.sql,203_lr1_archived_and_sms_pending.sql,204_lr2_member_lead_radar.sql,205_lr3_inbound.sql,206_lr4_get_found.sql", J([top]));
  check("R2. it adds hq_card_view and hq_orbit as text, only if they do not exist (safe to re-run)",
    has(mig, "ADD COLUMN IF NOT EXISTS hq_card_view text,") && has(mig, "ADD COLUMN IF NOT EXISTS hq_orbit     text;"));
  check("R3. the named CHECKs as live: user_preferences_hq_card_view_check (NULL or large, compact, grid) and user_preferences_hq_orbit_check (NULL or shown, hidden), each dropped if it exists first",
    has(mig, "DROP CONSTRAINT IF EXISTS user_preferences_hq_card_view_check;") && has(mig, "ADD CONSTRAINT user_preferences_hq_card_view_check\n  CHECK (hq_card_view IS NULL OR hq_card_view IN ('large', 'compact', 'grid'));") &&
    has(mig, "DROP CONSTRAINT IF EXISTS user_preferences_hq_orbit_check;") && has(mig, "ADD CONSTRAINT user_preferences_hq_orbit_check\n  CHECK (hq_orbit IS NULL OR hq_orbit IN ('shown', 'hidden'));") &&
    mig.indexOf("DROP CONSTRAINT IF EXISTS user_preferences_hq_orbit_check;") < mig.indexOf("ADD CONSTRAINT user_preferences_hq_orbit_check"));
  check("R4. no new table (row level security on user_preferences since migration 030), nothing deleted or updated", !/create table/i.test(mig) && !/\b(DELETE|UPDATE|DROP TABLE|DROP COLUMN)\b/i.test(mig.replace(/--[^\n]*/g, "")));

  /* ══ S. the preferences routes ══ */
  console.log("\n══ S. GET and PUT /api/user/preferences ══");
  const SRC = FILES[SERVER] || "";
  function routeFn(method) {
    const sig = "app." + method + "(\"/api/user/preferences\", requireAuth, async function (req, res, next) {";
    const at = SRC.indexOf(sig);
    if (at < 0) return null;
    const open = at + sig.length - 1;
    const end = s.braceMatch(SRC, open);
    return SRC.slice(at + sig.indexOf("async function"), end);
  }
  const listOf = name => { const m = new RegExp("var " + name + " = (\\[[^\\]]*\\]);").exec(SRC); return m ? JSON.parse(m[1]) : null; };
  const HQV = listOf("HQ_CARD_VIEWS"), HQO = listOf("HQ_ORBIT_CHOICES");
  check("S0. the server's two lists: large, compact, grid; shown, hidden", J(HQV) === J(["large", "compact", "grid"]) && J(HQO) === J(["shown", "hidden"]), J([HQV, HQO]));
  function db(row) {
    const st = { row: row ? Object.assign({}, row) : null, upserts: [], selects: [] };
    st.client = { from(t) {
      return {
        select(cols) { st.selects.push(cols); const q = { eq() { return q; }, maybeSingle: async () => {
          if (!st.row) return { data: null, error: null };
          const out = {}; String(cols).split(",").map(c => c.trim()).forEach(c => { out[c] = st.row[c] === undefined ? null : st.row[c]; }); return { data: out, error: null }; } }; return q; },
        upsert(u) { st.upserts.push(Object.assign({}, u)); st.row = Object.assign(st.row || {}, u); return Promise.resolve({ error: null }); }
      };
    } };
    return st;
  }
  function run(method, row, body) {
    const fn = routeFn(method);
    const st = db(row);
    const ctx = { supabase: st.client, nowIso: () => "2026-11-19T17:00:00.000Z", LANGUAGE_NAMES: { en: "English" }, MIST_POSITIONS: ["top-right"],
      AGENT_CARD_ORDERS: ["importance", "alphabetical"], HQ_CARD_VIEWS: HQV, HQ_ORBIT_CHOICES: HQO, dashboardTopCache: new Map(),
      AGENTS_CARD_VIEWS: ["large", "compact", "grid"],   // NAMED (Nov 21 2026, FX2): the Agent Directory's view (checkAgentViews holds the route's rules for it)
      require: m => require(m.indexOf("./") === 0 ? path.join(REPO, m) : m) };
    vm.createContext(ctx);
    const handler = vm.runInContext("(" + fn + ")", ctx);
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    let nextErr = null;
    return Promise.resolve(handler({ user: { id: "u1" }, body: body || {} }, res, e => { nextErr = e || new Error("next"); }))
      .then(() => ({ status: res.statusCode, body: res.body, st, nextErr }));
  }
  if (!routeFn("get") || !routeFn("put")) check("S. both routes are in server.js", false);
  else {
    let r = await run("get", null);
    check("S1. GET with no settings row: hq_card_view and hq_orbit are null (never chosen)", r.status === 200 && r.body.hq_card_view === null && r.body.hq_orbit === null, J(r.body));
    r = await run("get", { termaximus_active: true, hq_card_view: "grid", hq_orbit: "hidden" });
    check("S2. GET reads both columns and answers the stored choices", r.body && r.body.hq_card_view === "grid" && r.body.hq_orbit === "hidden" && /\bhq_card_view\b/.test(r.st.selects[0]) && /\bhq_orbit\b/.test(r.st.selects[0]), J([r.body, r.st.selects]));
    r = await run("get", { hq_card_view: "tiny", hq_orbit: "maybe" });
    check("S3. GET answers null for a stored value outside the lists", r.body && r.body.hq_card_view === null && r.body.hq_orbit === null, J(r.body));
    r = await run("put", { hq_card_view: "grid", hq_orbit: "hidden" }, { notifications_enabled: true });
    check("S4. PUT without either key leaves both alone (the upsert names neither)", r.status === 200 && !("hq_card_view" in r.st.upserts[0]) && !("hq_orbit" in r.st.upserts[0]) && r.st.row.hq_card_view === "grid", J(r.st.upserts));
    r = await run("put", { hq_card_view: "grid", hq_orbit: "hidden" }, { hq_card_view: null, hq_orbit: null });
    check("S5. PUT null clears each (stored as null)", r.status === 200 && r.st.upserts[0].hq_card_view === null && r.st.upserts[0].hq_orbit === null, J(r.st.upserts));
    r = await run("put", null, { hq_card_view: "large", hq_orbit: "shown" });
    check("S6. PUT a listed value stores it", r.status === 200 && r.st.upserts[0].hq_card_view === "large" && r.st.upserts[0].hq_orbit === "shown", J(r.st.upserts));
    r = await run("put", null, { hq_card_view: "tiny" });
    check("S7. PUT hq_card_view outside the list: 400 naming large, compact, grid; nothing written", r.status === 400 && J(r.body.valid_hq_card_views) === J(["large", "compact", "grid"]) && r.st.upserts.length === 0, J([r.status, r.body]));
    r = await run("put", null, { hq_orbit: 5 });
    check("S8. PUT hq_orbit outside the list (a number): 400 naming shown, hidden; nothing written", r.status === 400 && J(r.body.valid_hq_orbit) === J(["shown", "hidden"]) && r.st.upserts.length === 0, J([r.status, r.body]));
  }

  /* ══ Y. Your data ══ */
  console.log("\n══ Y. Your data ══");
  const YD = FILES[YOURDATA] || "";
  const prefLine = (YD.match(/\{ table: "user_preferences"[\s\S]*?onDelete: "delete" \}/) || [""])[0];
  check("Y1. lib/yourData.js exports hq_card_view and hq_orbit with the member's settings row", /select: "[^"]*"\s*\+\s*"[^"]*\bhq_card_view, hq_orbit\b/.test(prefLine), prefLine.slice(-200));
  // NAMED (Nov 21 2026, FX2): BEFORE "card view (large, compact or grid) and whether its orbit is shown."; AFTER "card view (large, compact or grid), whether its orbit is shown, and your Agent Directory's view."
  const SENT = "and on a phone your dashboard's card view (large, compact or grid), whether its orbit is shown, and your Agent Directory's view.";
  check("Y2. its description names them, and the built privacy page carries it", has(prefLine, SENT) && has(FILES[PRIVACY], "card view (large, compact or grid), whether its orbit is shown, and your Agent Directory&#39;s view."));

  /* ══ the page, in jsdom ══ */
  const a0 = FILES[DASH].indexOf("<style id=\"orbitStyle\">"), b0 = FILES[DASH].indexOf("</template>") + "</template>".length;
  const ORBIT_MARKUP = a0 >= 0 && b0 > a0 ? FILES[DASH].slice(a0, b0) : "";
  const TOP = () => ({
    generated_at: "2026-11-19T17:00:00.000Z",
    visits: { per_day: [3, 1, 0, 4, 2, 5, 1, 2, 6, 3, 4, 2, 5, 7], this_week: 29, last_week: 16, tracked: true },
    store: { connected: true, low_stock: { count: 3, names: ["Blue mug"] }, orders_this_week: 14, orders_per_day: [1, 0, 2, 0, 1, 0, 1, 2, 3, 1, 2, 2, 3, 1] },
    proposals_pending: 2, cards: { count: 2, views_today: 12 }, certifications: { earned: 2, total: 8 }, wallet: { balance: 1100 }, marketplace: { orders_this_week: 0 },
    self_reviews: { latest_at: "2026-11-18T09:00:00.000Z" }, mailbox: { connected: true },
    counts: { crm_customers: 18, prospects: 4, leads: 6, sms_subscribers: 0, campaigns: 1, routines: 2, saved_prompts: 3, purchases: 1, bizdoc_documents: 5 },
    media: { used_bytes: 1, cap_bytes: 2 }, agents: { running_now: [] }, goal: { set: false }
  });
  const MOON_ANSWER = { illuminatedFraction: 0.62, waxing: true, phaseAngle: 101.5, phaseName: "Waxing Gibbous" };
  async function page(o) {
    o = o || {};
    const dom = new JSDOM("<!DOCTYPE html><html><head></head><body>" + ORBIT_MARKUP + "</body></html>", { url: "https://bizforceai.net/dashboard.html", runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window;
    try { w.localStorage.setItem("bf_token", "check-token"); Object.keys(o.local || {}).forEach(k => w.localStorage.setItem(k, o.local[k])); } catch (e) { /* none */ }
    try { Object.keys(o.session || {}).forEach(k => w.sessionStorage.setItem(k, o.session[k])); } catch (e) { /* none */ }
    const calls = [];
    w.API_URL = "https://api.test";
    w.fetch = (url, init) => {
      const u = String(url), m = (init && init.method) || "GET";
      calls.push({ m, u: u.replace("https://api.test", ""), body: init && init.body ? JSON.parse(init.body) : null });
      let body = {};
      if (/\/api\/dashboard\/top$/.test(u)) body = TOP();
      else if (/\/api\/user\/preferences$/.test(u) && m === "GET") body = Object.assign({ termaximus_active: true }, o.prefs || { hq_card_view: null, hq_orbit: null });
      else if (/\/api\/moon$/.test(u)) body = MOON_ANSWER;
      else if (/\/api\/user\/preferences$/.test(u)) body = { saved: true };
      const p = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(JSON.parse(JSON.stringify(body))) });
      p.catch(() => {});
      return p;
    };
    w.requestAnimationFrame = () => 1;
    w.cancelAnimationFrame = () => {};
    const phone = o.phone !== false;
    w.matchMedia = q => ({ matches: /max-width: 760px/.test(q) ? phone : (/reduced-motion/.test(q) ? !!o.reduce : false), addEventListener() {}, addListener() {} });
    Object.defineProperty(w.HTMLElement.prototype, "clientWidth", { configurable: true, get() { return this.id === "orbitStage" ? 340 : 0; } });
    w.IntersectionObserver = function () { this.observe = () => {}; this.disconnect = () => {}; };
    let err = null;
    for (const f of [ORBIT, MOON, VIEWS]) { try { w.eval(FILES[f]); } catch (e) { err = err || (f + ": " + e.message); } }
    await settle(60);
    return { w, d: w.document, calls, err, O: w.BFOrbit, H: w.BFHqViews, close: () => w.close() };
  }
  const q = (d, sel) => Array.prototype.slice.call(d.querySelectorAll(sel));
  const cardsOf = d => q(d, "#orbitMain > .orbit-main-box").concat(d.getElementById("orbitGrid").hidden ? [] : q(d, "#orbitGrid > .orbit-box"));
  const slugOf = c => c.getAttribute("data-card") || (c.classList.contains("orbit-dir") ? "agent-directory" : "?");
  const cardHref = (c, O) => { const a = c.querySelector("a.bf-btn"); return a ? a.getAttribute("href") : (O.tools()[slugOf(c)] || {}).href; };
  const rows = d => q(d, "#hqList > .hq-item").map(it => ({ slug: it.getAttribute("data-card"), href: (it.querySelector("a.hq-link") || { getAttribute: () => null }).getAttribute("href"), main: it.getAttribute("data-main"), more: !!it.querySelector(":scope > button.hq-more") }));

  /* ══ V and D. the view row and the defaults ══ */
  console.log("\n══ V. the view row; D. the defaults ══");
  let P = await page({ session: { bf_orbit_portal: "sell" } });
  check("the page's scripts ran without an error", !P.err, P.err);
  const row = P.d.getElementById("hqViewRow");
  const kids = row ? q(row, "h2, button") : [];
  check("V1. the view row sits right under the orbit's panel: the set title, then Large, Compact, Grid and the orbit button, in that order",
    !!row && P.d.getElementById("orbitPanel").nextElementSibling === row && kids.map(k => k.tagName === "H2" ? "title" : (k.getAttribute("data-view") || k.id)).join() === "title,large,compact,grid,hqOrbitBtn",
    J(kids.map(k => k.getAttribute("data-view") || k.id || k.tagName)));
  check("V2. each button has an aria-label and aria-pressed", kids.filter(k => k.tagName === "BUTTON").every(b => (b.getAttribute("aria-label") || "").length > 3 && /^(true|false)$/.test(b.getAttribute("aria-pressed"))));
  check("V3. each is 44 x 44 on the phone (the rule)", has(HQ_STYLE, ".hq-view-btn,.hq-more{display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;min-width:44px;min-height:44px;"));
  const titles = {};
  for (const p of ["grow", "sell", "connect", "agents", "oracle"]) { P.O.open(p); await settle(); titles[p] = P.d.getElementById("hqSetTitle").textContent; }
  check("V4. the set title names the open portal's set", J(titles) === J({ grow: "GROW TOOLS", sell: "SELL TOOLS", connect: "CONNECT TOOLS", agents: "AGENT TOOLS", oracle: "THE ORACLE" }), J(titles));
  const root = P.d.getElementById("orbitTop");
  check("D1. a member who has not chosen gets Compact (pressed) and the orbit shown (pressed)", root.getAttribute("data-hq-view") === "compact" && root.getAttribute("data-hq-orbit") === "shown" &&
    P.d.querySelector('.hq-view-btn[data-view="compact"]').getAttribute("aria-pressed") === "true" && P.d.getElementById("hqOrbitBtn").getAttribute("aria-pressed") === "true" &&
    q(P.d, '.hq-view-btn[data-view][aria-pressed="true"]').length === 1, J([root.getAttribute("data-hq-view"), root.getAttribute("data-hq-orbit")]));
  check("D2. with the server holding nothing, nothing is sent (no choice was made)", !P.calls.some(c => c.m === "PUT"), J(P.calls));

  /* ══ T. the three views ══ */
  console.log("\n══ T. the three views ══");
  const per = {};
  for (const p of ["grow", "sell", "connect", "agents", "oracle"]) {
    P.O.open(p); await settle();
    const cs = cardsOf(P.d), rs = rows(P.d);
    const portal = P.O.PORTALS.filter(x => x.key === p)[0];
    const want = portal.tools.filter(t => P.O.mains().indexOf(t) === -1 && P.O.tools()[t]).sort();
    per[p] = { cards: cs.map(slugOf), rows: rs.map(r => r.slug), sameLinks: cs.every((c, i) => rs[i] && rs[i].href === cardHref(c, P.O) && !!rs[i].href),
      gridIsPortal: J(q(P.d, "#orbitGrid > .orbit-box").map(slugOf).sort()) === J(want), mainsFirst: rs.slice(0, 2).every(r => r.main !== null) && rs.slice(2).every(r => r.main === null) };
  }
  check("T1. Compact: one row per Large card (the two main boxes, then the open portal's tools), in the same order, for each of the five portals",
    Object.keys(per).every(k => per[k].cards.length > 2 && J(per[k].cards) === J(per[k].rows) && per[k].mainsFirst), J(per));
  check("T2. each row links where its card's button links", Object.keys(per).every(k => per[k].sameLinks), J(Object.keys(per).filter(k => !per[k].sameLinks)));
  check("T3. the boxes are each portal's own set (bf-orbit.js PORTALS, less the main boxes): nothing invented", Object.keys(per).every(k => per[k].gridIsPortal));
  P.O.open("sell"); await settle();
  const r0 = q(P.d, "#hqList > .hq-item")[0];
  check("T4. a row: the 40 px icon tile (the card's own icon and colour), the name, the sub-line and the figure (or a chevron)",
    !!r0 && !!r0.querySelector(".hq-icon > .bf-neon-icon svg") && /analytics|store/i.test(r0.querySelector(".hq-name").textContent) && !!r0.querySelector(".hq-sub") &&
    q(P.d, "#hqList .hq-fig").every(f => !!f.querySelector(".hq-num") || !!f.querySelector("svg polyline")));
  const anaRow = q(P.d, '#hqList > .hq-item[data-card="analytics"]')[0], crmRow = q(P.d, '#hqList > .hq-item[data-card="crm"]')[0];
  check("T5. the key figure is the card's own (Analytics 29, CRM 18)", !!anaRow && anaRow.querySelector(".hq-num").textContent === "29" && !!crmRow && crmRow.querySelector(".hq-num").textContent === "18",
    J([anaRow && anaRow.textContent, crmRow && crmRow.textContent]));
  check("T6. Compact on the phone: rows at least 60 px, 8 px apart, the icon tile 40 px; the cards hidden while it shows",
    has(HQ_STYLE, ".hq-link{display:flex;align-items:center;gap:12px;min-height:60px;") && has(HQ_STYLE, ".hq-list{display:flex;flex-direction:column;gap:8px;") &&
    has(HQ_STYLE, ".hq-icon > .bf-neon-icon{width:40px;height:40px;border-radius:12px;") && has(HQ_STYLE, "#orbitTop:not([data-hq-view=\"large\"]) #orbitMain,#orbitTop:not([data-hq-view=\"large\"]) #orbitGrid{display:none !important}"));
  P.d.querySelector('.hq-view-btn[data-view="large"]').click(); await settle();
  check("T7. Large: the PH1 cards as they are (the list empty, the main boxes and the grid drawn)", root.getAttribute("data-hq-view") === "large" && q(P.d, "#hqList > *").length === 0 && q(P.d, "#orbitMain > .orbit-main-box").length === 2);
  P.d.querySelector('.hq-view-btn[data-view="grid"]').click(); await settle();
  check("T8. Grid: one tile per Large card, the same order and links", root.getAttribute("data-hq-view") === "grid" && J(rows(P.d).map(r => r.slug)) === J(cardsOf(P.d).map(slugOf)) &&
    rows(P.d).every((r, i) => r.href === cardHref(cardsOf(P.d)[i], P.O)));
  check("T9. Grid on the phone: two columns, 10 px apart, tiles at least 120 px",
    has(HQ_STYLE, "#orbitTop[data-hq-view=\"grid\"] .hq-list{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:10px}") && has(HQ_STYLE, "gap:8px;min-height:120px;"));
  const mainRows = rows(P.d).filter(r => r.main !== null);
  check("T10. the two main-box rows (and tiles) carry Swap, a 44 px overflow button; no other row does", mainRows.length === 2 && mainRows.every(r => r.more) && rows(P.d).filter(r => r.main === null).every(r => !r.more));
  const more = P.d.querySelector('#hqList > .hq-item[data-main="0"] > button.hq-more');
  if (more) more.click();
  await settle();
  const pick = P.d.querySelector('#hqList > .hq-item[data-main="0"] .orbit-swap-list button[data-tool="crm"]');
  const more2 = P.d.querySelector('#hqList > .hq-item[data-main="0"] > button.hq-more');   // the row is drawn again on a click
  check("T11. Swap opens the main box's own list (BFOrbit's Swap)", !!pick && !!more2 && more2.getAttribute("aria-expanded") === "true");
  if (pick) pick.click();
  await settle();
  let saved = null; try { saved = P.w.localStorage.getItem("bf_main_boxes"); } catch (e) { /* none */ }
  check("T12. choosing a tool there swaps the main box (bf_main_boxes) and the rows follow", J(P.O.mains()) === J(["crm", "store"]) && saved === J(["crm", "store"]) && rows(P.d)[0].slug === "crm", J([P.O.mains(), saved]));

  /* ══ O. the orbit toggle ══ */
  console.log("\n══ O. the orbit toggle and the chips ══");
  P.O.open("connect"); await settle();
  P.d.getElementById("hqOrbitBtn").click(); await settle();
  const chips = q(P.d, "#hqChips > .hq-chip");
  check("O1. the orbit button hides the orbit (aria-pressed false) and five chips stand in its place, in the orbit's order",
    root.getAttribute("data-hq-orbit") === "hidden" && P.d.getElementById("hqOrbitBtn").getAttribute("aria-pressed") === "false" &&
    chips.map(c => c.getAttribute("data-portal")).join() === "grow,sell,connect,agents,oracle" && P.d.getElementById("hqChips").nextElementSibling === P.d.getElementById("orbitStage"),
    J(chips.map(c => c.getAttribute("data-portal"))));
  check("O2. on the phone the hidden orbit's stage is not shown and the chips are, each at least 44 px", has(HQ_STYLE, "#orbitTop[data-hq-orbit=\"hidden\"] .orbit-stage{display:none}") &&
    has(HQ_STYLE, "#orbitTop[data-hq-orbit=\"hidden\"] .hq-chips{display:flex;") && has(HQ_STYLE, ".hq-chip{position:relative;flex:1 1 0;min-width:0;min-height:44px;"));
  const openChip = () => q(P.d, "#hqChips > .hq-chip.is-open").map(c => c.getAttribute("data-portal") + ":" + c.getAttribute("aria-pressed"));
  check("O3. the open portal's chip is highlighted (as the orbit highlights it: the accent border, the name in the accent)", J(openChip()) === J(["connect:true"]) &&
    has(HQ_STYLE, ".hq-chip.is-open{border:1.8px solid var(--bf-accent-a, #22d3ee);"), J(openChip()));
  P.d.querySelector('#hqChips > .hq-chip[data-portal="agents"]').click(); await settle();
  check("O4. a chip opens its portal", P.O.state.open === "agents" && J(openChip()) === J(["agents:true"]) && P.d.getElementById("hqSetTitle").textContent === "AGENT TOOLS");
  P.d.getElementById("hqOrbitBtn").click(); await settle();
  const portalOpen = q(P.d, ".orbit-portal.is-open").map(b => b.getAttribute("data-portal"));
  check("O5. the orbit shown again keeps the same open portal", root.getAttribute("data-hq-orbit") === "shown" && P.O.state.open === "agents" && J(portalOpen) === J(["agents"]), J([P.O.state.open, portalOpen]));

  /* ══ C. the saved choices ══ */
  console.log("\n══ C. the saved choices ══");
  const puts = P.calls.filter(c => c.m === "PUT" && /\/api\/user\/preferences$/.test(c.u)).map(c => c.body);
  check("C1. each choice is sent to the server (PUT /api/user/preferences), one field at a time", J(puts) === J([{ hq_card_view: "large" }, { hq_card_view: "grid" }, { hq_orbit: "hidden" }, { hq_orbit: "shown" }]), J(puts));
  let lv = null, lo = null; try { lv = P.w.localStorage.getItem("bf_hq_view"); lo = P.w.localStorage.getItem("bf_hq_orbit"); } catch (e) { /* none */ }
  check("C2. and kept on this device (bf_hq_view, bf_hq_orbit)", lv === "grid" && lo === "shown", J([lv, lo]));
  P.close();
  // a reload: the device copy at once; the server's choice once it arrives
  let P2 = await page({ local: { bf_hq_view: "grid", bf_hq_orbit: "hidden" }, prefs: { hq_card_view: "large", hq_orbit: "shown" }, session: { bf_orbit_portal: "sell" } });
  check("C3. on a reload the server's stored choice wins once it arrives (large, shown), and the device copy follows it",
    P2.d.getElementById("orbitTop").getAttribute("data-hq-view") === "large" && P2.d.getElementById("orbitTop").getAttribute("data-hq-orbit") === "shown" && P2.w.localStorage.getItem("bf_hq_view") === "large",
    J([P2.d.getElementById("orbitTop").getAttribute("data-hq-view"), P2.d.getElementById("orbitTop").getAttribute("data-hq-orbit")]));
  P2.close();
  // before the server answers: a page whose fetch never answers the preferences
  {
    const dom = await page({ local: { bf_hq_view: "grid", bf_hq_orbit: "hidden" }, prefs: { hq_card_view: null, hq_orbit: null } });
    const r = dom.d.getElementById("orbitTop");
    const sent = dom.calls.filter(c => c.m === "PUT").map(c => c.body);
    check("C4. the device copy applies (grid, hidden); a choice the server does not hold yet is sent to it", r.getAttribute("data-hq-view") === "grid" && r.getAttribute("data-hq-orbit") === "hidden" &&
      J(sent) === J([{ hq_card_view: "grid", hq_orbit: "hidden" }]), J([r.getAttribute("data-hq-view"), r.getAttribute("data-hq-orbit"), sent]));
    dom.close();
  }
  {
    const dom = await page({ local: { bf_hq_view: "huge" } });
    check("C5. a device copy outside the list is ignored (Compact)", dom.d.getElementById("orbitTop").getAttribute("data-hq-view") === "compact");
    dom.close();
  }
  check("C6. sign-out clears the device copy (bf-session.js PER_USER_LOCAL)", has(FILES[SESSION], "    \"bf_main_boxes\",\n    \"bf_hq_view\", \"bf_hq_orbit\",\n"));
  check("C7. every storage access is in try/catch", /function readLocal\(k\) \{ try \{ return window\.localStorage\.getItem\(k\); \} catch \(e\) \{ return null; \} \}/.test(FILES[VIEWS]) &&
    /function writeLocal\(k, v\) \{ try \{ window\.localStorage\.setItem\(k, v\); return true; \} catch \(e\) \{ return false; \} \}/.test(FILES[VIEWS]) &&
    (FILES[VIEWS].match(/localStorage\./g) || []).length === 3);

  /* ══ P. phone only ══ */
  console.log("\n══ P. phone only ══");
  const st = noComments(HQ_STYLE);
  const media = blockAt(st, "@media (max-width: 760px){");
  const reduced = blockAt(st, "@media (prefers-reduced-motion: reduce){");
  const keys = blockAt(st, "@keyframes tmx-gold-shimmer {");
  const voidKeys = blockAt(st, "@keyframes tmx-chat-void {");   // NAMED (Nov 22 2026, FX3): the chat box's drift, for the abyss sun
  let outside = st;
  [media, reduced, keys, voidKeys].filter(Boolean).sort((a, b) => b.start - a.start).forEach(b => { outside = outside.slice(0, b.start) + outside.slice(b.end); });
  const outRules = outside.split("}").map(x => x.trim()).filter(Boolean).map(x => x.split("{")[0].trim());
  check("P1. outside @media (max-width: 760px) the block only hides HQ1's elements and defines the gold, its keyframes and its still version",
    // NAMED (Nov 21 2026, FX2): the hide list gained .hq-core-sun (the centre's Sun); the comment after it is no rule
    // NAMED (Nov 22 2026, FX3): BEFORE .hq-core-sun. AFTER .hq-core-abyss, and the tmx-chat-void keyframes (set aside like the gold's)
    !!media && !!voidKeys && J(outRules.map(r => r.replace(/^\/\*[\s\S]*?\*\/\s*/, ""))) === J([".hq-chips,.hq-view-row,.hq-list,.hq-moon,.hq-core-moon,.hq-core-abyss,.hq-gold-ring", ".hq-gold,.hq-gold-ring", ".hq-gold-ring", ".hq-gold-glyph"]) &&
    /\.hq-chips,\.hq-view-row,\.hq-list,\.hq-moon,\.hq-core-moon,\.hq-core-abyss,\.hq-gold-ring\{display:none\}/.test(outside) &&
    // the only shown display outside: the gold glyph's block, which lives inside .hq-list (hidden above 760 px)
    !/display:(?!none)/.test(outside.replace(".hq-gold-glyph{display:block;", ".hq-gold-glyph{")), J(outRules));
  {
    const dom = await page({ phone: false, session: { bf_orbit_portal: "oracle" } });
    const asked = dom.calls.filter(c => /\/api\/user\/preferences|\/api\/moon/.test(c.u));
    const label = dom.d.querySelector('.orbit-portal[data-portal="oracle"] .orbit-portal-name');
    check("P2. above 760 px nothing is asked of the server (no preferences, no moon) and no moon is drawn", asked.length === 0 && q(dom.d, "[data-hq-moon] svg").length === 0, J(asked));
    check("P3. above 760 px the orbit's own label is not gold (the desktop unchanged)", !!label && !label.classList.contains("hq-gold"));
    dom.close();
  }

  /* ══ M. the moon ══ */
  console.log("\n══ M. the moon ══");
  const ORA = FILES["oracle.html"] || "";
  const START = "    /* ── Moon phase (standard synodic-month calculation) ── */";
  const oa = ORA.indexOf(START), orr = ORA.indexOf("function renderAbyssMoon()", oa), oe = orr < 0 ? -1 : ORA.indexOf("\n    }\n", orr) + "\n    }".length;
  const ORA_BLOCK = oa >= 0 && oe > oa ? ORA.slice(oa, oe) : null;
  const between = (t, a, b) => { const i = t.indexOf(a), k = t.indexOf(b, i); return i >= 0 && k > i ? t.slice(i + a.length, k) : null; };
  const COPY = between(FILES[MOON] || "", "/* BEGIN COPY oracle.html moon block (exact; scripts/checkHqViews.js holds it equal) */\n", "\n/* END COPY oracle.html moon block */");
  const IMG = between(FILES[MOON] || "", "/* BEGIN COPY oracle.html MOON_IMG_URL (exact; scripts/checkHqViews.js holds it equal) */\n", "\n/* END COPY oracle.html MOON_IMG_URL */");
  const oraImg = ORA.split("\n").filter(l => l.indexOf("var MOON_IMG_URL = ") !== -1);
  check("M1. the copy is oracle.html's moon block, character for character (getMoonData to renderAbyssMoon)", !!ORA_BLOCK && COPY === ORA_BLOCK && ORA_BLOCK.length > 8000, ORA_BLOCK && COPY ? "lengths " + ORA_BLOCK.length + " / " + COPY.length : "a block is missing");
  check("M2. it holds every function the Oracle's moon uses", !!COPY && ["getMoonData", "fetchRealMoonPhase", "refreshRealMoonPhase", "buildMoonTerminatorPath", "drawSmallMoonSVG", "renderMoon", "renderAbyssMoon"].every(f => has(COPY, "function " + f + "(")));
  check("M3. and MOON_IMG_URL, as oracle.html has it", oraImg.length === 1 && IMG === oraImg[0], J([IMG, oraImg]));
  let PM = await page({ session: { bf_orbit_portal: "oracle" } });
  PM.d.getElementById("hqOrbitBtn").click(); await settle(60);
  // NAMED (Nov 21 2026, FX2): BEFORE three moons (the node, the chip, the centre). AFTER two: the centre is the Sun (M7 to M10).
  const moons = ["node", "chip"].map(k => PM.d.querySelector('[data-hq-moon="' + k + '"]'));
  const inPlace = !!moons[0] && !!moons[0].closest('.orbit-portal[data-portal="oracle"]') && !!moons[1] && !!moons[1].closest('.hq-chip[data-portal="oracle"]') && !PM.d.querySelector('#orbitCore [data-hq-moon]');
  check("M4. the moon is drawn on the ORACLE node and the ORACLE chip (none in the centre), each the Oracle's realistic moon (its photo through the lit mask)",
    inPlace && moons.every(m => m.querySelector("svg image") && m.querySelector("svg image").getAttribute("href") === (IMG || "").replace(/^.*"(https[^"]+)".*$/, "$1") && m.querySelector("mask path")), J(moons.map(m => m && m.innerHTML.length)));
  const asked = PM.calls.filter(c => /\/api\/moon$/.test(c.u)).length;
  check("M5. with the live phase from GET /api/moon (the Oracle's answer, its phase angle 101.5)", asked >= 1 && moons.every(m => m && m.getAttribute("data-moon-angle") === "101.5" && m.getAttribute("data-moon-live") === "true"),
    J([asked, moons.map(m => m && m.getAttribute("data-moon-angle"))]));
  const ids = q(PM.d, "[data-hq-moon] [id]").map(n => n.id);
  check("M6. every moon has its own SVG ids (no two masks share one), and every url(#) points inside its own moon",
    ids.length >= 18 && new Set(ids).size === ids.length   /* NAMED (Nov 21 2026, FX2): BEFORE >= 27 (three moons); AFTER two */ && moons.every(m => (m.innerHTML.match(/url\(#([^)]+)\)/g) || []).every(u => !!m.querySelector("#" + u.slice(5, -1)))), J(ids.length));
  /* FX3B (Nov 22 2026): NAMED BEFORE every repaint showed a moon again (drawn whole, its masks and blurs) until its photo's
     error hid it once more. AFTER a moon whose photo failed stays hidden while it is drawn again, a probe of the photo
     shows it once the photo loads, and a moon whose photo had not failed is painted as before. */
  {
    const MO = PM.w.BFOracleMoon, node = moons[0], chip = moons[1], RealImage = PM.w.Image, made = [];
    MO.paint();
    const shown = !!node && !node.hidden && !chip.hidden;
    node.querySelector("svg image").dispatchEvent(new PM.w.Event("error"));
    const failedNow = node.hidden && node.getAttribute("data-hq-moon-failed") === "true" && !chip.hidden;
    PM.w.Image = function () { const im = new RealImage(); made.push(im); return im; };
    MO.paint();
    const kept = node.hidden && !!node.querySelector("svg image") && node.getAttribute("data-moon-angle") === "101.5" && !chip.hidden;
    const probe = made[0], href = node.querySelector("svg image").getAttribute("href");
    if (probe && probe.onload) probe.onload();
    const back = !node.hidden && !node.hasAttribute("data-hq-moon-failed");
    node.querySelector("svg image").dispatchEvent(new PM.w.Event("error")); made.length = 0; MO.paint();
    node.querySelector("svg image").dispatchEvent(new PM.w.Event("error"));
    if (made[0] && made[0].onload) made[0].onload();
    const staysLost = node.hidden && node.getAttribute("data-hq-moon-failed") === "true";
    PM.w.Image = RealImage;
    check("M11. a moon whose photo failed stays hidden when it is drawn again (its drawing renewed); a probe of the photo shows it once the photo loads, and not if its own photo failed; the other moon is painted as before",
      shown && failedNow && kept && made.length >= 1 && !!probe && probe.src === href && back && staysLost, J([shown, failedNow, kept, made.length, probe && probe.src === href, back, staysLost]));
  }
  const cent = PM.d.getElementById("orbitTop").getAttribute("data-hq-open");
  // NAMED (Nov 21 2026, FX2): BEFORE "M7. the centre's moon shows only while ORACLE is open". AFTER the Sun, M7 to M10.
  // NAMED (Nov 22 2026, FX3): BEFORE the Sun (NASA SDO's photograph, its glow, its shimmer, its credit). AFTER the abyss sun, M7 to M10.
  const core = PM.d.getElementById("orbitCore"), abEl = core && core.querySelector(".hq-core-abyss"), abCv = abEl && abEl.querySelector("canvas.hq-core-abyss-canvas");
  check("M7. the centre's abyss shows only while ORACLE is open (the rule), first in the centre, under its words, with the gold ring after them",
    cent === "oracle" && !!abEl && core.firstChild === abEl && !!core.lastChild && core.lastChild.className === "hq-gold-ring" &&
    has(HQ_STYLE, "#orbitTop[data-hq-open=\"oracle\"] .hq-core-abyss{display:block;position:absolute;inset:0;border-radius:50%;overflow:hidden;pointer-events:none;z-index:0;") &&
    has(HQ_STYLE, "#orbitTop[data-hq-open=\"oracle\"] .orbit-core > :not(.hq-core-moon):not(.hq-core-abyss):not(.hq-gold-ring){position:relative;z-index:1;"));
  // the chat box's own rule, read from the presence's style lines
  const PRES0 = FILES[PRESENCE] || "";
  const presRule = head => { const a = PRES0.indexOf(head); if (a < 0) return ""; const b = PRES0.indexOf("\"}\",", a); return PRES0.slice(a, b).split("\n").map(l => (/^\s*"(.*)",?\s*$/.exec(l) || [])[1]).filter(x => x !== undefined).join("\n"); };
  const chatRule = presRule("\"#tmx-chat {\","), chatKeys = presRule("\"@keyframes tmx-chat-void {\",") + "\n}";
  const bgOf = s => { const m = /background:\s*([\s\S]*?rgba\(2,1,10,0\.98\));/.exec(s || ""); return m ? squash(m[1]) : null; };
  const val = (s, k) => { const m = String(s || "").split(/[;{}]/).map(x => x.trim()).filter(x => x.indexOf(k + ":") === 0)[0]; return m ? squash(m.slice(k.length + 1)) : null; };
  const abRule = (blockAt(HQ_STYLE, "#orbitTop[data-hq-open=\"oracle\"] .hq-core-abyss{") || {}).body || "";
  const keyBody = s => { const b = blockAt(s || "", "@keyframes tmx-chat-void {"); return b ? squash(b.body) : null; };
  check("M8. its background is EXACTLY the chat box's void: the same four gradients over rgba(2,1,10,0.98), the same sizes, the tmx-chat-void drift at 22 s, the same keyframes",
    !!bgOf(chatRule) && bgOf(abRule) === bgOf(chatRule) && (bgOf(chatRule).match(/radial-gradient/g) || []).length === 4 &&
    val(abRule, "background-size") === val(chatRule, "background-size") && val(abRule, "background-size") === "200% 200%, 200% 200%, 200% 200%, 240% 240%" &&
    val(abRule, "animation") === val(chatRule, "animation") && val(abRule, "animation") === "tmx-chat-void 22s ease-in-out infinite" &&
    !!keyBody(chatKeys) && keyBody(HQ_STYLE) === keyBody(chatKeys), J([bgOf(abRule), bgOf(chatRule), val(abRule, "background-size"), val(abRule, "animation"), keyBody(HQ_STYLE), keyBody(chatKeys)]));
  const SUN_FILE = path.join(FRONTEND, "brand", "sun-sdo-hmi-20261121.webp");
  check("M9. clipped to the circle, decorative (aria-hidden), a canvas on top running the chat's starfield at its density per area (BFAbyss, perArea); no glow, rays or corona; the NASA image gone",
    !!abEl && abEl.getAttribute("aria-hidden") === "true" && !!abCv && /border-radius:50%/.test(abRule) && /overflow:hidden/.test(abRule) &&
    has(FILES[VIEWS], "if (window.BFAbyss) abyss = window.BFAbyss.create(cv, { perArea: true });") &&
    !/box-shadow|filter:|corona|rays/.test(abRule) && !/hq-core-abyss[^{]*::(after|before)/.test(HQ_STYLE) && !fs.existsSync(SUN_FILE) && !/sun-sdo|hq-core-sun/.test(noComments(HQ_STYLE)), J([abRule.slice(0, 200)]));
  check("M10. the stars run only while ORACLE is open on the phone with the orbit shown; still under reduced motion; the green stats ring hidden while ORACLE is open",
    has(FILES[VIEWS], "    abyssRun(open === \"oracle\" && phone() && state.orbit === \"shown\");") &&
    has(HQ_STYLE, "    @media (prefers-reduced-motion: reduce){ .hq-core-abyss{animation:none !important} }") &&
    has(HQ_STYLE, "#orbitTop[data-hq-open=\"oracle\"] .orbit-core-halo,#orbitTop[data-hq-open=\"oracle\"] .orbit-core-arc,#orbitTop[data-hq-open=\"oracle\"] .orbit-goal-arc{display:none}"));

  /* ══ G. the gold ══ */
  console.log("\n══ G. the gold ══");
  const PRES = FILES[PRESENCE] || "";
  const presLines = (head, endLine) => { const a = PRES.indexOf(head); if (a < 0) return null; const b = PRES.indexOf(endLine, a); return PRES.slice(a, b).split("\n").map(l => (/^\s*"(.*)",?\s*$/.exec(l) || [])[1]).filter(x => x !== undefined).join("\n"); };
  const chatRim = presLines("\"#tmx-chat::before {\",", "\"@keyframes tmx-gold-shimmer {\",");
  const presKeys = presLines("\"@keyframes tmx-gold-shimmer {\",", "/* live canvas deep-space starfield");
  const gradOf = t => { const m = /background:\s*(linear-gradient\(135deg,[\s\S]*?\));/.exec(t || ""); return m ? squash(m[1]) : null; };
  const goldDef = (blockAt(HQ_STYLE, ".hq-gold,.hq-gold-ring{") || {}).body || "";
  check("G1. the same nine-stop gradient as the chat box's rim", !!gradOf(chatRim) && gradOf(goldDef) === gradOf(chatRim) && (gradOf(chatRim).match(/%/g) || []).length === 9, J([gradOf(goldDef), gradOf(chatRim)]));
  const prop = (t, p) => { const m = new RegExp(p + ":\\s*([^;]+);").exec(t || ""); return m ? squash(m[1]) : null; };
  check("G2. the same size (260% 260%) and animation (tmx-gold-shimmer 7s ease-in-out infinite)", prop(goldDef, "background-size") === prop(chatRim, "background-size") && prop(goldDef, "background-size") === "260% 260%" &&
    prop(goldDef, "animation") === prop(chatRim, "animation") && prop(chatRim, "animation") === "tmx-gold-shimmer 7s ease-in-out infinite", J([prop(goldDef, "animation"), prop(chatRim, "animation")]));
  const myKeys = (blockAt(HQ_STYLE, "@keyframes tmx-gold-shimmer {") || {}).text;
  check("G3. the same keyframes", !!presKeys && squash(myKeys) === squash(presKeys), J([squash(myKeys), squash(presKeys)]));
  check("G4. the rings use the chat box's mask method", has(HQ_STYLE, "-webkit-mask:linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);-webkit-mask-composite:xor;mask-composite:exclude") &&
    has(chatRim, "-webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);"));
  check("G5. under prefers-reduced-motion the shine holds still", has(HQ_STYLE, "@media (prefers-reduced-motion: reduce){ .hq-gold,.hq-gold-ring{animation:none} }"));
  check("G6. no other gold in HQ1's block (no flat or made-up gold)", (noComments(HQ_STYLE).match(/#[0-9a-f]{6}\b/gi) || []).filter(c => /^#(6b4e00|b8860b|fff6d5|d4af37|f7dd8a|8b6508|fff3c4)$/i.test(c) === false && /^#(ffc46b|fbbf24|f5c|d4af|ffd)/i.test(c)).length === 0);
  const goldOn = sel => !!PM.d.querySelector(sel) && PM.d.querySelector(sel).classList.contains("hq-gold");
  check("G7. with ORACLE open: the set title, the '(open)' label and the chip's name in gold; the gold rings on the node, the chip and the centre",
    goldOn("#hqSetTitle") && goldOn('.orbit-portal[data-portal="oracle"] .orbit-portal-name') && goldOn('.hq-chip[data-portal="oracle"] .hq-chip-name') &&
    !!PM.d.querySelector('.orbit-portal[data-portal="oracle"] .orbit-disc > .hq-gold-ring') && !!PM.d.querySelector('.hq-chip[data-portal="oracle"] .hq-gold-ring') && !!PM.d.querySelector("#orbitCore > .hq-gold-ring") &&
    has(HQ_STYLE, ".hq-set-title.hq-gold,.orbit-portal-name.hq-gold,.hq-chip-name.hq-gold{-webkit-background-clip:text;background-clip:text;color:transparent !important;"));
  const oracleRows = q(PM.d, "#hqList > .hq-item").filter(it => ["oracle", "mychart", "synastry", "the-third"].indexOf(it.getAttribute("data-card")) !== -1);
  check("G8. the Oracle tools' icons are the gold, masked by each icon's own drawing (and their violet tiles stay)",
    oracleRows.length === 4 && oracleRows.every(it => it.getAttribute("data-gold") === "true" && /data:image\/svg\+xml/.test(it.querySelector(".hq-gold-glyph").style.getPropertyValue("mask-image")) && /border-color:rgba\(var\(--bf-accent-b-rgb/.test(it.querySelector(".bf-neon-icon").getAttribute("style") || "")),
    J(oracleRows.map(it => it.getAttribute("data-card"))));
  PM.O.open("sell"); await settle();
  check("G9. with another portal open, nothing is gold", q(PM.d, ".hq-gold").length === 0, J(q(PM.d, ".hq-gold").map(n => n.className)));
  PM.close();

  /* ══ U. the Oracle pages ══ */
  console.log("\n══ U. no Oracle page changed ══");
  const changed = ORACLE_PAGES.filter(f => {
    let base = null;
    try { base = execFileSync("git", ["show", PH1_COMMIT + ":" + f], { cwd: FRONTEND, maxBuffer: 64 << 20 }).toString("utf8").replace(/\r\n/g, "\n"); } catch (e) { return true; }
    return base !== FILES[f];
  });
  check("U1. oracle.html, mychart.html, calendar.html, synastry.html and the-third.html are as they were at " + PH1_COMMIT, changed.length === 0, J(changed));

  /* ══ A. the boombox's sound on a page's load ══ */
  console.log("\n══ A. the boombox: sound on load only with the setting on ══");
  const M = FILES[MUSIC] || "";
  check("A1. one rule: loadPlayAllowed is the setting on (saved by its checkbox) and no pause or stop in this visit",
    once(M, "  function loadPlayAllowed() { return S.autoplay === true && !held(); }") && once(M, "  function setAutoplay(on) { S.autoplay = !!on; save(); render(); }"));
  const startFn = s.definitionOf ? null : null;
  const bootA = M.indexOf("    loadLibrary().then(function () {\n      /* HQ1"), bootB = M.indexOf("\n    });\n  }", bootA);
  const boot = bootA >= 0 && bootB > bootA ? M.slice(bootA, bootB) : "";
  const bootCode = noComments(boot);
  check("A2. on load, the carry-on from the last page runs only when it is allowed", /if \(loadPlayAllowed\(\) && S\.was_playing && S\.track_id && trackById\(S\.track_id\)\) \{\s*setTimeout\(resumeAfterNavigation, RESUME_WAIT_MS\);/.test(bootCode), boot.slice(0, 200));
  check("A3. on load, 'Play when I open BizForce' plays only when it is allowed, on every page alike (the dashboard's icon no longer left out)",
    /if \(loadPlayAllowed\(\) && LIB\.tracks\.length\) play\(\{ auto: true \}\);/.test(bootCode) && (bootCode.match(/play\(/g) || []).length === 1 && !/state\(\) === "icon"/.test(bootCode));
  check("A4. the carry-on itself checks the rule first", /function resumeAfterNavigation\(\) \{\n    R\.settled = true;\n    if \(!loadPlayAllowed\(\)\) \{ save\(\); render\(\); return Promise\.resolve\(false\); \}/.test(M));
  check("A5. a pause or a stop by the member is remembered for the visit; pressing play (or a track) clears it; the automatic start does not",
    has(M, "  function pause() { hold(true); if (popoutAlive())") && /function stop\(\) \{\n    hold\(true\);/.test(M) && has(M, "    if (!(opts && opts.auto)) hold(false);") && /function playTrack\(id\) \{\n    hold\(false\);/.test(M) &&
    has(M, "var HELD_KEY = \"bf_music_live_held\";") && has(M, "sessionStorage.getItem(HELD_KEY) === UID"));
  check("A6. the held flag is cleared at sign-out (its name starts with bf-session.js's \"bf_music_live\" prefix)", has(FILES[SESSION], "\"bf_music_live\"") && "bf_music_live_held".indexOf("bf_music_live") === 0);
  // every page that loads the boombox gets it from bf-music.js (directly or through bf-session.js), and starts nothing itself
  const boomPages = PAGES.filter(p => FILES[p] && has(FILES[p], "/scripts/termaximus-presence.js") && (has(FILES[p], "/scripts/bf-session.js") || has(FILES[p], "/scripts/bf-music.js")));
  const selfPlay = boomPages.filter(p => /BFMusic\.(play|toggle|playTrack|resume)\(|<audio[^>]*\bautoplay\b/.test(FILES[p]));
  check("A7. on every page that loads the boombox (" + boomPages.length + "), only bf-music.js starts its sound: no page plays it by itself", boomPages.length >= 30 && selfPlay.length === 0, J(selfPlay));

  /* ══ W. the service worker ══ */
  console.log("\n══ W. the service worker ══");
  // NAMED (Nov 19 2026, P2-1): BEFORE "hq1". AFTER "p21": the bottom bar, Home, the Inbox, the profile header and Settings, Local in the shell (checkAppShell W).
  // NAMED (Nov 20 2026, P2-2): BEFORE "p21". AFTER "p22": the report, block and mute menu (bf-safety.js), moderation.html and copyright.html in the shell.
  // NAMED (Nov 20 2026, P2-3): BEFORE "p22". AFTER "p23": posts, the Following feed, Talk and follows (bf-feed.js, bf-composer.js) and compose.html in the shell.
  // NAMED (Nov 20 2026, FX1): BEFORE "p23". AFTER "fx1": Home's feed and the Profile as the approved design pictures.
  // NAMED (Nov 20 2026, P3-1): BEFORE "fx1". AFTER "p31": free accounts (the members panel, the verification banner, landing by tier).
  // NAMED (Nov 21 2026, P3-2): BEFORE "p31". AFTER "p32": the Verified badge (bf-verified.js), and the members panel on media and business ID.
  // NAMED (Nov 21 2026, FX2): BEFORE "p32". AFTER "fx2": the feed's Tip and product strip, the Profile's banner, the Agent Directory's views (bf-agents-views.js) and the Oracle's Sun.
  // NAMED (Nov 21 2026, P3-1B): BEFORE "fx2". AFTER "p31b": the free-account rules (bf-access.js Buy sheet and members intercepts, the Create sheet's Members tags, the composer's photo rule and Show in Google, Talk's members box).
  // NAMED (Nov 21 2026, P3-1C): BEFORE SHELL_REV "p31b". AFTER "p31c" (the wallet's member-welcome sentence and ledger labels).
  // NAMED (Nov 22 2026, FX3): BEFORE "p31c". AFTER "fx3" (the abyss sun, Termaximus on the phone, the agent cards).
  // NAMED (Nov 22 2026, FX3B): BEFORE "fx3"; AFTER "fx3b"
  // NAMED (Nov 23 2026, P3-3): BEFORE "fx3b"; AFTER "p33" (Share, Offer or Need, the Need post and I can help, the Market filter)
  // NAMED (Nov 23 2026, LR-1): BEFORE "p33"; AFTER "lr1" (approve each reply before it posts, the Lead Radar sign-in prompt, tidy-ups). sw.js now carries its note on the SHELL_REV line, so the line may end in a // comment.
  // NAMED (Nov 25 2026, HOTFIX-G1): BEFORE "lr4b"; AFTER "g1" (phone layouts restored; only the controls under the Guide tab moved). LR-4B: BEFORE "lr4"; AFTER "lr4b" (the storefront menu draws whichever loads first). LR-4: BEFORE "lr3b"; AFTER "lr4" (Get found). LR-3B: BEFORE "lr3"; AFTER "lr3b" (nothing to tap under the Guide tab on the phone). LR-3: BEFORE "lr2b"; AFTER "lr3" (Inbound, the storefront Message button). LR-2B: BEFORE "lr2"; LR-2: BEFORE "lr1b".
  check("W1. SHELL_REV \"g1\" (bumped past HQ1's \"hq1\") in the cache's name, and the two new scripts cached", /var SHELL_REV = "g1";[ \t]*(?:\/\/[^\n]*)?\nvar CACHE = "bf-shell-" \+ BUILD \+ "-" \+ SHELL_REV;/.test(FILES[SW]) &&
    has(FILES[SW], "\"/scripts/bf-oracle-moon.js\", \"/scripts/bf-hq-views.js\","));
  check("W2. the dashboard loads both, after bf-orbit.js (NAMED, Nov 22 2026, FX3: bf-abyss.js, the abyss sun's stars, just before bf-oracle-moon.js)", /<script src="\/scripts\/bf-orbit\.js"><\/script>\n[\s\S]*?<script src="\/scripts\/bf-abyss\.js"><\/script>\n<script src="\/scripts\/bf-oracle-moon\.js"><\/script>\n<script src="\/scripts\/bf-hq-views\.js"><\/script>/.test(FILES[DASH]));

  /* ══ N. no emoji ══ */
  const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
  const blocks = { [VIEWS]: FILES[VIEWS], [MOON]: FILES[MOON], "dashboard.html (hq1Phone)": HQ_STYLE, [MIG]: FILES[MIG] };
  const withEmoji = Object.keys(blocks).filter(k => EMOJI.test(blocks[k] || ""));
  check("N1. no emoji in any file HQ1 added", withEmoji.length === 0, J(withEmoji));

  if (failures) { console.log("\nCHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("\nALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
