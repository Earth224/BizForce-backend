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
        font (as at the frontend's 1803344)

   It also prints the show and hide list as built (SHOWN / HIDDEN lines).

   Run: node scripts/checkAppShell.js      MUTATE=<name> | all
   Nothing here touches the live database or the network.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const H = require("./_p21Harness");

const P20_COMMIT = "1803344";   // the frontend before P2-1
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
  "shown-on-oracle": [[BAR, "    \"oracle.html\", \"mychart.html\", \"calendar.html\", \"synastry.html\", \"the-third.html\"\n", "    \"mychart.html\", \"calendar.html\", \"synastry.html\", \"the-third.html\"\n"]],
  "shown-on-legal": [[BAR, "    \"terms.html\", \"privacy.html\", \"refund.html\", \"contact.html\",\n", "    \"terms.html\", \"refund.html\", \"contact.html\",\n"]],
  "shown-on-campaign-link": [[BAR, "\"/campaign/\", \"/c/\", ", "\"/c/\", "]],
  "ignores-page-off": [[BAR, "    if (document.documentElement.getAttribute(\"data-bf-tabbar\") === \"off\") return false;\n", ""]],
  "shown-signed-out": [[BAR, "    if (!token()) return false;\n    if (HIDDEN_PAGES", "    if (HIDDEN_PAGES"]],
  "wrong-active": [[BAR, "\"profile.html\": \"profile\", \"settings.html\": \"profile\"", "\"profile.html\": \"profile\", \"settings.html\": \"hq\""]],
  "four-tabs": [[BAR, "    { key: \"home\", label: \"Home\", href: \"/home.html\" },\n", ""]],
  "bar-on-desktop": [[BAR, "    \"#bf-tabbar,#bf-tabbar-spacer{display:none}\",\n", "    \"#bf-tabbar{display:flex}\",\n"]],
  "bar-over-dialogs": [[BAR, "align-items:stretch;background:rgba(7,11,24,.97);", "align-items:stretch;z-index:2147483646;background:rgba(7,11,24,.97);"]],
  "guide-not-raised": [[BAR, "    \"html.bf-tabbar-on #tmx-guide-fab{bottom:calc(56px + 16px + env(safe-area-inset-bottom, 0px))}\",\n", ""]],
  "guide-spacer-short": [[BAR, "height:calc(136px + env(safe-area-inset-bottom, 0px))!important", "height:calc(80px + env(safe-area-inset-bottom, 0px))!important"]],
  "no-safe-area": [[BAR, "html.bf-tabbar-on #bf-tabbar-spacer{display:block;height:calc(56px + env(safe-area-inset-bottom, 0px))}", "html.bf-tabbar-on #bf-tabbar-spacer{display:block;height:56px}"]],
  "small-tabs": [[BAR, "#bf-tabbar .bf-tab{flex:1 1 0;min-width:44px;min-height:44px;", "#bf-tabbar .bf-tab{flex:1 1 0;min-width:44px;min-height:30px;"]],
  "styles-everywhere": [[BAR, "    if (!wanted()) return;   // a page the bar is not on", "    addStyle();\n    if (!wanted()) return;   // a page the bar is not on"]],
  "badge-on-zero": [[BAR, "    badge.hidden = count === 0;", "    badge.hidden = false;"]],
  "post-not-soon": [[BAR, "{ key: \"post\", title: \"Post\", sub: \"Photo or text to your followers\", soon: true,", "{ key: \"post\", title: \"Post\", sub: \"Photo or text to your followers\", href: \"/run.html\","]],
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
  "sw-old-rev": [[SW, "var SHELL_REV = \"p22\";", "var SHELL_REV = \"hq1\";"]],
  "sw-no-bar": [[SW, "  \"/scripts/bf-tabbar.js\", \"/scripts/bf-profile-shell.js\", \"/scripts/bf-local-settings.js\",\n", "  \"/scripts/bf-profile-shell.js\", \"/scripts/bf-local-settings.js\",\n"]],
  "sw-no-pages": [[SW, "  \"home.html\", \"inbox.html\"   //", "  //"]],
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
  check("L2. above the page (the Guide button is 40) and below dialogs: the Create sheet (2147483301), the music player's sheet (2147483000), the Guide's panel (2147483600)",
    z === 90 && z > 40 && z < 2147483000 && has(css, "#bf-create{position:fixed;z-index:2147483301;") && has(music, "2147483000") && has(FILES["scripts/termaximus-guide.js"], "z-index: 2147483600;") &&
    !/z-index:\s*(?:[0-9]{3,})/.test((/align-items:stretch;[^"]*?backdrop-filter:blur\(12px\)\}/.exec(css) || [""])[0]), J(z));
  check("L3. the Guide button sits 56 px higher and its spacer grows to 136 px", has(css, "html.bf-tabbar-on #tmx-guide-fab{bottom:calc(56px + 16px + env(safe-area-inset-bottom, 0px))}") &&
    has(css, "html.bf-tabbar-on #tmx-guide-fab-spacer{display:block!important;height:calc(136px + env(safe-area-inset-bottom, 0px))!important}"));
  check("L4. a page with the Guide uses its spacer, not a second one", has(css, "html.bf-tabbar-on body:has(#tmx-guide-fab-spacer) #bf-tabbar-spacer{display:none}"));
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
  check("C2. Post and Video are Coming soon and go nowhere; the rest open their real creators",
    J(opts) === J(["post:soon", "video:soon", "product:/marketplace.html?create=product", "service:/marketplace.html?create=service", "agent:/run.html",
      "campaign:/campaigns.html?create=campaign", "garage:/garage-sale.html?create=item", "card:/digital-cards.html"]), J(opts));
  const soon = Array.from(sheet.querySelectorAll(".is-soon"));
  check("C3. each Coming soon item says so and is not a link or a button", soon.length === 2 && soon.every(n => n.tagName === "DIV" && /Coming soon/.test(n.textContent) && !n.querySelector("a,button")));
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
  check("W1. SHELL_REV \"p22\" in the cache's name", has(sw, "var SHELL_REV = \"p22\";\nvar CACHE = \"bf-shell-\" + BUILD + \"-\" + SHELL_REV;"));
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
    return old !== now;
  });
  check("U1. the Oracle pages, the music player (its button icon), the Layered Stack logo (bf-marks.js), HQ1's dashboard views, the phone and UI stylesheets and the Guide are byte for byte as at " + P20_COMMIT,
    changed.length === 0, changed.join(","));
  let diffNames = [];
  try { diffNames = execFileSync("git", ["-C", FE, "diff", "--name-only", P20_COMMIT, "--"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(Boolean); } catch (e) { diffNames = ["git failed"]; }
  let addedFonts = "";
  try { addedFonts = execFileSync("git", ["-C", FE, "diff", P20_COMMIT, "--", "*.html", "*.css", "*.js"], { encoding: "utf8", maxBuffer: 64 << 20, stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(l => /^\+/.test(l) && /@font-face|fonts\.googleapis|fonts\.gstatic|font-family:\s*["']?(?!system-ui|inherit|var\()/i.test(l)).join("\n"); } catch (e) { addedFonts = "git failed"; }
  check("U2. no font is added or changed by any edited page (new rules use the system stack or inherit)", addedFonts === "", addedFonts.slice(0, 300));
  check("U3. no Oracle page is among the edited files", !diffNames.some(f => /^(oracle|mychart|calendar|synastry|the-third)\.html$/.test(f)), diffNames.join(","));

  T.finish();
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
