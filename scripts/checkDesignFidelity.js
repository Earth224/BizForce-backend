"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkDesignFidelity.js — Home's feed and the Profile hold the approved design
   (FX1, Nov 20 2026; the owner's pictures Downloads\design\feed.png and
   profile.png, measured into scripts/designSpec.js).

   WHAT THIS PROVES (the frontend's text; every expected value is built from
   scripts/designSpec.js, so a figure changed there and not in the CSS fails)
     A. THE FEED'S TOP ROW (home.html): Live, Local, Following, Market (its
        dot), For You, Search in that order; the tabs' font, height, padding and
        colours; the active underline; the dot; the row's place; the tabs not
        yet built open the Coming soon sheet; a desktop shows only Following
        and Search, as before.
     B. THE RAIL AND THE BOTTOM-LEFT BLOCK (scripts/bf-feed.js): the rail's
        place, width and gaps; the avatar, its follow badge; each action's icon,
        label and height; Tip BFC's slot kept unseen; the name and the caption;
        the product strip; photos fill the screen; a desktop card shows none of
        the rail's own parts.
     C. THE BAR (scripts/bf-tabbar.js, home.html): its height, the + button,
        the border colour; on the feed the darker bar with Home white.
     D. THE PROFILE (scripts/bf-profile-shell.js): the top row, the picture and
        its ring, the handle, the counts in the design's order, the buttons and
        the wallet, the bio, the four tabs, the grid; BizCash, the wallet and
        "BizForce member" only for a paid member; Reviews opens Coming soon;
        the page's old header hidden on a phone; desktop parts hidden.
     // NAMED (Nov 21 2026, P3-1C): BEFORE SHELL_REV "p31b". AFTER "p31c" (the wallet's member-welcome sentence and ledger labels).
     E. THE SHELL'S VERSION (sw.js): SHELL_REV is "p31c" (NAMED, P3-1B: BEFORE "fx2"; NAMED, P3-1: BEFORE "fx1"; NAMED, P3-2: BEFORE "p31"; NAMED, FX2: BEFORE "p32").
     F. FX2 (Nov 21 2026): Tip BFC for a paid member; the product strip, built and linked (lib/posts.js
        sends a post's active listing, run here over the P2-3 test database); the tabs on one line; the
        Profile's banner (added, changed, removed in Edit profile) and its ring; the Agent Directory's
        look (its behaviour is checkAgentViews'); the orbit's first settle (no jump, no jerk, at rest
        in SETTLE_MS, nothing under reduced motion).
   Every phone rule is checked to be inside its file's @media (max-width:
   760px) block, so the desktop is unchanged.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const DS = require("./designSpec");

const HOME = "home.html", FEED = "scripts/bf-feed.js", SHELL = "scripts/bf-profile-shell.js", BAR = "scripts/bf-tabbar.js", SW = "sw.js", PROFILE = "profile.html";
// NAMED (Nov 21 2026, FX2): the server's posts library, the Agent Directory's views and the orbit
const POSTS = "@lib/posts.js", AGV = "scripts/bf-agents-views.js", AGP = "ai-agents.html", ORB = "scripts/bf-orbit.js";
const MUTATIONS = {
  "tab-font": [[HOME, "color:#c9d1e6;font:600 16px/1 system-ui", "color:#c9d1e6;font:600 15px/1 system-ui"]],
  "underline-thin": [[HOME, "bottom:1px;height:3px;border-radius:2px;background:var(--bf-accent-a, #22d3ee)}", "bottom:1px;height:2px;border-radius:2px;background:var(--bf-accent-a, #22d3ee)}"]],
  "no-dot": [[HOME, 'class="feed-tab is-soon has-dot"', 'class="feed-tab is-soon"']],
  "tabs-reordered": [[HOME, 'id="tabMarket"', 'id="tabMarketX"']],
  "row-top": [[HOME, "padding:calc(12px + env(safe-area-inset-top, 0px)) 2px 0 9px;background:none}", "padding:calc(8px + env(safe-area-inset-top, 0px)) 12px 8px;background:none}"]],
  "soon-unwired": [[HOME, 'window.BFFeed.soon(t.getAttribute("data-soon"), t);', "say(\"Soon.\");"]],
  "desktop-shows-soon": [[HOME, "    .feed-live,.feed-tab.is-soon{display:none}\n", ""]],
  // NAMED (Nov 21 2026, FX2): BEFORE the rail sat at bottom:126px (the mutant moved it to 100). AFTER 16px; the mutant puts it back at 126.
  "rail-low": [[FEED, ".bfp-feed.is-full .bfp-actions{position:absolute;right:10px;bottom:16px;", ".bfp-feed.is-full .bfp-actions{position:absolute;right:10px;bottom:126px;"]],
  "rail-gap": [[FEED, "align-items:center;gap:18px}", "align-items:center;gap:6px}"]],
  "icon-small": [[FEED, ".bfp-feed.is-full .bfp-act svg{flex:none;width:30px;height:30px;", ".bfp-feed.is-full .bfp-act svg{flex:none;width:24px;height:24px;"]],
  "tip-shown": [[FEED, ".bfp-feed.is-full .bfp-tip{display:flex;visibility:hidden;", ".bfp-feed.is-full .bfp-tip{display:none;visibility:hidden;"]],
  "tip-missing": [[FEED, "'<button type=\"button\" class=\"bfp-act bfp-tip\"", "'<button type=\"button\" class=\"bfp-act bfp-tipx\""]],
  "meta-wide": [[FEED, ".bfp-feed.is-full .bfp-meta{position:absolute;left:14px;right:80px;bottom:16px;", ".bfp-feed.is-full .bfp-meta{position:absolute;left:14px;right:84px;bottom:16px;"]],
  "caption-font": [[FEED, ".bfp-feed.is-full .bfp-info .bfp-text{font-size:15px;line-height:1.4;", ".bfp-feed.is-full .bfp-info .bfp-text{font-size:14px;line-height:1.4;"]],
  "photo-contain": [[FEED, ".bfp-feed.is-full .bfp-photo img{height:100%;aspect-ratio:auto;object-fit:cover}", ".bfp-feed.is-full .bfp-photo img{height:100%;aspect-ratio:auto;object-fit:contain}"]],
  "badge-size": [[FEED, ".bfp-feed.is-full .bfp-badge-dot{position:absolute;left:11px;top:19px;width:22px;height:22px;", ".bfp-feed.is-full .bfp-badge-dot{position:absolute;left:11px;top:19px;width:18px;height:18px;"]],
  "desktop-rail": [[FEED, '    ".bfp-rail-av,.bfp-tip,.bfp-word,.bfp-act .ic-phone{display:none}",\n', ""]],
  "buy-pill": [[FEED, "height:34px;min-height:34px;padding:0 14px;border:0;border-radius:17px;background:var(--bf-accent-a, #22d3ee);", "height:34px;min-height:34px;padding:0 14px;border:0;border-radius:8px;background:var(--bf-accent-a, #22d3ee);"]],
  "bar-border": [[BAR, "border-top:1px solid #1e2848;", "border-top:1px solid rgba(var(--bf-accent-a-rgb, 34,211,238),.16);"]],
  "feed-bar": [[HOME, "html.bf-tabbar-on body.feed-full #bf-tabbar{background:#05070f;border-top-color:#141b33}", "html.bf-tabbar-on body.feed-full #bf-tabbar{background:#070b18;border-top-color:#141b33}"]],
  "avatar-size": [[SHELL, ".pfs-av{display:block;width:92px;height:92px;box-sizing:border-box;padding:3px;", ".pfs-av{display:block;width:80px;height:80px;box-sizing:border-box;padding:3px;"]],
  "stats-order": [[SHELL, ".pfs-k-following{order:1}.pfs-k-followers{order:2}", ".pfs-k-following{order:2}.pfs-k-followers{order:1}"]],
  "buttons-radius": [[SHELL, ".pfs-actions .pfs-btn{flex:1 1 0;height:44px;padding:0 8px;border-radius:12px;background:#1a2244;", ".pfs-actions .pfs-btn{flex:1 1 0;height:44px;padding:0 8px;border-radius:999px;background:#1a2244;"]],
  "bizcash-free": [[SHELL, "if (owner && state.member === true && typeof s.bizcash === \"number\")", "if (owner && typeof s.bizcash === \"number\")"]],
  "wallet-free": [[SHELL, "(owner && paid ? '<a class=\"pfs-btn is-wallet\"", "(owner ? '<a class=\"pfs-btn is-wallet\""]],
  "member-free": [[SHELL, "(handle ? \"@\" + esc(handle) + (paid ? \" &middot; BizForce member\" : \"\")", "(handle ? \"@\" + esc(handle) + \" &middot; BizForce member\""]],
  "no-reviews": [[SHELL, "    tabs.push([\"reviews\", \"Reviews\"]);", "    void 0;"]],
  "reviews-unwired": [[SHELL, "window.BFFeed.soon(\"reviews\", t); return; }", "void 0; }"]],
  "grid-gap": [[SHELL, "\".pfs-grid{gap:2px}\",", "\".pfs-grid{gap:8px}\","]],
  "old-header": [[SHELL, "\"body:not(.edit-mode) .pf-nav,body:not(.edit-mode) .pf-banner,body:not(.edit-mode) .pf-header-wrap{display:none}\",\n", ""]],
  "no-soon-script": [[PROFILE, "<script src=\"/scripts/bf-feed.js\"></script>", ""]],
  "shell-rev": [[SW, "var SHELL_REV = \"p31b\";", "var SHELL_REV = \"fx2\";"]],   // NAMED (Nov 21 2026, P3-1B): the mutant is now "fx2", was "p32"; NAMED (Nov 21 2026, FX2): BEFORE "p32" (mutant "p23")
  // NAMED (Nov 21 2026, FX2)
  "tip-never-shown": [[FEED, "    \".bfp-feed.is-full .bfp-tip.is-member{visibility:visible}\",\n", ""]],
  "tip-for-free": [[FEED, "setMember(!!a && a.tier === \"member\");", "setMember(!!a);"]],
  "tip-not-watched": [[FEED, "    watchAccess(40);   // NAMED (Nov 21 2026, FX2)", "   // NAMED (Nov 21 2026, FX2)"]],
  "strip-unlinked": [[FEED, "    return '<a class=\"bfp-buy\" href=\"' + esc(href) + '\"", "    return '<a class=\"bfp-buy\" data-href=\"' + esc(href) + '\""]],
  "strip-not-drawn": [[FEED, "status + stripHtml(p) + '</div></div>'", "status + '</div></div>'"]],
  "listing-any-status": [[POSTS, ".in(\"id\", ids).eq(\"status\", \"active\");", ".in(\"id\", ids);"]],
  "listing-not-sent": [[POSTS, "      listing: (p.listing_id && got[4][p.listing_id]) || null", "      listing: null"]],
  "tab-wraps": [[HOME, "font:600 16px/1 system-ui,-apple-system,\"Segoe UI\",Arial,sans-serif;white-space:nowrap;cursor:pointer;", "font:600 16px/1 system-ui,-apple-system,\"Segoe UI\",Arial,sans-serif;cursor:pointer;"]],
  "safe-area-twice": [[SHELL, "\".pfs-bar{display:flex;align-items:center;height:44px;margin-top:12px;padding:0 12px}\"", "\".pfs-bar{display:flex;align-items:center;height:44px;margin-top:calc(12px + env(safe-area-inset-top, 0px));padding:0 12px}\""]],
  "ring-vertical": [[SHELL, "background:linear-gradient(135deg,var(--bf-accent-a, #22d3ee),var(--bf-accent-b, #8b5cf6))}\",\n", "background:linear-gradient(180deg,var(--bf-accent-a, #22d3ee),var(--bf-accent-b, #8b5cf6))}\",\n"]],
  "banner-short": [[SHELL, "height:calc(158px + env(safe-area-inset-top, 0px));", "height:calc(140px + env(safe-area-inset-top, 0px));"]],
  "banner-no-fade": [[SHELL, "mask-image:linear-gradient(#000 0,#000 50%,rgba(0,0,0,.55) 75%,transparent 100%)}\",", "mask-image:none}\","]],
  "banner-on-desktop": [[SHELL, "    \".pfs-banner,.pfs-banner-edit{display:none}\",\n", ""]],
  "banner-no-remove": [[SHELL, "body: JSON.stringify({ banner_url: null }) })", "body: JSON.stringify({}) })"]],
  "banner-upload-not-shown": [[PROFILE, "    if (window.BFProfileShell && window.BFProfileShell.setBanner) window.BFProfileShell.setBanner(url);", "    void 0;"]],
  "agents-row-tall": [[AGV, "gap:12px;min-height:58px;padding:0 12px;", "gap:12px;min-height:72px;padding:0 12px;"]],
  "agents-grid-three": [[AGV, ".ag-list{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:10px}", ".ag-list{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}"]],
  "agents-on-desktop": [[AGV, "    \".ag-view-row,.ag-list{display:none}\",\n    \"@media (max-width: 760px){\",\n", "    \"@media (max-width: 760px){\",\n"]],
  "settle-jumps": [[ORB, "openPortal(firstPortal(state.top), \"settle\"); }", "openPortal(firstPortal(state.top), false); }"]],
  "settle-jerks": [[ORB, "return D * (1 - Math.pow(1 - t, 3)) + (V - 3 * D) * t * (1 - t) * (1 - t);", "return D * (1 - Math.pow(1 - t, 3));"]],
  "settle-slow": [[ORB, "  var SETTLE_MS = 1300;", "  var SETTLE_MS = 2400;"]],
  "settle-when-reduced": [[ORB, "    if (reduced()) { state.turn = null; state.base += delta; place(); flushSparks(); return; }\n", ""]]
};
const T = H.setup(__filename, MUTATIONS, [HOME, FEED, SHELL, BAR, SW, PROFILE, POSTS, AGV, AGP, ORB, "css/bf-phone.css"]);
const { FILES, check, J } = T;

/* The text of the block that opens at `marker` (its "{"), to the matching "}". The CSS in a .js file is an array of
   strings; its braces balance as in a stylesheet, and the code between the strings has none. */
function block(text, marker) {
  const at = text.indexOf(marker);
  if (at < 0) return "";
  let i = text.indexOf("{", at), depth = 0;
  for (let j = i; j < text.length; j++) {
    if (text[j] === "{") depth++;
    else if (text[j] === "}" && --depth === 0) return text.slice(i + 1, j);
  }
  return "";
}
/* A rule's declarations, { property: value }, from the first `selector{` in `text` (the exact selector text). */
function rule(text, selector) {
  const at = text.indexOf(selector + "{");
  if (at < 0) return null;
  const body = text.slice(at + selector.length + 1, text.indexOf("}", at));
  const out = {};
  body.split(";").forEach(d => { const k = d.indexOf(":"); if (k > 0) out[d.slice(0, k).trim()] = d.slice(k + 1).trim().replace(/\\"/g, '"'); });
  return out;
}
const px = n => n + "px";
/* every expected declaration is present with that value */
function holds(decls, want) { return !!decls && Object.keys(want).every(k => decls[k] === want[k]); }
function ruleCheck(name, text, selector, want) {
  const d = rule(text, selector);
  check(name, holds(d, want), J({ selector, want, got: d }));
}

const home = FILES[HOME] || "", feed = FILES[FEED] || "", shell = FILES[SHELL] || "", bar = FILES[BAR] || "";
const homePhone = block(home, "@media (max-width: 760px){");
const feedPhone = block(feed, '"@media " + BREAKPOINT + "{"');
const shellPhone = block(shell, '"@media (max-width: 760px){"');
const F = DS.FEED, P = DS.PROFILE, C = DS.COLOR;
// the accent and violet are the theme's tokens with the design's colours as their defaults (checkThemeSpectrums N1): a member's theme recolours them
const ACC = "var(--bf-accent-a, " + C.ACCENT + ")", VIO = "var(--bf-accent-b, " + C.VIOLET + ")";

/* ── A ── */
console.log("\n══ A. the feed's top row (home.html) ══");
const ids = [...home.matchAll(/<button type="button" class="feed-(?:live|tab[^"]*|search)" [^>]*id="([A-Za-z]+)"/g)].map(m => m[1]);
check("A1. Live, then the tabs Local, Following, Market, For You, then Search, in that order", J(ids) === J(["feedLive", "tabLocal", "tabFollowing", "tabMarket", "tabForYou", "feedSearch"]), J(ids));
const tabText = [...home.matchAll(/class="feed-tab[^"]*"[^>]*>([^<]+)<\/button>/g)].map(m => m[1]);
check("A2. the tabs read " + F.TOP.TABS.join(", ") + "; Following is the selected one; Market carries the dot",
  J(tabText) === J(F.TOP.TABS) && /id="tabFollowing" aria-selected="true"/.test(home) && /class="feed-tab is-soon has-dot" role="tab" id="tabMarket"/.test(home), J(tabText));
ruleCheck("A3. a tab (phone): " + F.TOP.TAB_FONT + " px " + F.TOP.TAB_WEIGHT + ", " + F.TOP.TAB_HEIGHT + " px tall, " + F.TOP.TAB_PAD_X + " px each side, " + C.TAB_INACTIVE, homePhone, ".feed-tab",
  { height: px(F.TOP.TAB_HEIGHT), "min-height": px(F.TOP.TAB_HEIGHT), padding: "0 " + px(F.TOP.TAB_PAD_X), color: C.TAB_INACTIVE, font: F.TOP.TAB_WEIGHT + " " + px(F.TOP.TAB_FONT) + '/1 system-ui,-apple-system,"Segoe UI",Arial,sans-serif' });
ruleCheck("A4. the active tab white", homePhone, ".feed-tab[aria-selected=true]", { color: "#fff" });
ruleCheck("A5. its underline " + F.TOP.UNDERLINE + " px " + C.ACCENT + ", " + F.TOP.UNDERLINE_INSET + " px in from its sides", homePhone, ".feed-tab[aria-selected=true]::after",
  { height: px(F.TOP.UNDERLINE), background: ACC, left: px(F.TOP.UNDERLINE_INSET), right: px(F.TOP.UNDERLINE_INSET) });
ruleCheck("A6. Market's dot " + F.TOP.DOT + " px " + C.ACCENT + ", " + F.TOP.DOT_TOP + " px from the top", homePhone, ".feed-tab.has-dot::before",
  { width: px(F.TOP.DOT), height: px(F.TOP.DOT), top: px(F.TOP.DOT_TOP), background: ACC, "border-radius": "50%" });
ruleCheck("A7. Live and Search " + F.TOP.BUTTON + " px, round, no frame", homePhone, ".feed-live,.feed-search",
  { width: px(F.TOP.BUTTON), height: px(F.TOP.BUTTON), border: "0", "border-radius": px(F.TOP.BUTTON / 2), background: "transparent" });
ruleCheck("A8. the row " + F.TOP.ROW_TOP + " px below the safe area, Live " + F.TOP.LIVE_LEFT + " px in, Search " + F.TOP.SEARCH_RIGHT + " px in", homePhone, "body.feed-full .feed-top",
  { padding: "calc(" + px(F.TOP.ROW_TOP) + " + env(safe-area-inset-top, 0px)) " + px(F.TOP.SEARCH_RIGHT) + " 0 " + px(F.TOP.LIVE_LEFT) });
check("A9. Live, Search on a phone, and Local, Market and For You open the Coming soon sheet",
  home.indexOf('window.BFFeed.soon(t.getAttribute("data-soon"), t);') !== -1 && home.indexOf('window.BFFeed.soon("live", this);') !== -1 && home.indexOf('if (phoneNow()) window.BFFeed.soon("search", this);') !== -1 &&
  ["local", "market", "foryou", "live", "search", "reviews"].every(k => new RegExp("\\n    " + k + ": \\[").test(feed)));
check("A10. a desktop shows only Following and Search, as before (Live and the later tabs hidden outside the phone block)",
  home.indexOf("    .feed-live,.feed-tab.is-soon{display:none}\n    @media (max-width: 760px){") !== -1 && homePhone.indexOf(".feed-live,.feed-tab.is-soon{display:inline-flex}") !== -1);

/* ── B ── */
console.log("\n══ B. the rail and the bottom-left block (scripts/bf-feed.js) ══");
const R = F.RAIL, M = F.META, S = F.STRIP;
ruleCheck("B1. the rail " + R.RIGHT + " px from the right, " + R.WIDTH + " px wide, its bottom " + R.BOTTOM_ABOVE_BAR + " px above the bar, items " + R.GAP + " px apart", feedPhone, ".bfp-feed.is-full .bfp-actions",
  { right: px(R.RIGHT), width: px(R.WIDTH), bottom: px(R.BOTTOM_ABOVE_BAR), gap: px(R.GAP), "flex-direction": "column" });
ruleCheck("B2. each action " + R.ITEM + " px tall, an icon over a " + R.LABEL_FONT + " px label, " + R.ICON_LABEL_GAP + " px between", feedPhone, ".bfp-feed.is-full .bfp-act",
  { height: px(R.ITEM), "min-height": px(R.ITEM), width: px(R.WIDTH), gap: px(R.ICON_LABEL_GAP), color: "#fff", font: "600 " + px(R.LABEL_FONT) + "/" + px(R.LABEL_LINE) + ' system-ui,-apple-system,"Segoe UI",Arial,sans-serif' });
check("B3. the item is the icon, the gap and the label's line", R.ITEM === R.ICON + R.ICON_LABEL_GAP + R.LABEL_LINE, J(R));
ruleCheck("B4. the icons " + R.ICON + " px", feedPhone, ".bfp-feed.is-full .bfp-act svg", { width: px(R.ICON), height: px(R.ICON) });
ruleCheck("B5. the icons filled white (Tip aside)", feedPhone, ".bfp-feed.is-full .bfp-act:not(.bfp-tip) svg", { fill: "currentColor", stroke: "none" });
ruleCheck("B6. the avatar " + R.AVATAR + " px, a cyan-to-violet circle", feedPhone, ".bfp-feed.is-full .bfp-rail-pic",
  { width: px(R.AVATAR), height: px(R.AVATAR), "border-radius": "50%", background: "linear-gradient(135deg," + ACC + "," + VIO + ")" });
const badge = rule(feedPhone, ".bfp-feed.is-full .bfp-badge"), dot = rule(feedPhone, ".bfp-feed.is-full .bfp-badge-dot");
const dotCentreY = badge && dot ? parseFloat(badge.top) + parseFloat(dot.top) + R.BADGE / 2 : NaN, dotCentreX = badge && dot ? parseFloat(badge.left) + parseFloat(dot.left) + R.BADGE / 2 : NaN;
check("B7. the follow badge " + R.BADGE + " px " + C.ACCENT + ", centred on the avatar's bottom edge, a 44 px tap area",
  holds(dot, { width: px(R.BADGE), height: px(R.BADGE), background: ACC, "border-radius": "50%" }) && holds(badge, { width: "44px", height: "44px" }) && dotCentreY === R.AVATAR && dotCentreX === R.AVATAR / 2, J([badge, dot]));
const order = (() => {
  const fn = feed.slice(feed.indexOf("function actionsHtml(p) {"), feed.indexOf("function actionsHtml(p) {") + 1400);
  return [["avatar", fn.indexOf("railAvatar(p)")], ["like", fn.indexOf('act("like"')], ["talk", fn.indexOf('act("talk"')], ["tip", fn.indexOf("tipHtml()")] /* NAMED (Nov 21 2026, FX2): BEFORE the markup was inline ("bfp-act bfp-tip"); AFTER tipHtml() */,
    ["save", fn.indexOf('data-act="save"')], ["share", fn.indexOf('act("share"')]].filter(x => x[1] >= 0).sort((a, b) => a[1] - b[1]).map(x => x[0]);
})();
check("B8. the rail's order: " + R.ORDER.join(", "), J(order) === J(R.ORDER), J(order));
// NAMED (Nov 21 2026, FX2): BEFORE "B9. Tip BFC's slot kept, unseen" and "B10. Tip BFC cannot be reached" for everyone. AFTER that is a free
// viewer's (and anyone's until their tier is known); a paid member's Tip is shown (F1 to F3).
ruleCheck("B9. Tip BFC's slot kept, unseen, gold, for a viewer who is not a paid member", feedPhone, ".bfp-feed.is-full .bfp-tip", { display: "flex", visibility: "hidden", color: C.GOLD });
check("B10. and for them Tip BFC cannot be reached (disabled, out of the tab order, hidden from readers)", feed.indexOf(": '<button type=\"button\" class=\"bfp-act bfp-tip\" data-act=\"tip\" disabled tabindex=\"-1\" aria-hidden=\"true\">'") !== -1);
ruleCheck("B11. the bottom-left block " + M.LEFT + " px from the left, its right edge " + M.RIGHT + " px in, its bottom " + M.BOTTOM_ABOVE_BAR + " px above the bar, " + M.GAP + " px gaps", feedPhone, ".bfp-feed.is-full .bfp-meta",
  { left: px(M.LEFT), right: px(M.RIGHT), bottom: px(M.BOTTOM_ABOVE_BAR), gap: px(M.GAP) });
ruleCheck("B12. the name " + M.NAME_FONT + " px, weight " + M.NAME_WEIGHT, feedPhone, ".bfp-feed.is-full .bfp-name", { font: M.NAME_WEIGHT + " " + px(M.NAME_FONT) + '/1.2 system-ui,-apple-system,"Segoe UI",Arial,sans-serif', color: C.TEXT });
ruleCheck("B13. the caption " + M.CAPTION_FONT + " px, line height " + M.CAPTION_LINE, feedPhone, ".bfp-feed.is-full .bfp-info .bfp-text", { "font-size": px(M.CAPTION_FONT), "line-height": String(M.CAPTION_LINE), color: C.TEXT });
ruleCheck("B14. the strip: radius " + S.RADIUS + ", a " + S.BORDER + " line, " + S.PAD + " px in", feedPhone, ".bfp-feed.is-full .bfp-buy", { "border-radius": px(S.RADIUS), border: "1px solid " + S.BORDER, padding: px(S.PAD) });
ruleCheck("B15. its tile " + S.TILE + " px", feedPhone, ".bfp-feed.is-full .bfp-buy-tile", { width: px(S.TILE), height: px(S.TILE) });
ruleCheck("B16. its title " + S.TITLE_FONT + " px semibold", feedPhone, ".bfp-feed.is-full .bfp-buy-title", { font: "600 " + px(S.TITLE_FONT) + '/1.3 system-ui,-apple-system,"Segoe UI",Arial,sans-serif' });
ruleCheck("B17. its price " + S.PRICE_FONT + " px, muted", feedPhone, ".bfp-feed.is-full .bfp-buy-price", { font: "400 " + px(S.PRICE_FONT) + '/1.3 system-ui,-apple-system,"Segoe UI",Arial,sans-serif', color: C.MUTED });
ruleCheck("B18. Buy: a cyan pill " + S.BUY_HEIGHT + " px tall, radius " + S.BUY_RADIUS + ", " + S.BUY_WIDTH + " px or wider", feedPhone, ".bfp-feed.is-full .bfp-buy-go",
  { height: px(S.BUY_HEIGHT), "border-radius": px(S.BUY_RADIUS), "min-width": px(S.BUY_WIDTH), background: ACC });
ruleCheck("B19. a photo fills the screen", feedPhone, ".bfp-feed.is-full .bfp-photo img", { "object-fit": "cover" });
ruleCheck("B20. no handle, three dots, Follow button or time on the screen (Share opens the options)", feedPhone,
  ".bfp-feed.is-full .bfp-head .bfp-av-link,.bfp-feed.is-full .bfp-handle,.bfp-feed.is-full .bfp-head .bfp-follow,.bfp-feed.is-full .bfp-menu,.bfp-feed.is-full .bfp-time", { display: "none" });
check("B21. on a phone's full-screen feed Share opens the options, Share link first", feed.indexOf('else if (kind === "share") { if (phone() && post.closest(".bfp-feed.is-full")) options(post, act); else share(post); }') !== -1 &&
  feed.indexOf('var extra = [{ label: "Share link", run: function () { share(el); } }];') !== -1);
const outside = feed.slice(0, feed.indexOf('"@media " + BREAKPOINT + "{"'));
check("B22. a desktop card shows none of the rail's own parts (outside the phone block), and every full-screen rule is inside it",
  outside.indexOf('".bfp-rail-av,.bfp-tip,.bfp-word,.bfp-act .ic-phone{display:none}",') !== -1 && outside.indexOf(".bfp-feed.is-full") === -1);

/* ── C ── */
console.log("\n══ C. the bar ══");
ruleCheck("C1. the + " + DS.BAR.PLUS_W + " x " + DS.BAR.PLUS_H + ", radius " + DS.BAR.PLUS_RADIUS, bar, "#bf-tabbar .bf-tab-plus",
  { width: px(DS.BAR.PLUS_W), height: px(DS.BAR.PLUS_H), "border-radius": px(DS.BAR.PLUS_RADIUS) });
check("C2. the bar " + DS.BAR.HEIGHT + " px plus the safe area, with a 1 px " + DS.BAR.BORDER + " line", bar.indexOf("border-top:1px solid " + DS.BAR.BORDER + ";") !== -1 &&
  bar.indexOf("height:calc(" + px(DS.BAR.HEIGHT) + " + env(safe-area-inset-bottom, 0px))") !== -1);
ruleCheck("C3. on the feed the bar is " + DS.BAR.FEED_BG + " with a " + DS.BAR.FEED_BORDER + " line", homePhone, "html.bf-tabbar-on body.feed-full #bf-tabbar", { background: DS.BAR.FEED_BG, "border-top-color": DS.BAR.FEED_BORDER });
ruleCheck("C4. and Home white", homePhone, "body.feed-full #bf-tabbar .bf-tab[aria-current=page]", { color: "#fff" });
check("C5. the active item's icon filled", bar.indexOf('"#bf-tabbar .bf-tab[aria-current=page]:is([data-tab=home],[data-tab=inbox],[data-tab=profile]) svg{fill:currentColor}",') !== -1);

/* ── D ── */
console.log("\n══ D. the profile (scripts/bf-profile-shell.js) ══");
const PT = P.TOP, PA = P.AVATAR, PS = P.STATS, PB = P.BUTTONS, PTB = P.TABS, PG = P.GRID;
// NAMED (Nov 21 2026, FX2): BEFORE margin-top calc(12px + env(safe-area-inset-top)): with css/bf-phone.css's own padding of the page by the
// safe area (a page with no top bar), the row sat a second safe area low. AFTER the row's own 12 px, the page's padding the safe area once.
ruleCheck("D1. the top row " + PT.ROW_TOP + " px below the safe area (counted once), " + PT.BUTTON + " px tall, " + PT.PAD_X + " px in", shellPhone, ".pfs-bar",
  { height: px(PT.BUTTON), "margin-top": px(PT.ROW_TOP), padding: "0 " + px(PT.PAD_X) });
check("D1b. the page itself is padded by the safe area once (css/bf-phone.css, a page with no top bar), and profile.html has no top bar",
  (FILES["css/bf-phone.css"] || "").indexOf("html:not(:has(header.topbar)) { padding-top: env(safe-area-inset-top, 0px);") !== -1 && !/<header class="topbar/.test(FILES[PROFILE] || ""));
ruleCheck("D2. its icons " + PT.BUTTON + " px", shellPhone, ".pfs-icon", { width: px(PT.BUTTON), height: px(PT.BUTTON) });
ruleCheck("D3. the name centred, " + PT.NAME_FONT + " px, weight " + PT.NAME_WEIGHT, shellPhone, ".pfs-title", { "text-align": "center", font: PT.NAME_WEIGHT + " " + px(PT.NAME_FONT) + '/1.25 system-ui,-apple-system,"Segoe UI",Arial,sans-serif' });
ruleCheck("D4. the picture " + PA.SIZE + " px with a " + PA.RING + " px cyan-to-violet ring", shellPhone, ".pfs-av",
  { width: px(PA.SIZE), height: px(PA.SIZE), padding: px(PA.RING), background: "linear-gradient(" + PA.RING_ANGLE + "deg," + ACC + "," + VIO + ")" });   // NAMED (Nov 21 2026, FX2): BEFORE 180deg
ruleCheck("D5. inside it " + PA.INNER + " with " + PA.INITIALS_FONT + " px initials", shellPhone, ".pfs-av-in", { background: PA.INNER, font: "800 " + px(PA.INITIALS_FONT) + '/1 system-ui,-apple-system,"Segoe UI",Arial,sans-serif' });
const barR = rule(shellPhone, ".pfs-bar"), picR = rule(shellPhone, ".pfs-pic");
check("D6. the picture " + PA.TOP + " px down (the row's top, its height, the gap)", !!barR && !!picR && PT.ROW_TOP + PT.BUTTON + parseFloat(picR["margin-top"]) === PA.TOP, J(picR));
ruleCheck("D7. the handle " + P.HANDLE.FONT + " px, muted, " + P.HANDLE.GAP + " px under the picture", shellPhone, ".pfs-handle",
  { "font-size": px(P.HANDLE.FONT), "line-height": px(P.HANDLE.LINE), color: C.MUTED, margin: px(P.HANDLE.GAP) + " 0 0", "text-align": "center" });
check("D8. the counts in the design's order: " + PS.LABELS.join(", "), shellPhone.indexOf(PS.ORDER.map((k, i) => ".pfs-k-" + k + "{order:" + (i + 1) + "}").join("")) !== -1);
ruleCheck("D9. the counts' row " + PS.GAP + " px under the handle, evenly across", shellPhone, ".pfs-stats", { margin: px(PS.GAP) + " 0 0", gap: "0" });
ruleCheck("D10. a number " + PS.NUM_FONT + " px bold", shellPhone, ".pfs-num", { "font-size": px(PS.NUM_FONT), "line-height": px(PS.NUM_LINE), "font-weight": "800" });
ruleCheck("D11. BizCash gold", shellPhone, ".pfs-num.is-bfc", { color: C.GOLD });
ruleCheck("D12. a label " + PS.LABEL_FONT + " px, muted", shellPhone, ".pfs-lab", { "font-size": px(PS.LABEL_FONT), "line-height": px(PS.LABEL_LINE), color: C.MUTED });
ruleCheck("D13. the buttons " + PB.HEIGHT + " px, radius " + PB.RADIUS + ", " + PB.FILL + ", " + PB.FONT + " px semibold, equal", shellPhone, ".pfs-actions .pfs-btn",
  { height: px(PB.HEIGHT), "border-radius": px(PB.RADIUS), background: PB.FILL, flex: "1 1 0", font: PB.WEIGHT + " " + px(PB.FONT) + ' system-ui,-apple-system,"Segoe UI",Arial,sans-serif' });
ruleCheck("D14. " + PB.GAP + " px apart", shellPhone, ".pfs-actions", { gap: px(PB.GAP) });
ruleCheck("D15. the wallet " + PB.WALLET + " px, " + PB.WALLET_BG + ", its mark gold", shellPhone, ".pfs-actions .pfs-btn.is-wallet", { flex: "0 0 " + px(PB.WALLET), width: px(PB.WALLET), background: PB.WALLET_BG, color: C.GOLD });
ruleCheck("D16. the bio " + P.BIO.FONT + " px, centred (the desktop's text-align kept), " + P.BIO.GAP + " px under the buttons", shellPhone, ".pfs-bio", { "font-size": px(P.BIO.FONT), "line-height": px(P.BIO.LINE), margin: px(P.BIO.GAP) + " 0 0", color: C.BIO });
ruleCheck("D17. Visit my storefront " + P.STORE.HEIGHT + " px, " + P.STORE.FONT + " px, centred", shellPhone, ".pfs-store", { "min-height": px(P.STORE.HEIGHT), "font-size": px(P.STORE.FONT), "align-self": "center", "margin-top": px(P.STORE.GAP) });
ruleCheck("D18. the tabs' " + PTB.DIVIDER + " px " + PTB.DIVIDER_COLOR + " divider", shellPhone, ".pfs-tabs", { "border-bottom": px(PTB.DIVIDER) + " solid " + PTB.DIVIDER_COLOR });
ruleCheck("D19. a tab " + PTB.HEIGHT + " px with a " + PTB.UNDERLINE + " px underline, muted", shellPhone, ".pfs-tab", { height: px(PTB.HEIGHT), "border-bottom-width": px(PTB.UNDERLINE), color: C.MUTED });
ruleCheck("D20. the active tab white", shellPhone, ".pfs-tab[aria-selected=true]", { color: "#fff" });
check("D21. a phone's tabs: " + PTB.ORDER.join(", ") + " (Saved is in the menu); Reviews opens Coming soon",
  shell.indexOf('    tabs.push(["reviews", "Reviews"]);') !== -1 && shellPhone.indexOf(".pfs-tab.is-saved{display:none}") !== -1 && shellPhone.indexOf(".pfs-tab.is-reviews{display:block}") !== -1 &&
  shell.indexOf('if (t.getAttribute("data-pfs-tab") === "reviews") { if (window.BFFeed && window.BFFeed.soon) window.BFFeed.soon("reviews", t); return; }') !== -1 &&
  /<script src="\/scripts\/bf-feed\.js"><\/script>[^\n]*\n<script src="\/scripts\/bf-profile-shell\.js"><\/script>/.test(FILES[PROFILE] || ""));
ruleCheck("D22. the grid " + PG.GAP + " px apart", shellPhone, ".pfs-grid", { gap: px(PG.GAP) });
ruleCheck("D23. " + PG.INSET + " px in from the screen's sides", shellPhone, "#pfsPanel", { padding: px(PG.INSET) + " " + px(PG.INSET) + " 0" });
check("D24. " + PG.COLUMNS + " across, tiles 3:4 (the grid's own rule)", shell.indexOf("grid-template-columns:repeat(" + PG.COLUMNS + ",minmax(0,1fr))") !== -1 && shell.indexOf("aspect-ratio:3/4") !== -1 && PG.ASPECT === 4 / 3);
check("D25. each tile's " + PG.LABEL_FONT + " px label at its bottom left", shellPhone.indexOf("position:absolute;left:6px;bottom:6px;") !== -1 && shellPhone.indexOf("font:600 " + px(PG.LABEL_FONT) + "/1.3") !== -1);
check("D26. BizCash only for the owner and a paid member", shell.indexOf('if (owner && state.member === true && typeof s.bizcash === "number")') !== -1);
check("D27. the gold wallet only for a paid member", shell.indexOf("(owner && paid ? '<a class=\"pfs-btn is-wallet\"") !== -1);
// NAMED (Nov 20 2026, P3-1): BEFORE a visitor read p.member !== false and the owner access.active === true. AFTER free accounts have
// public pages: a visitor reads the profile answer's member flag (ownerIsMember), the owner access.tier === "member".
check("D28. \"BizForce member\" only for a paid member", shell.indexOf('(handle ? "@" + esc(handle) + (paid ? " &middot; BizForce member" : "")') !== -1 &&
  shell.indexOf("var paid = owner ? state.member === true : state.visitorMember === true;") !== -1 &&
  shell.indexOf("state.visitorMember = d.member === true;") !== -1 &&
  shell.indexOf('get("/api/auth/me", true).then(function (d) { state.member = !!(d && d.access && d.access.tier === "member"); render(); })') !== -1);
check("D29. a visitor sees Follow and Message (Share profile is the owner's on a phone)", shell.indexOf("'<a class=\"pfs-btn pfs-msg\" id=\"pfsMessage\" href=\"/inbox.html?with=' + encodeURIComponent(viewId) + '\">Message</a>'") !== -1 &&
  shellPhone.indexOf(".pfs-share-v{display:none}") !== -1);
check("D30. on a phone the page's old header is hidden while not editing, and the Guide's button is not on this screen",
  shellPhone.indexOf("body:not(.edit-mode) .pf-nav,body:not(.edit-mode) .pf-banner,body:not(.edit-mode) .pf-header-wrap{display:none}") !== -1 && shellPhone.indexOf("#tmx-guide-fab{display:none}") !== -1);
const shellOutside = shell.slice(0, shell.indexOf('"@media (max-width: 760px){"'));
check("D31. a desktop shows none of the phone header's parts (hidden outside the phone block)",
  shellOutside.indexOf('".pfs-bar,.pfs-pic,.pfs-msg,.pfs-tab.is-reviews,.pfs-cell-label,.pfs-saved-head{display:none}",') !== -1);

/* ── E ── */
console.log("\n══ E. the shell's version ══");
// NAMED (Nov 21 2026, P3-2): BEFORE "p31". AFTER "p32" (the Verified badge). The only edit P3-2 made here; no design figure changed.
// NAMED (Nov 21 2026, FX2): BEFORE "p32". AFTER "fx2" (the feed's Tip and strip, the Profile's banner, the Agent Directory's views, the Sun).
// NAMED (Nov 21 2026, P3-1B): BEFORE "fx2". AFTER "p31b": the free-account rules (bf-access.js Buy sheet and members intercepts, the Create sheet's Members tags, the composer's photo rule and Show in Google, Talk's members box).
// NAMED (Nov 21 2026, P3-1C): BEFORE SHELL_REV "p31b". AFTER "p31c" (the wallet's member-welcome sentence and ledger labels).
check("E1. sw.js SHELL_REV is \"p31c\"", /\nvar SHELL_REV = "p31c";\n/.test(FILES[SW] || ""));

/* ── F (FX2) ── */
(async () => {
  console.log("\n══ F. FX2: Tip, the strip, the tabs, the banner, the Agent Directory's look, the settle ══");
  ruleCheck("F1. a paid member's Tip BFC is shown (gold, as B9)", feedPhone, ".bfp-feed.is-full .bfp-tip.is-member", { visibility: "visible" });
  check("F2. a paid member's Tip can be reached (no disabled, no aria-hidden, a label); the tier is bfAccess's, and only \"member\" shows it",
    feed.indexOf("? '<button type=\"button\" class=\"bfp-act bfp-tip is-member\" data-act=\"tip\" aria-label=\"Tip BFC\">'") !== -1 &&
    feed.indexOf("window.bfAccess.ready.then(function (a) { setMember(!!a && a.tier === \"member\"); });") !== -1 && feed.indexOf("    watchAccess(40);   // NAMED (Nov 21 2026, FX2)") !== -1 &&
    feed.indexOf("if (MEMBER) { b.removeAttribute(\"tabindex\"); b.removeAttribute(\"aria-hidden\"); b.setAttribute(\"aria-label\", \"Tip BFC\"); }") !== -1);
  check("F3. tapping it (a member) opens the Coming soon sheet: sending BizCash is not built yet", feed.indexOf("else if (kind === \"tip\") { if (MEMBER === true) soon(\"tip\", act); }") !== -1 &&
    /\n    tip: \["Tip BFC", "Send the author BizCash to say thanks\. Sending BizCash is for members\."\]/.test(feed));
  check("F4. the strip is drawn in the bottom-left block whenever a post carries a listing, as one link to the listing",
    feed.indexOf("status + stripHtml(p) + '</div></div>'") !== -1 && feed.indexOf("if (!L || typeof L.id !== \"string\" || !L.id) return \"\";") !== -1 &&
    feed.indexOf("    return '<a class=\"bfp-buy\" href=\"' + esc(href) + '\"") !== -1 && feed.indexOf("/^\\/listing\\/[^\\/?#]+$/.test(L.link) ? L.link : \"/listing/\" + encodeURIComponent(L.id);") !== -1);
  {
    // the server: lib/posts.js over the P2-3 test database (scripts/_p23Db.js)
    const P = T.libRequire("./lib/posts"), { memDb } = require("./_p23Db");
    const A = "a0000000-0000-4000-8000-000000000001", V = "a0000000-0000-4000-8000-000000000002", L1 = "b0000000-0000-4000-8000-000000000001", L2 = "b0000000-0000-4000-8000-000000000002";
    const at = "2026-11-21T10:00:00.000Z";
    const post = (id, listing) => ({ id, author_id: A, kind: "text", body: "Fresh jam", audience: "public", status: "published", place_city: null, place_region: null, place_country: null,
      like_count: 0, comment_count: 0, save_count: 0, share_count: 0, created_at: at, published_at: at, removed_at: null, listing_id: listing });
    const db = memDb({ users: [{ id: A, created_at: at, email_verified_at: at }, { id: V, created_at: at, email_verified_at: at }],
      posts: [post("c0000000-0000-4000-8000-000000000001", L1), post("c0000000-0000-4000-8000-000000000002", L2), post("c0000000-0000-4000-8000-000000000003", null)],
      marketplace_listings: [{ id: L1, slug: "strawberry-jam", seller_id: A, title: "Strawberry jam", price_bfc: 9, media: [{ url: "https://cdn.example/jam.jpg" }], status: "active" },
        { id: L2, slug: "old-jam", seller_id: A, title: "Old jam", price_bfc: 4, media: [], status: "sold_out" }],
      follows: [{ follower_id: V, following_id: A, created_at: at }], post_likes: [], post_saves: [], post_media: [], member_media: [], member_blocks: [], member_mutes: [], profiles: [],
      bf_profiles: [{ user_id: A, username: "pat", display_name: "Pat", avatar_url: null, updated_at: at }] });
    const deps = { sb: db.client, now: () => "2026-11-21T12:00:00.000Z", claims: () => null, ownerPublic: async () => true, push: async () => {}, env: {} };
    let r = null; try { r = await P.followingFeed(deps, V); } catch (e) { r = { err: e.message }; }
    const got = r && r.body && r.body.posts ? r.body.posts.map(p => [p.id.slice(-1), p.listing]) : r;
    const byId = k => (Array.isArray(got) ? got.find(x => x[0] === k) : null) || [k, undefined];
    check("F5. lib/posts.js sends a post's active listing: its id, title, price in BFC, first photo and page (/listing/<slug>)",
      J(byId("1")[1]) === J({ id: L1, title: "Strawberry jam", price_bfc: 9, photo: "https://cdn.example/jam.jpg", link: "/listing/strawberry-jam" }), J(got));
    check("F6. a listing that is no longer active (sold out) sends none, and a post with none sends null", byId("2")[1] === null && byId("3")[1] === null, J(got));
    check("F7. the listing is read once for the page, only the active ones", db.log.filter(q => q.table === "marketplace_listings").length === 1 &&
      J(db.log.filter(q => q.table === "marketplace_listings")[0].filters.map(f => f[0] + " " + f[1])) === J(["in id", "eq status"]), J(db.log.filter(q => q.table === "marketplace_listings")));
  }
  ruleCheck("F8. every feed tab stays on one line (\"For You\" never wraps)", homePhone, ".feed-tab", { "white-space": F.TOP.TAB_NOWRAP ? "nowrap" : "normal" });
  const PBN = P.BANNER;
  check("F9. the banner: from the screen's top (the safe area too) to the picture's bottom edge (" + PBN.BOTTOM + " px), cover-cropped, fading out below " + (PBN.FADE_FROM * 100) + "%, the top row shaded " + PBN.SHADE + " px",
    PBN.BOTTOM === P.AVATAR.TOP + P.AVATAR.SIZE &&
    shellPhone.indexOf(".pfs-banner{display:block;position:absolute;left:0;right:0;top:calc(-1 * env(safe-area-inset-top, 0px));height:calc(" + px(PBN.BOTTOM) + " + env(safe-area-inset-top, 0px));z-index:0;overflow:hidden;pointer-events:none;") !== -1 &&
    shellPhone.indexOf("mask-image:linear-gradient(#000 0,#000 " + (PBN.FADE_FROM * 100) + "%,rgba(0,0,0,.55) 75%,transparent 100%)}") !== -1 &&
    shellPhone.indexOf(".pfs-banner img{display:block;width:100%;height:100%;object-fit:cover}") !== -1 &&
    shellPhone.indexOf(".pfs-banner::after{content:\\\"\\\";position:absolute;left:0;right:0;top:0;height:calc(" + px(PBN.SHADE) + " + env(safe-area-inset-top, 0px));") !== -1);
  check("F10. only with a banner_url (none by default); the desktop hides it and its edit row (the page has its own banner)",
    shell.indexOf("    var banner = safeUrl(p.banner_url);\n") !== -1 && shell.indexOf("(banner ? '<div class=\"pfs-banner\" aria-hidden=\"true\"><img src=\"' + esc(banner) + '\" alt=\"\"></div>' : \"\")") !== -1 &&
    shellOutside.indexOf("    \".pfs-banner,.pfs-banner-edit{display:none}\",\n") !== -1);
  check("F11. Edit profile adds or changes it through the page's own upload (#fi-banner, storage counted per account) and removes it (banner_url null)",
    shell.indexOf("(banner ? \"Change banner\" : \"Add banner\")") !== -1 && shell.indexOf("var fi = document.getElementById(\"fi-banner\"); if (fi) fi.click();") !== -1 &&
    shell.indexOf("fetch(API + \"/api/bfp/profile/me\", { method: \"PUT\", headers: { \"Content-Type\": \"application/json\", Authorization: \"Bearer \" + token }, body: JSON.stringify({ banner_url: null }) })") !== -1 &&
    (FILES[PROFILE] || "").indexOf("window.BFProfileShell.setBanner(url);") !== -1 && (FILES[PROFILE] || "").indexOf("var url = await uploadToStorage(this.files[0], \"banners\");") !== -1);
  const AG = DS.AGENTS, agv = FILES[AGV] || "";
  check("F12. the Agent Directory (ai-agents.html) loads its views, which show only on a phone",
    (FILES[AGP] || "").indexOf("<script src=\"/scripts/bf-agents-views.js\"></script>") !== -1 && agv.indexOf("    \".ag-view-row,.ag-list{display:none}\",\n    \"@media (max-width: 760px){\",\n") !== -1);
  check("F13. its buttons " + AG.BUTTON + " px, a Compact row " + AG.ROW + " px (58 and its two border lines), the icon tile " + AG.TILE + " px, Grid " + AG.GRID_COLUMNS + " columns, Compact by default",
    agv.indexOf("width:" + px(AG.BUTTON) + ";height:" + px(AG.BUTTON) + ";min-width:" + px(AG.BUTTON) + ";min-height:" + px(AG.BUTTON)) !== -1 &&
    agv.indexOf("gap:12px;min-height:" + px(AG.ROW - 2) + ";padding:0 12px;") !== -1 && agv.indexOf(".ag-item{border-radius:16px;border:1px solid") !== -1 &&
    agv.indexOf(".ag-icon{flex:0 0 " + px(AG.TILE) + ";width:" + px(AG.TILE) + ";height:" + px(AG.TILE) + ";") !== -1 &&
    agv.indexOf(".ag-list{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:10px}") !== -1 && AG.GRID_COLUMNS === 2 &&
    agv.indexOf("DEFAULT_VIEW = \"" + AG.DEFAULT + "\"") !== -1 && agv.indexOf("var VIEW_KEY = \"" + AG.KEY + "\";") !== -1);
  // the orbit's first settle: bf-orbit.js's own settleCurve, run here
  const orb = FILES[ORB] || "", O = DS.ORBIT;
  const ms = Number((/\n  var SETTLE_MS = (\d+);/.exec(orb) || [])[1]);
  const src = (/\n  (function settleCurve\(t, D, V\) \{[^\n]*\})\n/.exec(orb) || [])[1];
  let curve = null; try { curve = src ? new Function("return (" + src + ");")() : null; } catch (e) { curve = null; }
  const dr = 360 / 120000, cases = [[-4, dr * ms], [2, dr * ms], [37, dr * ms], [-150, dr * ms], [0.5, dr * ms]];
  const bad = [];
  if (curve) cases.forEach(([D, V]) => {
    const h = 1e-6, at = t => curve(t, D, V), v0 = (at(h) - at(0)) / h, v1 = (at(1) - at(1 - h)) / h;
    let maxStep = 0; for (let i = 1; i <= 78; i++) maxStep = Math.max(maxStep, Math.abs(at(i / 78) - at((i - 1) / 78)));
    if (Math.abs(at(0)) > 1e-9 || Math.abs(at(1) - D) > 1e-9 || Math.abs(v0 - V) > 1e-3 * Math.max(1, Math.abs(D), Math.abs(V)) || Math.abs(v1) > 1e-3 * Math.max(1, Math.abs(D)) || maxStep > Math.abs(D) / 78 * 1.5 + Math.abs(V) / 78 * 1.5 + 1e-9) bad.push([D, V, at(1), v0, v1, maxStep]);
  });
  check("F14. the first settle takes " + O.SETTLE_MS + " ms (" + O.SETTLE_MIN_MS + " to " + O.SETTLE_MAX_MS + "): it starts where the drift is at the drift's own speed, ends on the rest place with its speed 0, no step bigger than its pace",
    ms === O.SETTLE_MS && ms >= O.SETTLE_MIN_MS && ms <= O.SETTLE_MAX_MS && !!curve && bad.length === 0, J([ms, !!curve, bad]));
  check("F15. it is the page's first opening (no jump to rest), the short way round; under reduced motion it is placed at once (no drift, no settle)",
    orb.indexOf("openPortal(firstPortal(state.top), \"settle\"); }") !== -1 && orb.indexOf("if (turn === \"settle\") settleTo(key, v0);") !== -1 &&
    orb.indexOf("var delta = ((target - state.base) % 360 + 540) % 360 - 180;   // the short way round") !== -1 &&
    orb.indexOf("    if (reduced()) { state.turn = null; state.base += delta; place(); flushSparks(); return; }\n") !== -1 &&
    orb.indexOf("var v0 = drifting() ? 360 / DRIFT_MS : 0;") !== -1 && /function drifting\(\) \{ return [^}]*!reduced\(\)/.test(orb));
  T.finish();
})();
