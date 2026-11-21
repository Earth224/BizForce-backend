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
     E. THE SHELL'S VERSION (sw.js): SHELL_REV is "fx1".
   Every phone rule is checked to be inside its file's @media (max-width:
   760px) block, so the desktop is unchanged.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const DS = require("./designSpec");

const HOME = "home.html", FEED = "scripts/bf-feed.js", SHELL = "scripts/bf-profile-shell.js", BAR = "scripts/bf-tabbar.js", SW = "sw.js", PROFILE = "profile.html";
const MUTATIONS = {
  "tab-font": [[HOME, "color:#c9d1e6;font:600 16px/1 system-ui", "color:#c9d1e6;font:600 15px/1 system-ui"]],
  "underline-thin": [[HOME, "bottom:1px;height:3px;border-radius:2px;background:var(--bf-accent-a, #22d3ee)}", "bottom:1px;height:2px;border-radius:2px;background:var(--bf-accent-a, #22d3ee)}"]],
  "no-dot": [[HOME, 'class="feed-tab is-soon has-dot"', 'class="feed-tab is-soon"']],
  "tabs-reordered": [[HOME, 'id="tabMarket"', 'id="tabMarketX"']],
  "row-top": [[HOME, "padding:calc(12px + env(safe-area-inset-top, 0px)) 2px 0 9px;background:none}", "padding:calc(8px + env(safe-area-inset-top, 0px)) 12px 8px;background:none}"]],
  "soon-unwired": [[HOME, 'window.BFFeed.soon(t.getAttribute("data-soon"), t);', "say(\"Soon.\");"]],
  "desktop-shows-soon": [[HOME, "    .feed-live,.feed-tab.is-soon{display:none}\n", ""]],
  "rail-low": [[FEED, ".bfp-feed.is-full .bfp-actions{position:absolute;right:10px;bottom:126px;", ".bfp-feed.is-full .bfp-actions{position:absolute;right:10px;bottom:100px;"]],
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
  "shell-rev": [[SW, "var SHELL_REV = \"fx1\";", "var SHELL_REV = \"p23\";"]]
};
const T = H.setup(__filename, MUTATIONS, [HOME, FEED, SHELL, BAR, SW, PROFILE]);
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
  return [["avatar", fn.indexOf("railAvatar(p)")], ["like", fn.indexOf('act("like"')], ["talk", fn.indexOf('act("talk"')], ["tip", fn.indexOf("bfp-act bfp-tip")],
    ["save", fn.indexOf('data-act="save"')], ["share", fn.indexOf('act("share"')]].filter(x => x[1] >= 0).sort((a, b) => a[1] - b[1]).map(x => x[0]);
})();
check("B8. the rail's order: " + R.ORDER.join(", "), J(order) === J(R.ORDER), J(order));
ruleCheck("B9. Tip BFC's slot kept, unseen, gold (tipping arrives for paid members)", feedPhone, ".bfp-feed.is-full .bfp-tip", { display: "flex", visibility: "hidden", color: C.GOLD });
check("B10. Tip BFC cannot be reached (disabled, out of the tab order, hidden from readers)", feed.indexOf('class="bfp-act bfp-tip" data-act="tip" disabled tabindex="-1" aria-hidden="true">') !== -1);
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
ruleCheck("D1. the top row " + PT.ROW_TOP + " px below the safe area, " + PT.BUTTON + " px tall, " + PT.PAD_X + " px in", shellPhone, ".pfs-bar",
  { height: px(PT.BUTTON), "margin-top": "calc(" + px(PT.ROW_TOP) + " + env(safe-area-inset-top, 0px))", padding: "0 " + px(PT.PAD_X) });
ruleCheck("D2. its icons " + PT.BUTTON + " px", shellPhone, ".pfs-icon", { width: px(PT.BUTTON), height: px(PT.BUTTON) });
ruleCheck("D3. the name centred, " + PT.NAME_FONT + " px, weight " + PT.NAME_WEIGHT, shellPhone, ".pfs-title", { "text-align": "center", font: PT.NAME_WEIGHT + " " + px(PT.NAME_FONT) + '/1.25 system-ui,-apple-system,"Segoe UI",Arial,sans-serif' });
ruleCheck("D4. the picture " + PA.SIZE + " px with a " + PA.RING + " px cyan-to-violet ring", shellPhone, ".pfs-av",
  { width: px(PA.SIZE), height: px(PA.SIZE), padding: px(PA.RING), background: "linear-gradient(180deg," + ACC + "," + VIO + ")" });
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
check("D28. \"BizForce member\" only for a paid member", shell.indexOf('(handle ? "@" + esc(handle) + (paid ? " &middot; BizForce member" : "")') !== -1 &&
  shell.indexOf("var paid = owner ? state.member === true : p.member !== false;") !== -1 &&
  shell.indexOf('get("/api/auth/me", true).then(function (d) { state.member = !!(d && d.access && d.access.active === true); render(); })') !== -1);
check("D29. a visitor sees Follow and Message (Share profile is the owner's on a phone)", shell.indexOf("'<a class=\"pfs-btn pfs-msg\" id=\"pfsMessage\" href=\"/inbox.html?with=' + encodeURIComponent(viewId) + '\">Message</a>'") !== -1 &&
  shellPhone.indexOf(".pfs-share-v{display:none}") !== -1);
check("D30. on a phone the page's old header is hidden while not editing, and the Guide's button is not on this screen",
  shellPhone.indexOf("body:not(.edit-mode) .pf-nav,body:not(.edit-mode) .pf-banner,body:not(.edit-mode) .pf-header-wrap{display:none}") !== -1 && shellPhone.indexOf("#tmx-guide-fab{display:none}") !== -1);
const shellOutside = shell.slice(0, shell.indexOf('"@media (max-width: 760px){"'));
check("D31. a desktop shows none of the phone header's parts (hidden outside the phone block)",
  shellOutside.indexOf('".pfs-bar,.pfs-pic,.pfs-msg,.pfs-tab.is-reviews,.pfs-cell-label,.pfs-saved-head{display:none}",') !== -1);

/* ── E ── */
console.log("\n══ E. the shell's version ══");
check("E1. sw.js SHELL_REV is \"fx1\"", /\nvar SHELL_REV = "fx1";\n/.test(FILES[SW] || ""));

T.finish();
