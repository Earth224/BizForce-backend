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
     E. THE SHELL'S VERSION (sw.js): SHELL_REV is "p33" (NAMED, P3-3: BEFORE "fx3b"; NAMED, FX3B: BEFORE "fx3"; NAMED, FX3: BEFORE "p31c"; NAMED, P3-1B: BEFORE "fx2"; NAMED, P3-1: BEFORE "fx1"; NAMED, P3-2: BEFORE "p31"; NAMED, FX2: BEFORE "p32").
     F. FX2 (Nov 21 2026): Tip BFC for a paid member; the product strip, built and linked (lib/posts.js
        sends a post's active listing, run here over the P2-3 test database); the tabs on one line; the
        Profile's banner (added, changed, removed in Edit profile) and its ring; the Agent Directory's
        look (its behaviour is checkAgentViews'); the orbit's first settle (no jump, no jerk, at rest
        in SETTLE_MS, nothing under reduced motion).
     G. FX3 (Nov 22 2026): the owner's canvas row 5, four boards (designSpec TMX and HQ.ABYSS): the abyss
        sun (the chat box's void and starfield density in the gold ring, no green ring); the mist a 56 px
        button 16 px from the right and 16 px above the bar; the Guide tab and its panel on the phone; the
        chat 8 px from each side, 10 px above the mist, at most 420 px; the still fade under reduced motion.
     NAMED (Nov 23 2026, LR-2): I. the owner's canvas row 6, three boards (designSpec LEADS): agents/lead-radar.html's
        header, its two tabs (Leads, Fingerprint; no Inbound or Get found), the stats, the source chips, the lead cards and
        their badges and buttons, the reply sheet (the quote, the draft box, the three checks, the link switch, Write it again
        and Post my reply, its line), the Fingerprint (its labels, chips, Where to look and Threads' waiting line); every
        control a 44 px target with the board's face inside; the site's fonts and music icon; members only (no request
        signed out or from a free account; bf-access.js MEMBER_PAGES; the dashboard's lead count read by members only);
        the reply sent is the box's own text.
   Every phone rule is checked to be inside its file's @media (max-width:
   760px) block, so the desktop is unchanged.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const DS = require("./designSpec");

const HOME = "home.html", FEED = "scripts/bf-feed.js", SHELL = "scripts/bf-profile-shell.js", BAR = "scripts/bf-tabbar.js", SW = "sw.js", PROFILE = "profile.html";
// NAMED (Nov 21 2026, FX2): the server's posts library, the Agent Directory's views and the orbit
const POSTS = "@lib/posts.js", AGV = "scripts/bf-agents-views.js", AGP = "ai-agents.html", ORB = "scripts/bf-orbit.js";
// NAMED (Nov 22 2026, FX3)
const TMXP = "scripts/termaximus-presence.js", TMXG = "scripts/termaximus-guide.js", ABY = "scripts/bf-abyss.js", DASHB = "dashboard.html";
// NAMED (Nov 23 2026, P3-3): the owner's canvas row 4, the composer and the Need post
const COMP = "scripts/bf-composer.js", COMPOSE = "compose.html";
// NAMED (Nov 23 2026, LR-2): Lead Radar's page and the members' page list
const LRP = "agents/lead-radar.html", BFA = "scripts/bf-access.js";
const HTABS = "scripts/bf-home-tabs.js";   // NAMED (Nov 25 2026, H1): Home's tabs and Search (section K)
const MUTATIONS = {
  "tab-font": [[HOME, "color:#c9d1e6;font:600 16px/1 system-ui", "color:#c9d1e6;font:600 15px/1 system-ui"]],
  "underline-thin": [[HOME, "bottom:1px;height:3px;border-radius:2px;background:var(--bf-accent-a, #22d3ee)}", "bottom:1px;height:2px;border-radius:2px;background:var(--bf-accent-a, #22d3ee)}"]],
  "no-dot": [[HTABS, 'm.classList.toggle("has-dot", r.body.market_new === true && S.tab !== "market");', 'm.classList.toggle("has-dot", true);']],   // NAMED (Nov 25 2026, H1): BEFORE the page's always-drawn dot was removed
  // NAMED (Nov 25 2026, H1): section K
  "h1-chip-height": [[HTABS, "display:inline-flex;align-items:center;gap:6px;height:34px;box-sizing:border-box;padding:0 12px;border-radius:17px", "display:inline-flex;align-items:center;gap:6px;height:32px;box-sizing:border-box;padding:0 12px;border-radius:17px"]],
  "h1-chip-no-target": [[HTABS, "align-items:center;height:44px;padding:0;border:0;background:none;color:inherit;cursor:pointer", "align-items:center;height:34px;padding:0;border:0;background:none;color:inherit;cursor:pointer"]],
  "h1-chip-no-face": [[HTABS, "'<button type=\"button\" class=\"bfh-chip\" data-bfh=\"change\" id=\"homeLocalChange\"><span class=\"bfh-chipf\">Change</span></button>'", "'<button type=\"button\" class=\"bfh-chip\" data-bfh=\"change\" id=\"homeLocalChange\">Change</button>'"]],
  "h1-tab-grey-on-phone": [[HOME,"    @media (min-width: 761px){.feed-tab[aria-selected=false]{border-bottom-color:transparent;color:#a9b3cc;cursor:pointer}}", "    .feed-tab[aria-selected=false]{border-bottom-color:transparent;color:#a9b3cc;cursor:pointer}"]],
  "h1-chips-low": [[HTABS, "top:calc(59px + env(safe-area-inset-top, 0px));z-index:42;padding:0}", "top:calc(64px + env(safe-area-inset-top, 0px));z-index:42;padding:0}"]],
  "h1-rail-gap": [[HTABS, "width:60px;flex-direction:column;align-items:center;gap:18px;padding:0}", "width:60px;flex-direction:column;align-items:center;gap:12px;padding:0}"]],
  "h1-meta-right": [[HTABS, ".bfm-list.is-full .bfm-meta{position:absolute;left:14px;right:80px;bottom:16px;", ".bfm-list.is-full .bfm-meta{position:absolute;left:14px;right:60px;bottom:16px;"]],
  "h1-title-size": [[HTABS, ".bfm-title{margin:0;font:700 21px/1.2 ", ".bfm-title{margin:0;font:700 19px/1.2 "]],
  "h1-price-white": [[HTABS, "font:700 22px/1.2 \" + F + \";color:#f5c46b}", "font:700 22px/1.2 \" + F + \";color:#ffffff}"]],
  "h1-buy-short": [[HTABS, ".bfm-buy{height:44px;padding:0 26px;", ".bfm-buy{height:40px;padding:0 26px;"]],
  "h1-local-line": [[HTABS, "#homeLocalFeed .bfp-kind.is-local .bfp-kmeta{font-size:13px;color:#c9d1e6}", "#homeLocalFeed .bfp-kind.is-local .bfp-kmeta{font-size:12px;color:#c9d1e6}"]],
  "h1-local-line-unscoped": [[HTABS, "#homeLocalFeed .bfp-kind.is-local .bfp-kmeta{", ".bfp-kind.is-local .bfp-kmeta{"]],
  "h1-follow-title": [[HTABS, 'followTitle: "Follow people to fill this tab"', 'followTitle: "Follow people"']],
  "h1-follow-top": [[HTABS, "body.bfh-board .page{padding-top:calc(68px + env(safe-area-inset-top, 0px))}", "body.bfh-board .page{padding-top:calc(80px + env(safe-area-inset-top, 0px))}"]],
  "h1-label-spacing": [[HTABS, "letter-spacing:1.6px;color:#8e9bbf}", "letter-spacing:1px;color:#8e9bbf}"]],
  "h1-row-line": [[HTABS, ".bfh-row{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #141b33}", ".bfh-row{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:0}"]],
  "h1-follow-pill": [[HTABS, "align-items:center;height:34px;box-sizing:border-box;padding:0 14px;border-radius:17px", "align-items:center;height:30px;box-sizing:border-box;padding:0 14px;border-radius:17px"]],
  "h1-follow-no-target": [[HTABS, "justify-content:center;height:44px;min-width:44px;padding:0;border:0;background:none", "justify-content:center;height:34px;min-width:44px;padding:0;border:0;background:none"]],
  "h1-suggest-max": [["@lib/homeTabs.js", "const SUGGEST_MAX = 8;", "const SUGGEST_MAX = 12;"]],
  "h1-field-radius": [[HTABS, "height:44px;box-sizing:border-box;border-radius:22px;border:1px solid var(--bf-accent-a, #22d3ee)", "height:44px;box-sizing:border-box;border-radius:12px;border:1px solid var(--bf-accent-a, #22d3ee)"]],
  "h1-search-pad": [[HTABS, "padding:calc(12px + env(safe-area-inset-top, 0px)) 12px 8px}", "padding:calc(16px + env(safe-area-inset-top, 0px)) 12px 8px}"]],
  "h1-scope-missing": [[HTABS, ', ["needs", "Needs"]];', '];']],
  "h1-thumb": [[HTABS, ".bfh-l-tile{flex:none;width:56px;height:56px;border-radius:12px;", ".bfh-l-tile{flex:none;width:48px;height:48px;border-radius:12px;"]],
  "h1-grid-two": [[HTABS, ".bfh-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:4px}", ".bfh-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px}"]],
  "h1-board-font": [[HTABS, "var F = 'system-ui,-apple-system,\"Segoe UI\",Arial,sans-serif';", "var F = '\"Space Grotesk\",system-ui';"]],
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
  // NAMED (Nov 22 2026, FX3B): BEFORE anchored on "fx3"; AFTER "fx3b"
  // NAMED (Nov 23 2026, P3-3): BEFORE "fx3b"; AFTER "p33" (Share, Offer or Need, the Need post and I can help, the Market filter): the anchor "p33", the mutant "fx3b"
  // NAMED (Nov 23 2026, LR-1): BEFORE "p33"; AFTER "lr1" (approve each reply before it posts, the Lead Radar sign-in prompt, tidy-ups). sw.js now carries its note on the SHELL_REV line, so the line may end in a // comment. Mutant "p33".
  // NAMED (Nov 26 2026, FX4S): BEFORE "fx4m"; AFTER "fx4s" (the phone music library shows only in the open boombox and is not reopened at a phone launch). FX4M: BEFORE "fx4a"; AFTER "fx4m" (music carries on across pages and stops on Home; the Guide tab on the Inbox). FX4A: BEFORE "h1b"; AFTER "fx4a" (the boombox, AI Agent Tasks, the Oracle pages and the calendar on phones). H1B: BEFORE "h1"; AFTER "h1b" (no mist on Home or the composer; room under the mist at the end of card-view and proposals). H1: BEFORE "g1"; AFTER "h1" (the home tabs, Search and the storefront badge). HOTFIX-G1: BEFORE "lr4b"; AFTER "g1" (phone layouts restored; only the controls under the Guide tab moved). LR-4B: BEFORE "lr4"; AFTER "lr4b" (the storefront menu draws whichever loads first). LR-4: BEFORE "lr3b"; AFTER "lr4" (Get found). LR-3B: BEFORE "lr3"; AFTER "lr3b" (nothing to tap under the Guide tab on the phone). LR-3: BEFORE "lr2b"; AFTER "lr3" (Inbound, the storefront Message button). LR-2B: BEFORE "lr2"; LR-2: BEFORE "lr1b".
  "shell-rev": [[SW, "var SHELL_REV = \"fx4s\";", "var SHELL_REV = \"p33\";"]],   // NAMED (Nov 22 2026, FX3): BEFORE the anchor "p31b" (mutant "fx2"), which no longer matched; AFTER "fx3" (mutant "p31c")
    // NAMED (Nov 21 2026, P3-1B): the mutant is now "fx2", was "p32"; NAMED (Nov 21 2026, FX2): BEFORE "p32" (mutant "p23")
  // NAMED (Nov 21 2026, FX2)
  "tip-never-shown": [[FEED, "    \".bfp-feed.is-full .bfp-tip.is-member{visibility:visible}\",\n", ""]],
  "tip-for-free": [[FEED, "setMember(!!a && a.tier === \"member\");", "setMember(!!a);"]],
  "tip-not-watched": [[FEED, "    watchAccess(40);   // NAMED (Nov 21 2026, FX2)", "   // NAMED (Nov 21 2026, FX2)"]],
  "strip-unlinked": [[FEED, "    return '<a class=\"bfp-buy\" href=\"' + esc(href) + '\"", "    return '<a class=\"bfp-buy\" data-href=\"' + esc(href) + '\""]],
  "strip-not-drawn": [[FEED, "status + stripHtml(p) + helpHtml(p) + '</div></div>'", "status + helpHtml(p) + '</div></div>'"]],   // NAMED (Nov 23 2026, P3-3): + helpHtml(p)
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
  // NAMED (Nov 22 2026, FX3B): BEFORE anchored on openPortal(firstPortal(state.top), "settle"); }. AFTER the first portal is held in first
  "settle-jumps": [[ORB, "if (!awaitFront(first)) openPortal(first, \"settle\");", "if (!awaitFront(first)) openPortal(first, false);"]],
  "settle-jerks": [[ORB, "return D * (1 - Math.pow(1 - t, 3)) + (V - 3 * D) * t * (1 - t) * (1 - t);", "return D * (1 - Math.pow(1 - t, 3));"]],
  "settle-slow": [[ORB, "  var SETTLE_MS = 1300;", "  var SETTLE_MS = 2400;"]],
  // NAMED (Nov 22 2026, FX3): the four boards of row 5
  "fx3-mist-size": [[TMXP, "  var TMX_PHONE_MIST = 56, TMX_DESK_MIST = 110;", "  var TMX_PHONE_MIST = 64, TMX_DESK_MIST = 110;"]],
  "fx3-mist-right": [[TMXP, "right: 16px !important; bottom: calc(16px + env(safe-area-inset-bottom, 0px)) !important;", "right: 12px !important; bottom: calc(16px + env(safe-area-inset-bottom, 0px)) !important;"]],
  "fx3-mist-on-bar": [[TMXP, "  html.bf-tabbar-on #tmx-presence-root { bottom: calc(56px + 16px + env(safe-area-inset-bottom, 0px)) !important; }", "  html.bf-tabbar-on #tmx-presence-root { bottom: calc(56px + env(safe-area-inset-bottom, 0px)) !important; }"]],
  "fx3-chat-sides": [[TMXP, "left: 8px !important; right: 8px !important; width: auto !important;", "left: 16px !important; right: 16px !important; width: auto !important;"]],
  "fx3-chat-tall": [[TMXP, "    var height = Math.min(420, visH - safeTop - 16,", "    var height = Math.min(520, visH - safeTop - 16,"]],
  "fx3-chat-gap": [[TMXP, "    var bottom = Math.max(0, layoutH - mistTop) + 10;", "    var bottom = Math.max(0, layoutH - mistTop) + 24;"]],
  "fx3-panel-wide": [[TMXG, "width: min(300px, calc(100vw - 48px)); margin-left: 0;", "width: min(340px, calc(100vw - 48px)); margin-left: 0;"]],
  "fx3-panel-tall": [[TMXG, "    max-height: min(70vh, calc(", "    max-height: min(85vh, calc("]],
  "fx3-slide-slow": [[TMXG, "transform: translate(calc(-1 * min(300px, 100vw - 48px)), -50%); transition: transform 0.3s ease; }", "transform: translate(calc(-1 * min(300px, 100vw - 48px)), -50%); transition: transform 0.6s ease; }"]],
  "fx3-tab-narrow": [[TMXG, "    \"  width: 32px;\",\n    \"  min-height: 170px;\",", "    \"  width: 28px;\",\n    \"  min-height: 170px;\","]],
  "fx3-fade-slow": [[TMXP, "tr: \"opacity 0.2s ease\", dur: 200 };", "tr: \"opacity 0.4s ease\", dur: 400 };"]],
  "fx3-abyss-dense": [[ABY, "  var BASE_COUNTS = [70, 35, 16];", "  var BASE_COUNTS = [90, 35, 16];"]],
  "fx3-green-ring": [[DASHB, "{display:none}\n    #orbitTop[data-hq-open=\"oracle\"] .orbit-core > :not(.hq-core-moon)", "{display:block}\n    #orbitTop[data-hq-open=\"oracle\"] .orbit-core > :not(.hq-core-moon)"]],
  "settle-when-reduced": [[ORB, "    if (reduced()) { state.turn = null; state.base += delta; place(); flushSparks(); return; }\n", ""]],
  // NAMED (Nov 23 2026, P3-3): the owner's canvas row 4 (section H)
  "p33-header-tall": [[COMPOSE, "height:64px;margin:0 -16px 16px;padding:0 12px;border-bottom:1px solid #1e2848}", "height:56px;margin:0 -16px 16px;padding:0 12px;border-bottom:1px solid #1e2848}"]],
  "p33-post-pill": [[COMP, "\".bfc-pill{display:inline-flex;align-items:center;height:40px;padding:0 18px;border-radius:20px;", "\".bfc-pill{display:inline-flex;align-items:center;height:36px;padding:0 18px;border-radius:20px;"]],
  "p33-tile-radius": [[COMP, "gap:2px;height:64px;box-sizing:border-box;padding:0 4px;border-radius:10px;", "gap:2px;height:64px;box-sizing:border-box;padding:0 4px;border-radius:14px;"]],
  "p33-tile-order": [[COMP, "var INTENTS = [[\"share\", \"Share\", \"Show your work\"], [\"offer\", \"Offer\", \"Sell or book\"], [\"need\", \"Need\", \"Ask for help\"]];", "var INTENTS = [[\"share\", \"Share\", \"Show your work\"], [\"need\", \"Need\", \"Ask for help\"], [\"offer\", \"Offer\", \"Sell or book\"]];"]],
  "p33-label-font": [[COMP, "\".bfc-lab{display:block;margin:0;font-size:13px;line-height:16px;", "\".bfc-lab{display:block;margin:0;font-size:12px;line-height:16px;"]],
  "p33-need-label": [[COMP, "need: \"What do you need?\" };", "need: \"Ask for help\" };"]],
  "p33-chip-tall": [[COMP, "\".bfc-chip .bfc-face{display:flex;align-items:center;height:40px;", "\".bfc-chip .bfc-face{display:flex;align-items:center;height:36px;"]],
  "p33-chips-wrap": [[COMP, "\".bfc-chips{display:flex;gap:8px;margin-top:-3px;overflow-x:auto;", "\".bfc-chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:-3px;overflow-x:auto;"]],
  "p33-box-for-followers": [[COMP, "needBox.hidden = !(it === \"need\" && audienceNow() === \"public\");", "needBox.hidden = !(it === \"need\");"]],
  "p33-box-words": [[COMP, "var NEED_BOX = \"Members who offer this nearby will be told about your post.\";", "var NEED_BOX = \"Members nearby will be told.\";"]],
  "p33-slots": [[COMP, "grid-template-columns:repeat(4,minmax(0,78px));gap:8px;", "grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;"]],
  "p33-when-off-screen": [[COMP, "\".bfc-where{flex:1;min-width:0;", "\".bfc-where{flex:none;width:241px;min-width:0;"]],
  "p33-tag-tall": [[FEED, "justify-content:center;height:24px;box-sizing:border-box;padding:0 9px;border-radius:12px;", "justify-content:center;height:28px;box-sizing:border-box;padding:0 9px;border-radius:12px;"]],
  "p33-meta-font": [[FEED, "\".bfp-kmeta{min-width:0;font:400 14px/16px ", "\".bfp-kmeta{min-width:0;font:400 13px/16px "]],
  "p33-help-pill": [[FEED, "height:34px;padding:0 12px;border-radius:17px;background:var(--bf-accent-a, #22d3ee);color:#04121a;", "height:34px;padding:0 12px;border-radius:8px;background:var(--bf-accent-a, #22d3ee);color:#04121a;"]],
  "p33-help-for-poster": [[FEED, "if (!p || p.intent !== \"need\" || p.can_help !== true || p.mine || isFound(p)) return \"\";", "if (!p || p.intent !== \"need\" || p.can_help !== true || isFound(p)) return \"\";"]],
  "p33-help-when-found": [[FEED, "if (!p || p.intent !== \"need\" || p.can_help !== true || p.mine || isFound(p)) return \"\";", "if (!p || p.intent !== \"need\" || p.can_help !== true || p.mine) return \"\";"]],
  "p33-help-words": [[FEED, "var HELP = { title: \"You offer this nearby\", sub: \"Reply privately with your work\", go: \"I can help\" };", "var HELP = { title: \"You offer this\", sub: \"Reply privately with your work\", go: \"Help\" };"]],
  "p33-backdrop": [[FEED, "radial-gradient(circle at 77% 28%,#123a4a 0,", "radial-gradient(circle at 50% 50%,#123a4a 0,"]],
  "p33-found-tag": [[FEED, "(isFound(p) ? \"FOUND\" : \"NEED\")", "\"NEED\""]],
  // NAMED (Nov 23 2026, LR-2): the owner's canvas row 6 (section I)
  "lr2-head-gap": [[LRP, ".lr-head { display: flex; align-items: center; gap: 6px; padding: 12px 8px 4px; }", ".lr-head { display: flex; align-items: center; gap: 10px; padding: 12px 8px 4px; }"]],
  "lr2-board-font": [[LRP, ".lr-title { flex: 1; min-width: 0; margin: 0; font: 700 18px system-ui,", ".lr-title { flex: 1; min-width: 0; margin: 0; font: 700 18px 'Space Grotesk', system-ui,"]],
  "lr2-no-music": [[LRP, "<span class=\"brand-badge\" data-bf-boombox-anchor>BizForce AI</span>", "<span class=\"brand-badge\">BizForce AI</span>"]],
  "lr2-inbound-tab": [[LRP, "<span class=\"lr-tbf\">Fingerprint</span></button>", "<span class=\"lr-tbf\">Fingerprint</span></button>\n      <button type=\"button\" role=\"tab\" class=\"lr-tb\" aria-selected=\"false\"><span class=\"lr-tbf\">Inbound</span></button>"]],
  "lr2-tab-tall": [[LRP, ".lr-tbf { display: flex; align-items: center; height: 40px;", ".lr-tbf { display: flex; align-items: center; height: 44px;"]],
  "lr2-tab-small-hit": [[LRP, ".lr-tb { flex: none; min-width: 44px; height: 44px; margin: -2px 0;", ".lr-tb { flex: none; min-width: 44px; height: 40px; margin: 0;"]],
  "lr2-card-radius": [[LRP, ".lr-card { display: flex; flex-direction: column; gap: 8px; padding: 12px; border-radius: 16px;", ".lr-card { display: flex; flex-direction: column; gap: 8px; padding: 12px; border-radius: 12px;"]],
  "lr2-won-white": [[LRP, ".lr-num.is-won { color: #f5c46b; }", ".lr-num.is-won { color: #e6eaf5; }"]],
  "lr2-chip-radius": [[LRP, "height: 34px; padding: 0 12px; border-radius: 17px;", "height: 34px; padding: 0 12px; border-radius: 12px;"]],
  "lr2-chip-sources": [[LRP, "[\"bizforce\", \"Inside BizForce\"], ", ""]],
  "lr2-badge-colour": [[LRP, ".lr-b-bsky { background: #1b2350; color: #b79cfa; }", ".lr-b-bsky { background: #1b2350; color: #e6eaf5; }"]],
  "lr2-yt-opaque": [[LRP, ".lr-card.is-yt { opacity: .8; }", ".lr-card.is-yt { opacity: 1; }"]],
  "lr2-button-tall": [[LRP, "width: 100%; height: 38px; padding: 0 14px; border-radius: 19px;", "width: 100%; height: 44px; padding: 0 14px; border-radius: 19px;"]],
  "lr2-button-words": [[LRP, "btn(\"Draft a reply\", ", "btn(\"Reply\", "]],
  "lr2-foot-words": [[LRP, "<p class=\"lr-foot\">You approve every reply. BizForce never messages anyone for you.</p>", "<p class=\"lr-foot\">You approve every reply.</p>"]],
  "lr2-sheet-short": [[LRP, "gap: 12px; height: 640px; max-height:", "gap: 12px; height: 600px; max-height:"]],
  "lr2-sheet-over-bar": [[LRP, ".lr-sheet { position: fixed; left: 0; right: 0; bottom: 0; z-index: 80;", ".lr-sheet { position: fixed; left: 0; right: 0; bottom: 0; z-index: 95;"]],
  "lr2-quote-line": [[LRP, "border-left: 3px solid var(--bf-accent-b, #8b5cf6);", "border-left: 2px solid var(--bf-accent-b, #8b5cf6);"]],
  "lr2-draft-box": [[LRP, "min-height: 132px; padding: 12px; border-radius: 14px;", "min-height: 100px; padding: 12px; border-radius: 14px;"]],
  "lr2-check-words": [[LRP, "c.no_hard_sell, \"No hard sell, no promises\"]", "c.no_hard_sell, \"No hard sell\"]"]],
  // NAMED (Nov 24 2026, LR-3): LeadsInbound
  "lr3-pipe-pad": [[LRP, ".lr-pipe { padding: 10px 12px; gap: 8px; }", ".lr-pipe { padding: 12px; gap: 8px; }"]],
  "lr3-bar-h": [[LRP, ".lr-bar { display: flex; height: 10px;", ".lr-bar { display: flex; height: 8px;"]],
  "lr3-talking-count": [[LRP, ".lr-pc-talking { color: #b79cfa; }", ".lr-pc-talking { color: #8b5cf6; }"]],
  "lr3-bar-static": [[LRP, "bar[0].style.flex = String(n);", "bar[0].style.flex = \"1\";"]],
  "lr3-chip-lost": [[LRP, ', ["lost", "Lost"]];', "];"]],
  "lr3-icon-radius": [[LRP, "width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; border-radius: 12px;", "width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; border-radius: 20px;"]],
  "lr3-summary-line": [[LRP, ".lr-is { font-size: 13.5px; line-height: 1.35;", ".lr-is { font-size: 13.5px; line-height: 1.5;"]],
  "lr3-won-pill": [[LRP, ".lr-s-won { background: #f5c46b;", ".lr-s-won { background: #6ee7b7;"]],
  "lr3-card-icon": [[LRP, ".lr-ico-card_lead { background: #14302a;", ".lr-ico-card_lead { background: #0f2a3a;"]],
  "lr3-heart": [[LRP, "M12 21s-7-4.5-7-10", "M12 20s-7-4.5-7-10"]],
  "lr3-no-tip-icon": [[LRP, "      tip: '", "      coin: '"]],
  "lr3-kind-weight": [[LRP, ".lr-ik { flex: none; font: 600 13px", ".lr-ik { flex: none; font: 700 13px"]],
  "lr3-tab-gone": [[LRP, '<span class="lr-tbf">Inbound</span>', '<span class="lr-tbf">Inbox</span>']],
  "lr2-link-on": [[LRP, "S.sheetLead = l; S.sheetLink = false;", "S.sheetLead = l; S.sheetLink = true;"]],
  "lr2-knob": [[LRP, "right: 3px; top: 3px; width: 20px; height: 20px;", "right: 3px; top: 3px; width: 18px; height: 18px;"]],
  "lr2-fp-pad": [[LRP, ".lr-fp { gap: 12px; padding: 0 16px; }", ".lr-fp { gap: 12px; padding: 0 12px; }"]],
  "lr2-label-spacing": [[LRP, "letter-spacing: 1.6px; color: #8e9bbf; text-transform: uppercase;", "letter-spacing: 1px; color: #8e9bbf; text-transform: uppercase;"]],
  "lr2-threads-words": [[LRP, "\"Waiting for Meta's approval\"", "\"Waiting\""]],
  "lr2-free-calls": [[LRP, "        if (a.tier === \"free\") { showState(\"members_only\"); return; }\n", ""]],
  "lr2-signed-out-calls": [[LRP, "      if (!tok()) { showState(\"signed_out\"); return; }\n", ""]],
  "lr2-not-member-page": [[BFA, "    \"agents/lead-radar.html\"\n  ];", "    \"campaigns.html\"\n  ];"]],
  // NAMED (Nov 23 2026, LR-2 pages fallout): BEFORE "lr2-dash-free-call" (the removed inline script). AFTER the orbit calls them scored leads again.
  "lr2-orbit-scored": [[ORB, "case \"lead-radar\": return count(\"leads\", \"new lead\", \"new leads\");", "case \"lead-radar\": return count(\"leads\", \"scored lead\", \"scored leads\");"]],
  // the dashboard reads the leads itself again
  "lr2-dash-call": [[DASHB, "</body>", "<script>fetch(\"/api/leads/summary\");</script>\n</body>"]],
  "lr2-send-the-draft": [[LRP, "var text = box.value.trim();", "var text = (box.defaultValue || \"\").trim();"]],
  // NAMED (Nov 23 2026, LR-2): the page drops under the theme's fixed backdrop (PHONE_LR2's first screenshot showed only the YouTube card)
  "lr2-under-backdrop": [[LRP, ".lr-page { position: relative; z-index: 1;", ".lr-page {"]],
  // NAMED (Nov 23 2026, LR-2): a slow read that started before Save lands after it and shows the lead unsaved again
  "lr2-stale-read": [[LRP, "        if (mine !== seq) return;\n", ""]],
  // NAMED (Nov 25 2026, LR-4): LeadsFound, section J
  "lr4-tab-gone": [[LRP, '<span class="lr-tbf">Get found</span>', '<span class="lr-tbf">Found</span>']],
  "lr4-tabs-clip": [[LRP, ".lr-tabs { display: flex; gap: 4px; padding: 0 12px 10px; overflow-x: auto; }", ".lr-tabs { display: flex; gap: 4px; padding: 0 12px 10px; overflow: hidden; }"]],
  "lr4-top-gap": [[LRP, ".lr-gf-top { display: flex; align-items: center; gap: 16px;", ".lr-gf-top { display: flex; align-items: center; gap: 12px;"]],
  "lr4-intro-words": [[LRP, "Do the gold ones first.</p>", "Start with the gold ones.</p>"]],
  "lr4-ring-arc": [[LRP, '<circle id="lrRingArc" cx="48" cy="48" r="40" fill="none" stroke="#f5c46b"', '<circle id="lrRingArc" cx="48" cy="48" r="40" fill="none" stroke="#22d3ee"']],
  "lr4-ring-track": [[LRP, 'r="40" fill="none" stroke="#1e2848" stroke-width="8"', 'r="40" fill="none" stroke="#141b33" stroke-width="8"']],
  "lr4-ring-size": [[LRP, '<svg class="lr-ring" id="lrRing" width="96" height="96"', '<svg class="lr-ring" id="lrRing" width="88" height="88"']],
  "lr4-ring-dash": [[LRP, 'arc.setAttribute("stroke-dasharray", Math.round(RING * n / 100) + " 252");', 'arc.setAttribute("stroke-dasharray", n + " 252");']],
  "lr4-ring-num": [[LRP, 'fill="#f7f3e8" font-weight="700" font-size="24"', 'fill="#f7f3e8" font-weight="700" font-size="22"']],
  "lr4-row-pad": [[LRP, ".lr-gfi { display: flex; align-items: center; gap: 10px; padding: 10px 0;", ".lr-gfi { display: flex; align-items: center; gap: 10px; padding: 12px 0;"]],
  "lr4-row-line": [[LRP, "padding: 10px 0; border-bottom: 1px solid #141b33; }", "padding: 10px 0; border-bottom: 1px solid #1e2848; }"]],
  "lr4-mark-size": [[LRP, ".lr-gfm { flex: none; width: 26px; height: 26px;", ".lr-gfm { flex: none; width: 24px; height: 24px;"]],
  "lr4-done-colour": [[LRP, ".lr-gfi.is-done .lr-gfm { border-color: #6ee7b7; color: #6ee7b7; }", ".lr-gfi.is-done .lr-gfm { border-color: #f5c46b; color: #f5c46b; }"]],
  "lr4-waiting-colour": [[LRP, ".lr-gfi.is-waiting .lr-gfm { border-color: #8e9bbf; color: #8e9bbf; }", ".lr-gfi.is-waiting .lr-gfm { border-color: #a9b3cc; color: #a9b3cc; }"]],
  "lr4-mark-words": [[LRP, 'var MARKS = { todo: "!", done: "&#10003;", waiting: "&#8230;" };', 'var MARKS = { todo: "!", done: "&#10003;", waiting: "-" };']],
  "lr4-title-font": [[LRP, ".lr-gft { display: block; font: 600 13.5px", ".lr-gft { display: block; font: 600 14px"]],
  "lr4-sub-font": [[LRP, ".lr-gfd { display: block; font-size: 12px; line-height: 1.35;", ".lr-gfd { display: block; font-size: 12px; line-height: 1.5;"]],
  "lr4-button-tall": [[LRP, ".lr-btn.is-s .lr-btnf { height: 34px; }", ".lr-btn.is-s .lr-btnf { height: 38px; }"]],
  "lr4-small-hit": [[LRP, "    .lr-btn.is-s { margin: -5px 0; }\n", ""]],
  "lr4-weight": [["@lib/foundScore.js", "var WEIGHTS = { basics: 15, profile: 20,", "var WEIGHTS = { basics: 20, profile: 15,"]],
  "lr4-waiting-words": [["@lib/foundScore.js", "detail: \"Connected, waiting for each platform's approval\"", "detail: \"Waiting for approval\""]]
};
// NAMED (Nov 23 2026, LR-2): + Lead Radar's page and bf-access.js
const T = H.setup(__filename, MUTATIONS, [HOME, FEED, SHELL, BAR, SW, PROFILE, POSTS, AGV, AGP, ORB, "css/bf-phone.css", TMXP, TMXG, ABY, DASHB, COMP, COMPOSE, LRP, BFA, HTABS, "@lib/homeTabs.js"]);   // NAMED (Nov 25 2026, H1): + HTABS, lib/homeTabs.js   // NAMED (Nov 23 2026, P3-3): + the composer and its page   // NAMED (Nov 22 2026, FX3): + the four boards' files
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
// NAMED (Nov 25 2026, H1): BEFORE the page drew Market's dot always (class "feed-tab is-soon has-dot"). AFTER bf-home-tabs.js draws it only
// when a member listed something since the viewer's last Market visit (GET /api/home/tabs market_new).
check("A2. the tabs read " + F.TOP.TABS.join(", ") + "; Following is the selected one; Market's dot only for new listings",
  J(tabText) === J(F.TOP.TABS) && /id="tabFollowing" aria-selected="true"/.test(home) && /class="feed-tab" role="tab" id="tabMarket"/.test(home) &&
  (FILES[HTABS] || "").indexOf('m.classList.toggle("has-dot", r.body.market_new === true && S.tab !== "market");') !== -1, J(tabText));
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
// NAMED (Nov 25 2026, H1): BEFORE Local, Market and Search (on a phone) opened the Coming soon sheet. AFTER they are built
// (scripts/bf-home-tabs.js); Live and For You still open it.
check("A9. Live and For You open the Coming soon sheet; Local and Market are tabs; Search opens the search screen on every width",
  home.indexOf('window.BFFeed.soon(t.getAttribute("data-soon"), t);') !== -1 && home.indexOf('window.BFFeed.soon("live", this);') !== -1 &&
  home.indexOf('document.getElementById("feedSearch").addEventListener("click", function () { if (window.BFHomeTabs) window.BFHomeTabs.openSearch(); });') !== -1 &&
  !/id="tab(Local|Market)"[^>]*data-soon/.test(home) && ["foryou", "live", "reviews"].every(k => new RegExp("\\n    " + k + ": \\[").test(feed)));
// NAMED (Nov 25 2026, H1): BEFORE a desktop showed only Following and Search. AFTER Local, Following, Market and Search, the
// inactive tabs grey (only above 760 px: a phone keeps the board's #c9d1e6); Live and For You stay hidden there.
check("A10. a desktop shows Local, Following, Market and Search, its inactive tabs grey only above 760 px (Live and For You hidden outside the phone block)",
  home.indexOf("    .feed-live,.feed-tab.is-soon{display:none}\n    /* NAMED (Nov 25 2026, H1)") !== -1 && home.indexOf("    @media (min-width: 761px){.feed-tab[aria-selected=false]{border-bottom-color:transparent;color:#a9b3cc;cursor:pointer}}") !== -1 &&
  (home.match(/\.feed-tab\[aria-selected=false\]/g) || []).length === 1 && homePhone.indexOf(".feed-live,.feed-tab.is-soon{display:inline-flex}") !== -1);

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
// NAMED (Nov 22 2026, FX3): BEFORE "p31c". AFTER "fx3".
// NAMED (Nov 22 2026, FX3B): BEFORE "fx3"; AFTER "fx3b"
// NAMED (Nov 23 2026, P3-3): BEFORE "fx3b"; AFTER "p33" (Share, Offer or Need, the Need post and I can help, the Market filter)
// NAMED (Nov 23 2026, LR-1): BEFORE "p33"; AFTER "lr1" (approve each reply before it posts, the Lead Radar sign-in prompt, tidy-ups). sw.js now carries its note on the SHELL_REV line, so the line may end in a // comment.
// NAMED (Nov 26 2026, FX4S): BEFORE "fx4m"; AFTER "fx4s" (the phone music library shows only in the open boombox and is not reopened at a phone launch). FX4M: BEFORE "fx4a"; AFTER "fx4m" (music carries on across pages and stops on Home; the Guide tab on the Inbox). FX4A: BEFORE "h1b"; AFTER "fx4a" (the boombox, AI Agent Tasks, the Oracle pages and the calendar on phones). H1B: BEFORE "h1"; AFTER "h1b" (no mist on Home or the composer; room under the mist at the end of card-view and proposals). H1: BEFORE "g1"; AFTER "h1" (the home tabs, Search and the storefront badge). HOTFIX-G1: BEFORE "lr4b"; AFTER "g1" (phone layouts restored; only the controls under the Guide tab moved). LR-4B: BEFORE "lr4"; AFTER "lr4b" (the storefront menu draws whichever loads first). LR-4: BEFORE "lr3b"; AFTER "lr4" (Get found). LR-3B: BEFORE "lr3"; AFTER "lr3b" (nothing to tap under the Guide tab on the phone). LR-3: BEFORE "lr2b"; AFTER "lr3" (Inbound, the storefront Message button). LR-2B: BEFORE "lr2"; LR-2: BEFORE "lr1b".
check("E1. sw.js SHELL_REV is \"fx4s\"", /\nvar SHELL_REV = "fx4s";[ \t]*(?:\/\/[^\n]*)?\n/.test(FILES[SW] || ""));

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
    // NAMED (Nov 23 2026, P3-3): BEFORE the strip ended the block; AFTER a Need's I can help strip follows it (helpHtml, section H)
    feed.indexOf("status + stripHtml(p) + helpHtml(p) + '</div></div>'") !== -1 && feed.indexOf("if (!L || typeof L.id !== \"string\" || !L.id) return \"\";") !== -1 &&
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
    // NAMED (Nov 22 2026, FX3B): BEFORE one line, openPortal(firstPortal(state.top), "settle"); }. AFTER the first portal is held in
    // first, settled at once when it is not just ahead, else its boxes are built while the ring drifts (prepareGrid).
    orb.indexOf("          if (!awaitFront(first)) openPortal(first, \"settle\");\n          else prepareGrid(first);") !== -1 && orb.indexOf("if (turn === \"settle\") settleTo(key, v0);") !== -1 &&
    orb.indexOf("var delta = ((target - state.base) % 360 + 540) % 360 - 180;   // the short way round") !== -1 &&
    orb.indexOf("    if (reduced()) { state.turn = null; state.base += delta; place(); flushSparks(); return; }\n") !== -1 &&
    orb.indexOf("var v0 = drifting() ? 360 / DRIFT_MS : 0;") !== -1 && /function drifting\(\) \{ return [^}]*!reduced\(\)/.test(orb));

  /* ── G ── NAMED (Nov 22 2026, FX3) */
  console.log("\n══ G. FX3: the owner's canvas row 5 (" + DS.TMX.BOARDS.join(", ") + ") ══");
  const TM = DS.TMX, AB = DS.HQ.ABYSS, tp = FILES[TMXP] || "", tg = FILES[TMXG] || "", ab = FILES[ABY] || "", db = FILES[DASHB] || "";
  const phoneCss = (() => { const a = tp.indexOf("  var TMX_PHONE = "), b = tp.indexOf("\n\n", a); return a < 0 ? "" : tp.slice(a, b); })();
  const mistM = /\n  var TMX_PHONE_MIST = (\d+), TMX_DESK_MIST = (\d+);/.exec(tp) || [], mistScale = mistM[1], deskMist = mistM[2];
  check("G1. TmxHQ: the abyss sun's void is the chat box's (" + AB.VOID_BASE + ", " + AB.VOID_SIZES + ", " + AB.VOID_ANIMATION + ")",
    db.indexOf("        " + AB.VOID_BASE + ";\n      background-size: " + AB.VOID_SIZES + ";\n      animation: " + AB.VOID_ANIMATION + "}") !== -1 &&
    tp.indexOf('    "    ' + AB.VOID_BASE + ';",\n    "  background-size: ' + AB.VOID_SIZES + ';",') !== -1 && tp.indexOf('"  animation: ' + AB.VOID_ANIMATION + ';",') !== -1);
  let counts = null; try { const w = {}; new Function("window", "document", ab)(w, { addEventListener() {}, hidden: false }); counts = w.BFAbyss && [w.BFAbyss.countsFor(AB.BOARD_RING, AB.BOARD_RING), w.BFAbyss.countsFor(AB.STAR_BASE.W, AB.STAR_BASE.H)]; } catch (e) { counts = String(e && e.message); }
  check("G2. its stars at the chat box's density per area: " + AB.STAR_BASE.COUNTS.join("/") + " in " + AB.STAR_BASE.W + " x " + AB.STAR_BASE.H + ", so " + AB.BOARD_COUNTS.join("/") + " in a " + AB.BOARD_RING + " px box (the board's ring)",
    Array.isArray(counts) && J(counts[0]) === J(AB.BOARD_COUNTS) && J(counts[1]) === J(AB.STAR_BASE.COUNTS), J(counts));
  check("G3. no green stats ring while ORACLE is open (" + AB.NO_GREEN_RING.join(", ") + "); the ring round the disc gold",
    db.indexOf(AB.NO_GREEN_RING.map(s => '#orbitTop[data-hq-open="oracle"] ' + s).join(",") + "{display:none}") !== -1 && AB.RING === "gold" && db.indexOf("hq-gold-ring") !== -1);
  check("G4. TmxChatGuide: the mist a " + TM.MIST.SIZE + " px button (the desktop's " + TM.MIST.DESK_SIZE + " px mist scaled), " + TM.MIST.RIGHT + " px from the right, " + TM.MIST.ABOVE_BAR + " px above the bar, \"" + TM.MIST.LABEL + "\", z-index " + TM.MIST.Z,
    Number(mistScale) === TM.MIST.SIZE && Number(deskMist) === TM.MIST.DESK_SIZE &&
    phoneCss.indexOf("right: " + px(TM.MIST.RIGHT) + " !important; bottom: calc(" + px(TM.MIST.ABOVE_BAR) + " + env(safe-area-inset-bottom, 0px)) !important;") !== -1 &&
    phoneCss.indexOf("html.bf-tabbar-on #tmx-presence-root { bottom: calc(" + px(DS.BAR.HEIGHT) + " + " + px(TM.MIST.ABOVE_BAR) + " + env(safe-area-inset-bottom, 0px)) !important; }") !== -1 &&
    phoneCss.indexOf("z-index: " + TM.MIST.Z + ";") !== -1 && tp.indexOf('root.setAttribute("aria-label", "' + TM.MIST.LABEL + '");') !== -1, J([mistScale, deskMist]));
  check("G5. the chat " + TM.CHAT.SIDE + " px from each side, " + TM.CHAT.ABOVE_MIST + " px above the mist, at most " + TM.CHAT.HEIGHT + " px (and the visible viewport less the top safe area and " + TM.CHAT.TOP_GAP + ")",
    phoneCss.indexOf("left: " + px(TM.CHAT.SIDE) + " !important; right: " + px(TM.CHAT.SIDE) + " !important; width: auto !important;") !== -1 &&
    phoneCss.indexOf("min(" + px(TM.CHAT.HEIGHT) + ", calc(100vh - env(safe-area-inset-top, 0px) - " + px(TM.CHAT.TOP_GAP) + "))") !== -1 &&
    tp.indexOf("    var bottom = Math.max(0, layoutH - mistTop) + " + TM.CHAT.ABOVE_MIST + ";") !== -1 &&
    tp.indexOf("    var height = Math.min(" + TM.CHAT.HEIGHT + ", visH - safeTop - " + TM.CHAT.TOP_GAP + ",") !== -1);
  const G = TM.GUIDE, tabRule = block(tg, '"#tmx-guide-tab {"'), panelRule = block(tg, '"#tmx-guide-panel {"'), gPhone = block(tg, '"@media (max-width: 760px) {"');
  check("G6. TmxGuideOpen: the tab " + G.TAB_W + " px wide, " + G.TAB_MIN_H + " px or taller, " + G.TAB_PAD + ", radius " + G.TAB_RADIUS + ", " + G.TAB_BG + ", blur " + G.TAB_BLUR + " (the desktop's look, at every width)",
    ["width: " + px(G.TAB_W) + ";", "min-height: " + px(G.TAB_MIN_H) + ";", "padding: " + G.TAB_PAD + ";", "border-radius: " + G.TAB_RADIUS + ";", "background: " + G.TAB_BG + ";", "backdrop-filter: blur(" + px(G.TAB_BLUR) + ");", "border-left: none;"].every(s => tabRule.indexOf(s) !== -1) &&
    !/tmx-guide-fab|tmx-guide-sheet/.test(tg.replace(/\/\*[\s\S]*?\*\//g, "")), J(tabRule.slice(0, 200)));   // the book button and its sheet gone from the code (named in comments only)
  check("G7. the panel open: min(" + G.PANEL_W + "px, 100vw - " + G.PANEL_EDGE + "px) wide, at most " + G.PANEL_MAX_VH + "vh, scrolling, radius " + G.PANEL_RADIUS + ", " + G.PANEL_BG + ", blur " + G.PANEL_BLUR + ", the tab at its right edge, " + G.SLIDE_S + " s",
    ["border-radius: " + G.PANEL_RADIUS + ";", "background: " + G.PANEL_BG + ";", "backdrop-filter: blur(" + px(G.PANEL_BLUR) + ");", "overflow-y: auto;", "max-height: " + G.PANEL_MAX_VH + "vh;"].every(s => panelRule.indexOf(s) !== -1) &&
    gPhone.indexOf("flex-direction: row-reverse;") !== -1 && gPhone.indexOf("transform: translate(calc(-1 * min(" + px(G.PANEL_W) + ", 100vw - " + px(G.PANEL_EDGE) + ")), -50%); transition: transform " + G.SLIDE_S + "s ease; }") !== -1 &&
    gPhone.indexOf("width: min(" + px(G.PANEL_W) + ", calc(100vw - " + px(G.PANEL_EDGE) + "));") !== -1 && gPhone.indexOf("max-height: min(" + G.PANEL_MAX_VH + "vh, calc(") !== -1 &&
    panelRule.indexOf("transition: opacity " + G.SLIDE_S + "s ease, transform " + G.SLIDE_S + "s ease;") !== -1, J(gPhone));
  check("G8. TmxChatOracle and reduced motion: every open and close is a plain " + TM.STILL_FADE_S + " s fade",
    tp.indexOf('tr: "opacity ' + TM.STILL_FADE_S + 's ease", dur: ' + (TM.STILL_FADE_S * 1000) + " };") !== -1);

  /* ── H ── NAMED (Nov 23 2026, P3-3) */
  console.log("\n══ H. P3-3: the owner's canvas row 4 (" + DS.COMPOSER.BOARD + ", " + DS.NEEDPOST.BOARD + ") ══");
  const CO = DS.COMPOSER, NP = DS.NEEDPOST;
  // the CSS arrays' strings joined, so a rule split over two strings reads as one
  const flat = t => t.replace(/",\s*\n\s*"/g, "");
  const cp = flat(FILES[COMP] || ""), cpage = FILES[COMPOSE] || "", fd = flat(feed);
  const sys = 'system-ui,-apple-system,"Segoe UI",Arial,sans-serif';
  ruleCheck("H1. " + CO.BOARD + ": the header " + CO.HEADER.HEIGHT + " px over a 1 px " + CO.HEADER.DIVIDER + " line, the page's " + CO.SIDE + " px sides", cpage, "    .compose-top",
    { height: px(CO.HEADER.HEIGHT), "border-bottom": "1px solid " + CO.HEADER.DIVIDER, padding: "0 12px", margin: "0 -" + px(CO.SIDE) + " " + px(CO.SECTION_GAP) });
  ruleCheck("H2. ...\"" + CO.HEADER.TITLE + "\" centred, " + CO.HEADER.TITLE_FONT + " px " + CO.HEADER.TITLE_WEIGHT, cpage, "    .compose-top h1",
    { flex: "1", "text-align": "center", "font-size": px(CO.HEADER.TITLE_FONT), "font-weight": String(CO.HEADER.TITLE_WEIGHT) });
  check("H3. ...Close a plain " + CO.HEADER.X_ICON + " px X in a 44 px target; Post in the header, a " + CO.HEADER.POST.H + " px pill (radius " + CO.HEADER.POST.RADIUS + ", " + CO.HEADER.POST.FONT + " px) in a " + CO.HEADER.POST.HIT + " px button",
    holds(rule(cpage, "    .compose-close"), { width: "44px", height: "44px" }) && holds(rule(cpage, "    .compose-close svg"), { width: "24px", height: "24px" }) &&
    cpage.indexOf('<span class="compose-post" id="composePost"></span>') !== -1 && cpage.indexOf('{ postSlot: document.getElementById("composePost") }') !== -1 &&
    holds(rule(cp, ".bfc-pill"), { height: px(CO.HEADER.POST.H), "border-radius": px(CO.HEADER.POST.RADIUS), font: "800 " + px(CO.HEADER.POST.FONT) + "/1 " + sys }) &&
    holds(rule(cp, ".bfc-post"), { "min-width": px(CO.HEADER.POST.HIT), "min-height": px(CO.HEADER.POST.HIT) }));
  const T0 = CO.TILES;
  check("H4. the tiles: " + T0.ITEMS.map(x => x[1] + " \"" + x[2] + "\"").join(", ") + ", in that order, " + T0.H + " px tall, " + T0.GAP + " px apart, radius " + T0.RADIUS + ", " + T0.BORDER + " px " + T0.LINE + " on " + T0.FILL + "; chosen " + T0.ON_FILL + " with a cyan edge and words",
    cp.indexOf("  var INTENTS = " + J(T0.ITEMS).replace(/","/g, '", "').replace(/\],\[/g, "], [") + ";") !== -1 &&
    holds(rule(cp, ".bfc-tiles"), { display: "grid", "grid-template-columns": "repeat(3,minmax(0,1fr))", gap: px(T0.GAP) }) &&
    holds(rule(cp, ".bfc-tile .bfc-face"), { height: px(T0.H), "border-radius": px(T0.RADIUS), border: T0.BORDER + "px solid " + T0.LINE, background: T0.FILL }) &&
    holds(rule(cp, ".bfc-tile b"), { "font-size": px(T0.TITLE_FONT), color: T0.TITLE }) && holds(rule(cp, ".bfc-tile small"), { "font-size": px(T0.SUB_FONT), color: T0.SUB }) &&
    holds(rule(cp, ".bfc-tile input:checked+.bfc-face"), { background: T0.ON_FILL, "border-color": ACC }) && holds(rule(cp, ".bfc-tile input:checked+.bfc-face b"), { color: ACC }) &&
    holds(rule(cp, ".bfc-tile input:checked+.bfc-face small"), { color: T0.ON_SUB }), J(rule(cp, ".bfc-tile .bfc-face")));
  check("H5. a free account's Offer tile carries the \"" + T0.MEMBERS_TAG + "\" tag and opens the members panel (bf-access.js [data-members-only]); offers are members only",
    cp.indexOf('t.setAttribute("data-members-only", "");') !== -1 && cp.indexOf('tag.className = "bfc-mtag"; tag.textContent = "' + T0.MEMBERS_TAG + '";') !== -1 &&
    cp.indexOf("if (window.bfAccess && window.bfAccess.showPanel) window.bfAccess.showPanel();") !== -1 && cp.indexOf("      if (membersOffer()) { rules(); return; }") !== -1);
  const L0 = CO.LABEL;
  check("H6. the labels " + L0.FONT + "/" + L0.LINE + " px, " + L0.WEIGHT + ", spaced " + L0.SPACING + " px, upper case, " + L0.COLOR + "; " + L0.GAP + " px over their control, sections " + CO.SECTION_GAP + " px apart; the box's label by intent: " + J(CO.LABELS),
    holds(rule(cp, ".bfc-lab"), { "font-size": px(L0.FONT), "line-height": px(L0.LINE), "font-weight": String(L0.WEIGHT), "letter-spacing": px(L0.SPACING), "text-transform": "uppercase", color: L0.COLOR }) &&
    holds(rule(cp, ".bfc-sec"), { gap: px(L0.GAP) }) && holds(rule(cp, ".bfc-form"), { gap: px(CO.SECTION_GAP) }) &&
    cp.indexOf("  var TEXT_LABEL = { share: " + J(CO.LABELS.share) + ", offer: " + J(CO.LABELS.offer) + ", need: " + J(CO.LABELS.need) + " };") !== -1 &&
    cp.indexOf("need: " + J(CO.NEED_HINT) + " };") !== -1 && cp.indexOf("      textL.textContent = TEXT_LABEL[it];") !== -1);
  const X0 = CO.TEXT;
  ruleCheck("H7. the box " + X0.H + " px tall, radius " + X0.RADIUS + ", " + X0.FILL + " with a " + X0.LINE + " line, " + X0.FONT + "/" + X0.LINE_H + " px, padded " + X0.PAD, cp, ".bfc-text",
    { height: px(X0.H), "border-radius": px(X0.RADIUS), background: X0.FILL, border: "1px solid " + X0.LINE, font: px(X0.FONT) + "/" + px(X0.LINE_H) + " " + sys, padding: "12px " + px(X0.PAD) });
  const C0 = CO.CHIPS;
  check("H8. the category chips: one row that swipes (no wrapping), " + C0.H + " px pills (radius " + C0.RADIUS + ", " + C0.GAP + " px apart, padded " + C0.PAD + ", " + C0.FONT + " px), chosen cyan; the note \"" + C0.NOTE + "\"; the list from GET /api/categories, never typed",
    holds(rule(cp, ".bfc-chips"), { display: "flex", gap: px(C0.GAP), "overflow-x": "auto" }) && !/flex-wrap/.test(JSON.stringify(rule(cp, ".bfc-chips"))) &&
    holds(rule(cp, ".bfc-chip .bfc-face"), { height: px(C0.H), "border-radius": px(C0.RADIUS), padding: "0 " + px(C0.PAD), "font-size": px(C0.FONT), background: C0.FILL, border: "1px solid " + C0.LINE, color: C0.TEXT }) &&
    holds(rule(cp, ".bfc-chip input:checked+.bfc-face"), { background: C0.ON_FILL, "border-color": ACC, color: ACC }) && holds(rule(cp, ".bfc-chip"), { height: "44px" }) &&
    cp.indexOf("  var CAT_NOTE = " + J(C0.NOTE) + ";") !== -1 && cp.indexOf('getJson("/api/categories")') !== -1 && !/tattoo_body_art|Hair & Beauty/.test(cp), J(rule(cp, ".bfc-chips")));
  const W0 = CO.WHERE, N0 = CO.WHEN;
  check("H9. a Need's Where (" + W0.H + " px, radius " + W0.RADIUS + ", at most " + W0.MAX + " characters, filling the row) and When (" + N0.ITEMS.join(", ") + ": " + N0.PILL_H + " px pills, radius " + N0.PILL_RADIUS + ", the chosen one cyan), inside the margins (the board's control ran off the screen)",
    holds(rule(cp, ".bfc-in"), { height: px(W0.H), "border-radius": px(W0.RADIUS), background: W0.FILL, border: "1px solid " + W0.LINE }) && cp.indexOf("  var NEED_PLACE_MAX = " + W0.MAX + ";") !== -1 &&
    holds(rule(cp, ".bfc-where"), { flex: "1", "min-width": "0" }) && holds(rule(cp, ".bfc-when"), { flex: "none" }) && holds(rule(cp, ".bfc-need"), { gap: px(N0.GAP) }) &&
    cp.indexOf('  var WHENS = [["today", "Today"], ["week", "Week"], ["any", "Any"]];') !== -1 && J(N0.ITEMS) === J(["Today", "Week", "Any"]) &&
    holds(rule(cp, ".bfc-seg"), { height: "44px", padding: "0 3px", background: N0.FILL, "box-shadow": "inset 0 0 0 1px " + N0.LINE }) && holds(rule(cp, ".bfc-opt"), { padding: "3px 0", "min-width": "44px" }) &&
    holds(rule(cp, ".bfc-opt .bfc-face"), { "border-radius": px(N0.PILL_RADIUS) }) && 44 - 2 * 3 === N0.PILL_H &&
    holds(rule(cp, ".bfc-when .bfc-opt input:checked+.bfc-face"), { background: ACC, color: "#070b18" }) && N0.FIT === true &&
    cp.indexOf('      needSec.hidden = it !== "need";') !== -1, J([rule(cp, ".bfc-where"), rule(cp, ".bfc-when")]));
  const PH = CO.PHOTOS;
  check("H10. photos: " + PH.COUNT + " slots of " + PH.SLOT + " px, " + PH.GAP + " px apart, radius " + PH.RADIUS + ", dashed " + PH.DASH + " on " + PH.FILL + "; the next free one adds",
    holds(rule(cp, ".bfc-photos"), { "grid-template-columns": "repeat(" + PH.COUNT + ",minmax(0," + px(PH.SLOT) + "))", gap: px(PH.GAP) }) &&
    holds(rule(cp, ".bfc-slot,.bfc-ph"), { "border-radius": px(PH.RADIUS), "aspect-ratio": "1/1" }) && holds(rule(cp, ".bfc-slot"), { border: "1.5px dashed " + PH.DASH, background: PH.FILL }) &&
    cp.indexOf("html.push(j === photos.length ? '<li class=\"bfc-slot\"><label class=\"bfc-add\" id=\"bfcAddLabel\" for=\"bfcFile\"") !== -1);
  const B0 = CO.BOX;
  check("H11. the Need box: \"" + B0.TEXT + "\" (" + B0.H + " px, radius " + B0.RADIUS + ", " + B0.FILL + ", a " + B0.ICON + " px cyan target), only on a public Need (lib/needAlerts.js tells members only of those)",
    cp.indexOf("  var NEED_BOX = " + J(B0.TEXT) + ";") !== -1 && cp.indexOf('      needBox.hidden = !(it === "need" && audienceNow() === "public");') !== -1 &&
    holds(rule(cp, ".bfc-info"), { "min-height": px(B0.H), "border-radius": px(B0.RADIUS), background: B0.FILL, border: "1px solid " + B0.LINE, "font-size": px(B0.FONT), gap: "14px", padding: "12px 16px 12px 15px" }) &&
    cp.indexOf('<svg viewBox="0 0 24 24" width="' + B0.ICON + '" height="' + B0.ICON + '"') !== -1 && 16 + 15 + B0.ICON + 14 === B0.TEXT_LEFT - 1 + 1);
  const A0 = CO.AUDIENCE;
  check("H12. Public / Followers: a " + A0.H + " px segment, the chosen " + A0.PILL_H + " px pill " + A0.ON_FILL,
    holds(rule(cp, ".bfc-aud .bfc-opt input:checked+.bfc-face"), { background: A0.ON_FILL }) && holds(rule(cp, ".bfc-aud .bfc-opt"), { flex: "1" }) &&
    cp.indexOf('radios("bfcAud", [["public", "Public"], ["followers", "Followers"]], "bfc-opt", "public")') !== -1);
  const G0 = NP.TAG, M0 = NP.META, S0 = NP.STRIP;
  check("H13. " + NP.BOARD + ": the " + G0.WORD + " tag " + G0.H + " px (radius " + G0.RADIUS + ", " + G0.FONT + " px, " + G0.FILL + " with " + G0.TEXT + "), \"" + G0.FOUND + "\" once Found",
    holds(rule(fd, ".bfp-tag"), { height: px(G0.H), "border-radius": px(G0.RADIUS), background: ACC, color: G0.TEXT, font: "800 " + px(G0.FONT) + "/1 " + sys }) &&
    fd.indexOf('(isFound(p) ? "' + G0.FOUND + '" : "' + G0.WORD + '")') !== -1 && G0.FILL === C.ACCENT);
  check("H14. ...then \"Category · Place · When\" " + M0.GAP + " px after it, " + M0.FONT + "/" + M0.LINE + " px " + M0.COLOR + " (When: " + J(M0.WHEN) + ", Any left out); a Share post's category a small " + NP.SHARE_CATEGORY_FONT + " px line",
    holds(rule(fd, ".bfp-kind"), { gap: px(M0.GAP), "align-items": "center" }) && holds(rule(fd, ".bfp-kmeta"), { font: "400 " + px(M0.FONT) + "/" + px(M0.LINE) + " " + sys, color: M0.COLOR }) &&
    fd.indexOf("  var WHEN_WORDS = { today: " + J(M0.WHEN.today) + ", week: " + J(M0.WHEN.week) + " };") !== -1 &&fd.indexOf('esc(parts.join(" \\u00b7 "))') !== -1 &&
    holds(rule(fd, ".bfp-kind.is-share .bfp-kmeta"), { "font-size": px(NP.SHARE_CATEGORY_FONT) }) && fd.indexOf("kindHtml(p) + head") !== -1);
  check("H15. the strip: \"" + S0.TITLE + "\" / \"" + S0.SUB + "\" / \"" + S0.BUTTON + "\" (radius " + S0.RADIUS + ", " + S0.LINE + ", padded " + S0.PAD + "; a " + S0.ICON + " px " + S0.ICON_FILL + " tile; " + S0.TITLE_FONT + " and " + S0.SUB_FONT + " px; a " + S0.BUTTON_H + " px pill, radius " + S0.BUTTON_RADIUS + "); the whole strip the tap target",
    fd.indexOf("  var HELP = { title: " + J(S0.TITLE) + ", sub: " + J(S0.SUB) + ", go: " + J(S0.BUTTON) + " };") !== -1 &&
    holds(rule(fd, ".bfp-help"), { "border-radius": px(S0.RADIUS), border: "1px solid " + S0.LINE, padding: px(S0.PAD), "min-height": "44px" }) &&
    holds(rule(fd, ".bfp-help-i"), { width: px(S0.ICON), height: px(S0.ICON), background: S0.ICON_FILL }) &&
    holds(rule(fd, ".bfp-help-t"), { font: "700 " + px(S0.TITLE_FONT) + "/1.3 " + sys }) && holds(rule(fd, ".bfp-help-s"), { font: "400 " + px(S0.SUB_FONT) + "/1.3 " + sys }) &&
    holds(rule(fd, ".bfp-help-go"), { height: px(S0.BUTTON_H), "border-radius": px(S0.BUTTON_RADIUS), font: "700 " + px(S0.BUTTON_FONT) + "/1 " + sys, background: ACC }) &&
    fd.indexOf("'<button type=\"button\" class=\"bfp-help\"") !== -1 && fd.indexOf('width="' + S0.TARGET + '" height="' + S0.TARGET + '"') !== -1);
  check("H16. the strip only for a signed-in member who offers in the category (the server's can_help), never for the poster, never on a Found Need",
    fd.indexOf('    if (!p || p.intent !== "need" || p.can_help !== true || p.mine || isFound(p)) return "";') !== -1 &&
    (FILES[POSTS] || "").indexOf("can_help") !== -1);
  const K0 = NP.BACKDROP;
  check("H17. a Need without a photo: the board's backdrop, a " + K0.GLOW + " glow at " + K0.GLOW_AT + " over " + K0.TOP + " to " + K0.BOTTOM + ", its text in the caption",
    fd.indexOf("radial-gradient(circle at " + K0.GLOW_AT + "," + K0.GLOW + " 0,rgba(18,58,74,0) 52%),linear-gradient(180deg," + K0.TOP + " 0%,#080d22 50%," + K0.BOTTOM + " 100%)") !== -1 &&
    fd.indexOf("(textPost && !needText ? \"\" : (p.body ?") !== -1);

  /* ── I ── NAMED (Nov 23 2026, LR-2) */
  console.log("\n══ I. LR-2: the owner's canvas row 6 (" + DS.LEADS.BOARDS.join(", ") + ") ══");
  const LD = DS.LEADS, lr = FILES[LRP] || "", F0 = LD.FONT;
  const r = sel => rule(lr, "    " + sel + " ");
  const rc = (name, sel, want) => check(name, holds(r(sel), want), J({ sel, want, got: r(sel) }));
  const has = t => lr.indexOf(t) !== -1;
  const lift = (hit, face) => "-" + px((hit - face) / 2) + " 0";
  const HD = LD.HEADER, TB = LD.TABS, CD = LD.CARD, ST = LD.STATS, CH = LD.CHIP, BG = LD.BADGE, LE = LD.LEAD, BT = LD.BUTTON, SH = LD.SHEET, SWC = LD.SWITCH, FP = LD.FINGERPRINT, LB = LD.LABEL;
  check("I1. LeadsHome's header: " + HD.PAD + ", " + HD.GAP + " px apart; Back and \"" + HD.SETTINGS + "\" " + HD.BUTTON + " px; the " + HD.MARK + " px mark (radius " + HD.MARK_RADIUS + ", " + HD.MARK_BG + "); \"" + HD.TITLE + "\" " + HD.TITLE_WEIGHT + " " + HD.TITLE_FONT + " px in the site's font (never Space Grotesk or Inter); the music icon kept",
    holds(r(".lr-head"), { display: "flex", "align-items": "center", gap: px(HD.GAP), padding: HD.PAD }) && holds(r(".lr-hbtn"), { width: px(HD.BUTTON), height: px(HD.BUTTON) }) &&
    holds(r(".lr-mark"), { width: px(HD.MARK), height: px(HD.MARK), "border-radius": px(HD.MARK_RADIUS), background: HD.MARK_BG, color: ACC }) &&
    holds(r(".lr-title"), { flex: "1", font: HD.TITLE_WEIGHT + " " + px(HD.TITLE_FONT) + " " + F0 }) && has('<h1 class="lr-title">' + HD.TITLE + "</h1>") &&
    has('aria-label="Back"') && has('aria-label="' + HD.SETTINGS + '"') && has("<span class=\"brand-badge\" data-bf-boombox-anchor>BizForce AI</span>") &&
    !/Space Grotesk|\bInter\b/.test(lr), J([r(".lr-head"), r(".lr-title")]));
  const tabs = [...lr.matchAll(/role="tab"[^>]*><span class="lr-tbf">([^<]+)<\/span>/g)].map(m => m[1]);
  check("I2. the tabs: " + TB.ITEMS.join(" and ") + " only (" + TB.NOT_DRAWN.join(" and ") + " not drawn); a " + TB.H + " px face (padded " + TB.PAD_X + ", radius " + TB.RADIUS + ", " + TB.WEIGHT + " " + TB.FONT + " px, " + TB.COLOR + "; chosen " + TB.ON_BG + " and cyan) in a " + LD.HIT + " px target; the row " + TB.PAD + ", " + TB.GAP + " px apart",
    J(tabs) === J(TB.ITEMS) && !TB.NOT_DRAWN.some(t => has(">" + t + "<")) && holds(r(".lr-tabs"), { display: "flex", gap: px(TB.GAP), padding: TB.PAD }) &&
    holds(r(".lr-tb"), { height: px(LD.HIT), "min-width": px(LD.HIT), margin: lift(LD.HIT, TB.H) }) &&
    holds(r(".lr-tbf"), { height: px(TB.H), padding: "0 " + px(TB.PAD_X), "border-radius": px(TB.RADIUS), color: TB.COLOR, font: TB.WEIGHT + " " + px(TB.FONT) + " " + F0 }) &&
    holds(r('.lr-tb[aria-selected="true"] .lr-tbf'), { background: TB.ON_BG, color: ACC }), J([tabs, r(".lr-tb"), r(".lr-tbf")]));
  check("I3. the cards (padded " + CD.PAD + ", radius " + CD.RADIUS + ", " + CD.BORDER + " on " + CD.BG + ", " + CD.GAP + " px inside), " + LD.CONTENT.GAP + " px apart, " + LD.CONTENT.PAD_X + " px sides; the three stats (" + ST.LABELS.join(", ") + "): " + ST.NUM_WEIGHT + " " + ST.NUM_FONT + " px figures, won in " + ST.WON,
    holds(r(".lr-main"), { display: "flex", "flex-direction": "column", gap: px(LD.CONTENT.GAP), padding: "0 " + px(LD.CONTENT.PAD_X) }) &&
    holds(r(".lr-card"), { display: "flex", "flex-direction": "column", gap: px(CD.GAP), padding: px(CD.PAD), "border-radius": px(CD.RADIUS), border: "1px solid " + CD.BORDER, background: CD.BG }) &&
    holds(r(".lr-stats"), { display: "flex", gap: px(ST.GAP) }) && holds(r(".lr-stat"), { flex: "1", "align-items": "center", gap: "2px", padding: px(ST.PAD) }) &&
    holds(r(".lr-num"), { font: ST.NUM_WEIGHT + " " + px(ST.NUM_FONT) + " " + F0 }) && holds(r(".lr-num.is-won"), { color: ST.WON }) &&
    holds(r(".lr-slbl"), { "font-size": px(ST.LABEL_FONT), color: "#a9b3cc" }) && ST.LABELS.every(t => has('<span class="lr-slbl">' + t + "</span>")), J([r(".lr-card"), r(".lr-num.is-won")]));
  check("I4. the source chips " + CH.SOURCES.join(", ") + " (Threads too once it is on): " + CH.H + " px faces (padded " + CH.PAD_X + ", radius " + CH.RADIUS + ", " + CH.BORDER + " on " + CH.BG + ", " + CH.WEIGHT + " " + CH.FONT + " px), chosen cyan on " + CH.ON_BG + ", in " + LD.HIT + " px targets " + CH.GAP + " px apart; the row swipes",
    has('  var SOURCES = [["all", "' + CH.SOURCES[0] + '"], ["bizforce", "' + CH.SOURCES[1] + '"], ["bluesky", "' + CH.SOURCES[2] + '"], ["youtube", "' + CH.SOURCES[3] + '"], ["threads", "Threads"]];') &&
    holds(r(".lr-chipf"), { height: px(CH.H), padding: "0 " + px(CH.PAD_X), "border-radius": px(CH.RADIUS), border: "1px solid " + CH.BORDER, background: CH.BG, color: CH.COLOR, font: CH.WEIGHT + " " + px(CH.FONT) + " " + F0 }) &&
    holds(r('.lr-chip[aria-pressed="true"] .lr-chipf'), { "border-color": ACC, background: CH.ON_BG, color: ACC }) &&
    holds(r(".lr-chip"), { height: px(LD.HIT), "min-width": px(LD.HIT), margin: lift(LD.HIT, CH.H) }) &&
    holds(r(".lr-chips"), { display: "flex", gap: px(CH.GAP), "overflow-x": "auto", margin: lift(LD.HIT, CH.H), padding: px((LD.HIT - CH.H) / 2) + " 0" }) &&
    holds(r(".lr-wrap"), { "flex-wrap": "wrap", gap: px(CH.GAP) }), J([r(".lr-chipf"), r(".lr-chip")]));
  check("I5. the badges " + BG.H + " px (padded " + BG.PAD_X + ", radius " + BG.RADIUS + ", " + BG.WEIGHT + " " + BG.FONT + " px, spaced " + BG.SPACING + " px): \"" + BG.NEED.TEXT + "\" cyan, \"" + BG.BSKY.TEXT + "\" " + BG.BSKY.COLOR + " on " + BG.BSKY.BG + ", \"" + BG.YT.TEXT + "\" " + BG.YT.COLOR + " on " + BG.YT.BG + " (its card at " + BG.YT.CARD_OPACITY + ")",
    holds(r(".lr-badge"), { height: px(BG.H), padding: "0 " + px(BG.PAD_X), "border-radius": px(BG.RADIUS), font: BG.WEIGHT + " " + px(BG.FONT) + " " + F0, "letter-spacing": px(BG.SPACING) }) &&
    holds(r(".lr-b-need"), { background: ACC, color: BG.NEED.COLOR }) && BG.NEED.BG === C.ACCENT && holds(r(".lr-b-bsky"), { background: BG.BSKY.BG, color: BG.BSKY.COLOR }) &&
    holds(r(".lr-b-yt"), { background: BG.YT.BG, color: BG.YT.COLOR }) && holds(r(".lr-card.is-yt"), { opacity: String(BG.YT.CARD_OPACITY).replace(/^0/, "") }) &&
    has('<span class="lr-badge lr-b-need">' + BG.NEED.TEXT + "</span>") && has('(l.reply_invited ? "' + BG.BSKY.TEXT +'" : "BLUESKY")') &&
    has('<span class="lr-badge lr-b-yt">' + BG.YT.TEXT + "</span>"), J([r(".lr-badge"), r(".lr-b-bsky"), r(".lr-card.is-yt")]));
  check("I6. a lead: meta " + LE.META_FONT + " px, text " + LE.TEXT_FONT + "/" + LE.TEXT_LINE + ", the match line " + LE.MATCH_FONT + " px " + LE.MATCH + "; buttons " + BT.H + " px faces (padded " + BT.PAD_X + ", radius " + BT.RADIUS + ", " + BT.WEIGHT + " " + BT.FONT + " px; the first cyan) in " + LD.HIT + " px targets, " + BT.GAP + " px apart: " + BT.NEED.join(", ") + " / " + BT.BSKY.join(", "),
    holds(r(".lr-meta"), { "font-size": px(LE.META_FONT) }) && holds(r(".lr-text"), { "font-size": px(LE.TEXT_FONT), "line-height": String(LE.TEXT_LINE) }) &&
    holds(r(".lr-match"), { "font-size": px(LE.MATCH_FONT), color: LE.MATCH }) &&
    holds(r(".lr-btnf"), { height: px(BT.H), padding: "0 " + px(BT.PAD_X), "border-radius": px(BT.RADIUS), border: "1px solid " + BT.BORDER, color: BT.COLOR, font: BT.WEIGHT + " " + px(BT.FONT) + " " + F0 }) &&
    holds(r(".lr-btn.is-p .lr-btnf"), { border: "0", background: ACC, color: BT.PRIMARY_TEXT }) && holds(r(".lr-btn"), { height: px(LD.HIT), "min-width": px(LD.HIT), margin: lift(LD.HIT, BT.H) }) &&
    holds(r(".lr-acts"), { gap: px(BT.GAP) }) && has('link("' + BT.NEED[0] + '", "/home.html?post=" + encodeURIComponent(l.need_post_id), true)') &&
    has('btn(saved ? "Saved" : "' + BT.NEED[1] + '"') && has('btn("' + BT.NEED[2] + '", ') && has('btn("' + BT.BSKY[0] + '", ') && has('link("' + BT.BSKY[1] + '", l.url'), J([r(".lr-btnf"), r(".lr-btn")]));
  rc("I7. the line under the leads: \"" + LD.FOOT.TEXT + "\" " + LD.FOOT.FONT + " px " + LD.FOOT.COLOR + ", centred", ".lr-foot",
    { "font-size": px(LD.FOOT.FONT), color: LD.FOOT.COLOR, "line-height": String(LD.FOOT.LINE), "text-align": "center", padding: "0 " + px(LD.FOOT.PAD_X) });
  check("I7b. ...its words", has('<p class="lr-foot">' + LD.FOOT.TEXT + "</p>"));
  const sh = r(".lr-sheet") || {}, vz = parseInt((r(".lr-veil") || {})["z-index"], 10), sz = parseInt(sh["z-index"], 10);
  check("I8. LeadsReply: the sheet " + SH.H + " px from the bottom (radius " + SH.RADIUS + " at its top, " + SH.BG + ", a " + SH.TOP_LINE + " top line, " + SH.PAD + ", " + SH.GAP + " px apart) over a " + SH.VEIL + " veil, both under the site's bar (z-index " + SH.UNDER_BAR + "); the " + SH.GRAB.W + " x " + SH.GRAB.H + " grabber; \"" + SH.TITLE + "\" " + SH.TITLE_FONT + " px; Close " + SH.CLOSE + " px",
    holds(sh, { position: "fixed", bottom: "0", height: px(SH.H), "border-radius": px(SH.RADIUS) + " " + px(SH.RADIUS) + " 0 0", background: SH.BG, "border-top": "1px solid " + SH.TOP_LINE, padding: SH.PAD, gap: px(SH.GAP) }) &&
    holds(r(".lr-veil"), { position: "fixed", background: SH.VEIL }) && vz < sz && sz < SH.UNDER_BAR &&
    holds(r(".lr-grab"), { width: px(SH.GRAB.W), height: px(SH.GRAB.H), "border-radius": px(SH.GRAB.RADIUS), background: SH.GRAB.COLOR }) &&
    holds(r(".lr-sh-title"), { font: "700 " + px(SH.TITLE_FONT) + " " + F0 }) && has('id="lrSheetTitle">' + SH.TITLE + "</h2>") && has('"Your reply on " + (PLATFORM[l.reply_platform || l.source] || "Bluesky")') &&
    has('class="lr-hbtn lr-close" id="lrSheetClose" aria-label="Close"'), J([sh, vz, sz]));
  check("I9. the quote (a " + SH.QUOTE.LINE + " px " + SH.QUOTE.COLOR + " edge, " + SH.QUOTE.PAD + ", " + SH.QUOTE.FONT + " px), \"" + SH.DRAFT_LABEL + "\", the draft box (at least " + SH.DRAFT.MIN_H + " px, padded " + SH.DRAFT.PAD + ", radius " + SH.DRAFT.RADIUS + ", a cyan line on " + SH.DRAFT.BG + ", " + SH.DRAFT.FONT + "/" + SH.DRAFT.LINE_H + "), the member's to edit",
    // NAMED (Nov 23 2026, LR-2 pages fallout): BEFORE the edge was the literal #8b5cf6. AFTER the theme's violet token
    // (checkThemeSpectrums: no original-palette colour outside a token), #8b5cf6 when no theme is set.
    SH.QUOTE.COLOR === C.VIOLET && holds(r(".lr-quote"), { "border-left": SH.QUOTE.LINE + "px solid " + VIO, padding: SH.QUOTE.PAD, "font-size": px(SH.QUOTE.FONT), "line-height": String(SH.QUOTE.LINE_H), color: SH.QUOTE.TEXT }) &&
    has('<label class="lr-lbl" for="lrDraft">Draft (edit anything)</label>') && "Draft (edit anything)".toUpperCase() === SH.DRAFT_LABEL &&
    holds(r(".lr-draft"), { "min-height": px(SH.DRAFT.MIN_H), padding: px(SH.DRAFT.PAD), "border-radius": px(SH.DRAFT.RADIUS), border: "1px solid " + ACC, background: SH.DRAFT.BG, font: px(SH.DRAFT.FONT) + "/" + SH.DRAFT.LINE_H + " " + F0 }) &&
    has('<textarea class="lr-draft" id="lrDraft"'), J([r(".lr-quote"), r(".lr-draft")]));
  check("I10. the three checks (" + SH.CHECKS.join("; ") + ") with a " + SH.TICK + " tick, " + SH.CHECK_GAP + " px apart, " + SH.CHECK_FONT + " px; \"" + SH.LINK + "\" (off); \"" + SH.AGAIN + "\" and \"" + SH.POST + "\" (" + SH.BIG_H + " px, radius " + SH.BIG_RADIUS + ", " + SH.POST_FLEX + " to 1); its line",
    // NAMED (Nov 23 2026, LR-2 pages fallout): BEFORE [[c.answers, ...], ...]. AFTER each row also carries its key
    // (data-check, so "No hard sell" is re-tested as the member edits) and is hidden when not met.
    has('[["answers", c.answers, ' + J(SH.CHECKS[0]) + '], ["no_hard_sell", c.no_hard_sell, ' + J(SH.CHECKS[1]) + '], ["invited", c.invited, ' + J(SH.CHECKS[2]) + "]]") &&
    has("(x[1] === true ? \"\" : \" hidden\")") && has('<span class="lr-ok" aria-hidden="true">&#10003;</span>') &&
    holds(r(".lr-checks"), { gap: px(SH.CHECK_GAP), "font-size": px(SH.CHECK_FONT) }) && holds(r(".lr-ok"), { color: SH.TICK }) &&
    holds(r(".lr-linkrow"), { padding: SH.LINK_PAD, "font-size": px(SH.LINK_FONT) }) && has('<span id="lrLinkLabel">' + SH.LINK + "</span>") && has("S.sheetLead = l; S.sheetLink = false;") &&
    holds(r(".lr-big"), { flex: "1", height: px(SH.BIG_H), "border-radius": px(SH.BIG_RADIUS) }) && holds(r(".lr-big.is-p"), { flex: String(SH.POST_FLEX), background: ACC }) &&
    has('id="lrAgain">' + SH.AGAIN + "</button>") && has('id="lrPost">' + SH.POST + "</button>") &&
    has('"Posted from your own connected " + (PLATFORM[d.platform] || "Bluesky") + " account"') && has("'. One reply per post, up to 5 a day.</p>'") &&
    SH.FOOT === "Posted from your own connected Bluesky account. One reply per post, up to 5 a day.", J([r(".lr-big"), r(".lr-checks")]));
  check("I11. the switches: " + SWC.W + " x " + SWC.H + " (radius " + SWC.RADIUS + "), on cyan with a " + SWC.KNOB + " px " + SWC.KNOB_ON + " knob " + SWC.INSET + " px in at the right, off " + SWC.OFF + " with a " + SWC.KNOB_OFF + " knob at the left, in " + LD.HIT + " px targets",
    holds(r(".lr-swf"), { width: px(SWC.W), height: px(SWC.H), "border-radius": px(SWC.RADIUS), background: ACC }) &&
    holds(r(".lr-swf::after"), { right: px(SWC.INSET), top: px(SWC.INSET), width: px(SWC.KNOB), height: px(SWC.KNOB), background: SWC.KNOB_ON }) &&
    holds(r('.lr-sw[aria-checked="false"] .lr-swf'), { background: SWC.OFF }) && holds(r('.lr-sw[aria-checked="false"] .lr-swf::after'), { left: px(SWC.INSET), background: SWC.KNOB_OFF }) &&
    holds(r(".lr-sw"), { width: px(LD.HIT), height: px(LD.HIT), margin: lift(LD.HIT, SWC.H) }) && SWC.ON === C.ACCENT, J([r(".lr-swf"), r(".lr-swf::after")]));
  /* NAMED (Nov 24 2026, LR-3): LeadsInbound, measured from its board (designSpec LEADS.INBOUND) */
  const IB = LD.INBOUND, PI = IB.PIPE, IT = IB.ITEM;
  check("I18. LeadsInbound: the pipeline card (padded " + PI.PAD + ", " + PI.GAP + " px apart), \"" + PI.LABEL + "\", a " + PI.BAR_H + " px bar (radius " + PI.BAR_RADIUS + ") of New cyan, Talking violet, Won " + PI.WON + ", and its counts " + PI.COUNTS_FONT + " px (" + PI.COUNT_TALKING + " for Talking)",
    holds(r(".lr-pipe"), { padding: PI.PAD, gap: px(PI.GAP) }) && has('<p class="lr-lbl lr-plbl">Your pipeline</p>') && "Your pipeline".toUpperCase() === PI.LABEL &&
    holds(r(".lr-bar"), { display: "flex", height: px(PI.BAR_H), "border-radius": px(PI.BAR_RADIUS) }) &&
    PI.NEW === C.ACCENT && PI.TALKING === C.VIOLET && holds(r(".lr-bar-new"), { background: ACC }) && holds(r(".lr-bar-talking"), { background: VIO }) && holds(r(".lr-bar-won"), { background: PI.WON }) &&
    holds(r(".lr-pcounts"), { display: "flex", "justify-content": "space-between", "font-size": px(PI.COUNTS_FONT) }) &&
    holds(r(".lr-pc-new"), { color: ACC }) && holds(r(".lr-pc-talking"), { color: PI.COUNT_TALKING }) && holds(r(".lr-pc-won"), { color: PI.COUNT_WON }) &&
    has('bar[0].style.flex = String(n); bar[1].style.flex = String(t); bar[2].style.flex = String(w);') &&
    has('$("lrPcNew").textContent = "New " + n; $("lrPcTalking").textContent = "Talking " + t; $("lrPcWon").textContent = "Won " + w;'), J([r(".lr-pipe"), r(".lr-bar"), r(".lr-pc-talking")]));
  check("I19. ...the chips " + IB.CHIPS.join(", ") + " (the Leads chips' faces); an item: a row " + IT.GAP + " px apart, the " + IT.ICON + " px icon (radius " + IT.ICON_RADIUS + ", " + IT.SVG + " px drawing), the kind " + IT.KIND_WEIGHT + " " + IT.KIND_FONT + " px, the summary " + IT.SUM_FONT + "/" + IT.SUM_LINE + " " + IT.SUM_COLOR + ", the NEW and WON pills",
    has('var STAGES = [["new", "' + IB.CHIPS[0] + '"], ["talking", "' + IB.CHIPS[1] + '"], ["won", "' + IB.CHIPS[2] + '"], ["lost", "' + IB.CHIPS[3] + '"]];') &&
    has("return chip(x[0], x[1], x[0] === IN.status);") &&
    holds(r(".lr-item"), { "flex-direction": "row", "align-items": "flex-start", gap: px(IT.GAP) }) &&
    holds(r(".lr-ico"), { width: px(IT.ICON), height: px(IT.ICON), "border-radius": px(IT.ICON_RADIUS) }) && has('<svg width="' + IT.SVG + '" height="' + IT.SVG + '" viewBox="0 0 24 24"') &&
    holds(r(".lr-ix"), { gap: px(IT.MID_GAP) }) && holds(r(".lr-ik"), { font: IT.KIND_WEIGHT + " " + px(IT.KIND_FONT) + " " + F0 }) &&
    holds(r(".lr-is"), { "font-size": px(IT.SUM_FONT), "line-height": String(IT.SUM_LINE), color: IT.SUM_COLOR }) &&
    IB.PILLS.NEW.BG === C.ACCENT && holds(r(".lr-s-new"), { background: ACC, color: IB.PILLS.NEW.COLOR }) && holds(r(".lr-s-won"), { background: IB.PILLS.WON.BG, color: IB.PILLS.WON.COLOR }) &&
    has("lr-badge lr-s-' + esc(it.status) + '"), J([r(".lr-item"), r(".lr-ico"), r(".lr-is")]));
  const icoRule = k => { const hit = lr.match(new RegExp("\\n    ([^{\\n]*\\.lr-ico-" + k + "\\b[^{\\n]*) \\{([^}]*)\\}")); return hit ? rule("\n" + hit[1] + " {" + hit[2] + "}", hit[1] + " ") : null; };
  check("I20. ...each drawn kind's icon: " + Object.keys(IB.ICONS).join(", ") + " (its colours and its drawing); " + IB.NOT_DRAWN.join(" and ") + " (not drawn) have one too",
    Object.keys(IB.ICONS).every(k => { const I = IB.ICONS[k], d = icoRule(k) || {};
      const line = lr.split("\n").find(l => l.indexOf("      " + k + ": '") === 0) || "";
      return d.background === I.BG && (d.color === I.COLOR || (I.COLOR === C.ACCENT && d.color === ACC)) && line.indexOf('d="' + I.PATH + '"') !== -1; }) &&
    IB.NOT_DRAWN.every(k => !!icoRule(k) && has("      " + k + ": '")), J(Object.keys(IB.ICONS).map(k => [k, icoRule(k)])));
  const lbls = [...lr.matchAll(/<p class="lr-lbl">([^<]+)<\/p>/g)].map(m => m[1].toUpperCase());
  check("I12. LeadsFingerprint: " + px(FP.PAD_X) + " sides, " + FP.GAP + " px apart; the intro (" + FP.INTRO_FONT + "/" + FP.INTRO_LINE + " " + FP.INTRO_COLOR + "); the labels " + FP.LABELS.join(", ") + " (" + LB.WEIGHT + " " + LB.FONT + " px, spaced " + LB.SPACING + ", " + LB.COLOR + "); " + FP.REACH.join(", ") + "; \"" + FP.ADD + "\"; Where to look's rows (" + FP.LOOK.PAD + ", " + FP.LOOK.TITLE_WEIGHT + " " + FP.LOOK.TITLE_FONT + " px over " + FP.LOOK.SUB_FONT + " px) and Threads' \"" + FP.LOOK.THREADS_WAITING + "\"",
    holds(r(".lr-fp"), { gap: px(FP.GAP), padding: "0 " + px(FP.PAD_X) }) && holds(r(".lr-intro"), { "font-size": px(FP.INTRO_FONT), "line-height": String(FP.INTRO_LINE), color: FP.INTRO_COLOR }) &&
    has('<p class="lr-intro">' + FP.INTRO + "</p>") && J(lbls) === J(FP.LABELS) &&
    holds(r(".lr-lbl"), { font: LB.WEIGHT + " " + px(LB.FONT) + " " + F0, "letter-spacing": px(LB.SPACING), color: LB.COLOR, "text-transform": "uppercase" }) &&
    has('  var REACH = [["city", "' + FP.REACH[0] + '"], ["25mi", "' + FP.REACH[1] + '"], ["online", "' + FP.REACH[2] + '"]];') && has('chip("", "' + FP.ADD + '", false') &&
    holds(r(".lr-look"), { padding: FP.LOOK.PAD }) && holds(r(".lr-look-t"), { font: FP.LOOK.TITLE_WEIGHT + " " + px(FP.LOOK.TITLE_FONT) + " " + F0 }) && holds(r(".lr-look-s"), { "font-size": px(FP.LOOK.SUB_FONT), color: "#a9b3cc" }) &&
    FP.LOOK.ROWS.every((x, i) => has('lookRow("' + ["bizforce", "bluesky", "youtube"][i] + '", "' + x[0] + '", "' + x[1] + '"')) &&
    has('threads = lookRow("threads", "Threads", ' + J(FP.LOOK.THREADS_WAITING) + ");"), J([lbls, r(".lr-fp"), r(".lr-lbl")]));
  const bfa = FILES[BFA] || "", dash = FILES[DASHB] || "";
  // NAMED (Nov 23 2026, LR-2 pages fallout): BEFORE the dashboard asked GET /api/leads/summary for a member only (its own
  // inline script). AFTER that script is gone: the Lead Radar box's figure is the orbit's counts.leads, which the server
  // now fills with the member's own new leads, so the dashboard makes no lead call of its own.
  check("I13. members only: signed out, the sign-in prompt and no request; a free account, the members panel (bf-access.js MEMBER_PAGES lists the page) and no request; the dashboard's figure is the orbit's own new leads, with no lead call of its own",
    has('      if (!tok()) { showState("signed_out"); return; }') && has('        if (a.tier === "free") { showState("members_only"); return; }') && has("Sign in to see Lead Radar.") &&
    has('data-members-only id="lrJoin"') && bfa.indexOf('    "agents/lead-radar.html"\n  ];') !== -1 &&
    dash.indexOf("/api/leads") === -1 && (FILES[ORB] || "").indexOf('case "lead-radar": return count("leads", "new lead", "new leads");') !== -1);
  check("I14. the reply sent is the box's own text, as the member left it, and only from \"" + SH.POST + "\"; with no account the sheet says \"" + SH.CONNECT + "\" with Connect",
    has("var text = box.value.trim();") && has('call("POST", "/api/leads/" + encodeURIComponent(l.id) + "/send", { text: text, add_link: S.sheetLink })') &&
    lr.split('/send"').length === 2 && has('if (e.target.closest("#lrPost")) { send(); return; }') &&
    has('"Connect your " + name + " account to reply"') && SH.CONNECT === "Connect your Bluesky account to reply");
  check("I15. the logo's words show on a desktop only (on a phone the music icon docks at the bottom, as on every page)",
    /@media \(max-width: 760px\) \{\n\s+\.brand-badge \{ display: none; \}/.test(lr));
  // NAMED (Nov 23 2026, LR-2): bf-theme.js paints html::before and body::before fixed at z-index var(--bf-backdrop-z) (0); an
  // unpositioned page is painted under them. The page wrapper is positioned at z 1, as every themed page's content is.
  check("I16. the page is drawn over the theme's backdrop: .lr-page is position relative, z-index 1",
    /^ {4}\.lr-page \{ position: relative; z-index: 1;/m.test(lr));
  // NAMED (Nov 23 2026, LR-2): PHONE_LR2 found it (a chip's read landing after Save showed the lead unsaved again)
  check("I17. a list read that lands after a newer read or a Save is dropped, and a Save that dropped one reads the list again",
    has("mine = ++seq;") && has("        if (mine !== seq) return;\n") && has("var dropped = reading; seq++; reading = false;") && has("if (dropped) { loadLeads(); return; }"));

  /* ── J ── NAMED (Nov 25 2026, LR-4): LeadsFound, "Get found: your Found score" */
  console.log("\n══ J. LR-4: LeadsFound (Get found: your Found score) ══");
  const FD = LD.FOUND, RG = FD.RING, RW = FD.ROW, TP = FD.TOP;
  const FSL = FILES["@lib/foundScore.js"] || "";
  check("J1. the four tabs " + TB.ITEMS.join(", ") + " in that order, Get found opening its own panel; the row swipes (overflow-x auto) so no tab is cut at 360 px",
    J(tabs) === J(["Leads", "Inbound", "Get found", "Fingerprint"]) && TB.SWIPE === true && holds(r(".lr-tabs"), { "overflow-x": "auto" }) &&
    has('id="lrTabGf"') && has('aria-labelledby="lrTabGf" hidden>') && has('["found", "lrTabGf", "lrGf"]'), J([tabs, r(".lr-tabs")]));
  check("J2. the top: " + px(FD.PANEL.PAD_X) + " sides, " + FD.PANEL.GAP + " px apart; the ring and words " + TP.GAP + " px apart (" + TP.PAD + "); \"" + TP.TITLE + "\" " + TP.TITLE_WEIGHT + " " + TP.TITLE_FONT + " px; the line " + TP.TEXT_FONT + "/" + TP.TEXT_LINE + " " + TP.TEXT_COLOR,
    holds(r(".lr-gf"), { gap: px(FD.PANEL.GAP), padding: "0 " + px(FD.PANEL.PAD_X) }) &&
    holds(r(".lr-gf-top"), { display: "flex", "align-items": "center", gap: px(TP.GAP), padding: TP.PAD }) &&
    holds(r(".lr-gf-t"), { font: TP.TITLE_WEIGHT + " " + px(TP.TITLE_FONT) + " " + F0 }) && has('<p class="lr-gf-t">' + TP.TITLE + "</p>") &&
    holds(r(".lr-gf-s"), { "font-size": px(TP.TEXT_FONT), "line-height": String(TP.TEXT_LINE), color: TP.TEXT_COLOR }) && has('<p class="lr-gf-s">' + TP.TEXT + "</p>"), J([r(".lr-gf"), r(".lr-gf-top"), r(".lr-gf-s")]));
  check("J3. the ring: " + RG.SIZE + " px, radius " + RG.R + ", " + RG.STROKE + " px, track " + RG.TRACK + ", gold arc " + RG.ARC + " (round, from the top), the figure " + RG.NUM_WEIGHT + " " + RG.NUM_FONT + " px " + RG.NUM_COLOR + "; the arc is round(2 pi " + RG.R + " x score / 100) of " + RG.DASH_TOTAL + " (" + RG.SAMPLE[0] + " draws " + RG.SAMPLE[1] + ", as the board)",
    has('<svg class="lr-ring" id="lrRing" width="' + RG.SIZE + '" height="' + RG.SIZE + '" viewBox="0 0 ' + RG.SIZE + " " + RG.SIZE + '"') &&
    has('<circle cx="48" cy="48" r="' + RG.R + '" fill="none" stroke="' + RG.TRACK + '" stroke-width="' + RG.STROKE + '"></circle>') &&
    has('<circle id="lrRingArc" cx="48" cy="48" r="' + RG.R + '" fill="none" stroke="' + RG.ARC + '" stroke-width="' + RG.STROKE + '" stroke-linecap="' + RG.CAP + '" stroke-dasharray="0 ' + RG.DASH_TOTAL + '" transform="rotate(' + RG.ROTATE + ' 48 48)"') &&
    has('<text id="lrRingNum" x="' + RG.NUM_X + '" y="' + RG.NUM_Y + '" text-anchor="middle" fill="' + RG.NUM_COLOR + '" font-weight="' + RG.NUM_WEIGHT + '" font-size="' + RG.NUM_FONT + '">') &&
    has("var RING = 251.33;") && has('arc.setAttribute("stroke-dasharray", Math.round(RING * n / 100) + " ' + RG.DASH_TOTAL + '");') &&
    Math.round(251.33 * RG.SAMPLE[0] / 100) === RG.SAMPLE[1] && Math.abs(2 * Math.PI * RG.R - 251.33) < 0.01);
  check("J4. a row: " + RW.GAP + " px apart, " + RW.PAD + ", a " + RW.LINE + " line; the " + RW.MARK + " px mark (" + RW.MARK_BORDER + " px ring, " + RW.MARK_WEIGHT + " " + RW.MARK_FONT + " px): to do " + RW.TODO + " \"!\", done " + RW.DONE + " tick, waiting " + RW.WAITING + " dots; the title " + RW.TITLE_WEIGHT + " " + RW.TITLE_FONT + " px, the line " + RW.SUB_FONT + "/" + RW.SUB_LINE + " " + RW.SUB_COLOR + "; a " + RW.BUTTON_H + " px button inside a " + LD.HIT + " px target",
    holds(r(".lr-gfi"), { display: "flex", "align-items": "center", gap: px(RW.GAP), padding: RW.PAD, "border-bottom": "1px solid " + RW.LINE }) &&
    holds(r(".lr-gfm"), { width: px(RW.MARK), height: px(RW.MARK), "border-radius": px(RW.MARK_RADIUS), border: RW.MARK_BORDER + "px solid " + RW.TODO, color: RW.TODO, font: RW.MARK_WEIGHT + " " + px(RW.MARK_FONT) + " " + F0 }) &&
    holds(r(".lr-gfi.is-done .lr-gfm"), { "border-color": RW.DONE, color: RW.DONE }) && holds(r(".lr-gfi.is-waiting .lr-gfm"), { "border-color": RW.WAITING, color: RW.WAITING }) &&
    has('var MARKS = { todo: "' + FD.MARKS.todo + '", done: "' + FD.MARKS.done + '", waiting: "' + FD.MARKS.waiting + '" };') &&
    holds(r(".lr-gft"), { font: RW.TITLE_WEIGHT + " " + px(RW.TITLE_FONT) + " " + F0 }) &&
    holds(r(".lr-gfd"), { "font-size": px(RW.SUB_FONT), "line-height": String(RW.SUB_LINE), color: RW.SUB_COLOR }) &&
    holds(r(".lr-btn.is-s .lr-btnf"), { height: px(RW.BUTTON_H) }) && holds(r(".lr-btn.is-s"), { margin: lift(LD.HIT, RW.BUTTON_H) }) && holds(rule(lr, "    a.lr-gfx "), { "min-height": px(LD.HIT) }),
    J([r(".lr-gfi"), r(".lr-gfm"), r(".lr-btn.is-s")]));
  check("J5. the score's weights " + J(FD.WEIGHTS) + " (sum 100) and the board's words, from lib/foundScore.js",
    FSL.indexOf("var WEIGHTS = { basics: 15, profile: 20, listings: 20, posts: 15, connected: 15, fingerprint: 15 };") !== -1 &&
    Object.values(FD.WEIGHTS).reduce((a, b) => a + b, 0) === 100 &&
    Object.values(FD.TITLES).every(t => FSL.indexOf('title: "' + t + '"') !== -1) &&
    Object.values(FD.DETAILS).every(t => FSL.indexOf('"' + t + '"') !== -1) && FD.WAITING_TITLE === ["YouTube", "TikTok", "Instagram", "Facebook"].join(", "));

  { /* ── K ── NAMED (Nov 25 2026, H1): the owner's canvas row 7; its own block (its names are its own) */
  console.log("\n══ K. H1: the owner's canvas row 7 (" + DS.HOME.BOARDS.join(", ") + ") ══");
  const HM = DS.HOME, CH = HM.CHIPS, RL = HM.RAIL, IN = HM.INFO, FW = HM.FOLLOW, SE = HM.SEARCH;
  const ht = FILES[HTABS] || "", htPhone = block(ht, '"@media " + BREAKPOINT + "{"');
  const FN = '" + F + "';   // the site's font stack, as bf-home-tabs.js writes it
  const hr = sel => rule(ht, sel), hp = sel => rule(htPhone, sel);
  check("K1. the four boards' tabs " + HM.TABS.join(", ") + "; Local and Market built (no Coming soon), For You still Coming soon",
    J(HM.TABS) === J(F.TOP.TABS) && /id="tabLocal" aria-selected="false" aria-controls="homeLocal"/.test(home) && /id="tabMarket" aria-selected="false" aria-controls="homeMarket"/.test(home) &&
    /class="feed-tab is-soon" role="tab" id="tabForYou"[^>]*data-soon="foryou"/.test(home) && home.indexOf('<script src="/scripts/bf-home-tabs.js"></script>') !== -1);
  // NAMED (Nov 25 2026, H1, PHONE_H1): BEFORE the chip itself was the 34 px face (the site's phone rule raised it to 44). AFTER a 44 px
  // target (.bfh-chip) holding the board's 34 px face (.bfh-chipf), as LR-4's .lr-btnf.
  check("K2. the chips: a " + CH.H + " px face in a " + CH.HIT + " px target, radius " + CH.RADIUS + ", 0 " + CH.PAD_X + " px, " + CH.BORDER + " on " + CH.BG + ", " + CH.TEXT + " " + CH.WEIGHT + " " + CH.FONT + " px, " + CH.GAP + " px apart; on: accent on " + CH.ON_BG,
    holds(hr(".bfh-chip"), { height: px(CH.HIT), padding: "0", border: "0", background: "none" }) &&
    holds(hr(".bfh-chipf"), { height: px(CH.H), "box-sizing": "border-box", padding: "0 " + px(CH.PAD_X), "border-radius": px(CH.RADIUS), border: "1px solid " + CH.BORDER, background: CH.BG, color: CH.TEXT, font: CH.WEIGHT + " " + CH.FONT + "px/1 " + FN }) &&
    holds(hr(".bfh-chips"), { gap: px(CH.GAP) }) && holds(hr(".bfh-chip.is-on .bfh-chipf,.bfh-chip[aria-pressed=true] .bfh-chipf"), { "border-color": ACC, background: CH.ON_BG, color: ACC }) &&
    ht.split('<span class="bfh-chipf">').length - 1 === 6, J([hr(".bfh-chip"), hr(".bfh-chipf"), hr(".bfh-chips")]));   // Local's three, All, each category, each filter
  check("K3. over a full-screen tab the chips sit " + CH.LEFT + " px in and " + CH.TOP + " px down (below the safe area); Local's: the city with a " + CH.PIN + " px pin, " + CH.LOCAL.join(", "),
    holds(hp("body.feed-full .bfh-chips.is-over"), { position: "fixed", left: px(CH.LEFT), top: "calc(" + px(CH.TOP - (CH.HIT - CH.H) / 2) + " + env(safe-area-inset-top, 0px))" }) &&   // the target 5 px above the face
    ht.indexOf("svg(ICON.pin, " + CH.PIN + ")") !== -1 && ht.indexOf('var REACH_WORDS = { city: "My city", "25": "' + CH.LOCAL[0] + '", anywhere: "Anywhere" };') !== -1 && ht.indexOf('id="homeLocalChange"><span class="bfh-chipf">' + CH.LOCAL[1] + "</span></button>") !== -1, J(hp("body.feed-full .bfh-chips.is-over")));
  check("K4. Market's rail: " + RL.RIGHT + " px from the right, " + RL.ABOVE_BAR + " px above the bar, " + RL.GAP + " px apart, " + RL.WIDTH + " px wide; the seller's " + RL.AVATAR + " px picture with a " + RL.PLUS + " px follow; " + RL.MARKET.join(", ") + "; no Tip",
    holds(hp(".bfm-list.is-full .bfm-rail"), { position: "absolute", right: px(RL.RIGHT), bottom: px(RL.ABOVE_BAR), width: px(RL.WIDTH), gap: px(RL.GAP) }) &&
    holds(hp(".bfm-list.is-full .bfm-list") || hp(".bfm-list.is-full"), { bottom: "calc(56px + env(safe-area-inset-bottom, 0px))" }) &&
    holds(hp(".bfm-list.is-full .bfm-pic"), { width: px(RL.AVATAR), height: px(RL.AVATAR) }) && holds(hp(".bfm-list.is-full .bfm-badge span"), { width: px(RL.PLUS), height: px(RL.PLUS) }) &&
    RL.MARKET.every(w => ht.indexOf("<span>" + w + "</span>") !== -1 || ht.indexOf("(l.saved ? \"Saved\" : \"" + w + "\")") !== -1) && !/data-mact="tip"|>Tip</.test(ht), J([hp(".bfm-list.is-full .bfm-rail"), hp(".bfm-list.is-full")]));
  check("K5. Market's block: " + IN.LEFT + " px in, " + IN.RIGHT + " px from the right, " + IN.ABOVE_BAR + " px above the bar, " + IN.GAP + " px apart; the line " + IN.LINE_FONT + " px " + IN.LINE_COLOR + "; the title " + IN.TITLE_WEIGHT + " " + IN.TITLE_FONT + "/" + IN.TITLE_LINE + "; the seller line " + IN.SUB_FONT + " px",
    holds(hp(".bfm-list.is-full .bfm-meta"), { position: "absolute", left: px(IN.LEFT), right: px(IN.RIGHT), bottom: px(IN.ABOVE_BAR) }) && holds(hr(".bfm-meta"), { gap: px(IN.GAP) }) &&
    holds(hr(".bfm-line"), { font: "400 " + IN.LINE_FONT + "px/1.3 " + FN, color: IN.LINE_COLOR }) && holds(hr(".bfm-title"), { font: IN.TITLE_WEIGHT + " " + IN.TITLE_FONT + "px/" + IN.TITLE_LINE + " " + FN }) &&
    holds(hr(".bfm-sub"), { font: "400 " + IN.SUB_FONT + "px/1.4 " + FN }), J([hp(".bfm-list.is-full .bfm-meta"), hr(".bfm-line"), hr(".bfm-title")]));
  check("K6. the price " + IN.PRICE_WEIGHT + " " + IN.PRICE_FONT + " px gold " + IN.PRICE + " in BizCash; Buy " + IN.BUY_H + " px, 0 " + IN.BUY_PAD_X + " px, radius " + IN.BUY_RADIUS + ", accent, " + IN.BUY_WEIGHT + " " + IN.BUY_FONT + " px",
    holds(hr(".bfm-price"), { font: IN.PRICE_WEIGHT + " " + IN.PRICE_FONT + "px/1.2 " + FN, color: IN.PRICE.toLowerCase() }) && ht.indexOf("n(l.price_bfc) + ' BFC</span>") !== -1 &&
    holds(hr(".bfm-buy"), { height: px(IN.BUY_H), padding: "0 " + px(IN.BUY_PAD_X), "border-radius": px(IN.BUY_RADIUS), background: ACC, color: IN.BUY_TEXT, font: IN.BUY_WEIGHT + " " + IN.BUY_FONT + "px/1 " + FN }), J([hr(".bfm-price"), hr(".bfm-buy")]));
  check("K7. Local: bf-feed.js's cards with the line \"" + HM.LOCAL_LINE.EXAMPLE + "\" (" + HM.LOCAL_LINE.FONT + " px " + HM.LOCAL_LINE.COLOR + "), the For You rail and the strip",
    feed.indexOf("    if (p.local && typeof p.local === \"object\") {") !== -1 && feed.indexOf('esc(lp.join(" \u00b7 "))') !== -1 &&
    holds(hr("#homeLocalFeed .bfp-kind.is-local .bfp-kmeta"), { "font-size": px(HM.LOCAL_LINE.FONT), color: HM.LOCAL_LINE.COLOR }) && ht.indexOf('window.BFFeed.mount(host, { full: true, local: true,') !== -1, J(hr("#homeLocalFeed .bfp-kind.is-local .bfp-kmeta")));
  check("K8. Following, nobody followed: " + FW.BG + ", " + FW.TOP + " px down, " + FW.PAD + ", " + FW.GAP + " px apart; the " + FW.ICON + " px circle; \"" + FW.TITLE + "\" " + FW.TITLE_WEIGHT + " " + FW.TITLE_FONT + " px; the line " + FW.SUB_FONT + "/" + FW.SUB_LINE,
    holds(hp("body.bfh-follow-empty .bfh-follow"), { padding: FW.PAD, background: FW.BG }) && holds(hp("body.bfh-board .page"), { "padding-top": "calc(" + px(FW.TOP) + " + env(safe-area-inset-top, 0px))" }) &&
    holds(hr(".bfh-follow"), { gap: px(FW.GAP) }) && holds(hr(".bfh-follow-ic"), { width: px(FW.ICON), height: px(FW.ICON), background: FW.ICON_BG, color: ACC }) &&
    holds(hr(".bfh-follow-t"), { font: FW.TITLE_WEIGHT + " " + FW.TITLE_FONT + "px/1.3 " + FN }) && holds(hr(".bfh-follow-s"), { font: "400 " + FW.SUB_FONT + "px/" + FW.SUB_LINE + " " + FN }) &&
    ht.indexOf('followTitle: "' + FW.TITLE + '"') !== -1 && ht.indexOf('followSub: "' + FW.SUB + '"') !== -1, J([hp("body.bfh-follow-empty .bfh-follow"), hr(".bfh-follow-t")]));
  check("K9. \"" + FW.LABEL + "\" " + FW.LABEL_WEIGHT + " " + FW.LABEL_FONT + " px, " + FW.LABEL_SPACING + " px apart, " + FW.LABEL_COLOR + "; a row " + FW.ROW_PAD + ", a " + FW.ROW_LINE + " line, " + FW.ROW_GAP + " px apart; the " + FW.AVATAR + " px picture; the name " + FW.NAME_WEIGHT + " " + FW.NAME_FONT + " px with Verified; the line " + FW.ROW_SUB_FONT + " px",
    holds(hr(".bfh-lbl"), { font: FW.LABEL_WEIGHT + " " + FW.LABEL_FONT + "px/1.2 " + FN, "letter-spacing": px(FW.LABEL_SPACING), color: FW.LABEL_COLOR }) && ht.indexOf('suggested: "' + FW.LABEL + '"') !== -1 &&
    holds(hr(".bfh-row"), { padding: FW.ROW_PAD, "border-bottom": "1px solid " + FW.ROW_LINE, gap: px(FW.ROW_GAP) }) && holds(hr(".bfh-av"), { width: px(FW.AVATAR), height: px(FW.AVATAR) }) &&
    holds(hr(".bfh-name"), { font: FW.NAME_WEIGHT + " " + FW.NAME_FONT + "px/1.3 " + FN }) && holds(hr(".bfh-sub"), { font: "400 " + FW.ROW_SUB_FONT + "px/1.35 " + FN }) && ht.indexOf("esc(p.name) + vb(p.verified)") !== -1, J([hr(".bfh-lbl"), hr(".bfh-row")]));
  // NAMED (Nov 25 2026, H1, PHONE_H1): BEFORE the button was the 34 px pill. AFTER a 44 px target (.bfh-fbtn) holding the 34 px face (.bfh-fbtnf).
  check("K10. Follow inline: a " + FW.BTN_H + " px face in a " + FW.BTN_HIT + " px target, 0 " + FW.BTN_PAD_X + " px, radius " + FW.BTN_RADIUS + ", accent, " + FW.BTN_TEXT + " " + FW.BTN_WEIGHT + " " + FW.BTN_FONT + " px; up to " + FW.MAX + " suggestions (lib/homeTabs.js)",
    holds(hr(".bfh-fbtn"), { height: px(FW.BTN_HIT), "min-width": px(FW.BTN_HIT), padding: "0", background: "none" }) &&
    holds(hr(".bfh-fbtnf"), { height: px(FW.BTN_H), padding: "0 " + px(FW.BTN_PAD_X), "border-radius": px(FW.BTN_RADIUS), background: ACC, color: FW.BTN_TEXT, font: FW.BTN_WEIGHT + " " + FW.BTN_FONT + "px/1 " + FN }) &&
    ht.indexOf('<span class="bfh-fbtnf">Follow</span></button>') !== -1 &&
    (FILES["@lib/homeTabs.js"] || "").indexOf("const SUGGEST_MAX = " + FW.MAX + ";") !== -1, J([hr(".bfh-fbtn"), hr(".bfh-fbtnf")]));
  check("K11. Search's top: " + SE.TOP_PAD + " px below the safe area, " + SE.SIDE + " px sides, " + SE.BOTTOM_PAD + " px under, " + SE.GAP + " px apart; back " + SE.BACK + " px; the field " + SE.FIELD_H + " px, radius " + SE.FIELD_RADIUS + ", accent line on " + SE.FIELD_BG + ", " + SE.FIELD_PAD_LEFT + " px in, a " + SE.ICON + " px magnifier, " + SE.INPUT_FONT + " px text, a " + SE.CLEAR + " px clear",
    holds(hr(".bfh-s-top"), { gap: px(SE.GAP), padding: "calc(" + px(SE.TOP_PAD) + " + env(safe-area-inset-top, 0px)) " + px(SE.SIDE) + " " + px(SE.BOTTOM_PAD) }) &&
    holds(hr(".bfh-s-back"), { width: px(SE.BACK), height: px(SE.BACK) }) &&
    holds(hr(".bfh-s-box"), { height: px(SE.FIELD_H), "border-radius": px(SE.FIELD_RADIUS), border: "1px solid " + ACC, background: SE.FIELD_BG, padding: "0 6px 0 " + px(SE.FIELD_PAD_LEFT) }) &&
    holds(hr(".bfh-s-input"), { font: "400 " + SE.INPUT_FONT + "px/1 " + FN }) && ht.indexOf("svg(ICON.search, " + SE.ICON + ")") !== -1 && ht.indexOf("svg(ICON.x, " + SE.CLEAR + ")") !== -1, J([hr(".bfh-s-top"), hr(".bfh-s-box")]));
  check("K12. the filters " + SE.SCOPES.join(", ") + "; the groups " + SE.GROUPS.join(", ") + " with \"" + SE.SEE_ALL + "\" (" + SE.SEE_ALL_FONT + " px); recent searches up to " + SE.RECENT_MAX,
    ht.indexOf("var SCOPES = " + J(SE.SCOPES.map(x => [x.toLowerCase(), x])).replace(/,/g, ", ") + ";") !== -1 &&
    ht.indexOf("var GROUPS = " + J(SE.GROUPS.map(x => [x.toLowerCase(), x])).replace(/,/g, ", ") + ";") !== -1 && ht.indexOf('seeAll: "' + SE.SEE_ALL + '"') !== -1 &&
    holds(hr(".bfh-s-all"), { font: "400 " + SE.SEE_ALL_FONT + "px/1 " + FN }) && ht.indexOf("var RECENT_MAX = " + SE.RECENT_MAX + ";") !== -1);
  check("K13. a listing row: the " + SE.THUMB + " px picture (radius " + SE.THUMB_RADIUS + "), the title " + SE.L_TITLE_WEIGHT + " " + SE.L_TITLE_FONT + " px, the line " + SE.L_SUB_FONT + " px, the price " + SE.PRICE_WEIGHT + " " + SE.PRICE_FONT + " px gold; posts " + SE.GRID_COLS + " across, " + SE.GRID_RATIO + ", radius " + SE.GRID_RADIUS + ", " + SE.GRID_GAP + " px apart",
    holds(hr(".bfh-l-tile"), { width: px(SE.THUMB), height: px(SE.THUMB), "border-radius": px(SE.THUMB_RADIUS) }) && holds(hr(".bfh-l-t"), { font: SE.L_TITLE_WEIGHT + " " + SE.L_TITLE_FONT + "px/1.3 " + FN }) &&
    holds(hr(".bfh-l-p"), { font: SE.PRICE_WEIGHT + " " + SE.PRICE_FONT + "px/1 " + FN, color: IN.PRICE.toLowerCase() }) &&
    holds(hr(".bfh-grid"), { "grid-template-columns": "repeat(" + SE.GRID_COLS + ",minmax(0,1fr))", gap: px(SE.GRID_GAP) }) && holds(hr(".bfh-tile"), { "aspect-ratio": SE.GRID_RATIO, "border-radius": px(SE.GRID_RADIUS) }), J([hr(".bfh-l-tile"), hr(".bfh-grid"), hr(".bfh-tile")]));
  check("K14. the site's fonts, never the boards' (Space Grotesk, Inter)", !/Space Grotesk|Inter\b/.test(ht) && ht.indexOf("var F = 'system-ui,-apple-system,\"Segoe UI\",Arial,sans-serif';") !== -1);
  }

  T.finish();
})();
