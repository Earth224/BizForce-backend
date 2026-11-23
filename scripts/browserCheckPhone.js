"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   browserCheckPhone — every member page on a phone, IN A REAL BROWSER (PH1,
   Nov 19 2026). The owner runs BizForce as an installed phone app (about 390
   px wide). This runs the installed Chrome, headless, over the Chrome DevTools
   Protocol (Node's own WebSocket and child_process; no package), the same way
   as scripts/browserCheckSocial.js.

   The frontend is served from disk on 127.0.0.1. Requests to the API host are
   answered from the fixtures below (browserCheckDashboard's, browserCheckAgents'
   and browserCheckSocial's: an owner named Rose, 18 agents, 20 runs, 11
   proposals, a connected Shopify store, analytics); every other outside
   request is refused. Math.random is seeded and the clock starts at a fixed
   time (Nov 19 2026, 17:00 UTC) and then runs, so a page draws the same and
   prints the same dates each run.

   THE PAGES are every page in lib/appMap.json (77), in batches of at most 15
   (PHONE_BATCH=1..6), or smaller batches (PHONE_SIZE=5 PHONE_BATCH=1..16), or a list
   (PHONE_PAGES=dashboard.html,oracle.html). PHONE_ONLY=phone runs only the
   three phone sizes and PHONE_ONLY=desktop only 1440, so a batch fits in a
   command on a busy machine.

   PHONE SIZES 360 x 780, 390 x 844 and 430 x 932: touch, a phone's user agent,
   deviceScaleFactor 2. DESKTOP 1440 x 900, with animations paused (injected
   CSS: animation-play-state paused, transition none) from the first paint.

   PHONE_MODE=before   STEP 1. Screenshots to <out>/before; per page and phone
                       width the defect list (below) to <out>/defects-before-<batch>.json;
                       at 1440 the bounding box of every visible element to
                       <out>/desktop-baseline-<batch>.json, measured twice 700
                       ms apart (an element that moved between the two, a JS
                       animation, is set aside as moving).
   PHONE_MODE=check    (the default) STEP 3. Screenshots to <out>/after, and
                       at each phone width, on every page:
                         no horizontal scroll;
                         no text cut off (an ellipsis, a line clamp, or text
                         clipped by its own box or a hidden-overflow ancestor;
                         this covers the header, the orbit, the agent tiles
                         and the dashboard cards);
                         no fixed element (the Guide button, the music button,
                         a toast) over a heading, text, a button or a link, at
                         rest and at the end of the page (the Guide is judged at
                         the end, where its spacer must keep it clear: mid-page
                         it floats over the scrolling content by design);
                         every tap target at least 44 x 44 (a link inside a
                         sentence is exempt, WCAG 2.5.8; a checkbox or radio is
                         measured by its label);
                         no decoration (stars, nebula glows, the mist) painted
                         over text (a decoration that moves on its own, an
                         aria-hidden fixed overlay, is set aside at 1440 only);
                         no empty gap over 48 px inside a card.
                       On the dashboard: the orbit's five portals sit on a
                       circle round the core (equal distance within 2 px),
                       every label is shown in full, no two labels overlap and
                       none overlaps the core, each disc is 44 px or more, no
                       empty space above the orbit, THIS WEEK and the goal
                       button under it at the card's width; the top bar's two
                       rows (brand, music, avatar; AGENTS, the orb, TERMAXIMUS)
                       with Settings and Sign Out off it; the R avatar opens a menu with Settings and Sign
                       Out, Settings goes to settings.html and Sign Out signs
                       out (bf_token removed, the sign-in page).
                       At 1440 every element of the baseline is matched by an
                       element of the same tag, id and text whose box is
                       within 1 px, and no new element is visible.
                       NAMED (Nov 19 2026, HQ1): privacy.html's 1440 baseline is
                       re-recorded in desktop-baseline-hq1-privacy.json (read
                       after the batch files, so it replaces that one page). The
                       Your data sentence for user_preferences names the phone
                       card view and orbit now, one line longer: that list item
                       and its four ancestors grew 26 px, the 317 elements below
                       moved down 26 px, the other 54 are where they were, and
                       nothing else differs (compared element by element).
                       NAMED (Nov 19 2026, P2-1): at each phone width every page
                       also gets the bottom bar's checks (barChecks): shown exactly
                       where scripts/bf-tabbar.js's list says, at the bottom, five
                       44 px items, the right tab active, nothing painted over it,
                       the Guide button clear of it; the bar, like the Guide, is
                       judged over the page at the END, not at rest. home.html and
                       inbox.html are new (their 1440 baseline is
                       desktop-baseline-p21-new.json); messages, proposals,
                       settings, profile and privacy changed on purpose and each
                       has a named desktop-baseline-p21-<page>.json, read after the
                       batch files and HQ1's (see the P2-1 report for the proof).
                       NAMED (Nov 20 2026, P2-2): the legal footer's second line
                       (Copyright notices) grows every page's footer by 22.8 px;
                       desktop-baseline-p22-footer.json holds those 76 pages, and
                       p22-settings, p22-terms, p22-privacy and p22-new (copyright,
                       moderation) the pages P2-2 changed on purpose; the proof is
                       Downloads\phone1\p22-desktop-proof.json.
                       NAMED (Nov 20 2026, P2-3): home.html (the Following feed; on a
                       desktop the Market and Campaigns move to the right-hand
                       column) and privacy.html (Your data names the posts, follows,
                       likes, saves and comments, and when a removed post's text
                       and photos go: 11 list items added, their 9 ancestors grew,
                       298 elements moved down, 78 where they were, none gone) are
                       re-recorded in desktop-baseline-p23-home.json and
                       p23-privacy.json; compose.html is new (p23-new). The other
                       79 pages, profile.html among them, are unchanged at 1440.
                       The proof is Downloads\phone1\p23-desktop-proof.json.
                       NAMED (Nov 20 2026, FX1): compose.html gains the legal footer
                       every page carries (P2-3 left it out): its 73 elements are
                       where they were and the footer's 13 are new; it is
                       re-recorded in desktop-baseline-pfx1-compose.json (the name
                       sorts after p23-new, so it replaces that one page). Home and
                       the Profile are unchanged at 1440. The proof is
                       Downloads\phone1\fx1-desktop-proof.json.
                       NAMED (Nov 20 2026, P3-1): three pages changed on purpose and
                       are re-recorded: privacy.html (Your data names the folded
                       email and the storage counts: 4 list items new, none gone),
                       terms.html (section 3, Free accounts and membership, and the
                       adult-content and BizCash sentences: 10 new, none gone) and
                       wallet.html (who may send, one sentence: 1 new, none gone),
                       in desktop-baseline-p31-privacy, p31-terms and p31-wallet.json;
                       every other element is the same or moved down below the new
                       text. The other 79 pages are unchanged at 1440 (the members
                       panel and the banner show only for a free or unconfirmed
                       account). The proof is Downloads\phone1\p31-desktop-proof.json.
                       NAMED (Nov 21 2026, P3-2): three pages changed on purpose and
                       are re-recorded: moderation.html (the owner's "Verified
                       sellers" section: 13 new, none gone), privacy.html (what is
                       kept for the Verified badge and who sees it: 2 list items
                       new, none gone) and terms.html (section "The Verified
                       badge": 7 new, none gone), in desktop-baseline-p32-moderation,
                       p32-privacy and p32-terms.json; every other element is the
                       same, moved down below the new text, or a container grown
                       to hold it. The other 79 pages are unchanged at 1440 (the
                       badge draws only for an account the server says is
                       verified, and the fixtures say none). The proof is
                       Downloads\phone1\p32-desktop-proof.json.
                       NAMED (Nov 21 2026, FX2): privacy.html changed on purpose
                       (Your data's settings line names the Agent Directory's
                       view, one line longer: that item and its four ancestors
                       grew 26.4 px, 343 elements moved down, 54 are where they
                       were, none new, none gone) and is re-recorded in
                       desktop-baseline-pfx2-privacy.json (the name sorts after
                       p32-privacy and pfx1-compose). The other pages are
                       unchanged at 1440: the strip shows only for a post with a
                       listing, the Profile's banner and the Agent Directory's
                       views only on a phone, the Sun only under 760 px. The
                       proof is Downloads\phone1\fx2-desktop-proof.json.
                       NAMED (Nov 21 2026, P3-1B): four pages changed on purpose and
                       are re-recorded in desktop-baseline-pp31b-<page>.json (the
                       name sorts after pfx2-privacy): compose.html (What is it,
                       Share or Need, and a member's Show in Google box: 14 new,
                       none gone), privacy.html (which posts search engines may
                       index: 1 list item new, none gone), terms.html (the free
                       account's photo rule, Show in Google, and BizCash for
                       members: 3 new, the old BizCash sentence gone) and
                       wallet.html (who may send and receive, one sentence
                       reworded). Every other element is the same, moved down
                       below the new text, or a container grown to hold it. The
                       other pages are unchanged at 1440 (the members panel, the
                       Buy sheet and the Members tags show only for a free
                       account). The proof is Downloads\phone1\p31b-desktop-proof.json.
                       NAMED (Nov 21 2026, P3-1C): two pages changed on purpose and
                       are re-recorded in desktop-baseline-pp31c-<page>.json (the
                       name sorts after pp31b-wallet): terms.html (members start
                       with 1,000 BizCash: 1 list item new, none gone, the BizCash
                       item one line taller) and wallet.html (who may send and
                       receive, the sentence one line longer: none new, none gone).
                       Every other element is the same or moved down below the new
                       text. privacy, refund and contact are unchanged at 1440. The
                       proof is Downloads\phone1\p31c-desktop-proof.json.
                       NAMED (Nov 23 2026, P3-3): three pages are re-recorded in
                       desktop-baseline-pp33-<page>.json (the names sort after pp31c):
                       compose.html (the composer rebuilt to the owner's canvas: the 64 px
                       header with Post, the three tiles, the category chips; 14 old
                       elements gone, 40 new; with no fixture the categories cannot
                       load, so its note and Try again are drawn), marketplace.html (the
                       category menu and its pills replaced by one row of chips: 8 gone,
                       2 new, the tab row 11 px lower) and privacy.html (the Your posts
                       sentence names the intent and category: one item 52.8 px taller,
                       217 elements below moved down by it). Every other page is
                       unchanged at 1440 (Settings' Need alerts row is in Preferences, a
                       closed section). The proof is Downloads\phone1\p33-desktop-proof.json.
     PHONE_P21=1         only P2-1's own pages (p21Run): the rewritten addresses,
                           signed out, Home, the Inbox's tabs and a thread, the
                           profile, the Create sheet, the dashboard with the bar,
                           at 360, 390 and 430; screenshots to Downloads\p21.
     PHONE_P22=1           only P2-2's own screens (p22Run): the report, block and
                           mute menu and its sheets, Settings, Blocked and muted,
                           moderation.html (owner and not), copyright.html and its
                           counter form, the owner's waiting count; at 360, 390
                           and 430; screenshots to Downloads\p22.
     PHONE_P23=1           only P2-3's own screens (p23Run): the Following feed,
                           Like, Talk, the own post's menu, Home at a post,
                           compose.html and Post, the profile's Posts and Saved,
                           a storefront's Follow, the public post page signed out
                           and in, few follows; answered by lib/posts.js over an
                           in-memory database; at 360, 390 and 430; screenshots
                           to Downloads\p23.

     PHONE_P31=1           only P3-1's own screens (p31Run): a free account with the email
                           not confirmed (the banner, Resend email, a public post refused),
                           then confirmed (Home, the composer posting, the Profile, Market
                           create, the Inbox, the HQ tab's members panel, the dashboard and
                           an agent page behind it); at 360, 390 and 430; screenshots to
                           Downloads\p31. NAMED (Nov 21 2026, P3-1B): the owner's final
                           rules (a share post needs a photo, Market create and the
                           Create sheet's members entries open the panel, Talk on a
                           member's post, the wallet, the Buy sheet, reply-only Inbox),
                           and at 390 a member's Show in Google and indexable /p/ page;
                           the P3-1B screenshots go to Downloads\p31b.

     PHONE_P33=1           only P3-3's own screens (p33Run): the composer's Share, Offer or Need, the
                           Need post and I can help, Found, the Market's categories, Need alerts in Settings
                           (NAMED (Nov 23 2026, P3-3)); screenshots to PHONE_P33_OUT (default Downloads\p33)
     PHONE_P32=1           only P3-2's own screens (p32Run): the Verified badge on the
                           Following feed, Talk, the profile, a storefront and the public
                           post page /p/; its tap sheet ("Verified: [kind]. This is not an
                           endorsement."); at 360, 390 and 430; screenshots at 390 x 844
                           to Downloads\p32.

     CHROME_PATH            the browser (default: the usual Windows paths)
     BIZFORCE_FRONTEND_DIR  the frontend checkout
     PHONE_OUT              the folder (default Downloads\phone1)

   NOT PART OF THE SERVER SUITE (its name does not start with "check"): run it
   by hand. With no Chrome it prints SKIPPED and exits 0.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const OUT = process.env.PHONE_OUT || path.join(os.homedir(), "Downloads", "phone1");
const MODE = process.env.PHONE_MODE === "before" ? "before" : "check";
const API_HOST = "dynamic-prosperity-production-5382.up.railway.app";
const ONLY = process.env.PHONE_ONLY || "";   // "desktop" or "phone": one half of the run (a loaded machine runs fewer pages a minute)
const PHONES = ONLY === "desktop" ? [] : [[360, 780], [390, 844], [430, 932]];
const DESK = [1440, 900];
const IPHONE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

const CANDIDATES = [process.env.CHROME_PATH,
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  path.join(process.env.LOCALAPPDATA || "", "Google\\Chrome\\Application\\chrome.exe"),
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"].filter(Boolean);
const CHROME = CANDIDATES.find(p => { try { return fs.statSync(p).isFile(); } catch (e) { return false; } });
if (!CHROME) { console.log("SKIPPED  no Chrome found (set CHROME_PATH); nothing was checked."); process.exit(0); }
if (typeof WebSocket !== "function") { console.log("SKIPPED  this Node has no built-in WebSocket (Node 22 or later needed)."); process.exit(0); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 900) + "]" : "")); }
}
const J = JSON.stringify;

/* ── the pages ── */
const MAP = JSON.parse(fs.readFileSync(path.join(REPO, "lib", "appMap.json"), "utf8"));
const ALL = Object.keys(MAP.pages).map(k => String(MAP.pages[k].p || "/" + k).replace(/^\//, ""));
let PAGES = ALL, BATCH = "all";
if (process.env.PHONE_PAGES) { PAGES = process.env.PHONE_PAGES.split(",").map(s => s.trim()).filter(Boolean); BATCH = "list"; }
else if (process.env.PHONE_BATCH) { const b = Number(process.env.PHONE_BATCH), n = Math.min(15, Number(process.env.PHONE_SIZE) || 15); PAGES = ALL.slice((b - 1) * n, b * n); BATCH = (n === 15 ? "" : "s" + n + "-") + b; }
// NAMED (Nov 20 2026, P2-2): PHONE_P22 is its own run too; NAMED (Nov 20 2026, P2-3): and PHONE_P23
if (process.env.PHONE_HQ1 !== "1" && process.env.PHONE_P21 !== "1" && process.env.PHONE_P22 !== "1" && process.env.PHONE_P23 !== "1" && process.env.PHONE_P31 !== "1" && process.env.PHONE_P32 !== "1" && process.env.PHONE_FX3 !== "1" && process.env.PHONE_P33 !== "1" && PAGES.length > 15) {   // NAMED (Nov 23 2026, P3-3): and PHONE_P33   // HQ1 and P2-1: their own runs, no page list
 console.log("At most 15 pages a run: set PHONE_BATCH=1.." + Math.ceil(ALL.length / 15) + " or PHONE_PAGES."); process.exit(1); }
const fileOf = (page, w, h) => page.replace(/[\/\\]/g, "_").replace(/\.html$/, "") + "-" + w + "x" + h + ".png";

/* ── fixtures (an owner named Rose; the checks' own answers) ── */
// The clock is fixed: the fixtures and the page both read 2026-11-19 17:00 UTC (the page's clock then runs on from there),
// so every date and time drawn is the same in every run.
const NOW = Date.UTC(2026, 10, 19, 17, 0, 0);
const ago = h => new Date(NOW - h * 3600000).toISOString();
const uid = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");
const ROSE = { id: uid(1), email: "rose@example.test", full_name: "Rose", username: "rose", role: "admin", created_at: ago(24 * 60) };
const AGENTS = [
  ["executive", "Executive"], ["ads", "Ads"], ["broker", "Broker"], ["community", "Community"], ["email", "Email"], ["etsy", "Etsy"],
  ["influencer", "Influencer"], ["operations", "Operations"], ["publicist", "Publicist"], ["rd", "R&D"], ["reputation", "Reputation"],
  ["store", "Store"], ["vertical_marketing", "Vertical Marketing"], ["analytics", "Analytics"], ["content", "Content"], ["sales", "Sales"],
  ["seo", "SEO"], ["social", "Social"]
].map(([type, name], i) => ({ agent_type: type, name: name + " Agent", status: i % 5 === 0 ? "running" : "idle", enabled: true, active: true, last_run_at: ago(i * 3 + 1), runs_7d: 3 + (i * 7) % 11 }));
const RUNS = [];
for (let i = 0; i < 20; i++) {
  const type = ["seo", "social", "content", "sales", "store"][i % 5];
  RUNS.push({ id: uid(1000 + i), agent_type: type, task_type: "general", status: i === 4 ? "failed" : "completed",
    title: ["Audit the bakery homepage", "Plan this week's posts", "Draft the spring cakes article", "Follow up warm leads", "Check low stock"][i % 5],
    input: "Weekly task", result: i === 4 ? null : "Done. Summary ready to review.", error: i === 4 ? "The store answered 500" : null,
    created_at: ago(i * 5 + 1), completed_at: ago(i * 5 + 0.8) });
}
const IG_URL = "https://www.instagram.com/reel/AbCdEf123/";
const VIDEOS = [
  { id: "22222222-2222-4222-8222-222222222222", label: "Spring cakes", bytes: 3 * 1048576, mime: "video/mp4", status: "ready", created_at: ago(30), instagram_status: "not_sent", instagram_post_url: null, facebook_status: "not_sent", facebook_post_url: null },
  { id: "44444444-4444-4444-8444-444444444444", label: "Bread day", bytes: 3 * 1048576, mime: "video/mp4", status: "ready", created_at: ago(60), instagram_status: "posted", instagram_post_url: IG_URL, facebook_status: "pending", facebook_post_url: null }
];
const REEL = { id: VIDEOS[0].id, bytes: 3145728 };
let pn = 0;
const prop = (action_type, title, payload, extra) => Object.assign({ id: "p" + (++pn), agent_type: "social", status: "pending", title: title, reasoning: "Suggested from this week's orders.",
  created_at: ago(pn * 2), execution_result: null, execution_error: null, action_type: action_type, payload: payload }, extra || {});
const PROPOSALS = [
  prop("publish_instagram_post", "Post the Spring cakes Reel to Instagram", { ig_user_id: "17841400000000000", kind: "reel", caption: "Spring cakes, fresh today. Come early!", video: REEL }),
  prop("publish_facebook_post", "Post the Spring cakes video to Facebook", { page_id: "100000000000001", kind: "video", message: "Spring cakes, fresh today.", video: REEL }),
  prop("publish_youtube_video", "Upload Spring cakes to YouTube", { channel_id: "UC123", title: "Spring cakes", description: "How we bake them, start to finish.", privacy: "private", made_for_kids: false, tags: ["cake", "bakery"], video: REEL }),
  prop("publish_tiktok_post", "Post Spring cakes to TikTok", { title: "Spring cakes", privacy_level: "SELF_ONLY", allow_comment: true, allow_duet: false, allow_stitch: false, video: REEL }),
  prop("publish_social_post", "Post about spring cakes on Bluesky", { platform: "bluesky", posts_as: "maplestreet.bsky.social", text: "Fresh spring cakes today at https://maplestreet.example/cakes" }),
  prop("publish_mastodon_post", "Post about spring cakes on Mastodon", { posts_as: "@maple@mastodon.social", text: "Spring cakes are here." }),
  prop("publish_blog_post", "Publish Spring cakes on the blog", { slug: "spring-cakes", meta_description: "Spring cakes at Maple Street.", body: "<p>Hello <a href='/menu'>menu</a></p>", internal_links: ["/menu", "/about"] }, { agent_type: "seo" }),
  prop("create_calendar_event", "Add the tasting to the calendar", { title: "Tasting", event_type: "meeting", notes: "Bring samples", jdn: 2461364, local_year: 2026, local_month: 11, local_day: 26 }, { agent_type: "executive" }),
  prop("update_store_item", "Raise the Spring cake price", { platform: "shopify", item_name: "Spring cake", field: "price", currency: "USD", measured: { from: 20, to: 22 } }, { agent_type: "store" }),
  prop("send_mailbox_reply", "Reply to Pat about the order", { to: "pat@example.com", from: "hello@maplestreet.example", subject: "Re: order", text: "Your order is ready." }, { agent_type: "mailbox" }),
  prop("publish_instagram_post", "Posted: the Bread day Reel", { ig_user_id: "17841400000000000", kind: "reel", caption: "Bread day.", video: REEL }, { status: "executed", execution_result: { published: true, permalink: IG_URL } })
];
const STORE = { id: "a1111111-1111-4111-8111-111111111111", platform: "shopify", store: "maple.myshopify.com", status: "connected", permission: "read_write", currency: "USD",
  connected_since: "2026-11-01T00:00:00Z", last_sync_at: ago(2), stock_scope: "location", location_name: "Main warehouse", location_id: "gid://shopify/Location/1" };
const ITEMS = Array.from({ length: 30 }, (_, k) => ({ id: "b0000000-0000-4000-8000-" + String(k + 1).padStart(12, "0"), name: "Spring cake " + (k + 1), sku: "CAKE-" + (k + 1),
  quantity_on_hand: k + 3, unit_price: (20 + k) + ".00", source: "shopify", store_connection_id: STORE.id, status: "active", unit: "unit", created_at: "2026-11-10T00:00:00Z" }));
function centerBody() {
  const counts = {};
  RUNS.forEach(r => { counts[r.agent_type] = counts[r.agent_type] || {}; counts[r.agent_type][r.status] = (counts[r.agent_type][r.status] || 0) + 1; });
  const verdicts = [], jobRuns = [];
  ["daily_store_proposals", "daily_self_reviews", "daily_youtube_retention", "ops_alert_scan", "store_sync", "nightly_backup"].forEach(n => {
    verdicts.push({ job_name: n, cadence: n === "ops_alert_scan" ? "every 30 minutes" : "daily", on_time: true, reason: null });
    jobRuns.push({ job_name: n, last_run_on: "2026-11-19", finished_at: ago(1), last_error: null });
  });
  return {
    generated_at: new Date(NOW).toISOString(), chaining_on: true,
    needs_you: { ok: true, data: { pending_proposals: { count: 2, rows: PROPOSALS.slice(0, 2).map(p => ({ id: p.id, title: p.title, agent_type: p.agent_type, created_at: p.created_at })) },
      failed_runs_7d: { count: 1, rows: [RUNS[4]] }, email_sender: { blocked_by: [] } } },
    plans: { ok: true, data: [] },
    plan_lists: { ok: true, data: { active: [], past_count: 0, past_after_days: 14, past_latest: [] } },
    activity: { ok: true, data: { since: ago(24 * 30), since_7d: ago(24 * 7), total: 20, by_agent: {}, counts_7d: counts, newest_runs: RUNS.slice(0, 10), newest_runs_20: RUNS, sales_dry_runs: 2 } },
    autopilot: { ok: true, data: { autonomy: [{ agent_type: "social", enabled: true, updated_at: ago(30) }, { agent_type: "seo", enabled: false, updated_at: ago(40) }],
      schedules: [{ agent_type: "social", task_type: "calendar", cadence: "weekly", hour_utc: 9, enabled: true, last_run_on: "2026-11-16" }] } },
    outbound: { ok: true, data: { email_sequences: [], social_drafts_by_status: { published: 1 }, content_published_30d: { count: 3 },
      social_latest: [{ id: uid(7000), status: "published", platform: "bluesky", preview: "Spring workshop seats are open", created_at: ago(20) }],
      articles_latest: [0, 1, 2].map(i => ({ id: uid(8000 + i), title: ["Spring cakes", "Our sourdough starter", "Wedding cake season"][i], status: "published", published_at: ago(24 * (i + 1)), created_at: ago(24 * (i + 2)) })) } },
    spend: { ok: true, data: { usd: 4.25, monthly_cap_usd: 60, resets_at: "2026-12-01T00:00:00.000Z", note: "Figures are estimates from token counts at list prices; the provider's bill can differ." } },
    usage: { ok: true, data: { model_calls_today: 12, model_calls_daily_cap: 250, model_calls_unavailable: null, subscription_active: true } },
    platform: { ok: true, data: { job_runs: jobRuns, jobs_on_time: verdicts, job_cadence: {}, radar_status: [{ source: "news", last_tick_finished_at: ago(1), last_outcome: "ok", last_error: null }], ceiling: { spent_usd: 3.1, cap_usd: 25 } } }
  };
}
function topBody() {
  return {
    generated_at: new Date(NOW).toISOString(),
    visits: { per_day: [3, 1, 0, 4, 2, 5, 1, 2, 6, 3, 4, 2, 5, 7], this_week: 29, last_week: 16, tracked: true },
    store: { connected: true, low_stock: { count: 3, names: ["Blue mug", "Tea tin", "Spoon"] }, orders_this_week: 14, orders_per_day: [1, 0, 2, 0, 1, 0, 1, 2, 3, 1, 2, 2, 3, 1] },
    proposals_pending: 2, cards: { count: 2, views_today: 12, views_7d: 31 }, certifications: { earned: 2, total: 8 },
    wallet: { balance: 1100, exists: true }, marketplace: { orders_this_week: 0 }, self_reviews: { latest_at: ago(30) }, mailbox: { connected: true },
    counts: { crm_customers: 18, prospects: 4, leads: 6, sms_subscribers: 0, campaigns: 1, routines: 2, saved_prompts: 3, purchases: 1, bizdoc_documents: 5 },
    media: { used_bytes: 52428800, cap_bytes: 1073741824 }, agents: { running_now: [] }, _unreadable: [], cached: false,
    goal: { set: false }
  };
}
/* NAMED (Nov 19 2026, HQ1): PHONE_HQ1=1 runs only the phone dashboard's HQ1 checks (hq1Run, at the end of this file), at
   PHONE_HQ1_WIDTHS (default 360,390,430), with screenshots to PHONE_HQ1_OUT (default Downloads\hq1). */
const HQ1 = process.env.PHONE_HQ1 === "1";
const HQ1_WIDTHS = String(process.env.PHONE_HQ1_WIDTHS || "360,390,430").split(",").map(Number).filter(Boolean);
const HQ1_OUT = process.env.PHONE_HQ1_OUT || path.join(os.homedir(), "Downloads", "hq1");

/* NAMED (Nov 19 2026, P2-1): the phone app shell's bottom bar. In every check run, at each phone width, the bar is
   shown exactly where scripts/bf-tabbar.js's list says (and only on a page that loads bf-session.js), 56 px or more at
   the very bottom, five items of 44 x 44 or more, the right tab active, nothing else painted over it (the big music
   player excepted, by design) and the Guide button clear of it. Like the Guide, the bar floats over the scrolling page
   by design, so it is judged at the END of the page (where its spacer must keep it clear), not at rest.
   PHONE_P21=1 runs only P2-1's own pages (p21Run, at the end of this file) at PHONE_P21_WIDTHS (default 360,390,430),
   with screenshots at 390 x 844 to PHONE_P21_OUT (default Downloads\p21). */
const P21 = process.env.PHONE_P21 === "1";
const P21_WIDTHS = String(process.env.PHONE_P21_WIDTHS || "360,390,430").split(",").map(Number).filter(Boolean);
const P21_OUT = process.env.PHONE_P21_OUT || path.join(os.homedir(), "Downloads", "p21");
// NAMED (Nov 20 2026, P2-2): PHONE_P22=1 runs only P2-2's own screens (p22Run, at the end of this file)
const P22 = process.env.PHONE_P22 === "1";
const P22_WIDTHS = String(process.env.PHONE_P22_WIDTHS || "360,390,430").split(",").map(Number).filter(Boolean);
const P22_OUT = process.env.PHONE_P22_OUT || path.join(os.homedir(), "Downloads", "p22");
// NAMED (Nov 20 2026, P2-3): PHONE_P23=1 runs only P2-3's own screens (p23Run, at the end of this file)
const P23 = process.env.PHONE_P23 === "1";
const P23_WIDTHS = String(process.env.PHONE_P23_WIDTHS || "360,390,430").split(",").map(Number).filter(Boolean);
const P23_OUT = process.env.PHONE_P23_OUT || path.join(os.homedir(), "Downloads", "p23");
// NAMED (Nov 22 2026, FX3): PHONE_FX3=1 runs only FX3's own screens (fx3Run, at the end of this file)
const FX3 = process.env.PHONE_FX3 === "1";
const FX3_WIDTHS = String(process.env.PHONE_FX3_WIDTHS || "360,390,430").split(",").map(Number).filter(Boolean);
const FX3_OUT = process.env.PHONE_FX3_OUT || path.join(os.homedir(), "Downloads", "fx3");
const BAR_HIDDEN = ["app.html", "reset-password.html", "verify-email.html", "terms.html", "privacy.html", "refund.html", "contact.html",
  "music-popout.html", "card-view.html", "blogpost.html", "blogindex.html", "oracle.html", "mychart.html", "calendar.html", "synastry.html", "the-third.html",
  "compose.html"];   // NAMED (Nov 20 2026, P2-3): the full-screen composer turns the bar off (data-bf-tabbar="off")
const BAR_ACTIVE = { "home.html": "home", "inbox.html": "inbox", "messages.html": "inbox", "proposals.html": "inbox", "profile.html": "profile", "settings.html": "profile" };
// a page loads the bar when it loads bf-session.js as a guard, or with data-music (settings.html); app.html's data-clear-only alone does not
function barLoads(file) {
  let html = "";
  try { html = fs.readFileSync(path.join(FRONTEND, file), "utf8"); } catch (e) { return false; }
  if (!/bf-session\.js/.test(html)) return false;
  const tag = (/<script src="\/scripts\/bf-session\.js"([^>]*)>/.exec(html) || [])[1];
  // your-data.html writes the tag itself, data-clear-only only when signed out: signed in (as here) it is a guard
  if (tag !== undefined && /bf_token/.test(tag)) return true;
  return !(tag !== undefined && /data-clear-only/.test(tag) && !/data-music/.test(tag));
}
const P21_PEER = uid(2), P21_PEER2 = uid(3);
const P21_IMG = ["/brand/agent-network-tile-256.png", "/brand/bizforce-logo-dark-256.png", "/brand/bizforce-logo-light-256.png", "/brand/agent-network-tile-512.png"];
const P21_FIX = {
  starter: {
    listings: [["Spring cake", 40, "product"], ["Cake decorating class", 120, "service"], ["Sourdough loaf", 12, "product"], ["Wedding cake tasting", 60, "service"]]
      .map(([t, pr, k], i) => ({ id: uid(5000 + i), title: t, price_bfc: pr, kind: k, category: "food", photo: P21_IMG[i] })),
    campaigns: [{ title: "New oven for the bakery", goal_bfc: 5000, raised_bfc: 1850, photo: P21_IMG[3], link: "/campaign/abcdefghijklmnop" },
      { title: "Community garden beds", goal_bfc: 2000, raised_bfc: 400, photo: null, link: "/campaign/qrstuvwxyzabcdef" }],
    people: [{ username: "pat", name: "Pat's Pantry", tagline: "Jams and preserves", avatar_url: null, link: "/@pat" },
      { username: "lee-ceramics", name: "Lee Ceramics", tagline: null, avatar_url: P21_IMG[1], link: "/@lee-ceramics" }]
  },
  counts: { notifications: 2, messages: 1, approvals: 10, badge: 3 },
  conversations: { conversations: [
    { other_id: P21_PEER, last_message: "Can I collect the order on Saturday morning?", last_at: ago(1), last_from_me: false, unread: 1, person: { username: "pat", name: "Pat's Pantry", avatar_url: null } },
    { other_id: P21_PEER2, last_message: "Thanks, the mugs arrived safely.", last_at: ago(30), last_from_me: true, unread: 0, person: { username: "lee-ceramics", name: "Lee Ceramics", avatar_url: P21_IMG[1] } }
  ], next_before: null },
  thread: { messages: [
    { id: uid(6001), sender_id: ROSE.id, receiver_id: P21_PEER, content: "Your order is ready. We open at 8.", created_at: ago(3) },
    { id: uid(6002), sender_id: P21_PEER, receiver_id: ROSE.id, content: "Can I collect the order on Saturday morning?", created_at: ago(1) }
  ], has_more: false, next_before: null },
  notifications: { notifications: [
    { id: uid(6101), type: "support", title: "@pat supported you with 50 BFC", message: "For the spring cakes", read: false, created_at: ago(2), link: "/wallet.html" },
    { id: uid(6102), type: "order", title: "New order", message: "Lee Ceramics bought a Sourdough loaf", read: false, created_at: ago(5), link: "/my-purchases.html" },
    { id: uid(6103), type: "system", title: "Welcome to BizForce", message: "Your account is ready.", read: true, created_at: ago(240), link: null }
  ] },
  profile: { profile: { user_id: ROSE.id, username: "rose", display_name: "Rose", title: "Baker", tagline: "Maple Street Bakery", bio: "We bake bread and cakes every morning on Maple Street." } },
  stats: { sales: 12, bizcash: 2400 },
  myListings: { listings: [
    { id: uid(5000), slug: "spring-cake", title: "Spring cake", status: "active", listing_kind: "product", price_bfc: 40, media: [{ url: P21_IMG[0], type: "image/png" }] },
    { id: uid(5001), slug: "sourdough-loaf", title: "Sourdough loaf", status: "active", listing_kind: "product", price_bfc: 12, media: [{ url: P21_IMG[2], type: "image/png" }] },
    { id: uid(5002), slug: "cake-class", title: "Cake decorating class", status: "active", listing_kind: "service", price_bfc: 120, media: [{ url: P21_IMG[1], type: "image/png" }] }
  ] },
  place: { place: { place_city: "Portland", place_region: "Oregon", place_country: "US", local_opt_in: false }, countries: ["CA", "GB", "US"] }
};
function p21Api(method, p) {
  if (p === "/api/home/starter") return P21_FIX.starter;
  if (p === "/api/inbox/counts") return P21_FIX.counts;
  if (p === "/api/inbox/conversations") return P21_FIX.conversations;
  if (p.indexOf("/api/inbox/person/") === 0) return { person: { id: P21_PEER, username: "pat", name: "Pat's Pantry", avatar_url: null } };
  if (p.indexOf("/api/inbox/read/") === 0) return { marked: 1 };
  if (p.indexOf("/api/messages/") === 0 && method === "GET") return P21_FIX.thread;
  if (p === "/api/notifications" && method === "GET") return P21_FIX.notifications;
  if (p === "/api/bfp/profile/me" && method === "GET") return P21_FIX.profile;
  if (p === "/api/bfp/profile/me/stats") return P21_FIX.stats;
  if (p === "/api/marketplace/my-listings") return P21_FIX.myListings;
  if (p === "/api/me/place" && method === "GET") return P21_FIX.place;
  return undefined;
}
// the site's own rewrites (_redirects) for the addresses the bar's list names, served from disk in a P21 run
function p21Rewrite(p) {
  if (/^\/@[a-z0-9_-]+$/i.test(p)) return "/seller.html";
  if (/^\/listing\/[^/]+$/.test(p)) return "/listing.html";
  if (/^\/blog\/[^/]+\/[^/]+$/.test(p)) return "/blogpost.html";
  if (/^\/blog\/[^/]+$/.test(p)) return "/blogindex.html";
  return p;
}
const HQS = { view: null, orbit: null, puts: [], moonAsks: 0 };
const MOON = { illuminatedFraction: 0.8312, waxing: false, phaseAngle: 220.4, phaseName: "Waning Gibbous" };
let ORIGIN = "";
const MOON_PHOTO = "https://upload.wikimedia.org/wikipedia/commons/e/e1/FullMoon2010.jpg";   // oracle.html MOON_IMG_URL
const MOON_STANDIN = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200"><circle cx="100" cy="100" r="100" fill="#c9c9c4"/>' +
  '<circle cx="70" cy="80" r="18" fill="#a9a9a3"/><circle cx="125" cy="120" r="24" fill="#b2b2ac"/><circle cx="120" cy="60" r="10" fill="#9f9f99"/></svg>';
const ID_TOKEN = "x." + Buffer.from(JSON.stringify({ id: ROSE.id })).toString("base64").replace(/=+$/, "") + ".y";
// a 20 s silent mono WAV (16-bit, 8 kHz; long enough to be playing when read), served at /__hq1/tone.wav for the boombox's track
const TONE = (() => { const n = 160000, b = Buffer.alloc(44 + n * 2); b.write("RIFF", 0); b.writeUInt32LE(36 + n * 2, 4); b.write("WAVEfmt ", 8); b.writeUInt32LE(16, 16);
  b.writeUInt16LE(1, 20); b.writeUInt16LE(1, 22); b.writeUInt32LE(8000, 24); b.writeUInt32LE(16000, 28); b.writeUInt16LE(2, 32); b.writeUInt16LE(16, 34); b.write("data", 36); b.writeUInt32LE(n * 2, 40); return b; })();
function api(method, u, request) {
  const p = u.pathname;
  if (FX3) { const a = fx3Api(method, u, request); if (a !== undefined) return a; }   // NAMED (Nov 22 2026, FX3)
  if (P23 && FX2S.on && !FX2S.inner) { const a = fx2Api(method, u, request); if (a !== undefined) return a; }   // NAMED (Nov 21 2026, FX2)
  // NAMED (Nov 20 2026, P3-1): with PHONE_P31=1, a free account's /api/auth/me and Resend email first (p31Api); then P2-3's posts and P2-1's fixtures
  if (P31) { const a = p31Api(method, p); if (a !== undefined) return a; }
  // NAMED (Nov 21 2026, P3-2): with PHONE_P32=1, the profile and the storefront carry the server's verified field (p32Api)
  if (P32) { const a = p32Api(method, p); if (a !== undefined) return a; }
  // NAMED (Nov 23 2026, P3-3): with PHONE_P33=1, P3-3's fixtures (p33Api), then P2-3's posts and P2-1's fixtures
  if (P33) { const a = p33Api(method, u, request); if (a !== undefined) return a; }
  // NAMED (Nov 23 2026, P3-3): the one category list (GET /api/categories) for the runs that post (the composer requires a category); the rows lib/categories.js answers
  if ((P23 || P31 || P32) && p === "/api/categories") return { categories: P33_CATS };
  const since = "2026-11-07T10:00:00Z";
  // NAMED (Nov 20 2026, P3-1): access.tier "member" and email_verified true (Rose is a member with a confirmed email): no panel, no banner
  if (p === "/api/auth/me") return { user: ROSE, access: { active: true, reason: "subscription", tier: "member", email_verified: true }, subscription: { status: "active", plan: "all_access", current_period_end: ago(-24 * 20), cancel_at_period_end: false } };
  if (p === "/api/auth/refresh") return { token: "phone-check-token", refresh_token: "phone-check-refresh", user: ROSE };
  if (p === "/api/dashboard/top") return topBody();
  if (p === "/api/dashboard/pulse") return { generated_at: new Date(NOW).toISOString(), since: new Date(NOW).toISOString(), running: [], events: [], links: ["grow|sell", "grow|connect", "grow|agents", "sell|connect", "sell|agents", "connect|agents"], _unreadable: [], cached: false };
  if (p === "/api/command-center") return centerBody();
  if (p === "/api/agents") return { agents: AGENTS };
  if (p === "/api/ai/tasks" && method === "GET") { const type = u.searchParams.get("agent_type") || u.searchParams.get("agent"); return { tasks: type ? RUNS.filter(r => r.agent_type === type) : RUNS }; }
  if (/^\/api\/ai\/tasks\/[^/]+$/.test(p)) return { task: RUNS.find(r => r.id === p.split("/").pop()) || RUNS[0] };
  if (p === "/api/proposals") { const st = u.searchParams.get("status"); return { proposals: st ? PROPOSALS.filter(x => x.status === st) : PROPOSALS }; }
  if (p === "/api/analytics/summary") return { stats: { tasksRun: 48, tasksCompleted: 45, contentItems: 23, subscribers: 312, optedIn: 287, campaigns: 4, blogItems: 12, smsItems: 9 } };
  if (p === "/api/store/connections" && method === "GET") return { connections: [STORE], shopify_available: true, etsy_available: true, amazon_available: true, amazon_draft: false };
  if (p === "/api/store/changes") return { changes: [] };
  if (p === "/api/inventory/items" && method === "GET") { const limit = Number(u.searchParams.get("limit") || 25), offset = Number(u.searchParams.get("offset") || 0); return { items: ITEMS.slice(offset, offset + limit), limit, offset, has_more: offset + limit < ITEMS.length }; }
  if (p === "/api/youtube/status") return { youtube_available: true, connected: true, status: "connected", channel_title: "Maple Street", since };
  if (p === "/api/tiktok/status") return { tiktok_available: true, connected: true, status: "connected", display_name: "Maple Street", since };
  if (p === "/api/instagram/status") return { instagram_available: true, connected: true, status: "connected", username: "maplestreet", since };
  if (p === "/api/facebook/status") return { facebook_available: true, connected: true, status: "connected", page_name: "Maple Street", since };
  if (p === "/api/videos" && method === "GET") return { videos: VIDEOS, max_bytes: 524288000, ready_max: 2 };
  if (p === "/api/media") return { media: [] };
  if (p === "/api/instagram/posts" || p === "/api/facebook/posts") return { posts: [] };
  if (p === "/api/tiktok/creator-info") return { creator_nickname: "Maple Street Bakery", privacy_level_options: ["PUBLIC_TO_EVERYONE", "MUTUAL_FOLLOW_FRIENDS", "SELF_ONLY"], comment_disabled: false, duet_disabled: false, stitch_disabled: false, max_video_post_duration_sec: 600 };
  if (p === "/api/business-profile") return { profile: { business_name: "Maple Street Bakery", industry: "Bakery", city: "Portland", website: "https://maplestreet.example" } };
  // NAMED (Nov 19 2026, HQ1): with PHONE_HQ1=1 the preferences remember hq_card_view and hq_orbit (a PUT sets them, null
  // clears them), GET /api/moon answers the fixture MOON, and the music library holds one short track. BEFORE (and still
  // without PHONE_HQ1): preferences answered {} and nothing else, so the 77-page run and its desktop baseline are unchanged.
  if (HQ1 && p === "/api/user/preferences") {
    if (method === "PUT") { let b = {}; try { b = JSON.parse((request && request.postData) || "{}"); } catch (e) { b = {}; } HQS.puts.push(b);
      if ("hq_card_view" in b) HQS.view = b.hq_card_view; if ("hq_orbit" in b) HQS.orbit = b.hq_orbit; return { saved: true }; }
    return { ok: true, preferences: {}, termaximus_active: true, hq_card_view: HQS.view, hq_orbit: HQS.orbit };
  }
  if (HQ1 && p === "/api/moon") { HQS.moonAsks++; return MOON; }
  if (HQ1 && p === "/api/music") return { tracks: [{ id: "c1000000-0000-4000-8000-000000000001", title: "Check Tone", artist: "Phone Check", duration: 4, bytes: 35324 }], playlists: [], used_bytes: 35324, cap_bytes: 1073741824 };
  if (HQ1 && /^\/api\/music\/tracks\/[^/]+\/url$/.test(p)) return { url: ORIGIN + "/__hq1/tone.wav", expires_at: new Date(Date.now() + 3600e3).toISOString() };
  // NAMED (Nov 19 2026, P2-1): with PHONE_P21=1, Home, the Inbox, the profile and Settings, Local answer the fixtures
  // above (p21Api). Without it every one of them answers {} as before, so the page runs and their baselines are unchanged.
  // NAMED (Nov 20 2026, P2-2): with PHONE_P22=1, P2-2's fixtures (p22Api), then P2-1's (the Inbox thread needs them).
  if (P22) { const a = p22Api(method, p); if (a !== undefined) return a; }
  // NAMED (Nov 20 2026, P2-3): with PHONE_P23=1, posts, the feed, comments and follows are lib/posts.js over P23S.db
  // (p23Api, a promise; the request handler awaits every answer), then P2-1's fixtures (the profile, the counts).
  if ((P23 || P31 || P32 || P33) && P23_IS(p)) return p23Api(method, u, request);   // NAMED (Nov 21 2026, P3-2): and PHONE_P32. NAMED (Nov 23 2026, P3-3): and PHONE_P33
  if (P23) { const a = fx1Api(method, p); if (a !== undefined) return a; }   // NAMED (Nov 20 2026, FX1)
  if (P21 || P22 || P23 || P31 || P32 || P33) { const a = p21Api(method, p); if (a !== undefined) return a; }   // NAMED (Nov 21 2026, P3-2): and PHONE_P32. NAMED (Nov 23 2026, P3-3): and PHONE_P33
  if (p === "/api/user/preferences") return { ok: true, preferences: {} };
  if (method !== "GET") return { ok: true };
  return {};
}

/* ── a small static server over the frontend ── */
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json",
  ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".webp": "image/webp", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".woff2": "font/woff2", ".mp3": "audio/mpeg", ".pdf": "application/pdf" };
function serve() {
  const root = path.resolve(FRONTEND);
  const server = http.createServer((req, res) => {
    let p;
    try { p = decodeURIComponent(new URL(req.url, "http://x").pathname); } catch (e) { res.writeHead(400); res.end(); return; }
    if (p === "/__hq1/tone.wav") { res.writeHead(200, { "Content-Type": "audio/wav", "Content-Length": TONE.length, "Cache-Control": "no-store" }); res.end(TONE); return; }   // HQ1
    if (p.endsWith("/")) p += "index.html";
    // NAMED (Nov 20 2026, P2-3): /p/<id> is the backend's page (lib/postPage.js over P23S.db), as _redirects proxies it
    if ((P23 || P32 || P31) && /^\/p\/[^/]+$/.test(p)) {   // NAMED (Nov 21 2026, P3-2): and PHONE_P32. NAMED (Nov 21 2026, P3-1B): and PHONE_P31
      p23PostPage(p.slice(3)).then(r => { res.writeHead(r.code, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }); res.end(r.html); },
        e => { res.writeHead(500); res.end(String(e && e.message)); });
      return;
    }
    if (P21 || P23 || P32) p = p21Rewrite(p);   // NAMED (Nov 21 2026, P3-2): and PHONE_P32   // P2-1: /@handle, /listing/:id, /blog/... as the site rewrites them
    let file = path.resolve(root, "." + p);
    if (!fs.existsSync(file) && fs.existsSync(file + ".html")) file += ".html";
    if (!file.startsWith(root) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end("not found"); return; }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(file).toLowerCase()] || "application/octet-stream", "Cache-Control": "no-store" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise(r => server.listen(0, "127.0.0.1", () => r(server)));
}

/* ── Chrome over the DevTools Protocol ── */
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function launch() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bf-phone-"));
  const proc = spawn(CHROME, ["--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + profile, "--no-first-run", "--no-default-browser-check",
    "--disable-gpu", "--disable-extensions", "--mute-audio", "--hide-scrollbars", "about:blank"], { stdio: "ignore" });
  const portFile = path.join(profile, "DevToolsActivePort");
  for (let i = 0; i < 150 && !fs.existsSync(portFile); i++) await sleep(100);
  if (!fs.existsSync(portFile)) throw new Error("Chrome did not open its debugging port");
  let port = "";
  for (let i = 0; i < 50 && !/^\d+$/.test(port); i++) { try { port = fs.readFileSync(portFile, "utf8").split("\n")[0].trim(); } catch (e) { /* still being written */ } if (!/^\d+$/.test(port)) await sleep(100); }
  let list = [];
  for (let i = 0; i < 50 && !list.some(t => t.type === "page"); i++) { try { list = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json(); } catch (e) { /* not yet */ } await sleep(100); }
  const target = list.find(t => t.type === "page");
  if (!target) throw new Error("Chrome opened no page");
  return { proc, profile, ws: target.webSocketDebuggerUrl };
}
function connect(url) {
  const ws = new WebSocket(url);
  let id = 0; const waiting = new Map(), handlers = [];
  ws.onmessage = ev => {
    const msg = JSON.parse(typeof ev.data === "string" ? ev.data : Buffer.from(ev.data).toString("utf8"));
    if (msg.id && waiting.has(msg.id)) { const w = waiting.get(msg.id); waiting.delete(msg.id); if (msg.error) w.reject(new Error(msg.error.message)); else w.resolve(msg.result); }
    else if (msg.method) handlers.forEach(h => h(msg));
  };
  const send = (method, params) => new Promise((resolve, reject) => { const n = ++id; waiting.set(n, { resolve, reject }); ws.send(JSON.stringify({ id: n, method, params: params || {} })); });
  return new Promise((resolve, reject) => { ws.onopen = () => resolve({ send, on: h => handlers.push(h), close: () => ws.close() }); ws.onerror = reject; });
}
async function evaluate(cdp, expr) {
  const r = await cdp.send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error("page threw: " + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text));
  return r.result.value;
}

/* The owner signed in, a seeded Math.random, and (desktop) animations paused from the first paint. */
const SEED = "try{if(!sessionStorage.getItem('phone_check_out')){localStorage.setItem('bf_token','phone-check-token');localStorage.setItem('bf_user'," + J(J(ROSE)) + ");}}catch(e){}" +
  "(function(){var s=20261119;Math.random=function(){s=(s*1664525+1013904223)>>>0;return s/4294967296;};})();" +
  "(function(){var R=Date,start=R.now(),base=" + NOW + ";function now(){return base+(R.now()-start);}" +
  "function D(){var a=[].slice.call(arguments);if(!(this instanceof D))return new R(now()).toString();return a.length?new (Function.prototype.bind.apply(R,[null].concat(a)))():new R(now());}" +
  "D.prototype=R.prototype;D.now=now;D.UTC=R.UTC;D.parse=R.parse;window.Date=D;})();";
const PAUSE = "(function(){var css='*,*::before,*::after{animation-play-state:paused!important;transition:none!important}';" +
  "function put(){var r=document.documentElement;if(!r)return false;var s=document.createElement('style');s.setAttribute('data-phone-check','pause');s.textContent=css;r.appendChild(s);return true;}" +
  "if(!put()){new MutationObserver(function(m,o){if(put())o.disconnect();}).observe(document,{childList:true});}})();";

/* ── page-side measures ── */
// One sweep of the page at the current scroll: returns every defect kind STEP 1 lists.
const MEASURE = String.raw`(function(){
  var W = innerWidth, H = innerHeight, out = {};
  function shown(n){ for (var e = n; e && e.nodeType === 1; e = e.parentElement) { var c = getComputedStyle(e); if (c.display === "none" || c.visibility === "hidden" || c.opacity === "0") return false; } return true; }
  function name(n){ var c = n.className && n.className.baseVal !== undefined ? n.className.baseVal : n.className; return n.tagName.toLowerCase() + (n.id ? "#" + n.id : "") + (c ? "." + String(c).trim().split(/\s+/).slice(0, 2).join(".") : ""); }
  function txt(n){ return (n.innerText || n.textContent || "").replace(/\s+/g, " ").trim().slice(0, 40); }
  function ownText(n){ for (var c = n.firstChild; c; c = c.nextSibling) if (c.nodeType === 3 && c.nodeValue.trim()) return true; return false; }
  function box(r){ return Math.round(r.left) + "," + Math.round(r.top + scrollY) + " " + Math.round(r.width) + "x" + Math.round(r.height); }
  var all = [].slice.call(document.querySelectorAll("body *"));
  var vis = all.filter(function(n){ var r = n.getBoundingClientRect(); return r.width > 0 && r.height > 0 && shown(n); });
  // 1. horizontal scroll
  out.hscroll = document.documentElement.scrollWidth > W + 1 ? document.documentElement.scrollWidth : 0;
  out.wide = out.hscroll ? vis.filter(function(n){ var r = n.getBoundingClientRect(); if (r.right <= W + 1) return false;
    for (var e = n; e && e.nodeType === 1; e = e.parentElement) if (getComputedStyle(e).position === "fixed") return false;
    for (var p = n.parentElement; p && p !== document.body; p = p.parentElement) { var cs = getComputedStyle(p); if (/auto|scroll|hidden|clip/.test(cs.overflowX) && p.getBoundingClientRect().right <= W + 1) return false; }
    return true; }).slice(0, 5).map(function(n){ return name(n) + " " + box(n.getBoundingClientRect()); }) : [];
  // 2. text cut off: an ellipsis, a line clamp, or own text clipped by its own box
  out.clipped = vis.filter(function(n){ var c = getComputedStyle(n), r = n.getBoundingClientRect(); if (r.width < 3 || r.height < 3) return false;
    if (n.closest("svg") || !txt(n)) return false;
    var ell = c.textOverflow === "ellipsis" && /hidden|clip/.test(c.overflowX) && n.scrollWidth > n.clientWidth + 1;
    var clampd = c.webkitLineClamp && c.webkitLineClamp !== "none" && n.scrollHeight > n.clientHeight + 2;
    if (ell || clampd) return true;
    if (!ownText(n)) return false;
    var clipX = /hidden|clip/.test(c.overflowX) && n.scrollWidth > n.clientWidth + 1;
    var clipY = /hidden|clip/.test(c.overflowY) && n.scrollHeight > n.clientHeight + 2 && c.position !== "absolute";
    if (clipX || clipY) return true;
    // clipped by an ancestor's hidden overflow (a scrolling container is not a clip)
    for (var p = n.parentElement; p && p !== document.body; p = p.parentElement) { var pc = getComputedStyle(p);
      if (/auto|scroll/.test(pc.overflowX)) break;
      if (/hidden|clip/.test(pc.overflowX)) { var pr = p.getBoundingClientRect(); if (pr.width > 2 && (r.left < pr.left - 1 || r.right > pr.right + 1)) return true; break; } }
    return false; }).slice(0, 12).map(function(n){ return name(n) + " \"" + txt(n) + "\""; });
  // 3. fixed or floating elements over text or controls (at this scroll)
  var TAPSEL = "a[href],button,input:not([type=hidden]),select,textarea,[role=button],[role=tab],[role=switch],summary,[tabindex]:not([tabindex='-1'])";
  var fixed = vis.filter(function(n){ var c = getComputedStyle(n); if (c.position !== "fixed" && c.position !== "sticky") return false; if (c.pointerEvents === "none") return false;
    var r = n.getBoundingClientRect(); if (r.width * r.height > W * H * 0.5) return false; if (r.bottom <= 0 || r.top >= H) return false;
    var p = n.parentElement; while (p && p !== document.body) { var pc = getComputedStyle(p); if (pc.position === "fixed" || pc.position === "sticky") return false; p = p.parentElement; } return true; });
  out.over = [];
  fixed.forEach(function(f){ var fr = f.getBoundingClientRect(), fc = getComputedStyle(f);
    var hits = vis.filter(function(n){ if (f.contains(n) || n.contains(f)) return false; var c = getComputedStyle(n); if (c.position === "fixed" || c.position === "sticky") return false;
      var inFixed = false; for (var e = n.parentElement; e && e !== document.body; e = e.parentElement) { var ec = getComputedStyle(e); if (ec.position === "fixed" || ec.position === "sticky") { inFixed = true; break; } } if (inFixed) return false;
      if (!(ownText(n) || n.matches(TAPSEL) || /^H[1-6]$/.test(n.tagName))) return false;
      var r = n.getBoundingClientRect(); if (r.width < 2 || r.height < 2) return false;
      var ix = Math.min(r.right, fr.right) - Math.max(r.left, fr.left), iy = Math.min(r.bottom, fr.bottom) - Math.max(r.top, fr.top);
      if (ix <= 1 || iy <= 1) return false;
      // painted over it? the floating element must win the hit test at the shared area's centre
      var x = (Math.max(r.left, fr.left) + Math.min(r.right, fr.right)) / 2, y = (Math.max(r.top, fr.top) + Math.min(r.bottom, fr.bottom)) / 2;
      var top = document.elementFromPoint(x, y); return !!top && f.contains(top); });
    if (hits.length) out.over.push(name(f) + " " + (fc.position) + " over " + hits.slice(0, 3).map(function(n){ return name(n) + " \"" + txt(n).slice(0, 20) + "\""; }).join(", ")); });
  // 4. tap targets under 44 x 44
  out.small = [];
  vis.filter(function(n){ return n.matches(TAPSEL); }).forEach(function(n){
    var t = n, r;
    if (n.tagName === "INPUT" && /checkbox|radio/.test(n.type)) { t = n.closest("label") || (n.id && document.querySelector("label[for='" + n.id + "']")) || n; }
    r = t.getBoundingClientRect();
    if (r.right < 0 || r.left > document.documentElement.scrollWidth) return;
    var c = getComputedStyle(n); if (c.opacity === "0" && t === n) return;
    if (r.width <= 2 || r.height <= 2) return;
    // NAMED (Nov 22 2026, FX3): the Guide's tab, now on the phone too, is the owner's board's 32 x 170 (the desktop's look,
    // drawn at every width); PHONE_FX3 holds it to that size. Every control inside its panel is still held to 44.
    if (n.id === "tmx-guide-tab") return;
    if (n.tagName === "A" && c.display === "inline") { var par = n.parentElement; var pt = (par.innerText || "").replace(/\s+/g, " ").trim(); var lt = (n.innerText || "").replace(/\s+/g, " ").trim(); if (pt.length > lt.length + 8) return; }
    if (r.width < 44 - 0.5 || r.height < 44 - 0.5) out.small.push(name(t) + " \"" + txt(t).slice(0, 18) + "\" " + Math.round(r.width) + "x" + Math.round(r.height));
  });
  out.smallCount = out.small.length; out.small = out.small.slice(0, 15);
  // 5. decoration painted over text
  var DECO = /star|nebula|glow|spark|cosmic|galaxy|aurora|particle|twinkle|halo|orb-bg|backdrop|sky/i;
  // NAMED (Nov 22 2026, FX3): BEFORE the Termaximus mist sat under the page on a phone, as decoration. AFTER it is a 56 px
  // button above the page (like the bar), so its own glows and sparkles are the button's face, not decoration over text.
  var decos = vis.filter(function(n){ var c = getComputedStyle(n); var nm = String(n.id) + " " + String(n.className && n.className.baseVal !== undefined ? n.className.baseVal : n.className);
    if (n.closest && n.closest("#tmx-presence-root")) return false;
    return (n.tagName === "CANVAS" || DECO.test(nm)) && (c.position === "fixed" || c.position === "absolute") && !n.matches(TAPSEL) && !ownText(n) && !n.querySelector(TAPSEL); });
  var texts = vis.filter(function(n){ return ownText(n) && !n.closest("svg"); });
  out.deco = [];
  decos.forEach(function(d){ var dr = d.getBoundingClientRect(); if (dr.bottom <= 0 || dr.top >= H) return; var old = d.style.pointerEvents; d.style.setProperty("pointer-events", "auto", "important");
    var cover = texts.filter(function(n){ if (d.contains(n)) return false; var r = n.getBoundingClientRect(); if (r.bottom <= 0 || r.top >= H) return false;
      var x = Math.max(r.left, dr.left), x2 = Math.min(r.right, dr.right), y = Math.max(r.top, dr.top), y2 = Math.min(r.bottom, dr.bottom); if (x2 - x < 2 || y2 - y < 2) return false;
      var st = document.elementsFromPoint((x + x2) / 2, (y + y2) / 2); var di = -1, ni = -1;
      for (var i = 0; i < st.length; i++) { if (di < 0 && (st[i] === d || d.contains(st[i]))) di = i; if (ni < 0 && (st[i] === n || n.contains(st[i]))) ni = i; }
      return di >= 0 && ni >= 0 && di < ni; });
    d.style.pointerEvents = old;
    if (cover.length) out.deco.push(name(d) + " over " + cover.slice(0, 3).map(function(n){ return name(n) + " \"" + txt(n).slice(0, 20) + "\""; }).join(", ")); });
  // 6. empty gaps over 48 px inside a card
  out.gaps = [];
  vis.filter(function(n){ var nm = String(n.className && n.className.baseVal !== undefined ? n.className.baseVal : n.className); if (!/card|panel|tile|box|bf-section/i.test(nm)) return false;
    var c = getComputedStyle(n); var r = n.getBoundingClientRect(); if (r.height < 60 || r.width < 120) return false; if (n.closest("svg")) return false;
    return (c.backgroundColor !== "rgba(0, 0, 0, 0)" || c.backgroundImage !== "none" || parseFloat(c.borderTopWidth) > 0); }).forEach(function(card){
    var cr = card.getBoundingClientRect(), cc = getComputedStyle(card);
    // a display:contents child stands for its own children
    var flat = []; (function add(list){ [].forEach.call(list, function(k){ if (getComputedStyle(k).display === "contents") add(k.children); else flat.push(k); }); })(card.children);
    var kids = flat.filter(function(k){ var r = k.getBoundingClientRect(), c = getComputedStyle(k); return r.width > 0 && r.height > 0 && shown(k) && c.position !== "absolute" && c.position !== "fixed"; })
      .map(function(k){ return k.getBoundingClientRect(); }).sort(function(a, b){ return a.top - b.top; });
    if (!kids.length) return;
    var top = cr.top + parseFloat(cc.borderTopWidth), bottom = cr.bottom - parseFloat(cc.borderBottomWidth);
    var gaps = [], end = kids[0].top - top; if (end > 48) gaps.push("top " + Math.round(end));
    var reach = kids[0].bottom; for (var i = 1; i < kids.length; i++) { var g = kids[i].top - reach; if (g > 48) gaps.push(Math.round(g)); reach = Math.max(reach, kids[i].bottom); }
    if (bottom - reach > 48) gaps.push("bottom " + Math.round(bottom - reach));
    if (gaps.length) out.gaps.push(name(card) + " [" + gaps.join(",") + "]"); });
  out.gaps = out.gaps.slice(0, 10);
  return out;
})()`;

// Every visible element's box (document coordinates), measured twice 700 ms apart; one that moved is set aside.
const BOXES = String.raw`new Promise(function(done){
  function shown(n){ for (var e = n; e && e.nodeType === 1; e = e.parentElement) { var c = getComputedStyle(e); if (c.display === "none" || c.visibility === "hidden") return false; } return true; }
  var els = [].slice.call(document.querySelectorAll("body, body *")).filter(function(n){ return n.tagName !== "SCRIPT" && n.tagName !== "STYLE" && !n.closest("[data-phone-check]"); });
  function own(n){ var s = ""; for (var c = n.firstChild; c; c = c.nextSibling) if (c.nodeType === 3) s += c.nodeValue; return s.replace(/\s+/g, " ").trim().slice(0, 24); }
  function take(){ return els.map(function(n){ if (!n.isConnected || !shown(n)) return null; var r = n.getBoundingClientRect(); if (!(r.width > 0 || r.height > 0)) return null;
    return [Math.round((r.left + scrollX) * 10) / 10, Math.round((r.top + scrollY) * 10) / 10, Math.round(r.width * 10) / 10, Math.round(r.height * 10) / 10]; }); }
  var a = take();
  setTimeout(function(){ var b = take(), list = [];
    els.forEach(function(n, i){ if (!a[i] && !b[i]) return; var key = n.tagName.toLowerCase() + "|" + (n.id || "") + "|" + own(n).replace(/[0-9]/g, "#");
      // decoration: inside an aria-hidden overlay, or a fixed layer that takes no tap (the Termaximus mist)
      var deco = false; for (var q = n; q && q.nodeType === 1; q = q.parentElement) { var qc = getComputedStyle(q); if (qc.position === "fixed" && qc.pointerEvents === "none") { deco = true; break; } }
      for (var e = n; e && e.nodeType === 1; e = e.parentElement) { if (e.getAttribute("aria-hidden") === "true") { for (var f = e; f && f.nodeType === 1; f = f.parentElement) { var fp = getComputedStyle(f).position; if (fp === "fixed" || fp === "absolute") { deco = true; break; } } break; } }
      var moving = !a[i] || !b[i] || a[i].some(function(v, k){ return Math.abs(v - b[i][k]) > 0.5; });
      list.push([key, b[i] || a[i], moving || deco ? 1 : 0]); });
    done({ w: innerWidth, h: document.documentElement.scrollHeight, list: list }); }, 700);
})`;

/* ── open a page at a size ── */
async function open(cdp, origin, page, w, h, phone) {
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: phone ? 2 : 1, mobile: phone, screenWidth: w, screenHeight: h });
  await cdp.send("Emulation.setTouchEmulationEnabled", { enabled: phone, maxTouchPoints: phone ? 5 : 1 });
  await cdp.send("Emulation.setUserAgentOverride", { userAgent: phone ? IPHONE_UA : DESK_UA, platform: phone ? "iPhone" : "Win32" });
  await cdp.send("Page.navigate", { url: "about:blank" });
  await sleep(120);
  await cdp.send("Page.navigate", { url: origin + "/" + page });
  for (let i = 0; i < 80; i++) { try { if (await evaluate(cdp, "document.readyState === 'complete'")) break; } catch (e) { /* navigating */ } await sleep(100); }
  await sleep(phone ? 1600 : 1800);
}
async function shotPage(cdp, file, w) {
  const hgt = await evaluate(cdp, "Math.min(document.documentElement.scrollHeight, 9000)");
  const r = await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width: w, height: hgt, scale: 1 } });
  fs.writeFileSync(file, Buffer.from(r.data, "base64"));
}
let DESK_UA = "";
let exceptionsSeen = () => [];   // NAMED (Nov 22 2026, FX3)

/* ── the dashboard's own checks (PH1) ── */
const ORBIT = String.raw`(function(){
  var core = document.getElementById("orbitCore"), stage = document.getElementById("orbitStage");
  var cr = core ? core.getBoundingClientRect() : null, sr = stage ? stage.getBoundingClientRect() : null;
  var ps = [].slice.call(document.querySelectorAll(".orbit-portal[data-portal]")).map(function(b){ var disc = b.querySelector(".orbit-disc"), lab = b.querySelector(".orbit-portal-name");
    var r = disc.getBoundingClientRect(), lr = lab.getBoundingClientRect(), lc = getComputedStyle(lab);
    return { name: b.getAttribute("data-portal"), cx: r.left + r.width / 2, cy: r.top + r.height / 2, w: r.width, h: r.height, label: lab.textContent.trim(),
      labelFull: lab.scrollWidth <= lab.clientWidth + 1 && lab.scrollHeight <= lab.clientHeight + 1 && lc.textOverflow !== "ellipsis" && !/hidden|clip/.test(lc.overflowX),
      labelIn: lr.left >= -0.5 && lr.right <= innerWidth + 0.5, lbox: [lr.left, lr.top, lr.right, lr.bottom] }; });
  var hit = function(a, b){ return a[0] < b[2] - 0.5 && a[2] > b[0] + 0.5 && a[1] < b[3] - 0.5 && a[3] > b[1] + 0.5; };
  var clash = [];
  ps.forEach(function(p, i){ ps.forEach(function(q, j){ if (j > i && hit(p.lbox, q.lbox)) clash.push(p.name + "/" + q.name); });
    if (cr && hit(p.lbox, [cr.left, cr.top, cr.right, cr.bottom])) clash.push(p.name + "/core"); });
  var below = document.querySelector(".orbit-below"), goal = document.getElementById("orbitGoalSet"), week = document.querySelector(".orbit-week");
  var br = below ? below.getBoundingClientRect() : null;
  return { core: cr ? { cx: cr.left + cr.width / 2, cy: cr.top + cr.height / 2, w: cr.width } : null, portals: ps, clash: clash,
    stageTop: sr ? Math.round(sr.top - document.getElementById("orbitPanel").getBoundingClientRect().top) : null,
    topGap: sr && ps.length ? Math.round(Math.min.apply(null, ps.map(function(p){ return p.cy - p.h / 2; })) - sr.top) : null,
    below: br ? { y: Math.round(br.top), w: Math.round(br.width), panelW: Math.round(document.getElementById("orbitPanel").clientWidth), stageBottom: Math.round(sr.bottom) } : null,
    goalIn: !!(goal && below && below.contains(goal)), goalH: goal ? Math.round(goal.getBoundingClientRect().height) : 0, week: week ? week.textContent : null,
    hscroll: document.documentElement.scrollWidth - innerWidth };
})()`;

(async () => {
  for (const d of ["before", "after"]) fs.mkdirSync(path.join(OUT, d), { recursive: true });
  const server = await serve();
  const origin = "http://127.0.0.1:" + server.address().port;
  const chrome = await launch();
  let cdp;
  const defects = {}, boxes = {};
  const exceptions = [];
  exceptionsSeen = () => exceptions.slice();   // NAMED (Nov 22 2026, FX3): fx3Run reads the page errors
  let currentPage = "";
  try {
    cdp = await connect(chrome.ws);
    cdp.on(async msg => {
      if (msg.method === "Runtime.exceptionThrown") { const d = msg.params.exceptionDetails; exceptions.push(currentPage + ": " + ((d.exception || {}).description || d.text).split("\n")[0]); return; }
      if (msg.method !== "Fetch.requestPaused") return;
      const { requestId, request } = msg.params;
      let u; try { u = new URL(request.url); } catch (e) { return; }
      try {
        if (u.origin === origin || u.protocol === "data:" || u.protocol === "blob:") await cdp.send("Fetch.continueRequest", { requestId });
        else if (u.hostname === API_HOST) {
          // NAMED (Nov 20 2026, P2-2): an answer may carry its own status ({ __status, __body }: moderation.html for a
          // member who is not the owner); every other answer is 200 as before.
          // NAMED (Nov 20 2026, P2-3): awaited (PHONE_P23's answers are promises; every other answer is a value, as before)
          const ans = request.method === "OPTIONS" ? "" : await api(request.method, u, request);
          const code = ans && ans.__status ? ans.__status : 200;
          const body = ans === "" ? "" : J(ans && ans.__status ? ans.__body : ans);
          await cdp.send("Fetch.fulfillRequest", { requestId, responseCode: code, body: Buffer.from(body).toString("base64"),
            responseHeaders: [{ name: "Content-Type", value: "application/json" }, { name: "Access-Control-Allow-Origin", value: "*" },
              { name: "Access-Control-Allow-Headers", value: "*" }, { name: "Access-Control-Allow-Methods", value: "GET,POST,PUT,PATCH,DELETE,OPTIONS" }] });
        } else if ((P23 || P32) && u.origin === P23_STORAGE) {   // NAMED (Nov 21 2026, P3-2): and PHONE_P32
          // NAMED (Nov 20 2026, P2-3): a post's photos, the frontend's own brand pictures
          const pic = P21_IMG[(u.pathname.length % P21_IMG.length)];
          await cdp.send("Fetch.fulfillRequest", { requestId, responseCode: 200, body: fs.readFileSync(path.join(FRONTEND, pic)).toString("base64"),
            responseHeaders: [{ name: "Content-Type", value: "image/png" }, { name: "Access-Control-Allow-Origin", value: "*" }] });
        } else if ((HQ1 || FX3) && request.url === MOON_PHOTO) {   // NAMED (Nov 22 2026, FX3): and PHONE_FX3
          // HQ1: the Oracle's moon photo (Wikimedia) answered by a stand-in disc, so the moon draws with no outside request
          await cdp.send("Fetch.fulfillRequest", { requestId, responseCode: 200, body: Buffer.from(MOON_STANDIN).toString("base64"),
            responseHeaders: [{ name: "Content-Type", value: "image/svg+xml" }, { name: "Access-Control-Allow-Origin", value: "*" }] });
        } else await cdp.send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
      } catch (e) { /* the page moved on */ }
    });
    await cdp.send("Fetch.enable", { patterns: [{ urlPattern: "*" }] });
    await cdp.send("Runtime.enable");
    await cdp.send("Page.enable");
    await cdp.send("Network.enable");
    await cdp.send("Network.setBypassServiceWorker", { bypass: true });
    DESK_UA = (await cdp.send("Browser.getVersion")).userAgent.replace("HeadlessChrome", "Chrome");
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: SEED });

    const baselineFile = n => path.join(OUT, "desktop-baseline-" + n + ".json");
    let baseline = null;
    if (MODE === "check") {
      baseline = {};
      fs.readdirSync(OUT).filter(f => /^desktop-baseline-.*\.json$/.test(f)).forEach(f => Object.assign(baseline, JSON.parse(fs.readFileSync(path.join(OUT, f), "utf8"))));
    }

    ORIGIN = origin;
    if (HQ1) { await hq1Run(cdp, origin); PAGES = []; }
    else if (P21) { await p21Run(cdp, origin); PAGES = []; }
    else if (P22) { await p22Run(cdp, origin); PAGES = []; }   // NAMED (Nov 20 2026, P2-2)
    else if (P23) { await p23Run(cdp, origin); PAGES = []; }   // NAMED (Nov 20 2026, P2-3)
    else if (P31) { await p31Run(cdp, origin); PAGES = []; }   // NAMED (Nov 20 2026, P3-1)
    else if (P32) { await p32Run(cdp, origin); PAGES = []; }   // NAMED (Nov 21 2026, P3-2)
    else if (FX3) { await fx3Run(cdp, origin); PAGES = []; }   // NAMED (Nov 22 2026, FX3)
    else if (P33) { await p33Run(cdp, origin); PAGES = []; }   // NAMED (Nov 23 2026, P3-3)
    else console.log("browserCheckPhone (" + MODE + ", batch " + BATCH + ", " + PAGES.length + " pages)");
    for (const page of PAGES) {
      currentPage = page;
      console.log("\n  " + page);
      defects[page] = {};
      for (const [w, h] of PHONES) {
        await open(cdp, origin, page, w, h, true);
        const atRest = await evaluate(cdp, "scrollTo(0,0)," + MEASURE);
        await shotPage(cdp, path.join(OUT, MODE === "before" ? "before" : "after", fileOf(page, w, h)), w);
        await evaluate(cdp, "scrollTo(0,document.documentElement.scrollHeight),true");
        await sleep(350);
        const atEnd = await evaluate(cdp, MEASURE);
        const d = { hscroll: atRest.hscroll, wide: atRest.wide, clipped: atRest.clipped, overAtRest: atRest.over, overAtEnd: atEnd.over,
          small: atRest.small, smallCount: atRest.smallCount, deco: atRest.deco.concat(atEnd.deco.filter(x => atRest.deco.indexOf(x) === -1)), gaps: atRest.gaps };
        defects[page][w] = d;
        if (MODE === "before") {
          const n = (d.hscroll ? 1 : 0) + d.clipped.length + d.overAtRest.length + d.overAtEnd.length + d.smallCount + d.deco.length + d.gaps.length;
          console.log("    " + w + ": " + n + " finding(s)" + (d.hscroll ? ", scrolls sideways to " + d.hscroll : ""));
        } else {
          const at = page + " at " + w + ": ";
          check(at + "no horizontal scroll", !d.hscroll, J(d.wide));
          check(at + "no text cut off (ellipsis or clipped)", d.clipped.length === 0, J(d.clipped));
          // NAMED (Nov 19 2026, P2-1): the bottom bar, like the Guide, floats over the scrolling page by design: judged at the end
          const restOver = d.overAtRest.filter(x => !/^(div#tmx-presence-root|nav#bf-tabbar) /.test(x));
          check(at + "no fixed element over a heading, text, button or link (the Guide at the end of the page, every other one at rest too)", restOver.length === 0 && d.overAtEnd.length === 0, J(restOver.concat(d.overAtEnd)));
          check(at + "every tap target is at least 44 x 44", d.smallCount === 0, d.smallCount + " " + J(d.small));
          check(at + "decoration is under the text", d.deco.length === 0, J(d.deco));
          check(at + "no empty gap over 48 px inside a card", d.gaps.length === 0, J(d.gaps));
          await barChecks(cdp, page, w);   // P2-1
          if (page === "dashboard.html") await dashboardChecks(cdp, origin, w, h);
        }
      }
      // the desktop
      if (ONLY === "phone") continue;
      await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: PAUSE }).then(async ({ identifier }) => {
        await open(cdp, origin, page, DESK[0], DESK[1], false);
        await evaluate(cdp, "scrollTo(0,0),true");
        const b = await evaluate(cdp, BOXES);
        await shotPage(cdp, path.join(OUT, MODE === "before" ? "before" : "after", fileOf(page, DESK[0], DESK[1])), DESK[0]);
        await cdp.send("Page.removeScriptToEvaluateOnNewDocument", { identifier });
        if (MODE === "before") { boxes[page] = b; console.log("    1440: " + b.list.length + " visible elements recorded (" + b.list.filter(x => x[2]).length + " moving, set aside)"); }
        else desktopCompare(page, baseline[page], b);
      });
    }
    if (MODE === "before") {
      if (ONLY !== "desktop") fs.writeFileSync(path.join(OUT, "defects-before-" + BATCH + ".json"), J(defects, null, 1));
      if (ONLY !== "phone") fs.writeFileSync(baselineFile(BATCH), J(boxes));
    } else if (ONLY !== "desktop" && !HQ1 && !P21 && !P23) fs.writeFileSync(path.join(OUT, "defects-after-" + BATCH + ".json"), J(defects, null, 1));
  } finally {
    try { cdp && cdp.close(); } catch (e) { /* gone */ }
    try { chrome.proc.kill(); } catch (e) { /* gone */ }
    server.close();
  }
  const ex = exceptions.filter((v, i, a) => a.indexOf(v) === i);
  if (ex.length) console.log("\n  page exceptions (reported, not counted): " + J(ex.slice(0, 10)));
  if (MODE === "before") console.log("\nRecorded " + PAGES.length + " pages to " + OUT);
  else console.log("\n" + (failures === 0 ? "ALL " + passes + " CHECKS PASSED" : failures + " FAILED, " + passes + " passed"));
  setTimeout(() => process.exit(MODE === "check" && failures ? 1 : 0), 300);
})().catch(e => { console.log("ERROR " + e.stack); setTimeout(() => process.exit(1), 300); });

/* At 1440 every baseline element is matched (same tag, id and own text, box within 1 px), and nothing new shows. */
function desktopCompare(page, base, now) {
  if (!base) { check(page + " at 1440: a desktop baseline exists", false, "none recorded"); return; }
  const movingKeys = new Set(base.list.filter(x => x[2]).map(x => x[0]).concat(now.list.filter(x => x[2]).map(x => x[0])));
  const pool = new Map();
  now.list.filter(x => !movingKeys.has(x[0])).forEach(x => { if (!pool.has(x[0])) pool.set(x[0], []); pool.get(x[0]).push(x[1]); });
  const missing = [];
  base.list.filter(x => !movingKeys.has(x[0])).forEach(x => {
    const list = pool.get(x[0]) || [];
    const i = list.findIndex(b => b.every((v, k) => Math.abs(v - x[1][k]) <= 1));
    if (i === -1) missing.push(x[0] + " " + x[1].join(","));
    else list.splice(i, 1);
  });
  const extra = [];
  pool.forEach((list, k) => list.forEach(b => extra.push(k + " " + b.join(","))));
  check(page + " at 1440: every element's box equals the baseline within 1 px (" + base.list.length + " elements, " + movingKeys.size + " moving set aside), page height " + base.h + " = " + now.h,
    missing.length === 0 && extra.length === 0 && Math.abs(base.h - now.h) <= 1, J({ missing: missing.slice(0, 8), extra: extra.slice(0, 8), missingCount: missing.length, extraCount: extra.length }));
}

async function dashboardChecks(cdp, origin, w, h) {
  await evaluate(cdp, "scrollTo(0,0),true");
  await sleep(300);
  const o = await evaluate(cdp, ORBIT);
  const at = "dashboard at " + w + ": ";
  const dist = o.core ? o.portals.map(p => Math.hypot(p.cx - o.core.cx, p.cy - o.core.cy)) : [];
  check(at + "the orbit has a core and five portals", !!o.core && o.portals.length === 5, J(o));
  check(at + "the five portals sit on a circle round the core (distance equal within 2 px)", dist.length === 5 && Math.max.apply(null, dist) - Math.min.apply(null, dist) <= 2, J(dist.map(Math.round)));
  check(at + "each portal disc is at least 44 px", o.portals.length === 5 && o.portals.every(p => p.w >= 44 && p.h >= 44), J(o.portals.map(p => p.name + " " + Math.round(p.w) + "x" + Math.round(p.h))));
  check(at + "all five labels are shown in full, inside the screen", o.portals.length === 5 && o.portals.every(p => p.label && p.labelFull && p.labelIn && p.ell !== "ellipsis"), J(o.portals.map(p => [p.name, p.label, p.labelFull, p.labelIn])));
  check(at + "no two labels overlap, and none overlaps the core", o.clash.length === 0, J(o.clash));
  check(at + "no empty space above the orbit (the top disc within 52 px of the stage's top)", o.topGap !== null && o.topGap <= 52, J({ topGap: o.topGap, stageTop: o.stageTop }));
  check(at + "THIS WEEK and the goal button sit under the orbit at the card's full width", !!o.below && o.below.y >= o.below.stageBottom - 1 && Math.abs(o.below.w - (o.below.panelW - 24)) <= 2 && o.goalIn && o.goalH >= 44 && /this week/i.test(o.week || ""), J({ below: o.below, goalIn: o.goalIn, goalH: o.goalH, week: o.week }));
  // A: the top bar's two rows
  const bar = await evaluate(cdp, "(function(){function c(sel){var n=document.querySelector(sel);if(!n)return null;var r=n.getBoundingClientRect();return {l:Math.round(r.left),r:Math.round(r.right),t:Math.round(r.top),b:Math.round(r.bottom),cy:Math.round(r.top+r.height/2),h:Math.round(r.height),shown:r.width>0&&getComputedStyle(n).display!=='none'};}" +
    "return {brand:c('.topbar-brand'),music:c('.topbar > .bfm-float'),avatar:c('#userAvatar'),agents:c('#agentsNavBtn'),orb:c('#oracleNavBtn'),tmx:c('#tmxPresenceToggle'),settings:c('#settingsNavBtn'),logout:c('.topbar .logout'),bar:c('.topbar'),num:(document.querySelector('.topbar-agents-num')||{}).textContent};})()");
  const row1 = [bar.brand, bar.music, bar.avatar], row2 = [bar.agents, bar.orb, bar.tmx];
  check(at + "top bar row 1: the logo and BizForce AI on the left, the music button and the R avatar on the right, on one centre line", row1.every(x => x && x.shown) &&
    Math.max.apply(null, row1.map(x => x.cy)) - Math.min.apply(null, row1.map(x => x.cy)) <= 2 && bar.brand.l < bar.music.l && bar.music.r <= bar.avatar.l && bar.avatar.r <= bar.bar.r, J(bar));
  check(at + "top bar row 2: AGENTS, the orb and TERMAXIMUS, the same height, under row 1, evenly across the full width", row2.every(x => x && x.shown) &&
    row2.every(x => x.h === row2[0].h && x.t >= bar.avatar.b) && Math.abs((bar.orb.l - bar.agents.r) - (bar.tmx.l - bar.orb.r)) <= 2 && bar.agents.l - bar.bar.l <= 24 && bar.bar.r - bar.tmx.r <= 24, J(row2));
  check(at + "Settings and Sign Out are off the top bar (in the avatar menu); the agent count reads 18", !bar.settings.shown && !bar.logout.shown && bar.num === "18", J([bar.settings, bar.logout, bar.num]));
  // the avatar menu
  const menu = await evaluate(cdp, "(function(){var a=document.getElementById('userAvatar');if(!a)return null;a.click();return new Promise(function(r){setTimeout(function(){var m=document.getElementById('bfAvatarMenu');" +
    "var items=m?[].filter.call(m.querySelectorAll('a,button'),function(n){var b=n.getBoundingClientRect();return b.width>=44&&b.height>=44&&getComputedStyle(m).display!=='none';}).map(function(n){return n.textContent.trim();}):[];" +
    "r({open:!!m&&getComputedStyle(m).display!=='none'&&m.getBoundingClientRect().height>0,items:items,expanded:a.getAttribute('aria-expanded')});},250);});})()");
  check(at + "tapping the R avatar opens a menu with Settings and Sign Out", !!menu && menu.open && menu.items.indexOf("Settings") !== -1 && menu.items.indexOf("Sign Out") !== -1 && menu.expanded === "true", J(menu));
  if (w !== 390) return;
  const settings = await evaluate(cdp, "(function(){var m=document.getElementById('bfAvatarMenu');var s=[].filter.call(m.querySelectorAll('a'),function(n){return n.textContent.trim()==='Settings';})[0];return s?s.getAttribute('href'):null;})()");
  check(at + "Settings in the menu goes to settings.html", settings === "settings.html", J(settings));
  await evaluate(cdp, "(function(){var m=document.getElementById('bfAvatarMenu');var s=[].filter.call(m.querySelectorAll('a'),function(n){return n.textContent.trim()==='Settings';})[0];s.click();return true;})()");
  await sleep(1500);
  const url1 = await evaluate(cdp, "location.pathname");
  check(at + "tapping Settings opens the Settings page", url1 === "/settings.html", url1);
  await open(cdp, origin, "dashboard.html", w, h, true);
  await evaluate(cdp, "document.getElementById('userAvatar').click(),true");
  await sleep(300);
  await evaluate(cdp, "sessionStorage.setItem('phone_check_out','1'),true");
  await evaluate(cdp, "(function(){var m=document.getElementById('bfAvatarMenu');var s=[].filter.call(m.querySelectorAll('button'),function(n){return n.textContent.trim()==='Sign Out';})[0];s.click();return true;})()");
  await sleep(1800);
  const after = await evaluate(cdp, "({path:location.pathname,token:(function(){try{return localStorage.getItem('bf_token');}catch(e){return 'x';}})()})");
  check(at + "tapping Sign Out signs out (bf_token removed, off the dashboard)", after.token === null && after.path !== "/dashboard.html", J(after));
  // sign the owner back in for the next size
  await evaluate(cdp, "sessionStorage.removeItem('phone_check_out')," + J(SEED) + ",true").catch(() => null);
  await evaluate(cdp, SEED + "true");
}

/* ══ HQ1 (Nov 19 2026): the phone dashboard's card views, orbit toggle, Oracle moon and the boombox's sound on load ══
   PHONE_HQ1=1. At each width: for every portal x view (Large, Compact, Grid) x orbit (shown, hidden), no sideways
   scroll, no text cut off, every tap target 44 x 44, and Compact and Grid hold one row or tile per Large card in the
   same order with the same link; the view row, the chips, the sizes the brief gives; Swap from a row and from a tile.
   At 390 also: the 30 screenshots (Downloads\hq1), a reload keeps both choices (the device copy at once, the
   server's once it answers), the moon's phase and drawing equal oracle.html's, and the boombox plays on load only
   with "Play when I open BizForce" on and no pause in this visit (an agent page and the dashboard). */
const HQ_STATE = `(function(){var r=document.getElementById("orbitTop");return {view:r&&r.getAttribute("data-hq-view"),orbit:r&&r.getAttribute("data-hq-orbit"),open:window.BFOrbit&&window.BFOrbit.state.open,
  local:(function(){try{return [localStorage.getItem("bf_hq_view"),localStorage.getItem("bf_hq_orbit")];}catch(e){return null;}})()};})()`;
const HQ_LINKS = `(function(){var O=window.BFOrbit;
  var cards=[].slice.call(document.querySelectorAll("#orbitMain > .orbit-main-box")).concat(document.getElementById("orbitGrid").hidden?[]:[].slice.call(document.querySelectorAll("#orbitGrid > .orbit-box")));
  function slug(c){return c.getAttribute("data-card")||(c.classList.contains("orbit-dir")?"agent-directory":"?");}
  function href(c){var a=c.querySelector("a.bf-btn");return a?a.getAttribute("href"):((O.tools()[slug(c)]||{}).href||null);}
  var rows=[].slice.call(document.querySelectorAll("#hqList > .hq-item")).map(function(it){var a=it.querySelector("a.hq-link");return {slug:it.getAttribute("data-card"),href:a&&a.getAttribute("href")};});
  return {cards:cards.map(function(c){return {slug:slug(c),href:href(c)};}),rows:rows};})()`;
const HQ_MEASURE = `(function(){
  function r(n){var b=n.getBoundingClientRect();return {w:b.width,h:b.height,l:b.left,t:b.top};}
  function vis(n){if(!n)return false;var b=n.getBoundingClientRect();if(!(b.width>0&&b.height>0))return false;for(var e=n;e&&e.nodeType===1;e=e.parentElement){if(getComputedStyle(e).display==="none")return false;}return true;}
  var btns=[].slice.call(document.querySelectorAll("#hqViewRow button")).filter(vis);
  var chips=[].slice.call(document.querySelectorAll("#hqChips > .hq-chip")).filter(vis);
  var items=[].slice.call(document.querySelectorAll("#hqList > .hq-item")).filter(vis);
  var lefts={};items.forEach(function(it){lefts[Math.round(r(it).l)]=1;});
  var cols=Object.keys(lefts).length, gaps=[];
  for(var i=cols;i<items.length;i++){var a=r(items[i-cols]),b=r(items[i]);gaps.push(Math.round((b.t-(a.t+a.h))*10)/10);}
  var colGap=cols===2&&items.length>1?Math.round((r(items[1]).l-(r(items[0]).l+r(items[0]).w))*10)/10:null;
  return {row:vis(document.getElementById("hqViewRow")),title:(document.getElementById("hqSetTitle")||{}).textContent,
    btns:btns.map(function(b){var x=r(b);return {id:b.id||b.getAttribute("data-view"),w:x.w,h:x.h,label:b.getAttribute("aria-label")||"",pressed:b.getAttribute("aria-pressed")};}),
    chips:chips.map(function(c){var x=r(c);return {p:c.getAttribute("data-portal"),w:x.w,h:x.h,open:c.classList.contains("is-open")};}),
    stage:vis(document.getElementById("orbitStage")),cards:vis(document.getElementById("orbitMain")),items:items.length,
    minH:Math.min.apply(null,items.map(function(it){return r(it.querySelector(".hq-link")).h;}).concat([999])),cols:cols,gaps:gaps,colGap:colGap,
    mores:[].slice.call(document.querySelectorAll("#hqList .hq-more")).filter(vis).map(function(m){var x=r(m);return Math.round(x.w)+"x"+Math.round(x.h);}),
    icons:items.map(function(it){var n=it.querySelector(".hq-icon > .bf-neon-icon");return n?Math.round(r(n).w)+"x"+Math.round(r(n).h):"none";})};})()`;
const HQ_TITLES = { grow: "GROW TOOLS", sell: "SELL TOOLS", connect: "CONNECT TOOLS", agents: "AGENT TOOLS", oracle: "THE ORACLE" };

/* NAMED (Nov 22 2026, FX3): the abyss sun in the orbit's centre, as drawn (HQ1 and P2-3's FX2 section read it) */
const ABYSS_READ = String.raw`(function(){var R=function(e){if(!e)return null;var r=e.getBoundingClientRect();return {l:+r.left.toFixed(1),t:+r.top.toFixed(1),w:+r.width.toFixed(1),h:+r.height.toFixed(1)};};
  var core=document.getElementById('orbitCore'),s=core&&core.querySelector('.hq-core-abyss'),cv=s&&s.querySelector('canvas'),ring=core&&core.querySelector('.hq-gold-ring');
  if(!s)return null;var cs=getComputedStyle(s),painted=0,ch=document.getElementById('tmx-chat'),chs=ch?getComputedStyle(ch):null;
  try{var x=cv.getContext('2d').getImageData(0,0,cv.width,cv.height).data;for(var i=3;i<x.length;i+=4)if(x[i]>0)painted++;}catch(e){painted=-1;}
  return {open:document.getElementById('orbitTop').getAttribute('data-hq-open'),core:R(core),disc:R(s),canvas:R(cv),first:core.firstChild===s,disp:cs.display,radius:cs.borderTopLeftRadius,overflow:cs.overflow,
    inner:core.clientWidth,chatBg:chs&&chs.backgroundImage,chatSize:chs&&chs.backgroundSize,chatColor:chs&&chs.backgroundColor,chatAnim:chs&&chs.animationName,chatDur:chs&&chs.animationDuration,
    bgImage:cs.backgroundImage,bgColor:cs.backgroundColor,grads:(cs.backgroundImage.match(/radial-gradient/g)||[]).length,size:cs.backgroundSize,anim:cs.animationName,dur:cs.animationDuration,
    glow:cs.boxShadow,filter:cs.filter,after:getComputedStyle(s,'::after').content,before:getComputedStyle(s,'::before').content,painted:painted,
    info:window.BFHqViews&&window.BFHqViews.abyss?window.BFHqViews.abyss():null,ring:R(ring),ringDisp:ring&&getComputedStyle(ring).display,
    green:[].map.call(document.querySelectorAll('#orbitTop .orbit-core-halo,#orbitTop .orbit-core-arc,#orbitTop .orbit-goal-arc'),function(n){return getComputedStyle(n).display;}),
    coreMoon:!!core.querySelector('[data-hq-moon]'),nodeMoon:!!document.querySelector('.orbit-portal[data-portal=oracle] [data-hq-moon=node]'),chipMoon:!!document.querySelector('[data-hq-moon=chip]')};})()`;
async function hq1Run(cdp, origin) {
  fs.mkdirSync(HQ1_OUT, { recursive: true });
  console.log("browserCheckPhone HQ1 (the phone dashboard's views, orbit toggle, Oracle moon, boombox sound on load) at " + HQ1_WIDTHS.join(", "));
  // a token that names the owner (bf-music.js reads the member's id from it); the SEED's sign-in otherwise as before
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{if(!sessionStorage.getItem('phone_check_out'))localStorage.setItem('bf_token'," + J(ID_TOKEN) + ");}catch(e){}" });
  const ev = x => evaluate(cdp, x);
  const PORTALS = ["grow", "sell", "connect", "agents", "oracle"], VIEWS = ["large", "compact", "grid"], ORBITS = ["shown", "hidden"];
  const HT = { 360: 780, 390: 844, 430: 932 };
  const pick = (sel) => ev("(function(){var b=document.querySelector(" + J(sel) + ");if(!b)return false;b.click();return true;})()");
  const fresh = async (w) => {
    HQS.view = null; HQS.orbit = null; HQS.puts = [];
    await open(cdp, origin, "sw.js", w, HT[w], true);
    await ev("(function(){try{localStorage.removeItem('bf_hq_view');localStorage.removeItem('bf_hq_orbit');localStorage.removeItem('bf_main_boxes');sessionStorage.clear();}catch(e){}return true;})()");
    await open(cdp, origin, "dashboard.html", w, HT[w], true);
  };
  for (const w of HQ1_WIDTHS) {
    const at = "HQ1 dashboard at " + w + ": ";
    await fresh(w);
    const d0 = await ev(HQ_STATE);
    check(at + "a member who never chose sees Compact with the orbit shown", d0.view === "compact" && d0.orbit === "shown", J(d0));
    for (const orbit of ORBITS) {
      if ((await ev(HQ_STATE)).orbit !== orbit) await pick("#hqOrbitBtn");
      for (const view of VIEWS) {
        await pick('.hq-view-btn[data-view="' + view + '"]');
        await sleep(250);
        const bad = { hscroll: [], clipped: [], small: [], links: [], row: [], orbit: [], sizes: [], fixed: [] };
        for (const p of PORTALS) {
          if (orbit === "hidden") await pick('#hqChips > .hq-chip[data-portal="' + p + '"]');
          else await ev("window.BFOrbit.open(" + J(p) + "),true");
          await sleep(320);
          await ev("scrollTo(0,0),true");
          const m = await ev(MEASURE), q = await ev(HQ_MEASURE), L = await ev(HQ_LINKS), s = await ev(HQ_STATE);
          if (m.hscroll) bad.hscroll.push(p + " " + J(m.wide));
          if (m.clipped.length) bad.clipped.push(p + " " + J(m.clipped));
          if (m.smallCount) bad.small.push(p + " " + J(m.small));
          // NAMED (Nov 21 2026, P3-1B): BEFORE only the Guide was set aside at rest, so the P2-1 bottom bar, fixed over the dashboard's
          // lower content by design, failed 14 of these. AFTER the bar is set aside at rest the same way P2-1's checks do, and the end
          // of the page is judged with the bar and the Guide included (below).
          const over = m.over.filter(x => !/^(div#tmx-presence-root|nav#bf-tabbar) /.test(x)); if (over.length) bad.fixed.push(p + " " + J(over));
          if (view === "large") { if (L.rows.length || !q.cards) bad.links.push(p + " rows " + L.rows.length + ", cards shown " + q.cards); }
          else if (!L.cards.length || J(L.rows) !== J(L.cards) || L.rows.some(x => !x.href)) bad.links.push(p + " " + J({ cards: L.cards, rows: L.rows }).slice(0, 300));
          const pressed = q.btns.filter(b => b.pressed === "true").map(b => b.id).sort().join();
          const wantPressed = [view].concat(orbit === "shown" ? ["hqOrbitBtn"] : []).sort().join();
          if (!q.row || q.title !== HQ_TITLES[p] || q.btns.map(b => b.id).join() !== "large,compact,grid,hqOrbitBtn" || q.btns.some(b => b.w < 43.5 || b.h < 43.5 || b.label.length < 4) || pressed !== wantPressed || s.view !== view || s.open !== p)
            bad.row.push(p + " " + J({ title: q.title, btns: q.btns, s }));
          if (orbit === "hidden" ? (q.stage || q.chips.map(c => c.p).join() !== PORTALS.join() || q.chips.some(c => c.w < 43.5 || c.h < 43.5) || q.chips.filter(c => c.open).map(c => c.p).join() !== p)
            : (!q.stage || q.chips.length)) bad.orbit.push(p + " " + J({ stage: q.stage, chips: q.chips }));
          if (view === "compact" && (q.cols !== 1 || q.minH < 59.5 || q.gaps.some(g => Math.abs(g - 8) > 0.6) || q.icons.some(x => x !== "40x40") || J(q.mores) !== J(["44x44", "44x44"])))
            bad.sizes.push(p + " " + J(q));
          if (view === "grid" && (q.cols !== 2 || q.minH < 119.5 || Math.abs(q.colGap - 10) > 0.6 || q.gaps.some(g => Math.abs(g - 10) > 0.6) || J(q.mores) !== J(["44x44", "44x44"])))
            bad.sizes.push(p + " " + J(q));
          if (w === 390) {
            await ev("(function(){var t=document.getElementById('orbitTop').getBoundingClientRect().top+scrollY;scrollTo(0,Math.max(0,t-8));return true;})()");
            await sleep(150);
            const shot = await cdp.send("Page.captureScreenshot", { format: "png" });
            fs.writeFileSync(path.join(HQ1_OUT, "dashboard-390x844-" + p + "-" + view + "-orbit-" + orbit + ".png"), Buffer.from(shot.data, "base64"));
          }
        }
        // NAMED (Nov 21 2026, P3-1B): the END of the dashboard, the bar and the Guide included: nothing fixed covers the last content
        await ev("scrollTo(0,document.documentElement.scrollHeight),true");
        await sleep(350);
        const endM = await ev(MEASURE);
        const endOver = endM.over.filter(x => !/ sticky over /.test(x));
        await ev("scrollTo(0,0),true");
        const c = at + view + ", orbit " + orbit + ", all five portals: ";
        check(c + "no horizontal scroll", !bad.hscroll.length, J(bad.hscroll));
        check(c + "no text cut off", !bad.clipped.length, J(bad.clipped));
        check(c + "every tap target at least 44 x 44", !bad.small.length, J(bad.small));
        check(c + "no fixed element over text or a control at rest (the bar and the Guide are judged at the end)", !bad.fixed.length, J(bad.fixed));
        check(c + "at the end of the dashboard no fixed element covers anything (the bar and the Guide included)", endOver.length === 0, J(endM.over));
        check(c + (view === "large" ? "the PH1 cards shown, no list" : "one " + (view === "grid" ? "tile" : "row") + " per Large card, the same order and the same link"), !bad.links.length, J(bad.links));
        check(c + "the view row: the set's title, Large, Compact, Grid and the orbit button, 44 px, labelled, the pressed ones right", !bad.row.length, J(bad.row));
        check(c + (orbit === "hidden" ? "the orbit hidden, five 44 px chips in order, the open one highlighted" : "the orbit shown, no chips"), !bad.orbit.length, J(bad.orbit));
        if (view !== "large") check(c + (view === "compact" ? "rows at least 60 px, 8 px apart, 40 px icon tiles, Swap 44 px on the two main boxes" : "two columns 10 px apart, tiles at least 120 px, Swap 44 px on the two main boxes"), !bad.sizes.length, J(bad.sizes).slice(0, 600));
      }
    }
    // Swap, from a Compact row and a Grid tile
    for (const view of ["compact", "grid"]) {
      await pick('.hq-view-btn[data-view="' + view + '"]');
      await ev("window.BFOrbit.open('sell'),true"); await sleep(250);
      const before = await ev("window.BFOrbit.mains()");
      await pick('#hqList > .hq-item[data-main="0"] > button.hq-more'); await sleep(200);
      const choice = await ev("(function(){var b=[].slice.call(document.querySelectorAll('#hqList .orbit-swap-list button[data-tool]')).filter(function(x){return window.BFOrbit.mains().indexOf(x.getAttribute('data-tool'))===-1;})[0];if(!b)return null;var t=b.getAttribute('data-tool');b.click();return t;})()");
      await sleep(300);
      const after = await ev("({mains:window.BFOrbit.mains(),first:(document.querySelector('#hqList > .hq-item')||{getAttribute:function(){return null;}}).getAttribute('data-card'),large:(document.querySelector('#orbitMain > .orbit-main-box')||{getAttribute:function(){return null;}}).getAttribute('data-card')})");
      check(at + "Swap from a " + (view === "grid" ? "Grid tile" : "Compact row") + " (the 44 px button): the main box changes to the tool chosen, in the list and in the Large cards",
        !!choice && after.mains[0] === choice && after.first === choice && after.large === choice && after.mains[1] === before[1], J({ before, choice, after }));
      await pick('#hqList > .hq-item[data-main="0"] > button.hq-more'); await sleep(200);
      await ev("(function(){var b=document.querySelector('#hqList .orbit-swap-list button[data-tool=" + J(before[0]) + "]');if(b)b.click();return true;})()"); await sleep(250);
    }
    if (w !== 390) continue;

    // a reload keeps both choices
    await pick('.hq-view-btn[data-view="grid"]'); await sleep(150);
    if ((await ev(HQ_STATE)).orbit !== "hidden") await pick("#hqOrbitBtn");
    await sleep(400);
    const sent = { view: HQS.view, orbit: HQS.orbit };
    await open(cdp, origin, "dashboard.html", w, HT[w], true);
    const r1 = await ev(HQ_STATE);
    check(at + "the choice is saved to the server (PUT hq_card_view grid, hq_orbit hidden) and a reload keeps both", sent.view === "grid" && sent.orbit === "hidden" && r1.view === "grid" && r1.orbit === "hidden", J({ sent, r1 }));
    await ev("(function(){try{localStorage.removeItem('bf_hq_view');localStorage.removeItem('bf_hq_orbit');}catch(e){}return true;})()");
    await open(cdp, origin, "dashboard.html", w, HT[w], true);
    const r2 = await ev(HQ_STATE);
    check(at + "on a device with no copy (another phone), the server's choice comes back", r2.view === "grid" && r2.orbit === "hidden" && J(r2.local) === J(["grid", "hidden"]), J(r2));
    HQS.view = "large"; HQS.orbit = "shown";
    await open(cdp, origin, "dashboard.html", w, HT[w], true);
    const r3 = await ev(HQ_STATE);
    check(at + "the server's value wins once loaded (changed elsewhere to Large, shown), and this device's copy follows", r3.view === "large" && r3.orbit === "shown" && J(r3.local) === J(["large", "shown"]), J(r3));

    // the moon: the same phase and drawing as oracle.html
    HQS.moonAsks = 0;
    await open(cdp, origin, "oracle.html", w, HT[w], true);
    await sleep(800);
    const om = await ev("({phase:(document.getElementById('celMoonPhase')||{}).textContent,paths:[].map.call(document.querySelectorAll('#abyssMoon path'),function(p){return p.getAttribute('d');})})");
    await fresh(w);
    await ev("window.BFOrbit.open('oracle'),true"); await sleep(900);
    const dm = await ev("(function(){var out={};['node','core'].forEach(function(k){var n=document.querySelector('[data-hq-moon='+k+']');var b=n?n.getBoundingClientRect():{width:0};" +
      "out[k]=n?{phase:n.getAttribute('data-moon-phase'),angle:n.getAttribute('data-moon-angle'),live:n.getAttribute('data-moon-live'),hidden:n.hidden,w:Math.round(b.width),paths:[].map.call(n.querySelectorAll('path'),function(p){return p.getAttribute('d');}),img:!!n.querySelector('image')}:null;});" +
      // NAMED (Nov 21 2026, FX2): the centre's Sun. NAMED (Nov 22 2026, FX3): BEFORE the Sun (.hq-core-sun, its img). AFTER the abyss sun
      "var s=document.querySelector('#orbitCore .hq-core-abyss'),cv=s&&s.querySelector('canvas'),q=s?s.getBoundingClientRect():{width:0};out.sun=s?{shown:getComputedStyle(s).display!=='none',w:Math.round(q.width),canvas:!!cv,running:!!(window.BFHqViews&&window.BFHqViews.abyss&&(window.BFHqViews.abyss()||{}).running)}:null;return out;})()");
    const gold = await ev("(function(){var t=document.getElementById('hqSetTitle');var cs=getComputedStyle(t);" +
      "return {title:t.classList.contains('hq-gold'),anim:cs.animationName,size:cs.backgroundSize,img:cs.backgroundImage.slice(0,40),icons:document.querySelectorAll('#hqList .hq-gold-glyph').length,rings:[].filter.call(document.querySelectorAll('.hq-gold-ring'),function(n){return getComputedStyle(n).display!=='none';}).length};})()");
    await shotPage(cdp, path.join(HQ1_OUT, "oracle-set-moon-and-gold-390.png"), 390).catch(() => null);
    await pick("#hqOrbitBtn"); await sleep(500);
    const cm = await ev("(function(){var n=document.querySelector('[data-hq-moon=chip]');var b=n?n.getBoundingClientRect():{width:0};return n?{phase:n.getAttribute('data-moon-phase'),hidden:n.hidden,w:Math.round(b.width),paths:[].map.call(n.querySelectorAll('path'),function(p){return p.getAttribute('d');})}:null;})()");
    check(at + "oracle.html shows the live phase (" + om.phase + ")", om.phase === MOON.phaseName && om.paths.length > 0, J(om).slice(0, 300));
    check(at + "the ORACLE node's moon: the same live phase and the same drawing (every path) as oracle.html's, drawn on the disc",
      !!dm.node && dm.node.phase === om.phase && dm.node.angle === String(MOON.phaseAngle) && dm.node.live === "true" && !dm.node.hidden && dm.node.w >= 44 && dm.node.img && J(dm.node.paths) === J(om.paths), J(dm.node).slice(0, 400));
    // NAMED (Nov 21 2026, FX2): BEFORE "the centre's moon while ORACLE is open: the same". AFTER the centre is the Sun (a NASA SDO
    // image, brand/sun-sdo-hmi-20261121.webp) in the same gold ring; the node and the chip keep the moon.
    check(at + "the centre while ORACLE is open: the abyss sun (60 px or more, its stars running), no moon", !dm.core && !!dm.sun && dm.sun.shown && dm.sun.canvas && dm.sun.running && dm.sun.w >= 60, J([dm.core, dm.sun]).slice(0, 300));   // NAMED (Nov 22 2026, FX3): BEFORE the Sun (loaded, its NASA file)
    check(at + "the ORACLE chip's moon (orbit hidden): the same", !!cm && cm.phase === om.phase && !cm.hidden && cm.w >= 20 && J(cm.paths) === J(om.paths), J(cm).slice(0, 300));
    check(at + "the gold with ORACLE open: the title's shine is tmx-gold-shimmer at 260% 260%, the rings on the node and the centre, the four Oracle tools' icons gold",
      gold.title && gold.anim === "tmx-gold-shimmer" && gold.size === "260% 260%" && /linear-gradient/.test(gold.img) && gold.icons === 4 && gold.rings >= 2, J(gold));

    // the boombox's sound on load
    const TRACK = "c1000000-0000-4000-8000-000000000001";
    const store = (autoplay, wasPlaying) => ({ v: 1, uid: ROSE.id, track_id: TRACK, position: 0, volume: 0.8, queue: [TRACK], autoplay, was_playing: wasPlaying });
    // the audio elements the player made (src, error, paused): the detail of a failure
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "(function(){var A=window.Audio;if(!A)return;window.__hqAud=[];window.Audio=function(s){var a=s===undefined?new A():new A(s);window.__hqAud.push(a);return a;};window.Audio.prototype=A.prototype;})();" });
    const music = "({armed:!!(window.BFMusic&&window.BFMusic.armed()),playing:!!(window.BFMusic&&window.BFMusic.playing()),aud:(window.__hqAud||[]).map(function(x){return [String(x.src).slice(-14),x.error&&x.error.code,x.paused,x.readyState];}),msg:((document.querySelector('.bfm-msg,.bfm-status,[data-bfm-msg]')||{}).textContent||'').slice(0,80),held:(function(){try{return sessionStorage.getItem('bf_music_live_held');}catch(e){return 'x';}})()})";
    async function load(page, st) {
      await open(cdp, origin, "sw.js", w, HT[w], true);
      await ev("(function(){try{sessionStorage.removeItem('bf_music_live_held');sessionStorage.removeItem('bf_music_live');" + (st ? "localStorage.setItem('bf_music'," + J(J(st)) + ");" : "") + "}catch(e){}return true;})()");
      await open(cdp, origin, page, w, HT[w], true);
      await sleep(700);
    }
    async function press() {
      await ev("(function(){if(document.activeElement&&document.activeElement.blur)document.activeElement.blur();return true;})()");
      await cdp.send("Input.dispatchKeyEvent", { type: "keyDown", key: "x", code: "KeyX", windowsVirtualKeyCode: 88 });
      await cdp.send("Input.dispatchKeyEvent", { type: "keyUp", key: "x", code: "KeyX", windowsVirtualKeyCode: 88 });
      await sleep(1500);
      return ev(music);
    }
    for (const page of ["agents/seo.html", "dashboard.html"]) {
      const a = "HQ1 boombox on " + page + " at " + w + ": ";
      await load(page, store(false, true));
      const off0 = await ev(music), off1 = await press();
      check(a + "\"Play when I open BizForce\" off, music playing on the last page: nothing plays on load, nothing is armed, a key press starts nothing", !off0.playing && !off0.armed && !off1.playing, J([off0, off1]));
      await load(page, store(true, false));
      const on0 = await ev(music), on1 = await press();
      check(a + "with it on: the track starts on load (or, where sound must wait, on the first key press)", (on0.playing || on0.armed) && on1.playing, J([on0, on1]));
      await ev("window.BFMusic.pause(),true"); await sleep(300);
      const other = page === "dashboard.html" ? "agents/seo.html" : "dashboard.html";
      await open(cdp, origin, other, w, HT[w], true);
      await sleep(700);
      const p0 = await ev(music), p1 = await press();
      check(a + "with it on but paused here, the next page (" + other + ") stays silent, even after a key press", !p0.playing && !p0.armed && !p1.playing && p0.held === ROSE.id, J([p0, p1]));
    }
  }
}

/* ══ P2-1 (Nov 19 2026): the bottom bar on every page, and P2-1's own pages ══ */
const BAR_STATE = String.raw`(function(){
  var bar = document.getElementById("bf-tabbar");
  function vis(n){ if (!n) return false; var r = n.getBoundingClientRect(); if (!(r.width > 0 && r.height > 0)) return false;
    for (var e = n; e && e.nodeType === 1; e = e.parentElement) { var c = getComputedStyle(e); if (c.display === "none" || c.visibility === "hidden") return false; } return true; }
  function nm(t){ var c = t.className && t.className.baseVal !== undefined ? t.className.baseVal : t.className; return t.tagName.toLowerCase() + (t.id ? "#" + t.id : "") + (c ? "." + String(c).trim().split(/\s+/)[0] : ""); }
  var path = location.pathname.replace(/^\/+/, ""); if (!path) path = "index.html";
  var out = { path: path, shown: vis(bar), iw: innerWidth, ih: innerHeight };
  if (!out.shown) return out;
  var br = bar.getBoundingClientRect();
  out.h = Math.round(br.height); out.bottomGap = Math.round(innerHeight - br.bottom); out.w = Math.round(br.width);
  out.items = [].map.call(bar.children, function(n){ var r = n.getBoundingClientRect(); return { tab: n.getAttribute("data-tab"), w: Math.round(r.width), h: Math.round(r.height), cur: n.getAttribute("aria-current") }; });
  out.active = (bar.querySelector("[aria-current=page]") || { getAttribute: function(){ return null; } }).getAttribute("data-tab");
  var g = document.getElementById("tmx-presence-root");   // NAMED (Nov 22 2026, FX3): BEFORE the Guide's book button (gone); AFTER the mist, 16 px above the bar
  if (vis(g)) { var gr = g.getBoundingClientRect(); out.guide = [Math.round(gr.left), Math.round(gr.top), Math.round(gr.right), Math.round(gr.bottom)];
    out.guideOverlap = !(gr.bottom <= br.top + 0.5 || gr.top >= br.bottom - 0.5 || gr.right <= br.left + 0.5 || gr.left >= br.right - 0.5); }
  // anything else painted over the bar: 20 points across it, at three heights; the topmost must be the bar
  var cover = [];
  for (var i = 0; i < 20; i++) { var x = br.left + (i + 0.5) * br.width / 20;
    [br.top + 4, br.top + br.height / 2, br.bottom - 4].forEach(function(y){ var t = document.elementFromPoint(x, y); if (!t || bar.contains(t)) return;
      var big = t.closest && t.closest(".bfm-float"); if (big && big.getBoundingClientRect().height >= 300) return;   // the big music player covers it by design
      var k = nm(t); if (cover.indexOf(k) === -1) cover.push(k); }); }
  out.cover = cover;
  return out;
})()`;

async function barChecks(cdp, page, w) {
  let s = await evaluate(cdp, BAR_STATE);
  if (s.iw !== w) { await sleep(600); s = await evaluate(cdp, BAR_STATE); }   // a page that redirects (index.html to the dashboard) is measured once it has settled
  const file = s.path;
  const want = BAR_HIDDEN.indexOf(file) === -1 && barLoads(file);
  const at = page + " at " + w + ": ";
  check(at + "the bottom bar is " + (want ? "shown" : "not shown") + " (" + file + ", P2-1)", s.shown === want, J(s));
  if (want) check(at + "the page is no wider than the screen, so the fixed bar and the Guide sit on it (layout viewport " + s.iw + " = " + w + ")", s.iw === w, J(s));
  if (!want || !s.shown) return;
  check(at + "the bar is at the very bottom, 56 px or more, five items each 44 x 44 or more, " + (BAR_ACTIVE[file] || "hq") + " active",
    s.h >= 56 && s.bottomGap === 0 && s.items.length === 5 && s.items.every(i => i.w >= 44 && i.h >= 44) && s.active === (BAR_ACTIVE[file] || "hq"), J(s));
  check(at + "nothing else is painted over the bar (the big music player excepted) and the mist clears it", s.cover.length === 0 && !s.guideOverlap, J({ cover: s.cover, guide: s.guide }));
}

async function p21Run(cdp, origin) {
  fs.mkdirSync(P21_OUT, { recursive: true });
  console.log("browserCheckPhone P2-1 (the bottom bar's addresses, signed out, Home, the Inbox, the profile, the Create sheet) at " + P21_WIDTHS.join(", "));
  // a token that names the owner (the Inbox and the profile read the member's id from it); signed out when phone_check_out is set
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{if(!sessionStorage.getItem('phone_check_out'))localStorage.setItem('bf_token'," + J(ID_TOKEN) + ");" +
    "else{localStorage.removeItem('bf_token');localStorage.removeItem('bf_user');localStorage.removeItem('bf_refresh_token');}}catch(e){}" });
  const ev = x => evaluate(cdp, x);
  const HT = { 360: 780, 390: 844, 430: 932 };
  const viewShot = async (file) => { const r = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(P21_OUT, file), Buffer.from(r.data, "base64")); };

  // 1. the addresses the site rewrites to a page on disk, signed in, at 390
  for (const [addr, want] of [["@rose", true], ["listing/wool-hat", false], ["blog/rose", false], ["blog/rose/first-post", false]]) {
    await open(cdp, origin, addr, 390, 844, true);
    const s = await ev(BAR_STATE);
    check("P21 /" + addr + " signed in at 390: the bar is " + (want ? "shown" : "not shown"), s.shown === want, J(s));
  }
  // 2. signed out: no bar anywhere; Home and an Inbox address are kept to come back to after sign-in
  await open(cdp, origin, "sw.js", 390, 844, true);
  await ev("sessionStorage.setItem('phone_check_out','1'),true");
  for (const pg of ["listing.html", "seller.html?u=rose", "@rose", "index.html"]) {
    await open(cdp, origin, pg, 390, 844, true);
    const s = await ev(BAR_STATE);
    check("P21 " + pg + " signed out at 390: no bar", !s.shown, J(s));
  }
  for (const [pg, keep] of [["home.html", "/home.html"], ["inbox.html?tab=approvals", "/inbox.html?tab=approvals"]]) {
    await ev("(function(){try{localStorage.removeItem('bf_return_to');}catch(e){}return true;})()");
    await open(cdp, origin, pg, 390, 844, true);
    const r = await ev("({path:location.pathname,back:(function(){try{return localStorage.getItem('bf_return_to');}catch(e){return null;}})()})");
    check("P21 " + pg + " signed out: sent to sign in (app.html), and " + keep + " kept to come back to", r.path === "/app.html" && r.back === keep, J(r));
  }
  await open(cdp, origin, "sw.js", 390, 844, true);
  await ev("(function(){sessionStorage.removeItem('phone_check_out');try{localStorage.removeItem('bf_return_to');}catch(e){}return true;})()");

  // 3. P2-1's pages at each width
  const STATES = [
    ["home", "home.html", null, "home"], ["inbox-messages", "inbox.html", null, "inbox"], ["inbox-thread", "inbox.html?with=" + P21_PEER, null, "inbox"],
    ["inbox-approvals", "inbox.html?tab=approvals", null, "inbox"], ["inbox-notifications", "inbox.html?tab=notifications", null, "inbox"],
    ["profile", "profile.html", null, "profile"], ["create-sheet", "home.html", "create", null], ["dashboard", "dashboard.html", null, "hq"]
  ];
  for (const w of P21_WIDTHS) {
    const h = HT[w] || 844;
    for (const [name, url, act, tab] of STATES) {
      await open(cdp, origin, url, w, h, true);
      const at = "P21 " + name + " at " + w + ": ";
      await ev("scrollTo(0,0),true");
      if (act === "create") { await ev("(function(){var b=document.querySelector('#bf-tabbar [data-tab=create]');if(b)b.click();return !!b;})()"); await sleep(350); }
      if (w === 390) await viewShot(name + "-390x844.png");
      if (act !== "create") { const s0 = await ev(BAR_STATE); check(at + "at rest the bar is on screen at the bottom with nothing over it", s0.shown && s0.bottomGap === 0 && s0.cover.length === 0, J(s0)); }
      const rest = await ev(MEASURE);
      check(at + "no horizontal scroll", !rest.hscroll, J(rest.wide));
      check(at + "no text cut off", rest.clipped.length === 0, J(rest.clipped));
      check(at + "every tap target is at least 44 x 44", rest.smallCount === 0, rest.smallCount + " " + J(rest.small));
      const deco = rest.deco.filter(x => !(act === "create" && /^div#bf-create-backdrop /.test(x)));   // the open dialog's scrim dims the page by design
      check(at + "decoration is under the text" + (act === "create" ? " (the open sheet's scrim aside)" : ""), deco.length === 0, J(deco));
      const restOver = rest.over.filter(x => !/^(div#tmx-presence-root|nav#bf-tabbar) /.test(x));
      check(at + "the page is no wider than the screen (layout viewport " + w + ")", (await ev("innerWidth")) === w);
      check(at + "no fixed element over text or a control at rest (the bar and the Guide are judged at the end)", restOver.length === 0, J(restOver));
      if (act === "create") {
        const c = await ev("(function(){var s=document.getElementById('bf-create');if(!s||s.hidden)return null;var r=s.getBoundingClientRect();var bar=document.getElementById('bf-tabbar').getBoundingClientRect();" +
          "var top=document.elementFromPoint(bar.left+bar.width/2,bar.top+bar.height/2);" +
          "return {t:Math.round(r.top),b:Math.round(r.bottom),l:Math.round(r.left),r:Math.round(r.right),role:s.getAttribute('role'),opts:[].map.call(s.querySelectorAll('.bf-create-opt'),function(o){var q=o.getBoundingClientRect();return Math.round(q.width)+'x'+Math.round(q.height);})," +
          "soon:s.querySelectorAll('.is-soon').length,overBar:!!top&&(s.contains(top)||top.id==='bf-create-backdrop'),focus:s.contains(document.activeElement)};})()");
        check(at + "the Create sheet opens from + as a bottom sheet inside the screen, over the bar, focus in it", !!c && c.role === "dialog" && c.t >= 0 && c.b <= h + 1 && c.l <= 0 && c.r >= w - 1 && c.overBar && c.focus, J(c));
        // NAMED (Nov 20 2026, FX1): BEFORE "Post and Video say Coming soon" (c.soon === 2); P2-3 made Post live, so AFTER only Video does
        check(at + "eight choices, each at least 44 px tall; Video says Coming soon (Post is live since P2-3)", !!c && c.opts.length === 8 && c.opts.every(o => Number(o.split("x")[1]) >= 44 && Number(o.split("x")[0]) >= 44) && c.soon === 1, J(c && [c.opts, c.soon]));
        continue;
      }
      await ev("scrollTo(0,document.documentElement.scrollHeight),true");
      await sleep(350);
      const end = await ev(MEASURE);
      const endOver = end.over.filter(x => !/ sticky over /.test(x));   // a sticky header covers what scrolled under it by design; fixed overlays are judged
      check(at + "at the end of the page no fixed element covers anything (the bar and the Guide included)", endOver.length === 0, J(end.over));
      const s = await ev(BAR_STATE);
      check(at + "the bar is shown, " + tab + " active, nothing over it, the Guide clear of it", s.shown && s.active === tab && s.cover.length === 0 && !s.guideOverlap && s.items.every(i => i.w >= 44 && i.h >= 44), J(s));
      const k = await ev("(function(){function q(s){return document.querySelectorAll(s).length;}function t(s){var n=document.querySelector(s);return n?n.textContent.replace(/\\s+/g,' ').trim():'';}" +
        "return {tiles:q('#marketList .tile'),camps:q('#campaignList .tile'),people:q('#peopleList .person'),soon:t('#soonLine'),tab:(document.querySelector('[role=tab][aria-selected=true]')||{}).id||null," +
        "rows:q('#listBody .item'),msgs:q('#paneOpen .msg, #paneOpen [data-msg], #paneOpen li'),shell:t('#pfShell'),open:document.body.className};})()");
      // NAMED (Nov 20 2026, FX1): BEFORE /Posts are coming/; since P2-3 the line reads "Video posts are coming. ..."
      if (name === "home") check(at + "Home shows the market, campaigns and people from the fixtures, and the line about video posts", k.tiles === 4 && k.camps === 2 && k.people === 2 && /^Video posts are coming/.test(k.soon), J(k));
      if (name === "inbox-messages") check(at + "the Messages tab lists the two conversations", k.tab === "tab-messages" && k.rows === 2, J(k));
      if (name === "inbox-thread") check(at + "?with= opens the conversation with its messages", k.tab === "tab-messages" && k.msgs >= 2, J(k));
      if (name === "inbox-approvals") check(at + "the Approvals tab lists the waiting proposals", k.tab === "tab-approvals" && k.rows === 10, J(k));
      if (name === "inbox-notifications") check(at + "the Notifications tab lists the three notices", k.tab === "tab-notifications" && k.rows === 3, J(k));
      // NAMED (Nov 20 2026, FX1): BEFORE no Reviews; AFTER the approved design's fourth tab, Reviews (Coming soon). These fixtures answer no follow counts.
      if (name === "profile") check(at + "the profile header: @rose, Sales 12, BizCash 2,400, the tabs with Reviews; no Following or Followers", /@rose/.test(k.shell) && /12\s*Sales/.test(k.shell) && /2,400\s*BizCash/.test(k.shell) && /Posts\s*Shop\s*Services/.test(k.shell) && /Reviews/.test(k.shell) && !/Follow/.test(k.shell), k.shell.slice(0, 300));
    }
  }
  // the screenshots the brief asks for, full length too for the pages that scroll
  for (const [name, url] of [["home", "home.html"], ["profile", "profile.html"], ["inbox-notifications", "inbox.html?tab=notifications"]]) {
    await open(cdp, origin, url, 390, 844, true);
    await shotPage(cdp, path.join(P21_OUT, name + "-390-full.png"), 390);
  }
  console.log("    screenshots: " + P21_OUT);
}

/* ══ P2-2 (Nov 20 2026): PHONE_P22=1 ═══════════════════════════════════════════════════════════════════════════════════
   P2-2's own screens at PHONE_P22_WIDTHS (default 360, 390, 430), screenshots at 390 x 844 to PHONE_P22_OUT (default
   Downloads\p22): the three-dot menu on an Inbox thread, its Report sheet (13 reasons) and its Block confirmation;
   Settings, Blocked and muted; moderation.html as the owner (the Waiting tab, an item) and as anyone else (one line);
   copyright.html (the notice, with ?where= filled in) and its counter-notice form; and the owner's waiting count on the
   dashboard. The fixtures below answer only with PHONE_P22=1 (and P2-1's, which the Inbox thread needs). */
const P22_NID = uid(7001), P22_QID = uid(7002), P22_ITEM = uid(7003);
const P22S = { notOwner: false };
const P22_FIX = {
  relation: { user_id: P21_PEER, self: false, blocked: false, muted: false },
  safety: { blocks: [{ user_id: P21_PEER2, since: ago(48), username: "lee-ceramics", name: "Lee Ceramics", avatar_url: null }],
    mutes: [{ user_id: P21_PEER, since: ago(72), username: "pat", name: "Pat's Pantry", avatar_url: null }] },
  waiting: { tab: "waiting", items: [
    { id: P22_QID, object_type: "listing", object_id: P22_ITEM, owner_id: P21_PEER, author: "@pat", source: "report", priority: 1, report_count: 3, state: "hidden", auto_hidden: true, created_at: ago(5) },
    { id: uid(7004), object_type: "profile", object_id: P21_PEER2, owner_id: P21_PEER2, author: "@lee-ceramics", source: "policy_screen", priority: 2, report_count: 0, state: "waiting", auto_hidden: false, created_at: ago(30) }
  ] },
  item: { item: { id: P22_QID, object_type: "listing", object_id: P22_ITEM, owner_id: P21_PEER, source: "report", priority: 1, report_count: 3, state: "hidden", auto_hidden: true, created_at: ago(5) },
    content: { title: "Spring cake", text: "Fresh spring cakes, made to order.", link: "/listing/spring-cake", media: [{ url: P21_IMG[0], type: "image/png" }] },
    author: { id: P21_PEER, name: "@pat", joined: "2026-10-01", account_age_days: 50, past_removals: 0, banned: false },
    reports: [{ id: "r1", reporter: "@lee-ceramics", reason: "copyright", detail: "These are my photos.", status: "open", created_at: ago(6) },
      { id: "r2", reporter: "@rose", reason: "spam", detail: null, status: "open", created_at: ago(5) }],
    findings: [{ field: "description", rule: "prohibited", category: "alcohol", term: "wine" }], notices: [] },
  storage: { buckets: [{ bucket: "bf-public", bytes: 312 * 1048576, files: 1840, partial: false }, { bucket: "bf-video", bytes: 96 * 1048576, files: 41, partial: false }],
    total_bytes: 408 * 1048576, limit_bytes: 1073741824, percent: 39.8, partial: false, measured_at: new Date(NOW).toISOString(), cached: false },
  counter: { notice: { id: P22_NID, status: "removed", received: "2026-11-18", object_type: "listing", title: "Spring cake", work: "A photo of my wedding cake" } }
};
function p22Api(method, p) {
  if (p === "/api/inbox/counts") return Object.assign({}, P21_FIX.counts, { moderation: 3 });
  if (p === "/api/me/relation") return P22_FIX.relation;
  if (p === "/api/me/safety") return P22_FIX.safety;
  if (p.indexOf("/api/admin/moderation") === 0 && P22S.notOwner) return { __status: 403, __body: { error: "Admin access required" } };
  if (p === "/api/admin/moderation") return P22_FIX.waiting;
  if (p === "/api/admin/moderation/storage") return P22_FIX.storage;
  if (p === "/api/admin/moderation/item/" + P22_QID) return P22_FIX.item;
  if (p === "/api/copyright/counter/" + P22_NID && method === "GET") return P22_FIX.counter;
  return undefined;
}
// The open sheet (scripts/bf-safety.js): inside the screen, every choice and button at least 44 px, focus inside it.
const P22_SHEET = String.raw`(function(){
  var s = document.getElementById("bf-safety"); if (!s || s.hidden) return null;
  var r = s.getBoundingClientRect(), W = innerWidth, H = innerHeight;
  var ctl = [].slice.call(s.querySelectorAll(".bf-safety-item,.bf-safety-btn,.bf-safety-close,.bf-safety-reason")).filter(function(n){ var q = n.getBoundingClientRect(); return q.width > 0 && q.height > 0; });
  var small = ctl.filter(function(n){ var q = n.getBoundingClientRect(); return q.width < 43.5 || q.height < 43.5; }).map(function(n){ var q = n.getBoundingClientRect(); return n.className + " " + Math.round(q.width) + "x" + Math.round(q.height); });
  return { l: Math.round(r.left), r: Math.round(r.right), t: Math.round(r.top), b: Math.round(r.bottom), W: W, H: H, scrolls: s.scrollHeight > s.clientHeight + 1,
    title: (s.querySelector("h2") || {}).textContent || "", items: [].map.call(s.querySelectorAll(".bf-safety-item"), function(n){ return n.textContent.replace(/\s+/g, " ").trim(); }),
    reasons: s.querySelectorAll("input[name=bf-safety-reason]").length, controls: ctl.length, small: small, focus: s.contains(document.activeElement),
    hscroll: document.documentElement.scrollWidth > W + 1 };
})()`;
async function p22Run(cdp, origin) {
  fs.mkdirSync(P22_OUT, { recursive: true });
  console.log("browserCheckPhone P2-2 (the report, block and mute menu, Settings, Moderation, Copyright, the owner's count) at " + P22_WIDTHS.join(", "));
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{localStorage.setItem('bf_token'," + J(ID_TOKEN) + ");}catch(e){}" });
  const ev = x => evaluate(cdp, x);
  const HT = { 360: 780, 390: 844, 430: 932 };
  const viewShot = async (file) => { const r = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(P22_OUT, file), Buffer.from(r.data, "base64")); };
  const pageChecks = async (at, opts) => {
    const m = await ev(MEASURE);
    check(at + "no horizontal scroll", !m.hscroll, J(m.wide));
    check(at + "no text cut off", m.clipped.length === 0, J(m.clipped));
    check(at + "every tap target is at least 44 x 44", m.smallCount === 0, m.smallCount + " " + J(m.small));
    const deco = m.deco.filter(x => !(opts && opts.sheet && /^div#bf-safety-backdrop /.test(x)));
    check(at + "decoration is under the text" + (opts && opts.sheet ? " (the open sheet's scrim aside)" : ""), deco.length === 0, J(deco));
    const over = m.over.filter(x => !/^(div#tmx-presence-root|nav#bf-tabbar) /.test(x) && !(opts && opts.sheet && /^div#bf-safety(-backdrop)? /.test(x)));
    check(at + "no fixed element over text or a control at rest" + (opts && opts.sheet ? " (the open sheet is meant to cover the page)" : ""), over.length === 0, J(over));
    return m;
  };
  const sheetOk = (at, s, w, h, what) => check(at + what + ": the sheet is inside the screen, every choice at least 44 px, focus in it, no sideways scroll",
    !!s && s.l >= -1 && s.r <= w + 1 && s.t >= 0 && s.b <= h + 1 && s.small.length === 0 && s.focus && !s.hscroll, J(s));
  const openMenu = async () => { await ev("(function(){var b=document.querySelector('#openMenu .bf-safety-dots');if(b)b.click();return !!b;})()"); await sleep(600); };

  for (const w of P22_WIDTHS) {
    const h = HT[w] || 844;
    const shot = async name => { if (w === 390) await viewShot(name + "-390x844.png"); };

    // 1. the menu on an Inbox thread, then Report, then Block
    P22S.notOwner = false;
    await open(cdp, origin, "inbox.html?with=" + P21_PEER, w, h, true);
    let at = "P22 inbox thread at " + w + ": ";
    const dots = await ev("(function(){var b=document.querySelector('#openMenu .bf-safety-dots');if(!b)return null;var r=b.getBoundingClientRect();return {w:Math.round(r.width),h:Math.round(r.height),label:b.getAttribute('aria-label'),right:Math.round(r.right)};})()");
    check(at + "the three-dot button is in the thread's header, 44 x 44 or more, named for the member (Report in it is about their latest message)", !!dots && dots.w >= 44 && dots.h >= 44 && dots.right <= w && dots.label === "More options for this profile", J(dots));
    await openMenu();
    let s = await ev(P22_SHEET);
    at = "P22 menu at " + w + ": ";
    sheetOk(at, s, w, h, "Options");
    check(at + "Report, Block, Mute and Send a copyright notice", !!s && s.items.length === 4 && /^Report this message$/.test(s.items[0]) && s.items.some(t => /^Block /.test(t)) && s.items.some(t => /^Mute /.test(t)) &&
      s.items[3] === "Send a copyright notice", J(s && s.items));
    await pageChecks(at, { sheet: true });
    await shot("menu");
    await ev("(function(){var b=document.querySelector('#bf-safety [data-act=report]');if(b)b.click();return !!b;})()"); await sleep(500);
    s = await ev(P22_SHEET);
    at = "P22 report sheet at " + w + ": ";
    sheetOk(at, s, w, h, "Report this message");
    check(at + "the 13 reasons, each a 44 px choice; the sheet scrolls when taller than the screen", !!s && s.reasons === 13 && s.title === "Report this message", J(s && { reasons: s.reasons, title: s.title, scrolls: s.scrolls }));
    await pageChecks(at, { sheet: true });
    await shot("report-sheet");
    await ev("(function(){var b=document.getElementById('bf-safety-cancel');if(b)b.click();return !!b;})()"); await sleep(300);
    await openMenu();
    await ev("(function(){var b=document.querySelector('#bf-safety [data-act=block]');if(b)b.click();return !!b;})()"); await sleep(500);
    s = await ev(P22_SHEET);
    at = "P22 block confirmation at " + w + ": ";
    sheetOk(at, s, w, h, "Block");
    check(at + "asks first, with Block and Cancel, focus on Cancel", !!s && /^Block .+\?$/.test(s.title) && (await ev("document.activeElement && document.activeElement.id")) === "bf-safety-block-no", J(s && s.title));
    await shot("block-confirm");
    await ev("(function(){var b=document.getElementById('bf-safety-block-no');if(b)b.click();return true;})()"); await sleep(300);

    // 2. Settings, Blocked and muted
    await open(cdp, origin, "settings.html#blocked", w, h, true);
    at = "P22 settings blocked at " + w + ": ";
    const st = await ev("(function(){var p=document.getElementById('panel-safety'),l=document.getElementById('safetyList');if(!p||!l)return null;var r=p.getBoundingClientRect();" +
      "return {shown:r.width>0&&r.height>0,rows:l.querySelectorAll('li').length,buttons:[].map.call(l.querySelectorAll('button[data-undo]'),function(b){var q=b.getBoundingClientRect();return b.textContent.trim()+' '+Math.round(q.width)+'x'+Math.round(q.height);})};})()");
    check(at + "#blocked opens the section: one blocked, one muted, with Unblock and Unmute of 44 px or more", !!st && st.shown && st.rows === 2 && st.buttons.length === 2 &&
      /^Unblock /.test(st.buttons[0]) && /^Unmute /.test(st.buttons[1]) && st.buttons.every(b => b.split(" ").pop().split("x").every(n => Number(n) >= 44)), J(st));
    await ev("(function(){var p=document.getElementById('panel-safety');if(p)p.scrollIntoView();return true;})()"); await sleep(200);
    await pageChecks(at);
    await shot("settings-blocked");

    // 3. moderation.html as the owner: the Waiting tab, then an item
    await open(cdp, origin, "moderation.html", w, h, true);
    at = "P22 moderation (owner) at " + w + ": ";
    const mo = await ev("(function(){var v=document.getElementById('ownerView'),o=document.getElementById('ownerOnly');return {view:!v.hidden,only:!o.hidden,tabs:document.querySelectorAll('.tab-btn').length,cards:document.querySelectorAll('#area .card').length,storage:(document.getElementById('storageBody')||{}).textContent||''};})()");
    check(at + "the owner sees the four tabs, the two waiting items and the storage panel", mo.view && !mo.only && mo.tabs === 4 && mo.cards === 2 && /408\.0 MB of 1024\.0 MB used/.test(mo.storage), J(mo));
    await pageChecks(at);
    await shot("moderation");
    await ev("(function(){var b=document.querySelector('[data-open]');if(b)b.click();return !!b;})()"); await sleep(700);
    at = "P22 moderation item at " + w + ": ";
    const it = await ev("(function(){var a=document.querySelectorAll('[data-act]');return {acts:[].map.call(a,function(b){var q=b.getBoundingClientRect();return b.getAttribute('data-act')+' '+Math.round(q.height);}),reports:document.querySelectorAll('.detail .list .card').length,title:(document.querySelector('.detail h2')||{}).textContent||''};})()");
    check(at + "the item: its title, two reports, and Keep, Hide, Remove, Remove and ban (each 44 px or more)", it.title === "Spring cake" && it.reports === 2 &&
      J(it.acts.map(a => a.split(" ")[0])) === J(["keep", "hide", "remove", "ban"]) && it.acts.every(a => Number(a.split(" ")[1]) >= 44), J(it));
    await pageChecks(at);
    await shot("moderation-item");

    // 4. moderation.html as anyone else
    P22S.notOwner = true;
    await open(cdp, origin, "moderation.html", w, h, true);
    at = "P22 moderation (not the owner) at " + w + ": ";
    const no = await ev("(function(){return {view:!document.getElementById('ownerView').hidden,only:!document.getElementById('ownerOnly').hidden,text:document.getElementById('ownerOnly').textContent,cards:document.querySelectorAll('#area .card').length};})()");
    check(at + "one line, and nothing else drawn", !no.view && no.only && no.text === "This page is for the site owner." && no.cards === 0, J(no));
    await pageChecks(at);
    await shot("moderation-not-owner");
    P22S.notOwner = false;

    // 5. copyright.html: the notice (where filled in), then the counter-notice
    await open(cdp, origin, "copyright.html?where=" + encodeURIComponent("https://bizforceai.net/listing/spring-cake"), w, h, true);
    at = "P22 copyright notice at " + w + ": ";
    const cn = await ev("(function(){return {where:document.getElementById('nWhere').value,form:!document.getElementById('noticeView').hidden,counter:!document.getElementById('counterView').hidden,checks:[].map.call(document.querySelectorAll('.check'),function(c){return Math.round(c.getBoundingClientRect().height);})};})()");
    check(at + "the notice form, where filled in from ?where=", cn.form && !cn.counter && cn.where === "https://bizforceai.net/listing/spring-cake", J(cn));
    await pageChecks(at);
    await shot("copyright");
    if (w === 390) await shotPage(cdp, path.join(P22_OUT, "copyright-390-full.png"), 390);
    await open(cdp, origin, "copyright.html?counter=" + P22_NID, w, h, true);
    at = "P22 counter-notice at " + w + ": ";
    const cc = await ev("(function(){var f=document.getElementById('counterForm');return {form:!f.hidden,facts:(document.getElementById('counterFacts')||{}).textContent||'',notice:!document.getElementById('noticeView').hidden};})()");
    check(at + "signed in, the member's own counter form, with what was removed", cc.form && !cc.notice && /Spring cake/.test(cc.facts) && /A photo of my wedding cake/.test(cc.facts), J(cc));
    await pageChecks(at);
    await shot("copyright-counter");

    // 6. the owner's waiting count on the dashboard
    await open(cdp, origin, "dashboard.html", w, h, true);
    at = "P22 dashboard at " + w + ": ";
    const dc = await ev("(function(){var e=document.getElementById('ownerModeration');if(!e)return null;var a=e.querySelector('a'),r=a?a.getBoundingClientRect():null;return {shown:!e.hidden,text:e.textContent.trim(),href:a&&a.getAttribute('href'),h:r&&Math.round(r.height)};})()");
    check(at + "the owner sees \"3 items waiting for review\", a link to Moderation of 44 px or more", !!dc && dc.shown && /^3 items waiting for review/.test(dc.text) && dc.href === "/moderation.html" && dc.h >= 44, J(dc));
    if (w === 390) { await ev("(function(){var e=document.getElementById('ownerModeration');if(e)e.scrollIntoView({block:'center'});return true;})()"); await sleep(200); await viewShot("dashboard-count-390x844.png"); }
  }
  console.log("    screenshots: " + P22_OUT);
}

/* ══ P2-3 (Nov 20 2026): PHONE_P23=1 ═══════════════════════════════════════════════════════════════════════
   P2-3's own screens at PHONE_P23_WIDTHS (default 360, 390, 430), screenshots at 390 x 844 to PHONE_P23_OUT (default
   Downloads\p23): Home's Following feed (a text post, a photo post of two, the member's own), Like, Talk and its sheet,
   the own post's menu (Edit, Delete), Home opened at a post with Talk (a notice's link), compose.html (typing, then
   Post, back on Home with the post first), the profile's Posts and Saved tabs and the follower counts, a storefront's
   Follow, the public post page /p/<id> signed out and signed in, and the feed with few follows (people to follow).
   The answers are the backend's own: lib/posts.js over an in-memory database (scripts/_p23Db.js, with migration 194's
   counters), rebuilt for each width, and the post page drawn by lib/postPage.js from lib/posts.js publicPost. Photos
   are served from P23_STORAGE (the frontend's own brand pictures). Nothing here answers without PHONE_P23=1. */
const P23_STORAGE = "https://p23-storage.test";
const P23S = { db: null, deps: null };
const P23_POST = { text: uid(8001), photo: uid(8002), own: uid(8003), long: uid(8004), other: uid(8005) };
/* NAMED (Nov 21 2026, FX2): while p23Run's FX2 block runs (FX2S.on), a free viewer's /api/auth/me (tier "free"), the agents with the
   display_name and page_url GET /api/agents sends, the Agent Directory's saved view, and the profile's banner (a PUT recorded).
   Off (every other screen, every other run) nothing here answers, so the baselines are unchanged. */
const FX2S = { on: false, inner: false, free: false, banner: null, agView: null, puts: [], profilePuts: [] };
const FX2_LISTING = "5f000000-0000-4000-8000-000000000001";
function fx2Api(method, u, request) {
  const p = u.pathname;
  const body = () => { try { return JSON.parse((request && request.postData) || "{}"); } catch (e) { return {}; } };
  const base = () => { FX2S.inner = true; try { return api(method, u, request); } finally { FX2S.inner = false; } };
  if (p === "/api/auth/me" && FX2S.free) return Promise.resolve(base()).then(a => Object.assign({}, a, { access: Object.assign({}, a.access, { active: false, reason: null, tier: "free" }) }));
  if (p === "/api/agents") return { agents: AGENTS.map(x => Object.assign({}, x, { display_name: x.name, page_url: "/" + x.agent_type + "-agent.html" })) };
  if (p === "/api/user/preferences") {
    if (method === "PUT") { const b = body(); FX2S.puts.push(b); if ("agents_card_view" in b) FX2S.agView = b.agents_card_view; return { saved: true }; }
    return { ok: true, preferences: {}, termaximus_active: true, agents_card_view: FX2S.agView };
  }
  if (p === "/api/bfp/profile/me" && method === "PUT") { FX2S.profilePuts.push(body()); return { ok: true }; }
  if (p === "/api/bfp/profile/me" && method === "GET" && FX2S.banner) return Promise.resolve(base()).then(a => { const c = JSON.parse(J(a)); c.profile = Object.assign({}, c.profile, { banner_url: FX2S.banner }); return c; });
  return undefined;
}
async function p23World(empty) {
  const { memDb } = require("./_p23Db");
  const P = require("../lib/posts");
  const OLD = ago(24 * 60), names = [[ROSE.id, "rose", "Rose"], [P21_PEER, "pat", "Pat's Pantry"], [P21_PEER2, "lee-ceramics", "Lee Ceramics"], [uid(4), "maple-mill", "Maple Mill"]];
  const media = (n, owner, file, alt) => ({ id: uid(8100 + n), user_id: owner, path: "media/" + owner + "/" + file, alt_text: alt, bytes: 40000, created_at: OLD });
  const post = (id, author, extra) => Object.assign({ id, author_id: author, kind: "text", audience: "public", status: "published", place_city: null, place_region: null, place_country: null,
    like_count: 0, comment_count: 0, save_count: 0, share_count: 0, removed_at: null }, extra);
  const at = hrs => ({ created_at: ago(hrs), published_at: ago(hrs) });
  const posts = [
    post(P23_POST.text, P21_PEER, Object.assign({ body: "Fresh jam this Saturday: strawberry, plum and a small batch of fig. Come early, the fig goes first." }, at(1))),
    post(P23_POST.photo, P21_PEER2, Object.assign({ kind: "photo", body: "New mugs out of the kiln today." }, at(3))),
    post(P23_POST.own, ROSE.id, Object.assign({ kind: "photo", body: "Sourdough, second bake of the morning." }, at(5))),
    post(P23_POST.long, P21_PEER, Object.assign({ body: "We are closed on Monday for a family wedding. Orders placed over the weekend go out on Tuesday morning, and every jar ordered before Sunday night gets a free sample of the new marmalade. Thank you for your patience." }, at(26))),
    post(P23_POST.other, uid(4), Object.assign({ body: "Stone-ground flour, milled this week." }, at(2)))
  ];
  const db = memDb({
    // NAMED (Nov 20 2026, P3-1): every member has confirmed their email (a public post needs it, lib/emailVerification.js)
    users: names.map(n => ({ id: n[0], created_at: OLD, email_verified_at: OLD })), posts, post_comments: [], post_likes: [], post_saves: [], post_share_days: [], notifications: [], moderation_queue: [],
    follows: empty ? [] : [{ follower_id: ROSE.id, following_id: P21_PEER, created_at: OLD }, { follower_id: ROSE.id, following_id: P21_PEER2, created_at: OLD }, { follower_id: P21_PEER, following_id: ROSE.id, created_at: OLD }],
    member_blocks: [], member_mutes: [], profiles: [],
    categories: require("./_categories").rows(),   // NAMED (Nov 23 2026, P3-3): the one category list (migration 200), which createPost checks
    member_media: [media(1, P21_PEER2, "mug-1.png", "A blue glazed mug"), media(2, P21_PEER2, "mug-1-thumb.png", ""), media(3, P21_PEER2, "mug-2.png", "A green glazed mug"), media(4, ROSE.id, "bread.png", "A sourdough loaf")],
    post_media: [{ post_id: P23_POST.photo, media_id: uid(8101), thumb_media_id: uid(8102), idx: 0 }, { post_id: P23_POST.photo, media_id: uid(8103), thumb_media_id: null, idx: 1 },
      { post_id: P23_POST.own, media_id: uid(8104), thumb_media_id: null, idx: 0 }],
    bf_profiles: names.map((n, i) => ({ user_id: n[0], username: n[1], display_name: n[2], avatar_url: null, updated_at: ago(i + 1) }))
  });
  const deps = { sb: db.client, now: () => new Date(NOW).toISOString(), claims: () => null, ownerPublic: async () => true, push: async () => {}, env: { SUPABASE_URL: P23_STORAGE } };
  // the counts come from the rows, as migration 194's triggers keep them
  await P.like(deps, P21_PEER2, P23_POST.text, true); await P.like(deps, uid(4), P23_POST.text, true);
  await P.like(deps, ROSE.id, P23_POST.photo, true); await P.like(deps, P21_PEER, P23_POST.photo, true);
  await P.addComment(deps, P21_PEER, P23_POST.photo, { body: "These are lovely. Do you take orders for a set of six?" });
  await P.addComment(deps, ROSE.id, P23_POST.photo, { body: "The blue one would suit the shop counter." });
  await P.save(deps, ROSE.id, P23_POST.long, true);
  db.t.notifications.length = 0;
  return { db, deps };
}
const P23_IS = p => /^\/api\/(feed\/|posts|comments\/|follows|bfp\/seller\/pat$|me\/relation$)/.test(p);
async function p23Api(method, u, request) {
  const P = require("../lib/posts"), d = P23S.deps, me = ROSE.id, p = u.pathname, q = k => u.searchParams.get(k) || undefined;
  let b = {}; try { b = JSON.parse((request && request.postData) || "{}"); } catch (e) { b = {}; }
  const out = r => r.status === 200 ? r.body : { __status: r.status, __body: r.body };
  let m;
  if (p === "/api/feed/following" && method === "GET") return out(await P.followingFeed(d, me, q("cursor")));
  if (p === "/api/posts/saved") return out(await P.savedPosts(d, me, q("cursor")));
  if ((m = /^\/api\/posts\/by\/([^/]+)$/.exec(p))) return out(await P.postsByAuthor(d, me, m[1], q("cursor")));
  if (p === "/api/posts" && method === "POST") return out(await P.createPost(d, me, b));
  // NAMED (Nov 23 2026, P3-3): the composer's place and listings, and a Need marked Found or reopened
  if (p === "/api/posts/composer" && method === "GET") return out(await P.composerInfo(d, me));
  if ((m = /^\/api\/posts\/([^/]+)\/found$/.exec(p))) return out(await P.markFound(d, me, m[1], method === "POST"));
  if ((m = /^\/api\/posts\/([^/]+)\/comments$/.exec(p))) return out(method === "POST" ? await P.addComment(d, me, m[1], b) : await P.listComments(d, me, m[1], q("after")));
  if ((m = /^\/api\/posts\/([^/]+)\/(like|save)$/.exec(p))) return out(await P[m[2]](d, me, m[1], method === "POST"));
  if ((m = /^\/api\/posts\/([^/]+)\/share$/.exec(p))) return out(await P.share(d, me, m[1]));
  if ((m = /^\/api\/posts\/([0-9a-f-]{36})$/.exec(p))) return out(method === "PATCH" ? await P.editPost(d, me, m[1], b) : method === "DELETE" ? await P.deletePost(d, me, m[1]) : await P.getPost(d, me, m[1]));
  if ((m = /^\/api\/comments\/([^/]+)$/.exec(p)) && method === "DELETE") return out(await P.deleteComment(d, me, m[1]));
  if ((m = /^\/api\/comments\/([^/]+)\/hide$/.exec(p))) return out(await P.hideComment(d, me, m[1]));
  if (p === "/api/follows" && method === "POST") return out(await P.follow(d, me, b));
  if ((m = /^\/api\/follows\/([^/]+)\/counts$/.exec(p))) return out(await P.followCounts(d, me, m[1]));
  if ((m = /^\/api\/follows\/([^/]+)\/(followers|following)$/.exec(p))) return out(await P.followList(d, me, m[1], m[2], q("cursor")));
  if ((m = /^\/api\/follows\/([^/]+)$/.exec(p)) && method === "DELETE") return out(await P.unfollow(d, me, m[1]));
  if (p === "/api/me/relation") {   // as the server answers it: self for the member and the member's own posts
    const who = q("user_id") || (q("object_type") === "post" ? ((P23S.db.t.posts.find(x => x.id === q("object_id")) || {}).author_id) : null) ||
      ((P23S.db.t.bf_profiles.find(x => x.username === q("handle")) || {}).user_id);
    if (!who) return { __status: 404, __body: { error: "Not found" } };
    return { user_id: who, self: who === me, blocked: false, muted: false };
  }
  if (p === "/api/bfp/seller/pat") return { seller: { user_id: P21_PEER, username: "pat", display_name: "Pat's Pantry", tagline: "Jams and preserves", avatar_url: null }, products: [], services: [], support_links: [] };
  // NAMED (Nov 20 2026, FX1): a visitor's view of Lee Ceramics' profile (profile.html?id=<Lee>)
  if (p === "/api/bfp/seller/lee-ceramics") return { seller: { user_id: P21_PEER2, username: "lee-ceramics", display_name: "Lee Ceramics", avatar_url: null }, products: [], services: [], support_links: [] };
  return { __status: 404, __body: { error: "Not found" } };
}
// NAMED (Nov 20 2026, FX1): Lee Ceramics' public profile and counts, for the visitor's view; only with PHONE_P23=1
const FX1_LEE = { profile: { user_id: P21_PEER2, username: "lee-ceramics", display_name: "Lee Ceramics", title: "Potter", tagline: "Lee Ceramics", bio: "Hand-thrown mugs and bowls, glazed in small batches.", avatar_url: null },
  member: true };   // NAMED (Nov 20 2026, P3-1): the server's own member flag (ownerIsMember); Lee is a member
function fx1Api(method, p) {
  if (p === "/api/bfp/profile/" + P21_PEER2) return FX1_LEE;
  if (p === "/api/bfp/profile/" + P21_PEER2 + "/stats") return { stats: { sales: 3 } };
  return undefined;
}
/* NAMED (Nov 20 2026, FX1): the approved design's boxes, measured in the page (scripts/designSpec.js). Every box is the
   element's getBoundingClientRect; a style is getComputedStyle. */
const FX1_FEED_MEASURE = String.raw`(function(id){
  var R=function(e){if(!e)return null;var r=e.getBoundingClientRect();return {l:+r.left.toFixed(1),t:+r.top.toFixed(1),r:+r.right.toFixed(1),b:+r.bottom.toFixed(1),w:+r.width.toFixed(1),h:+r.height.toFixed(1)};};
  var S=function(e,p,pe){return e?getComputedStyle(e,pe||null)[p]:null;};
  var post=document.querySelector('#feed [data-post="'+id+'"]');if(!post)return null;
  var bar=document.getElementById('bf-tabbar'),act=document.querySelector('.feed-tab[aria-selected=true]'),mk=document.getElementById('tabMarket');
  var tabs=[].filter.call(document.querySelectorAll('.feed-tab'),function(t){return t.getBoundingClientRect().width>0;});
  var rail=post.querySelector('.bfp-actions');
  var items=[].filter.call(rail.children,function(c){return c.matches('.bfp-rail-av,.bfp-act')&&getComputedStyle(c).display!=='none';});
  var av=post.querySelector('.bfp-rail-av'),dot=post.querySelector('.bfp-badge:not([hidden]) .bfp-badge-dot'),badge=post.querySelector('.bfp-badge:not([hidden])');
  var meta=post.querySelector('.bfp-meta'),name=post.querySelector('.bfp-name'),text=post.querySelector('.bfp-info .bfp-text');
  var plus=bar&&bar.querySelector('.bf-tab-plus'),home=bar&&bar.querySelector('[data-tab=home]');
  return {W:innerWidth,H:innerHeight,bar:R(bar),barBg:S(bar,'backgroundColor'),barBorder:S(bar,'borderTopColor'),homeColor:S(home,'color'),plus:R(plus),plusRadius:S(plus,'borderTopLeftRadius'),
    live:R(document.getElementById('feedLive')),search:R(document.getElementById('feedSearch')),
    tabs:tabs.map(function(t){return {text:t.textContent.trim(),box:R(t),font:S(t,'fontSize'),weight:S(t,'fontWeight'),color:S(t,'color'),sel:t.getAttribute('aria-selected')};}),
    under:{h:S(act,'height','::after'),bg:S(act,'backgroundColor','::after'),bottom:S(act,'bottom','::after'),content:S(act,'content','::after')},
    dot:{w:S(mk,'width','::before'),h:S(mk,'height','::before'),top:S(mk,'top','::before'),bg:S(mk,'backgroundColor','::before'),content:S(mk,'content','::before')},
    rail:R(rail),items:items.map(function(c){var ic=c.querySelector('svg:not(.ic-desk)')||c.querySelector('svg');var lab=c.querySelector('.bfp-word')&&getComputedStyle(c.querySelector('.bfp-word')).display!=='none'?c.querySelector('.bfp-word'):c.querySelector('span:not(.bfp-word)');
      return {kind:c.classList.contains('bfp-rail-av')?'avatar':c.getAttribute('data-act'),box:R(c),icon:R(ic),label:lab?lab.textContent:'',labelFont:S(lab,'fontSize'),color:S(c,'color'),vis:S(c,'visibility')};}),
    av:R(av&&av.querySelector('.bfp-rail-pic')),avBg:S(av&&av.querySelector('.bfp-rail-pic'),'backgroundImage'),badge:R(badge),badgeDot:R(dot),dotBg:S(dot,'backgroundColor'),
    meta:R(meta),metaGap:S(meta,'rowGap'),name:R(name),nameFont:S(name,'fontSize'),nameWeight:S(name,'fontWeight'),text:R(text),textFont:S(text,'fontSize'),textLine:S(text,'lineHeight'),
    hidden:{handle:!!post.querySelector('.bfp-handle')&&post.querySelector('.bfp-handle').getBoundingClientRect().width>0,dots:!!post.querySelector('.bfp-menu .bf-safety-dots')&&post.querySelector('.bfp-menu .bf-safety-dots').getBoundingClientRect().width>0}};
})`;
const FX1_PROFILE_MEASURE = String.raw`(function(){
  var R=function(e){if(!e)return null;var r=e.getBoundingClientRect();return {l:+r.left.toFixed(1),t:+r.top.toFixed(1),r:+r.right.toFixed(1),b:+r.bottom.toFixed(1),w:+r.width.toFixed(1),h:+r.height.toFixed(1)};};
  var S=function(e,p){return e?getComputedStyle(e)[p]:null;};
  var vis=function(e){return !!e&&e.getBoundingClientRect().width>0;};
  var q=function(s){return document.querySelector(s);};
  var stats=[].filter.call(document.querySelectorAll('.pfs-stats > li'),vis).map(function(li){var n=li.querySelector('.pfs-num'),l=li.querySelector('.pfs-lab');return {label:l.textContent,num:n.textContent,box:R(li),numBox:R(n),numFont:S(n,'fontSize'),numColor:S(n,'color'),labFont:S(l,'fontSize')};}).sort(function(a,b){return a.box.l-b.box.l;});
  var btns=[].filter.call(document.querySelectorAll('.pfs-actions .pfs-btn'),vis).map(function(b){return {text:b.textContent.trim(),id:b.id,cls:b.className,box:R(b),radius:S(b,'borderTopLeftRadius'),bg:S(b,'backgroundColor'),font:S(b,'fontSize'),weight:S(b,'fontWeight')};});
  var tabs=[].filter.call(document.querySelectorAll('.pfs-tab'),vis).map(function(t){return {text:t.textContent.trim(),box:R(t),sel:t.getAttribute('aria-selected'),under:S(t,'borderBottomWidth'),underColor:S(t,'borderBottomColor')};});
  var cells=[].filter.call(document.querySelectorAll('#pfsPanel .pfs-cell'),vis).map(function(c){var lb=c.querySelector('.pfs-cell-label');return {box:R(c),label:vis(lb)?lb.textContent:null,labelBox:R(lb),labelFont:S(lb,'fontSize')};});
  var store=q('.pfs-store'),bio=q('.pfs-bio'),tb=q('.pfs-tabs');
  return {W:innerWidth,bar:R(q('.pfs-bar')),invite:R(q('#pfsInvite')),menu:R(q('#pfsMenu')),title:R(q('.pfs-title')),titleText:(q('.pfs-title')||{}).textContent,titleFont:S(q('.pfs-title'),'fontSize'),titleWeight:S(q('.pfs-title'),'fontWeight'),
    av:R(q('.pfs-av')),avPad:S(q('.pfs-av'),'paddingTop'),avBg:S(q('.pfs-av'),'backgroundImage'),avInner:S(q('.pfs-av-in'),'backgroundColor'),initials:(q('.pfs-av-in')||{}).textContent,
    handle:R(q('.pfs-handle')),handleText:(q('.pfs-handle')||{}).textContent,handleFont:S(q('.pfs-handle'),'fontSize'),stats:stats,btns:btns,
    bio:R(bio),bioFont:S(bio,'fontSize'),bioAlign:S(bio,'textAlign'),store:R(store),storeText:store?store.textContent.trim():'',
    tabsBox:R(tb),divider:S(tb,'borderBottomWidth'),dividerColor:S(tb,'borderBottomColor'),tabs:tabs,cells:cells,
    oldHeader:[].some.call(document.querySelectorAll('.pf-nav,.pf-banner,.pf-header-wrap'),vis),fab:vis(document.getElementById('tmx-guide-root'))};   // NAMED (Nov 22 2026, FX3): BEFORE the book button; AFTER the Guide's tab, kept off this screen
})()`;
// FX1: the before and after screenshots beside the design pictures (Downloads\design), named by FX1_TAG (default "after")
const FX1_DIR = path.join(os.homedir(), "Downloads", "design");
const FX1_TAG = process.env.FX1_TAG === "before" ? "before" : "after";
async function p23PostPage(id) {
  const P = require("../lib/posts"), PG = require("../lib/postPage");
  const post = PG.isPostId(id) ? await P.publicPost(P23S.deps, id) : null;
  return { code: post ? 200 : 404, html: PG.renderPostPage(post) };
}
// an open sheet or panel: inside the screen, its controls 44 px or more, no sideways scroll
const P23_BOX = String.raw`(function(sel, ctl){
  var s = document.querySelector(sel); if (!s || s.hidden) return null;
  var r = s.getBoundingClientRect(), W = innerWidth;
  var c = [].slice.call(s.querySelectorAll(ctl)).filter(function(n){ var q = n.getBoundingClientRect(); return q.width > 0 && q.height > 0; });
  var small = c.filter(function(n){ var q = n.getBoundingClientRect(); return q.width < 43.5 || q.height < 43.5; }).map(function(n){ var q = n.getBoundingClientRect(); return (n.id || n.className || n.tagName) + " " + Math.round(q.width) + "x" + Math.round(q.height); });
  return { l: Math.round(r.left), r: Math.round(r.right), t: Math.round(r.top), b: Math.round(r.bottom), W: W, H: innerHeight, controls: c.length, small: small, hscroll: document.documentElement.scrollWidth > W + 1 };
})`;
async function p23Run(cdp, origin) {
  fs.mkdirSync(P23_OUT, { recursive: true });
  console.log("browserCheckPhone P2-3 (the Following feed, Like, Talk, the post menu, compose, the profile's posts, Follow, the public post page, few follows) at " + P23_WIDTHS.join(", "));
  // a token whose payload names Rose (the profile shell reads the id from it), except while signed out
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{if(!sessionStorage.getItem('phone_check_out'))localStorage.setItem('bf_token'," + J(ID_TOKEN) + ");}catch(e){}" });
  // NAMED (Nov 21 2026, FX2): the orbit's turn, frame by frame ([time, base, open]), only while sessionStorage fx2_frames is set (the FX2 block)
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{if(sessionStorage.getItem('fx2_frames')){window.__fr=[];var fx2f=function(ts){var O=window.BFOrbit;if(O&&O.state)window.__fr.push([ts,O.state.base,!!O.state.open]);if(window.__fr.length<600)requestAnimationFrame(fx2f);};requestAnimationFrame(fx2f);}}catch(e){}" });
  const ev = x => evaluate(cdp, x);
  const HT = { 360: 780, 390: 844, 430: 932 };
  const viewShot = async file => { const r = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(P23_OUT, file), Buffer.from(r.data, "base64")); };
  // NAMED (Nov 20 2026, FX1): at the pictures' own scale (1 px per CSS px), beside them in Downloads\design
  const fx1Shot = async file => { fs.mkdirSync(FX1_DIR, { recursive: true });
    const r = await cdp.send("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width: 390, height: 844, scale: 0.5 } });
    fs.writeFileSync(path.join(FX1_DIR, file), Buffer.from(r.data, "base64")); };
  const SHEETS = /^(div|section|aside)[#.](bf-safety|bf-safety-backdrop|bfp-talk|bfp-talk-backdrop|bfp-soon|bfp-soon-back|pfs-menu|pfs-menu-back)[ .]/;   // NAMED (Nov 20 2026, FX1): + the Coming soon sheet and the profile menu
  const pageChecks = async (at, opts) => {
    const m = await ev(MEASURE);
    check(at + "no horizontal scroll", !m.hscroll, J(m.wide));
    // a text post's square tile on the profile is a preview, its whole post one tap away: its clipped excerpt is set aside (named)
    const tiles = await ev("[].map.call(document.querySelectorAll('.pfs-cell.is-text > span'),function(s){return s.textContent.slice(0,40);})");
    const clipped = m.clipped.filter(x => !tiles.some(t => x.indexOf('"' + t.slice(0, 30)) !== -1));
    check(at + "no text cut off" + (clipped.length < m.clipped.length ? " (a text post's tile excerpt aside)" : ""), clipped.length === 0, J(clipped));
    check(at + "every tap target is at least 44 x 44", m.smallCount === 0, m.smallCount + " " + J(m.small));
    const deco = m.deco.filter(x => !(opts && opts.sheet && SHEETS.test(x)));
    check(at + "decoration is under the text" + (opts && opts.sheet ? " (the open sheet's scrim aside)" : ""), deco.length === 0, J(deco));
    const over = m.over.filter(x => !/^(div#tmx-presence-root|nav#bf-tabbar) /.test(x) && !(opts && opts.sheet && SHEETS.test(x)));
    check(at + "no fixed element over text or a control at rest" + (opts && opts.sheet ? " (the open sheet is meant to cover the page)" : ""), over.length === 0, J(over));
    return m;
  };
  const inScreen = (b, w, h) => !!b && b.l >= -1 && b.r <= w + 1 && b.t >= -1 && b.b <= h + 1 && b.small.length === 0 && !b.hscroll;
  const postBox = id => ev("(function(){var e=document.querySelector('#feed [data-post=\"" + id + "\"]');if(!e)return null;var r=e.getBoundingClientRect();" +
    "var acts=[].filter.call(e.querySelectorAll('.bfp-act'),function(b){return getComputedStyle(b).visibility!=='hidden';}).map(function(b){var q=b.getBoundingClientRect();return b.getAttribute('data-act')+' '+Math.round(q.width)+'x'+Math.round(q.height)+' '+(b.getAttribute('aria-pressed')||'');});" +
    "return {l:Math.round(r.left),r:Math.round(r.right),w:Math.round(r.width),h:Math.round(r.height),acts:acts,name:(e.querySelector('.bfp-name')||{}).textContent||'',photos:e.querySelectorAll('.bfp-photo').length,follow:!!e.querySelector('.bfp-follow'),dots:!!e.querySelector('.bfp-menu .bf-safety-dots')&&e.querySelector('.bfp-menu .bf-safety-dots').getBoundingClientRect().width>0,like:(e.querySelector('[data-count=like]')||{}).textContent||'',talk:(e.querySelector('[data-count=talk]')||{}).textContent||''};})()");
  const scrollTo = id => ev("(function(){var e=document.querySelector('#feed [data-post=\"" + id + "\"]');if(e)e.scrollIntoView({block:'start'});return !!e;})()").then(() => sleep(500));
  const click = sel => ev("(function(){var e=document.querySelector(" + J(sel) + ");if(e)e.click();return !!e;})()");
  const big = s => s.split(" ")[1].split("x").every(n => Number(n) >= 44);
  /* NAMED (Nov 20 2026, FX1): the feed against the approved design (scripts/designSpec.js), within DS.TOLERANCE px */
  const DS = require("./designSpec");
  const near = (a, b) => typeof a === "number" && Math.abs(a - b) <= DS.TOLERANCE;
  const px = v => Number(String(v).replace("px", ""));
  const rgb = hex => "rgb(" + [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16)).join(", ") + ")";
  const fx1Feed = async (w, id, badge) => {
    const at = "FX1 feed at " + w + ": ", F = DS.FEED, m = await ev(FX1_FEED_MEASURE + "(" + J(id) + ")");
    if (!m) { check(at + "the post is on the screen", false, "not found"); return null; }
    const barTop = m.bar.t;
    if (badge) {
      check(at + "the follow badge: " + F.RAIL.BADGE + " px cyan, centred on the avatar's bottom edge, its tap area 44 x 44", !!m.badgeDot && near(m.badgeDot.w, F.RAIL.BADGE) && near(m.badgeDot.h, F.RAIL.BADGE) &&
        near((m.badgeDot.t + m.badgeDot.b) / 2, m.av.b) && near((m.badgeDot.l + m.badgeDot.r) / 2, (m.av.l + m.av.r) / 2) && m.dotBg === rgb(DS.COLOR.ACCENT) && m.badge.w >= 44 && m.badge.h >= 44, J([m.badgeDot, m.av, m.dotBg, m.badge]));
      return m;
    }
    check(at + "the top row " + F.TOP.ROW_TOP + " px down: Live " + F.TOP.BUTTON + " px at " + F.TOP.LIVE_LEFT + ", Search " + F.TOP.BUTTON + " px " + F.TOP.SEARCH_RIGHT + " px from the right",
      near(m.live.t, F.TOP.ROW_TOP) && near(m.live.w, F.TOP.BUTTON) && near(m.live.h, F.TOP.BUTTON) && near(m.live.l, F.TOP.LIVE_LEFT) &&
      near(m.search.t, F.TOP.ROW_TOP) && near(m.search.w, F.TOP.BUTTON) && near(m.search.r, w - F.TOP.SEARCH_RIGHT), J([m.live, m.search]));
    check(at + "the tabs Local, Following, Market, For You in order, " + F.TOP.TAB_FONT + " px " + F.TOP.TAB_WEIGHT + ", " + F.TOP.TAB_HEIGHT + " px tall, between Live and Search; Following white, the rest " + DS.COLOR.TAB_INACTIVE,
      J(m.tabs.map(t => t.text)) === J(F.TOP.TABS) && m.tabs.every(t => px(t.font) === F.TOP.TAB_FONT && Number(t.weight) === F.TOP.TAB_WEIGHT && near(t.box.h, F.TOP.TAB_HEIGHT) && near(t.box.t, F.TOP.ROW_TOP) &&
        t.box.l >= m.live.r - 1 && t.box.r <= m.search.l + 1 && t.color === (t.sel === "true" ? rgb(DS.COLOR.WHITE) : rgb(DS.COLOR.TAB_INACTIVE))) && m.tabs[1].sel === "true", J(m.tabs));
    check(at + "the active tab's underline " + F.TOP.UNDERLINE + " px cyan at its bottom; Market's dot " + F.TOP.DOT + " px cyan, " + F.TOP.DOT_TOP + " px from the tab's top",
      px(m.under.h) === F.TOP.UNDERLINE && m.under.bg === rgb(DS.COLOR.ACCENT) && px(m.under.bottom) < 2 && px(m.dot.w) === F.TOP.DOT && px(m.dot.h) === F.TOP.DOT && px(m.dot.top) === F.TOP.DOT_TOP && m.dot.bg === rgb(DS.COLOR.ACCENT), J([m.under, m.dot]));
    const kinds = m.items.map(i => i.kind);
    check(at + "the rail: " + F.RAIL.ORDER.join(", ") + "; " + F.RAIL.WIDTH + " px wide, " + F.RAIL.RIGHT + " px from the right, its bottom " + F.RAIL.BOTTOM_ABOVE_BAR + " px above the bar",
      J(kinds) === J(F.RAIL.ORDER) && near(m.rail.w, F.RAIL.WIDTH) && near(m.rail.r, w - F.RAIL.RIGHT) && near(m.items[m.items.length - 1].box.b, barTop - F.RAIL.BOTTOM_ABOVE_BAR), J([kinds, m.rail, barTop]));
    const gaps = m.items.slice(1).map((it, i) => +(it.box.t - m.items[i].box.b).toFixed(1));
    check(at + "the rail's items " + F.RAIL.GAP + " px apart; the avatar " + F.RAIL.AVATAR + " px, the gradient; each action " + F.RAIL.ITEM + " px tall with a " + F.RAIL.ICON + " px icon over a " + F.RAIL.LABEL_FONT + " px label",
      gaps.every(g => near(g, F.RAIL.GAP)) && near(m.av.w, F.RAIL.AVATAR) && near(m.av.h, F.RAIL.AVATAR) && /linear-gradient/.test(m.avBg) &&
      m.items.slice(1).every(i => near(i.box.h, F.RAIL.ITEM) && near(i.icon.w, F.RAIL.ICON) && near(i.icon.h, F.RAIL.ICON) && px(i.labelFont) === F.RAIL.LABEL_FONT), J([gaps, m.av, m.items]));
    const tip = m.items.find(i => i.kind === "tip");
    // NAMED (Nov 21 2026, FX2): BEFORE "Tip BFC's slot is kept, unseen" for everyone. AFTER Rose (a paid member) sees it, gold;
    // a free viewer's stays unseen, in the same place (the FX2 block below).
    check(at + "Tip BFC shown for a paid member, its label gold", !!tip && tip.vis === "visible" && tip.color === rgb(DS.COLOR.GOLD) && tip.label === "Tip BFC", J(tip));
    check(at + "the bottom-left block " + F.META.LEFT + " px from the left, its right edge " + F.META.RIGHT + " px from the screen's, its bottom " + F.META.BOTTOM_ABOVE_BAR + " px above the bar; the name " + F.META.NAME_FONT + " px bold, the caption " + F.META.CAPTION_FONT + " px, " + F.META.GAP + " px between",
      near(m.meta.l, F.META.LEFT) && near(m.meta.r, w - F.META.RIGHT) && near(m.meta.b, barTop - F.META.BOTTOM_ABOVE_BAR) && px(m.nameFont) === F.META.NAME_FONT && Number(m.nameWeight) === F.META.NAME_WEIGHT &&
      !!m.text && px(m.textFont) === F.META.CAPTION_FONT && near(px(m.textLine), F.META.CAPTION_FONT * F.META.CAPTION_LINE) && near(m.text.t - m.name.b, F.META.GAP), J([m.meta, m.name, m.text, m.nameFont, m.textFont, m.textLine]));
    check(at + "no handle and no three-dot menu on the screen (Share opens the menu)", !m.hidden.handle && !m.hidden.dots, J(m.hidden));
    check(at + "the bar " + DS.BAR.HEIGHT + " px, " + DS.BAR.FEED_BG + " with a " + DS.BAR.FEED_BORDER + " line, Home white; the + " + DS.BAR.PLUS_W + " x " + DS.BAR.PLUS_H + ", radius " + DS.BAR.PLUS_RADIUS,
      near(m.bar.h, DS.BAR.HEIGHT) && near(m.bar.b, m.H) && m.barBg === rgb(DS.BAR.FEED_BG) && m.barBorder === rgb(DS.BAR.FEED_BORDER) && m.homeColor === rgb(DS.COLOR.WHITE) &&
      near(m.plus.w, DS.BAR.PLUS_W) && near(m.plus.h, DS.BAR.PLUS_H) && px(m.plusRadius) === DS.BAR.PLUS_RADIUS, J([m.bar, m.barBg, m.barBorder, m.homeColor, m.plus, m.plusRadius]));
    return m;
  };
  /* NAMED (Nov 20 2026, FX1): the profile against the approved design (scripts/designSpec.js PROFILE), within DS.TOLERANCE px.
     The buttons', tabs' and grid's tops follow a one-line bio and handle, so they are pinned at 390 only. */
  const fx1Profile = async (w, owner) => {
    const at = "FX1 profile " + (owner ? "(owner)" : "(visitor)") + " at " + w + ": ", P = DS.PROFILE, m = await ev(FX1_PROFILE_MEASURE);
    if (!m || !m.bar) { check(at + "the phone header is on the screen", false, J(m)); return null; }
    check(at + "the page's old header (its buttons, banner and picture) and the Guide's tab are not on the screen", !m.oldHeader && !m.fab, J([m.oldHeader, m.fab]));
    check(at + "the top row " + P.TOP.ROW_TOP + " px down: add friends and the menu " + P.TOP.BUTTON + " px, " + P.TOP.PAD_X + " px from each side, the name centred, " + P.TOP.NAME_FONT + " px bold",
      near(m.bar.t, P.TOP.ROW_TOP) && near(m.invite.w, P.TOP.BUTTON) && near(m.invite.h, P.TOP.BUTTON) && near(m.invite.l, P.TOP.PAD_X) && near(m.menu.w, P.TOP.BUTTON) && near(m.menu.r, w - P.TOP.PAD_X) &&
      near((m.title.l + m.title.r) / 2, w / 2) && px(m.titleFont) === P.TOP.NAME_FONT && Number(m.titleWeight) === P.TOP.NAME_WEIGHT && m.titleText === (owner ? "Rose" : "Lee Ceramics"), J([m.bar, m.invite, m.menu, m.title, m.titleText]));
    check(at + "the picture " + P.AVATAR.SIZE + " px, centred, " + P.AVATAR.TOP + " px down, a " + P.AVATAR.RING + " px cyan-to-violet ring, the initials on " + P.AVATAR.INNER,
      near(m.av.w, P.AVATAR.SIZE) && near(m.av.h, P.AVATAR.SIZE) && near(m.av.t, P.AVATAR.TOP) && near((m.av.l + m.av.r) / 2, w / 2) && px(m.avPad) === P.AVATAR.RING && /linear-gradient/.test(m.avBg) &&
      m.avInner === rgb(P.AVATAR.INNER) && m.initials === (owner ? "R" : "LC"), J([m.av, m.avPad, m.avInner, m.initials]));
    check(at + "the handle " + P.HANDLE.FONT + " px, " + P.HANDLE.GAP + " px under the picture, with BizForce member (a paid member's)",
      near(m.handle.t, m.av.b + P.HANDLE.GAP) && px(m.handleFont) === P.HANDLE.FONT && m.handleText === (owner ? "@rose · BizForce member" : "@lee-ceramics · BizForce member"), J([m.handle, m.handleText]));
    const labels = m.stats.map(x => x.label), want = owner ? P.STATS.LABELS : P.STATS.LABELS.filter(l => l !== "BizCash");
    const colW = (w - 2 * P.STATS.PAD_X) / want.length;
    check(at + "the counts " + want.join(", ") + " evenly across, " + P.STATS.NUM_FONT + " px numbers over " + P.STATS.LABEL_FONT + " px labels, " + P.STATS.GAP + " px under the handle" + (owner ? "; BizCash gold (the owner's, a paid member's)" : "; no BizCash for a visitor"),
      J(labels) === J(want) && m.stats.every((x, i) => near((x.box.l + x.box.r) / 2, P.STATS.PAD_X + colW * (i + 0.5)) && px(x.numFont) === P.STATS.NUM_FONT && px(x.labFont) === P.STATS.LABEL_FONT) &&
      near(m.stats[0].numBox.t, m.handle.b + P.STATS.GAP) && (!owner || m.stats[3].numColor === rgb(DS.COLOR.GOLD)), J(m.stats));
    const B = P.BUTTONS, pair = m.btns.filter(b => !/is-wallet/.test(b.cls));
    check(at + (owner ? "Edit profile and Share profile, equal, and the " + B.WALLET + " px gold wallet" : "Follow (Following) and Message, equal") + "; " + B.HEIGHT + " px tall, radius " + B.RADIUS + ", " + B.GAP + " px apart, " + B.PAD_X + " px from each side, " + B.FONT + " px semibold",
      pair.length === 2 && J(pair.map(b => b.text)) === J(owner ? ["Edit profile", "Share profile"] : ["Following", "Message"]) && near(pair[0].box.w, pair[1].box.w) && m.btns.every(b => near(b.box.h, B.HEIGHT) && px(b.radius) === B.RADIUS) &&
      near(m.btns[0].box.l, B.PAD_X) && near(m.btns[m.btns.length - 1].box.r, w - B.PAD_X) && m.btns.slice(1).every((b, i) => near(b.box.l - m.btns[i].box.r, B.GAP)) &&
      pair.every(b => px(b.font) === B.FONT && Number(b.weight) === B.WEIGHT) &&
      (owner ? m.btns.length === 3 && near(m.btns[2].box.w, B.WALLET) && m.btns[2].bg === rgb(B.WALLET_BG) && pair.every(b => b.bg === rgb(B.FILL)) : m.btns.length === 2) &&
      (w !== 390 || !owner || near(m.btns[0].box.t, B.TOP)), J(m.btns));
    check(at + "the bio " + P.BIO.FONT + " px, centred, " + P.BIO.GAP + " px under the buttons; Visit (my) storefront " + P.STORE.HEIGHT + " px, centred, under it",
      !!m.bio && px(m.bioFont) === P.BIO.FONT && m.bioAlign === "center" && near(m.bio.t, m.btns[0].box.b + P.BIO.GAP) && /^Visit (my )?storefront$/.test(m.storeText) && m.store.h >= P.STORE.HEIGHT - 1 &&
      near((m.store.l + m.store.r) / 2, w / 2) && near(m.store.t, m.bio.b + P.STORE.GAP), J([m.bio, m.bioFont, m.bioAlign, m.store, m.storeText]));
    check(at + "the tabs " + P.TABS.ORDER.join(", ") + ", equal across the whole width, " + P.TABS.HEIGHT + " px; Posts white with a " + P.TABS.UNDERLINE + " px cyan underline; a " + P.TABS.DIVIDER + " px " + P.TABS.DIVIDER_COLOR + " divider" + (w === 390 && owner ? "; " + P.TABS.TOP + " px down" : ""),
      J(m.tabs.map(t => t.text)) === J(P.TABS.ORDER) && m.tabs.every((t, i) => near(t.box.w, w / 4) && near(t.box.l, i * w / 4) && near(t.box.h, P.TABS.HEIGHT)) &&
      m.tabs[0].sel === "true" && px(m.tabs[0].under) === P.TABS.UNDERLINE && m.tabs[0].underColor === rgb(DS.COLOR.ACCENT) && px(m.divider) === P.TABS.DIVIDER && m.dividerColor === rgb(P.TABS.DIVIDER_COLOR) &&
      (w !== 390 || !owner || near(m.tabs[0].box.t, P.TABS.TOP)), J([m.tabs, m.divider, m.dividerColor]));
    const G = P.GRID, cw = (w - 2 * G.INSET - (G.COLUMNS - 1) * G.GAP) / G.COLUMNS;
    if (owner) check(at + "the grid " + G.COLUMNS + " across, " + G.GAP + " px apart, " + G.INSET + " px in; 3:4 tiles, each with its " + G.LABEL_FONT + " px label at the bottom left" + (w === 390 ? "; " + G.TOP + " px down" : ""),
      m.cells.length >= 1 && m.cells.every((c, i) => near(c.box.l, G.INSET + (i % G.COLUMNS) * (cw + G.GAP)) && near(c.box.w, cw) && near(c.box.h, cw * G.ASPECT) &&
        !!c.label && px(c.labelFont) === G.LABEL_FONT && near(c.labelBox.l, c.box.l + 6) && near(c.labelBox.b, c.box.b - 6)) && near(m.cells[0].box.t, m.tabsBox.b + G.INSET) &&
      (w !== 390 || near(m.cells[0].box.t, G.TOP)), J(m.cells));
    return m;
  };

  for (const w of P23_WIDTHS) {
    const h = HT[w] || 844;
    const shot = async name => { if (w === 390) await viewShot(name + "-390x844.png"); };
    Object.assign(P23S, await p23World(false));

    // 1. the Following feed
    await open(cdp, origin, "home.html", w, h, true);
    let at = "P23 Home feed at " + w + ": ";
    const feed = await ev("(function(){var t=document.getElementById('tabFollowing');return {ids:[].map.call(document.querySelectorAll('#feed .bfp-post'),function(e){return e.getAttribute('data-post');}),full:document.body.classList.contains('feed-full'),empty:!document.getElementById('feedEmpty').hidden,tab:t&&t.getAttribute('aria-selected')};})()");
    check(at + "the posts of the people followed and the member's own, newest first; a member not followed is not in it",
      J(feed.ids) === J([P23_POST.text, P23_POST.photo, P23_POST.own, P23_POST.long]) && feed.full && !feed.empty && feed.tab === "true", J(feed));
    const first = await postBox(P23_POST.text);
    // NAMED (Nov 20 2026, FX1): BEFORE "...; the menu's three dots" (first.dots); AFTER no three dots on a phone's full-screen
    // post (the approved design): Share opens the post's options (step 4). The unseen Tip BFC slot is not counted.
    // NAMED (Nov 21 2026, FX2): BEFORE Like, Talk, Save and Share (Tip unseen). AFTER Tip BFC between Talk and Save (Rose is a paid member).
    check(at + "a post is the screen's width; Like, Talk, Tip BFC, Save and Share, each 44 x 44 or more; no three dots (Share opens the options)", !!first && Math.abs(first.w - w) <= 1 &&
      J(first.acts.map(a => a.split(" ")[0])) === J(["like", "talk", "tip", "save", "share"]) && first.acts.every(big) && !first.dots && first.name === "Pat's Pantry", J(first));
    // nothing of the page shows through a full-screen post: the legal footer is at the feed's end, not over the first post
    const foot = await ev("(function(){var f=document.querySelector('.bf-legal-footer');if(!f)return null;var r=f.getBoundingClientRect();var hit=[].some.call(f.querySelectorAll('a'),function(a){var q=a.getBoundingClientRect();if(q.bottom<=0||q.top>=innerHeight)return false;var e=document.elementFromPoint(q.left+q.width/2,q.top+q.height/2);return !!e&&(e===a||a.contains(e));});return {inFeed:!!f.closest('#feed'),top:Math.round(r.top),seen:hit};})()");
    check(at + "the legal footer is at the feed's end, never painted over a post", !!foot && foot.inFeed && !foot.seen && foot.top >= h, J(foot));
    await ev("(function(){var f=document.getElementById('feed');f.scrollTop=f.scrollHeight;return true;})()"); await sleep(600);
    const footEnd = await ev("(function(){var f=document.querySelector('.bf-legal-footer'),a=f&&f.querySelector('a');if(!a)return null;var q=a.getBoundingClientRect();var e=document.elementFromPoint(q.left+q.width/2,q.top+q.height/2);return {top:Math.round(q.top),reach:!!e&&(e===a||a.contains(e))};})()");
    check(at + "at the feed's end the footer's links can be tapped", !!footEnd && footEnd.reach, J(footEnd));
    await ev("(function(){var f=document.getElementById('feed');f.scrollTop=0;return true;})()"); await sleep(500);
    await pageChecks(at);
    await shot("home-feed");
    await scrollTo(P23_POST.photo);
    const ph = await postBox(P23_POST.photo);
    check(at + "a photo post: two photos, liked already (Like pressed), two likes and two comments counted", !!ph && ph.photos === 2 && /^like .* true$/.test(ph.acts[0]) && ph.talk === "2" && ph.like === "2", J(ph));
    await pageChecks(at + "photo post: ");
    await shot("home-photo-post");
    if (w === 390) await fx1Shot("live-feed-" + FX1_TAG + ".png");
    await fx1Feed(w, P23_POST.photo, false);
    await click("#tabMarket"); await sleep(400);
    const fsoon = await ev("(function(){var s=document.getElementById('bfp-soon');if(!s||s.hidden)return null;var r=s.getBoundingClientRect();return {key:s.getAttribute('data-soon'),b:Math.round(r.bottom),l:Math.round(r.left),r:Math.round(r.right),focus:document.activeElement&&document.activeElement.id};})()");
    check("FX1 feed at " + w + ": Market opens the Coming soon sheet, a bottom sheet across the screen, Close focused", !!fsoon && fsoon.key === "market" && fsoon.b <= h + 1 && fsoon.l <= 1 && fsoon.r >= w - 1 && fsoon.focus === "bfpSoonClose", J(fsoon));
    await pageChecks("FX1 feed Coming soon at " + w + ": ", { sheet: true });
    await click("#bfpSoonClose"); await sleep(300);
    const fshut = await ev("(function(){return {hidden:document.getElementById('bfp-soon').hidden,focus:document.activeElement&&document.activeElement.id};})()");
    check("FX1 feed at " + w + ": Close shuts it and focus returns to Market", fshut.hidden && fshut.focus === "tabMarket", J(fshut));

    // 2. Like, through lib/posts.js
    await scrollTo(P23_POST.text);
    await click('#feed [data-post="' + P23_POST.text + '"] .bfp-act[data-act=like]'); await sleep(600);
    const liked = await postBox(P23_POST.text);
    const row = P23S.db.t.post_likes.some(x => x.post_id === P23_POST.text && x.user_id === ROSE.id);
    check(at + "Like: pressed, the count 2 to 3, and the like is stored", !!liked && /^like .* true$/.test(liked.acts[0]) && liked.like === "3" && row, J([liked && liked.acts[0], liked && liked.like, row]));

    // 3. Talk
    await scrollTo(P23_POST.photo);
    await click('#feed [data-post="' + P23_POST.photo + '"] .bfp-act[data-act=talk]'); await sleep(900);
    at = "P23 Talk at " + w + ": ";
    const talk = await ev(P23_BOX + "('#bfp-talk','button,textarea,input')");
    const talkInfo = await ev("(function(){var l=document.querySelectorAll('#bfpTalkList > li');return {items:l.length,focus:document.activeElement&&document.activeElement.id};})()");
    check(at + "the sheet is inside the screen with the two comments, the box focused, every control 44 px or more", inScreen(talk, w, h) && talkInfo.items === 2 && talkInfo.focus === "bfpTalkInput", J([talk, talkInfo]));
    await ev("(function(){var i=document.getElementById('bfpTalkInput');i.value='Saturday morning works for me.';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()");
    await click("#bfpTalkSend"); await sleep(800);
    const after = await ev("(function(){var c=document.querySelector('#feed [data-post=\"" + P23_POST.photo + "\"] [data-count=talk]');return {items:document.querySelectorAll('#bfpTalkList > li').length,count:c?c.textContent:''};})()");
    check(at + "Send adds the comment to the sheet and the post's count (2 to 3), and it is stored", after.items === 3 && after.count === "3" && P23S.db.t.post_comments.length === 3, J(after));
    await pageChecks(at, { sheet: true });
    await shot("talk");
    await click("#bfpTalkClose"); await sleep(400);

    // 4. the member's own post: the menu has Edit and Delete
    await scrollTo(P23_POST.own);
    // NAMED (Nov 20 2026, FX1): BEFORE the three dots; AFTER Share (the approved design has no three dots on a full-screen post)
    await click('#feed [data-post="' + P23_POST.own + '"] .bfp-act[data-act=share]'); await sleep(700);
    at = "P23 own post menu at " + w + ": ";
    const menu = await ev("(function(){var s=document.getElementById('bf-safety');if(!s||s.hidden)return null;var r=s.getBoundingClientRect();return {items:[].map.call(s.querySelectorAll('.bf-safety-item'),function(n){var q=n.getBoundingClientRect();return n.textContent.replace(/\\s+/g,' ').trim()+' '+Math.round(q.height);}),b:Math.round(r.bottom),r:Math.round(r.right)};})()");
    check(at + "Share link, Edit and Delete (no Report, Block or Mute of oneself), each 44 px or more, inside the screen", !!menu && menu.items.some(x => /^Share link /.test(x)) && menu.items.some(x => /^Edit /.test(x)) && menu.items.some(x => /^Delete /.test(x)) &&
      !menu.items.some(x => /^(Block|Mute|Report)/.test(x)) && menu.items.every(x => Number(x.split(" ").pop()) >= 44) && menu.b <= h + 1 && menu.r <= w + 1, J(menu));
    await pageChecks(at, { sheet: true });
    await shot("own-post-menu");

    // 5. Home opened at a post with Talk (a notice's link, the public page's buttons)
    await open(cdp, origin, "home.html?post=" + P23_POST.long + "&talk=1", w, h, true);
    at = "P23 Home at a post at " + w + ": ";
    const linked = await ev("(function(){var f=document.querySelector('#feed .bfp-post');var t=document.getElementById('bfp-talk');return {first:f&&f.getAttribute('data-post'),talk:!!t&&!t.hidden};})()");
    check(at + "home.html?post=<id>&talk=1: that post first, with Talk open", linked.first === P23_POST.long && linked.talk, J(linked));
    await pageChecks(at, { sheet: true });
    // NAMED (Nov 20 2026, FX1): a post by a member not followed (opened by its link): the rail's follow badge
    await open(cdp, origin, "home.html?post=" + P23_POST.other, w, h, true);
    await fx1Feed(w, P23_POST.other, true);

    // 6. compose.html: type, Post, back on Home with the post first
    await open(cdp, origin, "compose.html", w, h, true);
    at = "P23 compose at " + w + ": ";
    // NAMED (Nov 21 2026, P3-1B): "who sees it" is the audience fieldset, not the first .bfc-aud (P3-1B put What is it first)
    const cp = await ev(P23_BOX + "('#composer','button,textarea,select')");
    const cpInfo = await ev("(function(){var t=document.querySelector('.bfc-text');return {text:!!t,count:(document.querySelector('.bfc-count')||{}).textContent||'',post:!!document.querySelector('.bfc-post'),aud:(document.querySelector('.bfc-aud:not(#bfcIntent)')||{}).textContent||'',soon:(document.querySelector('.bfc-soon')||{}).textContent||''};})()");
    check(at + "the box, the count, photos, who sees it, and Post; every control inside the screen and 44 px or more", !!cp && cp.small.length === 0 && !cp.hscroll && cp.r <= w + 1 &&
      cpInfo.text && /^0 \/ 2,?200$/.test(cpInfo.count.trim()) && cpInfo.post && /Public/.test(cpInfo.aud) && /Followers/.test(cpInfo.aud), J([cp, cpInfo]));
    await ev("(function(){var t=document.querySelector('.bfc-text');t.focus();t.value='Cinnamon buns on Friday. Twelve only.';t.dispatchEvent(new Event('input',{bubbles:true}));return true;})()"); await sleep(200);
    // NAMED (Nov 23 2026, P3-3): every post names a category (the chips from GET /api/categories); Food & Cooking
    await ev("(function(){var r=document.querySelector('input[name=bfcCat][value=food]');if(r)(r.closest('label')||r).click();return !!r;})()"); await sleep(150);
    const count2 = await ev("(document.querySelector('.bfc-count')||{}).textContent||''");
    check(at + "the count follows the typing", /^37 \/ 2,?200$/.test(count2.trim()), count2);
    await pageChecks(at);
    await shot("compose");
    await click(".bfc-post"); await sleep(3000);
    const back = await ev("(function(){var f=document.querySelector('#feed .bfp-post');return {path:location.pathname,first:f?((f.querySelector('.bfp-textcard,.bfp-text')||{}).textContent||''):''};})()");
    const stored = P23S.db.t.posts.filter(x => x.author_id === ROSE.id && x.body === "Cinnamon buns on Friday. Twelve only.");
    check(at + "Post stores it (lib/posts.js createPost) and goes Home, the new post first", stored.length === 1 && back.path === "/home.html" && back.first === "Cinnamon buns on Friday. Twelve only.", J([back, stored.length]));

    // 7. the profile: Posts, Saved, the follower counts
    await open(cdp, origin, "profile.html", w, h, true);
    at = "P23 profile at " + w + ": ";
    const pf = await ev("(function(){var tabs=[].filter.call(document.querySelectorAll('.pfs-tab'),function(t){return t.getBoundingClientRect().width>0;}).map(function(t){return t.textContent.trim();});var cells=document.querySelectorAll('#pfsPanel [data-post-tile]').length;" +
      "var stats=[].map.call(document.querySelectorAll('.pfs-stat'),function(s){return s.textContent.replace(/\\s+/g,' ').trim();});return {tabs:tabs,cells:cells,stats:stats};})()");
    // NAMED (Nov 20 2026, FX1): BEFORE the tabs Posts, Shop, Services and Saved; AFTER on a phone the approved design's Posts, Shop,
    // Services and Reviews (Saved is in the menu); only the tabs on the screen are read
    check(at + "Posts, Shop, Services and Reviews; the member's two posts as tiles (the new one too); 1 follower, 2 following", J(pf.tabs) === J(DS.PROFILE.TABS.ORDER) && pf.cells === 2 &&
      pf.stats.some(s => /^1\s*Followers?$/.test(s)) && pf.stats.some(s => /^2\s*Following$/.test(s)), J(pf));
    await pageChecks(at);
    await shot("profile-posts");
    if (w === 390) await fx1Shot("live-profile-" + FX1_TAG + ".png");
    await fx1Profile(w, true);
    // NAMED (Nov 20 2026, FX1): BEFORE the Saved tab; AFTER the menu's Saved posts (a phone has no Saved tab)
    await click("#pfsMenu"); await sleep(400);
    const mn = await ev("(function(){var m=document.getElementById('pfs-menu');if(!m||m.hidden)return null;var r=m.getBoundingClientRect();return {items:[].map.call(m.querySelectorAll('.pfs-menu-item'),function(n){return n.textContent.trim()+' '+Math.round(n.getBoundingClientRect().height);}),b:Math.round(r.bottom)};})()");
    check(at + "the menu: Saved posts, Your data, Settings and Executive HQ, each 44 px or more, inside the screen", !!mn && ["Saved posts", "Your data", "Settings", "Executive HQ"].every(k => mn.items.some(x => x.indexOf(k + " ") === 0)) &&
      mn.items.every(x => Number(x.split(" ").pop()) >= 44) && mn.b <= h + 1, J(mn));
    await pageChecks(at + "menu: ", { sheet: true });
    await click('#pfs-menu [data-pfs-go="saved"]'); await sleep(500);
    const sv = await ev("(function(){return {cells:[].map.call(document.querySelectorAll('#pfsPanel [data-post-tile]'),function(c){return c.getAttribute('data-post-tile');}),sel:document.getElementById('pfs-tab-saved').getAttribute('aria-selected')};})()");
    check(at + "Saved: the one saved post", sv.sel === "true" && J(sv.cells) === J([P23_POST.long]), J(sv));
    await pageChecks(at + "saved: ");
    await shot("profile-saved");
    // NAMED (Nov 20 2026, FX1): a visitor's view of another member's profile
    await open(cdp, origin, "profile.html?id=" + P21_PEER2, w, h, true);
    await pageChecks("P23 profile (visitor) at " + w + ": ");
    await fx1Profile(w, false);
    await click("#pfs-tab-reviews"); await sleep(400);
    const soon = await ev("(function(){var s=document.getElementById('bfp-soon');if(!s||s.hidden)return null;var r=s.getBoundingClientRect();var c=document.getElementById('bfpSoonClose').getBoundingClientRect();return {key:s.getAttribute('data-soon'),text:s.textContent,b:Math.round(r.bottom),close:Math.round(c.height),focus:document.activeElement&&document.activeElement.id};})()");
    check("FX1 profile (visitor) at " + w + ": Reviews opens the Coming soon sheet (a bottom sheet, Close 44 px and focused)", !!soon && soon.key === "reviews" && /Coming soon/.test(soon.text) && soon.b <= h + 1 && soon.close >= 44 && soon.focus === "bfpSoonClose", J(soon));
    await ev("(function(){var s=document.getElementById('bfp-soon');s.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));return true;})()"); await sleep(300);
    const shut = await ev("(function(){var s=document.getElementById('bfp-soon');return {hidden:!!s&&s.hidden,focus:document.activeElement&&document.activeElement.id};})()");
    check("FX1 profile (visitor) at " + w + ": Escape closes it and focus returns to the Reviews tab", shut.hidden && shut.focus === "pfs-tab-reviews", J(shut));
    if (w === 390) await fx1Shot("live-profile-visitor-" + FX1_TAG + ".png");

    // 8. a storefront's Follow (Rose follows Pat already)
    await open(cdp, origin, "@pat", w, h, true);
    at = "P23 storefront at " + w + ": ";
    const sf = await ev("(function(){var b=document.getElementById('sfFollow');if(!b)return null;var r=b.getBoundingClientRect();return {text:b.textContent.trim(),w:Math.round(r.width),h:Math.round(r.height),r:Math.round(r.right),count:(document.getElementById('sfFollowers')||{}).textContent||''};})()");
    check(at + "Following (already followed), 44 px or more, with the follower count", !!sf && sf.text === "Following" && sf.w >= 44 && sf.h >= 44 && sf.r <= w && /1 follower/i.test(sf.count), J(sf));
    await pageChecks(at);
    await shot("storefront-follow");
    await click("#sfFollow"); await sleep(700);
    const unf = await ev("(document.getElementById('sfFollow')||{}).textContent||''");
    check(at + "tapping it unfollows (stored), and it reads Follow", unf.trim() === "Follow" && !P23S.db.t.follows.some(f => f.follower_id === ROSE.id && f.following_id === P21_PEER), J(unf));

    // 9. the public post page, signed out, then signed in
    await ev("sessionStorage.setItem('phone_check_out','1'),localStorage.removeItem('bf_token'),localStorage.removeItem('bf_user'),localStorage.removeItem('bf_return_to'),true");
    await open(cdp, origin, "p/" + P23_POST.photo, w, h, true);
    at = "P23 public post page (signed out) at " + w + ": ";
    const pp = await ev("(function(){var m=document.getElementById('postPage');if(!m)return null;var so=document.getElementById('ppSignedOut');return {state:m.getAttribute('data-state'),acts:[].map.call(document.querySelectorAll('[data-pp-act]'),function(a){var r=a.getBoundingClientRect();return a.getAttribute('data-pp-act')+' '+Math.round(r.width)+'x'+Math.round(r.height)+' '+a.getAttribute('href');}),photos:document.querySelectorAll('.pp-photos img').length,signedOut:!!so&&!so.hidden,robots:(document.querySelector('meta[name=robots]')||{}).content};})()");
    check(at + "the post, its two photos, Like, Talk, Save and Follow (each 44 px or more) to sign in, noindex", !!pp && pp.state === "on" && pp.photos === 2 && pp.acts.length === 4 &&
      pp.acts.every(a => / \/app\.html$/.test(a) && big(a)) && pp.robots === "noindex", J(pp));
    await pageChecks(at);
    await shot("post-page-signed-out");
    await click('[data-pp-act="like"]'); await sleep(1200);
    const ret = await ev("({path:location.pathname,ret:localStorage.getItem('bf_return_to')})");
    check(at + "Like keeps this page and goes to sign-in", ret.path === "/app.html" && ret.ret === "/p/" + P23_POST.photo, J(ret));
    await ev("sessionStorage.removeItem('phone_check_out'),localStorage.removeItem('bf_return_to'),true");
    await open(cdp, origin, "p/" + P23_POST.photo, w, h, true);
    at = "P23 public post page (signed in) at " + w + ": ";
    const pin = await ev("[].map.call(document.querySelectorAll('[data-pp-act]'),function(a){return a.getAttribute('data-pp-act')+' '+a.getAttribute('href');})");
    check(at + "Like, Talk and Save open the post in the app (Talk with &talk=1), Follow the author's storefront", J(pin) === J(["like /home.html?post=" + P23_POST.photo, "talk /home.html?post=" + P23_POST.photo + "&talk=1",
      "save /home.html?post=" + P23_POST.photo, "follow /@lee-ceramics"]), J(pin));
    await pageChecks(at);
    await shot("post-page-signed-in");
    await open(cdp, origin, "p/" + uid(8999), w, h, true);
    const none = await ev("(document.querySelector('h1')||{}).textContent||''");
    check("P23 public post page (no such post) at " + w + ": No post found", none === "No post found", J(none));

    // 10. few follows: people to follow
    Object.assign(P23S, await p23World(true));
    await open(cdp, origin, "home.html", w, h, true);
    at = "P23 few follows at " + w + ": ";
    const em = await ev("(function(){var f=document.getElementById('findPeople');return {find:!!f&&!f.hidden,people:[].map.call(document.querySelectorAll('#findPeople [data-follow]'),function(b){var r=b.getBoundingClientRect();return b.textContent.trim()+' '+Math.round(r.width)+'x'+Math.round(r.height);}),own:document.querySelectorAll('#feed .bfp-post').length};})()");
    check(at + "only the member's own post, then people to follow, each Follow 44 px or more", em.own === 1 && em.find && em.people.length === 3 && em.people.every(big), J(em));
    await ev("(function(){var f=document.getElementById('findPeople');if(f)f.scrollIntoView({block:'center'});return true;})()"); await sleep(400);
    await pageChecks(at);
    await shot("home-few-follows");
    await click("#findPeople [data-follow]"); await sleep(700);
    check(at + "Follow there is stored", P23S.db.t.follows.length === 1 && P23S.db.t.follows[0].follower_id === ROSE.id, J(P23S.db.t.follows));
  }

  /* ══ FX2 (Nov 21 2026): at 390 x 844 (the tabs at every width), screenshots to Downloads\design (fx1Shot's scale) ══
     The feed with a linked listing (Rose, a paid member): the rail 16 px above the bar, level with the caption block, Tip BFC
     shown; the product strip (a 40 px tile, the title, the price, the cyan Buy pill) one link to the listing. A free viewer:
     Tip unseen, nothing moved. The tabs on one line. The dashboard's first settle (no jump, no jerk, at rest on ORACLE's
     front place in SETTLE_MS; under reduced motion, placed at once), then the Sun in the centre with its gold ring (the
     shimmer stopped under reduced motion). The Profile without and with a banner (Edit profile: Change banner, Remove).
     The Agent Directory: Compact by default, Grid two across, the choice saved and kept after a reload. */
  {
    const w = 390, h = 844, F = DS.FEED, G = DS.COLOR;
    console.log("\n  FX2 at " + w + " x " + h);
    Object.assign(P23S, await p23World());
    const db = P23S.db, first = db.t.posts.slice().sort((a, b) => Date.parse(b.published_at) - Date.parse(a.published_at))[0];
    db.t.marketplace_listings = [{ id: FX2_LISTING, slug: "strawberry-jam", seller_id: first.author_id, title: "Strawberry jam, 12 oz jar", price_bfc: 9, media: [], status: "active", created_at: first.created_at }];
    first.listing_id = FX2_LISTING;
    Object.assign(FX2S, { on: true, free: false, banner: null, agView: null, puts: [], profilePuts: [] });
    const STRIP = String.raw`(function(id){var R=function(e){if(!e)return null;var r=e.getBoundingClientRect();return {l:+r.left.toFixed(1),t:+r.top.toFixed(1),r:+r.right.toFixed(1),b:+r.bottom.toFixed(1),w:+r.width.toFixed(1),h:+r.height.toFixed(1)};};
      var post=document.querySelector('#feed [data-post="'+id+'"]');var b=post&&post.querySelector('.bfp-buy');var tip=post&&post.querySelector('.bfp-tip');var go=b&&b.querySelector('.bfp-buy-go');
      return {tag:b&&b.tagName,href:b&&b.getAttribute('href'),box:R(b),tile:R(b&&b.querySelector('.bfp-buy-tile')),go:R(go),goBg:go&&getComputedStyle(go).backgroundColor,goText:go&&go.textContent.trim(),text:b&&b.textContent.replace(/\s+/g,' ').trim(),
        inMeta:!!(b&&b.closest('.bfp-meta')),tip:tip&&{vis:getComputedStyle(tip).visibility,hidden:tip.getAttribute('aria-hidden'),dis:tip.disabled,tab:tip.getAttribute('tabindex'),label:tip.getAttribute('aria-label')}};})`;

    // 1. the feed with a listing, a paid member
    await open(cdp, origin, "home.html", w, h, true);
    let at = "FX2 feed (a paid member) at " + w + ": ";
    const m = await ev(FX1_FEED_MEASURE + "(" + J(first.id) + ")"), st = await ev(STRIP + "(" + J(first.id) + ")");
    if (!m || !st) check(at + "the newest post is on the screen", false, J([!!m, st]));
    else {
      const last = m.items[m.items.length - 1], gaps = m.items.slice(1).map((it, i) => +(it.box.t - m.items[i].box.b).toFixed(1));
      check(at + "the rail " + F.RAIL.ORDER.join(", ") + ", every one shown, " + F.RAIL.GAP + " px apart; its bottom " + F.RAIL.BOTTOM_ABOVE_BAR + " px above the bar's top",
        J(m.items.map(i => i.kind)) === J(F.RAIL.ORDER) && m.items.every(i => i.vis === "visible") && gaps.every(g => near(g, F.RAIL.GAP)) && near(last.box.b, m.bar.t - F.RAIL.BOTTOM_ABOVE_BAR),
        J([m.items.map(i => i.kind + " " + i.vis + " " + i.box.t + "-" + i.box.b), m.bar.t]));
      check(at + "the rail's bottom is level with the bottom-left block's (the caption and the strip)", near(last.box.b, m.meta.b), J([last.box.b, m.meta.b]));
      check(at + "Tip BFC gold, reachable, labelled", !!st.tip && st.tip.vis === "visible" && st.tip.hidden === null && !st.tip.dis && st.tip.tab === null && st.tip.label === "Tip BFC" &&
        m.items.find(i => i.kind === "tip").color === rgb(G.GOLD), J(st.tip));
      check(at + "the product strip in the bottom-left block: a " + F.STRIP.TILE + " px tile, the title, the price, a cyan Buy pill " + F.STRIP.BUY_HEIGHT + " px tall; one link to /listing/strawberry-jam",
        st.tag === "A" && st.href === "/listing/strawberry-jam" && st.inMeta && !!st.tile && near(st.tile.w, F.STRIP.TILE) && near(st.tile.h, F.STRIP.TILE) &&
        /Strawberry jam, 12 oz jar/.test(st.text) && /9 BFC/.test(st.text) && st.goText === "Buy" && st.goBg === rgb(G.ACCENT) && near(st.go.h, F.STRIP.BUY_HEIGHT) && st.box.h >= 44 && st.box.r <= w - F.META.RIGHT + DS.TOLERANCE,
        J(st));
      await pageChecks(at);
      await fx1Shot("live-feed-after-fx2.png");
      FX2S.memberRail = m.items.map(i => [i.kind, i.box]);
      FX2S.memberMeta = m.meta;
    }
    const other = db.t.posts.find(p => p.id !== first.id && p.status === "published" && !p.listing_id);
    const none = other ? await ev("(function(){var p=document.querySelector('#feed [data-post=\"" + other.id + "\"]');return p?!!p.querySelector('.bfp-buy'):null;})()") : null;
    check(at + "a post with no listing has no strip", none === false, J(none));
    await click("#feed [data-post=\"" + first.id + "\"] .bfp-buy"); await sleep(1200);
    const went = await ev("location.pathname");
    check(at + "tapping the strip opens the listing's page", went === "/listing/strawberry-jam", J(went));

    // 2. a free viewer: Tip unseen, nothing moves
    FX2S.free = true;
    await open(cdp, origin, "home.html", w, h, true);
    at = "FX2 feed (a free viewer) at " + w + ": ";
    const mf = await ev(FX1_FEED_MEASURE + "(" + J(first.id) + ")"), sf = await ev(STRIP + "(" + J(first.id) + ")");
    if (!mf || !sf) check(at + "the newest post is on the screen", false, J([!!mf, sf]));
    else {
      check(at + "Tip BFC unseen and out of reach (disabled, out of the tab order, hidden from readers)", !!sf.tip && sf.tip.vis === "hidden" && sf.tip.hidden === "true" && sf.tip.dis && sf.tip.tab === "-1", J(sf.tip));
      const moved = (FX2S.memberRail || []).filter(([k, b], i) => !mf.items[i] || mf.items[i].kind !== k || ["l", "t", "r", "b"].some(e => Math.abs(mf.items[i].box[e] - b[e]) > 0.5));
      check(at + "nothing moves: every rail item and the bottom-left block where a member's are", !!FX2S.memberRail && moved.length === 0 && ["l", "t", "r", "b"].every(e => Math.abs(mf.meta[e] - FX2S.memberMeta[e]) <= 0.5), J(moved));
      check(at + "the strip is the same for a free viewer", sf.href === "/listing/strawberry-jam", J(sf.href));
      await pageChecks(at);
      await fx1Shot("live-feed-free-fx2.png");
    }
    FX2S.free = false;

    // 3. the tabs on one line at every width
    for (const tw of P23_WIDTHS) {
      await open(cdp, origin, "home.html", tw, HT[tw] || h, true);
      const tb = await ev("[].filter.call(document.querySelectorAll('.feed-tab'),function(t){return t.getBoundingClientRect().width>0;}).map(function(t){var r=document.createRange();r.selectNodeContents(t);var tops={};[].forEach.call(r.getClientRects(),function(q){if(q.width>0)tops[Math.round(q.top)]=1;});var b=t.getBoundingClientRect();return {text:t.textContent.trim(),ws:getComputedStyle(t).whiteSpace,lines:Object.keys(tops).length,h:Math.round(b.height),r:Math.round(b.right)};})");
      check("FX2 tabs at " + tw + ": " + F.TOP.TABS.join(", ") + " each on one line (never wrapped), inside the screen",
        J(tb.map(t => t.text)) === J(F.TOP.TABS) && tb.every(t => t.ws === "nowrap" && t.lines === 1 && near(t.h, F.TOP.TAB_HEIGHT) && t.r <= tw), J(tb));
    }

    // 4. the dashboard's first settle, then the Sun
    const frames = async reduced => {
      await cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: reduced ? "reduce" : "no-preference" }] });
      await ev("sessionStorage.removeItem('bf_orbit_portal'),sessionStorage.setItem('fx2_frames','1'),true");
      await open(cdp, origin, "dashboard.html", w, h, true);
      await sleep(1200);
      const r = await ev("(function(){var f=window.__fr||[],O=window.BFOrbit;return {f:f,drift:O&&O.DRIFT_MS,open:O&&O.state.open,front:O&&O.state.open?O.frontBase(O.state.open):null,base:O&&O.state.base,ms:O&&O.SETTLE_MS};})()");
      await ev("sessionStorage.removeItem('fx2_frames'),true");
      return r;
    };
    const mod = x => ((x % 360) + 360) % 360, same = (a, b) => Math.abs(((a - b) % 360 + 540) % 360 - 180) < 0.01;
    let fr = await frames(false);
    at = "FX2 HQ orbit at " + w + ": ";
    {
      const f = fr.f || [], oi = f.findIndex(x => x[2]);
      const seg = oi > 0 ? f.slice(oi - 1) : [];
      const speeds = seg.slice(1).map((x, i) => (x[1] - seg[i][1]) / ((x[0] - seg[i][0]) / 1000));   // degrees a second
      let endAt = null; for (let i = oi; oi >= 0 && i < f.length; i++) if (same(f[i][1], fr.front)) { endAt = f[i][0] - f[oi - 1][0]; break; }
      // the two frame loops (the orbit's and this recorder's) sample a frame at slightly different moments, so the speed is read over 100 ms windows
      const win = []; for (let t = seg.length ? seg[0][0] : 0; seg.length && t + 100 <= seg[seg.length - 1][0]; t += 100) {
        const at2 = x => { let k = seg.findIndex(q => q[0] >= x); if (k <= 0) return seg[0][1]; const a = seg[k - 1], b = seg[k]; return a[1] + (b[1] - a[1]) * (x - a[0]) / (b[0] - a[0]); };
        win.push((at2(t + 100) - at2(t)) * 10); }
      const jerks = win.slice(1).map((v, i) => Math.abs(v - win[i]));
      const steps = seg.slice(1).map((x, i) => Math.abs(x[1] - seg[i][1]));
      const driftSpeed = 360 / fr.drift * 1000;
      check(at + "the drift turned before the first opening (" + (oi > 0 ? f.slice(0, oi).length : 0) + " frames)", oi > 5 && Math.abs(f[oi - 1][1] - f[0][1]) > 0.01, J(f.slice(0, 3)));
      check(at + "it eases to rest, no jump: it starts at the drift's own speed (" + driftSpeed.toFixed(1) + " deg/s), its speed (over 100 ms) changes by at most 1.5 deg/s, stays under 6, and no frame moves it over 0.5 deg",
        speeds.length > 20 && win.length >= 10 && Math.abs(win[0] - driftSpeed) <= 1.5 && jerks.every(j => j <= 1.5) && win.every(v => Math.abs(v) <= 6) && steps.every(d => d <= 0.5),
        J([win.map(v => +v.toFixed(2)), Math.max.apply(null, jerks.concat([0])).toFixed(2), Math.max.apply(null, steps.concat([0])).toFixed(3)]));
      check(at + "at rest on " + fr.open + "'s front place in " + DS.ORBIT.SETTLE_MS + " ms (" + DS.ORBIT.SETTLE_MIN_MS + " to " + DS.ORBIT.SETTLE_MAX_MS + "), and still after",
        fr.ms === DS.ORBIT.SETTLE_MS && endAt !== null && endAt >= DS.ORBIT.SETTLE_MIN_MS - 50 && endAt <= DS.ORBIT.SETTLE_MAX_MS + 50 && same(fr.base, fr.front) && same(f[f.length - 1][1], fr.front), J([endAt, fr.base, fr.front, fr.ms]));
    }
    fr = await frames(true);
    {
      const f = fr.f || [], bases = f.map(x => x[1]);
      check(at + "under reduced motion nothing turns: placed at once on the front place", f.length > 20 && bases.every(b => same(b, bases[0])) && same(fr.base, fr.front), J([f.length, bases.slice(0, 3), fr.front]));
      // NAMED (Nov 22 2026, FX3): BEFORE "the Sun's shimmer is stopped". AFTER the abyss sun is drawn still (no void drift, the stars not running)
      await ev("window.BFOrbit&&window.BFOrbit.open('oracle'),true"); await sleep(900);
      const still = await ev(ABYSS_READ);
      const sp1 = await ev("(function(){var c=document.querySelector('#orbitCore .hq-core-abyss canvas');return c?c.toDataURL():null;})()"); await sleep(1500);
      const sp2 = await ev("(function(){var c=document.querySelector('#orbitCore .hq-core-abyss canvas');return c?c.toDataURL():null;})()");
      check(at + "under reduced motion the abyss sun is drawn still (no void drift; the same picture 1.5 s apart)", !!still && still.anim === "none" && !!still.info && still.info.reducedMotion && still.painted > 0 && !!sp1 && sp1 === sp2, J(still && [still.anim, still.info, still.painted, sp1 === sp2]));
    }
    await cdp.send("Emulation.setEmulatedMedia", { features: [] });
    await open(cdp, origin, "dashboard.html", w, h, true);
    await ev("window.BFOrbit&&window.BFOrbit.open('oracle'),true"); await sleep(1500);
    // NAMED (Nov 22 2026, FX3): BEFORE "FX2 the Sun" (the NASA SDO image, its glow and its shimmer). AFTER the abyss sun (the board
    // TmxHQ): the chat box's void and starfield in the centre's disc, the gold ring round it, no green ring, the stars running.
    const sun = await ev(ABYSS_READ);
    at = "FX3 the abyss sun at " + w + ": ";
    const AB = DS.HQ.ABYSS;
    check(at + "ORACLE open: the centre is the abyss disc, filling the centre's circle (its content box, the Sun's size), clipped round, first in the centre",
      !!sun && sun.open === "oracle" && sun.disp === "block" && sun.first && sun.radius === "50%" && sun.overflow === "hidden" && near(sun.disc.w, sun.inner) && near(sun.disc.h, sun.inner), J(sun && [sun.disc, sun.core, sun.inner]));
    check(at + "its background is the chat box's void, as the browser draws #tmx-chat: the same four gradients, sizes and colour, tmx-chat-void at 22 s",
      !!sun && sun.grads === 4 && !!sun.chatBg && sun.bgImage === sun.chatBg && sun.size === sun.chatSize && sun.bgColor === sun.chatColor && /rgba\(2, 1, 10, 0\.98\)/.test(sun.bgColor) &&
      sun.anim === "tmx-chat-void" && sun.anim === sun.chatAnim && sun.dur === "22s" && sun.dur === sun.chatDur, J(sun && [sun.grads, sun.bgColor, sun.chatColor, sun.size, sun.chatSize, sun.anim, sun.dur]));
    check(at + "no glow, rays or corona (no shadow, filter or pseudo-element round the disc)", !!sun && sun.glow === "none" && sun.filter === "none" && sun.after === "none" && sun.before === "none", J(sun && [sun.glow, sun.filter, sun.after, sun.before]));
    check(at + "the starfield runs on its canvas at the chat box's density per area (" + AB.STAR_BASE.COUNTS.join("/") + " per " + AB.STAR_BASE.W + " x " + AB.STAR_BASE.H + ")",
      !!sun && !!sun.info && sun.info.running && near(sun.canvas.w, sun.disc.w) && J(sun.info.counts) === J(AB.STAR_BASE.COUNTS.map(c => Math.round(c * sun.info.width * sun.info.height / (AB.STAR_BASE.W * AB.STAR_BASE.H)))) && sun.painted > 0, J(sun && [sun.info, sun.canvas, sun.painted]));
    check(at + "the gold ring kept round it (centred on the disc, outside it), shown; the green stats ring hidden", !!sun && sun.ringDisp !== "none" && !!sun.ring && sun.ring.w > sun.disc.w + 2 &&
      Math.abs((sun.ring.l + sun.ring.w / 2) - (sun.disc.l + sun.disc.w / 2)) <= 1 && Math.abs((sun.ring.t + sun.ring.h / 2) - (sun.disc.t + sun.disc.h / 2)) <= 1 && sun.green.length > 0 && sun.green.every(d => d === "none"), J(sun && [sun.ring, sun.disc, sun.green]));
    check(at + "the ORACLE node and the chip keep the moon; the centre has none", !!sun && !sun.coreMoon && sun.nodeMoon && sun.chipMoon, J(sun && [sun.coreMoon, sun.nodeMoon, sun.chipMoon]));
    await ev("window.BFOrbit&&window.BFOrbit.open('sell'),true"); await sleep(700);
    const otherAb = await ev(ABYSS_READ);
    check(at + "another portal (SELL): the disc hidden, the stars stopped, the green ring back", !!otherAb && otherAb.disp === "none" && !!otherAb.info && !otherAb.info.running && otherAb.green.some(d => d !== "none"), J(otherAb && [otherAb.disp, otherAb.info, otherAb.green]));
    await ev("window.BFOrbit&&window.BFOrbit.open('oracle'),true"); await sleep(900);
    await pageChecks(at);
    await fx1Shot("live-hq-oracle-abyss-fx3.png");

    // 5. the Profile, without and with a banner
    const PROF = String.raw`(function(){var R=function(e){if(!e)return null;var r=e.getBoundingClientRect();return {l:+r.left.toFixed(1),t:+r.top.toFixed(1),r:+r.right.toFixed(1),b:+r.bottom.toFixed(1)};};
      var av=document.querySelector('.pfs-av'),bn=document.querySelector('.pfs-banner'),img=bn&&bn.querySelector('img');
      return {bar:R(document.querySelector('.pfs-bar')),pic:R(document.querySelector('.pfs-pic')||av),banner:R(bn),ring:av&&getComputedStyle(av).backgroundImage,fit:img&&getComputedStyle(img).objectFit,
        mask:bn&&(getComputedStyle(bn).maskImage||getComputedStyle(bn).webkitMaskImage),src:img&&img.getAttribute('src'),has:!!document.querySelector('.pfs.has-banner')};})()`;
    await open(cdp, origin, "profile.html", w, h, true);
    at = "FX2 Profile (no banner) at " + w + ": ";
    let pr = await ev(PROF);
    const P = DS.PROFILE;
    check(at + "the top row " + P.TOP.ROW_TOP + " px below the safe area (none in this browser)", !!pr.bar && near(pr.bar.t, P.TOP.ROW_TOP), J(pr.bar));
    check(at + "the ring a " + P.AVATAR.RING_ANGLE + "deg teal-to-purple gradient (the theme's two accents)", /^linear-gradient\(135deg, rgb\(34, 211, 238\)/.test(pr.ring || "") && /rgb\(139, 92, 246\)\)$/.test(pr.ring || ""), J(pr.ring));
    check(at + "no banner unless the member sets one", !pr.banner && !pr.has, J(pr.banner));
    await pageChecks(at);
    await fx1Shot("live-profile-fx2.png");
    FX2S.banner = "/brand/force-hex-tile-1024.png";
    await open(cdp, origin, "profile.html", w, h, true);
    at = "FX2 Profile (a banner) at " + w + ": ";
    pr = await ev(PROF);
    check(at + "the banner from the screen's top to the picture's bottom (" + P.BANNER.BOTTOM + " px), the screen's width, cover-cropped, fading out",
      !!pr.banner && near(pr.banner.t, 0) && near(pr.banner.b, P.BANNER.BOTTOM) && near(pr.banner.b, pr.pic.b) && near(pr.banner.l, 0) && near(pr.banner.r, w) && pr.fit === "cover" &&
      /linear-gradient/.test(pr.mask || "") && pr.src === FX2S.banner && pr.has, J(pr));
    check(at + "the top row and the picture where they are without one", !!pr.bar && near(pr.bar.t, P.TOP.ROW_TOP) && near(pr.pic.t, P.AVATAR.TOP), J([pr.bar, pr.pic]));
    await pageChecks(at);
    await fx1Shot("live-profile-banner-fx2.png");
    await click("#pfsEdit"); await sleep(600);
    const ed = await ev("(function(){var a=document.getElementById('pfsBannerPick'),b=document.getElementById('pfsBannerRemove'),bn=document.querySelector('.pfs-banner');var r=a&&a.getBoundingClientRect(),q=b&&b.getBoundingClientRect();return {pick:a&&a.textContent.trim(),remove:b&&b.textContent.trim(),pw:r&&Math.round(r.height),rw:q&&Math.round(q.height),bannerShown:!!bn&&getComputedStyle(bn).display!=='none',file:!!document.getElementById('fi-banner')};})()");
    check(at + "Edit profile: Change banner (the page's own upload) and Remove banner, each 44 px or more; the banner itself steps aside",
      ed.pick === "Change banner" && ed.remove === "Remove banner" && ed.pw >= 44 && ed.rw >= 44 && !ed.bannerShown && ed.file, J(ed));
    await click("#pfsBannerRemove"); await sleep(900);
    const gone = await ev("({banner:!!document.querySelector('.pfs-banner'),pick:(document.getElementById('pfsBannerPick')||{}).textContent||null})");
    check(at + "Remove banner saves banner_url null and the banner is gone (Add banner offered)", FX2S.profilePuts.length === 1 && J(FX2S.profilePuts[0]) === J({ banner_url: null }) && !gone.banner && /Add banner/.test(gone.pick || ""),
      J([FX2S.profilePuts, gone]));
    FX2S.banner = null;

    // 6. the Agent Directory
    const AGM = String.raw`(function(){var R=function(e){if(!e)return null;var r=e.getBoundingClientRect();return {l:+r.left.toFixed(1),t:+r.top.toFixed(1),w:+r.width.toFixed(1),h:+r.height.toFixed(1)};};
      var it=[].slice.call(document.querySelectorAll('#agList .ag-item'));var list=document.getElementById('agList'),grid=document.querySelector('.agents-grid');
      return {view:document.querySelector('.page').getAttribute('data-ag-view'),btns:[].map.call(document.querySelectorAll('.ag-view-btn'),function(b){var r=R(b);return {v:b.getAttribute('data-view'),p:b.getAttribute('aria-pressed'),w:r.w,h:r.h};}),
        items:it.map(function(x){return R(x);}),cards:document.querySelectorAll('article.agent-card').length,listShown:!!list&&getComputedStyle(list).display!=='none',gridShown:!!grid&&getComputedStyle(grid).display!=='none',
        local:localStorage.getItem('bf_agents_view'),over:[].filter.call(document.querySelectorAll('.ag-name,.ag-sub'),function(n){return n.scrollWidth>n.clientWidth+1;}).length};})()`;
    await ev("localStorage.removeItem('bf_agents_view'),true");
    await open(cdp, origin, "ai-agents.html", w, h, true);
    at = "FX2 Agent Directory at " + w + ": ";
    let ag = await ev(AGM);
    const A = DS.AGENTS;
    check(at + "Large, Compact, Grid, each " + A.BUTTON + " x " + A.BUTTON + " with aria-pressed; Compact by default", J(ag.btns.map(b => b.v)) === J(A.VIEWS) && ag.btns.every(b => near(b.w, A.BUTTON) && near(b.h, A.BUTTON)) &&
      ag.view === "compact" && J(ag.btns.map(b => b.p)) === J(["false", "true", "false"]), J([ag.view, ag.btns]));
    check(at + "Compact: one " + A.ROW + " px row per agent (" + ag.cards + "), one under another, nothing cut off; the cards set aside",
      ag.cards > 0 && ag.items.length === ag.cards && ag.items.every(x => near(x.h, A.ROW) && near(x.w, ag.items[0].w)) && ag.items.slice(1).every((x, i) => x.t > ag.items[i].t) && ag.over === 0 && ag.listShown && !ag.gridShown,
      J([ag.items.slice(0, 3), ag.over]));
    await pageChecks(at + "Compact: ");
    await fx1Shot("live-agents-compact-fx2.png");
    await click('.ag-view-btn[data-view="grid"]'); await sleep(500);
    ag = await ev(AGM);
    check(at + "Grid: " + A.GRID_COLUMNS + " across, equal, nothing cut off; saved on this device and on the account",
      ag.view === "grid" && ag.items.length > 2 && near(ag.items[0].t, ag.items[1].t) && ag.items[2].t > ag.items[0].t && near(ag.items[0].w, ag.items[1].w) && near(ag.items[2].l, ag.items[0].l) && ag.over === 0 &&
      ag.local === "grid" && J(FX2S.puts) === J([{ agents_card_view: "grid" }]), J([ag.view, ag.items.slice(0, 3), ag.local, FX2S.puts]));
    await pageChecks(at + "Grid: ");
    await fx1Shot("live-agents-grid-fx2.png");
    await open(cdp, origin, "ai-agents.html", w, h, true);
    ag = await ev(AGM);
    check(at + "a reload keeps Grid", ag.view === "grid", J(ag.view));
    await ev("localStorage.setItem('bf_agents_view','large'),true");
    await open(cdp, origin, "ai-agents.html", w, h, true);
    ag = await ev(AGM);
    check(at + "the account's choice wins over this device's (Grid over a device's Large), and becomes this device's", ag.view === "grid" && ag.local === "grid", J([ag.view, ag.local]));
    await click('.ag-view-btn[data-view="large"]'); await sleep(500);
    ag = await ev(AGM);
    check(at + "Large: the page's own cards again", ag.view === "large" && ag.gridShown && !ag.listShown && FX2S.agView === "large", J([ag.view, ag.gridShown, FX2S.agView]));
    FX2S.on = false;
    console.log("    FX2 screenshots: " + FX1_DIR);
  }
  console.log("    screenshots: " + P23_OUT);
}

/* ══ P3-1 (Nov 20 2026): PHONE_P31=1 ═════════════════════════════════════════════════════════════════════════════
   A FREE account (no membership) at PHONE_P31_WIDTHS (default 360, 390, 430), screenshots at 390 x 844 to PHONE_P31_OUT
   (default Downloads\p31). GET /api/auth/me answers access.tier "free" and the members panel from code
   (lib/membership.js membersPanelFromCode, PLAN_CONFIG's price). First with the email NOT confirmed: Home shows the
   banner with "Resend email", which posts and says what happened, and a public post is refused with the server's own
   sentence. Then confirmed: Home without the banner, the composer posting (lib/posts.js over P2-3's in-memory database),
   the Profile (no "BizForce member", no BizCash), Market create (the listing form opens, no paywall), the Inbox, the
   bottom bar's HQ tab opening the members panel, the dashboard and an agent page behind the panel. */
const P31 = process.env.PHONE_P31 === "1";
const P31_WIDTHS = String(process.env.PHONE_P31_WIDTHS || "360,390,430").split(",").map(Number).filter(Boolean);
const P31_OUT = process.env.PHONE_P31_OUT || path.join(os.homedir(), "Downloads", "p31");
/* NAMED (Nov 21 2026, P3-1B, the owner's final rules): BEFORE the composer posted text, Market create opened the form, and the
   Inbox was checked only for no panel. AFTER the composer needs a photo for a share post (a Need posts as text), Market create and
   the Create sheet's members entries open the members panel (each tagged "Members"), Talk on a member's post shows the members
   box, the wallet is behind the panel, Buy opens the card-checkout-coming sheet, and the Inbox lets Rose reply where Pat wrote
   first but not start a conversation. lib/posts.js is handed the tier (Rose free, everyone else a member). At the end, at 390,
   P31S.member makes Rose a member for the member's composer (Show in Google) and an indexable /p/ page; the seven P3-1B
   screenshots go to PHONE_P31B_OUT (default Downloads\p31b). */
const P31S = { verified: false, resends: 0, member: false };
const P31B_OUT = process.env.PHONE_P31B_OUT || path.join(os.homedir(), "Downloads", "p31b");
const P31_LISTING = { id: "cccccccc-0000-4000-8000-000000000001", slug: "plum-jam", seller_id: P21_PEER, title: "Plum jam", description: "A jar of plum jam.", price_bfc: 15,
  status: "active", listing_kind: "product", category: "other", media: [] };
function p31Api(method, p) {
  if (p === "/api/auth/me") return { user: Object.assign({}, ROSE, { role: "user", email_verified_at: P31S.verified ? ago(24) : null }),
    access: P31S.member ? { active: true, exempt: false, access_reason: "subscription", inactive_reason: null, tier: "member", email_verified: true, members_panel: require("../lib/membership").membersPanelFromCode() }
      : { active: false, exempt: false, access_reason: null, inactive_reason: "no_subscription", tier: "free", email_verified: P31S.verified,
      members_panel: require("../lib/membership").membersPanelFromCode() }, subscription: null, profile: { username: "rose" } };
  if (p === "/api/marketplace/listings" && method === "GET") return { listings: [P31_LISTING] };   // NAMED (Nov 21 2026, P3-1B): a member's listing, so Buy shows
  if (p === "/api/auth/resend-verification" && method === "POST") { P31S.resends++; return { message: "We sent a new link to rose@example.test. It works for one hour." }; }
  return undefined;
}
async function p31Run(cdp, origin) {
  fs.mkdirSync(P31_OUT, { recursive: true });
  console.log("browserCheckPhone P3-1 (a free account: the banner, Home, the composer, the Profile, Market create, the Inbox, the members panel on HQ and an agent page) at " + P31_WIDTHS.join(", "));
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{localStorage.setItem('bf_token'," + J(ID_TOKEN) + ");}catch(e){}" });
  const ev = x => evaluate(cdp, x);
  const HT = { 360: 780, 390: 844, 430: 932 };
  const PANEL = require("../lib/membership").membersPanelFromCode();
  const viewShot = async file => { const r = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(P31_OUT, file), Buffer.from(r.data, "base64")); };
  const VEIL = /^div#bf-members-panel /;
  const pageChecks = async (at, opts) => {
    const m = await ev(MEASURE);
    check(at + "no horizontal scroll", !m.hscroll, J(m.wide));
    check(at + "no text cut off", m.clipped.length === 0, J(m.clipped));
    check(at + "every tap target is at least 44 x 44", m.smallCount === 0, m.smallCount + " " + J(m.small));
    // NAMED (Nov 21 2026, P3-1B): opts.sheet sets aside the open Talk sheet and its backdrop, as P2-3's checks do
    const TALK = /^(div|section)#bfp-talk(-backdrop)? /;
    const deco = m.deco.filter(x => !(opts && opts.panel && VEIL.test(x)) && !(opts && opts.sheet && TALK.test(x)));
    check(at + "decoration is under the text" + (opts && opts.panel ? " (the panel's veil aside)" : opts && opts.sheet ? " (the open sheet's backdrop aside)" : ""), deco.length === 0, J(deco));
    const over = m.over.filter(x => !/^(div#tmx-presence-root|nav#bf-tabbar) /.test(x) && !(opts && opts.panel && VEIL.test(x)) && !(opts && opts.sheet && TALK.test(x)));
    check(at + "no fixed element over text or a control at rest" + (opts && opts.panel ? " (the members panel is meant to cover the page)" : opts && opts.sheet ? " (the open sheet is meant to cover the page)" : ""), over.length === 0, J(over));
  };
  const panelBox = () => ev(P23_BOX + "('#bf-members-panel .bfa-panel', 'a,button')");
  const panelText = () => ev("(function(){var p=document.querySelector('#bf-members-panel .bfa-panel');if(!p)return null;var j=p.querySelector('.bfa-join'),h=p.querySelector('.bfa-home');" +
    "return {title:(p.querySelector('h2')||{}).textContent,price:(p.querySelector('.bfa-price')||{}).textContent,adds:[].map.call(p.querySelectorAll('li'),function(l){return l.textContent;})," +
    "join:j&&j.getAttribute('href'),joinText:j&&j.textContent,home:h&&h.textContent};})()");
  const panelOk = async (at, w, h, homeText) => {
    const b = await panelBox(), t = await panelText();
    check(at + "the members panel: \"Members get this\", " + PANEL.price_text + " (from code), the nine lines, Join to billing.html, " + homeText,
      !!t && t.title === "Members get this" && t.price === PANEL.price_text && J(t.adds) === J(PANEL.adds) && t.join === "/billing.html" && t.joinText === "Join" && t.home === homeText, J(t));
    check(at + "...inside the screen, its controls 44 px or more, no sideways scroll", !!b && b.l >= -1 && b.r <= w + 1 && b.t >= -1 && b.b <= h + 1 && b.small.length === 0 && !b.hscroll, J(b));
  };
  for (const w of P31_WIDTHS) {
    const h = HT[w] || 844;
    const shot = async name => { if (w === 390) await viewShot(name + "-390x844.png"); };
    Object.assign(P23S, await p23World(false));
    const roseRow = P23S.db.t.users.find(u => u.id === ROSE.id);
    // NAMED (Nov 21 2026, P3-1B): the tier, as postDeps hands it (Rose free unless P31S.member; everyone else a member)
    P31S.member = false;
    P23S.deps.tierOf = async id => (id === ROSE.id && !P31S.member ? "free" : "member");
    P23S.deps.membersPanel = () => require("../lib/membership").membersPanelFromCode();
    const shotB = async name => { if (w === 390) { fs.mkdirSync(P31B_OUT, { recursive: true }); const r = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(P31B_OUT, name + "-390x844.png"), Buffer.from(r.data, "base64")); } };

    // 1. Home, the email not confirmed: the banner and Resend email
    P31S.verified = false; P31S.resends = 0; roseRow.email_verified_at = null;
    await open(cdp, origin, "home.html", w, h, true);
    let at = "P31 Home (email not confirmed) at " + w + ": ";
    const ban = await ev("(function(){var b=document.getElementById('bf-verify-banner');if(!b)return null;var r=b.getBoundingClientRect(),btn=b.querySelector('button'),q=btn&&btn.getBoundingClientRect();" +
      "return {text:(b.querySelector('p')||{}).textContent,btn:btn&&btn.textContent,bw:q&&Math.round(q.width),bh:q&&Math.round(q.height),l:Math.round(r.left),r:Math.round(r.right),t:Math.round(r.top)};})()");
    check(at + "the banner says what a confirmed email is needed for, with \"Resend email\" (44 px), across the top of the screen",
      // NAMED (Nov 21 2026, P3-1B): BEFORE "post publicly, list in the Market, message people who do not follow you, and receive BizCash"
      !!ban && /post publicly and to message people who do not follow you/.test(ban.text) && !/BizCash|list in the Market/.test(ban.text) && ban.btn === "Resend email" && ban.bh >= 44 && ban.bw >= 44 &&
      ban.l >= -1 && ban.r <= w + 1 && ban.t <= 1, J(ban));
    const fb = await ev("(function(){var b=document.getElementById('bf-verify-banner'),t=document.querySelector('.feed-top');if(!b||!t)return null;var r=b.getBoundingClientRect(),q=t.getBoundingClientRect();return {bannerBottom:Math.round(r.bottom),rowTop:Math.round(q.top)};})()");
    check(at + "on the full-screen feed the top row (Live, the tabs, Search) sits below the banner, never under it", !!fb && fb.rowTop >= fb.bannerBottom - 1, J(fb));
    await pageChecks(at);
    await shot("home-banner");
    await ev("(function(){var b=document.querySelector('#bf-verify-banner button');if(b)b.click();return !!b;})()"); await sleep(700);
    const said = await ev("(function(){var s=document.querySelector('#bf-verify-banner .bfa-status');return s&&!s.hidden?s.textContent:null;})()");
    check(at + "Resend email posts once and says what happened", P31S.resends === 1 && /We sent a new link/.test(said || ""), J([P31S.resends, said]));
    await shot("home-banner-resent");
    // a public post from the composer: refused with the server's sentence, nothing saved
    await open(cdp, origin, "compose.html", w, h, true);
    at = "P31 composer (email not confirmed) at " + w + ": ";
    const before = P23S.db.t.posts.length;
    await ev("(function(){var t=document.querySelector('.bfc-text');if(!t)return false;t.value='Open on Saturday, all welcome.';t.dispatchEvent(new Event('input',{bubbles:true}));return true;})()");
    // NAMED (Nov 21 2026, P3-1B): as a Need (text is allowed), so the server's email rule is what refuses it
    await ev("(function(){var r=document.querySelector('input[name=bfcIntent][value=need]');if(r){r.click();}return !!r;})()");
    await ev("(function(){var r=document.querySelector('input[name=bfcCat][value=food]');if(r)(r.closest('label')||r).click();return !!r;})()");   // NAMED (Nov 23 2026, P3-3): a category, required
    await ev("(function(){var b=document.querySelector('.bfc-post');if(b)b.click();return !!b;})()");
    await sleep(900);
    const refused = await ev("document.body.innerText.indexOf('Confirm your email first') !== -1");
    check(at + "a public post is refused with the server's sentence, and nothing is saved", refused && P23S.db.t.posts.length === before, J([refused, P23S.db.t.posts.length, before]));
    await pageChecks(at);
    await shot("compose-unconfirmed");

    // 2. the email confirmed from here on
    P31S.verified = true; roseRow.email_verified_at = ago(24);
    await open(cdp, origin, "home.html", w, h, true);
    at = "P31 Home (a free account) at " + w + ": ";
    check(at + "no banner once the email is confirmed, and no members panel (Home is free)", (await ev("!document.getElementById('bf-verify-banner') && !document.getElementById('bf-members-panel')")) === true);
    await pageChecks(at);
    await shot("home-free");

    // 3. the composer. NAMED (Nov 21 2026, P3-1B): BEFORE a free account's text post went up. AFTER a share post needs a photo (the
    // note says why, Post sends nothing); a Need posts as text, at once; no Show in Google box for a free account.
    await open(cdp, origin, "compose.html", w, h, true);
    at = "P31 composer at " + w + ": ";
    const n0 = P23S.db.t.posts.length;
    await ev("(function(){var t=document.querySelector('.bfc-text');if(!t)return false;t.value='Open on Saturday, all welcome.';t.dispatchEvent(new Event('input',{bubbles:true}));return true;})()");
    const FREE_NOTE = "A free account's share post needs at least one photo. Text-only posts are for members; a Need can be text.";
    const note0 = await ev("(function(){var n=document.getElementById('bfcFreeNote'),s=document.getElementById('bfcSeo');return {note:n&&!n.hidden?n.textContent:null,seo:!!s&&!s.hidden,intent:!!document.getElementById('bfcIntent')};})()");
    check(at + "a free account's share post: the note says a photo is needed and why, and there is no Show in Google box", !!note0 && note0.note === FREE_NOTE && !note0.seo && note0.intent, J(note0));
    await pageChecks(at);
    await shot("compose-free");
    await ev("(function(){var b=document.querySelector('.bfc-post');if(b)b.click();return !!b;})()");
    await sleep(1200);
    const err0 = await ev("(function(){var e=document.getElementById('bfcErr');return e?e.textContent:null;})()");
    check(at + "Post without a photo says why and sends nothing", err0 === FREE_NOTE && P23S.db.t.posts.length === n0, J([err0, P23S.db.t.posts.length, n0]));
    await shotB("free-composer-photo-required");
    await ev("(function(){var r=document.querySelector('input[name=bfcIntent][value=need]');if(r)r.click();return !!r;})()"); await sleep(200);
    const noteNeed = await ev("(function(){var n=document.getElementById('bfcFreeNote');return !!n&&n.hidden;})()");
    await ev("(function(){var r=document.querySelector('input[name=bfcCat][value=food]');if(r)(r.closest('label')||r).click();return !!r;})()");   // NAMED (Nov 23 2026, P3-3): a category, required
    await ev("(function(){var b=document.querySelector('.bfc-post');if(b)b.click();return !!b;})()");
    await sleep(3000);
    const mine = P23S.db.t.posts.filter(x => x.author_id === ROSE.id && x.body === "Open on Saturday, all welcome.");
    check(at + "a free account's Need posts as text: published at once (no hold), intent need, not in Google, no members panel", noteNeed && P23S.db.t.posts.length === n0 + 1 && mine.length === 1 &&
      mine[0].status === "published" && mine[0].intent === "need" && mine[0].search_visible === false && (await ev("!document.getElementById('bf-members-panel')")) === true, J(mine.map(x => [x.status, x.intent, x.search_visible])));

    // 4. the Profile: no "BizForce member", no BizCash, no gold wallet
    await open(cdp, origin, "profile.html", w, h, true);
    at = "P31 Profile at " + w + ": ";
    const prof = await ev("(function(){var h=document.querySelector('.pfs-handle');return {handle:h&&h.textContent,bfc:!!document.querySelector('.pfs-k-bizcash'),wallet:!!document.querySelector('.pfs-btn.is-wallet'),panel:!!document.getElementById('bf-members-panel')};})()");
    check(at + "a free owner: the handle without \"BizForce member\", no BizCash count, no gold wallet, no members panel",
      !!prof && /@rose/.test(prof.handle || "") && !/BizForce member/.test(prof.handle || "") && !prof.bfc && !prof.wallet && !prof.panel, J(prof));
    await pageChecks(at);
    await shot("profile-free");

    // 5. Market create. NAMED (Nov 21 2026, P3-1B): BEFORE the listing form opened for a free account. AFTER selling is for
    // members: the ?create= link opens the members panel over the page.
    await open(cdp, origin, "marketplace.html?create=product", w, h, true);
    at = "P31 Market create at " + w + ": ";
    check(at + "the Create sheet's Product listing link opens the members panel (selling is for members)", (await ev("!!document.getElementById('bf-members-panel')")) === true);
    await panelOk(at, w, h, "Not now");
    await shot("market-create-panel");
    // Buy on a member's listing: the card-checkout-coming sheet, nothing bought
    await open(cdp, origin, "marketplace.html", w, h, true);
    at = "P31 Market Buy at " + w + ": ";
    const hasBuy = await ev("(function(){var b=document.querySelector('#listingsGrid .btn-buy');if(!b)return false;b.scrollIntoView({block:'center'});return true;})()");
    await sleep(200);
    await ev("(function(){var b=document.querySelector('#listingsGrid .btn-buy');if(b)b.click();return !!b;})()"); await sleep(500);
    const buy = await ev(P23_BOX + "('#bf-buy-sheet .bfa-panel','a,button')");
    const buyText = await ev("(function(){var s=document.querySelector('#bf-buy-sheet .bfa-panel');return s?s.innerText:null;})()");
    check(at + "Buy on a member's listing opens \"Card checkout is coming\" inside the screen, Close 44 px, no confirm, nothing bought",
      hasBuy && !!buy && /Card checkout is coming/.test(buyText || "") && /never pays in BizCash/.test(buyText || "") && buy.small.length === 0 && buy.l >= -1 && buy.r <= w + 1 && buy.b <= h + 1, J([hasBuy, buy, buyText]));
    await shotB("buy-sheet");
    await ev("(function(){var a=document.querySelector('#bf-buy-sheet .bfa-join');if(a)a.click();return !!a;})()"); await sleep(250);
    check(at + "Close shuts the sheet", (await ev("!document.getElementById('bf-buy-sheet')")) === true);
    // the Create sheet: the members entries tagged "Members", and Product listing opens the panel
    await open(cdp, origin, "home.html", w, h, true);
    at = "P31 Create sheet at " + w + ": ";
    await ev("(function(){var b=document.querySelector('#bf-tabbar [data-tab=create]');if(b)b.click();return !!b;})()"); await sleep(500);
    const cs = await ev("(function(){var s=document.getElementById('bf-create');if(!s||s.hidden)return null;return [].map.call(s.querySelectorAll('.bf-create-opt'),function(o){var t=o.querySelector('.bf-create-members'),q=t&&t.getBoundingClientRect(),r=o.getBoundingClientRect();" +
      "return [o.getAttribute('data-create'),!!t&&t.textContent,q?(q.right<=r.right+1&&q.bottom<=r.bottom+1):null];});})()");
    const tagged = (cs || []).filter(x => x[1] === "Members").map(x => x[0]);
    check(at + "Product listing, Service, Ask an agent, Campaign, Garage sale item and Business card carry a \"Members\" tag inside their tiles; Post and Video do not",
      J(tagged.slice().sort()) === J(["agent", "campaign", "card", "garage", "product", "service"]) && (cs || []).every(x => x[1] !== "Members" || x[2] === true), J(cs));
    await shotB("create-sheet-free");
    await ev("(function(){var a=document.querySelector('#bf-create a[data-create=product]');if(a)a.click();return !!a;})()"); await sleep(500);
    check(at + "tapping Product listing opens the members panel and stays on Home", (await ev("location.pathname")) === "/home.html" && (await ev("!!document.getElementById('bf-members-panel')")) === true);
    // Talk on a paid member's post: the members box with Join, no comment box
    await open(cdp, origin, "home.html", w, h, true);
    at = "P31 Talk on a member's post at " + w + ": ";
    await ev("(function(){var p=document.querySelector('#feed [data-post=\"" + P23_POST.photo + "\"]');if(p)p.scrollIntoView({block:'center'});return !!p;})()"); await sleep(300);
    await ev("(function(){var b=document.querySelector('#feed [data-post=\"" + P23_POST.photo + "\"] .bfp-act[data-act=talk]');if(b)b.click();return !!b;})()"); await sleep(1200);
    const tk = await ev("(function(){var b=document.getElementById('bfpTalkMembers'),f=document.getElementById('bfpTalkForm');if(!b)return null;var j=b.querySelector('a'),q=j&&j.getBoundingClientRect();" +
      "return {shown:!b.hidden,form:!!f&&!f.hidden&&f.getBoundingClientRect().height>0,head:(b.querySelector('.bfp-tm-h')||{}).textContent,paras:b.querySelectorAll('p').length,old:!!b.querySelector('.bfp-tm-s'),join:j&&j.getAttribute('href'),jw:q&&Math.round(q.width),jh:q&&Math.round(q.height),list:document.querySelectorAll('#bfpTalkList > li').length};})()");
    // NAMED (Nov 22 2026, FX3): BEFORE a heading typed in bf-feed.js ("Comments on members' posts are for members") over the server's refusal
    // sentence. AFTER one sentence, lib/membership.js's TALK_MEMBERS_ONLY, sent by the server before any try; the refusal keeps its own.
    const TMO = require("../lib/membership").TALK_MEMBERS_ONLY;
    check(at + "\"" + TMO + "\" (the server's one sentence, shown before any try) with Join (44 px, to billing.html), the comments still shown, no comment box",
      !!tk && tk.shown && !tk.form && tk.head === TMO && tk.paras === 1 && !tk.old && TMO !== require("../lib/membership").FREE_RULES.comment_member_post &&
      tk.join === "/billing.html" && tk.jh >= 44 && tk.jw >= 44 && tk.list >= 1, J(tk));
    await pageChecks(at, { panel: false, sheet: true });
    await shotB("talk-member-post-free");
    // the wallet: behind the members panel
    await open(cdp, origin, "wallet.html", w, h, true);
    at = "P31 wallet at " + w + ": ";
    await panelOk(at, w, h, "Go to Home");
    await shotB("wallet-panel");

    // 6. the Inbox
    await open(cdp, origin, "inbox.html", w, h, true);
    at = "P31 Inbox at " + w + ": ";
    check(at + "the Inbox opens for a free account, no members panel", (await ev("!document.getElementById('bf-members-panel') && !!document.getElementById('bf-tabbar')")) === true);
    await pageChecks(at);
    await shot("inbox-free");
    // NAMED (Nov 21 2026, P3-1B): reply-only. Pat wrote first, so Rose replies; a member who never wrote: the members panel, no compose box
    await open(cdp, origin, "inbox.html?with=" + P21_PEER, w, h, true);
    const rp = await ev("(function(){var c=document.getElementById('compose'),o=document.getElementById('replyOnly');return {compose:!!c&&!c.hidden,only:!!o&&!o.hidden,panel:!!document.getElementById('bf-members-panel')};})()");
    check(at + "in Pat's conversation (Pat wrote first) Rose can reply: the compose box, no members panel", rp.compose && !rp.only && !rp.panel, J(rp));
    await open(cdp, origin, "inbox.html?with=" + uid(4), w, h, true);
    const st = await ev("(function(){var c=document.getElementById('compose'),o=document.getElementById('replyOnly');return {compose:!!c&&!c.hidden,only:!!o&&!o.hidden?o.textContent:null,panel:!!document.getElementById('bf-members-panel')};})()");
    check(at + "starting a conversation with a member who never wrote: no compose box, the reply-only line with Join, and the members panel",
      !st.compose && /^Starting a conversation is for members\. You can reply when a member messages you first\. Join$/.test((st.only || "").trim()) && st.panel, J(st));

    // 7. the bottom bar's HQ tab opens the members panel (not the dashboard)
    await open(cdp, origin, "home.html", w, h, true);
    at = "P31 HQ tab at " + w + ": ";
    await ev("(function(){var a=document.querySelector('#bf-tabbar a[data-tab=hq]');if(a)a.click();return !!a;})()"); await sleep(600);
    const still = await ev("location.pathname");
    check(at + "tapping HQ opens the members panel and stays on Home", still === "/home.html" && (await ev("!!document.getElementById('bf-members-panel')")) === true, still);
    await panelOk(at, w, h, "Not now");
    await shot("hq-tab-panel");
    await ev("(function(){var b=document.querySelector('#bf-members-panel .bfa-home');if(b)b.click();return !!b;})()"); await sleep(300);
    check(at + "Not now closes it", (await ev("!document.getElementById('bf-members-panel')")) === true);

    // 8. the dashboard and an agent page, opened directly
    for (const [pg, label] of [["dashboard.html", "the dashboard (HQ)"], ["agents/sales.html", "an agent page (Sales)"]]) {
      await open(cdp, origin, pg, w, h, true);
      at = "P31 " + label + " at " + w + ": ";
      await panelOk(at, w, h, "Go to Home");
      await pageChecks(at, { panel: true });
      await shot(pg.replace(/\//g, "-").replace(/\.html$/, "") + "-panel");
    }

    // 9. NAMED (Nov 21 2026, P3-1B): Rose as a member, at 390: the composer's Show in Google, and the /p/ page Google may index
    if (w !== 390) continue;
    P31S.member = true;
    await open(cdp, origin, "compose.html", w, h, true);
    at = "P31B member composer at " + w + ": ";
    const BODY = "Fresh sourdough every morning on Maple Street, from 7. Rye on Saturdays.";
    await ev("(function(){var t=document.querySelector('.bfc-text');if(!t)return false;t.value=" + J(BODY) + ";t.dispatchEvent(new Event('input',{bubbles:true}));return true;})()"); await sleep(250);
    const sg = await ev("(function(){var b=document.getElementById('bfcSeo'),c=document.getElementById('bfcSearch'),t=document.getElementById('bfcSeoTitle'),d=document.getElementById('bfcSeoDesc'),n=document.getElementById('bfcFreeNote');" +
      "return {shown:!!b&&!b.hidden,on:!!c&&c.checked,title:t&&t.value,tmax:t&&t.maxLength,desc:d&&d.value,dmax:d&&d.maxLength,note:!!n&&!n.hidden};})()");
    check(at + "a member gets Show in Google, on by default, with a search title (70) and description (160) filled from the post's first words; no photo note",
      sg.shown && sg.on && sg.tmax === 70 && sg.dmax === 160 && !!sg.title && sg.title.length <= 70 && BODY.indexOf(sg.title.replace(/\.\.\.$/, "")) === 0 && sg.desc === BODY && !sg.note, J(sg));
    await ev("(function(){var t=document.getElementById('bfcSeoTitle');t.value='Sourdough on Maple Street';t.dispatchEvent(new Event('input',{bubbles:true}));return true;})()");
    await ev("(function(){var r=document.querySelector('input[name=bfcCat][value=food]');if(r)(r.closest('label')||r).click();return !!r;})()");   // NAMED (Nov 23 2026, P3-3): a category, required
    await ev("(function(){var b=document.getElementById('bfcSeo');if(b)b.scrollIntoView({block:'center'});return true;})()"); await sleep(250);
    await pageChecks(at);
    await shotB("member-composer-show-in-google");
    await ev("(function(){var b=document.querySelector('.bfc-post');if(b)b.click();return !!b;})()"); await sleep(3000);
    const mp = P23S.db.t.posts.find(x => x.author_id === ROSE.id && x.body === BODY);
    check(at + "posted as text, public, Show in Google on, with the search title and description stored", !!mp && mp.kind === "text" && mp.search_visible === true &&
      mp.seo_title === "Sourdough on Maple Street" && mp.seo_description === BODY, J(mp));
    at = "P31B member /p/ page at " + w + ": ";
    let src = null;
    if (mp) {
      await open(cdp, origin, "p/" + mp.id, w, h, true);
      src = await ev("fetch(location.href).then(function(r){return r.text();})");
      await ev("(function(s){s=s.slice(0,s.indexOf('</head>')+7).replace(/>\\s*</g,'>\\n<');document.open();document.write('<!doctype html><meta name=viewport content=\"width=device-width\"><title>view-source</title><pre id=src style=\"white-space:pre-wrap;word-break:break-all;font:11px/1.45 monospace;margin:8px;color:#111;background:#fff\"></pre>');document.close();" +
        "document.getElementById('src').textContent='view-source:'+location.href+'\\n\\n'+s;return true;})(" + J(src || "") + ")");
      await sleep(300);
    }
    const url = mp ? "https://bizforceai.net/p/" + mp.id : "";
    check(at + "the page source: robots \"index, follow\", the canonical URL, the search title in <title> and Open Graph, SocialMediaPosting",
      !!src && src.indexOf('<meta name="robots" content="index, follow"/>') !== -1 && src.indexOf('<link rel="canonical" href="' + url + '"/>') !== -1 &&
      src.indexOf("<title>Sourdough on Maple Street</title>") !== -1 && src.indexOf('<meta property="og:title" content="Sourdough on Maple Street"/>') !== -1 && /"@type":"SocialMediaPosting"/.test(src), (src || "").slice(0, 300));
    await shotB("member-post-page-source");
    P31S.member = false;
  }
}

/* ══ P3-2 (Nov 21 2026): PHONE_P32=1 ═════════════════════════════════════════════════════════════════════════════
   The Verified badge at PHONE_P32_WIDTHS (default 360, 390, 430), screenshots at 390 x 844 to PHONE_P32_OUT (default
   Downloads\p32). P2-3's in-memory world (lib/posts.js over scripts/_p23Db.js) with bf_profiles.verified_reason set:
   Pat's Pantry 'seller', Lee Ceramics 'member', Rose 'official'. So the feed and Talk get the badge from lib/posts.js
   peopleById, and /p/ from lib/postPage.js, as the server draws them; the profile (/api/bfp/profile/me) and the
   storefront (/api/bfp/seller/pat) answer the server's verified field beside what P2-1 and P2-3 answer.
   On each surface: the mark is inside the name, after its text, 16 x 16, on the name's line, inside the screen; its
   accessible name is its kind; a tap opens the sheet ("Verified: [kind]. This is not an endorsement.") inside the
   screen with a 44 px Close, and stays on the page; Close closes it; and the page keeps every rule of the phone run. */
const P32 = process.env.PHONE_P32 === "1";
const P32_WIDTHS = String(process.env.PHONE_P32_WIDTHS || "360,390,430").split(",").map(Number).filter(Boolean);
const P32_OUT = process.env.PHONE_P32_OUT || path.join(os.homedir(), "Downloads", "p32");
const P32_KIND = { [ROSE.id]: "official", [P21_PEER]: "seller", [P21_PEER2]: "member" };
function p32Api(method, p) {
  if (p === "/api/bfp/profile/me" && method === "GET") return Object.assign({}, P21_FIX.profile, { verified: P32_KIND[ROSE.id] });
  if (p === "/api/bfp/seller/pat") return { seller: { user_id: P21_PEER, username: "pat", display_name: "Pat's Pantry", tagline: "Jams and preserves", avatar_url: null }, products: [], services: [], support_links: [],
    member: true, verified: P32_KIND[P21_PEER] };
  return undefined;
}
// the mark inside the name element sel (the first one that holds a mark), measured
const P32_MARK = String.raw`(function(sel,kind){
  var names=[].filter.call(document.querySelectorAll(sel),function(n){var r=n.getBoundingClientRect();return r.width>0&&n.querySelector('.bf-vb[data-bf-verified="'+kind+'"]');});
  var n=names[0];if(!n)return null;var b=n.querySelector('.bf-vb'),nr=n.getBoundingClientRect(),br=b.getBoundingClientRect();
  var txt=document.createRange();txt.selectNodeContents(n);txt.setEndBefore(b);var tr=txt.getBoundingClientRect();
  var R=function(r){return {l:+r.left.toFixed(1),t:+r.top.toFixed(1),r:+r.right.toFixed(1),b:+r.bottom.toFixed(1),w:+r.width.toFixed(1),h:+r.height.toFixed(1)};};
  return {name:n.textContent.trim(),kind:b.getAttribute('data-bf-verified'),label:b.getAttribute('aria-label'),role:b.getAttribute('role'),focusable:b.tabIndex>=0,
    mark:R(br),nameBox:R(nr),text:R(tr),last:n.lastElementChild===b,W:innerWidth,H:innerHeight,hscroll:document.documentElement.scrollWidth>innerWidth+1};
})`;
async function p32Run(cdp, origin) {
  fs.mkdirSync(P32_OUT, { recursive: true });
  console.log("browserCheckPhone P3-2 (the Verified badge on the feed, Talk, the profile, a storefront and the public post page, and its sheet) at " + P32_WIDTHS.join(", "));
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{if(!sessionStorage.getItem('phone_check_out'))localStorage.setItem('bf_token'," + J(ID_TOKEN) + ");}catch(e){}" });
  const ev = x => evaluate(cdp, x);
  const HT = { 360: 780, 390: 844, 430: 932 };
  const VB = require("../lib/verified");
  const viewShot = async file => { const r = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(P32_OUT, file), Buffer.from(r.data, "base64")); };
  const SHEETS = /^(div|section|aside)[#.](bf-vb-veil|bf-vb-sheet|bfp-talk|bfp-talk-backdrop)[ .]/;
  const pageChecks = async (at, opts) => {
    const m = await ev(MEASURE);
    check(at + "no horizontal scroll", !m.hscroll, J(m.wide));
    const tiles = await ev("[].map.call(document.querySelectorAll('.pfs-cell.is-text > span'),function(s){return s.textContent.slice(0,40);})");
    const clipped = m.clipped.filter(x => !tiles.some(t => x.indexOf('"' + t.slice(0, 30)) !== -1));
    check(at + "no text cut off" + (clipped.length < m.clipped.length ? " (a text post's tile excerpt aside)" : ""), clipped.length === 0, J(clipped));
    check(at + "every tap target is at least 44 x 44", m.smallCount === 0, m.smallCount + " " + J(m.small));
    const deco = m.deco.filter(x => !(opts && opts.sheet && SHEETS.test(x)));
    check(at + "decoration is under the text" + (opts && opts.sheet ? " (the open sheet's scrim aside)" : ""), deco.length === 0, J(deco));
    const over = m.over.filter(x => !/^(div#tmx-presence-root|nav#bf-tabbar) /.test(x) && !(opts && opts.sheet && SHEETS.test(x)));
    check(at + "no fixed element over text or a control at rest" + (opts && opts.sheet ? " (the open sheet is meant to cover the page)" : ""), over.length === 0, J(over));
  };
  // the mark, then a tap on it: the sheet, Close, and the page stays
  const markAndSheet = async (at, sel, kind, w, h, shotName, shot) => {
    const m = await ev(P32_MARK + "(" + J(sel) + "," + J(kind) + ")");
    check(at + "the " + VB.LABELS[kind] + " mark is inside the name, after its text, 16 x 16, on the name's line, inside the screen",
      !!m && m.kind === kind && m.last && Math.abs(m.mark.w - 16) <= 0.5 && Math.abs(m.mark.h - 16) <= 0.5 && m.mark.l >= m.text.r - 0.5 &&
      m.mark.t >= m.nameBox.t - 1 && m.mark.b <= m.nameBox.b + 1 && m.mark.r <= w + 0.5 && m.mark.l >= 0 && !m.hscroll, J(m));
    check(at + "...its accessible name is its kind (role img, not a tab stop of its own)", !!m && m.role === "img" && m.label === VB.LABELS[kind] && m.focusable === false, J(m && [m.role, m.label, m.focusable]));
    await shot(shotName);
    const path0 = await ev("location.pathname + location.search");
    await ev("(function(){var k=" + J(kind) + ",n=[].filter.call(document.querySelectorAll(" + J(sel) + "),function(x){return x.getBoundingClientRect().width>0&&x.querySelector('.bf-vb[data-bf-verified=\"'+k+'\"]');})[0];var b=n&&n.querySelector('.bf-vb');if(b)b.click();return !!b;})()");
    await sleep(400);
    const sh = await ev("(function(){var v=document.querySelector('.bf-vb-veil'),s=v&&v.querySelector('.bf-vb-sheet');if(!s)return null;var r=s.getBoundingClientRect(),c=s.querySelector('button'),q=c&&c.getBoundingClientRect();" +
      "return {text:(s.querySelector('[data-bf-verified-text]')||{}).textContent,role:s.getAttribute('role'),l:Math.round(r.left),r:Math.round(r.right),t:Math.round(r.top),b:Math.round(r.bottom),close:c&&c.textContent,cw:q&&Math.round(q.width),ch:q&&Math.round(q.height),focus:document.activeElement===c,hscroll:document.documentElement.scrollWidth>innerWidth+1};})()");
    const path1 = await ev("location.pathname + location.search");
    check(at + "a tap opens the sheet: \"" + VB.sheetText(kind) + "\", inside the screen, Close 44 px or more, focused",
      !!sh && sh.text === VB.sheetText(kind) && sh.role === "dialog" && sh.l >= -1 && sh.r <= w + 1 && sh.t >= -1 && sh.b <= h + 1 && sh.cw >= 44 && sh.ch >= 44 && sh.focus && !sh.hscroll, J(sh));
    check(at + "...and the tap stays on the page (the name's link is not followed)", path1 === path0, J([path0, path1]));
    await pageChecks(at + "with the sheet open: ", { sheet: true });
    await shot(shotName + "-sheet");
    await ev("(function(){var c=document.querySelector('.bf-vb-sheet button');if(c)c.click();return !!c;})()"); await sleep(250);
    check(at + "Close closes it", (await ev("!document.querySelector('.bf-vb-veil')")) === true);
  };
  for (const w of P32_WIDTHS) {
    const h = HT[w] || 844;
    const shot = async name => { if (w === 390) await viewShot(name + "-390x844.png"); };
    Object.assign(P23S, await p23World(false));
    P23S.db.t.bf_profiles.forEach(r => { r.verified_reason = P32_KIND[r.user_id] || null; r.verified_at = P32_KIND[r.user_id] ? ago(24) : null; });

    // 1. the Following feed: Pat's text post first (a seller)
    await open(cdp, origin, "home.html", w, h, true);
    let at = "P32 feed at " + w + ": ";
    const first = await ev("(function(){var p=document.querySelector('#feed [data-post]');return p&&p.getAttribute('data-post');})()");
    check(at + "Pat's post is first, as P2-3 has it", first === P23_POST.text, first);
    await pageChecks(at);
    await markAndSheet(at, "#feed [data-post=\"" + P23_POST.text + "\"] .bfp-name", "seller", w, h, "feed", shot);
    const plain = await ev("(function(){var p=document.querySelector('#feed [data-post=\"" + P23_POST.other + "\"]');return p?!!p.querySelector('.bf-vb'):'absent';})()");
    check(at + "an account with no badge draws none (Maple Mill, not followed, is not in this feed or shows no mark)", plain === false || plain === "absent", J(plain));

    // 2. Talk on Lee's photo post: Pat (seller) and Rose (official) comment
    await ev("(function(){var e=document.querySelector('#feed [data-post=\"" + P23_POST.photo + "\"]');if(e)e.scrollIntoView({block:'start'});return !!e;})()"); await sleep(500);
    await markAndSheet("P32 feed (Lee's post) at " + w + ": ", "#feed [data-post=\"" + P23_POST.photo + "\"] .bfp-name", "member", w, h, "feed-member", shot);
    await ev("(function(){var b=document.querySelector('#feed [data-post=\"" + P23_POST.photo + "\"] [data-act=talk]');if(b)b.click();return !!b;})()"); await sleep(1200);
    at = "P32 Talk at " + w + ": ";
    const talkNames = await ev("[].map.call(document.querySelectorAll('.bfp-c-name'),function(n){var b=n.querySelector('.bf-vb');return n.textContent.trim()+'|'+(b?b.getAttribute('data-bf-verified'):'');})");
    check(at + "each comment's name carries its author's mark (Pat seller, Rose official)", talkNames.indexOf("Pat's Pantry|seller") !== -1 && talkNames.indexOf("Rose|official") !== -1, J(talkNames));
    await markAndSheet(at, ".bfp-c-name", "seller", w, h, "talk", shot);

    // 3. the profile (Rose's own: official)
    await open(cdp, origin, "profile.html", w, h, true);
    at = "P32 profile at " + w + ": ";
    await pageChecks(at);
    await markAndSheet(at, ".pfs-title", "official", w, h, "profile", shot);

    // 4. a storefront (Pat: seller)
    await open(cdp, origin, "@pat", w, h, true);
    at = "P32 storefront at " + w + ": ";
    await pageChecks(at);
    await markAndSheet(at, "#sfName", "seller", w, h, "storefront", shot);

    // 5. the public post page /p/ (Lee's photo post: member), signed in, then signed out
    await open(cdp, origin, "p/" + P23_POST.photo, w, h, true);
    at = "P32 public post page at " + w + ": ";
    await pageChecks(at);
    await markAndSheet(at, ".pp-name", "member", w, h, "post-page", shot);
    await ev("sessionStorage.setItem('phone_check_out','1'),localStorage.removeItem('bf_token'),localStorage.removeItem('bf_user'),true");
    await open(cdp, origin, "p/" + P23_POST.text, w, h, true);
    at = "P32 public post page (signed out) at " + w + ": ";
    await pageChecks(at);
    await markAndSheet(at, ".pp-name", "seller", w, h, "post-page-signed-out", shot);
    await ev("sessionStorage.removeItem('phone_check_out'),true");
  }
}

/* ══════════════════════════════════════════════════════════════════════════
   NAMED (Nov 22 2026, FX3): PHONE_FX3=1 runs only FX3's own screens (fx3Run) at PHONE_FX3_WIDTHS (default 360,390,430),
   with the owner's boards' screenshots at 390 x 844, DPR 2, to PHONE_FX3_OUT (default Downloads\fx3). Fixtures only:
   the owner Rose (a member), then a free account (/api/auth/me tier "free"). Every page's Guide insight is seeded in
   sessionStorage (bf_tmx_insight:<page>), so no insight is asked of the server; the free account's pass clears the seed
   and proves no /api/insights/page request is made. No chat message is ever sent (FX3S.sent stays 0).
     the HQ with ORACLE open: the abyss sun (the chat's void, its stars at the chat's density, no glow, the gold ring,
       no green ring), and another portal (SELL: none of it);
     the mist: 56 x 56, 16 px from the right, 16 px above the bar, z-index 46, a labelled button, its whisper inside;
     the Guide: the tab at the left edge, in the middle, 32 x 170 or taller; open, min(300, width - 48) wide, at most
       70vh, clear of the bar, the tab at its right edge; Escape, an outside tap and the tab close it; no book button;
     the chat: 8 px each side, 10 px above the mist, at most 420 px, Reset hidden, Guide and Oracle modes;
     a free account: the mist opens the members panel, never the chat; the Guide has no Insights and asks nothing;
     reduced motion: the disc and the chat drawn still, the plain fade, no shooting star;
     the Agent Directory: Large, Compact and Grid, each agent's colour and icon the shared map's and the dashboard's;
     where they stay hidden: oracle.html (no mist), signed out (neither).
   ══════════════════════════════════════════════════════════════════════════ */
const FX3S = { free: false, insightAsks: 0, sent: 0 };
function fx3Api(method, u, request) {
  const p = u.pathname;
  if (p === "/api/auth/me" && FX3S.free) return { user: Object.assign({}, ROSE, { role: "user", email_verified_at: ago(24) }),
    access: { active: false, exempt: false, access_reason: null, inactive_reason: "no_subscription", tier: "free", email_verified: true, members_panel: require("../lib/membership").membersPanelFromCode() },
    subscription: null, profile: { username: "rose" } };
  if (p === "/api/insights/page") { FX3S.insightAsks++; return { insight: "A live insight (this request should not have been made)." }; }
  if (p === "/api/oracle") { if (method !== "GET") { FX3S.sent++; return { reply: "" }; } return { messages: [] }; }
  if (p === "/api/user/preferences") return method === "PUT" ? { saved: true } : { ok: true, preferences: {}, termaximus_active: true, hq_card_view: null, hq_orbit: null, agents_card_view: null };
  if (p === "/api/moon") return MOON;
  // the Directory's names and links, as the server sends them (the shared fixture has neither)
  if (p === "/api/agents") return { agents: AGENTS.map(x => Object.assign({}, x, { display_name: x.name, page_url: "/" + x.agent_type + "-agent.html" })) };
  return undefined;
}
const FX3_SEED_PAGES = ["dashboard.html", "ai-agents.html", "home.html", "profile.html", "inbox.html"];
const FX3_INSIGHT = "A short insight about this page, written for you.";
// the mist, the Guide and the chat, as drawn
const FX3_READ = String.raw`(function(){var R=function(e){if(!e)return null;var r=e.getBoundingClientRect();return {l:+r.left.toFixed(1),t:+r.top.toFixed(1),r:+r.right.toFixed(1),b:+r.bottom.toFixed(1),w:+r.width.toFixed(1),h:+r.height.toFixed(1)};};
  var root=document.getElementById('tmx-presence-root'),gr=document.getElementById('tmx-guide-root'),tab=document.getElementById('tmx-guide-tab'),panel=document.getElementById('tmx-guide-panel'),
    chat=document.getElementById('tmx-chat'),bar=document.getElementById('bf-tabbar'),wh=document.getElementById('tmx-whisper'),reset=document.getElementById('tmx-chat-reset'),ins=panel&&panel.querySelector('.tmx-guide-section--insights');
  var vis=function(e){if(!e)return false;for(var n=e;n&&n.nodeType===1;n=n.parentElement){var c=getComputedStyle(n);if(c.display==='none'||c.visibility==='hidden')return false;}var r=e.getBoundingClientRect();return r.width>0&&r.height>0;};
  var cs=root&&getComputedStyle(root),pcs=panel&&getComputedStyle(panel),ccs=chat&&getComputedStyle(chat);
  return {W:innerWidth,H:innerHeight,mist:vis(root)?R(root):null,mistZ:cs&&cs.zIndex,mistPE:cs&&cs.pointerEvents,mistRole:root&&root.getAttribute('role'),mistLabel:root&&root.getAttribute('aria-label'),mistTab:root&&root.tabIndex,
    whisper:wh&&vis(wh)?R(wh):null,bar:vis(bar)?R(bar):null,guide:vis(gr),tab:vis(tab)?R(tab):null,open:!!gr&&gr.classList.contains('tmx-guide-open'),panel:panel?R(panel):null,
    panelOpacity:pcs&&pcs.opacity,panelOverflow:pcs&&pcs.overflowY,insights:vis(ins),insightText:ins?(ins.querySelector('#tmx-guide-insight-text')||{}).textContent:null,
    fab:!!document.getElementById('tmx-guide-fab')||!!document.getElementById('tmx-guide-sheet'),
    chat:chat?R(chat):null,chatOpacity:ccs&&ccs.opacity,chatVis:ccs&&ccs.visibility,chatTransform:ccs&&ccs.transform,chatFilter:ccs&&ccs.filter,chatPE:ccs&&ccs.pointerEvents,chatAnim:ccs&&ccs.animationName,chatRimAnim:chat&&getComputedStyle(chat,'::before').animationName,chatTransition:chat&&chat.style.transition,
    reset:reset?getComputedStyle(reset).display:null,shoot:(function(){var s=document.getElementById('tmx-chat-shoot');return s?{op:getComputedStyle(s).opacity,anim:getComputedStyle(s).animationName}:null;})(),
    hscroll:document.documentElement.scrollWidth>innerWidth+1,panelBox:!!document.getElementById('bf-members-panel')};})()`;
async function fx3Run(cdp, origin) {
  fs.mkdirSync(FX3_OUT, { recursive: true });
  console.log("browserCheckPhone FX3 (the abyss sun, Termaximus on the phone, the agents' colours and icons) at " + FX3_WIDTHS.join(", "));
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{if(!sessionStorage.getItem('phone_check_out'))localStorage.setItem('bf_token'," + J(ID_TOKEN) + ");" +
    "if(!sessionStorage.getItem('fx3_noseed'))" + J(FX3_SEED_PAGES) + ".forEach(function(p){sessionStorage.setItem('bf_tmx_insight:'+p," + J(J({ ok: true, insight: FX3_INSIGHT })) + ");});}catch(e){}" });
  const ev = x => evaluate(cdp, x);
  const DS = require("./designSpec"), TM = DS.TMX, AB = DS.HQ.ABYSS;
  const HT = { 360: 780, 390: 844, 430: 932 };
  const near = (a, b, d) => typeof a === "number" && typeof b === "number" && Math.abs(a - b) <= (d === undefined ? 1.5 : d);
  const shot = async (w, file) => { if (w !== 390) return; const r = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(FX3_OUT, file), Buffer.from(r.data, "base64")); };
  const exc0 = () => exceptionsSeen();
  const pageChecks = async (at, extra) => {
    const m = await ev(MEASURE);
    check(at + "no horizontal scroll", !m.hscroll, J(m.wide));
    check(at + "every tap target is at least 44 x 44 (the Guide's 32 px tab aside, the board's)", m.smallCount === 0, m.smallCount + " " + J(m.small));
    check(at + "decoration is under the text", m.deco.length === 0, J(m.deco));
    const over = m.over.filter(x => !/^(div#tmx-presence-root|nav#bf-tabbar) /.test(x) && !(extra && extra.test(x)));
    check(at + "no fixed element over text or a control at rest (the mist and the bar float by design)", over.length === 0, J(over));
  };
  const outside = "['pointerdown','mousedown','touchstart','click'].forEach(function(t){var e=t==='touchstart'?new Event(t,{bubbles:true}):new MouseEvent(t,{bubbles:true,clientX:innerWidth-6,clientY:40});document.body.dispatchEvent(e);}),true";
  const tapTab = "(function(){var t=document.getElementById('tmx-guide-tab');if(!t)return false;t.click();return true;})()";
  const tapMist = "(function(){var r=document.getElementById('tmx-presence-root');if(!r)return false;r.click();return true;})()";
  const startExc = exceptionsSeen();
  for (const w of FX3_WIDTHS) {
    const h = HT[w] || 844;
    FX3S.free = false; FX3S.insightAsks = 0;
    await open(cdp, origin, "sw.js", w, h, true);
    await ev("(function(){try{sessionStorage.removeItem('fx3_noseed');localStorage.removeItem('bf_hq_view');localStorage.removeItem('bf_hq_orbit');localStorage.removeItem('bf_agents_view');localStorage.removeItem('tmx_presence_pos');}catch(e){}return true;})()");

    // 1. the HQ, ORACLE open: the abyss sun
    await open(cdp, origin, "dashboard.html", w, h, true);
    await ev("window.BFOrbit&&window.BFOrbit.open('oracle'),true"); await sleep(1500);
    let at = "FX3 HQ ORACLE at " + w + ": ";
    const sun = await ev(ABYSS_READ);
    check(at + "the abyss disc fills the centre's circle (" + (sun && sun.disc && sun.disc.w) + " px, the Sun's size), clipped round, first in the centre; its gold ring " + AB.BOARD_RING + " px at 390 (the board's)",
      !!sun && sun.open === "oracle" && sun.disp === "block" && sun.first && sun.radius === "50%" && sun.overflow === "hidden" && near(sun.disc.w, sun.inner) && near(sun.disc.h, sun.inner) &&
      (w !== 390 || near(sun.ring.w, AB.BOARD_RING, 2)), J(sun && [sun.disc, sun.core, sun.inner, sun.ring]));
    check(at + "its void is the chat box's, as the browser draws #tmx-chat: the same four gradients, sizes and colour (" + AB.VOID_BASE + "), tmx-chat-void at 22 s",
      !!sun && sun.grads === 4 && !!sun.chatBg && sun.bgImage === sun.chatBg && sun.size === sun.chatSize && sun.bgColor === sun.chatColor && /rgba\(2, 1, 10, 0\.98\)/.test(sun.bgColor) &&
      sun.anim === "tmx-chat-void" && sun.anim === sun.chatAnim && sun.dur === "22s" && sun.dur === sun.chatDur, J(sun && [sun.grads, sun.bgColor, sun.chatColor, sun.size, sun.chatSize, sun.anim, sun.dur]));
    const want = sun && sun.info ? AB.STAR_BASE.COUNTS.map(c => Math.round(c * sun.info.width * sun.info.height / (AB.STAR_BASE.W * AB.STAR_BASE.H))) : null;
    check(at + "its stars run at the chat box's density per area (" + J(want) + " in " + (sun && sun.info ? sun.info.width + " x " + sun.info.height : "?") + "), painted",
      !!sun && !!sun.info && sun.info.running && J(sun.info.counts) === J(want) && sun.painted > 0 && near(sun.canvas.w, sun.disc.w), J(sun && [sun.info, sun.painted]));
    check(at + "no glow, rays or corona; the gold ring round it; the green stats ring hidden; the moon on the ORACLE node and chip, none in the centre",
      !!sun && sun.glow === "none" && sun.filter === "none" && sun.after === "none" && sun.before === "none" && sun.ringDisp !== "none" && sun.ring.w > sun.disc.w + 2 && Math.abs((sun.ring.l + sun.ring.w / 2) - (sun.disc.l + sun.disc.w / 2)) <= 1 &&
      sun.green.length > 0 && sun.green.every(d => d === "none") && !sun.coreMoon && sun.nodeMoon && sun.chipMoon, J(sun && [sun.glow, sun.ring, sun.green, sun.coreMoon, sun.nodeMoon, sun.chipMoon]));
    // the mist and the Guide's tab at rest
    let s = await ev(FX3_READ);
    const barTop = s.bar ? s.bar.t : s.H;
    check(at + "the mist: " + TM.MIST.SIZE + " x " + TM.MIST.SIZE + ", " + TM.MIST.RIGHT + " px from the right, " + TM.MIST.ABOVE_BAR + " px above the bar, z-index " + TM.MIST.Z + ", a labelled button (\"" + TM.MIST.LABEL + "\") that takes taps",
      !!s.mist && near(s.mist.w, TM.MIST.SIZE) && near(s.mist.h, TM.MIST.SIZE) && near(s.W - s.mist.r, TM.MIST.RIGHT) && near(barTop - s.mist.b, TM.MIST.ABOVE_BAR) && !!s.bar &&
      s.mistZ === String(TM.MIST.Z) && s.mistPE === "auto" && s.mistRole === "button" && s.mistLabel === TM.MIST.LABEL && s.mistTab === 0, J([s.mist, s.bar, s.mistZ, s.mistPE, s.mistRole, s.mistLabel]));
    check(at + "its whisper (when shown) stays inside the screen", !s.whisper || (s.whisper.l >= -0.5 && s.whisper.r <= s.W + 0.5), J(s.whisper));
    check(at + "the Guide's tab at the left edge, in the middle, " + TM.GUIDE.TAB_W + " px wide, " + TM.GUIDE.TAB_MIN_H + " px or taller; no book button and no sheet",
      !!s.tab && near(s.tab.l, 0) && near(s.tab.w, TM.GUIDE.TAB_W) && s.tab.h >= TM.GUIDE.TAB_MIN_H - 0.5 && near((s.tab.t + s.tab.b) / 2, s.H / 2, 2) && !s.open && !s.fab, J([s.tab, s.open, s.fab]));
    await pageChecks(at);
    await shot(w, "hq-abyss-sun.png");
    // the Guide open
    await ev(tapTab); await sleep(700);
    s = await ev(FX3_READ);
    const pw = Math.min(TM.GUIDE.PANEL_W, w - TM.GUIDE.PANEL_EDGE);
    at = "FX3 Guide open at " + w + ": ";
    check(at + "the panel " + pw + " px wide from the left edge, the tab at its right edge, shown",
      s.open && !!s.panel && near(s.panel.l, 0) && near(s.panel.w, pw) && !!s.tab && near(s.tab.l, s.panel.r, 1.5) && s.panelOpacity === "1", J([s.panel, s.tab, s.panelOpacity]));
    check(at + "at most " + TM.GUIDE.PANEL_MAX_VH + "vh tall, scrolling, clear of the bottom bar", s.panel.h <= s.H * TM.GUIDE.PANEL_MAX_VH / 100 + 0.5 && s.panelOverflow === "auto" && s.panel.b <= barTop + 0.5 && s.panel.t >= -0.5, J([s.panel, barTop, s.panelOverflow]));
    check(at + "a member sees the page's tips and the Insights section (the seeded insight; nothing asked of the server)", s.insights && s.insightText === FX3_INSIGHT && FX3S.insightAsks === 0, J([s.insights, s.insightText, FX3S.insightAsks]));
    const barHit = await ev("(function(){var b=document.getElementById('bf-tabbar');if(!b)return 'no bar';var r=b.getBoundingClientRect(),bad=[];for(var i=0;i<10;i++){var x=r.left+(i+.5)*r.width/10,e=document.elementFromPoint(x,r.top+r.height/2);if(e&&!b.contains(e))bad.push(e.id||e.className);}return bad;})()");
    check(at + "it never covers the bottom bar", Array.isArray(barHit) && barHit.length === 0, J(barHit));
    await shot(w, "guide-open.png");
    await ev("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true})),true"); await sleep(500);
    const escClosed = !(await ev(FX3_READ)).open;
    await ev(tapTab); await sleep(500); await ev(outside); await sleep(500);
    const outClosed = !(await ev(FX3_READ)).open;
    await ev(tapTab); await sleep(500); await ev(tapTab); await sleep(500);
    const tabClosed = !(await ev(FX3_READ)).open;
    check(at + "Escape, an outside tap and the tab each close it", escClosed && outClosed && tabClosed, J([escClosed, outClosed, tabClosed]));
    // the chat: Guide mode, then Oracle mode (measured once its opening transition has finished: the ten styles differ in length)
    await ev(tapMist); await sleep(900);
    for (let i = 0; i < 25; i++) { s = await ev(FX3_READ); if (s.chatOpacity === "1" && (s.chatTransform === "none" || /^matrix(1, 0, 0, 1, 0, 0)$/.test(s.chatTransform)) && (s.chatFilter === "none" || !s.chatFilter)) break; await sleep(200); }
    at = "FX3 chat at " + w + ": ";
    const mistTop = s.mist ? s.mist.t : NaN, wantH = Math.min(TM.CHAT.HEIGHT, s.H - TM.CHAT.TOP_GAP, s.H - (s.H - mistTop + TM.CHAT.ABOVE_MIST) - 8);
    check(at + "open, " + TM.CHAT.SIDE + " px from each side, its bottom " + TM.CHAT.ABOVE_MIST + " px above the mist, " + Math.round(wantH) + " px tall (at most " + TM.CHAT.HEIGHT + ")",
      !!s.chat && s.chatOpacity === "1" && s.chatPE === "auto" && near(s.chat.l, TM.CHAT.SIDE) && near(s.W - s.chat.r, TM.CHAT.SIDE) && near(mistTop - s.chat.b, TM.CHAT.ABOVE_MIST) && near(s.chat.h, wantH) && !s.hscroll, J([s.chat, s.mist, s.chatOpacity]));
    check(at + "Reset hidden; the box drawn (visible) and keeps its void and gold rim (animated, motion allowed)", s.chatVis === "visible" && s.reset === "none" && s.chatAnim === "tmx-chat-void" && !!s.chatRimAnim && s.chatRimAnim !== "none", J([s.reset, s.chatAnim, s.chatRimAnim]));
    const cv = await ev("(function(){var c=document.querySelector('#tmx-chat canvas');return c?{w:c.clientWidth,h:c.clientHeight}:null;})()");
    check(at + "its starfield canvas fills the phone's box", !!cv && near(cv.w, s.chat.w, 2) && near(cv.h, s.chat.h, 2), J([cv, s.chat]));
    await shot(w, "chat-guide.png");
    await ev("(function(){var t=document.getElementById('tmx-tab-oracle');if(t)t.click();return !!t;})()"); await sleep(900);
    const om = await ev("(function(){var t=document.getElementById('tmx-tab-oracle');var m=document.getElementById('tmx-chat-msgs');return {sel:t&&t.getAttribute('aria-selected'),text:m?m.textContent:''};})()");
    check(at + "Oracle mode: its tab selected, the Oracle's greeting; no message sent", om.sel === "true" && /The Oracle stirs/.test(om.text) && FX3S.sent === 0, J([om.sel, om.text.slice(0, 80), FX3S.sent]));
    await shot(w, "chat-oracle.png");
    await ev("(function(){var t=document.getElementById('tmx-tab-guide');if(t)t.click();return true;})()"); await sleep(300);
    await ev(tapMist); await sleep(1200);
    s = await ev(FX3_READ);
    check(at + "a second tap on the mist closes it, and once closed the box is not drawn on the phone (hidden, so no blur or animation is painted over the orbit)", s.chatOpacity === "0" && s.chatPE === "none" && s.chatVis === "hidden", J([s.chatOpacity, s.chatPE, s.chatVis]));
    // another portal
    await ev("window.BFOrbit&&window.BFOrbit.open('sell'),true"); await sleep(900);
    const other = await ev(ABYSS_READ);
    check("FX3 HQ another portal (SELL) at " + w + ": no abyss, its stars stopped, the green ring back", !!other && other.disp === "none" && !!other.info && !other.info.running && other.green.some(d => d !== "none"), J(other && [other.disp, other.info, other.green]));

    // 2. reduced motion
    await cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }] });
    await open(cdp, origin, "dashboard.html", w, h, true);
    await ev("window.BFOrbit&&window.BFOrbit.open('oracle'),true"); await sleep(1300);
    at = "FX3 reduced motion at " + w + ": ";
    const r1 = await ev(ABYSS_READ), pic1 = await ev("(function(){var c=document.querySelector('#orbitCore .hq-core-abyss canvas');return c?c.toDataURL():null;})()");
    await sleep(1500);
    const pic2 = await ev("(function(){var c=document.querySelector('#orbitCore .hq-core-abyss canvas');return c?c.toDataURL():null;})()");
    check(at + "the abyss disc is drawn still: no void drift, the same picture 1.5 s apart", !!r1 && r1.anim === "none" && !!r1.info && r1.info.reducedMotion && r1.painted > 0 && !!pic1 && pic1 === pic2, J(r1 && [r1.anim, r1.info, r1.painted, pic1 === pic2]));
    await ev(tapMist); await sleep(700);
    s = await ev(FX3_READ);
    check(at + "the chat opens with a plain " + TM.STILL_FADE_S + " s fade; its void, rim and shooting star still",
      s.chatOpacity === "1" && /opacity 0\.2s/.test(s.chatTransition || "") && s.chatAnim === "none" && s.chatRimAnim === "none" && !!s.shoot && s.shoot.op === "0", J([s.chatOpacity, s.chatTransition, s.chatAnim, s.chatRimAnim, s.shoot]));
    await shot(w, "chat-reduced-motion.png");
    await ev(tapMist); await sleep(500);
    await cdp.send("Emulation.setEmulatedMedia", { features: [] });

    // 3. another page: Home's feed (the mist over the feed, under its sheets); oracle.html (no mist)
    await open(cdp, origin, "home.html", w, h, true);
    s = await ev(FX3_READ);
    // Home loads no Guide (as before FX3), so only the mist is here
    check("FX3 Home at " + w + ": the mist in its place over the feed, no book button", !!s.mist && near(s.W - s.mist.r, TM.MIST.RIGHT) && !!s.bar && near(s.bar.t - s.mist.b, TM.MIST.ABOVE_BAR) && !s.fab, J([s.mist, s.bar]));
    await pageChecks("FX3 Home at " + w + ": ");
    await open(cdp, origin, "oracle.html", w, h, true);
    s = await ev(FX3_READ);
    check("FX3 oracle.html at " + w + ": no mist (TMX_NO_MIST_PAGES, as before)", !s.mist, J(s.mist));

    // 4. the Agent Directory: Large, Compact and Grid
    const dash = await (async () => {
      await open(cdp, origin, "dashboard.html", w, h, true);
      await ev("window.BFOrbit&&window.BFOrbit.open('agents'),true"); await sleep(900);
      return ev("[].map.call(document.querySelectorAll('#orbitGrid #agentDirectoryLanding .orbit-dir-icon'),function(e){var cs=getComputedStyle(e),s=e.querySelector('svg');return{agent:e.getAttribute('data-bf-agent-mark'),color:cs.color,ring:cs.borderTopColor,glow:cs.boxShadow,icon:s?s.innerHTML.replace(/\\s+/g,' '):null}})");
    })();
    check("FX3 dashboard agents at " + w + ": the Directory box's five agents carry their marks", Array.isArray(dash) && dash.length === 5 && dash.every(d => d.agent && d.icon), J(dash));
    await open(cdp, origin, "ai-agents.html", w, h, true);
    for (const view of ["large", "compact", "grid"]) {
      await ev("(function(){var b=document.querySelector('#agViewRow .ag-view-btn[data-view=\"" + view + "\"]');if(b)b.click();return !!b;})()"); await sleep(500);
      const items = await ev(FX3_AGENTS);
      at = "FX3 Agent Directory " + view + " at " + w + ": ";
      const bad = (items || []).filter(i => !i.known || i.color !== i.wantColor || i.icon !== i.wantIcon || !i.shown);
      const dashBad = (items || []).filter(i => { const d = (dash || []).find(x => x.agent === i.agent); return d && (d.color !== i.color || d.icon !== i.icon || d.ring !== i.ring || d.glow !== i.glow); });
      check(at + "every agent (" + (items || []).length + ") carries the shared map's own colour and icon", Array.isArray(items) && items.length >= 18 && bad.length === 0 && items.every(i => i.view === view), J(bad.slice(0, 3)));
      check(at + "and the dashboard's agents are identical there (colour, ring, glow, icon)", dashBad.length === 0 && (items || []).filter(i => (dash || []).some(d => d.agent === i.agent)).length === 5, J(dashBad.slice(0, 2)));
      await pageChecks(at);
      await shot(w, "agents-" + view + ".png");
    }

    // 5. a free account: the mist opens the members panel; the Guide asks nothing
    FX3S.free = true; FX3S.insightAsks = 0;
    await ev("(function(){try{sessionStorage.setItem('fx3_noseed','1');Object.keys(sessionStorage).filter(function(k){return k.indexOf('bf_tmx_insight:')===0;}).forEach(function(k){sessionStorage.removeItem(k);});}catch(e){}return true;})()");
    await open(cdp, origin, "dashboard.html", w, h, true);
    at = "FX3 free account at " + w + ": ";
    await ev(tapMist); await sleep(900);
    s = await ev(FX3_READ);
    check(at + "a tap on the mist opens the members panel, never the chat", s.panelBox && s.chatOpacity === "0" && s.chatPE === "none", J([s.panelBox, s.chatOpacity]));
    await shot(w, "free-mist-panel.png");
    await ev("(function(){var v=document.getElementById('bf-members-panel');if(v)v.parentNode.removeChild(v);return true;})()");
    await ev(tapTab); await sleep(900);
    s = await ev(FX3_READ);
    const insNode = await ev("!!document.querySelector('#tmx-guide-panel .tmx-guide-section--insights')");
    check(at + "the Guide shows the page's tips only: no Insights section, no /api/insights/page request", s.open && !s.insights && !insNode && FX3S.insightAsks === 0, J([s.open, s.insights, insNode, FX3S.insightAsks]));
    await ev(tapTab); await sleep(300);
    FX3S.free = false;
    await ev("(function(){try{sessionStorage.removeItem('fx3_noseed');}catch(e){}return true;})()");

    // 6. signed out: neither the mist nor the Guide
    await ev("sessionStorage.setItem('phone_check_out','1'),localStorage.removeItem('bf_token'),localStorage.removeItem('bf_user'),true");
    await open(cdp, origin, "ai-agents.html", w, h, true);
    s = await ev(FX3_READ);
    check("FX3 signed out at " + w + ": no mist and no Guide", !s.mist && !s.guide, J([s.mist, s.guide]));
    await ev("sessionStorage.removeItem('phone_check_out'),true");
  }
  check("FX3: no chat message was sent in the whole run", FX3S.sent === 0, FX3S.sent);
  const exc = exceptionsSeen().slice(startExc.length).filter(x => /tmx|abyss|Abyss|agent-marks|AgentMarks|guide|bf-hq-views/i.test(x));
  check("FX3: no page threw from the Termaximus, abyss or agent-marks scripts", exc.length === 0, J(exc.slice(0, 5)));
}
// the Agent Directory's marks against the shared map (BFAgentMarks), as drawn
const FX3_AGENTS = String.raw`(function(){var pg=document.querySelector('.page');var v=pg&&pg.getAttribute('data-ag-view');var M=window.BFAgentMarks;
  var q=v==='large'?[].map.call(document.querySelectorAll('article.agent-card'),function(c){return[(/agent-card--([a-z_]+)/.exec(c.className)||[])[1],c.querySelector('.agent-avatar')]}):[].map.call(document.querySelectorAll('#agList .ag-item'),function(i){return[i.getAttribute('data-agent'),i.querySelector('.ag-icon')]});
  var probe=document.createElement('span');document.body.appendChild(probe);
  var out=q.map(function(p){var e=p[1],cs=e?getComputedStyle(e):null,s=e&&e.querySelector('svg');var known=!!(M&&p[0]&&M.colour&&M.colour(p[0]));var wantColor=null,wantIcon=null;
    if(known){probe.style.color=M.colour(p[0]);wantColor=getComputedStyle(probe).color;var d=document.createElement('div');d.innerHTML=M.svg(p[0]);var ws=d.querySelector('svg');wantIcon=ws?ws.innerHTML.replace(/\s+/g,' '):null;}
    return{agent:p[0],view:v,known:known,color:cs&&cs.color,wantColor:wantColor,ring:cs&&cs.borderTopColor,glow:cs&&cs.boxShadow,icon:s?s.innerHTML.replace(/\s+/g,' '):null,wantIcon:wantIcon,shown:!!e&&e.getBoundingClientRect().width>0};});
  probe.remove();return out;})()`;

/* ══ P3-3 (Nov 23 2026): PHONE_P33=1 ═════════════════════════════════════════════════════════════════════════════
   Share, Offer or Need at PHONE_P33_WIDTHS (default 360, 390, 430), fixtures only; the seven screenshots at 390 x 844 to
   PHONE_P33_OUT (default Downloads\p33). The posts are lib/posts.js over P2-3's in-memory database with the categories table
   (migration 200's 32, scripts/_categories.js); GET /api/categories answers the same rows lib/categories.js would. Rose is a
   member (lib/posts.js is handed the tier) who sells a sourdough loaf (Food & Cooking); Pat posts a text-only Need in Food &
   Cooking in Portland this week. The composer (Need: the label, Where prefilled, When, the box, the chips that swipe, a
   category required; Offer: the listing picker and its category); a free account's Offer opening the members panel; the Need
   post with "You offer this nearby" and I can help (a private message through POST /api/messages, the post linked, then the
   Inbox); Found by the poster from the post's menu (FOUND, the strip gone) and reopened; the Market's chips (All and the 32,
   filtering by category_slug, the owner's uncategorised listing under All with "Add a category"); Market create refused
   without a category; and Settings' Need alerts switch (on, saved as need_alerts false when switched off). */
const P33 = process.env.PHONE_P33 === "1";
const P33_WIDTHS = String(process.env.PHONE_P33_WIDTHS || "360,390,430").split(",").map(Number).filter(Boolean);
const P33_OUT = process.env.PHONE_P33_OUT || path.join(os.homedir(), "Downloads", "p33");
const P33S = { member: true, needAlerts: null, prefPuts: [], messages: [], listingPosts: [], listings: [] };
const P33_CATS = require("./_categories").rows().filter(c => c.active !== false).sort((a, b) => a.sort_order - b.sort_order).map(c => ({ slug: c.slug, name: c.name, group: c.parent_group || null }));
const P33_NEED = uid(8301), P33_L = { rose: "cccccccc-0000-4000-8000-000000003301", bare: "cccccccc-0000-4000-8000-000000003302", pat: "cccccccc-0000-4000-8000-000000003303", lee: "cccccccc-0000-4000-8000-000000003304" };
const P33_NEED_BODY = "Looking for a baker for a birthday cake for 40 people, chocolate with raspberries, ready on Saturday.";
function p33Listings() {
  const l = (id, seller, title, slug, price, hrs) => ({ id, slug: title.toLowerCase().replace(/[^a-z0-9]+/g, "-"), seller_id: seller, title, description: title + ".", price_bfc: price, category: slug, category_slug: slug,
    tags: [], media: [], status: "active", listing_kind: "product", created_at: ago(hrs) });
  return [l(P33_L.rose, ROSE.id, "Sourdough loaf", "food", 12, 2), l(P33_L.bare, ROSE.id, "Bread basket", null, 20, 4), l(P33_L.pat, P21_PEER, "Plum jam", "food", 15, 6), l(P33_L.lee, P21_PEER2, "Blue mug", "crafts_handmade", 30, 8)];
}
function p33Api(method, u, request) {
  const p = u.pathname;
  let b = {}; try { b = JSON.parse((request && request.postData) || "{}"); } catch (e) { b = {}; }
  if (p === "/api/auth/me") return { user: Object.assign({}, ROSE, { role: "user", email_verified_at: ago(24) }),
    access: P33S.member ? { active: true, exempt: false, access_reason: "subscription", inactive_reason: null, tier: "member", email_verified: true, members_panel: require("../lib/membership").membersPanelFromCode() }
      : { active: false, exempt: false, access_reason: null, inactive_reason: "no_subscription", tier: "free", email_verified: true, members_panel: require("../lib/membership").membersPanelFromCode() },
    subscription: null, profile: { username: "rose" } };
  if (p === "/api/categories") return { categories: P33_CATS };
  if (p === "/api/user/preferences") {
    if (method === "PUT") { P33S.prefPuts.push(b); if ("need_alerts" in b) P33S.needAlerts = b.need_alerts; return { saved: true }; }
    return { ok: true, preferences: {}, termaximus_active: true, need_alerts: P33S.needAlerts !== false };
  }
  if (p === "/api/marketplace/listings" && method === "GET") { const c = u.searchParams.get("category"); return { listings: P33S.listings.filter(l => !c || c === "all" || l.category_slug === c) }; }
  if (p === "/api/marketplace/listings" && method === "POST") {   // as server.js answers it (P3-3): a category on the list, required
    P33S.listingPosts.push(b);
    if (!b.category) return { __status: 400, __body: { error: "Choose a category. It is the same list as posts.", field: "category" } };
    if (!P33_CATS.some(c => c.slug === b.category)) return { __status: 400, __body: { error: "That category isn't on the list. Choose one from the list.", field: "category" } };
    const row = Object.assign({}, b, { id: uid(8390 + P33S.listings.length), seller_id: ROSE.id, category_slug: b.category, status: "active", created_at: new Date(NOW).toISOString() });
    P33S.listings.unshift(row); return { listing: row };
  }
  if (p === "/api/messages" && method === "POST") { P33S.messages.push(b); return { message: { id: uid(8399), sender_id: ROSE.id, receiver_id: b.receiver_id, content: b.content, created_at: new Date(NOW).toISOString() } }; }
  return undefined;
}
async function p33World() {
  Object.assign(P23S, await p23World(false));
  const P = require("../lib/posts"), d = P23S.deps;
  d.tierOf = async id => (id === ROSE.id && !P33S.member ? "free" : "member");
  d.membersPanel = () => require("../lib/membership").membersPanelFromCode();
  const rose = P23S.db.t.bf_profiles.find(x => x.user_id === ROSE.id); rose.place_city = "Portland"; rose.place_region = "OR";
  P23S.db.t.marketplace_listings = p33Listings().map(l => Object.assign({}, l, { seller_id: l.seller_id, updated_at: l.created_at }));
  P23S.db.t.posts.push({ id: P33_NEED, author_id: P21_PEER, kind: "text", body: P33_NEED_BODY, audience: "public", status: "published", intent: "need", category: "food",
    need_place: "Portland, OR", need_when: "week", need_found_at: null, place_city: null, place_region: null, place_country: null, like_count: 0, comment_count: 0, save_count: 0, share_count: 0,
    removed_at: null, created_at: ago(0.5), published_at: ago(0.5) });
  P33S.listings = p33Listings(); P33S.messages = []; P33S.listingPosts = []; P33S.prefPuts = []; P33S.needAlerts = null; P33S.member = true;
  return P;
}
async function p33Run(cdp, origin) {
  fs.mkdirSync(P33_OUT, { recursive: true });
  console.log("browserCheckPhone P3-3 (the composer's Share, Offer or Need, the Need post, Found, the Market's categories, Need alerts in Settings) at " + P33_WIDTHS.join(", "));
  await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: "try{localStorage.setItem('bf_token'," + J(ID_TOKEN) + ");}catch(e){}" });
  const ev = x => evaluate(cdp, x);
  const HT = { 360: 780, 390: 844, 430: 932 };
  const DSC = require("./designSpec"), CO = DSC.COMPOSER, NP = DSC.NEEDPOST;
  const VEIL = /^div#bf-members-panel /, DLG = /^(div|section)#bfp-(dialog|talk)(-backdrop)? |^div\.bfp-(dlg|backdrop)/;
  const pageChecks = async (at, opts) => {
    const m = await ev(MEASURE);
    check(at + "no horizontal scroll", !m.hscroll, J(m.wide));
    check(at + "no text cut off", m.clipped.length === 0, J(m.clipped));
    check(at + "every tap target is at least 44 x 44", m.smallCount === 0, m.smallCount + " " + J(m.small));
    const deco = m.deco.filter(x => !(opts && opts.panel && VEIL.test(x)) && !(opts && opts.dialog && DLG.test(x)));
    check(at + "decoration is under the text" + (opts && opts.panel ? " (the panel's veil aside)" : ""), deco.length === 0, J(deco));
    const over = m.over.filter(x => !/^(div#tmx-presence-root|nav#bf-tabbar) /.test(x) && !(opts && opts.panel && VEIL.test(x)) && !(opts && opts.dialog && DLG.test(x)));
    check(at + "no fixed element over text or a control at rest" + (opts && opts.panel ? " (the members panel is meant to cover the page)" : ""), over.length === 0, J(over));
  };
  const rgb = h => { const n = parseInt(h.slice(1), 16); return "rgb(" + (n >> 16) + ", " + ((n >> 8) & 255) + ", " + (n & 255) + ")"; };
  const CYAN = rgb("#22d3ee");
  const tapIntent = v => ev("(function(){var r=document.querySelector('input[name=bfcIntent][value=" + v + "]');if(!r)return false;(r.closest('label')||r).click();return true;})()");
  const tapCat = v => ev("(function(){var r=document.querySelector('input[name=bfcCat][value=" + v + "]');if(!r)return false;(r.closest('label')||r).click();return true;})()");
  const type = t => ev("(function(){var t=document.getElementById('bfcText');if(!t)return false;t.focus();t.value=" + J(t) + ";t.dispatchEvent(new Event('input',{bubbles:true}));t.blur();return true;})()");
  const postIt = () => ev("(function(){var b=document.getElementById('bfcPost');if(b)b.click();return !!b;})()");
  const READ_COMPOSER = String.raw`(function(){
    var q=function(s){return document.querySelector(s);},vis=function(e){return !!e&&!e.hidden&&e.getBoundingClientRect().height>0;};
    var tiles=[].map.call(document.querySelectorAll('.bfc-tile'),function(t){var f=t.querySelector('.bfc-face'),cs=getComputedStyle(f),r=f.getBoundingClientRect(),i=t.querySelector('input');
      return {v:t.getAttribute('data-v'),on:!!i&&i.checked,bg:cs.backgroundColor,edge:cs.borderTopColor,h:Math.round(r.height),tag:(t.querySelector('.bfc-mtag')||{}).textContent||null,members:t.hasAttribute('data-members-only')};});
    var cats=q('#bfcCats'),chips=cats?cats.querySelectorAll('input[name=bfcCat]'):[],on=cats&&cats.querySelector('input:checked'),chip0=cats&&cats.querySelector('.bfc-chip .bfc-face');
    var when=[].map.call(document.querySelectorAll('input[name=bfcWhen]'),function(i){return [i.value,i.checked];});
    var sel=q('#bfcListing'),place=q('#bfcPlace'),box=q('#bfcNeedBox'),pr=q('#bfcPost');
    var wr=q('.bfc-when'),wrR=wr&&wr.getBoundingClientRect();
    return {tiles:tiles,label:(q('#bfcTextL')||{}).textContent,chips:chips.length,chipH:chip0?Math.round(chip0.getBoundingClientRect().height):0,swipes:!!cats&&cats.scrollWidth>cats.clientWidth+4,
      wraps:!!cats&&getComputedStyle(cats).flexWrap,cat:on?on.value:null,note:(q('#bfcCatNote')||{}).textContent,need:vis(q('#bfcNeed')),place:place&&place.value,placeMax:place&&place.maxLength,when:when,
      whenRight:wrR?Math.round(wrR.right):null,box:vis(box)?box.textContent.replace(/\s+/g,' ').trim():null,offer:vis(q('#bfcOffer')),listings:sel?[].map.call(sel.options,function(o){return o.value;}).filter(Boolean):[],
      listing:sel&&sel.value,photos:vis(q('#bfcPhotos')),aud:vis(q('#bfcAudience')),seo:vis(q('#bfcSeo')),post:pr?Math.round(pr.getBoundingClientRect().height):0,err:(q('#bfcErr')||{}).textContent||'',
      panel:!!document.getElementById('bf-members-panel')};})()`;
  for (const w of P33_WIDTHS) {
    const h = HT[w] || 844;
    const shot = async name => { if (w === 390) { const r = await cdp.send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(path.join(P33_OUT, name + ".png"), Buffer.from(r.data, "base64")); } };
    const P = await p33World();

    // 1. the composer, a member's Need
    await open(cdp, origin, "compose.html", w, h, true);
    let at = "P33 composer (Need) at " + w + ": ";
    let c = await ev(READ_COMPOSER);
    check(at + "three tiles Share, Offer, Need, " + CO.TILES.H + " px; Share chosen first", c.tiles.map(t => t.v).join() === "share,offer,need" && c.tiles.every(t => t.h === CO.TILES.H) && c.tiles[0].on, J(c.tiles));
    check(at + "the category chips: the 32 from the list, " + CO.CHIPS.H + " px, one row that swipes, the note \"" + CO.CHIPS.NOTE + "\"; none chosen", c.chips === 32 && c.chipH === CO.CHIPS.H && c.swipes && c.wraps === "nowrap" && c.note === CO.CHIPS.NOTE && c.cat === null, J(c));
    await tapIntent("need"); await sleep(250);
    c = await ev(READ_COMPOSER);
    const need = c.tiles.find(t => t.v === "need") || {};
    check(at + "Need chosen: its tile cyan (" + CO.TILES.ON_FILL + " with a cyan edge), the others not", need.on && need.bg === rgb(CO.TILES.ON_FILL) && need.edge === CYAN && c.tiles.filter(t => t.v !== "need").every(t => !t.on && t.edge !== CYAN), J(c.tiles));
    check(at + "the label \"" + CO.LABELS.need + "\"; Where prefilled from the profile (Portland, OR; 80 at most); When Today / Week / Any inside the screen", c.label === CO.LABELS.need && c.need && c.place === "Portland, OR" && c.placeMax === 80 &&
      c.when.map(x => x[0]).join() === "today,week,any" && c.whenRight !== null && c.whenRight <= w - 15, J(c));
    check(at + "the box \"" + CO.BOX.TEXT + "\" on a public Need; photos up to 4; Public / Followers; no listing picker", c.box === CO.BOX.TEXT && c.photos && c.aud && !c.offer, J(c));
    await ev("(function(){var r=document.querySelector('input[name=bfcAud][value=followers]');if(r)(r.closest('label')||r).click();return !!r;})()"); await sleep(150);
    const boxFol = (await ev(READ_COMPOSER)).box;
    await ev("(function(){var r=document.querySelector('input[name=bfcAud][value=public]');if(r)(r.closest('label')||r).click();return !!r;})()"); await sleep(150);
    check(at + "the box goes for a followers-only Need (no alerts are sent for one) and comes back for Public", boxFol === null && (await ev(READ_COMPOSER)).box === CO.BOX.TEXT, J(boxFol));
    const roseNeed = "Need a hand with a market stall this Saturday morning, setting up at 7.";
    await type(roseNeed);
    await ev("(function(){var r=document.querySelector('input[name=bfcWhen][value=week]');if(r)(r.closest('label')||r).click();return !!r;})()"); await sleep(150);
    const n0 = P23S.db.t.posts.length;
    await postIt(); await sleep(500);
    c = await ev(READ_COMPOSER);
    check(at + "Post without a category says so and sends nothing", c.err === "Choose a category. It is the same list as the Market." || (/category/i.test(c.err) && P23S.db.t.posts.length === n0), J([c.err, P23S.db.t.posts.length - n0]));
    check(at + "...nothing saved", P23S.db.t.posts.length === n0);
    await tapCat("food"); await sleep(200);
    await ev("(function(){var t=document.getElementById('bfcIntent');if(t)t.scrollIntoView({block:'start'});window.scrollTo(0,0);return true;})()"); await sleep(200);
    await pageChecks(at);
    await shot("composer-need");
    await postIt(); await sleep(3000);
    const rn = P23S.db.t.posts.find(x => x.author_id === ROSE.id && x.body === roseNeed);
    check(at + "Post stores the Need: intent need, category food, Where Portland, OR, When week, public", !!rn && rn.intent === "need" && rn.category === "food" && rn.need_place === "Portland, OR" && rn.need_when === "week" && rn.audience === "public", J(rn));

    // 2. the composer, a member's Offer
    await open(cdp, origin, "compose.html", w, h, true);
    at = "P33 composer (Offer, a member) at " + w + ": ";
    await tapIntent("offer"); await sleep(400);
    c = await ev(READ_COMPOSER);
    check(at + "the label \"" + CO.LABELS.offer + "\" and the picker of Rose's own active listings (the loaf and the basket; never Pat's or Lee's)", c.label === CO.LABELS.offer && c.offer &&
      J(c.listings.slice().sort()) === J([P33_L.rose, P33_L.bare].sort()) && !c.need && c.box === null, J(c));
    await ev("(function(){var s=document.getElementById('bfcListing');if(!s)return false;s.value=" + J(P33_L.rose) + ";s.dispatchEvent(new Event('change',{bubbles:true}));return true;})()"); await sleep(250);
    c = await ev(READ_COMPOSER);
    check(at + "the category follows the chosen listing's (Food & Cooking)", c.cat === "food", J(c.cat));
    await type("Sourdough loaves every morning from 7, rye on Saturdays.");
    await ev("window.scrollTo(0,0),true"); await sleep(150);
    await pageChecks(at);
    await shot("composer-offer-member");
    await postIt(); await sleep(3000);
    const ro = P23S.db.t.posts.find(x => x.author_id === ROSE.id && x.intent === "offer");
    check(at + "Post stores the Offer with its listing and category", !!ro && ro.listing_id === P33_L.rose && ro.category === "food", J(ro));

    // 3. a free account's Offer: the Members tag, the members panel
    P33S.member = false;
    await open(cdp, origin, "compose.html", w, h, true);
    at = "P33 composer (Offer, a free account) at " + w + ": ";
    c = await ev(READ_COMPOSER);
    const off = c.tiles.find(t => t.v === "offer") || {};
    check(at + "the Offer tile carries the \"" + CO.TILES.MEMBERS_TAG + "\" tag", off.tag === CO.TILES.MEMBERS_TAG && off.members, J(off));
    await tapIntent("offer"); await sleep(700);
    c = await ev(READ_COMPOSER);
    check(at + "a tap opens the members panel; Offer is not chosen (Share stays)", c.panel && c.tiles[0].on && !(c.tiles.find(t => t.v === "offer") || {}).on, J([c.panel, c.tiles.map(t => t.on)]));
    await pageChecks(at, { panel: true });
    await shot("composer-free-offer-panel");
    P33S.member = true;

    // 4. Pat's Need on Home: the tag, the line, the strip, I can help
    await open(cdp, origin, "home.html?post=" + P33_NEED, w, h, true);
    at = "P33 Need post (a member who offers) at " + w + ": ";
    const READ_POST = "(function(){var e=document.querySelector('.bfp-post[data-post=\"" + P33_NEED + "\"]');if(!e)return null;var t=e.querySelector('.bfp-tag'),m=e.querySelector('.bfp-kmeta'),s=e.querySelector('.bfp-help'),g=e.querySelector('.bfp-help-go'),bg=e.querySelector('.bfp-needbg');" +
      "var tr=t&&t.getBoundingClientRect(),sr=s&&s.getBoundingClientRect(),gr=g&&g.getBoundingClientRect();" +
      "return {intent:e.getAttribute('data-intent'),tag:t&&t.textContent,tagH:tr&&Math.round(tr.height),tagBg:t&&getComputedStyle(t).backgroundColor,meta:m&&m.textContent,strip:!!s&&sr.height>0,stripH:sr&&Math.round(sr.height),stripL:sr&&Math.round(sr.left),stripR:sr&&Math.round(sr.right)," +
      "title:(e.querySelector('.bfp-help-t')||{}).textContent,sub:(e.querySelector('.bfp-help-s')||{}).textContent,go:g&&g.textContent,goH:gr&&Math.round(gr.height),backdrop:!!bg&&bg.getBoundingClientRect().height>0," +
      "name:(e.querySelector('.bfp-name')||{}).textContent,text:(e.querySelector('.bfp-text')||{}).textContent};})()";
    let np = await ev(READ_POST);
    check(at + "the NEED tag (" + NP.TAG.H + " px, cyan), then \"Food & Cooking · Portland · This week\", the name and the text, over the board's backdrop", !!np && np.intent === "need" && np.tag === "NEED" && np.tagH === NP.TAG.H && np.tagBg === CYAN &&
      np.meta === "Food & Cooking · Portland · This week" && /Pat/.test(np.name || "") && (np.text || "").indexOf(P33_NEED_BODY.slice(0, 40)) !== -1 && np.backdrop, J(np));
    check(at + "the strip \"" + NP.STRIP.TITLE + "\" / \"" + NP.STRIP.SUB + "\" / \"" + NP.STRIP.BUTTON + "\" (a " + NP.STRIP.BUTTON_H + " px pill; the strip 44 px or taller), inside the screen", !!np && np.strip && np.title === NP.STRIP.TITLE && np.sub === NP.STRIP.SUB &&
      np.go === NP.STRIP.BUTTON && np.goH === NP.STRIP.BUTTON_H && np.stripH >= 44 && np.stripL >= 0 && np.stripR <= w, J(np));
    await pageChecks(at);
    await shot("need-post-member");
    await ev("(function(){var s=document.querySelector('.bfp-post[data-post=\"" + P33_NEED + "\"] .bfp-help');if(s)s.click();return !!s;})()"); await sleep(600);
    const dlg = await ev("(function(){var b=document.getElementById('bfpHelpBody');return b?{v:b.value,send:(document.getElementById('bfpHelpSend')||{}).textContent}:null;})()");
    check(at + "I can help opens a private message to Pat, the post's link in it", !!dlg && /^Hi Pat/.test(dlg.v) && dlg.v.indexOf("/p/" + P33_NEED) !== -1 && dlg.send === "Send privately", J(dlg));
    await pageChecks(at + "(the message open) ", { dialog: true });
    await ev("(function(){var b=document.getElementById('bfpHelpSend');if(b)b.click();return !!b;})()"); await sleep(1800);
    const sent = P33S.messages[0] || {}, where = await ev("location.pathname + location.search");
    check(at + "Send privately goes through POST /api/messages to Pat with the link, then the conversation", P33S.messages.length === 1 && sent.receiver_id === P21_PEER && String(sent.content).indexOf("/p/" + P33_NEED) !== -1 &&
      where === "/inbox.html?with=" + P21_PEER, J([P33S.messages, where]));
    check(at + "no Need alert, push or email was sent by the page (alerts are the server's, in-app)", P23S.db.t.notifications.filter(n => n.type === "need_alert" && n.user_id === ROSE.id).length === 0);

    // 5. Found: Rose marks her own Need Found from the post's menu, then reopens it; Pat's, marked Found, loses the strip
    await open(cdp, origin, "home.html?post=" + rn.id, w, h, true);
    at = "P33 Found (the poster) at " + w + ": ";
    const menuPick = label => ev("(function(){var e=document.querySelector('.bfp-post[data-post=\"" + rn.id + "\"]');if(!e)return 'no post';var a=e.querySelector('[data-act=share]');if(a)a.click();" +
      "return new Promise(function(res){setTimeout(function(){var b=[].filter.call(document.querySelectorAll('.bf-safety-item'),function(x){return x.textContent===" + J(label) + "&&x.getBoundingClientRect().height>0;})[0];if(b){b.click();res('ok');}else res([].map.call(document.querySelectorAll('.bf-safety-item'),function(x){return x.textContent;}).join('|'));},500);});})()");
    const pick1 = await menuPick("Mark Found"); await sleep(1200);
    const tagNow = await ev("(function(){var t=document.querySelector('.bfp-post[data-post=\"" + rn.id + "\"] .bfp-tag');return t?t.textContent:null;})()");
    check(at + "the post's menu marks it Found: the tag reads FOUND, stored", pick1 === "ok" && tagNow === "FOUND" && !!P23S.db.t.posts.find(x => x.id === rn.id).need_found_at, J([pick1, tagNow]));
    const pick2 = await menuPick("Reopen Need"); await sleep(1200);
    const tagBack = await ev("(function(){var t=document.querySelector('.bfp-post[data-post=\"" + rn.id + "\"] .bfp-tag');return t?t.textContent:null;})()");
    check(at + "...and Reopen Need reopens it: NEED again, stored", pick2 === "ok" && tagBack === "NEED" && !P23S.db.t.posts.find(x => x.id === rn.id).need_found_at, J([pick2, tagBack]));
    await P.markFound(P23S.deps, P21_PEER, P33_NEED, true);
    await open(cdp, origin, "home.html?post=" + P33_NEED, w, h, true);
    at = "P33 Need post (Found) at " + w + ": ";
    np = await ev(READ_POST);
    check(at + "Pat's Need, Found: the tag reads FOUND, no strip", !!np && np.tag === "FOUND" && !np.strip && np.meta === "Food & Cooking · Portland · This week", J(np));
    await pageChecks(at);
    await shot("need-post-found");

    // 6. the Market: the chips, the filter, the owner's uncategorised listing, create without a category
    await open(cdp, origin, "marketplace.html", w, h, true);
    at = "P33 Market at " + w + ": ";
    const READ_MARKET = "(function(){var row=document.getElementById('catFilter'),chips=row?[].map.call(row.querySelectorAll('.cat-chip'),function(b){var r=b.getBoundingClientRect();return [b.getAttribute('data-cat'),b.getAttribute('aria-pressed'),Math.round(r.height)];}):[];" +
      "var cards=[].map.call(document.querySelectorAll('#listingsGrid .listing-card'),function(c){return (c.querySelector('.listing-title,.card-title,h3')||{}).textContent||'';});" +
      "return {chips:chips,swipes:!!row&&row.scrollWidth>row.clientWidth+4,cards:cards,add:[].map.call(document.querySelectorAll('.add-cat-btn'),function(b){return b.textContent;})};})()";
    let mk = await ev(READ_MARKET);
    check(at + "the filter: All and the 32 from the list, All chosen, one row that swipes, each 44 px", mk.chips.length === 33 && mk.chips[0][0] === "all" && mk.chips[0][1] === "true" && mk.swipes && mk.chips.every(x => x[2] >= 44), J(mk.chips.slice(0, 3)));
    check(at + "All shows every listing, the uncategorised one too, with \"Add a category\" on Rose's own", mk.cards.length === 4 && mk.cards.some(t => /Bread basket/.test(t)) && mk.add.length === 1, J(mk));
    await ev("(function(){var b=document.querySelector('#catFilter .cat-chip[data-cat=food]');if(b){b.scrollIntoView({inline:'center',block:'nearest'});b.click();}return !!b;})()"); await sleep(900);
    mk = await ev(READ_MARKET);
    check(at + "Food & Cooking: only its two listings (by category_slug), the chip pressed", mk.cards.length === 2 && mk.cards.every(t => /Sourdough|Plum/.test(t)) && (mk.chips.find(x => x[0] === "food") || [])[1] === "true", J(mk));
    await ev("(function(){var r=document.getElementById('catFilter');if(r)window.scrollTo(0,r.getBoundingClientRect().top+window.scrollY-12);return true;})()"); await sleep(250);   // the chips and the listings they filter
    await pageChecks(at);
    await shot("market-filter");
    await ev("(function(){openCreateModal();return true;})()"); await sleep(500);
    at = "P33 Market create at " + w + ": ";
    await ev("(function(){document.getElementById('fTitle').value='Cinnamon buns';document.getElementById('fPrice').value='9';return true;})()");
    const catChips = await ev("(function(){var r=document.querySelectorAll('#fCategory input[name=fCat]');return {n:r.length,on:[].filter.call(r,function(x){return x.checked;}).length};})()");
    check(at + "the form's category chips: the 32 from the list, none chosen", catChips.n === 32 && catChips.on === 0, J(catChips));
    const posts0 = P33S.listingPosts.length;
    await ev("(function(){var b=document.getElementById('submitBtn');if(b)b.click();return !!b;})()"); await sleep(700);
    const cn = await ev("(function(){var n=document.getElementById('fCategoryNote');return n?{t:n.textContent,err:n.classList.contains('is-error')}:null;})()");
    check(at + "Save without a category says so and sends nothing", !!cn && cn.err && cn.t === "Choose a category. It is the same list as posts." && P33S.listingPosts.length === posts0, J([cn, P33S.listingPosts.length - posts0]));
    await pageChecks(at, { panel: false });
    await ev("(function(){var r=document.querySelector('#fCategory input[name=fCat][value=food]');if(r)(r.closest('label')||r).click();var b=document.getElementById('submitBtn');if(b)b.click();return !!r;})()"); await sleep(1500);
    const lp = P33S.listingPosts[P33S.listingPosts.length - 1] || {};
    check(at + "with Food & Cooking chosen it is sent with category food", P33S.listingPosts.length === posts0 + 1 && lp.category === "food", J(lp));

    // 7. Settings: Need alerts in my categories
    await open(cdp, origin, "settings.html", w, h, true);
    at = "P33 Settings at " + w + ": ";
    await sleep(600);
    await ev("(function(){var b=document.querySelector('.sidebar-item[data-target=preferences]');if(b)b.click();return !!b;})()"); await sleep(400);   // the Preferences section, where the switch is
    const st = await ev("(function(){var r=document.getElementById('needAlertsRow'),t=document.getElementById('needAlertsToggle');if(!r)return null;r.scrollIntoView({block:'center'});var b=r.getBoundingClientRect();return {shown:!r.hidden&&b.height>0,on:!!t&&t.checked,text:r.textContent.replace(/\\s+/g,' ').trim(),h:Math.round(b.height)};})()");
    check(at + "a member sees \"Need alerts\", on by default (never chosen)", !!st && st.shown && st.on && /Need alerts/.test(st.text) && st.h >= 44, J(st));
    await sleep(300);
    await pageChecks(at);
    await shot("settings-need-alerts");
    await ev("(function(){var t=document.getElementById('needAlertsToggle');if(t)t.click();return !!t;})()"); await sleep(900);
    check(at + "switched off, it is saved as need_alerts false", P33S.prefPuts.some(x => x.need_alerts === false) && P33S.needAlerts === false, J(P33S.prefPuts));
    P33S.member = false;
    await open(cdp, origin, "settings.html", w, h, true); await sleep(800);
    await ev("(function(){var b=document.querySelector('.sidebar-item[data-target=preferences]');if(b)b.click();return !!b;})()"); await sleep(400);
    const stFree = await ev("(function(){var r=document.getElementById('needAlertsRow');return !!r&&(r.hidden||r.getBoundingClientRect().height===0);})()");
    check("P33 Settings (a free account) at " + w + ": no Need alerts switch (alerts go to members only)", stFree === true);
    P33S.member = true;
  }
}
