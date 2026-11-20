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
     PHONE_P21=1           only P2-1's own pages (p21Run): the rewritten addresses,
                           signed out, Home, the Inbox's tabs and a thread, the
                           profile, the Create sheet, the dashboard with the bar,
                           at 360, 390 and 430; screenshots to Downloads\p21.
     PHONE_P22=1           only P2-2's own screens (p22Run): the report, block and
                           mute menu and its sheets, Settings, Blocked and muted,
                           moderation.html (owner and not), copyright.html and its
                           counter form, the owner's waiting count; at 360, 390
                           and 430; screenshots to Downloads\p22.

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
// NAMED (Nov 20 2026, P2-2): PHONE_P22 is its own run too
if (process.env.PHONE_HQ1 !== "1" && process.env.PHONE_P21 !== "1" && process.env.PHONE_P22 !== "1" && PAGES.length > 15) {   // HQ1 and P2-1: their own runs, no page list
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
const BAR_HIDDEN = ["app.html", "reset-password.html", "verify-email.html", "terms.html", "privacy.html", "refund.html", "contact.html",
  "music-popout.html", "card-view.html", "blogpost.html", "blogindex.html", "oracle.html", "mychart.html", "calendar.html", "synastry.html", "the-third.html"];
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
  const since = "2026-11-07T10:00:00Z";
  if (p === "/api/auth/me") return { user: ROSE, access: { active: true, reason: "subscription" }, subscription: { status: "active", plan: "all_access", current_period_end: ago(-24 * 20), cancel_at_period_end: false } };
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
  if (P21 || P22) { const a = p21Api(method, p); if (a !== undefined) return a; }
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
    if (P21) p = p21Rewrite(p);   // P2-1: /@handle, /listing/:id, /blog/... as the site rewrites them
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
    if (n.tagName === "A" && c.display === "inline") { var par = n.parentElement; var pt = (par.innerText || "").replace(/\s+/g, " ").trim(); var lt = (n.innerText || "").replace(/\s+/g, " ").trim(); if (pt.length > lt.length + 8) return; }
    if (r.width < 44 - 0.5 || r.height < 44 - 0.5) out.small.push(name(t) + " \"" + txt(t).slice(0, 18) + "\" " + Math.round(r.width) + "x" + Math.round(r.height));
  });
  out.smallCount = out.small.length; out.small = out.small.slice(0, 15);
  // 5. decoration painted over text
  var DECO = /star|nebula|glow|spark|cosmic|galaxy|aurora|particle|twinkle|halo|orb-bg|backdrop|sky/i;
  var decos = vis.filter(function(n){ var c = getComputedStyle(n); var nm = String(n.id) + " " + String(n.className && n.className.baseVal !== undefined ? n.className.baseVal : n.className);
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
          const ans = request.method === "OPTIONS" ? "" : api(request.method, u, request);
          const code = ans && ans.__status ? ans.__status : 200;
          const body = ans === "" ? "" : J(ans && ans.__status ? ans.__body : ans);
          await cdp.send("Fetch.fulfillRequest", { requestId, responseCode: code, body: Buffer.from(body).toString("base64"),
            responseHeaders: [{ name: "Content-Type", value: "application/json" }, { name: "Access-Control-Allow-Origin", value: "*" },
              { name: "Access-Control-Allow-Headers", value: "*" }, { name: "Access-Control-Allow-Methods", value: "GET,POST,PUT,PATCH,DELETE,OPTIONS" }] });
        } else if (HQ1 && request.url === MOON_PHOTO) {
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
          const restOver = d.overAtRest.filter(x => !/^(button#tmx-guide-fab|nav#bf-tabbar) /.test(x));
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
    } else if (ONLY !== "desktop" && !HQ1 && !P21) fs.writeFileSync(path.join(OUT, "defects-after-" + BATCH + ".json"), J(defects, null, 1));
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
          const over = m.over.filter(x => !/^button#tmx-guide-fab /.test(x)); if (over.length) bad.fixed.push(p + " " + J(over));
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
        const c = at + view + ", orbit " + orbit + ", all five portals: ";
        check(c + "no horizontal scroll", !bad.hscroll.length, J(bad.hscroll));
        check(c + "no text cut off", !bad.clipped.length, J(bad.clipped));
        check(c + "every tap target at least 44 x 44", !bad.small.length, J(bad.small));
        check(c + "no fixed element over text or a control", !bad.fixed.length, J(bad.fixed));
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
      "out[k]=n?{phase:n.getAttribute('data-moon-phase'),angle:n.getAttribute('data-moon-angle'),live:n.getAttribute('data-moon-live'),hidden:n.hidden,w:Math.round(b.width),paths:[].map.call(n.querySelectorAll('path'),function(p){return p.getAttribute('d');}),img:!!n.querySelector('image')}:null;});return out;})()");
    const gold = await ev("(function(){var t=document.getElementById('hqSetTitle');var cs=getComputedStyle(t);" +
      "return {title:t.classList.contains('hq-gold'),anim:cs.animationName,size:cs.backgroundSize,img:cs.backgroundImage.slice(0,40),icons:document.querySelectorAll('#hqList .hq-gold-glyph').length,rings:[].filter.call(document.querySelectorAll('.hq-gold-ring'),function(n){return getComputedStyle(n).display!=='none';}).length};})()");
    await shotPage(cdp, path.join(HQ1_OUT, "oracle-set-moon-and-gold-390.png"), 390).catch(() => null);
    await pick("#hqOrbitBtn"); await sleep(500);
    const cm = await ev("(function(){var n=document.querySelector('[data-hq-moon=chip]');var b=n?n.getBoundingClientRect():{width:0};return n?{phase:n.getAttribute('data-moon-phase'),hidden:n.hidden,w:Math.round(b.width),paths:[].map.call(n.querySelectorAll('path'),function(p){return p.getAttribute('d');})}:null;})()");
    check(at + "oracle.html shows the live phase (" + om.phase + ")", om.phase === MOON.phaseName && om.paths.length > 0, J(om).slice(0, 300));
    check(at + "the ORACLE node's moon: the same live phase and the same drawing (every path) as oracle.html's, drawn on the disc",
      !!dm.node && dm.node.phase === om.phase && dm.node.angle === String(MOON.phaseAngle) && dm.node.live === "true" && !dm.node.hidden && dm.node.w >= 44 && dm.node.img && J(dm.node.paths) === J(om.paths), J(dm.node).slice(0, 400));
    check(at + "the centre's moon while ORACLE is open: the same", !!dm.core && dm.core.phase === om.phase && !dm.core.hidden && dm.core.w >= 60 && J(dm.core.paths) === J(om.paths), J(dm.core).slice(0, 300));
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
  var g = document.getElementById("tmx-guide-fab");
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
  check(at + "nothing else is painted over the bar (the big music player excepted) and the Guide button clears it", s.cover.length === 0 && !s.guideOverlap, J({ cover: s.cover, guide: s.guide }));
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
      const restOver = rest.over.filter(x => !/^(button#tmx-guide-fab|nav#bf-tabbar) /.test(x));
      check(at + "the page is no wider than the screen (layout viewport " + w + ")", (await ev("innerWidth")) === w);
      check(at + "no fixed element over text or a control at rest (the bar and the Guide are judged at the end)", restOver.length === 0, J(restOver));
      if (act === "create") {
        const c = await ev("(function(){var s=document.getElementById('bf-create');if(!s||s.hidden)return null;var r=s.getBoundingClientRect();var bar=document.getElementById('bf-tabbar').getBoundingClientRect();" +
          "var top=document.elementFromPoint(bar.left+bar.width/2,bar.top+bar.height/2);" +
          "return {t:Math.round(r.top),b:Math.round(r.bottom),l:Math.round(r.left),r:Math.round(r.right),role:s.getAttribute('role'),opts:[].map.call(s.querySelectorAll('.bf-create-opt'),function(o){var q=o.getBoundingClientRect();return Math.round(q.width)+'x'+Math.round(q.height);})," +
          "soon:s.querySelectorAll('.is-soon').length,overBar:!!top&&(s.contains(top)||top.id==='bf-create-backdrop'),focus:s.contains(document.activeElement)};})()");
        check(at + "the Create sheet opens from + as a bottom sheet inside the screen, over the bar, focus in it", !!c && c.role === "dialog" && c.t >= 0 && c.b <= h + 1 && c.l <= 0 && c.r >= w - 1 && c.overBar && c.focus, J(c));
        check(at + "eight choices, each at least 44 px tall; Post and Video say Coming soon", !!c && c.opts.length === 8 && c.opts.every(o => Number(o.split("x")[1]) >= 44 && Number(o.split("x")[0]) >= 44) && c.soon === 2, J(c && c.opts));
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
      if (name === "home") check(at + "Home shows the market, campaigns and people from the fixtures, and the line about posts", k.tiles === 4 && k.camps === 2 && k.people === 2 && /Posts are coming/.test(k.soon), J(k));
      if (name === "inbox-messages") check(at + "the Messages tab lists the two conversations", k.tab === "tab-messages" && k.rows === 2, J(k));
      if (name === "inbox-thread") check(at + "?with= opens the conversation with its messages", k.tab === "tab-messages" && k.msgs >= 2, J(k));
      if (name === "inbox-approvals") check(at + "the Approvals tab lists the waiting proposals", k.tab === "tab-approvals" && k.rows === 10, J(k));
      if (name === "inbox-notifications") check(at + "the Notifications tab lists the three notices", k.tab === "tab-notifications" && k.rows === 3, J(k));
      if (name === "profile") check(at + "the profile header: @rose, Sales 12, BizCash 2,400, the tabs; no Following, Followers or Reviews", /@rose/.test(k.shell) && /12\s*Sales/.test(k.shell) && /2,400\s*BizCash/.test(k.shell) && /Posts\s*Shop\s*Services/.test(k.shell) && !/Follow|Review/.test(k.shell), k.shell.slice(0, 300));
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
    const over = m.over.filter(x => !/^(button#tmx-guide-fab|nav#bf-tabbar) /.test(x) && !(opts && opts.sheet && /^div#bf-safety(-backdrop)? /.test(x)));
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
