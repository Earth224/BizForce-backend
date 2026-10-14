"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkGuideTipClaims — every Termaximus tip that claimed to watch, monitor,
   track, alert, run in real time, or pointed at a panel or section, says
   only what is true.

   Frontend "Every Termaximus tip that claims to watch something has been
   checked" verified nine tips in scripts/termaximus-guide.js against the
   pages they describe and the server, kept the one that proved true
   (billing.html's cancellation banner) byte-for-byte, and rewrote the false
   parts of the other eight:

     analytics-dashboard.html  "real-time": the page reads its two endpoints
                               once, on load; nothing polls or streams.
     agents/sales.html         a Sales Pipeline panel exists; no Opportunities
                               panel and no code that finds a stalled deal.
     agents/analytics.html     no Warnings anywhere (the report cards were
                               removed in frontend bda6ecf); Revenue Forecast
                               builds a method and produces no figure.
     agents/lead-radar.html    the radars search fixed lists in their own
                               code and never read business_profiles.
     broker-agent.html (x2)    nothing tracks a pipeline; the Pipeline report
                               section was removed in bda6ecf.
     publicist-agent.html      the Coverage and Media Outreach reports were
                               removed in bda6ecf; nothing measures coverage.
     community-agent.html      the Engagement and Growth Plans sections were
                               removed in bda6ecf; nothing measures them.

   Tips and AGENT_PROFILE_CONFIG are read the way checkReputationTips.js reads
   them (regex extraction, evaluated in vm); page markup and server code are
   read as text. No DOM, no network, no model call, no database.

   WHAT THIS PROVES
     K. The kept tip's evidence still exists: billing.html's #cancelWarn
        banner, shown from sub.cancel_at_period_end, and /api/auth/me
        returning the whole subscriptions row.
     R. Each rewritten tip: the old false wording is gone, no watching word
        is used, and every feature it names is offered by its page (task
        type, tool, panel heading or element), and what it says is not there
        is still not there (no polling, no stall logic, no report sections).
     L. Lead Radar: no radar file reads business_profiles or a business
        profile, the search lists are fixed constants, and the tip mentions
        the Business Profile only to say the radar does not read it.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const GUIDE = "scripts/termaximus-guide.js", AP = "scripts/agent-profile.js";
const DASH = "analytics-dashboard.html", BILLING = "billing.html", SALES = "agents/sales.html", ANALYTICS = "agents/analytics.html",
  RADAR_PAGE = "agents/lead-radar.html", BROKER = "broker-agent.html", PUBLICIST = "publicist-agent.html", COMMUNITY = "community-agent.html";
const SERVER = "server.js", RADARS = ["leadRadar.js", "mastodonRadar.js", "youtubeRadar.js"];

const MUTATIONS = {
  // Lead Radar's tip claims the Business Profile again
  "restore-lead-radar-tip": [[GUIDE,
    '"It searches a fixed set of buyer-intent phrases and hashtags on Bluesky, Mastodon and YouTube, set in the radar\'s own code; it does not read your Business Profile, so editing your profile does not change what it finds."',
    '"It tracks against your Business Profile\'s Competitors and Industry — keep those current so the radar is watching the conversations that actually matter to you."']],
  // the broker tip points at the removed Pipeline report section again
  "restore-broker-pipeline-section": [[GUIDE,
    '"Each run is saved — open your latest from the Last run link on this page; the agent keeps no record of where your deals stand, so keep that yourself."',
    '"Track the Pipeline report section as your single source of truth for where every deal actually stands."']],
  // the kept billing tip loses its evidence: the banner is gone from the page
  "remove-cancel-banner": [[BILLING, '<div class="warn-banner" id="cancelWarn">', '<div class="warn-banner">']],
  // a radar starts reading the business profile, so the rewritten tip would be false
  "radar-reads-profile": [["leadRadar.js", "const KEYWORDS = [", 'const PROFILE_READ = () => supabase.from("business_profiles").select("*");\nconst KEYWORDS = [']],
  // the dashboard rewrite says "read once"; a poll would make that false
  "dashboard-polls": [[DASH, "    loadAnalytics();\n    loadActivity();", "    loadAnalytics();\n    loadActivity();\n    setInterval(loadAnalytics, 30000);"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[GUIDE, AP, DASH, BILLING, SALES, ANALYTICS, RADAR_PAGE, BROKER, PUBLICIST, COMMUNITY].forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(1); }
  FILES[f] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
});
[SERVER].concat(RADARS).forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

// A guide entry's tips, by its page key (the key the guide uses, without "agents/").
function tipsFor(key) {
  const esc = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp('"' + esc + '": (\\[[\\s\\S]*?\\n    \\])').exec(FILES[GUIDE]);
  return m ? vm.runInNewContext(m[1]) : [];
}
function configOf(file) {
  const m = /window\.AGENT_PROFILE_CONFIG = (\{[\s\S]*?\n\});/.exec(FILES[file]);
  return m ? vm.runInNewContext("(" + m[1] + ")") : { taskTypes: [], tools: [] };
}
function offeredOn(file) {
  const c = configOf(file);
  return c.taskTypes.map(t => t.label).concat((c.tools || []).map(t => t.label));
}
const WATCHING = /\b(watch|monitor|track|alert)\w*|real-?time|early[- ]warning/i;
// A tip found by a fragment of its text, or "" (never several).
function tipWith(tips, fragment) {
  const found = tips.filter(t => t.indexOf(fragment) !== -1);
  return found.length === 1 ? found[0] : "";
}
// Tips that point to the Last run link: the page carries #lastRunText and agent-profile.js links it to run.html.
function lastRunOffered(file) {
  return /id="lastRunText"/.test(FILES[file]) && /function loadLastRun\(\)/.test(FILES[AP]) && /\/run\.html\?id=/.test(FILES[AP]);
}

/* ── K. billing.html: kept, byte-identical ─────────────────────────────── */
console.log("\n══ K. billing.html — kept (TRUE) ══");
const billingTips = tipsFor("billing.html");
const KEPT = "Watch for the cancellation warning banner — if it's showing, your access has an end date, and you'll want to resubscribe before it hits.";
check("K. the billing tip is unchanged, byte for byte", billingTips.indexOf(KEPT) !== -1, JSON.stringify(billingTips));
check("K. billing.html has the #cancelWarn banner with its end-of-access text",
  /<div class="warn-banner" id="cancelWarn">\s*Your subscription will not renew — access ends at the period end date\./.test(FILES[BILLING]));
check("K. the banner is shown from the subscription's cancel_at_period_end",
  /document\.getElementById\("cancelWarn"\)\.style\.display\s*=\s*sub\.cancel_at_period_end \? "block" : "none"/.test(FILES[BILLING]));
check("K. the server's /api/auth/me returns the subscriptions row (select *), which carries cancel_at_period_end",
  /app\.get\("\/api\/auth\/me"/.test(FILES[SERVER]) &&
  /async function getActiveSubscription\(userId\) \{\s*const \{ data, error \} = await supabase\s*\.from\("subscriptions"\)\s*\.select\("\*"\)/.test(FILES[SERVER]));

/* ── R1. analytics-dashboard.html ──────────────────────────────────────── */
console.log("\n══ R1. analytics-dashboard.html — \"real-time\" rewritten ══");
const dashTip = tipWith(tipsFor("analytics-dashboard.html"), "business intelligence command center");
check("R1. the tip no longer says real-time", !!dashTip && !/real-?time/i.test(dashTip), dashTip);
check("R1. the tip says the page is read once when it opens", /read once when the page opens/.test(dashTip));
check("R1. the page fetches its data on load and never again: no setInterval, EventSource or WebSocket",
  /\n    loadAnalytics\(\);\n    loadActivity\(\);/.test(FILES[DASH]) && !/setInterval|EventSource|WebSocket/.test(FILES[DASH]));
const DASH_NAMED = { "Tasks Run": "statTasksRun", "Tasks Completed": "statTasksCompleted", "Content Items": "statContentItems",
  "SMS Subscribers": "statSubscribers", "Opted-In": "statOptedIn", "SMS Campaigns": "statCampaigns", "Content Breakdown": "chartContent", "Tasks by Agent": "chartAgents" };
check("R1. every tile and chart the tip names is on the page, by label and element id",
  Object.keys(DASH_NAMED).every(n => dashTip.indexOf(n) !== -1 && FILES[DASH].indexOf(">" + n + "<") !== -1 && FILES[DASH].indexOf('id="' + DASH_NAMED[n] + '"') !== -1),
  Object.keys(DASH_NAMED).filter(n => !(dashTip.indexOf(n) !== -1 && FILES[DASH].indexOf(">" + n + "<") !== -1 && FILES[DASH].indexOf('id="' + DASH_NAMED[n] + '"') !== -1)).join(", "));

/* ── R2. agents/sales.html ─────────────────────────────────────────────── */
console.log("\n══ R2. sales.html — Pipeline and Opportunities rewritten ══");
const salesTips = tipsFor("sales.html");
const salesTip = tipWith(salesTips, "Sales Pipeline panel");
check("R2. the old \"Pipeline and Opportunities panels … flag where deals are stalling\" tip is gone",
  salesTips.every(t => !/Opportunities panel|flag where deals are stalling/.test(t)) && !!salesTip, JSON.stringify(salesTips));
check("R2. the new tip uses no watching word", !WATCHING.test(salesTip), salesTip);
check("R2. the Sales Pipeline panel exists: its heading and #salesPipelineBoard",
  /<h2 class="section-label">Sales Pipeline<\/h2>\s*<div class="sales-pipeline-board" id="salesPipelineBoard"><\/div>/.test(FILES[SALES]));
check("R2. its stages are the five the tip names, in order",
  /var STATUS_LABELS = \{ new: "New", drafted: "Drafted", contacted: "Contacted", replied: "Replied", converted: "Converted" \};/.test(FILES[SALES]) &&
  /New, Drafted, Contacted, Replied, Converted/.test(salesTip));
check("R2. a lead's stage can be moved: each card has a stage select and the board handles its change",
  /class="sales-pipeline-item-select"/.test(FILES[SALES]) && /board\.addEventListener\("change"/.test(FILES[SALES]));
check("R2. still no Opportunities panel and no stalled-deal logic on the page or the server (the tip says so)",
  !/Opportunities<\/h2>|id="[^"]*[Oo]pportunit/.test(FILES[SALES]) && !/\bstall(ed|ing)\b/i.test(FILES[SALES]) && !/\bstall(ed|ing)[ _]deal/i.test(FILES[SERVER]) &&
  /nothing here judges which deals are stalling/.test(salesTip));

/* ── R3. agents/analytics.html ─────────────────────────────────────────── */
console.log("\n══ R3. analytics.html — Warnings rewritten ══");
const anTips = tipsFor("analytics.html");
const anTip = tipWith(anTips, "KPI and forecasting layer");
check("R3. the old \"Warnings that flag risk\" wording is gone from that tip", !!anTip && !/Warnings that flag risk|insights, revenue forecasts/.test(anTip), anTip);
check("R3. the new tip uses no watching word", !WATCHING.test(anTip), anTip);
const anOffered = offeredOn(ANALYTICS);
check("R3. every feature the tip names is offered: KPI Review, Funnel Analysis, Revenue Forecast",
  ["KPI Review", "Funnel Analysis", "Revenue Forecast"].every(n => anTip.indexOf(n) !== -1 && anOffered.indexOf(n) !== -1), JSON.stringify(anOffered));
check("R3. the page has no Warnings section, and the tip names none",
  !/Warnings/.test(FILES[ANALYTICS]) && !/Warnings/.test(anTip));
check("R3. revenue_forecast still produces no revenue figure (the tip says it reads no revenue data)",
  /revenue_forecast: "[^"\n]*This platform reads no sales, revenue or pipeline data, so produce no revenue figure/.test(FILES[SERVER]) &&
  /reads no revenue data of its own/.test(anTip));

/* ── L. agents/lead-radar.html ─────────────────────────────────────────── */
console.log("\n══ L. lead-radar.html — Business Profile claim rewritten ══");
const lrTips = tipsFor("lead-radar.html");
const lrTip = tipWith(lrTips, "fixed set of buyer-intent phrases");
check("L. the old \"tracks against your Business Profile's Competitors and Industry\" tip is gone",
  lrTips.every(t => !/tracks against your Business Profile|Competitors and Industry/.test(t)) && !!lrTip, JSON.stringify(lrTips));
check("L. the tip says the radar searches fixed buyer-intent phrases and hashtags on Bluesky, Mastodon and YouTube",
  /fixed set of buyer-intent phrases and hashtags on Bluesky, Mastodon and YouTube/.test(lrTip));
check("L. the tip says it does not read your Business Profile", /does not read your Business Profile/.test(lrTip));
check("L. no Lead Radar tip makes a Business Profile claim: the profile is named only in that denial",
  lrTips.every(t => t.replace(/does not read your Business Profile/g, "").search(/Business Profile|\bprofile's\b|Competitors|Industry/) === -1 ||
    t === lrTip && t.replace(/does not read your Business Profile/g, "").replace(/editing your profile does not change what it finds/, "").search(/Business Profile|profile|Competitors|Industry/) === -1),
  lrTips.filter(t => t.replace(/does not read your Business Profile/g, "").replace(/editing your profile does not change what it finds/, "").search(/Business Profile|profile|Competitors|Industry/) !== -1).join(" | "));
check("L. the rewritten tip uses no watching word", !WATCHING.test(lrTip), lrTip);
// A read, not a mention: leadRadar.js's scorer prompt describes BizForce as "eighteen AI agents working from one business profile".
const PROFILE_READ = /business_profiles|businessProfile|bfLoadBusinessContext/;
check("L. no radar file reads business_profiles or a business profile",
  RADARS.every(f => !PROFILE_READ.test(FILES[f])), RADARS.filter(f => PROFILE_READ.test(FILES[f])).join(", "));
check("L. the searches are fixed lists in code: KEYWORDS and BIZFORCE_KEYWORDS, HASHTAGS, and YouTube's KEYWORDS",
  /\nconst KEYWORDS = \[/.test(FILES["leadRadar.js"]) && /\nconst BIZFORCE_KEYWORDS = \[/.test(FILES["leadRadar.js"]) &&
  /\nconst HASHTAGS = \[/.test(FILES["mastodonRadar.js"]) && /\nconst KEYWORDS = \[/.test(FILES["youtubeRadar.js"]));
check("L. the Lead Radar page itself reads no business profile", !/business_profile|bfLoadBusinessContext|\/api\/business/i.test(FILES[RADAR_PAGE]));

/* ── R4–R7. the template pages whose report sections were removed ──────── */
console.log("\n══ R4–R7. broker, publicist, community — report sections rewritten ══");
const brTips = tipsFor("broker-agent.html");
const brIntro = tipWith(brTips, "deal flow and partnerships");
check("R4. broker: \"manages deal flow … pipeline tracking\" is gone", !!brIntro && !/pipeline tracking|manages deal flow/.test(brIntro), brIntro);
check("R4. broker: the intro names Deal Pipeline as the page offers it", /Deal Pipeline analysis/.test(brIntro) && offeredOn(BROKER).indexOf("Deal Pipeline") !== -1);
check("R5. broker: \"Track the Pipeline report section\" is gone", brTips.every(t => !/Pipeline report section/.test(t)), JSON.stringify(brTips));
const pubTips = tipsFor("publicist-agent.html");
check("R6. publicist: \"Track Coverage and Media Outreach reports\" is gone", pubTips.every(t => !/Coverage and Media Outreach reports/.test(t)), JSON.stringify(pubTips));
const comTips = tipsFor("community-agent.html");
check("R7. community: \"Watch the Engagement and Growth Plans sections\" is gone", comTips.every(t => !/Engagement and Growth Plans sections/.test(t)), JSON.stringify(comTips));
[[BROKER, brTips, "R5", "the agent keeps no record of where your deals stand"],
 [PUBLICIST, pubTips, "R6", "nothing here measures coverage"],
 [COMMUNITY, comTips, "R7", "nothing here measures engagement or growth"]].forEach(([file, tips, id, says]) => {
  const t = tipWith(tips, "Last run link");
  check(id + ". " + file + ": the new tip points to the Last run link, which the page offers and links to run.html", !!t && lastRunOffered(file), t);
  check(id + ". " + file + ": the new tip says what is not measured, and uses no watching word", t.indexOf(says) !== -1 && !WATCHING.test(t), t);
  check(id + ". " + file + ": the page still renders no report sections (REPORT_SECTIONS, #reportsGrid)", !/REPORT_SECTIONS|reportsGrid/.test(FILES[file]));
});
check("R4–R7. no tip on these three pages uses a watching word", brTips.concat(pubTips, comTips).every(t => !WATCHING.test(t)),
  brTips.concat(pubTips, comTips).filter(t => WATCHING.test(t)).join(" | "));

console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
process.exit(failures ? 1 : 0);
